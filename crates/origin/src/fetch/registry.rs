//! Image indexes, manifests and bundles, from an OCI registry.

use std::collections::HashMap;

use landfall_core::ids::{ImageDigest, ReleaseTag};
use landfall_core::release::Platform;
use reqwest::Url;
use reqwest::header::HeaderValue;
use serde::Deserialize;

use super::http::{
    Fetched, SameHost, Transfer, content_digest, join, media_type, parse, sha256_digest,
};
use super::{
    ATTESTATION_MANIFEST, BUNDLE_TYPE, DOCKER_LIST, FetchError, Fetcher, MANIFEST_LIMIT, OCI_INDEX,
    OCI_MANIFEST, PREDICATE_TYPE_ANNOTATION, REFERENCE_TYPE_ANNOTATION, Service,
};
use crate::attestation::{MAX_BUNDLE_BYTES, SLSA_PROVENANCE};

impl Fetcher {
    /// The digest of the multi-arch image index `image:tag` and the
    /// platforms it serves. `image` is the registry path, `<owner>/<name>`.
    ///
    /// The digest is the sha256 of the bytes received, and must equal the
    /// `Docker-Content-Digest` header when there is one. Only an OCI image
    /// index or a Docker manifest list is accepted. The attestation
    /// manifests buildx adds are not platforms and are left out.
    ///
    /// # Errors
    ///
    /// [`FetchError::OciTag`] when `tag` is not a valid OCI tag (checked
    /// before any request), [`FetchError::MediaType`] for a single-platform
    /// manifest or any other media type, [`FetchError::Digest`] when the
    /// header disagrees with the bytes, [`FetchError::Malformed`] for an
    /// index that lists no platform, and the transport and parsing errors.
    pub async fn resolve_index(
        &self,
        image: &str,
        tag: &ReleaseTag,
    ) -> Result<(ImageDigest, Vec<Platform>), FetchError> {
        check_image(image)?;
        check_oci_tag(tag)?;
        let token = self.registry_token(image).await?;
        let url = self.manifest_url(image, tag.as_ref())?;
        let accept = format!("{OCI_INDEX}, {DOCKER_LIST}");
        let response = self
            .registry_get(&url, &accept, Some(&token), MANIFEST_LIMIT)
            .await?;

        let media_type = media_type(&response.headers);
        if media_type != OCI_INDEX && media_type != DOCKER_LIST {
            return Err(FetchError::MediaType {
                url: url.to_string(),
                found: media_type,
                expected: "an OCI image index or a Docker manifest list",
            });
        }
        let digest = content_digest(&url, &response)?;
        let index: Index = parse(&url, &response.body)?;
        index.check(&url, &media_type)?;
        let platforms = index
            .manifests
            .into_iter()
            .filter(|m| !m.is_attestation_manifest())
            .filter_map(|m| m.platform)
            .collect::<Vec<_>>();
        if platforms.is_empty() {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: "the index lists no platforms".to_owned(),
            });
        }
        Ok((digest, platforms))
    }

    /// The Sigstore bundle attached to `digest` in `image`, found through
    /// the referrers tag schema: the tag `sha256-<hex>` names an index of
    /// referrer manifests (or one manifest); exactly one of them must have
    /// the bundle artifact type and the predicate type annotation
    /// `https://slsa.dev/provenance/v1` (other attestations, such as SBOMs,
    /// and descriptors without the annotation are skipped, not counted). The
    /// manifest's own annotation must agree; it must refer to `digest` and
    /// hold one layer, the bundle, whose bytes must match its descriptor.
    /// The annotations only select: the bundle's signed statement is checked
    /// again by [`crate::attestation::verify_bundle`].
    ///
    /// # Errors
    ///
    /// [`FetchError::Bundles`] when no bundle or several bundles refer to
    /// the digest, [`FetchError::Digest`] when a manifest or the bundle does
    /// not match its descriptor, and the transport and parsing errors.
    pub async fn bundle(&self, image: &str, digest: &ImageDigest) -> Result<Vec<u8>, FetchError> {
        let token = self.pull_token(image).await?;
        self.bundle_with(image, digest, &token).await
    }

    /// [`Fetcher::bundle`] with a token from [`Fetcher::pull_token`], for looking at
    /// many digests of one image.
    pub(crate) async fn bundle_with(
        &self,
        image: &str,
        digest: &ImageDigest,
        token: &HeaderValue,
    ) -> Result<Vec<u8>, FetchError> {
        let referrers_tag = digest.as_ref().replacen(':', "-", 1);
        let url = self.manifest_url(image, &referrers_tag)?;
        let accept = format!("{OCI_INDEX}, {OCI_MANIFEST}");
        let no_bundle = || FetchError::Bundles {
            digest: digest.clone(),
            count: 0,
        };
        let response = match self
            .registry_get(&url, &accept, Some(token), MANIFEST_LIMIT)
            .await
        {
            Err(FetchError::NotFound { .. }) => return Err(no_bundle()),
            other => other?,
        };
        content_digest(&url, &response)?;

        let (manifest_url, manifest) = match media_type(&response.headers).as_str() {
            OCI_INDEX => {
                let index: Index = parse(&url, &response.body)?;
                index.check(&url, OCI_INDEX)?;
                let bundles: Vec<Descriptor> = index
                    .manifests
                    .into_iter()
                    .filter(|m| {
                        m.artifact_type.as_deref() == Some(BUNDLE_TYPE)
                            && annotation(m.annotations.as_ref(), PREDICATE_TYPE_ANNOTATION)
                                == Some(SLSA_PROVENANCE)
                    })
                    .collect();
                let [descriptor] = bundles.as_slice() else {
                    return Err(FetchError::Bundles {
                        digest: digest.clone(),
                        count: bundles.len(),
                    });
                };
                let manifest_url = self.manifest_url(image, descriptor.digest.as_ref())?;
                let response = self
                    .registry_get(&manifest_url, OCI_MANIFEST, Some(token), MANIFEST_LIMIT)
                    .await?;
                let found = media_type(&response.headers);
                if found != OCI_MANIFEST {
                    return Err(FetchError::MediaType {
                        url: manifest_url.to_string(),
                        found,
                        expected: OCI_MANIFEST,
                    });
                }
                descriptor.check_content(&manifest_url, &response.body)?;
                let manifest: Manifest = parse(&manifest_url, &response.body)?;
                let found = manifest.predicate_type();
                if found != Some(SLSA_PROVENANCE) {
                    return Err(FetchError::Malformed {
                        url: manifest_url.to_string(),
                        reason: format!(
                            "the manifest's predicate type {found:?} disagrees with its \
                             descriptor's {SLSA_PROVENANCE}"
                        ),
                    });
                }
                (manifest_url, manifest)
            }
            OCI_MANIFEST => {
                let manifest: Manifest = parse(&url, &response.body)?;
                if manifest.artifact_type() != BUNDLE_TYPE
                    || manifest.predicate_type() != Some(SLSA_PROVENANCE)
                {
                    return Err(no_bundle());
                }
                (url, manifest)
            }
            other => {
                return Err(FetchError::MediaType {
                    url: url.to_string(),
                    found: other.to_owned(),
                    expected: "an OCI image index or an OCI image manifest",
                });
            }
        };

        let layer = manifest.bundle_layer(&manifest_url, digest)?;
        if usize::try_from(layer.size).map_or(true, |size| size > MAX_BUNDLE_BYTES) {
            return Err(FetchError::TooLarge {
                url: manifest_url.to_string(),
                limit: MAX_BUNDLE_BYTES,
            });
        }
        let mut segments = vec!["v2"];
        segments.extend(image.split('/'));
        segments.extend(["blobs", layer.digest.as_ref()]);
        let blob_url = join(&self.endpoints.registry, &segments)?;
        let response = self
            .registry_get(&blob_url, BUNDLE_TYPE, Some(token), MAX_BUNDLE_BYTES)
            .await?;
        layer.check_content(&blob_url, &response.body)?;
        Ok(response.body)
    }

    /// A pull token for `image`, whose name is checked first.
    pub(crate) async fn pull_token(&self, image: &str) -> Result<HeaderValue, FetchError> {
        check_image(image)?;
        self.registry_token(image).await
    }

    /// An anonymous pull token for `image`, as an `Authorization` value.
    async fn registry_token(&self, image: &str) -> Result<HeaderValue, FetchError> {
        let mut url = join(&self.endpoints.registry, &["token"])?;
        url.query_pairs_mut()
            .append_pair("scope", &format!("repository:{image}:pull"));
        let response = self
            .registry_get(&url, "application/json", None, MANIFEST_LIMIT)
            .await?;
        let token: RegistryToken = parse(&url, &response.body)?;
        let mut value =
            HeaderValue::from_str(&format!("Bearer {}", token.token)).map_err(|_| {
                FetchError::Malformed {
                    url: url.to_string(),
                    reason: "the token is not a valid HTTP header value".to_owned(),
                }
            })?;
        value.set_sensitive(true);
        Ok(value)
    }

    fn manifest_url(&self, image: &str, reference: &str) -> Result<Url, FetchError> {
        let mut segments = vec!["v2"];
        segments.extend(image.split('/'));
        segments.extend(["manifests", reference]);
        join(&self.endpoints.registry, &segments)
    }

    /// A GET to the registry, with its pull token when there is one; never
    /// with the GitHub token.
    pub(super) async fn registry_get(
        &self,
        url: &Url,
        accept: &str,
        token: Option<&HeaderValue>,
        limit: usize,
    ) -> Result<Fetched, FetchError> {
        let transfer = Transfer {
            accept,
            service: Service::Registry,
            limit,
            timeout: None,
        };
        self.get(url, transfer, token, SameHost::KeepsCredential)
            .await
    }
}

/// Refuses a release tag that is not an OCI tag,
/// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`: a `/` would change the registry
/// path the request goes to, and `+` is not allowed in an image tag.
fn check_oci_tag(tag: &ReleaseTag) -> Result<(), FetchError> {
    let bytes = tag.as_ref().as_bytes();
    let valid = (1..=128).contains(&bytes.len())
        && bytes
            .first()
            .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
        && bytes
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
    if valid {
        Ok(())
    } else {
        Err(FetchError::OciTag(tag.clone()))
    }
}

/// An image path: `/`-separated components of `[a-z0-9._-]`, each starting
/// and ending with `[a-z0-9]`, 255 bytes at most.
fn check_image(image: &str) -> Result<(), FetchError> {
    let edge = |b: Option<&u8>| b.is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    let valid = (1..=255).contains(&image.len())
        && image.split('/').all(|component| {
            let bytes = component.as_bytes();
            edge(bytes.first())
                && edge(bytes.last())
                && bytes.iter().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
                })
        });
    if valid {
        Ok(())
    } else {
        Err(FetchError::Image(image.to_owned()))
    }
}

#[derive(Deserialize)]
struct RegistryToken {
    token: String,
}

fn annotation<'a>(annotations: Option<&'a HashMap<String, String>>, key: &str) -> Option<&'a str> {
    annotations.and_then(|a| a.get(key)).map(String::as_str)
}

/// An OCI image index or Docker manifest list.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Index {
    schema_version: u32,
    media_type: Option<String>,
    manifests: Vec<Descriptor>,
}

impl Index {
    /// Schema version 2, and a `mediaType`, when present, equal to the one
    /// the registry served it as.
    fn check(&self, url: &Url, served_as: &str) -> Result<(), FetchError> {
        if self.schema_version != 2 {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("schemaVersion {}, expected 2", self.schema_version),
            });
        }
        match &self.media_type {
            Some(found) if found != served_as => Err(FetchError::MediaType {
                url: url.to_string(),
                found: found.clone(),
                expected: "the media type the registry served it as",
            }),
            _ => Ok(()),
        }
    }
}

/// An OCI content descriptor.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor {
    media_type: String,
    digest: ImageDigest,
    size: u64,
    artifact_type: Option<String>,
    platform: Option<Platform>,
    annotations: Option<HashMap<String, String>>,
}

impl Descriptor {
    fn is_attestation_manifest(&self) -> bool {
        annotation(self.annotations.as_ref(), REFERENCE_TYPE_ANNOTATION)
            == Some(ATTESTATION_MANIFEST)
    }

    /// The bytes fetched for this descriptor have its size and digest.
    fn check_content(&self, url: &Url, body: &[u8]) -> Result<(), FetchError> {
        let computed = sha256_digest(body);
        if computed != self.digest.as_ref() {
            return Err(FetchError::Digest {
                url: url.to_string(),
                expected: self.digest.to_string(),
                computed,
            });
        }
        if u64::try_from(body.len()).ok() != Some(self.size) {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("{} bytes, the descriptor says {}", body.len(), self.size),
            });
        }
        Ok(())
    }
}

/// An OCI image manifest, as a referrer.
#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Manifest {
    schema_version: u32,
    media_type: Option<String>,
    artifact_type: Option<String>,
    config: Descriptor,
    layers: Vec<Descriptor>,
    subject: Option<Descriptor>,
    annotations: Option<HashMap<String, String>>,
}

impl Manifest {
    /// `artifactType`, or the config media type when it is absent (OCI image
    /// spec, "Guidelines for Artifact Usage").
    fn artifact_type(&self) -> &str {
        self.artifact_type
            .as_deref()
            .unwrap_or(&self.config.media_type)
    }

    fn predicate_type(&self) -> Option<&str> {
        annotation(self.annotations.as_ref(), PREDICATE_TYPE_ANNOTATION)
    }

    /// The one bundle layer of a referrer manifest for `subject`.
    fn bundle_layer(&self, url: &Url, subject: &ImageDigest) -> Result<&Descriptor, FetchError> {
        let malformed = |reason: String| FetchError::Malformed {
            url: url.to_string(),
            reason,
        };
        if self.schema_version != 2 {
            return Err(malformed(format!(
                "schemaVersion {}, expected 2",
                self.schema_version
            )));
        }
        if let Some(found) = &self.media_type
            && found != OCI_MANIFEST
        {
            return Err(FetchError::MediaType {
                url: url.to_string(),
                found: found.clone(),
                expected: OCI_MANIFEST,
            });
        }
        if self.artifact_type() != BUNDLE_TYPE {
            return Err(malformed(format!(
                "artifact type {:?}, expected {BUNDLE_TYPE}",
                self.artifact_type()
            )));
        }
        match &self.subject {
            Some(found) if found.digest == *subject => {}
            Some(found) => {
                return Err(malformed(format!(
                    "the bundle refers to {}, not {subject}",
                    found.digest
                )));
            }
            None => return Err(malformed("the bundle names no subject".to_owned())),
        }
        let [layer] = self.layers.as_slice() else {
            return Err(malformed(format!(
                "{} layers, expected one bundle",
                self.layers.len()
            )));
        };
        if layer.media_type != BUNDLE_TYPE {
            return Err(FetchError::MediaType {
                url: url.to_string(),
                found: layer.media_type.clone(),
                expected: BUNDLE_TYPE,
            });
        }
        Ok(layer)
    }
}
