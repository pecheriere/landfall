//! Fetchers for release material: signed tag objects from the GitHub API,
//! image indexes and Sigstore bundles from an OCI registry (GHCR).
//!
//! Everything fetched here is hostile input until it is verified. This module
//! checks only what binds the bytes to the name they were asked for (the git
//! object id, content digests, media types and sizes) and enforces size caps
//! while the body streams in. Signatures and attestations are verified
//! elsewhere: [`landfall_core::tag`] and [`crate::attestation`].
//!
//! Requests go over HTTPS only, with a connect timeout of 10 s and a total
//! timeout of 30 s. Bodies are never decompressed (no compression feature is
//! enabled in the HTTP client), so a cap applies to the bytes on the wire.

use std::collections::HashMap;
use std::time::Duration;

use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};
use reqwest::header::{ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderValue};
use reqwest::{Client, StatusCode, Url, redirect};
use serde::Deserialize;
use sha1::Sha1;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub use landfall_core::release::Platform;

/// Cap on a GitHub API response for a tag ref or tag object.
pub const TAG_OBJECT_LIMIT: usize = 64 * 1024;
/// Cap on an image index or manifest, and on a registry token response.
pub const MANIFEST_LIMIT: usize = 1024 * 1024;
/// Cap on a Sigstore bundle.
pub const BUNDLE_LIMIT: usize = 4 * 1024 * 1024;

/// The public GitHub REST API.
const GITHUB_API: &str = "https://api.github.com";
/// The GitHub container registry.
const GHCR: &str = "https://ghcr.io";

/// Connect timeout for every request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Total timeout for every request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Redirects followed per request (a registry blob redirects to its storage).
const MAX_REDIRECTS: usize = 3;
/// Tag objects followed when peeling a tag to its commit.
const MAX_TAG_DEPTH: usize = 4;

const GITHUB_ACCEPT: &str = "application/vnd.github+json";
const GITHUB_API_VERSION: &str = "2022-11-28";
const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";
const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";
const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";
const BUNDLE_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";
/// The annotation buildx puts on the attestation manifests it adds to an
/// index; they declare the platform `unknown/unknown` and run nowhere.
const REFERENCE_TYPE_ANNOTATION: &str = "vnd.docker.reference.type";
const ATTESTATION_MANIFEST: &str = "attestation-manifest";

/// Why release material could not be fetched, or was refused.
#[derive(Debug, Error)]
pub enum FetchError {
    /// A base URL is not acceptable.
    #[error("invalid endpoint {url}: {reason}")]
    Endpoint {
        /// The URL as given.
        url: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The GitHub token cannot be sent as an HTTP header.
    #[error("the GitHub token is not a valid HTTP header value")]
    Token,
    /// The image name is not a lowercase registry path.
    #[error(
        "invalid image name {0:?}: expected 1 to 255 bytes of '/'-separated components of \
         [a-z0-9._-], each starting and ending with [a-z0-9]"
    )]
    Image(String),
    /// The HTTP client could not be built.
    #[error("HTTP client")]
    Client(#[source] reqwest::Error),
    /// The request failed: connection, TLS, timeout, redirect or body read.
    #[error("request to {url} failed")]
    Request {
        /// The URL requested.
        url: String,
        /// The transport error.
        #[source]
        source: reqwest::Error,
    },
    /// The server answered 404.
    #[error("{url} returned 404 not found")]
    NotFound {
        /// The URL requested.
        url: String,
    },
    /// The server answered with a status other than 200 and 404.
    #[error("{url} returned HTTP {status}")]
    Status {
        /// The URL requested.
        url: String,
        /// The HTTP status code.
        status: u16,
    },
    /// The response body is larger than the cap for its kind.
    #[error("{url} returned more than {limit} bytes")]
    TooLarge {
        /// The URL requested.
        url: String,
        /// The cap, in bytes.
        limit: usize,
    },
    /// The response is not the JSON document expected.
    #[error("{url} returned malformed JSON")]
    Json {
        /// The URL requested.
        url: String,
        /// The parse error.
        #[source]
        source: serde_json::Error,
    },
    /// The response parsed but says something impossible or inconsistent.
    #[error("{url}: {reason}")]
    Malformed {
        /// The URL requested.
        url: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The tag ref points straight at a commit: there is no tag object.
    #[error("tag {tag} is a lightweight tag, not a tag object")]
    LightweightTag {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The tag object carries no signature, so GitHub serves no signed
    /// payload and its raw bytes cannot be reconstructed. Callers report this
    /// as "tag is not signed".
    #[error("tag {tag} is not signed: GitHub serves no signed payload for it")]
    NotSigned {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The reconstructed tag object does not hash to the id it was fetched by.
    #[error("tag object id mismatch: fetched {expected}, the served bytes hash to {computed}")]
    ObjectId {
        /// The object id the tag ref named.
        expected: String,
        /// The git object id of the bytes served.
        computed: String,
    },
    /// The tag points at a tree or a blob, not a commit or tag object.
    #[error("tag {tag} points at a {found} object, not a commit")]
    ObjectType {
        /// The tag.
        tag: ReleaseTag,
        /// The git object type found.
        found: String,
    },
    /// The tag is a chain of more than four tag objects.
    #[error("tag {tag} nests more than {MAX_TAG_DEPTH} tag objects")]
    TagDepth {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The response has a media type other than the ones asked for.
    #[error("{url} served media type {found:?}, expected {expected}")]
    MediaType {
        /// The URL requested.
        url: String,
        /// The media type served.
        found: String,
        /// What was acceptable.
        expected: &'static str,
    },
    /// The bytes served do not hash to the digest they were named by.
    #[error(
        "{url}: content digest mismatch: expected {expected}, the served bytes hash to {computed}"
    )]
    Digest {
        /// The URL requested.
        url: String,
        /// The digest from the header or the referring descriptor.
        expected: String,
        /// The sha256 of the bytes served.
        computed: String,
    },
    /// Not exactly one Sigstore bundle refers to the digest.
    #[error("expected exactly one Sigstore bundle for {digest}, found {count}")]
    Bundles {
        /// The image digest.
        digest: ImageDigest,
        /// How many bundles refer to it.
        count: usize,
    },
}

/// The base URLs requests go to.
///
/// [`Endpoints::new`] accepts only `https` URLs. Plain `http`, for the mock
/// servers in this crate's tests, is reachable only through a constructor
/// compiled into test builds.
#[derive(Debug, Clone)]
pub struct Endpoints {
    github_api: Url,
    registry: Url,
    https_only: bool,
}

impl Endpoints {
    /// Endpoints for the GitHub REST API at `github_api` and the OCI registry
    /// at `registry`.
    ///
    /// # Errors
    ///
    /// [`FetchError::Endpoint`] when a URL is not `https`, has no host, or
    /// carries credentials, a query or a fragment.
    pub fn new(github_api: Url, registry: Url) -> Result<Self, FetchError> {
        check_endpoint(&github_api)?;
        check_endpoint(&registry)?;
        Ok(Self {
            github_api,
            registry,
            https_only: true,
        })
    }

    /// `https://api.github.com` and `https://ghcr.io`.
    ///
    /// # Errors
    ///
    /// None in practice: the URLs are constants that pass [`Endpoints::new`].
    pub fn public() -> Result<Self, FetchError> {
        let parse = |url: &str| {
            Url::parse(url).map_err(|_| FetchError::Endpoint {
                url: url.to_owned(),
                reason: "not a URL",
            })
        };
        Self::new(parse(GITHUB_API)?, parse(GHCR)?)
    }

    /// Endpoints over plain `http`, for mock servers. Test builds only.
    #[cfg(test)]
    pub(crate) fn plain_http(github_api: Url, registry: Url) -> Self {
        Self {
            github_api,
            registry,
            https_only: false,
        }
    }
}

fn check_endpoint(url: &Url) -> Result<(), FetchError> {
    let refuse = |reason| {
        Err(FetchError::Endpoint {
            url: url.to_string(),
            reason,
        })
    };
    if url.scheme() != "https" {
        return refuse("not https");
    }
    if url.host_str().is_none() {
        return refuse("no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refuse("carries credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return refuse("carries a query or a fragment");
    }
    Ok(())
}

/// Fetches tag objects from the GitHub API and image indexes and bundles
/// from an OCI registry.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: Client,
    endpoints: Endpoints,
    /// Sent to the GitHub API only, never to the registry.
    github_token: Option<HeaderValue>,
}

impl Fetcher {
    /// A fetcher for `endpoints`, without a GitHub token.
    ///
    /// # Errors
    ///
    /// [`FetchError::Client`] when the HTTP client cannot be built.
    pub fn new(endpoints: Endpoints) -> Result<Self, FetchError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .https_only(endpoints.https_only)
            .redirect(redirect::Policy::limited(MAX_REDIRECTS))
            .user_agent(concat!("landfall/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(FetchError::Client)?;
        Ok(Self {
            client,
            endpoints,
            github_token: None,
        })
    }

    /// Sends `token` to the GitHub API, for its higher rate limit. It is
    /// never sent to the registry.
    ///
    /// # Errors
    ///
    /// [`FetchError::Token`] when the token cannot be an HTTP header value.
    pub fn with_github_token(mut self, token: &str) -> Result<Self, FetchError> {
        let mut value =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| FetchError::Token)?;
        value.set_sensitive(true);
        self.github_token = Some(value);
        Ok(self)
    }

    /// The raw signed tag object for `tag`: the bytes `git cat-file tag`
    /// prints, rebuilt from GitHub's signed payload and signature.
    ///
    /// # Errors
    ///
    /// [`FetchError::LightweightTag`] when the tag is not a tag object,
    /// [`FetchError::NotSigned`] when it carries no signature,
    /// [`FetchError::ObjectId`] when the bytes do not hash to the tag
    /// object's id, and the transport and parsing errors.
    pub async fn tag_object(
        &self,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<Vec<u8>, FetchError> {
        let reference = self.tag_ref(repo, tag).await?;
        match reference.kind.as_str() {
            "tag" => {}
            "commit" => return Err(FetchError::LightweightTag { tag: tag.clone() }),
            other => {
                return Err(FetchError::ObjectType {
                    tag: tag.clone(),
                    found: other.to_owned(),
                });
            }
        }
        let object = self.git_tag(repo, &reference.sha).await?;
        let Some(Verification {
            payload: Some(payload),
            signature: Some(signature),
        }) = object.verification
        else {
            return Err(FetchError::NotSigned { tag: tag.clone() });
        };
        let mut raw = payload.into_bytes();
        raw.extend_from_slice(signature.as_bytes());
        let computed = git_tag_id(&raw);
        if computed != reference.sha {
            return Err(FetchError::ObjectId {
                expected: reference.sha,
                computed,
            });
        }
        Ok(raw)
    }

    /// The commit `tag` points at, peeling annotated tag objects. For
    /// deployments that do not require signed tags.
    ///
    /// # Errors
    ///
    /// [`FetchError::ObjectType`] when the tag ends at a tree or blob,
    /// [`FetchError::TagDepth`] for a chain of too many tag objects, and the
    /// transport and parsing errors.
    pub async fn tag_commit(
        &self,
        repo: &RepoName,
        tag: &ReleaseTag,
    ) -> Result<CommitSha, FetchError> {
        let mut object = self.tag_ref(repo, tag).await?;
        for _ in 0..=MAX_TAG_DEPTH {
            match object.kind.as_str() {
                "commit" => {
                    return object.sha.parse().map_err(|_| FetchError::Malformed {
                        url: self.endpoints.github_api.to_string(),
                        reason: format!(
                            "commit id {:?} is not 40 lowercase hex digits",
                            object.sha
                        ),
                    });
                }
                "tag" => object = self.git_tag(repo, &object.sha).await?.object,
                other => {
                    return Err(FetchError::ObjectType {
                        tag: tag.clone(),
                        found: other.to_owned(),
                    });
                }
            }
        }
        Err(FetchError::TagDepth { tag: tag.clone() })
    }

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
    /// [`FetchError::MediaType`] for a single-platform manifest or any other
    /// media type, [`FetchError::Digest`] when the header disagrees with the
    /// bytes, and the transport and parsing errors.
    pub async fn resolve_index(
        &self,
        image: &str,
        tag: &ReleaseTag,
    ) -> Result<(ImageDigest, Vec<Platform>), FetchError> {
        check_image(image)?;
        let token = self.registry_token(image).await?;
        let mut segments = vec!["v2"];
        segments.extend(image.split('/'));
        segments.push("manifests");
        segments.extend(tag.as_ref().split('/'));
        let url = join(&self.endpoints.registry, &segments)?;
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
            .collect();
        Ok((digest, platforms))
    }

    /// The Sigstore bundle attached to `digest` in `image`, found through
    /// the referrers tag schema: the tag `sha256-<hex>` names an index of
    /// referrer manifests (or one manifest); exactly one of them must have
    /// the bundle artifact type, refer to `digest`, and hold one layer, the
    /// bundle, whose bytes must match its descriptor.
    ///
    /// # Errors
    ///
    /// [`FetchError::Bundles`] when no bundle or several bundles refer to
    /// the digest, [`FetchError::Digest`] when a manifest or the bundle does
    /// not match its descriptor, and the transport and parsing errors.
    pub async fn bundle(&self, image: &str, digest: &ImageDigest) -> Result<Vec<u8>, FetchError> {
        check_image(image)?;
        let token = self.registry_token(image).await?;
        let referrers_tag = digest.as_ref().replacen(':', "-", 1);
        let url = self.manifest_url(image, &referrers_tag)?;
        let accept = format!("{OCI_INDEX}, {OCI_MANIFEST}");
        let no_bundle = || FetchError::Bundles {
            digest: digest.clone(),
            count: 0,
        };
        let response = match self
            .registry_get(&url, &accept, Some(&token), MANIFEST_LIMIT)
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
                    .filter(|m| m.artifact_type.as_deref() == Some(BUNDLE_TYPE))
                    .collect();
                let [descriptor] = bundles.as_slice() else {
                    return Err(FetchError::Bundles {
                        digest: digest.clone(),
                        count: bundles.len(),
                    });
                };
                let manifest_url = self.manifest_url(image, descriptor.digest.as_ref())?;
                let response = self
                    .registry_get(&manifest_url, OCI_MANIFEST, Some(&token), MANIFEST_LIMIT)
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
                (manifest_url, manifest)
            }
            OCI_MANIFEST => {
                let manifest: Manifest = parse(&url, &response.body)?;
                if manifest.artifact_type() != BUNDLE_TYPE {
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
        if usize::try_from(layer.size).map_or(true, |size| size > BUNDLE_LIMIT) {
            return Err(FetchError::TooLarge {
                url: manifest_url.to_string(),
                limit: BUNDLE_LIMIT,
            });
        }
        let mut segments = vec!["v2"];
        segments.extend(image.split('/'));
        segments.extend(["blobs", layer.digest.as_ref()]);
        let blob_url = join(&self.endpoints.registry, &segments)?;
        let response = self
            .registry_get(&blob_url, BUNDLE_TYPE, Some(&token), BUNDLE_LIMIT)
            .await?;
        layer.check_content(&blob_url, &response.body)?;
        Ok(response.body)
    }

    /// `GET /repos/<repo>/git/ref/tags/<tag>`: the object the tag ref names.
    async fn tag_ref(&self, repo: &RepoName, tag: &ReleaseTag) -> Result<GitObject, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["git", "ref", "tags"]);
        segments.extend(tag.as_ref().split('/'));
        let url = join(&self.endpoints.github_api, &segments)?;
        let body = self.github_get(&url).await?;
        let reference: GitRef = parse(&url, &body)?;
        if reference.name != format!("refs/tags/{tag}") {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("asked for refs/tags/{tag}, got {:?}", reference.name),
            });
        }
        check_object_id(&url, &reference.object.sha)?;
        Ok(reference.object)
    }

    /// `GET /repos/<repo>/git/tags/<sha>`: the tag object `sha`.
    async fn git_tag(&self, repo: &RepoName, sha: &str) -> Result<GitTag, FetchError> {
        let mut segments = vec!["repos"];
        segments.extend(repo.as_ref().split('/'));
        segments.extend(["git", "tags", sha]);
        let url = join(&self.endpoints.github_api, &segments)?;
        let body = self.github_get(&url).await?;
        let object: GitTag = parse(&url, &body)?;
        if object.sha != sha {
            return Err(FetchError::Malformed {
                url: url.to_string(),
                reason: format!("asked for tag object {sha}, got {:?}", object.sha),
            });
        }
        check_object_id(&url, &object.object.sha)?;
        Ok(object)
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

    /// A GET to the GitHub API, with the token when there is one.
    async fn github_get(&self, url: &Url) -> Result<Vec<u8>, FetchError> {
        let mut request = self
            .client
            .get(url.clone())
            .header(ACCEPT, GITHUB_ACCEPT)
            .header("x-github-api-version", GITHUB_API_VERSION);
        if let Some(token) = &self.github_token {
            request = request.header(AUTHORIZATION, token.clone());
        }
        Ok(send(request, url, TAG_OBJECT_LIMIT).await?.body)
    }

    /// A GET to the registry, with its pull token when there is one; never
    /// with the GitHub token.
    async fn registry_get(
        &self,
        url: &Url,
        accept: &str,
        token: Option<&HeaderValue>,
        limit: usize,
    ) -> Result<Fetched, FetchError> {
        let mut request = self.client.get(url.clone()).header(ACCEPT, accept);
        if let Some(token) = token {
            request = request.header(AUTHORIZATION, token.clone());
        }
        send(request, url, limit).await
    }
}

/// A response that passed the status check, with its capped body.
struct Fetched {
    headers: HeaderMap,
    body: Vec<u8>,
}

/// Sends `request`, refuses any status but 200, and reads at most `limit`
/// bytes of body.
async fn send(
    request: reqwest::RequestBuilder,
    url: &Url,
    limit: usize,
) -> Result<Fetched, FetchError> {
    let transport = |source| FetchError::Request {
        url: url.to_string(),
        source,
    };
    let mut response = request.send().await.map_err(transport)?;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => {
            return Err(FetchError::NotFound {
                url: url.to_string(),
            });
        }
        status => {
            return Err(FetchError::Status {
                url: url.to_string(),
                status: status.as_u16(),
            });
        }
    }
    let too_large = || FetchError::TooLarge {
        url: url.to_string(),
        limit,
    };
    // A declared length over the cap is refused before any byte is read; an
    // absent or false one is caught while streaming. Never preallocate from it.
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        if chunk.len() > limit - body.len() {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        headers: response.headers().clone(),
        body,
    })
}

/// `base` with `segments` appended to its path, each percent-encoded.
fn join(base: &Url, segments: &[&str]) -> Result<Url, FetchError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| FetchError::Endpoint {
            url: base.to_string(),
            reason: "cannot be a base URL",
        })?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

fn parse<'a, T: Deserialize<'a>>(url: &Url, body: &'a [u8]) -> Result<T, FetchError> {
    serde_json::from_slice(body).map_err(|source| FetchError::Json {
        url: url.to_string(),
        source,
    })
}

/// The media type of a response, without parameters.
fn media_type(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

/// The sha256 digest of the body, which must equal `Docker-Content-Digest`
/// when the response has that header.
fn content_digest(url: &Url, response: &Fetched) -> Result<ImageDigest, FetchError> {
    let computed = sha256_digest(&response.body);
    if let Some(header) = response.headers.get("docker-content-digest") {
        let expected = header.to_str().map_err(|_| FetchError::Malformed {
            url: url.to_string(),
            reason: "Docker-Content-Digest is not ASCII".to_owned(),
        })?;
        if expected != computed {
            return Err(FetchError::Digest {
                url: url.to_string(),
                expected: expected.to_owned(),
                computed,
            });
        }
    }
    computed.parse().map_err(|_| FetchError::Malformed {
        url: url.to_string(),
        reason: format!("computed digest {computed} did not parse"),
    })
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// The git object id of a tag object with content `raw`.
fn git_tag_id(raw: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("tag {}\0", raw.len()).as_bytes());
    hasher.update(raw);
    hex(&hasher.finalize())
}

/// Lowercase hex.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 0x0f)]),
            ]
        })
        .collect()
}

/// Refuses an object id that is not 40 lowercase hex digits (SHA-1; GitHub
/// does not host SHA-256 repositories).
fn check_object_id(url: &Url, sha: &str) -> Result<(), FetchError> {
    if sha.len() == 40 && sha.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Ok(())
    } else {
        Err(FetchError::Malformed {
            url: url.to_string(),
            reason: format!("object id {sha:?} is not 40 lowercase hex digits"),
        })
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
struct GitRef {
    #[serde(rename = "ref")]
    name: String,
    object: GitObject,
}

#[derive(Deserialize)]
struct GitObject {
    sha: String,
    #[serde(rename = "type")]
    kind: String,
}

#[derive(Deserialize)]
struct GitTag {
    sha: String,
    object: GitObject,
    verification: Option<Verification>,
}

/// GitHub's view of a tag's signature: the object bytes before the
/// signature, and the signature. Both are null for an unsigned tag.
#[derive(Deserialize)]
struct Verification {
    payload: Option<String>,
    signature: Option<String>,
}

#[derive(Deserialize)]
struct RegistryToken {
    token: String,
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
        self.annotations
            .as_ref()
            .and_then(|a| a.get(REFERENCE_TYPE_ANNOTATION))
            .is_some_and(|kind| kind == ATTESTATION_MANIFEST)
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
}

impl Manifest {
    /// `artifactType`, or the config media type when it is absent (OCI image
    /// spec, "Guidelines for Artifact Usage").
    fn artifact_type(&self) -> &str {
        self.artifact_type
            .as_deref()
            .unwrap_or(&self.config.media_type)
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

#[cfg(test)]
mod tests {
    use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};
    use reqwest::Url;
    use serde_json::json;
    use sha1::Sha1;
    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        BUNDLE_TYPE, DOCKER_LIST, Endpoints, FetchError, Fetcher, MANIFEST_LIMIT, OCI_INDEX,
        OCI_MANIFEST, Platform, TAG_OBJECT_LIMIT, hex,
    };

    const VALID_TAG: &[u8] = include_bytes!("../../core/tests/fixtures/tag/valid.tag");
    const BUNDLE: &[u8] = include_bytes!("../tests/fixtures/attestation/bundle.json");
    const RELEASE_COMMIT: &str = "7160f743d0664e041913065355d7bcd291ad2a01";
    const IMAGE: &str = "example/app";
    const GITHUB_TOKEN: &str = "github-test-token";
    const REGISTRY_TOKEN: &str = "registry-test-token";

    fn repo() -> RepoName {
        "example/app".parse().unwrap()
    }

    fn tag() -> ReleaseTag {
        "v1.2.3".parse().unwrap()
    }

    fn sha256(bytes: &[u8]) -> String {
        format!("sha256:{}", hex(&Sha256::digest(bytes)))
    }

    fn tag_object_id(raw: &[u8]) -> String {
        let mut hasher = Sha1::new();
        hasher.update(format!("tag {}\0", raw.len()).as_bytes());
        hasher.update(raw);
        hex(&hasher.finalize())
    }

    fn fetcher_for(github: &str, registry: &str) -> Fetcher {
        Fetcher::new(Endpoints::plain_http(
            Url::parse(github).unwrap(),
            Url::parse(registry).unwrap(),
        ))
        .unwrap()
    }

    fn fetcher(github: &MockServer, registry: &MockServer) -> Fetcher {
        fetcher_for(&github.uri(), &registry.uri())
    }

    /// The valid fixture split the way GitHub serves it.
    fn payload_and_signature(raw: &[u8]) -> (String, String) {
        let text = std::str::from_utf8(raw).unwrap();
        let at = text.find("-----BEGIN SSH SIGNATURE-----").unwrap();
        (text[..at].to_owned(), text[at..].to_owned())
    }

    async fn mount_ref(server: &MockServer, kind: &str, sha: &str) {
        Mock::given(method("GET"))
            .and(path("/repos/example/app/git/ref/tags/v1.2.3"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "ref": "refs/tags/v1.2.3",
                "object": { "sha": sha, "type": kind },
            })))
            .mount(server)
            .await;
    }

    async fn mount_tag(
        server: &MockServer,
        sha: &str,
        target: (&str, &str),
        signed: Option<(&str, &str)>,
    ) {
        let verification = match signed {
            Some((payload, signature)) => json!({
                "verified": false, "reason": "unknown_key",
                "payload": payload, "signature": signature,
            }),
            None => json!({
                "verified": false, "reason": "unsigned", "payload": null, "signature": null,
            }),
        };
        Mock::given(method("GET"))
            .and(path(format!("/repos/example/app/git/tags/{sha}")))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "sha": sha,
                "tag": "v1.2.3",
                "object": { "sha": target.0, "type": target.1 },
                "verification": verification,
            })))
            .mount(server)
            .await;
    }

    async fn mount_token(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/token"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({ "token": REGISTRY_TOKEN })),
            )
            .mount(server)
            .await;
    }

    async fn mount_manifest(
        server: &MockServer,
        reference: &str,
        media_type: &str,
        body: Vec<u8>,
        header_digest: Option<&str>,
    ) {
        let mut response = ResponseTemplate::new(200).set_body_raw(body, media_type);
        if let Some(digest) = header_digest {
            response = response.insert_header("docker-content-digest", digest);
        }
        Mock::given(method("GET"))
            .and(path(format!("/v2/{IMAGE}/manifests/{reference}")))
            .respond_with(response)
            .mount(server)
            .await;
    }

    async fn mount_blob(server: &MockServer, digest: &str, body: Vec<u8>) {
        Mock::given(method("GET"))
            .and(path(format!("/v2/{IMAGE}/blobs/{digest}")))
            .respond_with(ResponseTemplate::new(200).set_body_raw(body, BUNDLE_TYPE))
            .mount(server)
            .await;
    }

    /// A multi-arch index shaped like the one buildx pushes to GHCR: two
    /// platforms and an attestation manifest.
    fn index_body() -> Vec<u8> {
        let image = |n: u8| format!("sha256:{}", format!("{n:02x}").repeat(32));
        serde_json::to_vec_pretty(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": [
                { "mediaType": OCI_MANIFEST, "digest": image(1), "size": 2000,
                  "platform": { "architecture": "amd64", "os": "linux" } },
                { "mediaType": OCI_MANIFEST, "digest": image(2), "size": 566,
                  "annotations": {
                      "vnd.docker.reference.digest": image(1),
                      "vnd.docker.reference.type": "attestation-manifest" },
                  "platform": { "architecture": "unknown", "os": "unknown" } },
                { "mediaType": OCI_MANIFEST, "digest": image(3), "size": 2000,
                  "platform": { "architecture": "arm", "os": "linux", "variant": "v7" } },
            ],
        }))
        .unwrap()
    }

    fn release_digest() -> ImageDigest {
        sha256(b"the release index").parse().unwrap()
    }

    fn referrers_tag(digest: &ImageDigest) -> String {
        digest.as_ref().replace(':', "-")
    }

    /// A referrer manifest holding `bundle` as its one layer, shaped like the
    /// ones `actions/attest-build-provenance` pushes.
    fn bundle_manifest(subject: &ImageDigest, bundle: &[u8]) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_MANIFEST,
            "artifactType": BUNDLE_TYPE,
            "config": {
                "mediaType": "application/vnd.oci.empty.v1+json",
                "digest": sha256(b"{}"),
                "size": 2,
            },
            "layers": [
                { "mediaType": BUNDLE_TYPE, "digest": sha256(bundle), "size": bundle.len() },
            ],
            "subject": { "mediaType": OCI_INDEX, "digest": subject.as_ref(), "size": 3161 },
            "annotations": { "dev.sigstore.bundle.predicateType": "https://slsa.dev/provenance/v1" },
        }))
        .unwrap()
    }

    fn referrers_index(manifests: &[&[u8]]) -> Vec<u8> {
        let manifests: Vec<_> = manifests
            .iter()
            .map(|m| {
                json!({
                    "mediaType": OCI_MANIFEST,
                    "digest": sha256(m),
                    "size": m.len(),
                    "artifactType": BUNDLE_TYPE,
                })
            })
            .collect();
        serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": OCI_INDEX,
            "manifests": manifests,
        }))
        .unwrap()
    }

    /// Mounts the token, the referrers index and every manifest and blob.
    async fn mount_bundles(server: &MockServer, digest: &ImageDigest, bundles: &[&[u8]]) {
        mount_token(server).await;
        let manifests: Vec<Vec<u8>> = bundles.iter().map(|b| bundle_manifest(digest, b)).collect();
        for (manifest, bundle) in manifests.iter().zip(bundles) {
            mount_manifest(
                server,
                &sha256(manifest),
                OCI_MANIFEST,
                manifest.clone(),
                None,
            )
            .await;
            mount_blob(server, &sha256(bundle), bundle.to_vec()).await;
        }
        let refs: Vec<&[u8]> = manifests.iter().map(Vec::as_slice).collect();
        mount_manifest(
            server,
            &referrers_tag(digest),
            OCI_INDEX,
            referrers_index(&refs),
            None,
        )
        .await;
    }

    #[tokio::test]
    async fn tag_object_round_trips() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let sha = tag_object_id(VALID_TAG);
        let (payload, signature) = payload_and_signature(VALID_TAG);
        mount_ref(&github, "tag", &sha).await;
        mount_tag(
            &github,
            &sha,
            (RELEASE_COMMIT, "commit"),
            Some((&payload, &signature)),
        )
        .await;

        let raw = fetcher(&github, &registry)
            .tag_object(&repo(), &tag())
            .await
            .unwrap();
        assert_eq!(raw, VALID_TAG);
    }

    #[tokio::test]
    async fn lightweight_tag_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_ref(&github, "commit", RELEASE_COMMIT).await;

        let result = fetcher(&github, &registry)
            .tag_object(&repo(), &tag())
            .await;
        assert!(
            matches!(result, Err(FetchError::LightweightTag { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn unsigned_annotated_tag_is_not_signed() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let sha = "1".repeat(40);
        mount_ref(&github, "tag", &sha).await;
        mount_tag(&github, &sha, (RELEASE_COMMIT, "commit"), None).await;

        let result = fetcher(&github, &registry)
            .tag_object(&repo(), &tag())
            .await;
        assert!(
            matches!(result, Err(FetchError::NotSigned { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn tag_object_id_mismatch_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let sha = tag_object_id(VALID_TAG);
        let (payload, signature) = payload_and_signature(VALID_TAG);
        let altered = payload.replace("release v1.2.3", "release v1.2.4");
        mount_ref(&github, "tag", &sha).await;
        mount_tag(
            &github,
            &sha,
            (RELEASE_COMMIT, "commit"),
            Some((&altered, &signature)),
        )
        .await;

        let result = fetcher(&github, &registry)
            .tag_object(&repo(), &tag())
            .await;
        match result {
            Err(FetchError::ObjectId { expected, computed }) => {
                assert_eq!(expected, sha);
                assert_ne!(computed, sha);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn tag_commit_peels_annotated_and_lightweight() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_ref(&github, "commit", RELEASE_COMMIT).await;
        let commit = fetcher(&github, &registry)
            .tag_commit(&repo(), &tag())
            .await
            .unwrap();
        assert_eq!(commit, RELEASE_COMMIT.parse::<CommitSha>().unwrap());

        let annotated = MockServer::start().await;
        let (outer, inner) = ("1".repeat(40), "2".repeat(40));
        mount_ref(&annotated, "tag", &outer).await;
        mount_tag(&annotated, &outer, (&inner, "tag"), None).await;
        mount_tag(&annotated, &inner, (RELEASE_COMMIT, "commit"), None).await;
        let commit = fetcher(&annotated, &registry)
            .tag_commit(&repo(), &tag())
            .await
            .unwrap();
        assert_eq!(commit, RELEASE_COMMIT.parse::<CommitSha>().unwrap());

        let tree = MockServer::start().await;
        mount_ref(&tree, "tag", &outer).await;
        mount_tag(&tree, &outer, (&inner, "tree"), None).await;
        let result = fetcher(&tree, &registry).tag_commit(&repo(), &tag()).await;
        assert!(
            matches!(result, Err(FetchError::ObjectType { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn index_digest_is_computed_from_bytes() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let body = index_body();
        let expected = sha256(&body);
        mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

        let (digest, platforms) = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await
            .unwrap();
        assert_eq!(digest.as_ref(), expected);
        assert_eq!(
            platforms,
            [
                Platform {
                    os: "linux".into(),
                    architecture: "amd64".into(),
                    variant: None
                },
                Platform {
                    os: "linux".into(),
                    architecture: "arm".into(),
                    variant: Some("v7".into()),
                },
            ]
        );
    }

    #[tokio::test]
    async fn docker_manifest_list_is_accepted_with_matching_header() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let body = serde_json::to_vec(&json!({
            "schemaVersion": 2,
            "mediaType": DOCKER_LIST,
            "manifests": [{
                "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
                "digest": sha256(b"arm64"), "size": 1000,
                "platform": { "architecture": "arm64", "os": "linux", "variant": "v8" },
            }],
        }))
        .unwrap();
        let expected = sha256(&body);
        mount_manifest(&registry, "v1.2.3", DOCKER_LIST, body, Some(&expected)).await;

        let (digest, platforms) = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await
            .unwrap();
        assert_eq!(digest.as_ref(), expected);
        assert_eq!(platforms.len(), 1);
    }

    #[tokio::test]
    async fn manifest_digest_mismatch_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let body = index_body();
        let header = sha256(b"some other index");
        mount_manifest(&registry, "v1.2.3", OCI_INDEX, body.clone(), Some(&header)).await;

        let result = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await;
        match result {
            Err(FetchError::Digest {
                expected, computed, ..
            }) => {
                assert_eq!(expected, header);
                assert_eq!(computed, sha256(&body));
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn single_arch_manifest_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let body = bundle_manifest(&release_digest(), b"{}");
        mount_manifest(&registry, "v1.2.3", OCI_MANIFEST, body, None).await;

        let result = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await;
        match result {
            Err(FetchError::MediaType { found, .. }) => assert_eq!(found, OCI_MANIFEST),
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn index_whose_body_contradicts_its_media_type_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let mut index: serde_json::Value = serde_json::from_slice(&index_body()).unwrap();
        index["mediaType"] = json!(OCI_MANIFEST);
        let body = serde_json::to_vec(&index).unwrap();
        mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

        let result = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await;
        assert!(
            matches!(result, Err(FetchError::MediaType { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn bundle_is_found_by_referrers_tag() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let digest = release_digest();
        mount_bundles(&registry, &digest, &[BUNDLE]).await;

        let bundle = fetcher(&github, &registry)
            .bundle(IMAGE, &digest)
            .await
            .unwrap();
        assert_eq!(bundle, BUNDLE);
    }

    #[tokio::test]
    async fn bundle_manifest_tagged_directly_is_found() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let digest = release_digest();
        mount_token(&registry).await;
        let manifest = bundle_manifest(&digest, BUNDLE);
        mount_manifest(
            &registry,
            &referrers_tag(&digest),
            OCI_MANIFEST,
            manifest,
            None,
        )
        .await;
        mount_blob(&registry, &sha256(BUNDLE), BUNDLE.to_vec()).await;

        let bundle = fetcher(&github, &registry)
            .bundle(IMAGE, &digest)
            .await
            .unwrap();
        assert_eq!(bundle, BUNDLE);
    }

    #[tokio::test]
    async fn two_bundles_are_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let digest = release_digest();
        mount_bundles(&registry, &digest, &[BUNDLE, b"{\"another\":\"bundle\"}"]).await;

        let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
        assert!(
            matches!(result, Err(FetchError::Bundles { count: 2, .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn missing_referrers_tag_means_no_bundle() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;

        let result = fetcher(&github, &registry)
            .bundle(IMAGE, &release_digest())
            .await;
        assert!(
            matches!(result, Err(FetchError::Bundles { count: 0, .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn bundle_for_another_subject_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let digest = release_digest();
        let other: ImageDigest = sha256(b"another index").parse().unwrap();
        mount_token(&registry).await;
        let manifest = bundle_manifest(&other, BUNDLE);
        mount_manifest(
            &registry,
            &referrers_tag(&digest),
            OCI_MANIFEST,
            manifest,
            None,
        )
        .await;
        mount_blob(&registry, &sha256(BUNDLE), BUNDLE.to_vec()).await;

        let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
        assert!(
            matches!(result, Err(FetchError::Malformed { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn bundle_not_matching_its_descriptor_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let digest = release_digest();
        mount_token(&registry).await;
        let manifest = bundle_manifest(&digest, BUNDLE);
        mount_manifest(
            &registry,
            &referrers_tag(&digest),
            OCI_MANIFEST,
            manifest,
            None,
        )
        .await;
        let mut altered = BUNDLE.to_vec();
        altered[10] ^= 1;
        mount_blob(&registry, &sha256(BUNDLE), altered).await;

        let result = fetcher(&github, &registry).bundle(IMAGE, &digest).await;
        assert!(
            matches!(result, Err(FetchError::Digest { .. })),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn oversized_body_is_refused() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        mount_token(&registry).await;
        let body = vec![b' '; MANIFEST_LIMIT + 1];
        mount_manifest(&registry, "v1.2.3", OCI_INDEX, body, None).await;

        let result = fetcher(&github, &registry)
            .resolve_index(IMAGE, &tag())
            .await;
        assert!(
            matches!(
                result,
                Err(FetchError::TooLarge {
                    limit: MANIFEST_LIMIT,
                    ..
                })
            ),
            "{result:?}"
        );
    }

    /// Without a `Content-Length`, the cap is enforced on the bytes as they
    /// arrive: a chunked body one byte over the cap is refused.
    #[tokio::test]
    async fn oversized_chunked_body_is_refused() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            let mut buffer = [0_u8; 1024];
            while !request.windows(4).any(|w| w == b"\r\n\r\n") {
                let n = socket.read(&mut buffer).await.unwrap();
                request.extend_from_slice(&buffer[..n]);
            }
            let head = "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                        transfer-encoding: chunked\r\n\r\n";
            socket.write_all(head.as_bytes()).await.unwrap();
            let chunk = vec![b' '; 1024];
            let mut sent = 0;
            // The client hangs up once it is over the cap; writes then fail.
            while sent <= TAG_OBJECT_LIMIT {
                let frame = [format!("{:x}\r\n", chunk.len()).as_bytes(), &chunk, b"\r\n"].concat();
                if socket.write_all(&frame).await.is_err() {
                    return;
                }
                sent += chunk.len();
            }
            let _ = socket.write_all(b"0\r\n\r\n").await;
        });

        let base = format!("http://{address}");
        let result = fetcher_for(&base, &base).tag_object(&repo(), &tag()).await;
        assert!(
            matches!(
                result,
                Err(FetchError::TooLarge {
                    limit: TAG_OBJECT_LIMIT,
                    ..
                })
            ),
            "{result:?}"
        );
        server.await.unwrap();
    }

    #[tokio::test]
    async fn token_is_not_sent_to_registry() {
        let (github, registry) = (MockServer::start().await, MockServer::start().await);
        let sha = tag_object_id(VALID_TAG);
        let (payload, signature) = payload_and_signature(VALID_TAG);
        mount_ref(&github, "tag", &sha).await;
        mount_tag(
            &github,
            &sha,
            (RELEASE_COMMIT, "commit"),
            Some((&payload, &signature)),
        )
        .await;
        mount_manifest(&registry, "v1.2.3", OCI_INDEX, index_body(), None).await;
        let digest = release_digest();
        mount_bundles(&registry, &digest, &[BUNDLE]).await;

        let fetcher = fetcher(&github, &registry)
            .with_github_token(GITHUB_TOKEN)
            .unwrap();
        fetcher.tag_object(&repo(), &tag()).await.unwrap();
        fetcher.resolve_index(IMAGE, &tag()).await.unwrap();
        fetcher.bundle(IMAGE, &digest).await.unwrap();

        let authorization = |request: &wiremock::Request| {
            request
                .headers
                .get("authorization")
                .map(|v| v.to_str().unwrap().to_owned())
        };
        let to_github = github.received_requests().await.unwrap();
        assert!(!to_github.is_empty());
        for request in &to_github {
            assert_eq!(
                authorization(request).as_deref(),
                Some("Bearer github-test-token")
            );
        }
        let to_registry = registry.received_requests().await.unwrap();
        assert!(to_registry.len() >= 5);
        for request in &to_registry {
            let sent = authorization(request);
            assert!(
                sent.as_deref().is_none_or(|v| !v.contains(GITHUB_TOKEN)),
                "{} carried the GitHub token",
                request.url
            );
            if request.url.path().starts_with("/v2/") {
                assert_eq!(sent.as_deref(), Some("Bearer registry-test-token"));
            }
        }
    }

    #[test]
    fn endpoints_must_be_https() {
        let https = Url::parse("https://registry.example").unwrap();
        for bad in [
            "http://api.example",
            "https://user:pass@api.example",
            "https://api.example/?x=1",
            "https://api.example/#x",
        ] {
            let result = Endpoints::new(Url::parse(bad).unwrap(), https.clone());
            assert!(
                matches!(result, Err(FetchError::Endpoint { .. })),
                "{bad}: {result:?}"
            );
            let result = Endpoints::new(https.clone(), Url::parse(bad).unwrap());
            assert!(
                matches!(result, Err(FetchError::Endpoint { .. })),
                "{bad}: {result:?}"
            );
        }
        assert!(Endpoints::public().is_ok());
    }

    #[tokio::test]
    async fn image_name_is_validated() {
        let fetcher = fetcher_for("http://127.0.0.1:9", "http://127.0.0.1:9");
        for bad in [
            "",
            "Example/app",
            "example/../app",
            "example//app",
            "example/app?x",
            "-x/app",
            "example/app:tag",
        ] {
            let result = fetcher.resolve_index(bad, &tag()).await;
            assert!(
                matches!(result, Err(FetchError::Image(_))),
                "{bad:?}: {result:?}"
            );
        }
    }

    /// The attestation fixture's release, fetched from the real GitHub API
    /// and GHCR: the tag object, its commit, the index digest and the bundle.
    #[tokio::test]
    #[ignore = "network: runs nightly in advisories.yml"]
    async fn live_fixture_release() {
        const INDEX_DIGEST: &str = include_str!("../tests/fixtures/attestation/index-digest.txt");
        let fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
        let repo: RepoName = "dani-garcia/vaultwarden".parse().unwrap();
        let tag: ReleaseTag = "1.37.4".parse().unwrap();

        let raw = fetcher.tag_object(&repo, &tag).await.unwrap();
        assert!(raw.starts_with(b"object 7c188967e7a467b19b2757bc3326f9cf3ccae327\ntype commit\n"));
        let commit = fetcher.tag_commit(&repo, &tag).await.unwrap();
        assert_eq!(commit.as_ref(), "7c188967e7a467b19b2757bc3326f9cf3ccae327");

        let (digest, platforms) = fetcher
            .resolve_index("dani-garcia/vaultwarden", &tag)
            .await
            .unwrap();
        assert_eq!(digest.as_ref(), INDEX_DIGEST.trim());
        assert!(platforms.iter().all(|p| p.os == "linux"), "{platforms:?}");

        let bundle = fetcher
            .bundle("dani-garcia/vaultwarden", &digest)
            .await
            .unwrap();
        let served: serde_json::Value = serde_json::from_slice(&bundle).unwrap();
        let fixture: serde_json::Value = serde_json::from_slice(BUNDLE).unwrap();
        assert_eq!(served, fixture);
    }
}
