//! Mock GitHub API and registry responses shared by the fetcher and release
//! tests, shaped like what GitHub and GHCR serve.

use landfall_core::ids::ImageDigest;
use reqwest::Url;
use serde_json::json;
use sha1_checked::Digest as _;
use sha1_checked::Sha1;
use sha2::{Digest, Sha256};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use crate::fetch::{BUNDLE_TYPE, Endpoints, Fetcher, OCI_INDEX, OCI_MANIFEST, hex};

/// The pull token the mock registry hands out.
pub(crate) const REGISTRY_TOKEN: &str = "registry-test-token";

pub(crate) fn sha256(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// The git object id of a raw tag object.
pub(crate) fn tag_object_id(raw: &[u8]) -> String {
    let mut hasher = Sha1::new();
    hasher.update(format!("tag {}\0", raw.len()).as_bytes());
    hasher.update(raw);
    hex(&hasher.finalize())
}

pub(crate) fn fetcher_for(github: &str, registry: &str) -> Fetcher {
    Fetcher::new(Endpoints::plain_http(
        Url::parse(github).unwrap(),
        Url::parse(registry).unwrap(),
    ))
    .unwrap()
}

pub(crate) fn fetcher(github: &MockServer, registry: &MockServer) -> Fetcher {
    fetcher_for(&github.uri(), &registry.uri())
}

/// A raw tag object split the way GitHub serves it.
pub(crate) fn payload_and_signature(raw: &[u8]) -> (String, String) {
    let text = std::str::from_utf8(raw).unwrap();
    let at = text.find("-----BEGIN SSH SIGNATURE-----").unwrap();
    (text[..at].to_owned(), text[at..].to_owned())
}

/// The tag ref `tag` of `repo`, pointing at `sha` of type `kind`.
pub(crate) async fn mount_ref(server: &MockServer, repo: &str, tag: &str, kind: &str, sha: &str) {
    Mock::given(method("GET"))
        .and(path(format!("/repos/{repo}/git/ref/tags/{tag}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "ref": format!("refs/tags/{tag}"),
            "object": { "sha": sha, "type": kind },
        })))
        .mount(server)
        .await;
}

/// The tag object `sha` named `tag` in `repo`, pointing at `target`
/// (`(sha, type)`), with the `(payload, signature)` GitHub reports for a
/// signed tag.
pub(crate) async fn mount_tag(
    server: &MockServer,
    (repo, tag): (&str, &str),
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
        .and(path(format!("/repos/{repo}/git/tags/{sha}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "sha": sha,
            "tag": tag,
            "object": { "sha": target.0, "type": target.1 },
            "verification": verification,
        })))
        .mount(server)
        .await;
}

pub(crate) async fn mount_token(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "token": REGISTRY_TOKEN })))
        .mount(server)
        .await;
}

pub(crate) async fn mount_manifest(
    server: &MockServer,
    (image, reference): (&str, &str),
    media_type: &str,
    body: Vec<u8>,
    header_digest: Option<&str>,
) {
    let mut response = ResponseTemplate::new(200).set_body_raw(body, media_type);
    if let Some(digest) = header_digest {
        response = response.insert_header("docker-content-digest", digest);
    }
    Mock::given(method("GET"))
        .and(path(format!("/v2/{image}/manifests/{reference}")))
        .respond_with(response)
        .mount(server)
        .await;
}

pub(crate) async fn mount_blob(server: &MockServer, image: &str, digest: &str, body: Vec<u8>) {
    Mock::given(method("GET"))
        .and(path(format!("/v2/{image}/blobs/{digest}")))
        .respond_with(ResponseTemplate::new(200).set_body_raw(body, BUNDLE_TYPE))
        .mount(server)
        .await;
}

pub(crate) fn referrers_tag(digest: &ImageDigest) -> String {
    digest.as_ref().replace(':', "-")
}

/// A referrer manifest holding `bundle` as its one layer, shaped like the
/// ones `actions/attest-build-provenance` pushes, annotated with
/// `predicate`.
pub(crate) fn bundle_manifest(subject: &ImageDigest, bundle: &[u8], predicate: &str) -> Vec<u8> {
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
        "annotations": {
            "dev.sigstore.bundle.content": "dsse-envelope",
            "dev.sigstore.bundle.predicateType": predicate,
        },
    }))
    .unwrap()
}

/// A referrers index listing each manifest, its descriptor annotated with
/// the predicate type given (none when `None`), as GHCR serves it.
pub(crate) fn referrers_index(entries: &[(&[u8], Option<&str>)]) -> Vec<u8> {
    let manifests: Vec<_> = entries
        .iter()
        .map(|(manifest, predicate)| {
            let mut descriptor = json!({
                "mediaType": OCI_MANIFEST,
                "digest": sha256(manifest),
                "size": manifest.len(),
                "artifactType": BUNDLE_TYPE,
            });
            if let Some(predicate) = predicate {
                descriptor["annotations"] = json!({
                    "dev.sigstore.bundle.content": "dsse-envelope",
                    "dev.sigstore.bundle.predicateType": predicate,
                });
            }
            descriptor
        })
        .collect();
    serde_json::to_vec(&json!({
        "schemaVersion": 2,
        "mediaType": OCI_INDEX,
        "manifests": manifests,
    }))
    .unwrap()
}

/// Mounts the token, the referrers index and every manifest and blob of
/// `image`, each `(bundle, predicate type)` in a manifest and descriptor
/// annotated with that predicate type.
pub(crate) async fn mount_bundles(
    server: &MockServer,
    image: &str,
    digest: &ImageDigest,
    bundles: &[(&[u8], &str)],
) {
    mount_token(server).await;
    let manifests: Vec<Vec<u8>> = bundles
        .iter()
        .map(|(bundle, predicate)| bundle_manifest(digest, bundle, predicate))
        .collect();
    for (manifest, (bundle, _)) in manifests.iter().zip(bundles) {
        mount_manifest(
            server,
            (image, &sha256(manifest)),
            OCI_MANIFEST,
            manifest.clone(),
            None,
        )
        .await;
        mount_blob(server, image, &sha256(bundle), bundle.to_vec()).await;
    }
    let entries: Vec<(&[u8], Option<&str>)> = manifests
        .iter()
        .zip(bundles)
        .map(|(manifest, (_, predicate))| (manifest.as_slice(), Some(*predicate)))
        .collect();
    mount_manifest(
        server,
        (image, &referrers_tag(digest)),
        OCI_INDEX,
        referrers_index(&entries),
        None,
    )
    .await;
}
