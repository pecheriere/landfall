//! The fetchers against a mock GitHub and a mock registry.

use landfall_core::ids::{ImageDigest, ReleaseTag, RepoName};
use serde_json::json;
use wiremock::MockServer;

use super::{OCI_INDEX, OCI_MANIFEST};
use crate::test_support::sha256;

mod bundles;
mod errors;
mod tags_and_indexes;
mod validation;

const VALID_TAG: &[u8] = include_bytes!("../../../core/tests/fixtures/tag/valid.tag");

const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/attestation/bundle.json");

const RELEASE_COMMIT: &str = "7160f743d0664e041913065355d7bcd291ad2a01";

const IMAGE: &str = "example/app";

const GITHUB_TOKEN: &str = "github-test-token";

const SBOM: &str = "https://spdx.dev/Document/v2.3";

fn repo() -> RepoName {
    "example/app".parse().unwrap()
}

fn tag() -> ReleaseTag {
    "v1.2.3".parse().unwrap()
}

async fn mount_ref(server: &MockServer, kind: &str, sha: &str) {
    crate::test_support::mount_ref(server, IMAGE, "v1.2.3", kind, sha).await;
}

async fn mount_tag(
    server: &MockServer,
    sha: &str,
    target: (&str, &str),
    signed: Option<(&str, &str)>,
) {
    crate::test_support::mount_tag(server, (IMAGE, "v1.2.3"), sha, target, signed).await;
}

async fn mount_manifest(
    server: &MockServer,
    reference: &str,
    media_type: &str,
    body: Vec<u8>,
    header_digest: Option<&str>,
) {
    crate::test_support::mount_manifest(
        server,
        (IMAGE, reference),
        media_type,
        body,
        header_digest,
    )
    .await;
}

async fn mount_blob(server: &MockServer, digest: &str, body: Vec<u8>) {
    crate::test_support::mount_blob(server, IMAGE, digest, body).await;
}

async fn mount_bundles(server: &MockServer, digest: &ImageDigest, bundles: &[(&[u8], &str)]) {
    crate::test_support::mount_bundles(server, IMAGE, digest, bundles).await;
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
