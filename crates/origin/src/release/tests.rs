//! Release verification against a mock GitHub and a mock registry.

use landfall_core::config::{self, Config};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::release::Platform;
use wiremock::MockServer;

use super::{ReleaseError, ReleaseOrigin, verify_release};
use crate::fetch::OCI_INDEX;
use crate::test_support::{
    fetcher, mount_manifest, mount_ref, mount_tag, mount_token, payload_and_signature,
    tag_object_id,
};
use crate::trust::TrustRoot;

mod attestations;
mod errors;
mod tags;

const SIGNER: &str = include_str!("../../../core/tests/fixtures/tag/signer.pub");

const VALID_TAG: &[u8] = include_bytes!("../../../core/tests/fixtures/tag/valid.tag");

/// Signed by the same key as `VALID_TAG`, named like the attestation
/// fixture's tag, on `SIGNED_COMMIT`.
const OTHER_COMMIT_TAG: &[u8] = include_bytes!("../../../core/tests/fixtures/tag/other-commit.tag");

const SIGNED_COMMIT: &str = "7160f743d0664e041913065355d7bcd291ad2a01";

const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/attestation/bundle.json");

const INDEX: &[u8] = include_bytes!("../../tests/fixtures/attestation/index.json");

const TRUSTED_ROOT: &str = include_str!("../../tests/fixtures/attestation/trusted_root.json");

const VW_REPO: &str = "dani-garcia/vaultwarden";

const VW_TAG: &str = "1.37.4";

const VW_COMMIT: &str = "7c188967e7a467b19b2757bc3326f9cf3ccae327";

const VW_DIGEST: &str = "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055";

/// A configuration with one deployment, `app/prod`, of `repo` (a TOML
/// inline table) with `origin` (another).
fn config(repo: &str, origin: &str) -> Config {
    let text = format!(
        r#"
[signers]
maintainer = "{}"

[approvers]
operator = {{ credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }}

[[deployment]]
id = "app/prod"
repo = {repo}
host = "host-1"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {origin}
rule = {{ approvers = ["operator"] }}
checks = ["container-healthy"]
"#,
        SIGNER.trim()
    );
    config::parse(text.as_bytes()).unwrap()
}

/// A signed deployment of `example/app`, releases `v*`.
fn signed_config() -> Config {
    config(
        r#"{ name = "example/app", id = 1, owner_id = 2 }"#,
        r#"{ workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }"#,
    )
}

/// An unsigned deployment of the attestation fixture's project, with
/// `repo_id` as its repository id (the real one is 121898717).
fn unsigned_config(repo_id: u64) -> Config {
    config(
        &format!(r#"{{ name = "{VW_REPO}", id = {repo_id}, owner_id = 725423 }}"#),
        r#"{ workflow = ".github/workflows/release.yml", tags = "*", signed_tags = false }"#,
    )
}

/// A signed deployment of the attestation fixture's project, with its
/// real ids, trusting the signed-tag fixtures' key.
fn signed_fixture_project_config() -> Config {
    config(
        &format!(r#"{{ name = "{VW_REPO}", id = 121898717, owner_id = 725423 }}"#),
        r#"{ workflow = ".github/workflows/release.yml", tags = "*", signers = ["maintainer"] }"#,
    )
}

fn root() -> TrustRoot {
    TrustRoot::from_json(TRUSTED_ROOT)
}

fn deployment() -> DeploymentId {
    "app/prod".parse().unwrap()
}

fn platform(text: &str) -> Platform {
    text.parse().unwrap()
}

async fn verify(
    github: &MockServer,
    registry: &MockServer,
    config: &Config,
    tag: &str,
    want: &str,
) -> Result<ReleaseOrigin, ReleaseError> {
    let tag: ReleaseTag = tag.parse().unwrap();
    verify_release(
        &fetcher(github, registry),
        &root(),
        config,
        &deployment(),
        &tag,
        &platform(want),
    )
    .await
}

async fn servers() -> (MockServer, MockServer) {
    (MockServer::start().await, MockServer::start().await)
}

/// GitHub serves `raw` as the signed tag object `v1.2.3` of `example/app`.
async fn mount_signed_tag(github: &MockServer, raw: &[u8]) {
    mount_signed_tag_of(github, ("example/app", "v1.2.3"), raw).await;
}

/// GitHub serves `raw` as the signed tag object `tag` of `repo`.
async fn mount_signed_tag_of(github: &MockServer, (repo, tag): (&str, &str), raw: &[u8]) {
    let sha = tag_object_id(raw);
    let (payload, signature) = payload_and_signature(raw);
    mount_ref(github, repo, tag, "tag", &sha).await;
    mount_tag(
        github,
        (repo, tag),
        &sha,
        (SIGNED_COMMIT, "commit"),
        Some((&payload, &signature)),
    )
    .await;
}

/// GitHub serves the fixture project's tag as a lightweight tag of the
/// release commit, and the registry its real index.
async fn mount_unsigned_release(github: &MockServer, registry: &MockServer) {
    mount_ref(github, VW_REPO, VW_TAG, "commit", VW_COMMIT).await;
    mount_token(registry).await;
    mount_manifest(
        registry,
        (VW_REPO, VW_TAG),
        OCI_INDEX,
        INDEX.to_vec(),
        Some(VW_DIGEST),
    )
    .await;
}
