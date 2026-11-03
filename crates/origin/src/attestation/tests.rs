//! Attestation verification against a real bundle and edited copies of it.

use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};
use serde_json::Value;

use super::{AttestationError, CertificateIdentity, Expected, verify_bundle};
use crate::trust::TrustRoot;

mod bundles;
mod files;
mod identity;

const BUNDLE: &[u8] = include_bytes!("../../tests/fixtures/attestation/bundle.json");

const TRUSTED_ROOT: &str = include_str!("../../tests/fixtures/attestation/trusted_root.json");

const INDEX_DIGEST: &str = include_str!("../../tests/fixtures/attestation/index-digest.txt");

const REPO: &str = "dani-garcia/vaultwarden";

const REPO_ID: u64 = 121_898_717;

const OWNER_ID: u64 = 725_423;

const WORKFLOW: &str = ".github/workflows/release.yml";

const TAG: &str = "1.37.4";

const COMMIT: &str = "7c188967e7a467b19b2757bc3326f9cf3ccae327";

const SAN: &str =
    "https://github.com/dani-garcia/vaultwarden/.github/workflows/release.yml@refs/tags/1.37.4";

const RUN_URL: &str =
    "https://github.com/dani-garcia/vaultwarden/actions/runs/37388798451/attempts/1";

const REKOR_LOG_INDEX: u64 = 3_097_402_908;

const INTEGRATED_TIME: i64 = 1_791_243_479;

/// The configured values, owned, so a test can change one of them.
struct Config {
    repo: RepoName,
    repo_id: u64,
    owner_id: u64,
    workflow: String,
    tag: ReleaseTag,
    commit: CommitSha,
}

impl Config {
    fn fixture() -> Self {
        Self {
            repo: REPO.parse().unwrap(),
            repo_id: REPO_ID,
            owner_id: OWNER_ID,
            workflow: WORKFLOW.to_owned(),
            tag: TAG.parse().unwrap(),
            commit: COMMIT.parse().unwrap(),
        }
    }

    fn expected(&self) -> Expected<'_> {
        Expected {
            repo: &self.repo,
            repo_id: self.repo_id,
            owner_id: self.owner_id,
            workflow: &self.workflow,
            tag: &self.tag,
            commit: &self.commit,
        }
    }
}

fn root() -> TrustRoot {
    TrustRoot::from_json(TRUSTED_ROOT)
}

fn digest() -> ImageDigest {
    INDEX_DIGEST.trim().parse().unwrap()
}

fn verify(bundle: &[u8], config: &Config) -> Result<(), AttestationError> {
    verify_bundle(bundle, &digest(), &root(), &config.expected()).map(|_| ())
}

/// The fixture bundle, edited as JSON.
fn edited_bundle(edit: impl FnOnce(&mut Value)) -> Vec<u8> {
    let mut bundle: Value = serde_json::from_slice(BUNDLE).unwrap();
    edit(&mut bundle);
    serde_json::to_vec(&bundle).unwrap()
}

/// A wrong configuration: its name, the change, the claim it must name.
type Case = (&'static str, fn(&mut Config), &'static str);

/// The identity claims of the fixture's certificate.
fn fixture_identity() -> CertificateIdentity {
    CertificateIdentity {
        san: Some(SAN.to_owned()),
        issuer: Some("https://token.actions.githubusercontent.com".to_owned()),
        build_config_uri: Some(SAN.to_owned()),
        source_repository_digest: Some(COMMIT.to_owned()),
        source_repository_ref: Some(format!("refs/tags/{TAG}")),
        source_repository_identifier: Some(REPO_ID.to_string()),
        source_repository_owner_identifier: Some(OWNER_ID.to_string()),
        build_trigger: Some("push".to_owned()),
        runner_environment: Some("github-hosted".to_owned()),
        run_invocation_uri: Some(RUN_URL.to_owned()),
    }
}

fn mismatched_field<T: std::fmt::Debug>(result: Result<T, AttestationError>) -> &'static str {
    match result {
        Err(AttestationError::Identity { field, .. }) => field,
        other => panic!("expected an identity mismatch, got {other:?}"),
    }
}
