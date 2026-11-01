//! GitHub build-provenance bundles: Sigstore verification and Fulcio identity.

use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};
use sigstore_verify::crypto::CertificateInfo;
use sigstore_verify::types::{
    Artifact, Bundle, MediaType, Sha256Hash, SignatureContent, Statement,
};
use sigstore_verify::{SubjectAltName, VerificationPolicy, Verifier};
use thiserror::Error;

pub use sigstore_verify::trust_root::TrustedRoot;

/// What the bundle must say, taken from the deployment's configuration and
/// the verified release tag.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// `<owner>/<repo>`, compared ASCII case-insensitively.
    pub repo: &'a RepoName,
    /// GitHub repository id.
    pub repo_id: u64,
    /// GitHub owner id.
    pub owner_id: u64,
    /// Workflow path, `.github/workflows/<name>.yml`.
    pub workflow: &'a str,
    /// The release tag.
    pub tag: &'a ReleaseTag,
    /// The release commit.
    pub commit: &'a CommitSha,
}

/// The facts a verified bundle establishes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedAttestation {
    /// The image index digest the bundle attests.
    pub digest: ImageDigest,
    /// The certificate's SAN.
    pub san: String,
    /// Source Repository Digest.
    pub commit: CommitSha,
    /// Source Repository Ref.
    pub git_ref: String,
    /// Source Repository Identifier.
    pub repo_id: u64,
    /// Source Repository Owner Identifier.
    pub owner_id: u64,
    /// Run Invocation URI.
    pub run_url: String,
    /// Rekor log index of the entry.
    pub rekor_log_index: u64,
    /// Rekor integrated time, seconds since the Unix epoch.
    pub integrated_time: i64,
}

/// The claims of a certificate that passed [`match_identity`] and are not
/// already known from the configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct MatchedIdentity<'a> {
    /// The SAN, with the repository name in the certificate's case.
    san: &'a str,
    /// Source Repository Ref.
    git_ref: &'a str,
    /// Run Invocation URI.
    run_url: &'a str,
}

/// The identity claims of a Fulcio certificate that landfall checks.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
struct CertificateIdentity {
    /// SAN URI.
    san: Option<String>,
    /// OIDC issuer.
    issuer: Option<String>,
    /// Build Config URI.
    build_config_uri: Option<String>,
    /// Source Repository Digest.
    source_repository_digest: Option<String>,
    /// Source Repository Ref.
    source_repository_ref: Option<String>,
    /// Source Repository Identifier.
    source_repository_identifier: Option<String>,
    /// Source Repository Owner Identifier.
    source_repository_owner_identifier: Option<String>,
    /// Build Trigger.
    build_trigger: Option<String>,
    /// Runner Environment.
    runner_environment: Option<String>,
    /// Run Invocation URI.
    run_invocation_uri: Option<String>,
}

/// Why a bundle was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum AttestationError {
    /// Not a parseable build-provenance bundle.
    #[error("malformed bundle: {0}")]
    Bundle(String),
    /// The Sigstore verification failed.
    #[error("bundle does not verify: {0}")]
    Signature(String),
    /// The signed statement is not a SLSA build provenance attestation.
    #[error("attestation predicate type is {found:?}, expected {expected:?}")]
    PredicateType {
        /// [`SLSA_PROVENANCE`].
        expected: String,
        /// The statement's predicate type.
        found: String,
    },
    /// The bundle attests another digest.
    #[error("bundle attests {found}, not {expected}")]
    Subject {
        /// The digest asked for.
        expected: String,
        /// The digests the bundle names.
        found: String,
    },
    /// A certificate claim differs from the configuration.
    #[error("certificate {field} is {found:?}, expected {expected:?}")]
    Identity {
        /// The claim that differed.
        field: &'static str,
        /// The configured value.
        expected: String,
        /// The certificate's value.
        found: String,
    },
}

/// The OIDC issuer of GitHub Actions workflow identities.
pub const GITHUB_ISSUER: &str = "https://token.actions.githubusercontent.com";

/// The largest bundle accepted, in bytes. A GitHub build-provenance bundle is
/// around 10 KiB.
pub const MAX_BUNDLE_BYTES: usize = 4 << 20;

/// The in-toto predicate type of a SLSA build provenance attestation.
pub const SLSA_PROVENANCE: &str = "https://slsa.dev/provenance/v1";

/// The in-toto payload type of an attestation.
const IN_TOTO_PAYLOAD_TYPE: &str = "application/vnd.in-toto+json";

/// Shown for a claim the certificate does not carry.
const ABSENT: &str = "<absent>";

/// Verifies `bundle_json` for `digest` against `root` and `expected`.
///
/// In order: the bundle parses as a DSSE in-toto attestation of at most
/// [`MAX_BUNDLE_BYTES`], in bundle format v0.3 only (the media type is not
/// signed, and older formats need no inclusion proof); its statement has
/// predicate type [`SLSA_PROVENANCE`] and names `digest` as a subject; it has exactly one transparency log entry, a Rekor
/// v1 entry with an inclusion proof, its signed checkpoint and an inclusion
/// promise (signed entry timestamp), all required (Rekor v2 entries, which
/// carry no promise, are refused); the Sigstore verification passes (certificate chain to the Fulcio roots,
/// signed certificate timestamp, Rekor inclusion proof and checkpoint,
/// signature over the payload); the certificate's identity satisfies
/// the identity rules below. Only certificate claims are trusted, never the
/// provenance predicate.
///
/// Identity rules, each compared exactly unless noted: issuer
/// [`GITHUB_ISSUER`]; Source Repository Identifier and Owner Identifier equal
/// to the configured ids; Source Repository Ref `refs/tags/<tag>`; Source
/// Repository Digest the release commit; SAN and Build Config URI both
/// `https://github.com/<repo>/<workflow>@refs/tags/<tag>`, the repository
/// name ASCII case-insensitive (the configured workflow signed and was the
/// workflow that ran: a call of it as a reusable workflow is refused); Build
/// Trigger `push`; Runner Environment `github-hosted`; a Run Invocation URI
/// present.
///
/// # Errors
///
/// Returns [`AttestationError`] naming the first check that failed.
pub fn verify_bundle(
    bundle_json: &[u8],
    digest: &ImageDigest,
    root: &TrustedRoot,
    expected: &Expected<'_>,
) -> Result<VerifiedAttestation, AttestationError> {
    let bundle = parse_bundle(bundle_json)?;
    check_statement(&bundle, digest)?;
    let rekor_log_index = single_log_index(&bundle)?;

    let hex = digest
        .as_ref()
        .strip_prefix("sha256:")
        .ok_or_else(|| AttestationError::Subject {
            expected: digest.to_string(),
            found: "a digest that is not sha256".to_owned(),
        })?;
    let artifact = Sha256Hash::from_hex(hex)
        .map(Artifact::from_digest)
        .map_err(|e| AttestationError::Subject {
            expected: digest.to_string(),
            found: e.to_string(),
        })?;

    // The identity is matched below, claim by claim, so a refusal can name
    // the claim; the policy here only requires the cryptographic checks.
    let verifier = Verifier::new(root).map_err(|e| signature(&e))?;
    let result = verifier
        .verify(artifact, &bundle, &VerificationPolicy::any_identity())
        .map_err(|e| signature(&e))?;
    if !(result.certificate_verified() && result.sct_verified() && result.tlog_verified()) {
        return Err(AttestationError::Signature(
            "certificate chain, certificate timestamp or transparency log not verified".to_owned(),
        ));
    }
    let integrated_time = result
        .integrated_time()
        .ok_or_else(|| AttestationError::Signature("no verified Rekor integrated time".to_owned()))?
        .as_second();
    let certificate = result
        .certificate()
        .ok_or_else(|| AttestationError::Signature("no signing certificate".to_owned()))?;

    let identity = CertificateIdentity::from_certificate(certificate);
    let matched = match_identity(&identity, expected)?;
    Ok(VerifiedAttestation {
        digest: digest.clone(),
        san: matched.san.to_owned(),
        commit: expected.commit.clone(),
        git_ref: matched.git_ref.to_owned(),
        repo_id: expected.repo_id,
        owner_id: expected.owner_id,
        run_url: matched.run_url.to_owned(),
        rekor_log_index,
        integrated_time,
    })
}

/// Checks a certificate identity against `expected`, claim by claim:
/// issuer, repository and owner ids, ref, commit, SAN, build config URI,
/// build trigger, runner environment, and the presence of a run URL.
///
/// The SAN and the Build Config URI must both be
/// `https://github.com/<repo>/<workflow>@refs/tags/<tag>`: the configured
/// workflow both signed and was the workflow that ran, so a call of it as a
/// reusable workflow from another workflow is refused. The repository name
/// is compared ASCII case-insensitively, as GitHub treats it; everything
/// else is compared exactly.
///
/// # Errors
///
/// Returns [`AttestationError::Identity`] naming the first claim that differs.
fn match_identity<'a>(
    identity: &'a CertificateIdentity,
    expected: &Expected<'_>,
) -> Result<MatchedIdentity<'a>, AttestationError> {
    let git_ref = format!("refs/tags/{}", expected.tag);
    exact("issuer", identity.issuer.as_deref(), GITHUB_ISSUER)?;
    exact(
        "source_repository_identifier",
        identity.source_repository_identifier.as_deref(),
        &expected.repo_id.to_string(),
    )?;
    exact(
        "source_repository_owner_identifier",
        identity.source_repository_owner_identifier.as_deref(),
        &expected.owner_id.to_string(),
    )?;
    exact(
        "source_repository_ref",
        identity.source_repository_ref.as_deref(),
        &git_ref,
    )?;
    exact(
        "source_repository_digest",
        identity.source_repository_digest.as_deref(),
        expected.commit.as_ref(),
    )?;
    workflow_uri("san", identity.san.as_deref(), expected, &git_ref)?;
    workflow_uri(
        "build_config_uri",
        identity.build_config_uri.as_deref(),
        expected,
        &git_ref,
    )?;
    exact("build_trigger", identity.build_trigger.as_deref(), "push")?;
    exact(
        "runner_environment",
        identity.runner_environment.as_deref(),
        "github-hosted",
    )?;
    match (
        identity.san.as_deref(),
        identity.source_repository_ref.as_deref(),
        identity.run_invocation_uri.as_deref(),
    ) {
        (Some(san), Some(git_ref), Some(run_url)) => Ok(MatchedIdentity {
            san,
            git_ref,
            run_url,
        }),
        _ => Err(AttestationError::Identity {
            field: "run_invocation_uri",
            expected: "a run URL".to_owned(),
            found: ABSENT.to_owned(),
        }),
    }
}

impl CertificateIdentity {
    /// The claims of a parsed certificate. A SAN that is not a URI (an email
    /// address, issued to a person) is treated as absent.
    fn from_certificate(certificate: &CertificateInfo) -> Self {
        let claims = &certificate.ci_claims;
        Self {
            san: match &certificate.identity {
                Some(SubjectAltName::Uri(uri)) => Some(uri.clone()),
                _ => None,
            },
            issuer: certificate.issuer.clone(),
            build_config_uri: claims.build_config_uri.clone(),
            source_repository_digest: claims.source_repository_digest.clone(),
            source_repository_ref: claims.source_repository_ref.clone(),
            source_repository_identifier: claims.source_repository_identifier.clone(),
            source_repository_owner_identifier: claims.source_repository_owner_identifier.clone(),
            build_trigger: claims.build_trigger.clone(),
            runner_environment: claims.runner_environment.clone(),
            run_invocation_uri: claims.run_invocation_uri.clone(),
        }
    }
}

fn exact(field: &'static str, found: Option<&str>, expected: &str) -> Result<(), AttestationError> {
    if found == Some(expected) {
        Ok(())
    } else {
        Err(mismatch(field, expected.to_owned(), found))
    }
}

/// `https://github.com/<repo>/<workflow>@<git_ref>`, the repository name in
/// any ASCII case.
fn workflow_uri(
    field: &'static str,
    found: Option<&str>,
    expected: &Expected<'_>,
    git_ref: &str,
) -> Result<(), AttestationError> {
    const PREFIX: &str = "https://github.com/";
    let repo = expected.repo.as_ref();
    let suffix = format!("/{}@{git_ref}", expected.workflow);
    let matches = found.is_some_and(|uri| {
        uri.strip_prefix(PREFIX).is_some_and(|rest| {
            rest.len() == repo.len() + suffix.len()
                && rest
                    .as_bytes()
                    .get(..repo.len())
                    .is_some_and(|name| name.eq_ignore_ascii_case(repo.as_bytes()))
                && rest.as_bytes().get(repo.len()..) == Some(suffix.as_bytes())
        })
    });
    if matches {
        Ok(())
    } else {
        Err(mismatch(field, format!("{PREFIX}{repo}{suffix}"), found))
    }
}

fn mismatch(field: &'static str, expected: String, found: Option<&str>) -> AttestationError {
    AttestationError::Identity {
        field,
        expected,
        found: found.unwrap_or(ABSENT).to_owned(),
    }
}

fn signature(error: &sigstore_verify::Error) -> AttestationError {
    AttestationError::Signature(error.to_string())
}

fn parse_bundle(bundle_json: &[u8]) -> Result<Bundle, AttestationError> {
    if bundle_json.len() > MAX_BUNDLE_BYTES {
        return Err(AttestationError::Bundle(format!(
            "{} bytes, more than the {MAX_BUNDLE_BYTES} accepted",
            bundle_json.len()
        )));
    }
    let text = std::str::from_utf8(bundle_json)
        .map_err(|e| AttestationError::Bundle(format!("not UTF-8: {e}")))?;
    let bundle = Bundle::from_json(text).map_err(|e| AttestationError::Bundle(e.to_string()))?;
    // The media type is not signed, and older formats relax what the bundle
    // must carry (v0.1 needs no inclusion proof). GitHub emits v0.3.
    if bundle.media_type == MediaType::Bundle0_3 {
        Ok(bundle)
    } else {
        Err(AttestationError::Bundle(format!(
            "media type {}, only {} is accepted",
            bundle.media_type,
            MediaType::Bundle0_3
        )))
    }
}

/// Refuses a bundle whose in-toto statement is not a SLSA build provenance
/// attestation or does not name `digest`. The statement is the DSSE payload,
/// so the signature checked after this covers both; the Sigstore
/// verification checks the subject binding again, and checking first lets
/// the refusal say which predicate type or digests it found.
fn check_statement(bundle: &Bundle, digest: &ImageDigest) -> Result<(), AttestationError> {
    let SignatureContent::DsseEnvelope(envelope) = &bundle.content else {
        return Err(AttestationError::Bundle(
            "not a DSSE attestation".to_owned(),
        ));
    };
    if envelope.payload_type != IN_TOTO_PAYLOAD_TYPE {
        return Err(AttestationError::Bundle(format!(
            "payload type is not {IN_TOTO_PAYLOAD_TYPE}"
        )));
    }
    let statement: Statement = serde_json::from_slice(envelope.payload.as_bytes())
        .map_err(|e| AttestationError::Bundle(format!("in-toto statement: {e}")))?;
    if statement.predicate_type != SLSA_PROVENANCE {
        return Err(AttestationError::PredicateType {
            expected: SLSA_PROVENANCE.to_owned(),
            found: statement.predicate_type,
        });
    }
    let named: Vec<String> = statement
        .subject
        .iter()
        .filter_map(|subject| subject.digest.sha256.as_ref())
        .map(|hash| format!("sha256:{}", hash.to_hex()))
        .collect();
    if named.iter().any(|name| name == digest.as_ref()) {
        Ok(())
    } else {
        Err(AttestationError::Subject {
            expected: digest.to_string(),
            found: if named.is_empty() {
                "no sha256 subject".to_owned()
            } else {
                named.join(", ")
            },
        })
    }
}

/// The Rekor log index of the bundle's only transparency log entry, which
/// must carry both an inclusion proof and an inclusion promise.
///
/// The Sigstore verification checks each only when present. The inclusion
/// proof, with its signed checkpoint, is what proves the entry is in the
/// log. For a Rekor v1 entry it authenticates a shard-local index; the log
/// index users look an entry up by is signed only by the inclusion promise
/// (signed entry timestamp). Rekor v2 entries carry no promise, so they are
/// refused here.
fn single_log_index(bundle: &Bundle) -> Result<u64, AttestationError> {
    match bundle.verification_material.tlog_entries.as_slice() {
        [entry] if entry.inclusion_proof.is_none() => Err(AttestationError::Bundle(
            "transparency log entry has no inclusion proof".to_owned(),
        )),
        [entry] if entry.inclusion_promise.is_none() => Err(AttestationError::Bundle(
            "transparency log entry has no inclusion promise".to_owned(),
        )),
        [entry] => Ok(entry.log_index.get()),
        entries => Err(AttestationError::Bundle(format!(
            "{} transparency log entries, expected exactly one",
            entries.len()
        ))),
    }
}

#[cfg(test)]
mod tests {
    //! The real bundle is verified offline against a trusted-root snapshot;
    //! values come from `tests/fixtures/attestation/README.md`.

    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};
    use serde_json::Value;

    use super::{
        AttestationError, CertificateIdentity, Expected, TrustedRoot, match_identity, verify_bundle,
    };

    const BUNDLE: &[u8] = include_bytes!("../tests/fixtures/attestation/bundle.json");
    const TRUSTED_ROOT: &str = include_str!("../tests/fixtures/attestation/trusted_root.json");
    const INDEX_DIGEST: &str = include_str!("../tests/fixtures/attestation/index-digest.txt");

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

    fn root() -> TrustedRoot {
        TrustedRoot::from_json(TRUSTED_ROOT).unwrap()
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

    #[test]
    fn real_bundle_verifies() {
        let config = Config::fixture();
        let verified = verify_bundle(BUNDLE, &digest(), &root(), &config.expected()).unwrap();

        assert_eq!(verified.digest, digest());
        assert_eq!(verified.san, SAN);
        assert_eq!(verified.commit, config.commit);
        assert_eq!(verified.git_ref, "refs/tags/1.37.4");
        assert_eq!(verified.repo_id, REPO_ID);
        assert_eq!(verified.owner_id, OWNER_ID);
        assert_eq!(verified.run_url, RUN_URL);
        assert_eq!(verified.rekor_log_index, REKOR_LOG_INDEX);
        assert_eq!(verified.integrated_time, INTEGRATED_TIME);
    }

    #[test]
    fn repo_name_is_compared_case_insensitively() {
        let mut config = Config::fixture();
        config.repo = "Dani-Garcia/VaultWarden".parse().unwrap();
        assert_eq!(verify(BUNDLE, &config), Ok(()));
    }

    #[test]
    fn each_identity_mismatch_is_named() {
        let cases: [Case; 6] = [
            (
                "repo id",
                |c| c.repo_id = REPO_ID + 1,
                "source_repository_identifier",
            ),
            (
                "owner id",
                |c| c.owner_id = OWNER_ID + 1,
                "source_repository_owner_identifier",
            ),
            (
                "workflow",
                |c| c.workflow = ".github/workflows/docker.yml".to_owned(),
                "san",
            ),
            (
                "tag",
                |c| c.tag = "1.37.3".parse().unwrap(),
                "source_repository_ref",
            ),
            (
                "commit",
                |c| c.commit = "0000000000000000000000000000000000000000".parse().unwrap(),
                "source_repository_digest",
            ),
            (
                "repo name",
                |c| c.repo = "dani-garcia/vaultwardem".parse().unwrap(),
                "san",
            ),
        ];
        for (name, change, field) in cases {
            let mut config = Config::fixture();
            change(&mut config);
            assert_eq!(
                mismatched_field(verify(BUNDLE, &config)),
                field,
                "wrong {name}"
            );
        }
    }

    #[test]
    fn fixture_identity_matches() {
        let config = Config::fixture();
        let identity = fixture_identity();
        let matched = match_identity(&identity, &config.expected()).unwrap();
        assert_eq!(
            (matched.san, matched.git_ref, matched.run_url),
            (SAN, "refs/tags/1.37.4", RUN_URL)
        );
    }

    #[test]
    fn manual_trigger_is_refused() {
        let config = Config::fixture();
        let identity = CertificateIdentity {
            build_trigger: Some("workflow_dispatch".to_owned()),
            ..fixture_identity()
        };
        assert_eq!(
            match_identity(&identity, &config.expected()),
            Err(AttestationError::Identity {
                field: "build_trigger",
                expected: "push".to_owned(),
                found: "workflow_dispatch".to_owned(),
            })
        );
    }

    #[test]
    fn self_hosted_runner_is_refused() {
        let config = Config::fixture();
        let identity = CertificateIdentity {
            runner_environment: Some("self-hosted".to_owned()),
            ..fixture_identity()
        };
        assert_eq!(
            mismatched_field(match_identity(&identity, &config.expected())),
            "runner_environment"
        );
    }

    #[test]
    fn other_issuer_is_refused() {
        let config = Config::fixture();
        let identity = CertificateIdentity {
            issuer: Some("https://issuer.example".to_owned()),
            ..fixture_identity()
        };
        assert_eq!(
            mismatched_field(match_identity(&identity, &config.expected())),
            "issuer"
        );
    }

    #[test]
    fn reusable_workflow_call_is_refused() {
        // The configured workflow signed, but another workflow called it.
        let config = Config::fixture();
        let identity = CertificateIdentity {
            build_config_uri: Some(SAN.replace("release.yml", "caller.yml")),
            ..fixture_identity()
        };
        assert_eq!(
            mismatched_field(match_identity(&identity, &config.expected())),
            "build_config_uri"
        );
    }

    #[test]
    fn missing_claim_is_refused() {
        let config = Config::fixture();
        let identity = CertificateIdentity {
            source_repository_identifier: None,
            ..fixture_identity()
        };
        assert_eq!(
            mismatched_field(match_identity(&identity, &config.expected())),
            "source_repository_identifier"
        );
    }

    #[test]
    fn san_with_a_suffix_is_refused() {
        let config = Config::fixture();
        let identity = CertificateIdentity {
            san: Some(format!("{SAN}x")),
            ..fixture_identity()
        };
        assert_eq!(
            mismatched_field(match_identity(&identity, &config.expected())),
            "san"
        );
    }

    #[test]
    fn other_predicate_type_is_refused() {
        let config = Config::fixture();
        let sbom = edited_bundle(|b| {
            let payload = &mut b["dsseEnvelope"]["payload"];
            let mut statement: Value =
                serde_json::from_slice(&STANDARD.decode(payload.as_str().unwrap()).unwrap())
                    .unwrap();
            statement["predicateType"] = Value::from("https://spdx.dev/Document/v2.3");
            *payload = Value::from(STANDARD.encode(serde_json::to_vec(&statement).unwrap()));
        });
        assert_eq!(
            verify(&sbom, &config),
            Err(AttestationError::PredicateType {
                expected: "https://slsa.dev/provenance/v1".to_owned(),
                found: "https://spdx.dev/Document/v2.3".to_owned(),
            })
        );
    }

    #[test]
    fn wrong_digest_is_refused() {
        let other: ImageDigest = format!("sha256:{}", "ab".repeat(32)).parse().unwrap();
        let config = Config::fixture();
        let result = verify_bundle(BUNDLE, &other, &root(), &config.expected());
        assert_eq!(
            result,
            Err(AttestationError::Subject {
                expected: other.to_string(),
                found: digest().to_string(),
            })
        );
    }

    #[test]
    fn tampered_bundle_is_refused() {
        let config = Config::fixture();

        let signature = edited_bundle(|b| {
            let sig = &mut b["dsseEnvelope"]["signatures"][0]["sig"];
            let mut text = sig.as_str().unwrap().to_owned();
            let flipped = if text.as_bytes()[20] == b'A' {
                "B"
            } else {
                "A"
            };
            text.replace_range(20..21, flipped);
            *sig = Value::String(text);
        });
        assert!(
            matches!(
                verify(&signature, &config),
                Err(AttestationError::Signature(_))
            ),
            "flipped signature character"
        );

        let payload = edited_bundle(|b| {
            let field = &mut b["dsseEnvelope"]["payload"];
            let mut bytes = STANDARD.decode(field.as_str().unwrap()).unwrap();
            // A byte inside the predicate, so the statement still parses and
            // still names the right subject: only the signature can catch it.
            let at = bytes
                .windows(b"\"predicate\"".len())
                .position(|w| w == b"\"predicate\"")
                .unwrap();
            let letter = at
                + bytes[at..]
                    .iter()
                    .position(|b| b.is_ascii_lowercase() && *b != b'p')
                    .unwrap();
            bytes[letter] ^= 0x01;
            *field = Value::String(STANDARD.encode(bytes));
        });
        assert!(
            matches!(
                verify(&payload, &config),
                Err(AttestationError::Signature(_))
            ),
            "flipped payload byte"
        );

        let no_proof = edited_bundle(|b| {
            b["verificationMaterial"]["tlogEntries"][0]
                .as_object_mut()
                .unwrap()
                .remove("inclusionProof")
                .unwrap();
        });
        assert!(
            matches!(verify(&no_proof, &config), Err(AttestationError::Bundle(_))),
            "inclusion proof dropped"
        );

        let no_promise = edited_bundle(|b| {
            b["verificationMaterial"]["tlogEntries"][0]
                .as_object_mut()
                .unwrap()
                .remove("inclusionPromise")
                .unwrap();
        });
        assert!(
            matches!(
                verify(&no_promise, &config),
                Err(AttestationError::Bundle(_))
            ),
            "inclusion promise dropped"
        );

        let other_log_index = edited_bundle(|b| {
            b["verificationMaterial"]["tlogEntries"][0]["logIndex"] =
                Value::String((REKOR_LOG_INDEX + 1).to_string());
        });
        assert!(
            matches!(
                verify(&other_log_index, &config),
                Err(AttestationError::Signature(_))
            ),
            "log index changed"
        );
    }

    /// The fixture bundle relabelled as bundle format v0.1, which does not
    /// require an inclusion proof. The media type is not signed.
    fn downgraded_bundle(drop_proof: bool) -> Vec<u8> {
        edited_bundle(|b| {
            b["mediaType"] =
                Value::String("application/vnd.dev.sigstore.bundle+json;version=0.1".to_owned());
            if drop_proof {
                b["verificationMaterial"]["tlogEntries"][0]
                    .as_object_mut()
                    .unwrap()
                    .remove("inclusionProof")
                    .unwrap();
            }
        })
    }

    #[test]
    fn downgraded_media_type_without_proof_is_refused() {
        let config = Config::fixture();
        assert!(matches!(
            verify(&downgraded_bundle(true), &config),
            Err(AttestationError::Bundle(_))
        ));
    }

    #[test]
    fn downgraded_media_type_is_refused() {
        let config = Config::fixture();
        assert!(matches!(
            verify(&downgraded_bundle(false), &config),
            Err(AttestationError::Bundle(_))
        ));
    }

    #[test]
    fn garbage_is_refused() {
        let config = Config::fixture();
        for input in [&b""[..], b"{}", &vec![b'['; 4 << 20]] {
            assert!(
                matches!(verify(input, &config), Err(AttestationError::Bundle(_))),
                "{} bytes",
                input.len()
            );
        }
    }
}
