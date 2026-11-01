//! End-to-end verification of one release of one deployment.
//!
//! [`verify_release`] composes the steps of the design's section 5.2 in
//! order, each failing closed: the tag matches the deployment's pattern; the
//! tag is signed by one of the deployment's signers (or, with
//! `origin.signed_tags = false`, the tag ref is simply followed to its
//! commit); the image index for the tag is found in the registry; its
//! digest is the release's single candidate digest (the exactly-one-digest
//! rule runs over the candidates it is given, and today that is the one the
//! registry tag resolves to: discovering every attested digest of a release
//! is tracked in issue #11); a build-provenance bundle for that digest
//! verifies and its Fulcio identity names the deployment's repository,
//! workflow, tag and the release commit; the host's platform is in the
//! index. The first failing step is the error, and it names the step.

use landfall_core::config::{Config, SignerKey};
use landfall_core::ids::{CommitSha, DeploymentId, PrincipalId, ReleaseTag, TagError};
use landfall_core::release::{
    DigestRuleError, Platform, PlatformError, require_platform, select_release_digest,
};
use landfall_core::tag::{SignedTag, TagVerifyError, verify_tag};
use serde::Serialize;
use thiserror::Error;

use crate::attestation::{AttestationError, Expected, VerifiedAttestation, verify_bundle};
use crate::fetch::{FetchError, Fetcher};
use crate::trust::TrustRoot;

/// Where a verified release came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ReleaseOrigin {
    /// The release commit: the one the signed tag names, or with
    /// `origin.signed_tags = false` the one the tag ref points to.
    pub commit: CommitSha,
    /// The verified maintainer signature; `None` when the deployment does
    /// not require signed tags.
    pub tag: Option<SignedTag>,
    /// The verified build-provenance attestation, including the image
    /// index digest that is pinned and recorded.
    pub attestation: VerifiedAttestation,
    /// The platforms the image index serves.
    pub platforms: Vec<Platform>,
}

/// Why a release was refused. Each variant is one step of the verification
/// and carries that step's error as its source.
#[derive(Debug, Error)]
pub enum ReleaseError {
    /// The deployment is not in the configuration.
    #[error("deployment {0} is not in the configuration")]
    UnknownDeployment(DeploymentId),
    /// The tag does not match the deployment's tag pattern.
    #[error("tag pattern")]
    TagPattern(#[source] TagError),
    /// The tag object could not be fetched from GitHub.
    #[error("tag object")]
    TagObject(#[source] FetchError),
    /// The tag is not signed by a trusted signer of the deployment. A
    /// lightweight tag or an annotated tag without signature is
    /// [`TagVerifyError::NotSigned`].
    #[error("tag signature")]
    TagSignature(#[source] TagVerifyError),
    /// The commit of an unsigned release tag could not be read from GitHub.
    #[error("tag commit")]
    TagCommit(#[source] FetchError),
    /// The image index for the tag could not be resolved in the registry.
    #[error("image index")]
    Index(#[source] FetchError),
    /// The release does not have exactly one digest.
    #[error("release digest")]
    Digest(#[source] DigestRuleError),
    /// The build-provenance bundle for the digest could not be fetched.
    #[error("attestation bundle")]
    Bundle(#[source] FetchError),
    /// The bundle does not verify, or its identity is not the deployment's.
    #[error("attestation")]
    Attestation(#[source] AttestationError),
    /// The index does not serve the wanted platform.
    #[error("platform")]
    Platform(#[source] PlatformError),
}

impl ReleaseError {
    /// Whether the release itself was refused: a verification check failed
    /// on material that was obtained (tag pattern, signature, served content,
    /// digest rule, attestation, platform). `false` when it could not be
    /// verified: the deployment is unknown, or material could not be fetched
    /// ([`FetchError::is_unavailable`]), which may succeed on a later try.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        match self {
            Self::UnknownDeployment(_) => false,
            Self::TagObject(e) | Self::TagCommit(e) | Self::Index(e) | Self::Bundle(e) => {
                !e.is_unavailable()
            }
            Self::TagPattern(_)
            | Self::TagSignature(_)
            | Self::Digest(_)
            | Self::Attestation(_)
            | Self::Platform(_) => true,
        }
    }
}

/// Verifies release `tag` of `deployment` for a host on `platform`, and
/// returns where it came from.
///
/// The image is `ghcr.io/<owner>/<repo>` (with the registry of `fetcher`),
/// the deployment's repository name in lowercase, and its tag the release's
/// semantic version without the tag pattern's prefix (`v1.2.3` is looked up
/// as `1.2.3`). That registry tag is only a lookup hint: the digest it
/// resolves to is bound to the release by the attestation. Only that digest
/// is a candidate: finding every attested digest for a release is left to
/// the release watcher.
///
/// # Errors
///
/// The [`ReleaseError`] of the first step that fails.
pub async fn verify_release(
    fetcher: &Fetcher,
    root: &TrustRoot,
    config: &Config,
    deployment: &DeploymentId,
    tag: &ReleaseTag,
    platform: &Platform,
) -> Result<ReleaseOrigin, ReleaseError> {
    let d = config
        .deployment(deployment)
        .ok_or_else(|| ReleaseError::UnknownDeployment(deployment.clone()))?;
    let (repo, origin) = (d.repo(), d.origin());

    let version = origin
        .tags()
        .parse_tag(tag)
        .map_err(ReleaseError::TagPattern)?;
    // The image is tagged with the bare version (`v1.2.3` -> `1.2.3`), as
    // `docker/metadata-action` does with `type=semver`. A semantic version
    // is always a valid tag; were it not, the tag is refused here.
    let image_tag: ReleaseTag = version.to_string().parse().map_err(|_| {
        ReleaseError::TagPattern(TagError {
            tag: tag.to_string(),
            reason: "its version is not a valid image tag",
        })
    })?;

    let (commit, signed) = if origin.signed_tags() {
        let raw = match fetcher.tag_object(repo.name(), tag).await {
            Ok(raw) => raw,
            Err(FetchError::LightweightTag { .. } | FetchError::NotSigned { .. }) => {
                return Err(ReleaseError::TagSignature(TagVerifyError::NotSigned));
            }
            Err(e) => return Err(ReleaseError::TagObject(e)),
        };
        // A validated configuration names only signers that exist, so
        // nothing is dropped here; were one missing, trust would only narrow.
        let signers: Vec<(PrincipalId, &SignerKey)> = origin
            .signers()
            .iter()
            .filter_map(|id| config.signer(id).map(|key| (id.clone(), key)))
            .collect();
        let signed = verify_tag(&raw, tag, &signers).map_err(ReleaseError::TagSignature)?;
        (signed.commit.clone(), Some(signed))
    } else {
        let commit = fetcher
            .tag_commit(repo.name(), tag)
            .await
            .map_err(ReleaseError::TagCommit)?;
        (commit, None)
    };

    let image = repo.name().as_ref().to_ascii_lowercase();
    let (index_digest, platforms) = fetcher
        .resolve_index(&image, &image_tag)
        .await
        .map_err(ReleaseError::Index)?;
    let candidates = [index_digest];
    let digest = select_release_digest(&candidates).map_err(ReleaseError::Digest)?;

    let bundle = fetcher
        .bundle(&image, digest)
        .await
        .map_err(ReleaseError::Bundle)?;
    let expected = Expected {
        repo: repo.name(),
        repo_id: repo.id(),
        owner_id: repo.owner_id(),
        workflow: origin.workflow(),
        tag,
        commit: &commit,
    };
    let attestation =
        verify_bundle(&bundle, digest, root, &expected).map_err(ReleaseError::Attestation)?;

    require_platform(&platforms, platform).map_err(ReleaseError::Platform)?;

    Ok(ReleaseOrigin {
        commit,
        tag: signed,
        attestation,
        platforms,
    })
}

#[cfg(test)]
mod tests {
    //! Each test fails at one step and checks that the error names it. The
    //! signed-tag fixtures (`crates/core/tests/fixtures/tag`) and the
    //! attestation fixtures (`tests/fixtures/attestation`) come from
    //! different repositories, so a signed release cannot pass every step;
    //! an unsigned deployment of the attestation fixture's project does.

    use landfall_core::config::{self, Config};
    use landfall_core::ids::{DeploymentId, ReleaseTag};
    use landfall_core::release::{Platform, PlatformError};
    use landfall_core::tag::TagVerifyError;
    use wiremock::MockServer;

    use super::{ReleaseError, ReleaseOrigin, verify_release};
    use crate::attestation::{AttestationError, SLSA_PROVENANCE};
    use crate::fetch::{Endpoints, FetchError, Fetcher, OCI_INDEX, OCI_MANIFEST};
    use crate::test_support::{
        fetcher, mount_bundles, mount_manifest, mount_ref, mount_tag, mount_token,
        payload_and_signature, tag_object_id,
    };
    use crate::trust::{Refresh, TrustRoot, load_trusted_root};

    const SIGNER: &str = include_str!("../../core/tests/fixtures/tag/signer.pub");
    const VALID_TAG: &[u8] = include_bytes!("../../core/tests/fixtures/tag/valid.tag");
    /// Signed by the same key as `VALID_TAG`, named like the attestation
    /// fixture's tag, on `SIGNED_COMMIT`.
    const OTHER_COMMIT_TAG: &[u8] =
        include_bytes!("../../core/tests/fixtures/tag/other-commit.tag");
    const SIGNED_COMMIT: &str = "7160f743d0664e041913065355d7bcd291ad2a01";

    const BUNDLE: &[u8] = include_bytes!("../tests/fixtures/attestation/bundle.json");
    const INDEX: &[u8] = include_bytes!("../tests/fixtures/attestation/index.json");
    const TRUSTED_ROOT: &str = include_str!("../tests/fixtures/attestation/trusted_root.json");
    const VW_REPO: &str = "dani-garcia/vaultwarden";
    const VW_TAG: &str = "1.37.4";
    const VW_COMMIT: &str = "7c188967e7a467b19b2757bc3326f9cf3ccae327";
    const VW_DIGEST: &str =
        "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055";

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

    #[tokio::test]
    async fn unsigned_release_verifies_end_to_end() {
        let (github, registry) = servers().await;
        mount_unsigned_release(&github, &registry).await;
        mount_bundles(
            &registry,
            VW_REPO,
            &VW_DIGEST.parse().unwrap(),
            &[(BUNDLE, SLSA_PROVENANCE)],
        )
        .await;

        let origin = verify(
            &github,
            &registry,
            &unsigned_config(121_898_717),
            VW_TAG,
            "linux/arm64",
        )
        .await
        .unwrap();
        assert_eq!(origin.commit.as_ref(), VW_COMMIT);
        assert_eq!(origin.tag, None);
        assert_eq!(origin.attestation.digest.as_ref(), VW_DIGEST);
        assert_eq!(origin.attestation.commit.as_ref(), VW_COMMIT);
        assert_eq!(
            origin.platforms,
            ["linux/amd64", "linux/arm/v7", "linux/arm64", "linux/arm/v6"].map(platform)
        );
        let json = serde_json::to_value(&origin).unwrap();
        assert_eq!(json["tag"], serde_json::Value::Null);
        assert_eq!(json["attestation"]["digest"], VW_DIGEST);
        assert_eq!(json["platforms"][1]["variant"], "v7");
    }

    #[tokio::test]
    async fn bad_tag_pattern_is_refused_before_any_request() {
        let (github, registry) = servers().await;
        let result = verify(&github, &registry, &signed_config(), "1.2.3", "linux/amd64").await;
        assert!(
            matches!(result, Err(ReleaseError::TagPattern(_))),
            "{result:?}"
        );
        assert!(github.received_requests().await.unwrap().is_empty());
        assert!(registry.received_requests().await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn lightweight_tag_is_not_signed() {
        let (github, registry) = servers().await;
        mount_ref(&github, "example/app", "v1.2.3", "commit", SIGNED_COMMIT).await;

        let result = verify(
            &github,
            &registry,
            &signed_config(),
            "v1.2.3",
            "linux/amd64",
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::TagSignature(TagVerifyError::NotSigned))
            ),
            "{result:?}"
        );
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), "tag signature");
        assert_eq!(
            std::error::Error::source(&error).unwrap().to_string(),
            "tag is not signed"
        );
    }

    #[tokio::test]
    async fn unsigned_annotated_tag_is_not_signed() {
        let (github, registry) = servers().await;
        let sha = "1".repeat(40);
        mount_ref(&github, "example/app", "v1.2.3", "tag", &sha).await;
        mount_tag(
            &github,
            ("example/app", "v1.2.3"),
            &sha,
            (SIGNED_COMMIT, "commit"),
            None,
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &signed_config(),
            "v1.2.3",
            "linux/amd64",
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::TagSignature(TagVerifyError::NotSigned))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn unsigned_deployment_accepts_a_lightweight_tag() {
        let (github, registry) = servers().await;
        // The tag step passes on a lightweight tag; nothing is in the
        // registry, so the next step fails.
        mount_ref(&github, VW_REPO, VW_TAG, "commit", VW_COMMIT).await;

        let result = verify(
            &github,
            &registry,
            &unsigned_config(121_898_717),
            VW_TAG,
            "linux/amd64",
        )
        .await;
        assert!(matches!(result, Err(ReleaseError::Index(_))), "{result:?}");
    }

    #[tokio::test]
    async fn bad_signature_is_refused() {
        let (github, registry) = servers().await;
        // The object id matches the bytes served, but the signed message
        // was altered after signing.
        let tampered = String::from_utf8(VALID_TAG.to_vec()).unwrap().replacen(
            "release v1.2.3",
            "release v1.2.4",
            1,
        );
        assert_ne!(tampered.as_bytes(), VALID_TAG);
        mount_signed_tag(&github, tampered.as_bytes()).await;

        let result = verify(
            &github,
            &registry,
            &signed_config(),
            "v1.2.3",
            "linux/amd64",
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::TagSignature(TagVerifyError::BadSignature))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn single_arch_manifest_is_refused() {
        let (github, registry) = servers().await;
        mount_signed_tag(&github, VALID_TAG).await;
        mount_token(&registry).await;
        let manifest =
            br#"{"schemaVersion":2,"mediaType":"application/vnd.oci.image.manifest.v1+json"}"#;
        mount_manifest(
            &registry,
            ("example/app", "1.2.3"),
            OCI_MANIFEST,
            manifest.to_vec(),
            None,
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &signed_config(),
            "v1.2.3",
            "linux/amd64",
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::Index(FetchError::MediaType { .. }))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn missing_bundle_is_refused() {
        let (github, registry) = servers().await;
        mount_signed_tag(&github, VALID_TAG).await;
        mount_token(&registry).await;
        mount_manifest(
            &registry,
            ("example/app", "1.2.3"),
            OCI_INDEX,
            INDEX.to_vec(),
            None,
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &signed_config(),
            "v1.2.3",
            "linux/amd64",
        )
        .await;
        assert!(
            matches!(
                result,
                Err(ReleaseError::Bundle(FetchError::Bundles { count: 0, .. }))
            ),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn signed_tag_commit_is_what_the_attestation_must_name() {
        let (github, registry) = servers().await;
        // A signed tag of the fixture project that matches the real bundle
        // in repository, ids, tag and workflow, but names another commit:
        // the bundle is refused for its commit, so the signed tag's commit is
        // what the attestation is checked against.
        mount_signed_tag_of(&github, (VW_REPO, VW_TAG), OTHER_COMMIT_TAG).await;
        mount_token(&registry).await;
        mount_manifest(
            &registry,
            (VW_REPO, VW_TAG),
            OCI_INDEX,
            INDEX.to_vec(),
            Some(VW_DIGEST),
        )
        .await;
        mount_bundles(
            &registry,
            VW_REPO,
            &VW_DIGEST.parse().unwrap(),
            &[(BUNDLE, SLSA_PROVENANCE)],
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &signed_fixture_project_config(),
            VW_TAG,
            "linux/amd64",
        )
        .await;
        match result {
            Err(ReleaseError::Attestation(AttestationError::Identity {
                field,
                expected,
                found,
            })) => {
                assert_eq!(field, "source_repository_digest");
                assert_eq!(expected, SIGNED_COMMIT);
                assert_eq!(found, VW_COMMIT);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn identity_mismatch_is_refused() {
        let (github, registry) = servers().await;
        mount_unsigned_release(&github, &registry).await;
        mount_bundles(
            &registry,
            VW_REPO,
            &VW_DIGEST.parse().unwrap(),
            &[(BUNDLE, SLSA_PROVENANCE)],
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &unsigned_config(1),
            VW_TAG,
            "linux/amd64",
        )
        .await;
        match result {
            Err(ReleaseError::Attestation(AttestationError::Identity { field, .. })) => {
                assert_eq!(field, "source_repository_identifier");
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn missing_platform_is_refused() {
        let (github, registry) = servers().await;
        mount_unsigned_release(&github, &registry).await;
        mount_bundles(
            &registry,
            VW_REPO,
            &VW_DIGEST.parse().unwrap(),
            &[(BUNDLE, SLSA_PROVENANCE)],
        )
        .await;

        let result = verify(
            &github,
            &registry,
            &unsigned_config(121_898_717),
            VW_TAG,
            "linux/riscv64",
        )
        .await;
        match result {
            Err(ReleaseError::Platform(PlatformError::Missing { want, available })) => {
                assert_eq!(want, platform("linux/riscv64"));
                assert_eq!(available.len(), 4);
            }
            other => panic!("{other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_deployment_is_refused() {
        let (github, registry) = servers().await;
        let result = verify_release(
            &fetcher(&github, &registry),
            &root(),
            &signed_config(),
            &"other/prod".parse().unwrap(),
            &"v1.2.3".parse().unwrap(),
            &platform("linux/amd64"),
        )
        .await;
        assert!(
            matches!(result, Err(ReleaseError::UnknownDeployment(_))),
            "{result:?}"
        );
    }

    #[tokio::test]
    async fn refusals_are_told_apart_from_unavailable_material() {
        let (github, registry) = servers().await;
        // Nothing is mounted: the tag ref is a 404, which a later try may
        // find.
        let result = verify(
            &github,
            &registry,
            &unsigned_config(121_898_717),
            VW_TAG,
            "linux/amd64",
        )
        .await;
        match result {
            Err(error @ ReleaseError::TagCommit(FetchError::NotFound { .. })) => {
                assert!(!error.is_refusal(), "{error:?}");
            }
            other => panic!("{other:?}"),
        }

        // Material that was served and failed a check is a refusal.
        assert!(ReleaseError::TagSignature(TagVerifyError::NotSigned).is_refusal());
        let bundles = |count| FetchError::Bundles {
            digest: VW_DIGEST.parse().unwrap(),
            count,
        };
        assert!(ReleaseError::Bundle(bundles(2)).is_refusal());
        // A release still being published has no provenance bundle yet.
        assert!(!ReleaseError::Bundle(bundles(0)).is_refusal());
        assert!(!ReleaseError::UnknownDeployment(deployment()).is_refusal());
    }

    /// The attestation fixture's release, verified end to end against the
    /// real GitHub API, GHCR and Sigstore TUF repository, as an unsigned
    /// deployment.
    #[tokio::test]
    #[ignore = "network: runs nightly in advisories.yml"]
    async fn live_unsigned_release_verifies() {
        let cache = tempfile::tempdir().unwrap();
        let root = load_trusted_root(cache.path(), Refresh::Online)
            .await
            .unwrap();
        let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
        // The nightly job passes its token for the higher API rate limit.
        if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
            fetcher = fetcher.with_github_token(&token).unwrap();
        }

        let origin = verify_release(
            &fetcher,
            &root,
            &unsigned_config(121_898_717),
            &deployment(),
            &VW_TAG.parse().unwrap(),
            &platform("linux/amd64"),
        )
        .await
        .unwrap();
        assert_eq!(origin.commit.as_ref(), VW_COMMIT);
        assert_eq!(origin.tag, None);
        assert_eq!(origin.attestation.digest.as_ref(), VW_DIGEST);
    }
}
