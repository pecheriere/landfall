//! End-to-end verification of one release of one deployment.
//!
//! [`verify_release`] composes the steps of the design's section 5.2 in
//! order, each failing closed: the tag matches the deployment's pattern; the
//! tag is signed by one of the deployment's signers (or, with
//! `origin.signed_tags = false`, the tag ref is simply followed to its
//! commit); the image index for the tag is found in the registry; its
//! digest is the release's single candidate digest (the exactly-one-digest
//! rule runs over the candidates it is given, and here that is the one the
//! registry tag resolves to: the controller also looks for every other attested
//! digest of the release, through [`crate::candidates`]); a build-provenance
//! bundle for that digest verifies and its Fulcio identity names the
//! deployment's repository, workflow, tag and the release commit; the host's
//! platform is in the index. The first failing step is the error, and it names
//! the step.
//!
//! The controller has no platform to ask for, since a host's is its own, so it
//! calls [`verify_release_origin`], which is all of this but the last step.

use landfall_core::config::{Config, SignerKey};
use landfall_core::ids::{
    CommitSha, DeploymentId, ImageDigest, PrincipalId, ReleaseTag, RepoName, TagError,
};
use landfall_core::release::{
    DigestRuleError, Platform, PlatformError, RunRuleError, require_platform, select_release_digest,
};
use landfall_core::tag::{SignedTag, TagVerifyError, verify_tag};
use serde::Serialize;
use thiserror::Error;

use crate::attestation::{AttestationError, Expected, VerifiedAttestation, verify_bundle};
use crate::fetch::{FetchError, Fetcher};
use crate::trust::TrustRoot;

#[cfg(test)]
mod tests;

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
#[non_exhaustive]
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
    /// The release's attested digests do not come from one run and attempt, or
    /// the version tag's digest is not among them.
    #[error("release run")]
    Runs(#[source] RunRuleError),
    /// The build-provenance bundle for the digest could not be fetched.
    #[error("attestation bundle")]
    Bundle(#[source] FetchError),
    /// The bundle does not verify, or its identity is not the deployment's.
    #[error("attestation")]
    Attestation(#[source] AttestationError),
    /// The index does not serve the wanted platform.
    #[error("platform")]
    Platform(#[source] PlatformError),
    /// A list of tags, or the material of a candidate in one, could not be read
    /// or was refused for what it holds. Nothing is known about what it would
    /// have said, so this is never a refusal of the release: it is tried again.
    #[error("release listing")]
    Listing(#[source] FetchError),
    /// There is no Sigstore trust root to verify against.
    #[error("no trust root")]
    NoTrustRoot,
    /// The verification was stopped before it ended, as the process stops.
    #[error("verification was interrupted")]
    Interrupted,
}

impl ReleaseError {
    /// Whether the release itself was refused: a verification result, which holds
    /// until the release changes (tag pattern, signature, digest rule, the run rule,
    /// attestation, platform). `false` for anything one bad answer from a server can
    /// cause, which may be otherwise on a later try: material that could not be
    /// fetched, was the wrong shape or did not match what named it; a version tag's
    /// digest not listed; a bundle that does not parse; an unknown deployment. And for
    /// a clock behind the transparency log, which says nothing of the release.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        match self {
            Self::UnknownDeployment(_)
            | Self::Listing(_)
            | Self::NoTrustRoot
            | Self::Interrupted
            | Self::TagObject(_)
            | Self::TagCommit(_)
            | Self::Index(_)
            | Self::Bundle(_)
            | Self::Runs(RunRuleError::VersionDigestOutside { .. })
            | Self::Attestation(AttestationError::Bundle(_) | AttestationError::ClockBehind(_)) => {
                false
            }
            Self::TagPattern(_)
            | Self::TagSignature(_)
            | Self::Digest(_)
            | Self::Runs(_)
            | Self::Attestation(_)
            | Self::Platform(_) => true,
        }
    }

    /// Whether this may pass with the registry's list catching up, and so is
    /// worth trying only now and then: the version tag's digest is not listed.
    #[must_use]
    pub fn is_slow_to_retry(&self) -> bool {
        matches!(self, Self::Runs(RunRuleError::VersionDigestOutside { .. }))
    }

    /// The fetch that failed, if that is what this is: for telling a rate limit
    /// or an outage from the rest.
    #[must_use]
    pub fn fetch_error(&self) -> Option<&FetchError> {
        match self {
            Self::TagObject(e)
            | Self::TagCommit(e)
            | Self::Index(e)
            | Self::Bundle(e)
            | Self::Listing(e) => Some(e),
            Self::UnknownDeployment(_)
            | Self::TagPattern(_)
            | Self::TagSignature(_)
            | Self::Digest(_)
            | Self::Runs(_)
            | Self::Attestation(_)
            | Self::Platform(_)
            | Self::NoTrustRoot
            | Self::Interrupted => None,
        }
    }
}

/// The registry host releases are published to.
pub const REGISTRY_HOST: &str = "ghcr.io";

/// The image path of a repository's releases on [`REGISTRY_HOST`]: the
/// repository name in lowercase (`Owner/Repo` is `owner/repo`).
#[must_use]
pub fn image_name(repo: &RepoName) -> String {
    repo.as_ref().to_ascii_lowercase()
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
    let origin = verify_release_origin(fetcher, root, config, deployment, tag).await?;
    require_platform(&origin.platforms, platform).map_err(ReleaseError::Platform)?;
    Ok(origin)
}

/// [`verify_release`] for no host in particular: every step but the platform.
///
/// # Errors
///
/// The [`ReleaseError`] of the first step that fails.
pub async fn verify_release_origin(
    fetcher: &Fetcher,
    root: &TrustRoot,
    config: &Config,
    deployment: &DeploymentId,
    tag: &ReleaseTag,
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
        // A validated configuration names only signers that exist, so
        // nothing is dropped here; were one missing, trust would only narrow.
        let signers: Vec<(PrincipalId, &SignerKey)> = origin
            .signers()
            .iter()
            .filter_map(|id| config.signer(id).map(|key| (id.clone(), key)))
            .collect();
        let (commit, signed) = signed_commit(fetcher, repo.name(), tag, &signers).await?;
        (commit, Some(signed))
    } else {
        let commit = fetcher
            .tag_commit(repo.name(), tag)
            .await
            .map_err(ReleaseError::TagCommit)?;
        (commit, None)
    };

    let image = image_name(repo.name());
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
    let attestation = verify_bundle_off_runtime(bundle, digest, root, &expected)
        .await?
        .map_err(ReleaseError::Attestation)?;

    Ok(ReleaseOrigin {
        commit,
        tag: signed,
        attestation,
        platforms,
    })
}

/// The commit of `tag`, from its tag object, which one of `signers` must have signed.
/// A lightweight or unsigned tag is [`TagVerifyError::NotSigned`].
///
/// # Errors
///
/// [`ReleaseError::TagSignature`] when the tag is not signed as it must be, and
/// [`ReleaseError::TagObject`] when its object could not be fetched.
pub async fn signed_commit(
    fetcher: &Fetcher,
    repo: &RepoName,
    tag: &ReleaseTag,
    signers: &[(PrincipalId, &SignerKey)],
) -> Result<(CommitSha, SignedTag), ReleaseError> {
    let raw = match fetcher.tag_object(repo, tag).await {
        Ok(raw) => raw,
        Err(FetchError::LightweightTag { .. } | FetchError::NotSigned { .. }) => {
            return Err(ReleaseError::TagSignature(TagVerifyError::NotSigned));
        }
        Err(e) => return Err(ReleaseError::TagObject(e)),
    };
    let signed = verify_tag(&raw, tag, signers).map_err(ReleaseError::TagSignature)?;
    Ok((signed.commit.clone(), signed))
}

/// [`verify_bundle`] on a blocking thread, since it is signature checks with no
/// waiting in them. A panic in it goes on as a panic here.
///
/// # Errors
///
/// [`ReleaseError::Interrupted`] if the runtime dropped it; its own answer is the
/// inner result.
pub(crate) async fn verify_bundle_off_runtime(
    bundle: Vec<u8>,
    digest: &ImageDigest,
    root: &TrustRoot,
    expected: &Expected<'_>,
) -> Result<Result<VerifiedAttestation, AttestationError>, ReleaseError> {
    let digest = digest.clone();
    let root = root.clone();
    let (repo, tag, commit, workflow) = (
        expected.repo.clone(),
        expected.tag.clone(),
        expected.commit.clone(),
        expected.workflow.to_owned(),
    );
    let (repo_id, owner_id) = (expected.repo_id, expected.owner_id);
    let joined = tokio::task::spawn_blocking(move || {
        let expected = Expected {
            repo: &repo,
            repo_id,
            owner_id,
            workflow: &workflow,
            tag: &tag,
            commit: &commit,
        };
        verify_bundle(&bundle, &digest, &root, &expected)
    })
    .await;
    match joined {
        Ok(answer) => Ok(answer),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(ReleaseError::Interrupted),
    }
}
