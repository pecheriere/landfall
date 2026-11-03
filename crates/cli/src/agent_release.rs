//! Fetching a release of the agent, verified, to install it.
//!
//! The file names here are the release's, which `assemble_release.py` writes and the
//! attestation vouches for. [`AgentSource`] is what `host install` asks: nothing it hands
//! out has skipped [`GitHubReleases`]'s checks, other than through [`VerifiedAgent::new`],
//! which a test's fake uses and no command line can reach.

use std::fmt::{self, Write as _};
use std::future::Future;
use std::path::PathBuf;

use landfall_core::config::SignerKey;
use landfall_core::ids::{IdError, PrincipalId, ReleaseTag, RepoName, TagError, TagPattern};
use landfall_origin::artifact::{
    FileError, ReleaseFileNames, ReleaseIdentity, VerifiedFile, verify_release_file,
};
use landfall_origin::trust::Refresh;
use semver::Version;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::access::{AccessError, public_fetcher, trust_root};
use crate::project::{self, ProjectError};

#[cfg(test)]
mod tests;

/// The file of checksums in a release.
pub const SUMS_ASSET: &str = "SHA256SUMS";

/// The workspace version of a build that isn't a release.
const DEV_VERSION: &str = "0.0.0";

/// A host's architecture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    /// `linux/arm64`.
    Arm64,
    /// `linux/amd64`.
    Amd64,
}

impl Arch {
    /// The architecture `uname -m` names, among those a release has.
    #[must_use]
    pub fn from_uname(machine: &str) -> Option<Self> {
        match machine {
            "aarch64" | "arm64" => Some(Self::Arm64),
            "x86_64" => Some(Self::Amd64),
            _ => None,
        }
    }

    /// Its name in a release file's.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64",
            Self::Amd64 => "amd64",
        }
    }
}

impl fmt::Display for Arch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The agent's file in release `version`, for `arch`.
#[must_use]
pub fn agent_asset(version: &Version, arch: Arch) -> String {
    format!("landfall-agent-{version}-linux-{arch}")
}

/// The attestation's file in release `version`.
#[must_use]
pub fn bundle_asset(version: &Version) -> String {
    format!("landfall-{version}.sigstore.json")
}

/// An agent binary that came through verification, or a test's fake.
#[derive(Clone)]
pub struct VerifiedAgent {
    tag: ReleaseTag,
    version: Version,
    arch: Arch,
    bytes: Vec<u8>,
    sha256: String,
    summary: String,
}

impl VerifiedAgent {
    /// An agent, with the hash of `bytes`. `summary` says where it came from, for showing
    /// to the operator. For a source other than a real one: nothing on a command line
    /// reaches this.
    #[must_use]
    pub fn new(
        tag: ReleaseTag,
        version: Version,
        arch: Arch,
        bytes: Vec<u8>,
        summary: String,
    ) -> Self {
        let sha256 = sha256_hex(&bytes);
        Self {
            tag,
            version,
            arch,
            bytes,
            sha256,
            summary,
        }
    }

    /// The release's tag.
    #[must_use]
    pub fn tag(&self) -> &ReleaseTag {
        &self.tag
    }

    /// The release's version.
    #[must_use]
    pub fn version(&self) -> &Version {
        &self.version
    }

    /// The architecture it is for.
    #[must_use]
    pub fn arch(&self) -> Arch {
        self.arch
    }

    /// The binary.
    #[must_use]
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// The binary's SHA-256, as 64 lowercase hex digits.
    #[must_use]
    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Where it came from, in a line for the operator.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }
}

impl fmt::Debug for VerifiedAgent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedAgent")
            .field("tag", &self.tag)
            .field("version", &self.version)
            .field("arch", &self.arch)
            .field("bytes", &self.bytes.len())
            .field("sha256", &self.sha256)
            .field("summary", &self.summary)
            .finish()
    }
}

/// Why an agent release could not be had.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AgentReleaseError {
    /// This build trusts no release, or what it trusts is not in order.
    #[error(transparent)]
    Project(#[from] ProjectError),
    /// The trust root or the fetcher could not be had.
    #[error(transparent)]
    Access(#[from] AccessError),
    /// A build that isn't a release doesn't know which release it goes with.
    #[error(
        "this is a development build of landfall (version {DEV_VERSION}), which goes with no \
         release: pass --tag"
    )]
    NeedsTag,
    /// The version can't be a release's tag.
    #[error("{tag:?} can't be a release's tag")]
    Tag {
        /// What it would be.
        tag: String,
        /// Why not.
        #[source]
        source: IdError,
    },
    /// A value built into this binary is not valid, which a test keeps from happening.
    #[error("this build's {what} is invalid")]
    Build {
        /// Which value.
        what: &'static str,
        /// Why.
        #[source]
        source: IdError,
    },
    /// The tag isn't one a release of landfall can have.
    #[error(transparent)]
    Version(TagError),
    /// The release was refused, or its material could not be fetched.
    #[error(
        "the agent of release {tag} {}",
        if source.is_refusal() { "is refused" } else { "could not be verified" }
    )]
    File {
        /// The tag.
        tag: ReleaseTag,
        /// The step that failed.
        #[source]
        source: Box<FileError>,
    },
}

impl AgentReleaseError {
    /// Whether the release itself was refused, and not merely out of reach.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        matches!(self, Self::File { source, .. } if source.is_refusal())
    }
}

/// Where a verified agent comes from.
pub trait AgentSource {
    /// Whether this can verify anything at all, which is asked before connecting to a host.
    ///
    /// # Errors
    ///
    /// Why it can't.
    fn ready(&self) -> Result<(), AgentReleaseError>;

    /// The agent of release `tag`, for `arch`, verified.
    fn agent(
        &self,
        tag: &ReleaseTag,
        arch: Arch,
    ) -> impl Future<Output = Result<VerifiedAgent, AgentReleaseError>>;
}

/// This project's releases on GitHub, as [`crate::project`] says to trust them.
#[derive(Debug, Clone)]
pub struct GitHubReleases {
    cache_dir: Option<PathBuf>,
    refresh: Refresh,
}

impl GitHubReleases {
    /// Verifying with the Sigstore trust root cached at `cache_dir`, or by default in the
    /// usual place, refreshed or not.
    #[must_use]
    pub fn new(cache_dir: Option<PathBuf>, refresh: Refresh) -> Self {
        Self { cache_dir, refresh }
    }
}

impl AgentSource for GitHubReleases {
    fn ready(&self) -> Result<(), AgentReleaseError> {
        project::signers()?;
        Ok(())
    }

    async fn agent(
        &self,
        tag: &ReleaseTag,
        arch: Arch,
    ) -> Result<VerifiedAgent, AgentReleaseError> {
        let keys = project::signers()?;
        let signers: Vec<(PrincipalId, &SignerKey)> =
            keys.iter().map(|(id, key)| (id.clone(), key)).collect();
        let version = release_version(tag)?;
        let repo: RepoName = project::REPO
            .parse()
            .map_err(|source| AgentReleaseError::Build {
                what: "repository",
                source,
            })?;
        let identity = ReleaseIdentity {
            repo: &repo,
            repo_id: project::REPO_ID,
            owner_id: project::OWNER_ID,
            workflow: project::WORKFLOW,
            signers: &signers,
        };
        let (file, bundle) = (agent_asset(&version, arch), bundle_asset(&version));
        let names = ReleaseFileNames {
            file: &file,
            sums: SUMS_ASSET,
            bundle: &bundle,
        };

        let root = trust_root(self.cache_dir.clone(), self.refresh).await?;
        let fetcher = public_fetcher()?;
        let verified = verify_release_file(&fetcher, &root, &identity, tag, &names)
            .await
            .map_err(|source| AgentReleaseError::File {
                tag: tag.clone(),
                source: Box::new(source),
            })?;
        Ok(from_verified(verified, tag.clone(), version, arch))
    }
}

/// The SHA-256 of `bytes`, as 64 lowercase hex digits.
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::with_capacity(64), |mut text, byte| {
            // Writing to a `String` can't fail.
            let _ = write!(text, "{byte:02x}");
            text
        })
}

/// The hash was taken and checked in verifying it: this keeps that one.
fn from_verified(
    verified: VerifiedFile,
    tag: ReleaseTag,
    version: Version,
    arch: Arch,
) -> VerifiedAgent {
    let summary = format!(
        "{tag}, signed by {}, commit {}, built by {}",
        verified.tag.fingerprint, verified.commit, verified.attestation.run_url
    );
    let sha256 = verified
        .digest
        .as_ref()
        .trim_start_matches("sha256:")
        .to_owned();
    VerifiedAgent {
        tag,
        version,
        arch,
        bytes: verified.bytes,
        sha256,
        summary,
    }
}

/// The version of a release of landfall from its tag, `v<version>`.
///
/// # Errors
///
/// [`AgentReleaseError::Version`] when the tag isn't that.
pub fn release_version(tag: &ReleaseTag) -> Result<Version, AgentReleaseError> {
    let pattern: TagPattern = "v*".parse().map_err(|source| AgentReleaseError::Build {
        what: "tag pattern",
        source,
    })?;
    pattern.parse_tag(tag).map_err(AgentReleaseError::Version)
}

/// The tag to install: `explicit`, or the one of the build's own `version`.
///
/// # Errors
///
/// [`AgentReleaseError::NeedsTag`] for a development build with no `explicit`.
pub fn default_tag(
    version: &str,
    explicit: Option<ReleaseTag>,
) -> Result<ReleaseTag, AgentReleaseError> {
    if let Some(tag) = explicit {
        return Ok(tag);
    }
    if version == DEV_VERSION {
        return Err(AgentReleaseError::NeedsTag);
    }
    let tag = format!("v{version}");
    tag.parse()
        .map_err(|source| AgentReleaseError::Tag { tag, source })
}
