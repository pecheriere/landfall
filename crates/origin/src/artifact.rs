//! Verifying one file of a release, before anything uses it.
//!
//! [`verify_release_file`] takes the release's signed tag, its files, and the
//! attestation that vouches for them, and returns the file's bytes only when each of
//! these holds: the tag is signed by a trusted key, and names the commit; the release's
//! sums give the file's name the digest its bytes have; and one attestation, from the
//! expected repository and workflow at that tag and commit, names both the file and the
//! sums, with their names and digests. Each file is a separate download from a host that
//! proves nothing, so all of that is about the bytes in hand.

use std::collections::BTreeMap;
use std::fmt;

use landfall_core::config::SignerKey;
use landfall_core::ids::{CommitSha, ImageDigest, PrincipalId, ReleaseTag, RepoName};
use landfall_core::tag::{SignedTag, TagVerifyError};
use landfall_core::text::shown;
use sha2::{Digest as _, Sha256};
use thiserror::Error;

use crate::attestation::{
    AttestationError, Expected, FileSubject, MAX_BUNDLE_BYTES, VerifiedAttestation,
    verify_file_bundle,
};
use crate::fetch::{BINARY_LIMIT, FetchError, Fetcher, ReleaseAsset, SUMS_LIMIT, hex};
use crate::release::{ReleaseError, signed_commit};
use crate::trust::TrustRoot;

#[cfg(test)]
mod tests;

/// The end of the run URL of a release's only allowed attempt: hosts refuse a release
/// attested by two attempts, and a tag can't be moved.
const FIRST_ATTEMPT: &str = "/attempts/1";

/// Where a release must come from: what is known beforehand, and not read from it.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseIdentity<'a> {
    /// `<owner>/<repo>`.
    pub repo: &'a RepoName,
    /// GitHub repository id.
    pub repo_id: u64,
    /// GitHub owner id.
    pub owner_id: u64,
    /// Workflow path, `.github/workflows/<name>.yml`.
    pub workflow: &'a str,
    /// The keys that may sign the release's tag.
    pub signers: &'a [(PrincipalId, &'a SignerKey)],
}

/// The files of a release that verifying one of them takes.
#[derive(Debug, Clone, Copy)]
pub struct ReleaseFileNames<'a> {
    /// The file wanted.
    pub file: &'a str,
    /// The file of checksums.
    pub sums: &'a str,
    /// The Sigstore bundle.
    pub bundle: &'a str,
}

/// A release file that passed every check.
pub struct VerifiedFile {
    /// The file's name, which the attestation gives these bytes.
    pub name: String,
    /// The file.
    pub bytes: Vec<u8>,
    /// The sha256 of the bytes.
    pub digest: ImageDigest,
    /// The commit the signed tag names, which the attestation also names.
    pub commit: CommitSha,
    /// The verified signature on the tag.
    pub tag: SignedTag,
    /// The verified attestation. Its `digest` is this file's, the first it was asked for.
    pub attestation: VerifiedAttestation,
}

impl fmt::Debug for VerifiedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedFile")
            .field("name", &self.name)
            .field("bytes", &self.bytes.len())
            .field("digest", &self.digest)
            .field("commit", &self.commit)
            .field("tag", &self.tag)
            .field("attestation", &self.attestation)
            .finish()
    }
}

/// Why a release file was refused or could not be verified.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FileError {
    /// The tag is not signed as it must be, or could not be read.
    #[error("release tag")]
    Tag(#[source] ReleaseError),
    /// The tag claims a key this build doesn't trust.
    #[error(
        "the release tag is signed by a key this build doesn't trust; it trusts {}: a newer \
         build may trust that key",
        .trusted.join(", ")
    )]
    UntrustedSigner {
        /// The fingerprints this build trusts.
        trusted: Vec<String>,
    },
    /// The release's files could not be listed.
    #[error("the release's files could not be listed")]
    Assets(#[source] FetchError),
    /// A file isn't there exactly once.
    #[error("the release has {count} files named {name:?}, expected one")]
    Asset {
        /// The file's name.
        name: String,
        /// How many it has.
        count: usize,
    },
    /// A file could not be downloaded.
    #[error("{name} could not be downloaded")]
    Download {
        /// The file's name.
        name: String,
        /// Why.
        #[source]
        source: FetchError,
    },
    /// The file of checksums isn't what it must be.
    #[error("the unverified checksums, at line {line}: {reason}")]
    SumsMalformed {
        /// The line, counted from 1.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
    /// The file of checksums has a name twice.
    #[error("the unverified checksums name {name} more than once")]
    SumsDuplicate {
        /// The name, quoted and shortened.
        name: String,
    },
    /// The file of checksums doesn't have the file.
    #[error("the unverified checksums do not name {name:?}")]
    NotInSums {
        /// The file's name.
        name: String,
    },
    /// The file's bytes aren't what the checksums say.
    #[error("{name} hashes to {computed}, and the unverified checksums say {expected}")]
    SumsMismatch {
        /// The file's name.
        name: String,
        /// What the checksums say.
        expected: String,
        /// The sha256 of the bytes.
        computed: String,
    },
    /// The attestation does not vouch for these files.
    #[error("attestation")]
    Attestation(#[source] AttestationError),
    /// The release was attested by another run attempt than the first.
    #[error("the release was attested by {run_url:?}, which is not a first attempt")]
    NotFirstAttempt {
        /// The certificate's Run Invocation URI.
        run_url: String,
    },
    /// The verification was stopped before it ended, as the process stops.
    #[error("verification was interrupted")]
    Interrupted,
}

impl FileError {
    /// Whether the release was refused for what it is: its tag's signature, its signer, its
    /// checksums, its attempt, or what the attestation says. `false` for what says nothing of
    /// the release, as [`ReleaseError::is_refusal`] has it: a file that could not be listed or
    /// fetched, or a bundle that does not parse. The checksums are an unverified download, so
    /// a bad answer can cause that refusal too, and nothing keeps a refusal: asking again asks
    /// again.
    #[must_use]
    pub fn is_refusal(&self) -> bool {
        match self {
            Self::Tag(error) => error.is_refusal(),
            Self::Attestation(error) => !matches!(
                error,
                AttestationError::Bundle(_) | AttestationError::ClockBehind(_)
            ),
            Self::Assets(_) | Self::Asset { .. } | Self::Download { .. } | Self::Interrupted => {
                false
            }
            Self::UntrustedSigner { .. }
            | Self::SumsMalformed { .. }
            | Self::SumsDuplicate { .. }
            | Self::NotInSums { .. }
            | Self::SumsMismatch { .. }
            | Self::NotFirstAttempt { .. } => true,
        }
    }
}

/// [`Expected`], owned, to go to a blocking thread.
#[derive(Debug, Clone)]
pub(crate) struct OwnedExpected {
    repo: RepoName,
    repo_id: u64,
    owner_id: u64,
    workflow: String,
    tag: ReleaseTag,
    commit: CommitSha,
}

impl OwnedExpected {
    pub(crate) fn expected(&self) -> Expected<'_> {
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

/// Fetches and verifies one file of the release of `tag`, as the module says.
///
/// # Errors
///
/// The [`FileError`] of the first check that fails. No byte of the file is returned
/// before they all pass.
pub async fn verify_release_file(
    fetcher: &Fetcher,
    root: &TrustRoot,
    identity: &ReleaseIdentity<'_>,
    tag: &ReleaseTag,
    names: &ReleaseFileNames<'_>,
) -> Result<VerifiedFile, FileError> {
    let root = root.clone();
    check_release_file(
        fetcher,
        identity,
        tag,
        names,
        move |bundle, files, expected| {
            let subjects: Vec<FileSubject<'_>> = files
                .iter()
                .map(|(name, digest)| FileSubject { name, digest })
                .collect();
            verify_file_bundle(&bundle, &subjects, &root, &expected.expected())
        },
    )
    .await
}

/// [`verify_release_file`], with the step that verifies the bundle given: it gets the
/// bundle, the file's name and digest followed by the sums', and what must be expected of
/// the certificate. It runs on a blocking thread, as it is signature checks with no
/// waiting in them.
pub(crate) async fn check_release_file<C>(
    fetcher: &Fetcher,
    identity: &ReleaseIdentity<'_>,
    tag: &ReleaseTag,
    names: &ReleaseFileNames<'_>,
    bundle_check: C,
) -> Result<VerifiedFile, FileError>
where
    C: FnOnce(
            Vec<u8>,
            Vec<(String, ImageDigest)>,
            OwnedExpected,
        ) -> Result<VerifiedAttestation, AttestationError>
        + Send
        + 'static,
{
    let (commit, signed) = signed_commit(fetcher, identity.repo, tag, identity.signers)
        .await
        .map_err(|error| tag_error(error, identity))?;

    let assets = fetcher
        .release_assets(identity.repo, tag)
        .await
        .map_err(FileError::Assets)?;
    let file_asset = one_asset(&assets, names.file)?;
    let sums_asset = one_asset(&assets, names.sums)?;
    let bundle_asset = one_asset(&assets, names.bundle)?;
    let file = download(fetcher, identity, file_asset, BINARY_LIMIT).await?;
    let sums = download(fetcher, identity, sums_asset, SUMS_LIMIT).await?;
    let bundle = download(fetcher, identity, bundle_asset, MAX_BUNDLE_BYTES).await?;

    let name = names.file.to_owned();
    let (file, digest) = off_runtime(move || {
        let digest = digest_of(&name, &file);
        (file, digest)
    })
    .await?;
    let digest = digest?;
    let sums_digest = digest_of(names.sums, &sums)?;
    let listed = parse_sums(&sums)?;
    let said = listed.get(names.file).ok_or_else(|| FileError::NotInSums {
        name: names.file.to_owned(),
    })?;
    if said != &digest {
        return Err(FileError::SumsMismatch {
            name: names.file.to_owned(),
            expected: said.to_string(),
            computed: digest.to_string(),
        });
    }

    let subjects = vec![
        (names.file.to_owned(), digest.clone()),
        (names.sums.to_owned(), sums_digest),
    ];
    let expected = OwnedExpected {
        repo: identity.repo.clone(),
        repo_id: identity.repo_id,
        owner_id: identity.owner_id,
        workflow: identity.workflow.to_owned(),
        tag: tag.clone(),
        commit: commit.clone(),
    };
    let attestation = off_runtime(move || bundle_check(bundle, subjects, expected))
        .await?
        .map_err(FileError::Attestation)?;
    if !attestation.run_url.ends_with(FIRST_ATTEMPT) {
        return Err(FileError::NotFirstAttempt {
            run_url: attestation.run_url,
        });
    }

    Ok(VerifiedFile {
        name: names.file.to_owned(),
        bytes: file,
        digest,
        commit,
        tag: signed,
        attestation,
    })
}

/// A tag signed by a key that isn't trusted says so with the keys that are.
fn tag_error(error: ReleaseError, identity: &ReleaseIdentity<'_>) -> FileError {
    match error {
        ReleaseError::TagSignature(TagVerifyError::UnknownSigner { .. }) => {
            FileError::UntrustedSigner {
                trusted: identity
                    .signers
                    .iter()
                    .map(|(_, key)| key.fingerprint())
                    .collect(),
            }
        }
        other => FileError::Tag(other),
    }
}

fn one_asset<'a>(assets: &'a [ReleaseAsset], name: &str) -> Result<&'a ReleaseAsset, FileError> {
    let named: Vec<&ReleaseAsset> = assets.iter().filter(|asset| asset.name == name).collect();
    match named.as_slice() {
        [asset] => Ok(asset),
        _ => Err(FileError::Asset {
            name: name.to_owned(),
            count: named.len(),
        }),
    }
}

async fn download(
    fetcher: &Fetcher,
    identity: &ReleaseIdentity<'_>,
    asset: &ReleaseAsset,
    limit: usize,
) -> Result<Vec<u8>, FileError> {
    fetcher
        .release_asset(identity.repo, asset, limit)
        .await
        .map_err(|source| FileError::Download {
            name: asset.name.clone(),
            source,
        })
}

/// `work` on a blocking thread. A panic in it goes on as a panic here.
async fn off_runtime<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, FileError> {
    match tokio::task::spawn_blocking(work).await {
        Ok(answer) => Ok(answer),
        Err(error) if error.is_panic() => std::panic::resume_unwind(error.into_panic()),
        Err(_) => Err(FileError::Interrupted),
    }
}

/// The sha256 of the file `name`. Its text is always a valid [`ImageDigest`], whose only
/// constructor is the parser.
fn digest_of(name: &str, bytes: &[u8]) -> Result<ImageDigest, FileError> {
    let computed = format!("sha256:{}", hex(&Sha256::digest(bytes)));
    computed.parse().map_err(|_| FileError::Download {
        name: name.to_owned(),
        source: FetchError::Malformed {
            url: name.to_owned(),
            reason: format!("computed digest {computed} did not parse"),
        },
    })
}

/// Reads a file of checksums: every line `<64 lowercase hex>  <name>`, each ended by a
/// newline, and no name twice. This is what `sha256sum` writes in text mode. Anything else
/// is refused, as there is one spelling of each line, and a name holds no control
/// character, so a carriage return can't hide in one.
fn parse_sums(bytes: &[u8]) -> Result<BTreeMap<&str, ImageDigest>, FileError> {
    let malformed = |line, reason: &str| FileError::SumsMalformed {
        line,
        reason: reason.to_owned(),
    };
    let text = std::str::from_utf8(bytes).map_err(|_| malformed(1, "it is not UTF-8"))?;
    if text.is_empty() {
        return Err(malformed(1, "it is empty"));
    }
    let mut sums = BTreeMap::new();
    for (index, line) in text.split_inclusive('\n').enumerate() {
        let number = index + 1;
        let line = line
            .strip_suffix('\n')
            .ok_or_else(|| malformed(number, "it has no end of line"))?;
        let (sum, name) = line
            .split_once("  ")
            .ok_or_else(|| malformed(number, "it is not a checksum, two spaces and a name"))?;
        let digest: ImageDigest = format!("sha256:{sum}")
            .parse()
            .map_err(|_| malformed(number, "its checksum is not 64 lowercase hex digits"))?;
        if name.is_empty() || name.chars().any(char::is_control) {
            return Err(malformed(
                number,
                "its name is empty or holds a control character",
            ));
        }
        if sums.insert(name, digest).is_some() {
            return Err(FileError::SumsDuplicate { name: shown(name) });
        }
    }
    Ok(sums)
}
