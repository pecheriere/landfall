//! A named release file, against a bundle that attests many.
//!
//! One bundle vouches for every file of a release, so a digest alone would accept
//! one attested file in place of another: the agent for one architecture as the
//! other's, or the CLI as the agent. Here the name and the digest are checked
//! together.

use landfall_core::ids::ImageDigest;
use landfall_core::text::shown;
use sigstore_verify::types::Statement;

use super::{
    AttestationError, Expected, VerifiedAttestation, parse_bundle, provenance_statement,
    verify_parsed,
};
use crate::trust::TrustRoot;

/// How many of a statement's names a refusal lists. A release has around a dozen
/// files, and each name shown is bounded by [`shown`].
const NAMES_SHOWN: usize = 16;

/// A release file, as its attestation must name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileSubject<'a> {
    /// The subject's name, compared exactly. `actions/attest` names a file by its
    /// basename.
    pub name: &'a str,
    /// The file's digest.
    pub digest: &'a ImageDigest,
}

/// Verifies `bundle_json` for every file of `subjects` against `root` and `expected`.
///
/// The same checks as [`verify_bundle`](super::verify_bundle), but for the subject:
/// the bundle's limits and format, a [`SLSA_PROVENANCE`](super::SLSA_PROVENANCE)
/// statement, its one transparency log entry, the Sigstore verification and the
/// certificate's identity rules. In place of a digest being named somewhere in the
/// statement, each subject must be there with that exact name and sha256 together,
/// and its name must have no other digest. A bundle's signature covers its whole
/// statement, so one verification, on the first subject's digest, holds for every name
/// read from that statement.
///
/// The result's `digest` is the first subject's.
///
/// # Errors
///
/// Returns [`AttestationError`] naming the first check that failed:
/// [`AttestationError::NoFileSubjects`] for no subjects, and
/// [`AttestationError::FileSubject`] for a file the statement does not name with that
/// digest, or whose name it also gives another digest.
pub fn verify_file_bundle(
    bundle_json: &[u8],
    subjects: &[FileSubject<'_>],
    root: &TrustRoot,
    expected: &Expected<'_>,
) -> Result<VerifiedAttestation, AttestationError> {
    let Some(first) = subjects.first() else {
        return Err(AttestationError::NoFileSubjects);
    };
    let bundle = parse_bundle(bundle_json)?;
    let statement = provenance_statement(&bundle)?;
    for subject in subjects {
        find_subject(&statement, subject)?;
    }
    verify_parsed(&bundle, first.digest, root, expected)
}

/// Whether `statement` gives the name of `subject` to at least one subject, and every
/// subject of that name has the digest of `subject`.
///
/// A name with two digests is refused for either of them: it no longer says which file
/// it means, and the digest asked for must not be what chooses. The same name twice with
/// the same digest leaves no doubt, so it passes; `actions/attest` removes those anyway.
/// A subject may have no name, which reads as empty: that is not a name to find.
pub(super) fn find_subject(
    statement: &Statement,
    subject: &FileSubject<'_>,
) -> Result<(), AttestationError> {
    let named = || {
        statement
            .subject
            .iter()
            .filter(|named| named.name == subject.name)
    };
    let found = !subject.name.is_empty()
        && named().next().is_some()
        && named().all(|named| {
            named.digest.sha256.as_ref().is_some_and(|hash| {
                subject.digest.as_ref().strip_prefix("sha256:") == Some(&*hash.to_hex())
            })
        });
    if found {
        return Ok(());
    }
    let times = named().count();
    Err(AttestationError::FileSubject {
        name: subject.name.to_owned(),
        expected: subject.digest.to_string(),
        // Only an empty name is refused with every digest right, and that is no fault of theirs.
        found: if times > 1 && !subject.name.is_empty() {
            format!(
                "{} {times} times, not all with this digest",
                shown(subject.name)
            )
        } else {
            names_shown(statement)
        },
    })
}

/// The statement's names for a refusal. Nothing has checked them yet, as this comes
/// before the signature, so each is quoted and shortened, and only so many are listed.
fn names_shown(statement: &Statement) -> String {
    let names = &statement.subject;
    if names.is_empty() {
        return "no subject".to_owned();
    }
    let mut listed: Vec<String> = names
        .iter()
        .take(NAMES_SHOWN)
        .map(|subject| shown(&subject.name))
        .collect();
    let more = names.len().saturating_sub(NAMES_SHOWN);
    if more > 0 {
        listed.push(format!("and {more} more"));
    }
    listed.join(", ")
}
