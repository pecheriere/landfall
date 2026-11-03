//! What landfall trusts about its own releases.
//!
//! This is separate from a deployment's `origin.signed_tags`, which is a host's rule
//! about the releases it deploys, read from its configuration. Nothing here reads any
//! configuration. A fork changes these constants, and `release-signers`.

use std::collections::HashSet;

use landfall_core::config::SignerKey;
use landfall_core::ids::PrincipalId;
use thiserror::Error;

#[cfg(test)]
mod tests;

/// The repository that releases landfall.
pub const REPO: &str = "pecheriere/landfall";

/// Its GitHub id: numeric, so a re-created account can't take over.
pub const REPO_ID: u64 = 1_441_186_089;

/// Its owner's GitHub id.
pub const OWNER_ID: u64 = 1_872_741;

/// The workflow that publishes a release.
pub const WORKFLOW: &str = ".github/workflows/release.yml";

/// The keys that may sign a release tag, as `release_preflight.py` also reads them.
const SIGNERS: &str = include_str!("../assets/release-signers");

/// The key type on every line of [`SIGNERS`].
const KEY_TYPE: &str = "ssh-ed25519";

/// 51 bytes fill their last base64 group exactly, so this many characters of the
/// standard alphabet are the one spelling of a key.
const KEY_FIELD_LENGTH: usize = 68;

/// Why this build's trust in its own releases can't be had.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum ProjectError {
    /// The file holds no key, which is where a fork starts.
    #[error(
        "this build of landfall trusts no release-signing key, so it can't verify an agent: \
         crates/cli/assets/release-signers holds no key. Use an official release of landfall, \
         or see the guide for forks."
    )]
    NoSigners,
    /// An editor can show such a file unlike how it's read.
    #[error("the release-signers file holds a carriage return")]
    CarriageReturn,
    /// A line that isn't exactly a key.
    #[error("line {line} of the release-signers file is refused: {reason}")]
    Line {
        /// The line, counted from 1.
        line: usize,
        /// What is wrong with it.
        reason: String,
    },
    /// A key given twice.
    #[error("line {line} of the release-signers file repeats a key")]
    Repeated {
        /// The line, counted from 1.
        line: usize,
    },
}

/// The keys this build trusts to sign a release tag.
///
/// # Errors
///
/// [`ProjectError::NoSigners`] when it trusts none, and the others if the file
/// embedded in it is not as it must be.
pub fn signers() -> Result<Vec<(PrincipalId, SignerKey)>, ProjectError> {
    parse_signers(SIGNERS)
}

/// Reads a file of signers, by the rule of `release_preflight.py`'s `parse_signers`,
/// which must not differ. Only `\n` ends a line, and a carriage return anywhere is
/// refused. A line is skipped only if it is empty or its first character is `#`, with
/// no trimming. Every other line must be exactly `ssh-ed25519 <base64>` for a good key,
/// so a key's comment, which usually carries a name, is refused, and no key may repeat.
///
/// # Errors
///
/// A [`ProjectError`] saying which line and why, and [`ProjectError::NoSigners`] when
/// there is no key.
fn parse_signers(text: &str) -> Result<Vec<(PrincipalId, SignerKey)>, ProjectError> {
    if text.contains('\r') {
        return Err(ProjectError::CarriageReturn);
    }
    let mut seen = HashSet::new();
    let mut keys = Vec::new();
    for (index, line) in text.split('\n').enumerate() {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let number = index + 1;
        let key = signer_line(line).map_err(|reason| ProjectError::Line {
            line: number,
            reason,
        })?;
        if !seen.insert(key.fingerprint()) {
            return Err(ProjectError::Repeated { line: number });
        }
        let name = format!("release-{}", keys.len() + 1);
        let id = name.parse().map_err(|_| ProjectError::Line {
            line: number,
            reason: format!("{name} is not a principal's name"),
        })?;
        keys.push((id, key));
    }
    if keys.is_empty() {
        return Err(ProjectError::NoSigners);
    }
    Ok(keys)
}

/// The line as a key: the fields' form here, and the key's bytes and what they are by
/// [`SignerKey::parse`], which ignores a comment and is lenient about space, as a `.pub`
/// file needs.
fn signer_line(line: &str) -> Result<SignerKey, String> {
    let fields: Vec<&str> = line.split(' ').collect();
    let [key_type, key] = fields.as_slice() else {
        return Err("it is not exactly a key type and a key, each after a single space".to_owned());
    };
    if *key_type != KEY_TYPE {
        return Err(format!("it is not an {KEY_TYPE} key"));
    }
    let in_alphabet = |b: u8| b.is_ascii_alphanumeric() || b == b'+' || b == b'/';
    if key.len() != KEY_FIELD_LENGTH || !key.bytes().all(in_alphabet) {
        return Err(format!(
            "its key is not {KEY_FIELD_LENGTH} characters of base64"
        ));
    }
    SignerKey::parse(line)
}
