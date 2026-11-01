//! Maintainer signatures on release tags.
//!
//! `git tag -s` with an SSH key (`gpg.format = ssh`) writes an annotated tag
//! object whose signature, an armored `SshSig` in namespace `git`, is
//! appended to the message. The signed bytes are the object up to the
//! signature block. [`verify_tag`] checks such an object against the trusted
//! keys and returns the facts it proves: which tag, which commit, signed by
//! whom. Nothing outside the signed bytes is trusted, and a failure names
//! what was expected and what was found.

use ssh_key::SshSig;
use thiserror::Error;

use crate::config::SignerKey;
use crate::ids::{CommitSha, PrincipalId, ReleaseTag};

/// The namespace `git` signs tags under.
const NAMESPACE: &str = "git";

/// Opens the armored signature that `git` appends to a signed tag.
const SIGNATURE_START: &[u8] = b"-----BEGIN SSH SIGNATURE-----";

/// What a valid maintainer signature on a release tag proves.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedTag {
    /// The signed tag name, equal to the expected one.
    pub tag: ReleaseTag,
    /// The commit the signed tag points at: "the release commit".
    pub commit: CommitSha,
    /// The configured signer whose key made the signature.
    pub signer: PrincipalId,
    /// The signing key's fingerprint, `SHA256:<base64>`.
    pub fingerprint: String,
}

/// Why a tag object was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum TagVerifyError {
    /// The object carries no signature block: a lightweight tag, or an
    /// annotated tag that nobody signed (what `gh release create` makes).
    #[error("tag is not signed")]
    NotSigned,
    /// The object cannot be read as a signed annotated tag.
    #[error("tag object is malformed: {reason}")]
    Malformed {
        /// What is wrong with it.
        reason: String,
    },
    /// The tag points at something other than a commit.
    #[error("tag points at a {found:?} object, expected a commit")]
    WrongType {
        /// The object type the tag names.
        found: String,
    },
    /// The signed tag has another name than the release being verified.
    #[error("signed tag is named {found:?}, expected a different one")]
    WrongTag {
        /// The tag name inside the signed object.
        found: String,
    },
    /// The signature does not match the bytes it covers.
    #[error("tag signature does not verify")]
    BadSignature,
    /// The signature is valid but its key is not among the trusted signers.
    #[error("tag is signed by {fingerprint}, which is not a trusted signer")]
    UnknownSigner {
        /// Fingerprint of the signing key.
        fingerprint: String,
    },
    /// The signature was made for another purpose than signing git objects.
    #[error("signature namespace is {found:?}, expected \"git\"")]
    WrongNamespace {
        /// The namespace inside the signature.
        found: String,
    },
}

/// Verifies a raw annotated tag object (`git cat-file tag <tag>`).
///
/// The headers are checked before the signature, so a malformed or
/// mismatched object is refused for that reason. A tag is accepted only if
/// it is named `expected_tag`, points at a commit, and carries a `git`
/// namespace signature that verifies with one of `signers`.
///
/// # Errors
///
/// A [`TagVerifyError`] naming the first check that failed.
pub fn verify_tag(
    raw: &[u8],
    expected_tag: &ReleaseTag,
    signers: &[(PrincipalId, &SignerKey)],
) -> Result<SignedTag, TagVerifyError> {
    let start = signature_start(raw).ok_or(TagVerifyError::NotSigned)?;
    let (payload, armored) = raw.split_at(start);
    let headers = Headers::parse(payload)?;

    if headers.kind != "commit" {
        return Err(TagVerifyError::WrongType {
            found: shown(headers.kind),
        });
    }
    if headers.tag != expected_tag.as_ref() as &str {
        return Err(TagVerifyError::WrongTag {
            found: shown(headers.tag),
        });
    }
    let commit = headers.object.parse::<CommitSha>().map_err(|_| {
        malformed(format!(
            "object {:?} is not a commit id",
            shown(headers.object)
        ))
    })?;

    let signature = SshSig::from_pem(armored)
        .map_err(|e| malformed(format!("signature block is not a valid SSH signature: {e}")))?;
    if signature.namespace() != NAMESPACE {
        return Err(TagVerifyError::WrongNamespace {
            found: shown(signature.namespace()),
        });
    }
    let fingerprint = signature
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let (signer, key) = signers
        .iter()
        .find(|(_, key)| key.public_key().key_data() == signature.public_key())
        .ok_or(TagVerifyError::UnknownSigner {
            fingerprint: fingerprint.clone(),
        })?;
    key.public_key()
        .verify(NAMESPACE, payload, &signature)
        .map_err(|_| TagVerifyError::BadSignature)?;

    Ok(SignedTag {
        tag: expected_tag.clone(),
        commit,
        signer: signer.clone(),
        fingerprint,
    })
}

/// Offset of the last line that starts the signature block.
fn signature_start(raw: &[u8]) -> Option<usize> {
    let mut found = None;
    let mut line_start = 0;
    while line_start < raw.len() {
        if raw[line_start..].starts_with(SIGNATURE_START) {
            found = Some(line_start);
        }
        match raw[line_start..].iter().position(|&b| b == b'\n') {
            Some(newline) => line_start += newline + 1,
            None => break,
        }
    }
    found
}

/// The headers of a tag object that matter here.
struct Headers<'a> {
    object: &'a str,
    kind: &'a str,
    tag: &'a str,
}

impl<'a> Headers<'a> {
    /// Reads the header block (up to the first empty line) of the signed
    /// bytes. `object`, `type` and `tag` must each appear exactly once.
    fn parse(payload: &'a [u8]) -> Result<Self, TagVerifyError> {
        let (mut object, mut kind, mut tag) = (None, None, None);
        for line in payload.split(|&b| b == b'\n') {
            if line.is_empty() {
                break;
            }
            let line = std::str::from_utf8(line)
                .map_err(|_| malformed("a header line is not UTF-8".into()))?;
            let (name, value) = line
                .split_once(' ')
                .ok_or_else(|| malformed("a header line has no value".into()))?;
            let slot = match name {
                "object" => &mut object,
                "type" => &mut kind,
                "tag" => &mut tag,
                _ => continue,
            };
            if slot.replace(value).is_some() {
                return Err(malformed(format!("duplicate {name} header")));
            }
        }
        let missing = |name: &str| malformed(format!("no {name} header"));
        Ok(Self {
            object: object.ok_or_else(|| missing("object"))?,
            kind: kind.ok_or_else(|| missing("type"))?,
            tag: tag.ok_or_else(|| missing("tag"))?,
        })
    }
}

fn malformed(reason: String) -> TagVerifyError {
    TagVerifyError::Malformed { reason }
}

/// Shortens attacker-controlled text before it goes into an error.
fn shown(text: &str) -> String {
    const MAX: usize = 128;
    text.chars().take(MAX).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{self, Config};

    const VALID: &[u8] = include_bytes!("../tests/fixtures/tag/valid.tag");
    const UNKNOWN: &[u8] = include_bytes!("../tests/fixtures/tag/unknown-signer.tag");
    const UNSIGNED: &[u8] = include_bytes!("../tests/fixtures/tag/unsigned.tag");
    const WRONG_NAMESPACE: &[u8] = include_bytes!("../tests/fixtures/tag/wrong-namespace.tag");
    const TREE: &[u8] = include_bytes!("../tests/fixtures/tag/tree-object.tag");

    // Recorded from `make-fixtures.sh`; see the fixtures README.
    const COMMIT: &str = "7160f743d0664e041913065355d7bcd291ad2a01";
    const SIGNER_FINGERPRINT: &str = "SHA256:gdcqb1DcL2Rv7xn5I2LqM0wcjbk377gXNansYwAXoDQ";
    const OTHER_FINGERPRINT: &str = "SHA256:2CMsEhXo18QW2DrGcNms5cgJmcdUlUUyXlMIfWSmKA0";

    fn key(file: &str) -> SignerKey {
        let text = std::fs::read_to_string(format!(
            "{}/tests/fixtures/tag/{file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        SignerKey::parse(&text).unwrap()
    }

    fn tag(name: &str) -> ReleaseTag {
        name.parse().unwrap()
    }

    fn maintainer() -> PrincipalId {
        "maintainer".parse().unwrap()
    }

    fn verify(raw: &[u8], expected: &str) -> Result<SignedTag, TagVerifyError> {
        let key = key("signer.pub");
        verify_tag(raw, &tag(expected), &[(maintainer(), &key)])
    }

    fn signature_offset(raw: &[u8]) -> usize {
        signature_start(raw).unwrap()
    }

    #[test]
    fn valid_tag_verifies() {
        let signed = verify(VALID, "v1.2.3").unwrap();
        assert_eq!(signed.tag, tag("v1.2.3"));
        assert_eq!(signed.commit.to_string(), COMMIT);
        assert_eq!(signed.signer, maintainer());
        assert_eq!(signed.fingerprint, SIGNER_FINGERPRINT);
    }

    #[test]
    fn tampered_payload_is_refused() {
        let at = VALID
            .windows(b"tagger maintainer".len())
            .position(|w| w == b"tagger maintainer")
            .unwrap()
            + b"tagger ".len();
        let mut flipped = VALID.to_vec();
        flipped[at] ^= 1;
        assert_eq!(
            verify(&flipped, "v1.2.3"),
            Err(TagVerifyError::BadSignature)
        );

        let split = signature_offset(VALID);
        let mut extended = VALID[..split].to_vec();
        extended.push(b'\n');
        extended.extend_from_slice(&VALID[split..]);
        assert_eq!(
            verify(&extended, "v1.2.3"),
            Err(TagVerifyError::BadSignature)
        );
    }

    #[test]
    fn unknown_signer_is_refused() {
        assert_eq!(
            verify(UNKNOWN, "v1.2.3"),
            Err(TagVerifyError::UnknownSigner {
                fingerprint: OTHER_FINGERPRINT.to_owned()
            })
        );
    }

    #[test]
    fn unsigned_tag_is_refused() {
        assert_eq!(verify(UNSIGNED, "v1.2.3"), Err(TagVerifyError::NotSigned));
        assert_eq!(verify(b"", "v1.2.3"), Err(TagVerifyError::NotSigned));
    }

    #[test]
    fn wrong_tag_name_is_refused() {
        assert_eq!(
            verify(VALID, "v1.2.4"),
            Err(TagVerifyError::WrongTag {
                found: "v1.2.3".to_owned()
            })
        );
    }

    #[test]
    fn non_commit_object_is_refused() {
        assert_eq!(
            verify(TREE, "v1.2.3"),
            Err(TagVerifyError::WrongType {
                found: "tree".to_owned()
            })
        );
    }

    #[test]
    fn duplicate_headers_are_malformed() {
        let split = signature_offset(VALID);
        let payload = std::str::from_utf8(&VALID[..split]).unwrap();
        let (first, _) = payload.split_once('\n').unwrap();
        for duplicated in [first, "type commit", "tag v1.2.3"] {
            let mut raw = format!("{duplicated}\n{payload}").into_bytes();
            raw.extend_from_slice(&VALID[split..]);
            assert!(
                matches!(
                    verify(&raw, "v1.2.3"),
                    Err(TagVerifyError::Malformed { .. })
                ),
                "{duplicated}"
            );
        }
    }

    #[test]
    fn missing_headers_are_malformed() {
        let split = signature_offset(VALID);
        let payload = std::str::from_utf8(&VALID[..split]).unwrap();
        for dropped in ["object ", "type ", "tag "] {
            let kept: Vec<&str> = payload
                .split_inclusive('\n')
                .filter(|l| !l.starts_with(dropped))
                .collect();
            let mut raw = kept.concat().into_bytes();
            raw.extend_from_slice(&VALID[split..]);
            assert!(
                matches!(
                    verify(&raw, "v1.2.3"),
                    Err(TagVerifyError::Malformed { .. })
                ),
                "{dropped}"
            );
        }
    }

    #[test]
    fn signature_in_another_namespace_is_refused() {
        assert_eq!(
            verify(WRONG_NAMESPACE, "v1.2.3"),
            Err(TagVerifyError::WrongNamespace {
                found: "file".to_owned()
            })
        );
    }

    #[test]
    fn garbage_signature_block_is_malformed() {
        let split = signature_offset(VALID);
        let mut raw = VALID[..split].to_vec();
        raw.extend_from_slice(
            b"-----BEGIN SSH SIGNATURE-----\nnot base64 !\n-----END SSH SIGNATURE-----\n",
        );
        assert!(matches!(
            verify(&raw, "v1.2.3"),
            Err(TagVerifyError::Malformed { .. })
        ));
    }

    #[test]
    fn config_signers_feed_verification() {
        let text = format!(
            "[signers]\nmaintainer = {:?}\n",
            std::fs::read_to_string(format!(
                "{}/tests/fixtures/tag/signer.pub",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap()
        );
        let config: Config = config::parse(text.as_bytes()).unwrap();
        let id = maintainer();
        let key = config.signer(&id).unwrap();
        assert!(verify_tag(VALID, &tag("v1.2.3"), &[(id, key)]).is_ok());
    }
}
