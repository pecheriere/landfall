//! Maintainer signatures on release tags.
//!
//! `git tag -s` with an SSH key (`gpg.format = ssh`) writes an annotated tag
//! object whose signature, an armored `SshSig` in namespace `git`, is
//! appended to the message. The signed bytes are the object up to the
//! signature block. [`verify_tag`] checks such an object against the trusted
//! keys and returns the facts it proves: which tag, which commit, signed by
//! whom. Nothing outside the signed bytes is trusted, and a failure names
//! what was expected and what was found. OpenPGP and X.509 signatures are
//! recognised and refused as unsupported.

use serde::Serialize;
use ssh_key::SshSig;
use thiserror::Error;

use crate::config::SignerKey;
use crate::ids::{CommitSha, PrincipalId, ReleaseTag};
use crate::text::shown;

/// The namespace `git` signs tags under.
const NAMESPACE: &str = "git";

/// Opens the armored signature that `git` appends to a signed tag.
const SIGNATURE_START: &[u8] = b"-----BEGIN SSH SIGNATURE-----";

/// The armor lines `git` writes for the signature formats landfall does not
/// verify (`gpg.format = openpgp` and `x509`), with their names.
const UNSUPPORTED_SIGNATURES: [(&[u8], &str); 2] = [
    (b"-----BEGIN PGP SIGNATURE-----", "OpenPGP"),
    (b"-----BEGIN SIGNED MESSAGE-----", "X.509"),
];

/// What a valid maintainer signature on a release tag proves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
    /// The object carries an OpenPGP or X.509 signature and no SSH one.
    /// Only SSH signatures are verified, so such a tag is refused.
    #[error(
        "tag carries an {kind} signature; only SSH signatures are supported \
         (git tag -s with gpg.format = ssh)"
    )]
    UnsupportedSignature {
        /// `"OpenPGP"` or `"X.509"`.
        kind: &'static str,
    },
    /// The object cannot be read as a signed annotated tag.
    #[error("tag object is malformed: {reason}")]
    Malformed {
        /// What is wrong with it.
        reason: String,
    },
    /// The tag points at something other than a commit.
    #[error("tag points at a {found} object, expected a commit")]
    WrongType {
        /// The object type the tag names, quoted and shortened.
        found: String,
    },
    /// The signed tag has another name than the release being verified.
    #[error("signed tag is named {found}, expected {expected:?}")]
    WrongTag {
        /// The tag name being verified.
        expected: String,
        /// The tag name inside the signed object, quoted and shortened.
        found: String,
    },
    /// The signature does not match the bytes it covers.
    #[error("tag signature does not verify")]
    BadSignature,
    /// The signature claims a key that is not among the trusted signers. The
    /// signature has not been checked at that point, so the fingerprint is
    /// only what the object says.
    #[error("tag signature claims key {fingerprint}, which is not a trusted signer")]
    UnknownSigner {
        /// Fingerprint of the key the signature claims.
        fingerprint: String,
    },
    /// The signature was made for another purpose than signing git objects.
    #[error("signature namespace is {found}, expected \"git\"")]
    WrongNamespace {
        /// The namespace inside the signature, quoted and shortened.
        found: String,
    },
}

/// Verifies a raw annotated tag object (`git cat-file tag <tag>`).
///
/// The headers are checked before the signature, so a malformed or
/// mismatched object is refused for that reason. A tag is accepted only if
/// it is named `expected_tag`, points at a commit, and carries a `git`
/// namespace SSH signature that verifies with one of `signers`.
///
/// # Errors
///
/// A [`TagVerifyError`] naming the first check that failed.
pub fn verify_tag(
    raw: &[u8],
    expected_tag: &ReleaseTag,
    signers: &[(PrincipalId, &SignerKey)],
) -> Result<SignedTag, TagVerifyError> {
    let start = signature_start(raw).ok_or_else(|| unsigned(raw))?;
    let (payload, armored) = raw.split_at(start);
    let headers = Headers::parse(payload)?;

    if headers.kind != "commit" {
        return Err(TagVerifyError::WrongType {
            found: shown(headers.kind),
        });
    }
    if headers.tag != expected_tag.as_ref() as &str {
        return Err(TagVerifyError::WrongTag {
            expected: expected_tag.to_string(),
            found: shown(headers.tag),
        });
    }
    let commit = headers.object.parse::<CommitSha>().map_err(|_| {
        malformed(format!(
            "object {} is not a commit id",
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
    lines(raw)
        .filter(|&(_, line)| line.starts_with(SIGNATURE_START))
        .map(|(offset, _)| offset)
        .last()
}

/// Why an object without an SSH signature block is refused: it carries a
/// signature of an unsupported format, or none.
fn unsigned(raw: &[u8]) -> TagVerifyError {
    lines(raw)
        .find_map(|(_, line)| {
            UNSUPPORTED_SIGNATURES
                .iter()
                .find(|(armor, _)| line.starts_with(armor))
        })
        .map_or(TagVerifyError::NotSigned, |&(_, kind)| {
            TagVerifyError::UnsupportedSignature { kind }
        })
}

/// Each line of `raw` with its offset.
fn lines(raw: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    raw.split_inclusive(|&b| b == b'\n')
        .scan(0, |offset, line| {
            let start = *offset;
            *offset += line.len();
            Some((start, line))
        })
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
    const SIGNER_FINGERPRINT: &str = "SHA256:aN9xB/PG8u3ubV37qOIeOe3nPDkWfAzfFl+We+g5ASA";
    const OTHER_FINGERPRINT: &str = "SHA256:cRL49yC67xm1DyK5ViDqOGgd4BMfcjucVSAUA7c0Aeo";

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

    /// A tag signed with `gpg.format = openpgp` or `x509`: the payload of
    /// the valid tag with that format's armor block appended.
    #[test]
    fn unsupported_signature_formats_are_named() {
        let split = signature_offset(VALID);
        for (armor, kind) in [
            (
                "-----BEGIN PGP SIGNATURE-----\n\niQEzBAABCAAdFiEE\n=abcd\n-----END PGP SIGNATURE-----\n",
                "OpenPGP",
            ),
            (
                "-----BEGIN SIGNED MESSAGE-----\nMIIC\n-----END SIGNED MESSAGE-----\n",
                "X.509",
            ),
        ] {
            let mut raw = VALID[..split].to_vec();
            raw.extend_from_slice(armor.as_bytes());
            let result = verify(&raw, "v1.2.3");
            assert_eq!(
                result,
                Err(TagVerifyError::UnsupportedSignature { kind }),
                "{kind}"
            );
            let message = result.unwrap_err().to_string();
            assert!(
                message.contains("only SSH signatures are supported"),
                "{message}"
            );
        }
    }

    #[test]
    fn hostile_header_values_are_quoted_and_shortened() {
        let split = signature_offset(VALID);
        let payload = std::str::from_utf8(&VALID[..split]).unwrap();
        let hostile = format!("x\u{1b}[2J{}", "y".repeat(200));
        let mut raw = payload
            .replacen("tag v1.2.3", &format!("tag {hostile}"), 1)
            .into_bytes();
        raw.extend_from_slice(&VALID[split..]);
        match verify(&raw, "v1.2.3") {
            Err(TagVerifyError::WrongTag { found, .. }) => {
                assert!(found.starts_with("\"x\\u{1b}[2J"), "{found}");
                assert!(found.ends_with("\"..."), "{found}");
                assert!(found.len() < 80, "{found}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn wrong_tag_name_is_refused() {
        assert_eq!(
            verify(VALID, "v1.2.4"),
            Err(TagVerifyError::WrongTag {
                expected: "v1.2.4".to_owned(),
                found: "\"v1.2.3\"".to_owned()
            })
        );
    }

    #[test]
    fn non_commit_object_is_refused() {
        assert_eq!(
            verify(TREE, "v1.2.3"),
            Err(TagVerifyError::WrongType {
                found: "\"tree\"".to_owned()
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
                found: "\"file\"".to_owned()
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
