//! Parsing a `none` attestation, `WebAuthn` 7.1, for the key it carries.
//!
//! This proves nothing about the authenticator, and is not meant to: the key is
//! trusted because an operator copies it into the configuration (design 6.3).

use landfall_core::text::shown;
use minicbor::Decoder;

use crate::authenticator_data::{AuthenticatorData, AuthenticatorDataError};
use crate::client_data::{self, ClientDataError};
use crate::cose::{CoseError, CoseKey};

/// `aaguid` (16) and `credentialIdLength` (2).
const CREDENTIAL_HEADER_LEN: usize = 18;
/// 7.1: a relying party refuses a longer credential id.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

const MAJOR_BYTES: u8 = 2;
const MAJOR_TEXT: u8 = 3;

/// What a registration yields, for the operator to copy into the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The new credential's id.
    pub credential_id: Vec<u8>,
    /// The new credential's key.
    pub key: CoseKey,
}

/// Why a registration was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RegistrationError {
    /// A check on the client data failed.
    #[error(transparent)]
    ClientData(#[from] ClientDataError),
    /// A check on the authenticator data failed.
    #[error(transparent)]
    AuthenticatorData(#[from] AuthenticatorDataError),
    /// The attested key was refused.
    #[error(transparent)]
    Key(#[from] CoseError),
    /// The attestation object isn't the CBOR map it should be.
    #[error("attestation object is malformed: {0}")]
    Malformed(String),
    /// The attestation format isn't `none`.
    #[error("attestation format: expected \"none\", found {found}")]
    Format {
        /// The format in the object.
        found: String,
    },
    /// A `none` attestation's statement isn't the empty map (8.7).
    #[error("a none attestation has a non-empty statement")]
    StatementNotEmpty,
    /// The right values, not in the CTAP2 canonical encoding.
    #[error("attestation object is not in the canonical encoding")]
    NotCanonical,
    /// Attested credential data ends before it should.
    #[error("attested credential data is too short")]
    CredentialDataTooShort,
    /// The credential id is empty or longer than 1023 bytes.
    #[error("credential id is {found} bytes, 1 to {MAX_CREDENTIAL_ID_LEN} are allowed")]
    CredentialIdLength {
        /// The length in the attested credential data.
        found: usize,
    },
}

/// Runs the checks of `WebAuthn` 7.1 that apply to a `none` attestation, in its
/// order, and returns the credential.
///
/// # Errors
///
/// The first check that failed, as a [`RegistrationError`].
pub fn parse_registration(
    attestation_object: &[u8],
    client_data_json: &[u8],
    rp_id: &str,
    origin: &str,
    challenge: &[u8],
) -> Result<Registered, RegistrationError> {
    client_data::check(
        client_data_json,
        &client_data::Expected {
            kind: "webauthn.create",
            challenge,
            origin,
        },
    )?;
    let object = AttestationObject::decode(attestation_object)?;
    let data = AuthenticatorData::parse(object.auth_data)?;
    data.check_relying_party_and_user(rp_id)?;
    if !data.has_attested_data() {
        return Err(AuthenticatorDataError::MissingAttestedData.into());
    }
    let (credential_id, key, tail) = attested_credential(data.rest)?;
    data.check_extensions(tail)?;

    if object.format != "none" {
        return Err(RegistrationError::Format {
            found: shown(object.format),
        });
    }
    if object.statement != [0xa0] {
        return Err(RegistrationError::StatementNotEmpty);
    }
    if encode_attestation_object(object.format, object.statement, object.auth_data)
        != attestation_object
    {
        return Err(RegistrationError::NotCanonical);
    }
    Ok(Registered { credential_id, key })
}

/// 6.5.1: `aaguid`, the credential id with its length, then the key, whose encoding
/// is the only thing that says where it ends.
fn attested_credential(rest: &[u8]) -> Result<(Vec<u8>, CoseKey, &[u8]), RegistrationError> {
    let (header, rest) = rest
        .split_at_checked(CREDENTIAL_HEADER_LEN)
        .ok_or(RegistrationError::CredentialDataTooShort)?;
    let [.., high, low] = *header else {
        return Err(RegistrationError::CredentialDataTooShort);
    };
    let length = usize::from(u16::from_be_bytes([high, low]));
    if length == 0 || length > MAX_CREDENTIAL_ID_LEN {
        return Err(RegistrationError::CredentialIdLength { found: length });
    }
    let (id, rest) = rest
        .split_at_checked(length)
        .ok_or(RegistrationError::CredentialDataTooShort)?;
    let (key, end) = CoseKey::parse_prefix(rest)?;
    Ok((id.to_vec(), key, rest.get(end..).unwrap_or_default()))
}

/// The members of an attestation object, not yet judged.
struct AttestationObject<'a> {
    format: &'a str,
    /// The statement's encoded bytes.
    statement: &'a [u8],
    auth_data: &'a [u8],
}

impl<'a> AttestationObject<'a> {
    fn decode(bytes: &'a [u8]) -> Result<Self, RegistrationError> {
        let malformed = |e: minicbor::decode::Error| RegistrationError::Malformed(e.to_string());
        let mut d = Decoder::new(bytes);
        let Some(3) = d.map().map_err(malformed)? else {
            return Err(RegistrationError::Malformed(
                "expected a map of three entries".to_owned(),
            ));
        };
        let (mut format, mut statement, mut auth_data) = (None, None, None);
        for _ in 0..3 {
            let key = d.str().map_err(malformed)?;
            match key {
                "fmt" => format = Some(d.str().map_err(malformed)?),
                "authData" => auth_data = Some(d.bytes().map_err(malformed)?),
                "attStmt" => {
                    let start = d.position();
                    d.skip().map_err(malformed)?;
                    statement = bytes.get(start..d.position());
                }
                other => {
                    return Err(RegistrationError::Malformed(format!(
                        "unexpected entry {}",
                        shown(other)
                    )));
                }
            }
        }
        if d.position() != bytes.len() {
            return Err(RegistrationError::Malformed(format!(
                "{} bytes follow the map",
                bytes.len() - d.position()
            )));
        }
        // Three entries and three allowed keys: a repeated one leaves another unset.
        match (format, statement, auth_data) {
            (Some(format), Some(statement), Some(auth_data)) => Ok(Self {
                format,
                statement,
                auth_data,
            }),
            _ => Err(RegistrationError::Malformed(
                "an entry is missing or repeated".to_owned(),
            )),
        }
    }
}

/// The canonical encoding of an attestation object: three keys, shortest first.
pub(crate) fn encode_attestation_object(
    format: &str,
    statement: &[u8],
    auth_data: &[u8],
) -> Vec<u8> {
    let mut out = vec![0xa3];
    push_text(&mut out, "fmt");
    push_text(&mut out, format);
    push_text(&mut out, "attStmt");
    out.extend_from_slice(statement);
    push_text(&mut out, "authData");
    push_head(&mut out, MAJOR_BYTES, auth_data.len());
    out.extend_from_slice(auth_data);
    out
}

fn push_text(out: &mut Vec<u8>, text: &str) {
    push_head(out, MAJOR_TEXT, text.len());
    out.extend_from_slice(text.as_bytes());
}

/// A CBOR head in its shortest form.
fn push_head(out: &mut Vec<u8>, major: u8, len: usize) {
    let be = (len as u64).to_be_bytes();
    let (info, width) = match len {
        0..=23 => (be[7], 0),
        24..=0xff => (24, 1),
        0x100..=0xffff => (25, 2),
        0x1_0000..=0xffff_ffff => (26, 4),
        _ => (27, 8),
    };
    out.push((major << 5) | info);
    out.extend_from_slice(&be[8 - width..]);
}
