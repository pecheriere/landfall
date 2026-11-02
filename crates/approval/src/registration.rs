//! Parsing an attestation, `WebAuthn` 7.1, for the key it carries.
//!
//! This proves nothing about the authenticator, and is not meant to: the key is
//! trusted because an operator reviews it and copies it into the configuration (design
//! 6.3). So any `fmt` is accepted and `attStmt` is never read, which lets a passkey
//! that insists on self attestation register.
//!
//! Parsing is lenient about encoding, since refusing here gains nothing: entries and
//! labels in any order and longer lengths are accepted, and the key comes out in its
//! canonical encoding, which is what's stored and shown, and the only form
//! [`CoseKey::parse`] takes at config load.

use landfall_core::text::shown;
use minicbor::Decoder;

use crate::authenticator_data::{AuthenticatorData, AuthenticatorDataError};
use crate::client_data::{self, ClientDataError};
use crate::cose::{CoseError, CoseKey};

/// `aaguid` (16) and `credentialIdLength` (2).
const CREDENTIAL_HEADER_LEN: usize = 18;
/// 7.1: a relying party refuses a longer credential id.
const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// What a registration yields, for the operator to copy into the configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Registered {
    /// The new credential's id.
    pub credential_id: Vec<u8>,
    /// The new credential's key, in its canonical encoding whatever was sent.
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

/// Runs the checks of `WebAuthn` 7.1 that don't trust an attestation, in its order,
/// and returns the credential.
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
    let auth_data = authenticator_data_of(attestation_object)?;
    let data = AuthenticatorData::parse(auth_data)?;
    data.check_relying_party_and_user(rp_id)?;
    if !data.has_attested_data() {
        return Err(AuthenticatorDataError::MissingAttestedData.into());
    }
    let (credential_id, key, tail) = attested_credential(data.rest)?;
    data.check_extensions(tail)?;
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
    let (key, end) = CoseKey::normalise_prefix(rest)?;
    Ok((id.to_vec(), key, rest.get(end..).unwrap_or_default()))
}

/// The `authData` of an attestation object: a map of exactly `fmt`, `attStmt` and
/// `authData`, in any order, with nothing after it. `fmt` has to be text and `attStmt`
/// well-formed, and neither is otherwise read.
fn authenticator_data_of(bytes: &[u8]) -> Result<&[u8], RegistrationError> {
    let malformed = |e: minicbor::decode::Error| RegistrationError::Malformed(e.to_string());
    let mut d = Decoder::new(bytes);
    let Some(3) = d.map().map_err(malformed)? else {
        return Err(RegistrationError::Malformed(
            "expected a map of three entries".to_owned(),
        ));
    };
    let (mut format, mut statement, mut auth_data) = (false, false, None);
    for _ in 0..3 {
        match d.str().map_err(malformed)? {
            "fmt" => {
                d.str().map_err(malformed)?;
                format = true;
            }
            "attStmt" => {
                d.skip().map_err(malformed)?;
                statement = true;
            }
            "authData" => auth_data = Some(d.bytes().map_err(malformed)?),
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
    match auth_data {
        Some(auth_data) if format && statement => Ok(auth_data),
        _ => Err(RegistrationError::Malformed(
            "an entry is missing or repeated".to_owned(),
        )),
    }
}
