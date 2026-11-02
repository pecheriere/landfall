//! Verifying an assertion, `WebAuthn` 7.2.

use aws_lc_rs::digest::{SHA256, digest};
use landfall_core::config::MAX_CREDENTIAL_ID_LEN;
use landfall_core::protocol::AssertionText;
use landfall_core::text::quoted;
use serde::{Deserialize, Serialize};

use crate::authenticator_data::{AuthenticatorData, AuthenticatorDataError};
use crate::client_data::{self, ClientDataError};
use crate::cose::CoseKey;
use crate::wire;

/// How much of a credential id an error shows: it comes from the sender, and it
/// isn't otherwise bounded here.
const SHOWN_CREDENTIAL_ID: usize = 128;

/// The longest authenticator data off the wire: 37 bytes and the extensions, which are
/// short CBOR on anything real.
pub const MAX_AUTHENTICATOR_DATA_BYTES: usize = 4096;
/// The longest client data off the wire: browsers send a few hundred bytes.
pub const MAX_CLIENT_DATA_BYTES: usize = 16 * 1024;
/// The longest signature off the wire: ES256 DER is at most 72 bytes and `EdDSA` is 64.
pub const MAX_SIGNATURE_BYTES: usize = 256;

/// What `navigator.credentials.get()` returned, all bytes, base64url on the wire.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Assertion {
    /// The credential that signed.
    #[serde(with = "wire")]
    pub credential_id: Vec<u8>,
    /// The authenticator's data, as signed.
    #[serde(with = "wire")]
    pub authenticator_data: Vec<u8>,
    /// The browser's client data, as hashed into the signature.
    #[serde(with = "wire")]
    pub client_data_json: Vec<u8>,
    /// The signature: ASN.1 DER for ES256, 64 bytes for `EdDSA`.
    #[serde(with = "wire")]
    pub signature: Vec<u8>,
}

/// What an assertion has to match, all of it from the verifier's own state.
#[derive(Debug, Clone, Copy)]
pub struct Expect<'a> {
    /// The key from local configuration.
    pub key: &'a CoseKey,
    /// That key's credential id.
    pub credential_id: &'a [u8],
    /// The configured RP ID, the origin's exact hostname.
    pub rp_id: &'a str,
    /// The configured origin.
    pub origin: &'a str,
    /// The challenge's raw bytes: recomputed from the intent, never taken from the
    /// sender.
    pub challenge: &'a [u8],
}

/// Why an assertion was refused. Nothing here is secret: it's about what a sender
/// sent, quoted and truncated, and goes in the journal.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AssertionError {
    /// Another credential signed.
    #[error("credential id: expected {expected}, found {found}")]
    CredentialId {
        /// The base64url of the configured credential id.
        expected: String,
        /// The base64url of the one sent.
        found: String,
    },
    /// A check on the client data failed.
    #[error(transparent)]
    ClientData(#[from] ClientDataError),
    /// A check on the authenticator data failed.
    #[error(transparent)]
    AuthenticatorData(#[from] AuthenticatorDataError),
    /// The signature isn't one by this key over these bytes.
    #[error("the signature does not verify")]
    Signature,
    /// A field off the wire is longer than any real one. It wasn't decoded.
    #[error("assertion {field}: longer than the {limit} bytes allowed")]
    TooLong {
        /// The field.
        field: &'static str,
        /// The most bytes it may decode to.
        limit: usize,
    },
    /// A field off the wire isn't unpadded base64url.
    #[error("assertion {field}: not unpadded base64url")]
    Encoding {
        /// The field.
        field: &'static str,
    },
}

/// Decodes one field of an [`AssertionText`], its length checked first: the text may be
/// as long as the whole body it came in, and [`verify`] has no limits of its own.
fn decoded(field: &'static str, text: &str, limit: usize) -> Result<Vec<u8>, AssertionError> {
    if text.len() > (limit * 4).div_ceil(3) {
        return Err(AssertionError::TooLong { field, limit });
    }
    wire::decode(text).map_err(|_| AssertionError::Encoding { field })
}

impl TryFrom<&AssertionText> for Assertion {
    type Error = AssertionError;

    /// Reads an assertion as the wire has it, each field capped before it is decoded.
    fn try_from(text: &AssertionText) -> Result<Self, AssertionError> {
        Ok(Self {
            credential_id: decoded("credential_id", &text.credential_id, MAX_CREDENTIAL_ID_LEN)?,
            authenticator_data: decoded(
                "authenticator_data",
                &text.authenticator_data,
                MAX_AUTHENTICATOR_DATA_BYTES,
            )?,
            client_data_json: decoded(
                "client_data_json",
                &text.client_data_json,
                MAX_CLIENT_DATA_BYTES,
            )?,
            signature: decoded("signature", &text.signature, MAX_SIGNATURE_BYTES)?,
        })
    }
}

/// Verifies `assertion` against `expect`, in the order of `WebAuthn` 7.2. Every
/// check is required.
///
/// # Errors
///
/// The first check that failed, as an [`AssertionError`].
pub fn verify(assertion: &Assertion, expect: &Expect<'_>) -> Result<(), AssertionError> {
    if assertion.credential_id != expect.credential_id {
        return Err(AssertionError::CredentialId {
            expected: shown_id(expect.credential_id),
            found: shown_id(&assertion.credential_id),
        });
    }
    client_data::check(
        &assertion.client_data_json,
        &client_data::Expected {
            kind: "webauthn.get",
            challenge: expect.challenge,
            origin: expect.origin,
        },
    )?;
    let data = AuthenticatorData::parse(&assertion.authenticator_data)?;
    data.check_relying_party_and_user(expect.rp_id)?;
    // 6.3.3 leaves attested credential data out of an assertion, and nothing here
    // would read it.
    if data.has_attested_data() {
        return Err(AuthenticatorDataError::UnexpectedAttestedData.into());
    }
    data.check_extensions(data.rest)?;

    let hash = digest(&SHA256, &assertion.client_data_json);
    let mut signed = assertion.authenticator_data.clone();
    signed.extend_from_slice(hash.as_ref());
    if expect.key.verify_signature(&signed, &assertion.signature) {
        Ok(())
    } else {
        Err(AssertionError::Signature)
    }
}

fn shown_id(id: &[u8]) -> String {
    quoted(&wire::encode(id), SHOWN_CREDENTIAL_ID)
}
