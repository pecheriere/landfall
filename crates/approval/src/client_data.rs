//! `clientDataJSON`: what the browser says it was asked to sign.

use std::collections::HashSet;
use std::fmt;

use landfall_core::text::{quoted, shown};
use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};

use crate::wire;

/// Why client data was refused. Found values are quoted and truncated: they come
/// from whoever sent the assertion.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum ClientDataError {
    /// Not JSON, has a duplicate key, or lacks a required member.
    #[error("clientDataJSON is malformed: {0}")]
    Malformed(String),
    /// `type` is not the one this ceremony needs.
    #[error("clientDataJSON type: expected {expected}, found {found}")]
    Type {
        /// The ceremony's type.
        expected: String,
        /// The type in the client data.
        found: String,
    },
    /// `challenge` is not the base64url of the expected challenge.
    #[error("clientDataJSON challenge: expected {expected}, found {found}")]
    Challenge {
        /// The base64url of the expected challenge.
        expected: String,
        /// The challenge in the client data.
        found: String,
    },
    /// `origin` is not exactly the configured one.
    #[error("clientDataJSON origin: expected {expected}, found {found}")]
    Origin {
        /// The configured origin.
        expected: String,
        /// The origin in the client data.
        found: String,
    },
    /// `crossOrigin` is true: the ceremony ran in a frame of another origin.
    #[error("clientDataJSON crossOrigin: expected absent or false, found true")]
    CrossOrigin,
    /// `tokenBinding` claims a bound connection.
    #[error("clientDataJSON tokenBinding: expected no bound connection, found one")]
    TokenBinding,
}

/// What one ceremony expects of its client data.
pub(crate) struct Expected<'a> {
    /// `webauthn.get` or `webauthn.create`.
    pub(crate) kind: &'static str,
    /// The challenge's raw bytes.
    pub(crate) challenge: &'a [u8],
    /// The exact origin.
    pub(crate) origin: &'a str,
}

/// The members read from client data. Others are allowed, section 5.8.1 reserves
/// room for them, and none of them changes what is checked here.
#[derive(serde::Deserialize)]
struct ClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default, rename = "crossOrigin", deserialize_with = "present_bool")]
    cross_origin: Option<bool>,
    #[serde(default, rename = "tokenBinding")]
    token_binding: Option<TokenBinding>,
}

#[derive(serde::Deserialize)]
struct TokenBinding {
    status: String,
}

/// A member that is present must be a boolean: `null` is neither absent nor false.
fn present_bool<'de, D: Deserializer<'de>>(d: D) -> Result<Option<bool>, D::Error> {
    bool::deserialize(d).map(Some)
}

/// Runs the client data steps of `WebAuthn` 7.1 and 7.2 in order. Nothing is
/// decoded before it is compared: the challenge is compared as text, so one
/// challenge has one accepted form. A leading byte order mark, which step 9's decoder
/// would strip, is refused: 5.8.1.1 has client data start with `{"type":`.
pub(crate) fn check(
    client_data_json: &[u8],
    expected: &Expected<'_>,
) -> Result<(), ClientDataError> {
    let malformed = |e: serde_json::Error| ClientDataError::Malformed(quoted(&e.to_string(), 128));
    serde_json::from_slice::<NoDuplicateKeys>(client_data_json).map_err(malformed)?;
    let data: ClientData = serde_json::from_slice(client_data_json).map_err(malformed)?;

    if data.kind != expected.kind {
        return Err(ClientDataError::Type {
            expected: shown(expected.kind),
            found: shown(&data.kind),
        });
    }
    let challenge = wire::encode(expected.challenge);
    if data.challenge != challenge {
        return Err(ClientDataError::Challenge {
            expected: shown(&challenge),
            found: shown(&data.challenge),
        });
    }
    if data.origin != expected.origin {
        return Err(ClientDataError::Origin {
            expected: shown(expected.origin),
            found: shown(&data.origin),
        });
    }
    if data.cross_origin == Some(true) {
        return Err(ClientDataError::CrossOrigin);
    }
    // Token binding belongs to the TLS connection the browser used, which the
    // verifier is not on and the controller never negotiates, so a client saying
    // one was in use can't be telling the truth about this ceremony.
    if data.token_binding.is_some_and(|t| t.status == "present") {
        return Err(ClientDataError::TokenBinding);
    }
    Ok(())
}

/// Accepts any JSON value without a repeated key in any object, nested or not,
/// comparing keys after unescaping. A parser that keeps the last of two `origin`
/// members and one that keeps the first would read different client data.
struct NoDuplicateKeys;

impl<'de> Deserialize<'de> for NoDuplicateKeys {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(NoDuplicateKeysVisitor)
    }
}

struct NoDuplicateKeysVisitor;

impl<'de> Visitor<'de> for NoDuplicateKeysVisitor {
    type Value = NoDuplicateKeys;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<NoDuplicateKeys, A::Error> {
        let mut seen = HashSet::new();
        while let Some(key) = map.next_key::<String>()? {
            map.next_value::<NoDuplicateKeys>()?;
            if !seen.insert(key) {
                return Err(serde::de::Error::custom("duplicate key"));
            }
        }
        Ok(NoDuplicateKeys)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<NoDuplicateKeys, A::Error> {
        while seq.next_element::<NoDuplicateKeys>()?.is_some() {}
        Ok(NoDuplicateKeys)
    }

    fn visit_bool<E>(self, _: bool) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_i64<E>(self, _: i64) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_u64<E>(self, _: u64) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_f64<E>(self, _: f64) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_str<E>(self, _: &str) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }

    fn visit_unit<E>(self) -> Result<NoDuplicateKeys, E> {
        Ok(NoDuplicateKeys)
    }
}
