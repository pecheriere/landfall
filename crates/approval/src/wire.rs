//! Base64url without padding: the text form of every `WebAuthn` byte string here.
//!
//! The engine refuses padding and non-zero trailing bits, so one byte string has
//! exactly one text form.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serializer};

/// The text form of `bytes`.
pub(crate) fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Serde adapter: serializes bytes as their text form.
pub(crate) fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&encode(bytes))
}

/// Serde adapter: deserializes bytes from their text form.
pub(crate) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
    let text = String::deserialize(d)?;
    URL_SAFE_NO_PAD
        .decode(&text)
        .map_err(|_| serde::de::Error::custom("not unpadded base64url"))
}
