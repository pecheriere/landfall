//! Authenticator data (`WebAuthn` 6.1): what the authenticator signed about itself.

use std::collections::HashSet;

use aws_lc_rs::digest::{SHA256, digest};
use minicbor::Decoder;

use crate::wire;

/// Bit 0: a person was present.
pub(crate) const FLAG_UP: u8 = 0x01;
/// Bit 2: the person was verified, by a PIN or biometric.
pub(crate) const FLAG_UV: u8 = 0x04;
/// Bit 6: attested credential data follows the fixed part.
pub(crate) const FLAG_AT: u8 = 0x40;
/// Bit 7: extension data follows.
pub(crate) const FLAG_ED: u8 = 0x80;

/// `rpIdHash` (32), flags (1) and `signCount` (4).
const FIXED_LEN: usize = 37;

/// Why authenticator data was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum AuthenticatorDataError {
    /// Shorter than its fixed part.
    #[error("authenticator data is {found} bytes, at least {FIXED_LEN} are required")]
    TooShort {
        /// The length received.
        found: usize,
    },
    /// `rpIdHash` is not the SHA-256 of the configured RP ID.
    #[error("rpIdHash: expected {expected}, found {found}")]
    RpIdHash {
        /// The base64url of the hash of the configured RP ID.
        expected: String,
        /// The base64url of the hash received.
        found: String,
    },
    /// The UP flag is clear.
    #[error("the user present flag is not set")]
    UserNotPresent,
    /// The UV flag is clear.
    #[error("the user verified flag is not set")]
    UserNotVerified,
    /// An assertion carries attested credential data, which only registration has.
    #[error("the attested credential data flag is set on an assertion")]
    UnexpectedAttestedData,
    /// A registration lacks attested credential data.
    #[error("the attested credential data flag is not set")]
    MissingAttestedData,
    /// The ED flag is set, with no bytes after it.
    #[error("the extension data flag is set, with no extension data")]
    MissingExtensions,
    /// The extension data isn't a CBOR map of text keys.
    #[error("extension data is malformed: {0}")]
    MalformedExtensions(String),
    /// Bytes follow everything the flags declare.
    #[error("{found} bytes follow what the flags declare")]
    TrailingBytes {
        /// How many.
        found: usize,
    },
}

/// Authenticator data split into its fixed part and the rest.
pub(crate) struct AuthenticatorData<'a> {
    rp_id_hash: &'a [u8],
    flags: u8,
    /// Attested credential data and extensions, as the flags declare.
    pub(crate) rest: &'a [u8],
}

impl<'a> AuthenticatorData<'a> {
    /// Splits `bytes`. The signature counter is not read: see the crate's docs.
    pub(crate) fn parse(bytes: &'a [u8]) -> Result<Self, AuthenticatorDataError> {
        let too_short = AuthenticatorDataError::TooShort { found: bytes.len() };
        let (fixed, rest) = bytes.split_at_checked(FIXED_LEN).ok_or(too_short)?;
        let (rp_id_hash, tail) = fixed.split_at(32);
        let flags = tail.first().copied().unwrap_or_default();
        Ok(Self {
            rp_id_hash,
            flags,
            rest,
        })
    }

    /// `rpIdHash` is exactly the hash of `rp_id`, UP and UV are set. Other flag bits
    /// are not read: bits 3 and 4 say whether the credential is synced, which is
    /// how passkeys legitimately differ.
    pub(crate) fn check_relying_party_and_user(
        &self,
        rp_id: &str,
    ) -> Result<(), AuthenticatorDataError> {
        let expected = digest(&SHA256, rp_id.as_bytes());
        if self.rp_id_hash != expected.as_ref() {
            return Err(AuthenticatorDataError::RpIdHash {
                expected: wire::encode(expected.as_ref()),
                found: wire::encode(self.rp_id_hash),
            });
        }
        if self.flags & FLAG_UP == 0 {
            return Err(AuthenticatorDataError::UserNotPresent);
        }
        if self.flags & FLAG_UV == 0 {
            return Err(AuthenticatorDataError::UserNotVerified);
        }
        Ok(())
    }

    /// Whether attested credential data is declared.
    pub(crate) fn has_attested_data(&self) -> bool {
        self.flags & FLAG_AT != 0
    }

    /// `tail`, what follows attested credential data, is exactly what the ED flag
    /// declares: nothing, or one CBOR map. A valid signature over bytes nobody
    /// parses would still be a signature over something unknown.
    pub(crate) fn check_extensions(&self, tail: &[u8]) -> Result<(), AuthenticatorDataError> {
        if self.flags & FLAG_ED == 0 {
            return if tail.is_empty() {
                Ok(())
            } else {
                Err(AuthenticatorDataError::TrailingBytes { found: tail.len() })
            };
        }
        if tail.is_empty() {
            return Err(AuthenticatorDataError::MissingExtensions);
        }
        let end = extensions_end(tail)?;
        match tail.len() - end {
            0 => Ok(()),
            found => Err(AuthenticatorDataError::TrailingBytes { found }),
        }
    }
}

/// Where the extension map at the start of `bytes` ends. Outputs aren't read: 7.2
/// lets a relying party ignore what it didn't ask for, and it asks for nothing.
fn extensions_end(bytes: &[u8]) -> Result<usize, AuthenticatorDataError> {
    let malformed =
        |e: minicbor::decode::Error| AuthenticatorDataError::MalformedExtensions(e.to_string());
    let mut d = Decoder::new(bytes);
    let Some(count) = d.map().map_err(malformed)? else {
        return Err(AuthenticatorDataError::MalformedExtensions(
            "indefinite-length map".to_owned(),
        ));
    };
    let mut seen = HashSet::new();
    for _ in 0..count {
        let key = d.str().map_err(malformed)?;
        if !seen.insert(key) {
            return Err(AuthenticatorDataError::MalformedExtensions(
                "duplicate key".to_owned(),
            ));
        }
        d.skip().map_err(malformed)?;
    }
    Ok(d.position())
}
