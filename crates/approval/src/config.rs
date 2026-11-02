//! Loading a configuration with its approver keys checked by this crate's own parser.
//!
//! `landfall-core` has to stay free of the cryptographic library that says whether a
//! point is on its curve, and a second, lighter parser there could disagree with this
//! one: a key could load and never verify. So there is one parser, and core takes it as
//! a required argument.

use landfall_core::config::{self, Config, ConfigError};

use crate::cose::CoseKey;

/// Parses and validates a configuration file from its exact bytes. Every binary loads its
/// configuration through this, so that an approver's key is refused at load for the
/// reason [`CoseKey::parse`] would refuse it when verifying.
///
/// # Errors
///
/// As [`landfall_core::config::parse`], with [`ConfigError::InvalidApprover`] for a key
/// [`CoseKey::parse`] refuses.
#[expect(
    clippy::disallowed_methods,
    reason = "the one place the real check is supplied: everything else calls this function"
)]
pub fn parse_config(bytes: &[u8]) -> Result<Config, ConfigError> {
    config::parse(bytes, check_key)
}

/// A [`CoseError`](crate::CoseError) names a label, a length or an algorithm, never the
/// key's bytes.
fn check_key(public_key: &[u8]) -> Result<(), String> {
    CoseKey::parse(public_key)
        .map(drop)
        .map_err(|error| error.to_string())
}
