//! `WebAuthn` assertion verification: the check a host agent makes before it runs
//! a deploy a person approved.
//!
//! An approval is an assertion whose challenge is the hash of the exact deploy
//! ([`DeployIntent::challenge`](landfall_core::intent::DeployIntent::challenge)),
//! verified with [`verify`] against a key from the host's local configuration. A
//! false accept here means a compromised controller can deploy something no person
//! approved, so every check is required and anything unexpected is refused.
//!
//! [`parse_registration`] does the other half of a passkey's life: it takes an
//! attestation apart for the credential id and key the operator then reviews and copies
//! into the configuration. No attestation is trusted. Only ES256 and `EdDSA` exist here.
//!
//! The signature counter is not checked: synced passkeys report 0, and a replay is
//! stopped by the host's nonce log and the running digest named in the intent.
//! Nothing here reads a clock or does I/O. Callers cap the size of what they pass; an
//! assertion off the wire goes through `Assertion`'s `TryFrom<&AssertionText>`, which does.
//!
//! [`parse_config`] is how a binary loads its configuration, because the keys in it are
//! judged by the parser that verifying uses.

mod assertion;
mod authenticator_data;
mod client_data;
mod config;
mod cose;
mod registration;
#[cfg(any(test, feature = "test-support"))]
mod software;
#[cfg(test)]
mod tests;
mod wire;

pub use assertion::{
    Assertion, AssertionError, Expect, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES,
    MAX_SIGNATURE_BYTES, verify,
};
pub use authenticator_data::AuthenticatorDataError;
pub use client_data::ClientDataError;
pub use config::parse_config;
pub use cose::{Algorithm, CoseError, CoseKey};
pub use registration::{Registered, RegistrationError, parse_registration};
#[cfg(any(test, feature = "test-support"))]
pub use software::{Attestation, Ceremony, SoftwareAuthenticator, SoftwareError};
