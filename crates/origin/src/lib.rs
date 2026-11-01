//! Release origin verification for landfall.
//!
//! Everything here that touches the Sigstore stack or the network lives in
//! this crate, so `landfall-core` stays free of I/O. [`attestation`] verifies
//! a GitHub build-provenance bundle for an image digest and matches its
//! Fulcio certificate identity against a deployment's configuration. [`trust`]
//! builds the Sigstore trust root they are verified against, through TUF.
//! [`fetch`] gets the material to verify: signed tag objects from the GitHub
//! API, image index digests and Sigstore bundles from the registry.
//! [`release`] composes them into the verification of one release.

pub mod attestation;
pub mod fetch;
pub mod release;
pub mod trust;

#[cfg(test)]
mod test_support;

pub use landfall_core::release::Platform;
