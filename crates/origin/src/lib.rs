//! Release origin verification for landfall.
//!
//! Everything here that touches the Sigstore stack or the network lives in
//! this crate, so `landfall-core` stays free of I/O. [`attestation`] verifies
//! a GitHub build-provenance bundle for an image digest and matches its
//! Fulcio certificate identity against a deployment's configuration.

pub mod attestation;
