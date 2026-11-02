//! The protocol's signing, wire shapes and strictness.

pub use ed25519_dalek::SigningKey;

use super::Nonce;
use crate::ids::HostId;

mod signing;
mod strictness;
mod wire;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn nonce(byte: u8) -> Nonce {
    Nonce::from_bytes([byte; 32])
}

fn host(name: &str) -> HostId {
    name.parse().unwrap()
}

fn identity_key_bytes() -> [u8; 32] {
    let mut bytes = [0_u8; 32];
    bytes[0] = 1;
    bytes
}
