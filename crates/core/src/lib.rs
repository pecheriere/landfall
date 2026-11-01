//! Shared types and pure logic for landfall.
//!
//! This crate performs no I/O, reads no clock and draws no randomness.

pub mod config;
mod hex;
pub mod ids;
pub mod intent;
pub mod release;
pub mod rule;
pub mod tag;
mod text;
