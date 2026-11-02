//! A nonce for tests, named by a label: the same label gives the same nonce, on every run, and a
//! test that needs one twice says so by using the label twice. What a nonce is checked for is
//! only that it is the one the log has, so nothing depends on how it was made.
//!
//! Compiled into the library's unit tests (`testing.rs`) and `docker_daemon.rs` with `#[path]`,
//! as `compose_project.rs` is, so it is in no release build.

use sha2::{Digest as _, Sha256};

/// The nonce called `label`.
#[must_use]
pub fn test_nonce(label: &str) -> [u8; 32] {
    Sha256::digest(label).into()
}
