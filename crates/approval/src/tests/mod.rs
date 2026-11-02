//! Each refusal is shown with a properly signed input where exactly one thing is
//! wrong, so that the check under test is the only thing that can refuse it.

mod assertion;
mod client_data;
mod config;
mod cose;
mod malformed;
mod registration;
mod vectors;

use crate::{Assertion, AssertionError, Ceremony, Expect, SoftwareAuthenticator, verify};

pub(super) const RP_ID: &str = "landfall.example";
pub(super) const ORIGIN: &str = "https://landfall.example";
pub(super) const CHALLENGE: [u8; 32] = [7; 32];

pub(super) fn authenticators() -> [SoftwareAuthenticator; 2] {
    [
        SoftwareAuthenticator::es256().unwrap(),
        SoftwareAuthenticator::eddsa().unwrap(),
    ]
}

pub(super) fn ceremony() -> Ceremony {
    Ceremony::new(RP_ID, ORIGIN, &CHALLENGE)
}

/// Verifies `assertion` against what `authenticator` is configured with.
pub(super) fn verify_as(
    authenticator: &SoftwareAuthenticator,
    assertion: &Assertion,
) -> Result<(), AssertionError> {
    let key = authenticator.key().unwrap();
    verify(
        assertion,
        &Expect {
            key: &key,
            credential_id: authenticator.credential_id(),
            rp_id: RP_ID,
            origin: ORIGIN,
            challenge: &CHALLENGE,
        },
    )
}

/// Runs `ceremony` on each kind of key and hands over the result.
pub(super) fn each_key(ceremony: &Ceremony, check: impl Fn(Result<(), AssertionError>)) {
    for authenticator in authenticators() {
        let assertion = authenticator.assertion(ceremony).unwrap();
        check(verify_as(&authenticator, &assertion));
    }
}
