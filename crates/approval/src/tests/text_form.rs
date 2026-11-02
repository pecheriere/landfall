//! An assertion as the wire has it: every field capped before it is decoded.

use landfall_core::config::MAX_CREDENTIAL_ID_LEN;
use landfall_core::protocol::AssertionText;

use super::{authenticators, ceremony, verify_as};
use crate::{
    Assertion, AssertionError, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES,
    MAX_SIGNATURE_BYTES,
};

fn text_of(assertion: &Assertion) -> AssertionText {
    serde_json::from_value(serde_json::to_value(assertion).unwrap()).unwrap()
}

#[test]
fn an_honest_assertion_verifies_after_the_wire() {
    for authenticator in authenticators() {
        let assertion = authenticator.assertion(&ceremony()).unwrap();
        let read = Assertion::try_from(&text_of(&assertion)).unwrap();
        assert_eq!(read, assertion);
        verify_as(&authenticator, &read).unwrap();
    }
}

/// Puts a value in one field.
type Set = fn(&mut AssertionText, String);

fn fields() -> [(&'static str, usize, Set); 4] {
    [
        ("credential_id", MAX_CREDENTIAL_ID_LEN, |text, value| {
            text.credential_id = value;
        }),
        (
            "authenticator_data",
            MAX_AUTHENTICATOR_DATA_BYTES,
            |text, value| text.authenticator_data = value,
        ),
        ("client_data_json", MAX_CLIENT_DATA_BYTES, |text, value| {
            text.client_data_json = value;
        }),
        ("signature", MAX_SIGNATURE_BYTES, |text, value| {
            text.signature = value;
        }),
    ]
}

/// Base64url of `bytes` zero bytes.
fn encoded(bytes: usize) -> String {
    "A".repeat((bytes * 4).div_ceil(3))
}

#[test]
fn each_field_is_capped_and_must_be_base64url() {
    let good = text_of(&authenticators()[0].assertion(&ceremony()).unwrap());
    for (name, limit, set) in fields() {
        // At the limit it decodes, whatever it then verifies to.
        let mut text = good.clone();
        set(&mut text, encoded(limit));
        assert!(Assertion::try_from(&text).is_ok(), "{name}");

        // Past it, in text a decoder would have taken: refused without decoding.
        let mut text = good.clone();
        set(&mut text, encoded(limit + 1));
        let error = Assertion::try_from(&text).unwrap_err();
        assert!(
            matches!(&error, AssertionError::TooLong { field, .. } if *field == name),
            "{name}: {error}"
        );

        // Whatever the text is: the cap comes first.
        let mut text = good.clone();
        set(&mut text, "!".repeat((limit * 4).div_ceil(3) + 1));
        assert!(
            matches!(
                Assertion::try_from(&text),
                Err(AssertionError::TooLong { .. })
            ),
            "{name}"
        );

        for bad in ["!!!!", "AAA=", "A", "AB\n", "é"] {
            let mut text = good.clone();
            set(&mut text, bad.to_owned());
            let error = Assertion::try_from(&text).unwrap_err();
            assert!(
                matches!(&error, AssertionError::Encoding { field } if *field == name),
                "{name} {bad:?}: {error}"
            );
        }
    }
}
