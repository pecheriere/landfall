//! Hostile bytes: every one of these must come back as an error, never a panic.

use super::vectors::{self, Credential};
use super::{CHALLENGE, ORIGIN, RP_ID, authenticators, ceremony, verify_as};
use crate::authenticator_data::{FLAG_ED, FLAG_UP, FLAG_UV};
use crate::{Assertion, CoseKey, Expect, parse_registration, verify};

/// CBOR that each parser must survive: wrong types, impossible lengths, truncated
/// heads, reserved values, huge counts.
fn cbor_table() -> Vec<Vec<u8>> {
    let mut table: Vec<Vec<u8>> = vec![
        vec![],
        vec![0x00],
        vec![0xff],
        vec![0xa0],
        vec![0x80],
        vec![0xf6],
        vec![0xc0],
        vec![0x1c],
        vec![0x5f],
        vec![0x7f],
        vec![0x9f],
        vec![0xbf],
        vec![0xa1],
        vec![0xa1, 0x01],
        vec![0xa5, 0x01],
        vec![0x58],
        vec![0x58, 0xff],
        vec![0x5b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x7b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0x9b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        vec![0xbb, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff],
        // A negative label below what fits in an i64.
        vec![
            0xa1, 0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00,
        ],
        // Text that isn't UTF-8, as a key.
        vec![0xa1, 0x62, 0xff, 0xfe, 0x00],
        // A tag on everything.
        vec![0xd8, 0x18, 0xa0],
        // Every label and value a break.
        vec![0xa2, 0xff, 0xff, 0xff, 0xff],
    ];
    // Nesting deep enough to break anything recursive.
    table.push(vec![0x81; 200_000]);
    table.push(vec![0xa1; 200_000]);
    table.push(vec![0xc0; 200_000]);
    table.push(vec![0x9f; 200_000]);
    table.push(vec![0xbf; 200_000]);
    table.push([vec![0xa1, 0x61, b'a'], vec![0x81; 200_000]].concat());
    table.push([vec![0xa1, 0x61, b'a'], vec![0x9f; 200_000]].concat());
    table
}

#[test]
fn malformed_inputs_never_panic() {
    let [es256, eddsa] = authenticators();
    let client = es256.attestation(&ceremony()).client_data_json;

    for bytes in cbor_table() {
        assert!(CoseKey::parse(&bytes).is_err(), "{:02x?}", head(&bytes));
        assert!(
            parse_registration(&bytes, &client, RP_ID, ORIGIN, &CHALLENGE).is_err(),
            "{:02x?}",
            head(&bytes)
        );
        // As extension data. Well-formed maps are allowed there, and anything else
        // must fail on its own terms rather than panic.
        let mut c = ceremony();
        c.flags = Some(FLAG_UP | FLAG_UV | FLAG_ED);
        c.trailing.clone_from(&bytes);
        let _ = verify_as(&eddsa, &eddsa.assertion(&c).unwrap());
    }
}

fn head(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.len().min(16)]
}

fn json_table() -> Vec<Vec<u8>> {
    let mut table: Vec<Vec<u8>> = [
        &b""[..],
        b"null",
        b"[]",
        b"{}",
        b"1",
        b"\"\"",
        b"{",
        b"{\"type\"",
        b"{\"type\":",
        b"{\"type\":1}",
        b"{\"type\":\"webauthn.get\"}",
        b"{\"type\":\"webauthn.get\",\"challenge\":\"\"}",
        b"{\"type\":null,\"challenge\":null,\"origin\":null}",
        // Not UTF-8, an unpaired surrogate, a byte order mark, a NUL, a trailing
        // member, a value after the object, a number out of range.
        b"\xff\xfe",
        b"{\"type\":\"\xc3\x28\"}",
        b"{\"type\":\"\\ud800\"}",
        b"\xef\xbb\xbf{}",
        b"\0",
        b"{\"type\":\"webauthn.get\",}",
        b"{} {}",
        b"{\"x\":1e999}",
    ]
    .iter()
    .map(|bytes| bytes.to_vec())
    .collect();
    // Nesting deeper than the parser's limit, each way it can nest.
    table.push(b"[".repeat(200_000));
    table.push(b"{\"a\":".repeat(200_000));
    table
}

#[test]
fn malformed_client_data_never_panics() {
    for authenticator in authenticators() {
        for json in json_table() {
            let mut c = ceremony();
            c.client_data_json = Some(json.clone());
            let result = verify_as(&authenticator, &authenticator.assertion(&c).unwrap());
            assert!(result.is_err(), "{:?}", head(&json));
            let attestation = authenticator.attestation(&c);
            assert!(
                parse_registration(
                    &attestation.attestation_object,
                    &json,
                    RP_ID,
                    ORIGIN,
                    &CHALLENGE
                )
                .is_err(),
                "{:?}",
                head(&json)
            );
        }
    }
}

/// `assertion` with one field cut at every length: none of them is valid.
fn check_truncations(assertion: &Assertion, check: &impl Fn(&Assertion) -> bool) {
    assert!(check(assertion), "the uncut assertion is valid");
    let fields: [fn(&mut Assertion) -> &mut Vec<u8>; 4] = [
        |a| &mut a.credential_id,
        |a| &mut a.authenticator_data,
        |a| &mut a.client_data_json,
        |a| &mut a.signature,
    ];
    for field in fields {
        let length = field(&mut assertion.clone()).len();
        for cut in 0..length {
            let mut a = assertion.clone();
            field(&mut a).truncate(cut);
            assert!(!check(&a), "accepted at length {cut} of {length}");
        }
    }
}

/// An attestation cut at every length: none of them yields a credential.
fn check_registration_truncations(object: &[u8], client: &[u8], challenge: &[u8]) {
    parse_registration(object, client, RP_ID, ORIGIN, challenge).unwrap();
    for cut in 0..object.len() {
        assert!(
            parse_registration(&object[..cut], client, RP_ID, ORIGIN, challenge).is_err(),
            "object accepted at {cut}"
        );
    }
    for cut in 0..client.len() {
        assert!(
            parse_registration(object, &client[..cut], RP_ID, ORIGIN, challenge).is_err(),
            "client data accepted at {cut}"
        );
    }
}

#[test]
fn truncating_software_vectors_is_always_refused() {
    for authenticator in authenticators() {
        let assertion = authenticator.assertion(&ceremony()).unwrap();
        check_truncations(&assertion, &|a| verify_as(&authenticator, a).is_ok());

        let attestation = authenticator.attestation(&ceremony());
        check_registration_truncations(
            &attestation.attestation_object,
            &attestation.client_data_json,
            &CHALLENGE,
        );

        let key = authenticator.key().unwrap();
        for cut in 0..key.as_bytes().len() {
            assert!(CoseKey::parse(&key.as_bytes()[..cut]).is_err());
        }
    }
}

#[test]
fn truncating_real_browser_vectors_is_always_refused() {
    let file = vectors::load();
    for credential in &file.credentials {
        let Credential {
            attestation_object,
            registration_client_data_json,
            assertion,
            ..
        } = credential;
        check_registration_truncations(
            attestation_object,
            registration_client_data_json,
            &file.registration_challenge,
        );

        let registered = vectors::registered(&file, credential);
        let challenge = file.intent.challenge();
        check_truncations(assertion, &|a| {
            verify(
                a,
                &Expect {
                    key: &registered.key,
                    credential_id: &registered.credential_id,
                    rp_id: RP_ID,
                    origin: ORIGIN,
                    challenge: &challenge,
                },
            )
            .is_ok()
        });
    }
}
