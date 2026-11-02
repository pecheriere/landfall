use aws_lc_rs::digest::{SHA256, digest};
use landfall_core::intent::DeployIntent;

use super::{CHALLENGE, ORIGIN, RP_ID, authenticators, ceremony, each_key, verify_as};
use crate::authenticator_data::{FLAG_AT, FLAG_ED, FLAG_UP, FLAG_UV};
use crate::{
    Assertion, AssertionError, AuthenticatorDataError, Ceremony, Expect, SoftwareAuthenticator,
    verify,
};

const HONEST_FLAGS: u8 = FLAG_UP | FLAG_UV;

fn data_error(result: Result<(), AssertionError>) -> AuthenticatorDataError {
    match result {
        Err(AssertionError::AuthenticatorData(e)) => e,
        other => panic!("expected an authenticator data error, got {other:?}"),
    }
}

#[test]
fn valid_assertion_verifies() {
    each_key(&ceremony(), |result| assert_eq!(result, Ok(())));
}

#[test]
fn synced_passkey_flags_and_any_counter_verify() {
    // Bits 3 and 4 say backup eligible and backed up; synced passkeys report a
    // counter of 0, others count up. None of it decides anything here.
    for sign_count in [0, 1, u32::MAX] {
        let mut c = ceremony();
        c.flags = Some(HONEST_FLAGS | 0x08 | 0x10);
        c.sign_count = sign_count;
        each_key(&c, |result| assert_eq!(result, Ok(())));
    }
}

#[test]
fn a_long_credential_id_is_truncated_in_errors() {
    let mut c = ceremony();
    c.credential_id = Some(vec![9; 100_000]);
    each_key(&c, |result| {
        let text = result.unwrap_err().to_string();
        assert!(text.len() < 400, "{}", text.len());
    });
}

#[test]
fn another_credential_id_is_refused() {
    let mut c = ceremony();
    c.credential_id = Some(vec![9; 32]);
    each_key(&c, |result| {
        assert!(
            matches!(result, Err(AssertionError::CredentialId { .. })),
            "{result:?}"
        );
    });
}

#[test]
fn a_signature_by_another_key_is_refused() {
    // Same credential id and everything else right: the configured key is another.
    for (signer, configured) in [
        (
            SoftwareAuthenticator::es256().unwrap(),
            SoftwareAuthenticator::es256().unwrap(),
        ),
        (
            SoftwareAuthenticator::eddsa().unwrap(),
            SoftwareAuthenticator::eddsa().unwrap(),
        ),
        (
            SoftwareAuthenticator::es256().unwrap(),
            SoftwareAuthenticator::eddsa().unwrap(),
        ),
    ] {
        let mut c = ceremony();
        c.credential_id = Some(configured.credential_id().to_vec());
        let assertion = signer.assertion(&c).unwrap();
        assert_eq!(
            verify_as(&configured, &assertion),
            Err(AssertionError::Signature)
        );
    }
}

#[test]
fn signature_over_other_bytes_is_refused() {
    for authenticator in authenticators() {
        let honest = authenticator.assertion(&ceremony()).unwrap();
        let hash = digest(&SHA256, &honest.client_data_json);
        let bad_messages = [
            // The client data itself rather than its hash.
            [&honest.authenticator_data[..], &honest.client_data_json[..]].concat(),
            // The hash alone, the authenticator data alone, and the wrong order.
            hash.as_ref().to_vec(),
            honest.authenticator_data.clone(),
            [hash.as_ref(), &honest.authenticator_data[..]].concat(),
            Vec::new(),
        ];
        for message in bad_messages {
            let mut c = ceremony();
            c.signed_message = Some(message);
            let assertion = authenticator.assertion(&c).unwrap();
            assert_eq!(
                verify_as(&authenticator, &assertion),
                Err(AssertionError::Signature)
            );
        }
    }
}

#[test]
fn a_signature_with_bytes_after_it_is_refused() {
    for authenticator in authenticators() {
        let mut assertion = authenticator.assertion(&ceremony()).unwrap();
        assertion.signature.push(0);
        assert_eq!(
            verify_as(&authenticator, &assertion),
            Err(AssertionError::Signature)
        );
    }
}

#[test]
fn an_es256_signature_must_be_der() {
    let authenticator = SoftwareAuthenticator::es256().unwrap();
    let mut assertion = authenticator.assertion(&ceremony()).unwrap();
    // The fixed-width r || s form some libraries produce: 64 bytes, no DER.
    assertion.signature = vec![0x11; 64];
    assert_eq!(
        verify_as(&authenticator, &assertion),
        Err(AssertionError::Signature)
    );
}

#[test]
fn changing_any_signed_byte_is_refused() {
    for authenticator in authenticators() {
        let honest = authenticator.assertion(&ceremony()).unwrap();
        assert_eq!(verify_as(&authenticator, &honest), Ok(()));
        for i in 0..honest.authenticator_data.len() {
            let mut a = honest.clone();
            a.authenticator_data[i] ^= 0x01;
            assert!(verify_as(&authenticator, &a).is_err(), "authData byte {i}");
        }
        for i in 0..honest.client_data_json.len() {
            let mut a = honest.clone();
            a.client_data_json[i] ^= 0x01;
            assert!(verify_as(&authenticator, &a).is_err(), "client byte {i}");
        }
        for i in 0..honest.signature.len() {
            let mut a = honest.clone();
            a.signature[i] ^= 0x01;
            assert!(verify_as(&authenticator, &a).is_err(), "signature byte {i}");
        }
    }
}

#[test]
fn rp_id_hash_of_another_rp_is_refused() {
    let mut c = ceremony();
    c.rp_id = "other.example".to_owned();
    each_key(&c, |result| {
        assert!(matches!(
            data_error(result),
            AuthenticatorDataError::RpIdHash { .. }
        ));
    });
}

#[test]
fn parent_domain_rp_id_is_refused() {
    // WebAuthn lets a page on landfall.ops.example use ops.example as its RP ID, so
    // a passkey made for the parent domain really does sign on this origin. The host
    // takes only the exact hostname, whatever a browser would have allowed.
    let authenticator = SoftwareAuthenticator::eddsa().unwrap();
    let key = authenticator.key().unwrap();
    let mut c = Ceremony::new("ops.example", "https://landfall.ops.example", &CHALLENGE);
    let expect = Expect {
        key: &key,
        credential_id: authenticator.credential_id(),
        rp_id: "landfall.ops.example",
        origin: "https://landfall.ops.example",
        challenge: &CHALLENGE,
    };
    let assertion = authenticator.assertion(&c).unwrap();
    assert!(matches!(
        data_error(verify(&assertion, &expect)),
        AuthenticatorDataError::RpIdHash { .. }
    ));
    // And the same in the other direction: a subdomain's passkey on the parent.
    c.rp_id = format!("sub.{RP_ID}");
    c.origin = ORIGIN.to_owned();
    each_key(&c, |result| {
        assert!(matches!(
            data_error(result),
            AuthenticatorDataError::RpIdHash { .. }
        ));
    });
}

#[test]
fn user_present_flag_is_required() {
    let mut c = ceremony();
    c.flags = Some(FLAG_UV);
    each_key(&c, |result| {
        assert_eq!(data_error(result), AuthenticatorDataError::UserNotPresent);
    });
}

#[test]
fn user_verified_flag_is_required() {
    let mut c = ceremony();
    c.flags = Some(FLAG_UP);
    each_key(&c, |result| {
        assert_eq!(data_error(result), AuthenticatorDataError::UserNotVerified);
    });
}

#[test]
fn attested_data_flag_on_an_assertion_is_refused() {
    let mut c = ceremony();
    c.flags = Some(HONEST_FLAGS | FLAG_AT);
    each_key(&c, |result| {
        assert_eq!(
            data_error(result),
            AuthenticatorDataError::UnexpectedAttestedData
        );
    });
}

#[test]
fn short_authenticator_data_is_refused() {
    let mut c = ceremony();
    c.authenticator_data = Some(vec![0; 36]);
    each_key(&c, |result| {
        assert_eq!(
            data_error(result),
            AuthenticatorDataError::TooShort { found: 36 }
        );
    });
}

#[test]
fn declared_extensions_are_allowed() {
    let mut c = ceremony();
    c.flags = Some(HONEST_FLAGS | FLAG_ED);
    // {"credProtect": 1}, and nothing else.
    c.trailing = [&[0xa1, 0x6b][..], b"credProtect", &[0x01]].concat();
    each_key(&c, |result| assert_eq!(result, Ok(())));
    // An empty map says nothing, and is still exactly what the flag declares.
    c.trailing = vec![0xa0];
    each_key(&c, |result| assert_eq!(result, Ok(())));
}

#[test]
fn extensions_flag_without_data_is_refused() {
    let mut c = ceremony();
    c.flags = Some(HONEST_FLAGS | FLAG_ED);
    each_key(&c, |result| {
        assert_eq!(
            data_error(result),
            AuthenticatorDataError::MissingExtensions
        );
    });
}

#[test]
fn trailing_bytes_without_the_flag_are_refused() {
    let mut c = ceremony();
    // A well-formed extension map, not declared.
    c.trailing = vec![0xa0];
    each_key(&c, |result| {
        assert_eq!(
            data_error(result),
            AuthenticatorDataError::TrailingBytes { found: 1 }
        );
    });
}

#[test]
fn bytes_after_the_declared_extensions_are_refused() {
    let mut c = ceremony();
    c.flags = Some(HONEST_FLAGS | FLAG_ED);
    c.trailing = vec![0xa0, 0x00, 0x00];
    each_key(&c, |result| {
        assert_eq!(
            data_error(result),
            AuthenticatorDataError::TrailingBytes { found: 2 }
        );
    });
}

#[test]
fn extension_data_that_is_not_a_text_keyed_map_is_refused() {
    let malformed: &[&[u8]] = &[
        // An integer, an array, an indefinite map.
        &[0x01],
        &[0x80],
        &[0xbf, 0xff],
        // An integer key.
        &[0xa1, 0x01, 0x01],
        // A map that says it has more than it has.
        &[0xa2, 0x61, 0x61, 0x01],
        // The same key twice.
        &[0xa2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02],
    ];
    for trailing in malformed {
        let mut c = ceremony();
        c.flags = Some(HONEST_FLAGS | FLAG_ED);
        c.trailing = trailing.to_vec();
        each_key(&c, |result| {
            assert!(
                matches!(
                    data_error(result),
                    AuthenticatorDataError::MalformedExtensions(_)
                ),
                "{trailing:02x?}"
            );
        });
    }
}

fn intent() -> DeployIntent {
    DeployIntent {
        deployment: "app/prod".parse().unwrap(),
        tag: "v1.2.4".parse().unwrap(),
        commit: "a".repeat(40).parse().unwrap(),
        digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
        expected_running: Some(format!("sha256:{}", "c".repeat(64)).parse().unwrap()),
        nonce: [7; 32],
    }
}

#[test]
fn assertion_for_another_intent_is_refused() {
    let authenticator = SoftwareAuthenticator::es256().unwrap();
    let key = authenticator.key().unwrap();
    let signed = intent();
    let assertion = authenticator
        .assertion(&Ceremony::new(RP_ID, ORIGIN, &signed.challenge()))
        .unwrap();
    let check = |intent: &DeployIntent| {
        verify(
            &assertion,
            &Expect {
                key: &key,
                credential_id: authenticator.credential_id(),
                rp_id: RP_ID,
                origin: ORIGIN,
                challenge: &intent.challenge(),
            },
        )
    };
    assert_eq!(check(&signed), Ok(()));

    let others = [
        DeployIntent {
            deployment: "app/stage".parse().unwrap(),
            ..signed.clone()
        },
        DeployIntent {
            tag: "v1.2.5".parse().unwrap(),
            ..signed.clone()
        },
        DeployIntent {
            commit: "d".repeat(40).parse().unwrap(),
            ..signed.clone()
        },
        DeployIntent {
            digest: format!("sha256:{}", "d".repeat(64)).parse().unwrap(),
            ..signed.clone()
        },
        DeployIntent {
            expected_running: None,
            ..signed.clone()
        },
        DeployIntent {
            nonce: [8; 32],
            ..signed.clone()
        },
    ];
    for other in &others {
        assert!(
            matches!(check(other), Err(AssertionError::ClientData(_))),
            "{other:?}"
        );
    }
}

#[test]
fn an_assertion_travels_as_base64url() {
    let assertion = SoftwareAuthenticator::eddsa()
        .unwrap()
        .assertion(&ceremony())
        .unwrap();
    let json = serde_json::to_value(&assertion).unwrap();
    assert_eq!(
        serde_json::from_value::<Assertion>(json.clone()).unwrap(),
        assertion
    );

    for (field, bad) in [
        ("signature", "AA=="),  // Padded.
        ("signature", "AA+/"),  // Standard alphabet.
        ("signature", "AB"),    // Non-zero trailing bits.
        ("signature", "A"),     // An impossible length.
        ("signature", "A A"),   // Whitespace.
        ("credential_id", "é"), // Not base64 at all.
    ] {
        let mut v = json.clone();
        v[field] = bad.into();
        assert!(serde_json::from_value::<Assertion>(v).is_err(), "{bad}");
    }

    let mut v = json.clone();
    v["extra"] = "AA".into();
    assert!(serde_json::from_value::<Assertion>(v).is_err());
    let mut v = json;
    v.as_object_mut().unwrap().remove("signature");
    assert!(serde_json::from_value::<Assertion>(v).is_err());
}
