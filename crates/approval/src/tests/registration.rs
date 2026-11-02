use super::{CHALLENGE, ORIGIN, RP_ID, authenticators, ceremony};
use crate::authenticator_data::{FLAG_AT, FLAG_ED, FLAG_UP, FLAG_UV};
use crate::registration::encode_attestation_object;
use crate::{
    Attestation, AuthenticatorDataError, Ceremony, ClientDataError, CoseError, Expect, Registered,
    RegistrationError, parse_registration, verify,
};

const HONEST_FLAGS: u8 = FLAG_UP | FLAG_UV | FLAG_AT;

fn parse(attestation: &Attestation) -> Result<Registered, RegistrationError> {
    parse_registration(
        &attestation.attestation_object,
        &attestation.client_data_json,
        RP_ID,
        ORIGIN,
        &CHALLENGE,
    )
}

fn each_key(ceremony: &Ceremony, check: impl Fn(Result<Registered, RegistrationError>)) {
    for authenticator in authenticators() {
        check(parse(&authenticator.attestation(ceremony)));
    }
}

#[test]
fn registration_yields_the_credential() {
    for authenticator in authenticators() {
        let registered = parse(&authenticator.attestation(&ceremony())).unwrap();
        assert_eq!(registered.credential_id, authenticator.credential_id());
        assert_eq!(registered.key, authenticator.key().unwrap());
    }
}

#[test]
fn what_registration_yields_verifies_an_assertion() {
    for authenticator in authenticators() {
        let registered = parse(&authenticator.attestation(&ceremony())).unwrap();
        let assertion = authenticator.assertion(&ceremony()).unwrap();
        verify(
            &assertion,
            &Expect {
                key: &registered.key,
                credential_id: &registered.credential_id,
                rp_id: RP_ID,
                origin: ORIGIN,
                challenge: &CHALLENGE,
            },
        )
        .unwrap();
    }
}

#[test]
fn client_data_is_checked_for_a_create_ceremony() {
    let mut c = ceremony();
    c.kind = Some("webauthn.get".to_owned());
    each_key(&c, |result| {
        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(ClientDataError::Type { .. }))
        ));
    });
    let mut c = ceremony();
    c.challenge = vec![8; 32];
    each_key(&c, |result| {
        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(
                ClientDataError::Challenge { .. }
            ))
        ));
    });
    let mut c = ceremony();
    c.origin = "https://evil.example".to_owned();
    each_key(&c, |result| {
        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(
                ClientDataError::Origin { .. }
            ))
        ));
    });
    let mut c = ceremony();
    c.cross_origin = Some(true);
    each_key(&c, |result| {
        assert!(matches!(
            result,
            Err(RegistrationError::ClientData(ClientDataError::CrossOrigin))
        ));
    });
}

#[test]
fn authenticator_data_is_checked() {
    for (flags, expected) in [
        (FLAG_UV | FLAG_AT, AuthenticatorDataError::UserNotPresent),
        (FLAG_UP | FLAG_AT, AuthenticatorDataError::UserNotVerified),
        (
            FLAG_UP | FLAG_UV,
            AuthenticatorDataError::MissingAttestedData,
        ),
    ] {
        let mut c = ceremony();
        c.flags = Some(flags);
        each_key(&c, |result| {
            assert_eq!(
                result,
                Err(RegistrationError::AuthenticatorData(expected.clone()))
            );
        });
    }
    let mut c = ceremony();
    c.rp_id = "example".to_owned();
    each_key(&c, |result| {
        assert!(matches!(
            result,
            Err(RegistrationError::AuthenticatorData(
                AuthenticatorDataError::RpIdHash { .. }
            ))
        ));
    });
}

#[test]
fn another_format_is_refused() {
    let mut c = ceremony();
    c.format = "packed".to_owned();
    // A statement that would mean something to a verifier of that format.
    c.statement = vec![0xa1, 0x63, b'a', b'l', b'g', 0x26];
    each_key(&c, |result| {
        assert_eq!(
            result,
            Err(RegistrationError::Format {
                found: "\"packed\"".to_owned()
            })
        );
    });
}

#[test]
fn a_none_attestation_with_a_statement_is_refused() {
    let mut c = ceremony();
    c.statement = vec![0xa1, 0x61, b'x', 0x01];
    each_key(&c, |result| {
        assert_eq!(result, Err(RegistrationError::StatementNotEmpty));
    });
    // Empty, but not the empty map.
    let mut c = ceremony();
    c.statement = vec![0x80];
    each_key(&c, |result| {
        assert_eq!(result, Err(RegistrationError::StatementNotEmpty));
    });
    // The empty map, in an indefinite-length form.
    let mut c = ceremony();
    c.statement = vec![0xbf, 0xff];
    each_key(&c, |result| {
        assert_eq!(result, Err(RegistrationError::StatementNotEmpty));
    });
}

#[test]
fn extensions_after_the_key_are_read_as_the_flags_declare() {
    let mut c = ceremony();
    c.flags = Some(HONEST_FLAGS | FLAG_ED);
    c.trailing = vec![0xa0];
    each_key(&c, |result| assert!(result.is_ok(), "{result:?}"));

    c.trailing = Vec::new();
    each_key(&c, |result| {
        assert_eq!(
            result,
            Err(RegistrationError::AuthenticatorData(
                AuthenticatorDataError::MissingExtensions
            ))
        );
    });

    let mut c = ceremony();
    c.trailing = vec![0xa0];
    each_key(&c, |result| {
        assert_eq!(
            result,
            Err(RegistrationError::AuthenticatorData(
                AuthenticatorDataError::TrailingBytes { found: 1 }
            ))
        );
    });
}

#[test]
fn credential_id_length_is_bounded() {
    for (id, found) in [(Vec::new(), 0), (vec![1; 1024], 1024)] {
        let mut c = ceremony();
        c.credential_id = Some(id);
        each_key(&c, |result| {
            assert_eq!(result, Err(RegistrationError::CredentialIdLength { found }));
        });
    }
    let mut c = ceremony();
    c.credential_id = Some(vec![1; 1023]);
    each_key(&c, |result| assert!(result.is_ok(), "{result:?}"));
}

#[test]
fn a_bad_attested_key_is_refused() {
    let mut c = ceremony();
    // The alg of an RSA key, and nothing else of one.
    c.attested_key = Some(vec![0xa1, 0x03, 0x39, 0x01, 0x00]);
    each_key(&c, |result| {
        assert_eq!(
            result,
            Err(RegistrationError::Key(CoseError::UnsupportedAlgorithm(
                -257
            )))
        );
    });
}

/// An honest attestation object, taken apart for rebuilding.
fn honest_auth_data() -> (Vec<u8>, Vec<u8>) {
    let [authenticator, _] = authenticators();
    let attestation = authenticator.attestation(&ceremony());
    let object = attestation.attestation_object;
    let auth_data = object[object.len() - 164..].to_vec();
    (auth_data, attestation.client_data_json)
}

fn text(value: &str) -> Vec<u8> {
    let mut out = vec![0x60 | u8::try_from(value.len()).unwrap()];
    out.extend_from_slice(value.as_bytes());
    out
}

fn auth_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = vec![0x58, u8::try_from(data.len()).unwrap()];
    out.extend_from_slice(data);
    out
}

fn refused(object: &[u8], client: &[u8]) -> RegistrationError {
    parse_registration(object, client, RP_ID, ORIGIN, &CHALLENGE).unwrap_err()
}

#[test]
fn the_attestation_object_is_exactly_three_known_entries() {
    let (data, client) = honest_auth_data();
    let fmt = [text("fmt"), text("none")].concat();
    let statement = [text("attStmt"), vec![0xa0]].concat();
    let auth = [text("authData"), auth_bytes(&data)].concat();

    // The helpers build what the crate accepts.
    let good = [&[0xa3][..], &fmt, &statement, &auth].concat();
    assert_eq!(good, encode_attestation_object("none", &[0xa0], &data));
    parse_registration(&good, &client, RP_ID, ORIGIN, &CHALLENGE).unwrap();

    let malformed = [
        // An entry missing, an entry too many, the same entry twice.
        [&[0xa2][..], &fmt, &auth].concat(),
        [&[0xa4][..], &fmt, &statement, &auth, &text("x"), &[0x01]].concat(),
        [&[0xa3][..], &fmt, &fmt, &auth].concat(),
        [&[0xa3][..], &fmt, &statement, &statement].concat(),
        [&[0xa3][..], &auth, &statement, &auth].concat(),
        // An unknown entry in place of a known one.
        [&[0xa3][..], &text("x"), &[0x01], &statement, &auth].concat(),
        // Bytes after the map.
        [&good[..], &[0x00]].concat(),
        // An indefinite-length map, which also has the right entries.
        [&[0xbf][..], &fmt, &statement, &auth, &[0xff]].concat(),
    ];
    for object in malformed {
        assert!(
            matches!(refused(&object, &client), RegistrationError::Malformed(_)),
            "{object:02x?}"
        );
    }
}

#[test]
fn a_non_canonical_attestation_object_is_refused() {
    let (data, client) = honest_auth_data();
    let fmt = [text("fmt"), text("none")].concat();
    let statement = [text("attStmt"), vec![0xa0]].concat();
    let auth = [text("authData"), auth_bytes(&data)].concat();

    // Out of order; and a length longer than it needs to be.
    let reordered = [&[0xa3][..], &auth, &fmt, &statement].concat();
    assert_eq!(
        refused(&reordered, &client),
        RegistrationError::NotCanonical
    );
    let long_length = [
        &[0xa3][..],
        &fmt,
        &statement,
        &text("authData"),
        &[0x59, 0x00, u8::try_from(data.len()).unwrap()],
        &data,
    ]
    .concat();
    assert_eq!(
        refused(&long_length, &client),
        RegistrationError::NotCanonical
    );
}
