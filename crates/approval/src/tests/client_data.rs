use super::{CHALLENGE, ORIGIN, ceremony, each_key};
use crate::wire;
use crate::{AssertionError, ClientDataError};

fn client_error(result: Result<(), AssertionError>) -> ClientDataError {
    match result {
        Err(AssertionError::ClientData(e)) => e,
        other => panic!("expected a client data error, got {other:?}"),
    }
}

/// Client data with the given members after the three required ones.
fn honest_with(extra: &str) -> Vec<u8> {
    format!(
        r#"{{"type":"webauthn.get","challenge":"{}","origin":"{ORIGIN}"{extra}}}"#,
        wire::encode(&CHALLENGE),
    )
    .into_bytes()
}

fn raw(client_data_json: Vec<u8>, check: impl Fn(Result<(), AssertionError>)) {
    let mut c = ceremony();
    c.client_data_json = Some(client_data_json);
    each_key(&c, check);
}

#[test]
fn another_type_is_refused() {
    for kind in ["webauthn.create", "WEBAUTHN.GET", "webauthn.get ", ""] {
        let mut c = ceremony();
        c.kind = Some(kind.to_owned());
        each_key(&c, |result| {
            assert!(
                matches!(client_error(result), ClientDataError::Type { .. }),
                "{kind}"
            );
        });
    }
}

#[test]
fn another_challenge_is_refused() {
    let mut c = ceremony();
    c.challenge = vec![8; 32];
    each_key(&c, |result| {
        assert!(matches!(
            client_error(result),
            ClientDataError::Challenge { .. }
        ));
    });
}

#[test]
fn a_challenge_is_compared_as_text() {
    // Other text for the same bytes, or for the raw bytes before hashing.
    let exact = wire::encode(&CHALLENGE);
    for text in [
        format!("{exact}="),
        exact.to_uppercase(),
        format!(" {exact}"),
    ] {
        raw(
            format!(r#"{{"type":"webauthn.get","challenge":"{text}","origin":"{ORIGIN}"}}"#)
                .into_bytes(),
            |result| {
                assert!(matches!(
                    client_error(result),
                    ClientDataError::Challenge { .. }
                ));
            },
        );
    }
}

#[test]
fn only_the_exact_origin_is_accepted() {
    for origin in [
        "http://landfall.example",
        "https://landfall.example/",
        "https://landfall.example:443",
        "https://LANDFALL.example",
        "https://sub.landfall.example",
        "https://landfall.example.evil.example",
        "https://evil.example",
        "null",
        "",
    ] {
        let mut c = ceremony();
        c.origin = origin.to_owned();
        each_key(&c, |result| {
            assert!(
                matches!(client_error(result), ClientDataError::Origin { .. }),
                "{origin}"
            );
        });
    }
}

#[test]
fn crossorigin_true_is_refused() {
    let mut c = ceremony();
    c.cross_origin = Some(true);
    each_key(&c, |result| {
        assert_eq!(client_error(result), ClientDataError::CrossOrigin);
    });
}

#[test]
fn crossorigin_false_or_absent_verifies() {
    let mut c = ceremony();
    c.cross_origin = Some(false);
    each_key(&c, |result| assert_eq!(result, Ok(())));
    c.cross_origin = None;
    each_key(&c, |result| assert_eq!(result, Ok(())));
}

#[test]
fn crossorigin_that_is_not_a_boolean_is_refused() {
    // Each of these reads as "not cross-origin" to some parser.
    for value in ["null", "\"false\"", "0", "[]"] {
        raw(
            honest_with(&format!(r#","crossOrigin":{value}"#)),
            |result| {
                assert!(
                    matches!(client_error(result), ClientDataError::Malformed(_)),
                    "{value}"
                );
            },
        );
    }
}

#[test]
fn token_binding_in_use_is_refused() {
    raw(
        honest_with(r#","tokenBinding":{"status":"present","id":"AA"}"#),
        |result| assert_eq!(client_error(result), ClientDataError::TokenBinding),
    );
}

#[test]
fn token_binding_not_in_use_verifies() {
    for status in ["supported", "not-supported"] {
        raw(
            honest_with(&format!(r#","tokenBinding":{{"status":"{status}"}}"#)),
            |result| assert_eq!(result, Ok(())),
        );
    }
}

#[test]
fn other_members_are_allowed() {
    raw(
        honest_with(r#","other_keys_can_be_added_here":"as Chromium does","n":[1,{"a":null}]"#),
        |result| assert_eq!(result, Ok(())),
    );
}

#[test]
fn a_byte_order_mark_is_refused() {
    raw(
        [&b"\xef\xbb\xbf"[..], &honest_with("")].concat(),
        |result| {
            assert!(matches!(
                client_error(result),
                ClientDataError::Malformed(_)
            ));
        },
    );
}

#[test]
fn client_data_must_be_an_object() {
    // A derived struct also takes its members by position, from an array: signed
    // bytes that no browser would produce, and that other parsers read differently.
    let array = format!(
        r#"["webauthn.get","{}","{ORIGIN}"]"#,
        wire::encode(&CHALLENGE)
    );
    raw(array.into_bytes(), |result| {
        assert!(matches!(
            client_error(result),
            ClientDataError::Malformed(_)
        ));
    });
}

#[test]
fn token_binding_must_be_an_object() {
    for value in [
        r#"["supported"]"#,
        r#"["present"]"#,
        "null",
        "\"present\"",
        "1",
    ] {
        raw(
            honest_with(&format!(r#","tokenBinding":{value}"#)),
            |result| {
                assert!(
                    matches!(client_error(result), ClientDataError::Malformed(_)),
                    "{value}"
                );
            },
        );
    }
}

#[test]
fn invalid_utf8_in_a_member_nothing_reads_is_refused() {
    let mut json = honest_with(r#","x":"?""#);
    let at = json.iter().position(|b| *b == b'?').unwrap();
    json[at] = 0xff;
    raw(json, |result| {
        assert!(matches!(
            client_error(result),
            ClientDataError::Malformed(_)
        ));
    });
}

#[test]
fn duplicate_json_keys_are_refused() {
    let challenge = wire::encode(&CHALLENGE);
    let cases = [
        // The right origin first, then another, and the other way round: a parser
        // keeping the last and one keeping the first must not get to differ.
        honest_with(r#","origin":"https://evil.example""#),
        format!(
            r#"{{"origin":"https://evil.example","type":"webauthn.get","challenge":"{challenge}","origin":"{ORIGIN}"}}"#
        )
        .into_bytes(),
        honest_with(r#","type":"webauthn.create""#),
        honest_with(&format!(r#","challenge":"{challenge}""#)),
        // Identical, but spelled differently: keys are compared after unescaping. The
        // backslash and the `u006f` are put together here, so that this source really
        // holds an escape, and the assert below sees it in the bytes.
        honest_with(&format!(r#","\{}rigin":"https://evil.example""#, "u006f")),
        // Members nothing here reads, at the top and nested in another's value.
        honest_with(r#","x":1,"x":2"#),
        honest_with(r#","x":{"y":1,"y":2}"#),
        honest_with(r#","x":[{"y":{"z":1,"z":2}}]"#),
        honest_with(r#","crossOrigin":false,"crossOrigin":true"#),
    ];
    assert!(
        cases[4].windows(2).any(|pair| pair == b"\\u"),
        "the escaped case holds no escape"
    );
    for case in cases {
        let text = String::from_utf8(case.clone()).unwrap();
        raw(case, |result| {
            let error = client_error(result);
            assert!(
                matches!(&error, ClientDataError::Malformed(reason) if reason.contains("duplicate key")),
                "{text}: {error}"
            );
        });
    }
}

#[test]
fn a_refusal_names_what_was_expected_and_found() {
    let mut c = ceremony();
    c.origin = "https://evil.example".to_owned();
    each_key(&c, |result| {
        assert_eq!(
            result.unwrap_err().to_string(),
            "clientDataJSON origin: expected \"https://landfall.example\", \
             found \"https://evil.example\""
        );
    });
}

#[test]
fn hostile_text_is_quoted_and_truncated_in_errors() {
    let long = format!(
        "https://evil.example\n\u{202e}\u{1b}[31m{}",
        "x".repeat(10_000)
    );
    let mut c = ceremony();
    c.origin = long;
    each_key(&c, |result| {
        let text = result.unwrap_err().to_string();
        assert!(text.len() < 300, "{}", text.len());
        assert!(!text.contains('\n'), "{text}");
        assert!(!text.contains('\u{202e}'), "{text}");
        assert!(!text.contains('\u{1b}'), "{text}");
    });

    // serde_json's own messages quote what they read, so they're shown the same way.
    raw(
        honest_with(&format!(r#","crossOrigin":"{}""#, "x\\n".repeat(5_000))),
        |result| {
            let text = result.unwrap_err().to_string();
            assert!(text.len() < 400, "{}", text.len());
            assert!(!text.contains('\n'), "{text}");
        },
    );
}
