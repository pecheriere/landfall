//! `[approval]`, `[approvers]`, and who a grant may let approve.
//!
//! What a key's bytes must be is the verifier's business, so the refusals of a real key
//! are tested in `crates/approval`, against the real check. Here the check is a stand-in,
//! and what's shown is what the configuration itself does around it.

use super::super::{ConfigError, MAX_CREDENTIAL_ID_LEN, parse_for_tests};
use super::{EXAMPLE, edited, id, parse_str};
use crate::ids::PrincipalId;

const OPERATOR: &str =
    "operator = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }";
const APPROVAL: &str =
    "[approval]\nrp_id = \"landfall.example\"\norigin = \"https://landfall.example\"\n\n";

fn principal(name: &str) -> PrincipalId {
    name.parse().unwrap()
}

fn with_operator(credential_id: &str, public_key: &str) -> String {
    edited(
        OPERATOR,
        &format!(
            "operator = {{ credential_id = \"{credential_id}\", public_key = \"{public_key}\" }}"
        ),
    )
}

fn with_approval(rp_id: &str, origin: &str) -> String {
    edited(
        APPROVAL,
        &format!("[approval]\nrp_id = {rp_id:?}\norigin = {origin:?}\n\n"),
    )
}

/// A second approver, whose values differ from the operator's unless a test says not.
fn with_second_approver(line: &str) -> String {
    edited(OPERATOR, &format!("{OPERATOR}\n{line}"))
}

#[test]
fn approver_values_are_decoded() {
    let config = parse_str(EXAMPLE).unwrap();
    let operator = config.approver(&principal("operator")).unwrap();
    assert_eq!(operator.credential_id(), b"credential");
    assert_eq!(operator.public_key(), b"public-key");
    assert!(config.approver(&principal("nobody")).is_none());
    let approval = config.approval().unwrap();
    assert_eq!(approval.rp_id(), "landfall.example");
    assert_eq!(approval.origin(), "https://landfall.example");
}

#[test]
fn approver_key_must_parse() {
    // The check is given the decoded bytes, and what it says is the answer.
    let only_that_key = |key: &[u8]| {
        if key == b"public-key" {
            Ok(())
        } else {
            Err("not that key".to_owned())
        }
    };
    assert!(parse_for_tests(EXAMPLE.as_bytes(), only_that_key).is_ok());
    let text = with_operator("Y3JlZGVudGlhbA", "b3RoZXIta2V5");
    assert_eq!(
        parse_for_tests(text.as_bytes(), only_that_key).unwrap_err(),
        ConfigError::InvalidApprover {
            approver: principal("operator"),
            reason: "not that key".to_owned(),
        }
    );

    // Text that isn't one spelling of some bytes never reaches it.
    for bad in [
        "cHVibGljLWtleQ==", // Padded.
        "cHVibGljLWtleR",   // Trailing bits set: a second spelling of the same bytes.
        "cHVibGljLWtle+",   // The standard alphabet.
        "not base64 at all",
    ] {
        let err = parse_str(&with_operator("Y3JlZGVudGlhbA", bad)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidApprover { approver, reason }
                if *approver == principal("operator") && reason.contains("public_key")),
            "{bad}: {err}"
        );
    }
}

#[test]
fn credential_id_must_be_one_spelling_of_a_usable_length() {
    for bad in ["", "Y3JlZGVudGlhbA==", "Y3JlZGVudGlhbB", "Y3Jl+GVudGlhbA"] {
        let err = parse_str(&with_operator(bad, "cHVibGljLWtleQ")).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidApprover { approver, reason }
                if *approver == principal("operator") && reason.contains("credential_id")),
            "{bad:?}: {err}"
        );
    }
    // 4 base64 characters to 3 bytes: exactly the longest allowed, and one more.
    let longest = "AAAA".repeat(MAX_CREDENTIAL_ID_LEN / 3);
    assert!(parse_str(&with_operator(&longest, "cHVibGljLWtleQ")).is_ok());
    let too_long = format!("{longest}AA");
    let err = parse_str(&with_operator(&too_long, "cHVibGljLWtleQ")).unwrap_err();
    assert!(
        matches!(&err, ConfigError::InvalidApprover { reason, .. } if reason.contains("1024")),
        "{err}"
    );
}

#[test]
fn duplicate_credential_ids_are_refused() {
    let text = with_second_approver(
        "backup = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"b3RoZXIta2V5\" }",
    );
    assert_eq!(
        parse_str(&text).unwrap_err(),
        ConfigError::DuplicateCredentialId {
            first: principal("backup"),
            second: principal("operator"),
        }
    );
}

#[test]
fn duplicate_approver_keys_are_refused() {
    let text = with_second_approver(
        "backup = { credential_id = \"b3RoZXI\", public_key = \"cHVibGljLWtleQ\" }",
    );
    assert_eq!(
        parse_str(&text).unwrap_err(),
        ConfigError::DuplicateApproverKey {
            first: principal("backup"),
            second: principal("operator"),
        }
    );
}

#[test]
fn errors_do_not_echo_a_whole_key() {
    let key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
    for text in [
        // TOML's own error shows the line. An unknown field, with the key beside it.
        edited(
            OPERATOR,
            &format!(
                "operator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_keey = \"{key}\" }}"
            ),
        ),
        // The key where a table should be: serde's message quotes the value it found.
        edited(OPERATOR, &format!("operator = \"{key}\"")),
        // A syntax error on the same line.
        edited(
            OPERATOR,
            &format!("operator = {{ credential_id = \"Y3JlZGVudGlhbA\" public_key = \"{key}\" }}"),
        ),
        // A value the configuration can't decode.
        with_operator("Y3JlZGVudGlhbA", &format!("{key}=")),
        with_operator(&format!("{key}="), "cHVibGljLWtleQ"),
        // The key where an identifier should be.
        edited(
            OPERATOR,
            &format!(
                "{key} = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}"
            ),
        ),
        edited(
            "principal = \"operator\"",
            &format!("principal = \"{key}\""),
        ),
        edited(
            "auto = \"any\", approvers = [\"operator\"]",
            &format!("auto = \"any\", approvers = [\"{key}\"]"),
        ),
        // The key where a fixed word should be.
        edited("auto = \"patch\"", &format!("auto = \"{key}\"")),
        edited("can = [\"view\"", &format!("can = [\"{key}\"")),
        // The key as a name nothing expects.
        format!("{key} = 1\n{EXAMPLE}"),
        edited("[[grant]]", &format!("[[grant]]\n{key} = 1")),
    ] {
        let err = parse_str(&text).unwrap_err().to_string();
        assert!(!err.contains(key), "{err}");
    }
}

#[test]
fn a_toml_error_names_its_exact_line() {
    let err = parse_str(&edited(OPERATOR, "operator = 1")).unwrap_err();
    let err = err.to_string();
    assert!(
        err.starts_with("configuration is not valid: line 10: "),
        "{err}"
    );
    let err = parse_str("unknown = 1\n").unwrap_err().to_string();
    assert!(
        err.starts_with("configuration is not valid: line 1: "),
        "{err}"
    );
}

/// Whatever the message says and wherever TOML found the text: names and values, each
/// written with TOML's own escape so that the file itself parses.
#[test]
fn a_toml_error_is_escaped_and_short() {
    let long = "a".repeat(10_000);
    for value in ["\\u001b[31mEVIL", long.as_str()] {
        for text in [
            format!("\"{value}\" = 1\n{EXAMPLE}"),
            edited("can = [\"view\"", &format!("can = [\"{value}\"")),
            edited("auto = \"patch\"", &format!("auto = \"{value}\"")),
            edited(
                "principal = \"operator\"",
                &format!("principal = \"{value}\""),
            ),
        ] {
            let err = parse_str(&text).unwrap_err();
            assert!(matches!(err, ConfigError::Toml(_)), "{err}");
            let err = err.to_string();
            assert!(!err.contains('\u{1b}'), "{err}");
            assert!(err.len() < 150, "{} bytes: {err}", err.len());
        }
    }
}

#[test]
fn rp_id_must_be_the_origins_hostname() {
    let accepted = [
        ("example.com", "https://example.com"),
        ("deploy.example.com", "https://deploy.example.com"),
        ("example.com", "https://example.com:8443"),
        ("localhost", "https://localhost"),
    ];
    for (rp_id, origin) in accepted {
        let config = parse_str(&with_approval(rp_id, origin)).unwrap();
        assert_eq!(config.approval().unwrap().rp_id(), rp_id);
        assert_eq!(config.approval().unwrap().origin(), origin);
    }
    let refused = [
        // A parent domain: WebAuthn would allow it, the plan doesn't.
        ("example.com", "https://deploy.example.com"),
        // A subdomain, which no browser would sign for.
        ("deploy.example.com", "https://example.com"),
        ("other.example", "https://example.com"),
        ("Example.com", "https://example.com"),
        ("example.com.", "https://example.com"),
        ("", "https://example.com"),
        // An RP ID has no port, whatever the origin has.
        ("example.com:8443", "https://example.com:8443"),
        ("https://example.com", "https://example.com"),
    ];
    for (rp_id, origin) in refused {
        let err = parse_str(&with_approval(rp_id, origin)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::RpIdNotOriginHost { rp_id: found, .. } if found == rp_id),
            "{rp_id:?}, {origin}: {err}"
        );
    }
}

#[test]
fn origin_must_be_https_with_no_path() {
    for origin in [
        "http://example.com",
        "HTTPS://example.com",
        "example.com",
        "",
        "https://",
        // What a browser would never send: it writes an origin in one form.
        "https://example.com/",
        "https://example.com/path",
        "https://example.com?query",
        "https://example.com#fragment",
        "https://Example.com",
        "https://EXAMPLE.COM",
        "https://example.com.",
        "https://example.com:443",
        "https://example.com:",
        "https://example.com:08443",
        "https://example.com:+8443",
        "https://example.com:0",
        "https://example.com:65536",
        "https://example.com:port",
        "https://user@example.com",
        "https://user:pass@example.com",
        "https://exa\\mple.com",
        "https://exam ple.com",
        "https://example.com\n",
        "https://exa%6dple.com",
        "https://caf\u{e9}.example",
        // WebAuthn's RP ID is a domain, never an address.
        "https://192.0.2.1",
        "https://192.0.2.1:8443",
        "https://3221225985",
        "https://0x7f",
        "https://[2001:db8::1]",
        "https://[2001:db8::1]:8443",
        // Not a hostname.
        "https://-example.com",
        "https://example-.com",
        "https://exam_ple.com",
        "https://example..com",
    ] {
        // The RP ID is right wherever there is a host to take it from, so that the
        // origin is the only thing refused.
        let rp_id = origin
            .strip_prefix("https://")
            .and_then(|rest| rest.split([':', '/']).next())
            .unwrap_or("example.com");
        let err = parse_str(&with_approval(rp_id, origin)).unwrap_err();
        assert!(
            matches!(&err, ConfigError::InvalidApprovalOrigin { origin: found, .. } if found == origin),
            "{origin:?}: {err}"
        );
    }

    // Lengths: a label of 63, a name of 253, and one more of each.
    let label = "a".repeat(63);
    let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    assert_eq!(longest.len(), 253);
    assert!(parse_str(&with_approval(&longest, &format!("https://{longest}"))).is_ok());
    for host in [format!("{longest}a"), format!("{label}a.example")] {
        let err = parse_str(&with_approval(&host, &format!("https://{host}"))).unwrap_err();
        assert!(
            matches!(err, ConfigError::InvalidApprovalOrigin { .. }),
            "{err}"
        );
    }
}

#[test]
fn a_hostile_origin_is_quoted_and_truncated() {
    // Written out, since TOML has its own spelling of an escape. The control character
    // comes first, so that it is inside what's kept.
    let section = |rp_id: &str, origin: &str| {
        edited(
            APPROVAL,
            &format!("[approval]\nrp_id = \"{rp_id}\"\norigin = \"{origin}\"\n\n"),
        )
    };
    let long = "a".repeat(10_000);
    let bad_origin = parse_str(&section("example.com", &format!("http://\\u001b{long}")));
    let bad_rp_id = parse_str(&section(&format!("\\u001b{long}"), "https://example.com"));
    assert!(matches!(
        &bad_origin,
        Err(ConfigError::InvalidApprovalOrigin { .. })
    ));
    assert!(matches!(
        &bad_rp_id,
        Err(ConfigError::RpIdNotOriginHost { .. })
    ));
    for err in [bad_origin, bad_rp_id] {
        let err = err.unwrap_err().to_string();
        assert!(err.len() < 300, "{err}");
        assert!(!err.contains('\u{1b}'), "{err}");
        assert!(err.contains("\\u{1b}"), "{err}");
    }
}

#[test]
fn a_deployment_needs_the_approval_settings() {
    assert_eq!(
        parse_str(&edited(APPROVAL, "")).unwrap_err(),
        ConfigError::MissingApproval
    );
}

#[test]
fn without_deployments_the_approval_settings_are_optional() {
    let config = parse_str("").unwrap();
    assert!(config.approval().is_none());
    assert!(config.approvers().is_empty());
    assert_eq!(config.deployments(), []);

    // They're still judged when they're there, and so is a key.
    let err = parse_str("[approval]\nrp_id = \"example.com\"\norigin = \"http://example.com\"\n")
        .unwrap_err();
    assert!(
        matches!(err, ConfigError::InvalidApprovalOrigin { .. }),
        "{err}"
    );
    let refuse_every_key = |_: &[u8]| Err("refused".to_owned());
    let text = "[approvers]\noperator = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }\n";
    let err = parse_for_tests(text.as_bytes(), refuse_every_key).unwrap_err();
    assert!(matches!(err, ConfigError::InvalidApprover { .. }), "{err}");
}

#[test]
fn approval_settings_refuse_unknown_and_missing_keys() {
    for section in [
        "[approval]\nrp_id = \"example.com\"\n\n",
        "[approval]\norigin = \"https://example.com\"\n\n",
        "[approval]\nrp_id = \"example.com\"\norigin = \"https://example.com\"\nport = 1\n\n",
    ] {
        let err = parse_str(&edited(APPROVAL, section)).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)), "{section}: {err}");
    }
}

#[test]
fn approve_grant_must_be_a_listed_approver() {
    // `backup` is in [approvers], and on app/staging's rule only.
    let two = with_second_approver(
        "backup = { credential_id = \"YmFja3Vw\", public_key = \"YmFja3VwLWtleQ\" }",
    )
    .replacen(
        "rule = { auto = \"any\", approvers = [\"operator\"] }",
        "rule = { auto = \"any\", approvers = [\"operator\", \"backup\"] }",
        1,
    );
    let grant = |deployments: &str, can: &str| {
        format!(
            "{two}\n[[grant]]\nprincipal = \"backup\"\ndeployments = {deployments}\ncan = {can}\n"
        )
    };

    let config = parse_str(&grant("[\"app/staging\"]", "[\"approve\"]")).unwrap();
    assert_eq!(config.grants().len(), 2);

    for deployments in ["[\"app/prod\"]", "[\"app/staging\", \"app/prod\"]"] {
        let err = parse_str(&grant(deployments, "[\"view\", \"approve\"]")).unwrap_err();
        assert_eq!(
            err,
            ConfigError::ApproveNotListed {
                principal: principal("backup"),
                deployment: id("app/prod"),
            }
        );
        let err = err.to_string();
        assert!(err.contains("backup") && err.contains("app/prod"), "{err}");
    }

    // Only `approve` is tied to the rule.
    assert!(
        parse_str(&grant(
            "[\"app/prod\"]",
            "[\"view\", \"request\", \"rollback\"]"
        ))
        .is_ok()
    );
}
