//! The hash, the encoding, and what the parser names in an error.

use super::super::{ConfigError, LOG_PATTERN_LIMIT, parse_for_tests, sha256_hex};
use super::checks::with_staging_checks;
use super::{EXAMPLE, edited, parse_str};

#[test]
fn sha256_hex_matches_the_empty_input_vector() {
    assert_eq!(
        sha256_hex(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
}

#[test]
fn hash_covers_exactly_the_file_bytes() {
    let config = parse_str(EXAMPLE).unwrap();
    assert_eq!(config.hash(), sha256_hex(EXAMPLE.as_bytes()));
    // Same meaning, different bytes: a different hash.
    let spaced = format!("{EXAMPLE}\n");
    let other = parse_str(&spaced).unwrap();
    assert_ne!(other.hash(), config.hash());
}

#[test]
fn non_utf8_bytes_are_refused() {
    let mut bytes = EXAMPLE.as_bytes().to_vec();
    bytes.insert(10, 0xff);
    assert_eq!(
        parse_for_tests(&bytes, |_| Ok(())).unwrap_err(),
        ConfigError::NotUtf8 { offset: 10 }
    );
}

#[test]
fn unknown_key_in_a_check_table_is_named() {
    let text = edited(
        "checks = [\"container-healthy\"]",
        "checks = [{ http = \"/h\", netwrok = \"app\", expect = 200 }]",
    );
    let err = parse_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::Toml(_)), "{err}");
    assert!(err.to_string().contains("netwrok"), "{err}");
}

#[test]
fn check_errors_name_the_entry_and_the_keys() {
    let text = edited(
        "checks = [\"container-healthy\"]",
        "checks = [\"container-healthy\", \"container-healthy\", { http = \"/h\", command = [\"x\"] }]",
    );
    let err = parse_str(&text).unwrap_err().to_string();
    assert!(err.contains("app/staging"), "{err}");
    assert!(err.contains("checks[2]"), "{err}");
    assert!(err.contains("http") && err.contains("command"), "{err}");
    assert!(!err.contains("{...}"), "{err}");

    let text = edited("checks = [\"container-healthy\"]", "checks = [\"healthy\"]");
    let err = parse_str(&text).unwrap_err().to_string();
    assert!(
        err.contains("checks[0]") && err.contains("healthy"),
        "{err}"
    );
}

#[test]
fn compose_dir_must_be_canonical() {
    // Spellings of the same directory as app/prod's must not slip past
    // the one-service-per-host rule.
    for dir in [
        "/srv/compose/app/",
        "/srv//compose/app",
        "/srv/./compose/app",
        "/srv/compose/app/.",
        "/srv/compose/../compose/app",
        "/",
        "//",
    ] {
        let text = edited(
            "dir = \"/srv/compose/app-staging\"",
            &format!("dir = \"{dir}\""),
        );
        let err = parse_str(&text).unwrap_err();
        assert!(
            matches!(&err, ConfigError::Invalid { field, .. } if field == "compose.dir"),
            "{dir}: {err}"
        );
    }
}

#[test]
fn backup_paths_must_be_canonical() {
    for path in ["state/", "a//b", "./state", "state/."] {
        let text = edited("paths = [\"state\"]", &format!("paths = [\"{path}\"]"));
        assert!(
            matches!(parse_str(&text), Err(ConfigError::Invalid { .. })),
            "{path}"
        );
    }
}

#[test]
fn log_checks_stay_within_what_the_agent_can_run() {
    let long = "x".repeat(LOG_PATTERN_LIMIT + 1);
    for bad in [
        format!("[\"container-healthy\", {{ no_log_match = \"{long}\", within_secs = 1 }}]"),
        "[\"container-healthy\", { no_log_match = \"a\\nb\", within_secs = 1 }]".to_owned(),
        "[\"container-healthy\", { no_log_match = \"x\", within_secs = 3601 }]".to_owned(),
    ] {
        let err = parse_str(&with_staging_checks(&bad)).unwrap_err();
        assert!(
            matches!(
                &err,
                ConfigError::Invalid { deployment, field, .. }
                    if deployment.as_ref() == "app/staging" && field == "checks[1]"
            ),
            "{err}"
        );
    }
    let longest = "x".repeat(LOG_PATTERN_LIMIT);
    let at_the_limits =
        format!("[\"container-healthy\", {{ no_log_match = \"{longest}\", within_secs = 3600 }}]");
    assert!(parse_str(&with_staging_checks(&at_the_limits)).is_ok());
}
