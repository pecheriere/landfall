//! What a deployment's checks must observe.

use super::super::ConfigError;
use super::{edited, id, parse_str};

/// The fixture with app/staging's check list replaced by `checks`.
pub(super) fn with_staging_checks(checks: &str) -> String {
    edited(
        "checks = [\"container-healthy\"]",
        &format!("checks = {checks}"),
    )
}

#[test]
fn a_deployment_needs_a_check_that_observes_the_service() {
    let text = with_staging_checks("[{ no_log_match = \"panicked\", within_secs = 30 }]");
    let err = parse_str(&text).unwrap_err();
    assert_eq!(err, ConfigError::NoObservingCheck(id("app/staging")));
    assert!(err.to_string().contains("app/staging"), "{err}");
    for observing in [
        "[\"container-healthy\", { no_log_match = \"panicked\", within_secs = 30 }]",
        "[{ command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"x\", within_secs = 1 }]",
        "[{ no_log_match = \"x\", within_secs = 1 }, { http = \"/\", network = \"app\", port = 8080, expect = 204 }]",
    ] {
        assert!(
            parse_str(&with_staging_checks(observing)).is_ok(),
            "{observing}"
        );
    }
}

#[test]
fn http_checks_validate_path_network_and_status() {
    for (check, field, value) in [
        (
            "{ http = \"/h\", network = \"app\", port = 8080, expect = 0 }",
            "checks[0].expect",
            "0",
        ),
        (
            "{ http = \"/h\", network = \"app\", port = 8080, expect = 99 }",
            "checks[0].expect",
            "99",
        ),
        (
            "{ http = \"/h\", network = \"app\", port = 8080, expect = 600 }",
            "checks[0].expect",
            "600",
        ),
        (
            "{ http = \"/h\\r\\nX: y\", network = \"app\", port = 8080, expect = 200 }",
            "checks[0].http",
            "/h\r\nX: y",
        ),
        (
            "{ http = \"/a b\", network = \"app\", port = 8080, expect = 200 }",
            "checks[0].http",
            "/a b",
        ),
        (
            "{ http = \"/caf\u{e9}\", network = \"app\", port = 8080, expect = 200 }",
            "checks[0].http",
            "/caf\u{e9}",
        ),
        (
            "{ http = \"health\", network = \"app\", port = 8080, expect = 200 }",
            "checks[0].http",
            "health",
        ),
        (
            "{ http = \"/h\", network = \"n n\", port = 8080, expect = 200 }",
            "checks[0].network",
            "n n",
        ),
        (
            "{ http = \"/h\", network = \"\", port = 8080, expect = 200 }",
            "checks[0].network",
            "",
        ),
        (
            "{ http = \"/h\", network = \"-net\", port = 8080, expect = 200 }",
            "checks[0].network",
            "-net",
        ),
    ] {
        let err = parse_str(&with_staging_checks(&format!("[{check}]"))).unwrap_err();
        assert!(
            matches!(
                &err,
                ConfigError::Invalid { field: f, value: v, .. } if f == field && v == value
            ),
            "{check}: {err}"
        );
    }
    let long = format!("n{}", "x".repeat(128));
    let err = parse_str(&with_staging_checks(&format!(
        "[{{ http = \"/h\", network = \"{long}\", port = 8080, expect = 200 }}]"
    )))
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    let at_limit = format!("n{}", "x".repeat(127));
    for check in [
        "{ http = \"/h?a=1&b=%20\", network = \"app_net.1-x\", port = 8080, expect = 100 }"
            .to_owned(),
        format!("{{ http = \"/\", network = \"{at_limit}\", port = 8080, expect = 599 }}"),
    ] {
        assert!(
            parse_str(&with_staging_checks(&format!("[{check}]"))).is_ok(),
            "{check}"
        );
    }
}
