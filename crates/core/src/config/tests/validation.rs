//! The example, and each validation rule.

use super::super::{Check, ConfigError, Level};
use super::checks::with_staging_checks;
use super::{EXAMPLE, edited, id, parse_str};
use crate::ids::HostId;

#[test]
fn example_parses() {
    let config = parse_str(EXAMPLE).unwrap();
    let prod = config.deployment(&id("app/prod")).unwrap();
    assert_eq!(prod.rule().auto(), Some(Level::Patch));
    assert_eq!(prod.rule().approve(), Some(Level::Minor));
    assert!(!prod.rule().prereleases());
    assert_eq!(prod.compose().service(), "app");
    let staging = config.deployment(&id("app/staging")).unwrap();
    assert_eq!(staging.promote_to().unwrap().healthy_for_secs(), 86_400);
    let host: HostId = "home-1".parse().unwrap();
    assert_eq!(config.deployments_for_host(&host).count(), 2);
    let other: HostId = "home-2".parse().unwrap();
    assert_eq!(config.deployments_for_host(&other).count(), 0);
    assert_eq!(config.grants()[0].can().len(), 4);
}

#[test]
fn unknown_fields_are_errors() {
    let text = edited(
        "checks = [\"container-healthy\"]",
        "checks = [\"container-healthy\"]\nrul = { auto = \"patch\" }",
    );
    let err = parse_str(&text).unwrap_err();
    assert!(matches!(err, ConfigError::Toml(_)));
    assert!(err.to_string().contains("rul"), "{err}");
}

/// Two spellings of one entry must never leave the file saying one thing to a reader and
/// another to the parser: a signer or an approver named twice could otherwise be replaced by
/// a line further down.
#[test]
fn duplicate_keys_are_errors() {
    for text in [
        edited("[signers]", "[signers]\nmaintainer = \"x\""),
        edited("[signers]", "[signers]\n\"maintainer\" = \"x\""),
        edited("[signers]", "[signers]\n\"\\u006daintainer\" = \"x\""),
        edited("[approvers]", "[approvers]\noperator = {}"),
        edited("[[grant]]", "[approvers.operator]\n[[grant]]"),
        edited("[[grant]]", "[approval]\n[[grant]]"),
        edited("[[grant]]", "[signers]\n[[grant]]"),
        edited("host = ", "host = \"home-2\"\nhost = "),
        edited("repo = { name", "repo = { name = \"example/other\", name"),
    ] {
        let err = parse_str(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)), "{err}");
        assert!(err.to_string().contains("duplicate key"), "{err}");
    }
}

#[test]
fn each_validation_rule_is_enforced() {
    // 1: duplicate ids.
    let err = parse_str(&edited("id = \"app/staging\"", "id = \"app/prod\"")).unwrap_err();
    assert!(matches!(err, ConfigError::DuplicateDeployment(_)), "{err}");
    assert!(err.to_string().contains("app/prod"));

    // 2: unknown or empty origin signers.
    let err = parse_str(&edited(
        "signers = [\"maintainer\"]",
        "signers = [\"nobody\"]",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::UnknownSigner { .. }), "{err}");
    assert!(err.to_string().contains("app/prod") && err.to_string().contains("nobody"));
    let err = parse_str(&edited("signers = [\"maintainer\"]", "signers = []")).unwrap_err();
    assert!(matches!(err, ConfigError::NoSigners(_)), "{err}");
    assert!(err.to_string().contains("app/prod"));

    // 3: approvers always non-empty and known.
    let err = parse_str(&edited(
        "approvers = [\"operator\"] }\nchecks = [\"container",
        "approvers = [] }\nchecks = [\"container",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::NoApprovers(_)), "{err}");
    assert!(err.to_string().contains("app/staging"));
    let err = parse_str(&edited(
        "approve = \"minor\", approvers = [\"operator\"]",
        "approve = \"minor\", approvers = [\"ghost\"]",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::UnknownApprover { .. }), "{err}");
    assert!(err.to_string().contains("app/prod") && err.to_string().contains("ghost"));

    // 4: approve must be broader than auto.
    let err = parse_str(&edited("approve = \"minor\"", "approve = \"patch\"")).unwrap_err();
    assert!(
        matches!(err, ConfigError::ApproveNotBroader { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("app/prod"));

    // 5: checks non-empty.
    let err = parse_str(&edited(
        "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
        "checks = []",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::NoChecks(_)), "{err}");
    assert!(err.to_string().contains("app/prod"));

    // 6: promotion target unknown, itself, or a cycle.
    let err = parse_str(&edited(
        "deployment = \"app/prod\", healthy_for",
        "deployment = \"app/none\", healthy_for",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::UnknownPromotion { .. }), "{err}");
    assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/none"));
    let err = parse_str(&edited(
        "deployment = \"app/prod\", healthy_for",
        "deployment = \"app/staging\", healthy_for",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::SelfPromotion(_)), "{err}");
    assert!(err.to_string().contains("app/staging"));
    let cyclic = edited(
        "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
        "checks = [\"container-healthy\"]\npromote_to = { deployment = \"app/staging\", healthy_for = \"1h\" }",
    );
    let err = parse_str(&cyclic).unwrap_err();
    assert!(matches!(err, ConfigError::PromotionCycle { .. }), "{err}");
    assert!(
        err.to_string()
            .contains("app/prod -> app/staging -> app/prod"),
        "{err}"
    );

    // 7: grants.
    let err = parse_str(&edited(
        "deployments = [\"app/prod\", \"app/staging\"]",
        "deployments = [\"app/none\"]",
    ))
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::UnknownGrantDeployment { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("app/none") && err.to_string().contains("operator"));
    let err = parse_str(&edited(
        "principal = \"operator\"",
        "principal = \"maintainer\"",
    ))
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::ApproveWithoutApprover { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("maintainer"));

    // 8: one deployment per host and compose directory.
    let err = parse_str(&edited(
        "dir = \"/srv/compose/app-staging\"",
        "dir = \"/srv/compose/app\"",
    ))
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::DuplicateComposeDir { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/prod"));
}

#[test]
fn http_check_requires_a_port() {
    let err = parse_str(&with_staging_checks(
        "[{ http = \"/h\", network = \"app\", expect = 200 }]",
    ))
    .unwrap_err();
    assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
    let err = err.to_string();
    assert!(err.contains("port") && err.contains("app/staging"), "{err}");
}

#[test]
fn port_zero_is_rejected() {
    for port in ["0", "65536", "-1"] {
        let check =
            format!("[{{ http = \"/h\", network = \"app\", port = {port}, expect = 200 }}]");
        assert!(parse_str(&with_staging_checks(&check)).is_err(), "{port}");
    }
    for port in ["1", "65535"] {
        let check =
            format!("[{{ http = \"/h\", network = \"app\", port = {port}, expect = 200 }}]");
        assert!(parse_str(&with_staging_checks(&check)).is_ok(), "{port}");
    }
}

#[test]
fn two_deployments_cannot_share_a_directory() {
    let err = parse_str(&edited(
        "dir = \"/srv/compose/app-staging\", service = \"app\"",
        "dir = \"/srv/compose/app\", service = \"other\"",
    ))
    .unwrap_err();
    assert!(
        matches!(err, ConfigError::DuplicateComposeDir { .. }),
        "{err}"
    );
    let err = err.to_string();
    assert!(
        err.contains("app/staging") && err.contains("app/prod"),
        "{err}"
    );
    assert!(err.contains("/srv/compose/app"), "{err}");
}

#[test]
fn malformed_values_name_the_deployment() {
    for (from, to) in [
        ("dir = \"/srv/compose/app\"", "dir = \"srv/compose/app\""),
        ("dir = \"/srv/compose/app\"", "dir = \"/srv/../app\""),
        (
            "service = \"app\" }\norigin = { workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "service = \"App\" }\norigin = { workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        ),
        (
            "workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "workflow = \"release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
        ),
        ("paths = [\"state\"]", "paths = [\"/etc\"]"),
        ("paths = [\"state\"]", "paths = [\"a/../b\"]"),
        ("paths = [\"state\"]", "paths = []"),
        ("healthy_for = \"24h\"", "healthy_for = \"24\""),
        ("healthy_for = \"24h\"", "healthy_for = \"0h\""),
    ] {
        let err = parse_str(&edited(from, to)).unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{to}: {err}");
        assert!(err.to_string().contains("app/"), "{err}");
    }
}

#[test]
fn durations_use_minutes_hours_days() {
    for (text, secs) in [("90m", 5_400), ("2h", 7_200), ("1d", 86_400)] {
        let config = parse_str(&edited(
            "healthy_for = \"24h\"",
            &format!("healthy_for = \"{text}\""),
        ))
        .unwrap();
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(staging.promote_to().unwrap().healthy_for_secs(), secs);
    }
}

#[test]
fn checks_parse_in_both_forms() {
    let all = "checks = [\"container-healthy\", { http = \"/health\", network = \"app\", port = 8080, expect = 200 }, { command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"panicked\", within_secs = 30 }]";
    let config = parse_str(&edited("checks = [\"container-healthy\"]", all)).unwrap();
    let staging = config.deployment(&id("app/staging")).unwrap();
    assert_eq!(
        staging.checks(),
        vec![
            Check::ContainerHealthy,
            Check::Http {
                path: "/health".into(),
                network: "app".into(),
                port: 8080,
                expect: 200
            },
            Check::Command {
                argv: vec!["/app".into(), "healthcheck".into()]
            },
            Check::NoLogMatch {
                pattern: "panicked".into(),
                within_secs: 30
            },
        ]
    );
    for bad in [
        "{ http = \"/h\", command = [\"x\"] }",
        "{ http = \"/h\" }",
        "{ command = [] }",
        "{ no_log_match = \"x\" }",
        "{}",
        "\"unknown\"",
    ] {
        let text = edited(
            "checks = [\"container-healthy\"]",
            &format!("checks = [{bad}]"),
        );
        let err = parse_str(&text).unwrap_err();
        assert!(
            matches!(
                &err,
                ConfigError::Invalid { deployment, field, .. }
                    if deployment.as_ref() == "app/staging" && field == "checks[0]"
            ),
            "{bad}: {err}"
        );
    }
}
