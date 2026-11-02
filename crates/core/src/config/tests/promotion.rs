//! Workflows, promotion chains and grants.

use super::super::{ConfigError, Level};
use super::{edited, id, parse_str};
use crate::ids::PrincipalId;

#[test]
fn workflow_is_a_file_directly_in_the_workflows_directory() {
    let from = "workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"";
    for bad in [
        ".github/workflows/.yml",
        ".github/workflows/a/b.yml",
        ".github/workflows/a b@refs.yml",
        ".github/workflows/release.json",
        ".github/workflows/../workflows/release.yml",
        "x/.github/workflows/release.yml",
    ] {
        let to = from.replace(".github/workflows/release.yml", bad);
        let err = parse_str(&edited(from, &to)).unwrap_err();
        assert!(
            matches!(
                &err,
                ConfigError::Invalid { field, value, .. }
                    if field == "origin.workflow" && value == bad
            ),
            "{bad}: {err}"
        );
        assert!(!err.to_string().contains("without '..'"), "{err}");
    }
    for ok in [
        ".github/workflows/release.yaml",
        ".github/workflows/Release_v2.1-x.yml",
    ] {
        let to = from.replace(".github/workflows/release.yml", ok);
        assert!(parse_str(&edited(from, &to)).is_ok(), "{ok}");
    }
}

#[test]
fn promotion_cycle_reports_the_loop() {
    // app/canary -> app/staging -> app/prod -> app/staging: the error is
    // reported for app/canary and names only the loop.
    let canary = r#"
[[deployment]]
id = "app/canary"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-canary", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/staging", healthy_for = "1h" }

[[deployment]]
id = "app/prod""#;
    let text = edited("\n[[deployment]]\nid = \"app/prod\"", canary);
    let text = text.replacen(
        "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
        "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]\npromote_to = { deployment = \"app/staging\", healthy_for = \"1h\" }",
        1,
    );
    let err = parse_str(&text).unwrap_err();
    assert_eq!(
        err,
        ConfigError::PromotionCycle {
            deployment: id("app/canary"),
            chain: vec![id("app/staging"), id("app/prod"), id("app/staging")],
        }
    );
    assert!(
        err.to_string().ends_with(
            "app/canary: promote_to chain forms a cycle: app/staging -> app/prod -> app/staging"
        ),
        "{err}"
    );
}

#[test]
fn promotion_stays_within_one_repository() {
    let text = edited(
        "id = \"app/staging\"\nrepo = { name = \"example/app\", id = 1234",
        "id = \"app/staging\"\nrepo = { name = \"example/app\", id = 4321",
    );
    let err = parse_str(&text).unwrap_err();
    assert_eq!(
        err,
        ConfigError::PromotionRepoMismatch {
            deployment: id("app/staging"),
            target: id("app/prod"),
            repo_id: 4321,
            target_repo_id: 1234,
        }
    );
    assert!(err.to_string().contains("app/staging"), "{err}");
}

#[test]
fn grants_must_list_deployments_and_permissions() {
    let principal: PrincipalId = "operator".parse().unwrap();
    let err = parse_str(&edited(
        "deployments = [\"app/prod\", \"app/staging\"]",
        "deployments = []",
    ))
    .unwrap_err();
    assert_eq!(
        err,
        ConfigError::EmptyGrant {
            principal: principal.clone(),
            field: "deployments"
        }
    );
    assert!(err.to_string().contains("operator"), "{err}");
    let err = parse_str(&edited(
        "can = [\"view\", \"request\", \"approve\", \"rollback\"]",
        "can = []",
    ))
    .unwrap_err();
    assert_eq!(
        err,
        ConfigError::EmptyGrant {
            principal,
            field: "can"
        }
    );
}

#[test]
fn approve_not_broader_names_levels_in_config_spelling() {
    let err = parse_str(&edited("approve = \"minor\"", "approve = \"patch\"")).unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("rule.approve = \"patch\"") && text.contains("rule.auto = \"patch\""),
        "{text}"
    );
    assert!(!text.contains("Patch"), "{text}");
    assert_eq!(Level::Minor.to_string(), "minor");
    assert_eq!(Level::Any.to_string(), "any");
}
