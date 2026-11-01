//! Promotion: no proposal to the target until the source has had the release
//! healthy for long enough.

use super::*;

/// `app/staging` promoting to `app/prod` after a day, both of one repository.
const PROMOTING: &str = r#"
[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "host-a"
compose = { dir = "/srv/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]

[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "host-a"
compose = { dir = "/srv/staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "24h" }
"#;

const STAGING: &str = "app/staging";

#[tokio::test]
async fn promotion_waits_for_healthy_for() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.tags(STAGING, &["v1.2.4"]);

    h.tick().await;
    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "manual");
    assert!(reason.contains(STAGING), "{reason}");
    assert!(reason.contains("controller only"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);

    h.clock.advance(24 * 60 * 60 - 1);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, []);

    h.clock.advance(1);
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await.len(), 1);
    // Each decision once: waiting, then allowed.
    let decisions = h.audit("rule_decision").await;
    let prod: Vec<_> = decisions
        .iter()
        .filter(|d| d["decision"] == "manual" || d["decision"] == "auto")
        .collect();
    assert_eq!(prod.len(), 2, "{decisions:?}");
}

#[tokio::test]
async fn promotion_counts_from_the_drift_clearing() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);

    h.clock.advance(23 * 60 * 60);
    let mut drifted = Harness::state_of(STAGING, Some("v1.2.4"));
    drifted.drift = true;
    h.report_state(HOST, drifted).await;
    h.clock.advance(60 * 60);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "drifted");

    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.clock.advance(60 * 60);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "only an hour since it cleared");

    h.clock.advance(23 * 60 * 60);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn promotion_needs_the_source_to_have_run_that_release() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.5")).await;
    h.fake.tags(PROD, &["v1.2.4"]);

    h.clock.advance(48 * 60 * 60);
    h.tick().await;

    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn promotion_counts_a_release_the_source_has_since_replaced() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.3")).await;
    // Prod is held back by promotion throughout; staging moves along.
    h.fake.tags(STAGING, &["v1.2.4"]);
    h.tick().await;
    h.finish(HOST, ReportedOutcome::Deployed {}).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.clock.advance(25 * 60 * 60);
    h.fake.tags(STAGING, &["v1.2.4", "v1.2.5"]);
    h.tick().await;
    h.finish(HOST, ReportedOutcome::Deployed {}).await;
    h.report(STAGING, HOST, Some("v1.2.5")).await;

    h.fake.tags(PROD, &["v1.2.4", "v1.2.5"]);
    h.tick().await;

    // v1.2.4 had its day, and v1.2.5 has not yet.
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.decision(PROD, "v1.2.5").await.0, "manual");
    assert_eq!(h.deploys(PROD).await[0].0, "v1.2.4");
}
