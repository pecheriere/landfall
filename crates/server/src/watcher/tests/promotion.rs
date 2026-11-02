//! Promotion: no proposal to the target until the source has had the release
//! healthy for long enough.

use landfall_core::protocol::{Phase, ReportedOutcome};

use super::{HOST, Harness, PROD};

/// `app/staging` promoting to `app/prod` after a day, both of one repository.
pub(super) const PROMOTING: &str = r#"
[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }

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

pub(super) const STAGING: &str = "app/staging";

/// Staging's host goes on saying it runs `tag`, ten minutes apart, for `seconds`.
async fn keep_saying(h: &Harness, tag: &str, seconds: i64) {
    let mut left = seconds;
    while left > 0 {
        let step = left.min(10 * 60);
        h.clock.advance(step);
        h.report(STAGING, HOST, Some(tag)).await;
        left -= step;
    }
}

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

    keep_saying(&h, "v1.2.4", 24 * 60 * 60 - 1).await;
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

    keep_saying(&h, "v1.2.4", 23 * 60 * 60).await;
    let mut drifted = Harness::state_of(STAGING, Some("v1.2.4"));
    drifted.drift = true;
    h.report_state(HOST, drifted).await;
    h.clock.advance(60 * 60);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "drifted");

    h.report(STAGING, HOST, Some("v1.2.4")).await;
    keep_saying(&h, "v1.2.4", 60 * 60).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "only an hour since it cleared");

    keep_saying(&h, "v1.2.4", 23 * 60 * 60).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_source_host_gone_quiet_stops_its_clock_and_it_goes_on_when_it_is_back() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    keep_saying(&h, "v1.2.4", 12 * 60 * 60).await;

    // Quiet for far longer than the day it needs: that is no evidence of anything.
    h.clock.advance(48 * 60 * 60);
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;
    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "manual");
    assert!(reason.contains("quiet"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);

    // It is back, saying the same: the silence didn't count, and neither did it undo
    // the half day before.
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "half a day so far");
    keep_saying(&h, "v1.2.4", 12 * 60 * 60 - 1).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "a second short");
    keep_saying(&h, "v1.2.4", 1).await;
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

/// A failed try at another release, say: the release that runs is the same throughout.
async fn deploying_for(h: &Harness, tag: &str, seconds: i64) {
    let mut deploying = Harness::state_of(STAGING, Some(tag));
    deploying.phase = Phase::Deploying;
    deploying.busy = true;
    let mut left = seconds;
    while left > 0 {
        let step = left.min(10 * 60);
        h.report_state(HOST, deploying.clone()).await;
        h.clock.advance(step);
        left -= step;
    }
    h.report(STAGING, HOST, Some(tag)).await;
}

#[tokio::test]
async fn time_that_is_not_idle_does_not_count_for_the_release_that_runs() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    keep_saying(&h, "v1.2.4", 12 * 60 * 60).await;
    deploying_for(&h, "v1.2.4", 24 * 60 * 60).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, []);
    keep_saying(&h, "v1.2.4", 12 * 60 * 60).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn time_that_is_not_idle_does_not_count_for_a_replaced_release() {
    let h = replaced_after(async |h| {
        keep_saying(h, "v1.2.4", 12 * 60 * 60).await;
        deploying_for(h, "v1.2.4", 24 * 60 * 60).await;
    })
    .await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");

    let h = replaced_after(async |h| {
        keep_saying(h, "v1.2.4", 12 * 60 * 60).await;
        deploying_for(h, "v1.2.4", 24 * 60 * 60).await;
        keep_saying(h, "v1.2.4", 12 * 60 * 60).await;
    })
    .await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
}

#[tokio::test]
async fn a_report_counts_for_a_quarter_of_an_hour() {
    use crate::store::REPORT_FRESH_SECS;

    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    keep_saying(&h, "v1.2.4", 24 * 60 * 60 - REPORT_FRESH_SECS).await;
    h.fake.tags(PROD, &["v1.2.4"]);

    h.clock.advance(REPORT_FRESH_SECS + 1);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "a second too late");

    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    keep_saying(&h, "v1.2.4", 24 * 60 * 60 - REPORT_FRESH_SECS).await;
    h.fake.tags(PROD, &["v1.2.4"]);

    h.clock.advance(REPORT_FRESH_SECS);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn an_unchanged_report_is_noted_at_most_once_a_minute_and_never_audited() {
    let h = Harness::new(PROMOTING).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    let audited = h.audit("running_changed").await.len();
    let noted = async |h: &Harness| -> i64 {
        sqlx::query_scalar("SELECT last_report FROM running_states")
            .fetch_one(h.store.pool())
            .await
            .unwrap()
    };
    let first = noted(&h).await;

    h.clock.advance(59);
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    assert_eq!(noted(&h).await, first);

    h.clock.advance(1);
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    assert_eq!(noted(&h).await, first + 60);
    assert_eq!(h.audit("running_changed").await.len(), audited);
}

#[tokio::test]
async fn another_hosts_report_says_nothing_about_a_source() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    // The configuration gives staging to this host; this is some other's word.
    h.report(STAGING, "host-z", Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);

    h.clock.advance(24 * 60 * 60);
    h.report(STAGING, "host-z", Some("v1.2.4")).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;

    assert_eq!(h.deploys(PROD).await, []);
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
    keep_saying(&h, "v1.2.4", 25 * 60 * 60).await;
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

/// `v1.2.4` is deployed on staging, then replaced by `v1.2.5`; prod is asked about
/// `v1.2.4` after `between` has run, between them.
async fn replaced_after(between: impl AsyncFnOnce(&Harness)) -> Harness {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.3")).await;
    h.fake.tags(STAGING, &["v1.2.4"]);
    h.tick().await;
    h.finish(HOST, ReportedOutcome::Deployed {}).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    between(&h).await;
    h.fake.tags(STAGING, &["v1.2.4", "v1.2.5"]);
    h.tick().await;
    h.finish(HOST, ReportedOutcome::Deployed {}).await;
    h.report(STAGING, HOST, Some("v1.2.5")).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    h
}

#[tokio::test]
async fn elapsed_time_is_no_promotion_for_a_release_replaced_after_going_quiet() {
    let h = replaced_after(async |h| h.clock.advance(25 * 60 * 60)).await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");
    assert_eq!(h.deploys(PROD).await, []);

    // One report after the silence, as the host comes back, makes it no better.
    let h = replaced_after(async |h| {
        h.clock.advance(24 * 60 * 60);
        h.report(STAGING, HOST, Some("v1.2.4")).await;
    })
    .await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn elapsed_time_is_no_promotion_for_a_release_replaced_while_drifted() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.clock.advance(60 * 60);
    let mut drifted = Harness::state_of(STAGING, Some("v1.2.4"));
    drifted.drift = true;
    h.report_state(HOST, drifted.clone()).await;
    h.clock.advance(24 * 60 * 60);
    h.report_state(HOST, drifted).await;
    // Put right by a release that a deploy by hand brought, as far as this can tell.
    h.report(STAGING, HOST, Some("v1.2.5")).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn a_replaced_release_counts_what_it_was_seen_to_do_and_no_more() {
    let h = replaced_after(async |h| {
        keep_saying(h, "v1.2.4", 24 * 60 * 60 - 1).await;
        h.clock.advance(60 * 60);
    })
    .await;
    assert_eq!(
        h.decision(PROD, "v1.2.4").await.0,
        "manual",
        "a second short"
    );

    let h = replaced_after(async |h| keep_saying(h, "v1.2.4", 24 * 60 * 60).await).await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_rollback_starts_the_time_again_for_what_it_put_back() {
    // Heard of as it happens...
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    keep_saying(&h, "v1.2.4", 23 * 60 * 60).await;
    let mut rolling = Harness::state_of(STAGING, Some("v1.2.4"));
    rolling.phase = Phase::RollingBack;
    rolling.busy = true;
    h.report_state(HOST, rolling).await;
    h.report(STAGING, HOST, Some("v1.2.4")).await;
    keep_saying(&h, "v1.2.4", 23 * 60 * 60).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, [], "23 hours since it came back");
    keep_saying(&h, "v1.2.4", 60 * 60).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);

    // ...and known only by the report, the poll having missed it.
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.3")).await;
    h.fake.tags(STAGING, &["v1.2.4"]);
    keep_saying(&h, "v1.2.3", 24 * 60 * 60).await;
    h.tick().await;
    h.finish(
        HOST,
        ReportedOutcome::RolledBack {
            reason: "checks failed".to_owned(),
        },
    )
    .await;
    h.report(STAGING, HOST, Some("v1.2.3")).await;
    let secs: Option<i64> =
        sqlx::query_scalar("SELECT healthy_secs FROM running_states WHERE deployment = ?")
            .bind(STAGING)
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(secs, Some(0));
}
