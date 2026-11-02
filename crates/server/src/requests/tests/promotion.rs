//! Promotion when approving: looked at again in the transaction that queues, as nothing
//! later catches it, since it is the controller's alone to enforce.

use axum::http::StatusCode;
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};

use super::requesting::on_promotion;
use super::{HOST, Harness, PROD, digest, request_of};

/// Staging's host says what it runs.
async fn staging_says(h: &Harness, (tag, fill): (&str, char), drift: bool) {
    let state = RunningState {
        deployment: "app/staging".parse().unwrap(),
        deployed: Some(DeployedRelease {
            tag: tag.parse().unwrap(),
            digest: digest(fill),
        }),
        drift,
        phase: Phase::Idle,
        busy: false,
    };
    h.store
        .record_host_state(&"host-c".parse().unwrap(), None, &[&state])
        .await
        .unwrap();
}

/// `v1.1.0` on staging, reported every ten minutes for `seconds`.
async fn staging_healthy_for(h: &Harness, seconds: i64) {
    staging_says(h, ("v1.1.0", '1'), false).await;
    let mut left = seconds;
    while left > 0 {
        h.clock.advance(10 * 60);
        staging_says(h, ("v1.1.0", '1'), false).await;
        left -= 10 * 60;
    }
}

/// A request for `v1.1.0` that promotion let through.
async fn opened(h: &Harness) -> (i64, DeployIntent) {
    let answer = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    request_of(&answer.json())
}

#[tokio::test]
async fn approving_looks_again_and_a_refusal_leaves_the_request_open() {
    let h = on_promotion().await;
    h.ready().await;
    staging_healthy_for(&h, 3600).await;
    let (id, intent) = opened(&h).await;
    let alice = h.session("alice").await;

    // It drifted on staging: not healthy there now, and it may be again.
    staging_says(&h, ("v1.1.0", '1'), true).await;
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "promotion_pending");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);
    let rows = h.audited("approval_refused").await;
    assert_eq!(rows.last().unwrap()["problem"], "promotion_pending");

    // Time starts again when the drift clears, and once it has run, this goes through.
    staging_healthy_for(&h, 3600).await;
    let alice = h.session("alice").await;
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_source_gone_quiet_holds_an_approval_back() {
    let h = on_promotion().await;
    h.ready().await;
    staging_healthy_for(&h, 3600).await;
    let (id, intent) = opened(&h).await;
    h.clock.advance(crate::store::REPORT_FRESH_SECS + 1);
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "promotion_pending");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}

#[tokio::test]
async fn a_source_that_moved_on_before_it_was_seen_healthy_for_long_enough_holds_it_back() {
    let h = on_promotion().await;
    h.ready().await;
    // Reported up to 50 minutes. The hour comes from the time since that report, which a
    // later release's report takes back.
    staging_healthy_for(&h, 3000).await;
    h.clock.advance(10 * 60);
    let (id, intent) = opened(&h).await;
    staging_says(&h, ("v1.1.1", '7'), false).await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "promotion_pending");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);
}

/// The watcher's own rule (`promotion_counts_a_release_the_source_has_since_replaced`): a
/// release seen healthy for the whole time has passed, whatever replaced it since.
#[tokio::test]
async fn a_source_that_moved_on_after_the_whole_time_does_not_hold_it_back() {
    let h = on_promotion().await;
    h.ready().await;
    staging_healthy_for(&h, 3600).await;
    let (id, intent) = opened(&h).await;
    staging_says(&h, ("v1.1.1", '7'), false).await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_first_deploy_does_not_skip_the_look() {
    let h = on_promotion().await;
    h.reports(None).await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    staging_healthy_for(&h, 3600).await;
    let (id, intent) = opened(&h).await;
    assert_eq!(intent.expected_running, None);
    staging_says(&h, ("v1.1.0", '1'), true).await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "promotion_pending");
    assert_eq!(h.count_deploys().await, 0);
}

#[tokio::test]
async fn a_host_calling_what_it_runs_higher_does_not_make_a_request_a_rollback() {
    let h = on_promotion().await;
    h.ready().await;
    staging_healthy_for(&h, 3600).await;
    let (id, intent) = opened(&h).await;
    staging_says(&h, ("v1.1.0", '1'), true).await;
    // The same digest, so it isn't stale, under a tag that would make this one a downgrade.
    h.reports(Some(("v9.0.0", '0'))).await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "promotion_pending");
}

#[tokio::test]
async fn a_rollback_stays_one_whatever_the_host_calls_what_it_runs_later() {
    let h = on_promotion().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let answer = h.ask(&h.token("erin").await, "v1.0.0").await;
    let (id, intent) = request_of(&answer.json());
    // The same digest, under a tag that would make this one an upgrade.
    h.reports(Some(("v0.9.0", '1'))).await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_rollback_does_not_wait_for_promotion_to_be_approved_either() {
    let h = on_promotion().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let answer = h.ask(&h.token("erin").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (id, intent) = request_of(&answer.json());
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}
