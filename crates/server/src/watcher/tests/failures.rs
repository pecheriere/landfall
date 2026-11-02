//! What fails, and what that leaves working: holds, retries and backoff.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use super::super::backoff::{BACKOFF_MAX_SECS, BACKOFF_START_SECS, RATE_LIMIT_MAX_SECS};
use super::super::{
    BELOW_RUNNING_RETRY_SECS, EAGER_RETRY_SECS, SLOW_RETRY_SECS, VERIFICATIONS_PER_TICK,
};
use super::promotion::{PROMOTING, STAGING};
use super::{
    HOST, Harness, MakeError, OTHER, PROD, RateLimitReset, WatcherState, list_cap, no_bundle,
    rate_limited, server_error,
};
#[tokio::test]
async fn tags_that_keep_failing_do_not_starve_a_release_below_them() {
    let h = Harness::running("v1.2.3").await;
    let junk: Vec<String> = (100..100 + 2 * VERIFICATIONS_PER_TICK)
        .map(|n| format!("v1.2.{n}"))
        .collect();
    let mut tags: Vec<&str> = junk.iter().map(String::as_str).collect();
    tags.push("v1.2.4");
    h.fake.tags(PROD, &tags);
    for tag in &junk {
        h.fake
            .locked()
            .verify_fails
            .insert(tag.clone(), no_bundle("v1.2.0"));
    }

    for _ in 0..3 {
        h.tick().await;
        h.clock.advance(300);
    }

    assert_eq!(
        h.deploys(PROD).await,
        [("v1.2.4".to_owned(), "queued".to_owned())]
    );
}

#[tokio::test]
async fn a_tag_below_the_running_version_is_hardly_ever_tried_again() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.2"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.2".to_owned(), no_bundle("v1.2.2"));

    h.tick().await;
    assert_eq!(h.fake.verify_count(), 1);
    h.clock.advance(EAGER_RETRY_SECS + SLOW_RETRY_SECS);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 1);
    h.clock.advance(BELOW_RUNNING_RETRY_SECS);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 2);
}

#[tokio::test]
async fn a_deadline_leaves_a_reason_once() {
    let mut h = Harness::running("v1.2.3").await;
    h.state = Arc::new(WatcherState::with_deadline(Duration::from_millis(50)));
    h.fake.locked().tags_hang.insert(PROD.to_owned());
    h.fake.tags(OTHER, &[]);

    h.tick().await;
    h.clock.advance(BACKOFF_START_SECS);
    h.tick().await;

    let held = h.hold_reason(PROD, "").await.unwrap();
    assert!(held.contains("deadline"), "{held}");
    let audited = h.audit("release_held").await;
    let of_deadline = audited
        .iter()
        .filter(|d| d["reason"].to_string().contains("deadline"));
    assert_eq!(of_deadline.count(), 1, "{audited:?}");
}

#[tokio::test]
async fn each_deployment_of_a_repository_gets_its_turn() {
    let h = Harness::new(PROMOTING).await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.report(STAGING, HOST, Some("v1.2.3")).await;
    h.fake.tags(STAGING, &["v1.2.4"]);
    // The first in the file stops the repository's work each time.
    h.fake
        .locked()
        .tags_fail
        .insert(PROD.to_owned(), server_error());

    h.tick().await;
    assert_eq!(h.deploys(STAGING).await, []);

    h.clock.advance(BACKOFF_START_SECS);
    h.tick().await;
    assert_eq!(h.deploys(STAGING).await.len(), 1);
}

#[tokio::test]
async fn unreadable_tag_list_fails_closed() {
    let cases: [(MakeError, &str); 2] =
        [(server_error(), "502"), (list_cap(), "goes on past 5000")];
    for (fail, expected) in cases {
        let h = Harness::running("v1.2.3").await;
        h.fake.tags(PROD, &["v1.2.4"]);
        h.fake
            .locked()
            .attested_fails
            .insert("v1.2.4".to_owned(), fail);

        h.tick().await;

        assert_eq!(h.deploys(PROD).await, [], "{expected}");
        let held = h.hold_reason(PROD, "v1.2.4").await.unwrap();
        assert!(held.contains(expected), "{held}");
        assert_eq!(h.decided_count().await, 0, "nothing without the list");
    }
}

#[tokio::test]
async fn transient_failure_retries() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.4".to_owned(), no_bundle("v1.2.4"));

    h.tick().await;
    h.clock.advance(300);
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 2);
    assert_eq!(h.deploys(PROD).await, []);
    let held = h.hold_reason(PROD, "v1.2.4").await.unwrap();
    assert!(held.contains("attestation bundle"), "{held}");
    assert_eq!(
        h.audit("release_held").await.len(),
        2,
        "this and other/prod"
    );
    assert_eq!(h.decided_count().await, 0);

    // The bundle arrives.
    h.fake.locked().verify_fails.clear();
    h.clock.advance(300);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await.len(), 1);
    assert_eq!(h.hold_reason(PROD, "v1.2.4").await, None);
}

#[tokio::test]
async fn a_release_that_keeps_failing_is_tried_less_often() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.4".to_owned(), no_bundle("v1.2.4"));

    h.tick().await;
    assert_eq!(h.fake.verify_count(), 1);
    h.clock.advance(EAGER_RETRY_SECS + 1);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 2);
    h.clock.advance(300);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 2, "tried too soon");
    h.clock.advance(SLOW_RETRY_SECS);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 3);
}

#[tokio::test]
async fn a_rate_limit_backs_off_its_repository_alone_until_the_reset() {
    let h = Harness::running("v1.2.3").await;
    h.report(OTHER, "host-b", Some("v1.0.0")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.tags(OTHER, &["v1.0.1"]);
    let reset = jiff::Timestamp::from_second(1_800_000_000 + 1000).unwrap();
    h.fake
        .locked()
        .tags_fail
        .insert(PROD.to_owned(), rate_limited(RateLimitReset::At(reset)));

    let first = h.tick().await;
    assert_eq!(h.deploys(OTHER).await.len(), 1, "the other goes on");
    assert_eq!(first.backed_off, 0);
    let reason = h.hold_reason(PROD, "").await.unwrap();
    assert!(reason.contains("rate limited"), "{reason}");
    let lists_of_both = h.fake.tag_lists.load(Ordering::SeqCst);

    // Before the reset, its repository is not asked at all.
    h.clock.advance(999);
    let waiting = h.tick().await;
    assert_eq!(waiting.backed_off, 1);
    // Only the other repository was asked.
    assert_eq!(h.fake.tag_lists.load(Ordering::SeqCst), lists_of_both + 1);

    // At the reset it is, and the hold goes.
    h.fake.locked().tags_fail.clear();
    h.clock.advance(1);
    assert_eq!(h.tick().await.queued.len(), 1);
    assert_eq!(h.hold_reason(PROD, "").await, None);
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_rate_limit_during_verification_stops_the_repository_for_this_tick() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4", "v1.2.5"]);
    h.fake.locked().verify_fails.insert(
        "v1.2.5".to_owned(),
        rate_limited(RateLimitReset::After(1000)),
    );

    h.tick().await;
    assert_eq!(h.fake.verify_count(), 1, "the rest waits");
    h.clock.advance(999);
    assert_eq!(h.tick().await.backed_off, 1);
    assert_eq!(h.fake.verify_count(), 1);
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn a_rate_limit_among_old_tags_does_not_hold_up_a_new_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.2", "v1.2.4"]);
    h.fake.locked().verify_fails.insert(
        "v1.2.2".to_owned(),
        rate_limited(RateLimitReset::After(1000)),
    );

    assert_eq!(h.tick().await.queued.len(), 1);
    assert_eq!(h.deploys(PROD).await[0].0, "v1.2.4");
    // Its repository waits all the same.
    assert_eq!(h.tick().await.backed_off, 1);
}

#[test]
fn a_servers_word_on_a_rate_limit_is_bounded() {
    let state = WatcherState::default();
    state.rate_limited(1, RateLimitReset::After(u64::MAX), 1000);
    assert!(state.is_waiting(1, 1000 + RATE_LIMIT_MAX_SECS - 1));
    assert!(!state.is_waiting(1, 1000 + RATE_LIMIT_MAX_SECS));

    // A reset already past still waits a moment rather than hammering.
    let past = jiff::Timestamp::from_second(10).unwrap();
    state.rate_limited(2, RateLimitReset::At(past), 1000);
    assert!(state.is_waiting(2, 1000));
    assert!(!state.is_waiting(2, 1001));

    state.rate_limited(3, RateLimitReset::Unknown, 1000);
    assert!(state.is_waiting(3, 1000 + BACKOFF_START_SECS - 1));
}

#[test]
fn failures_wait_longer_up_to_a_limit_and_success_resets() {
    let state = WatcherState::default();
    let wait_after = |now: i64| {
        (now..)
            .step_by(60)
            .find(|at| !state.is_waiting(1, *at))
            .unwrap()
            - now
    };
    state.failed(1, 0);
    assert_eq!(wait_after(0), BACKOFF_START_SECS);
    state.failed(1, 0);
    assert_eq!(wait_after(0), 2 * BACKOFF_START_SECS);
    for _ in 0..100 {
        state.failed(1, 0);
    }
    assert_eq!(wait_after(0), BACKOFF_MAX_SECS);
    state.succeeded(1);
    assert!(!state.is_waiting(1, 0));
    state.failed(1, 0);
    assert_eq!(wait_after(0), BACKOFF_START_SECS);
}

#[tokio::test]
async fn an_outage_backs_its_repository_off_and_is_recorded_once() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .tags_fail
        .insert(PROD.to_owned(), server_error());

    h.tick().await;
    let held = h.hold_reason(PROD, "").await.unwrap();
    assert!(held.contains("502"), "{held}");
    let waiting = h.tick().await;
    assert_eq!(waiting.backed_off, 1);
    h.clock.advance(BACKOFF_START_SECS);
    h.tick().await;
    let audited = h.audit("release_held").await;
    let of_prod = audited
        .iter()
        .filter(|d| d["reason"].to_string().contains("release listing"));
    assert_eq!(of_prod.count(), 1, "{audited:?}");
}

#[tokio::test]
async fn a_panic_in_one_repository_does_not_stop_the_others() {
    let h = Harness::running("v1.2.3").await;
    h.report(OTHER, "host-b", Some("v1.0.0")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.locked().tags_panic.insert(OTHER.to_owned());

    let summary = h.tick().await;

    assert_eq!(summary.failed, 1);
    assert_eq!(summary.queued.len(), 1);
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_repository_that_hangs_does_not_stop_the_others_and_backs_off() {
    let mut h = Harness::running("v1.2.3").await;
    h.state = Arc::new(WatcherState::with_deadline(Duration::from_millis(100)));
    h.report(OTHER, "host-b", Some("v1.0.0")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.locked().tags_hang.insert(OTHER.to_owned());

    let summary = tokio::time::timeout(Duration::from_secs(10), h.tick())
        .await
        .expect("the tick should end");

    assert_eq!(summary.failed, 1);
    assert_eq!(h.deploys(PROD).await.len(), 1);
    assert_eq!(h.tick().await.backed_off, 1);
}

#[tokio::test]
async fn a_trust_root_that_is_gone_fails_closed_and_says_why_once() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.locked().prepare_fails = Some("the trust root is unavailable: expired".to_owned());

    h.tick().await;
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 0);
    assert_eq!(h.deploys(PROD).await, []);
    let reason = h.hold_reason(PROD, "").await.unwrap();
    assert!(reason.contains("trust root"), "{reason}");
    let reasons = h.audit("release_held").await;
    assert_eq!(reasons.len(), 2, "both deployments, once: {reasons:?}");

    // Back, the hold goes and the release moves.
    h.fake.locked().prepare_fails = None;
    h.tick().await;
    assert_eq!(h.hold_reason(PROD, "").await, None);
    assert_eq!(h.deploys(PROD).await.len(), 1);
}
