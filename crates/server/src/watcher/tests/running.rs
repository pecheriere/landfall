//! How the work runs: what it holds, how much it takes on, and stopping.

use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tokio::sync::watch;

use super::super::{TICK_INTERVAL, VERIFICATIONS_PER_TICK, run};
use super::{HOST, Harness, PATCH_RULE, PROD, config_text};

#[tokio::test]
async fn a_tick_ends_a_request_past_its_time_with_its_audit_row() {
    let h = Harness::running("v1.2.3").await;
    for statement in [
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', 'v1.3.0', 'manual', 'why', 0)",
        "INSERT INTO deploy_requests
             (deployment, host, tag, commit_sha, digest, nonce, state, requested_by, created_at,
              expires_at)
         VALUES ('app/prod', 'host-a', 'v1.3.0', '0000000000000000000000000000000000000000',
                 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                 zeroblob(32), 'awaiting_approval', 'someone', 0, 1)",
    ] {
        sqlx::query(statement)
            .execute(h.store.pool())
            .await
            .unwrap();
    }
    assert_eq!(h.audit("request_expired").await.len(), 0);
    h.tick().await;
    let state: String = sqlx::query_scalar("SELECT state FROM deploy_requests")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "expired");
    assert_eq!(h.audit("request_expired").await.len(), 1);
    // Once.
    h.tick().await;
    assert_eq!(h.audit("request_expired").await.len(), 1);
    h.chain_is_intact().await;
}

#[tokio::test]
async fn no_database_connection_is_held_across_the_network() {
    let h = Harness::running("v1.2.3").await;
    // The store under test has one connection, so anything holding a transaction
    // or a connection across a call to the source fails this.
    h.fake.locked().store = Some(h.store.clone());
    h.fake.tags(PROD, &["v1.2.2", "v1.2.4"]);

    let summary = h.tick().await;
    assert_eq!(summary.failed, 0, "{summary:?}");
    assert_eq!(summary.queued.len(), 1);

    // Again with a release verified earlier, which is enumerated again just
    // before it is queued.
    let h = Harness::running("v1.2.3").await;
    h.report_busy(PROD, HOST, "v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.fake.locked().store = Some(h.store.clone());
    let summary = h.tick().await;
    assert_eq!(summary.failed, 0, "{summary:?}");
    assert_eq!(summary.queued.len(), 1);
}

#[tokio::test]
async fn a_long_history_is_spread_over_ticks_newest_first() {
    let h = Harness::new(&config_text(PATCH_RULE)).await;
    h.report(PROD, HOST, None).await;
    let tags: Vec<String> = (0..VERIFICATIONS_PER_TICK + 3)
        .map(|n| format!("v1.0.{n}"))
        .collect();
    let refs: Vec<&str> = tags.iter().map(String::as_str).collect();
    h.fake.tags(PROD, &refs);

    let first = h.tick().await;
    assert_eq!(h.fake.verify_count(), VERIFICATIONS_PER_TICK);
    assert_eq!(first.deferred, 3);
    let newest = format!("v1.0.{}", VERIFICATIONS_PER_TICK + 2);
    assert_eq!(h.fake.verifies.lock().unwrap()[0], newest);

    let second = h.tick().await;
    assert_eq!(second.deferred, 0);
    assert_eq!(h.fake.verify_count(), VERIFICATIONS_PER_TICK + 3);
}

#[tokio::test]
async fn run_goes_on_after_a_panic_and_stops_when_told() {
    let h = Harness::running("v1.2.3").await;
    h.fake.locked().prepare_panics = true;
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(run(
        h.store.clone(),
        Arc::clone(&h.config),
        Arc::clone(&h.fake),
        Duration::from_millis(1),
        stopped,
    ));

    for _ in 0..200 {
        if h.fake.prepares.load(Ordering::SeqCst) >= 3 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert!(h.fake.prepares.load(Ordering::SeqCst) >= 3);

    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stopping should not hang")
        .unwrap();
}

#[tokio::test]
async fn stopping_lets_go_of_work_in_flight() {
    let h = Harness::running("v1.2.3").await;
    h.fake.locked().tags_hang.insert(PROD.to_owned());
    let (stop, stopped) = watch::channel(false);
    let task = tokio::spawn(run(
        h.store.clone(),
        Arc::clone(&h.config),
        Arc::clone(&h.fake),
        TICK_INTERVAL,
        stopped,
    ));
    tokio::time::sleep(Duration::from_millis(50)).await;

    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stopping should not wait for the network")
        .unwrap();
}
