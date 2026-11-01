use std::time::{Duration, Instant};

use axum::http::StatusCode;
use landfall_core::protocol::{DeployedRelease, Phase, RunningState, WorkRequest};
use sqlx::Row as _;

use super::{Harness, WORK, deployed_report, test_limits};
use crate::agent_api::Limits;

const A: &str = "host-a";
const B: &str = "host-b";

fn running(deployment: &str, drift: bool) -> RunningState {
    RunningState {
        deployment: deployment.parse().unwrap(),
        deployed: Some(DeployedRelease {
            tag: "v1.0.0".parse().unwrap(),
            digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
        }),
        drift,
        phase: Phase::Idle,
        busy: false,
    }
}

#[tokio::test]
async fn host_sees_only_its_own_work() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let b = h.enrolled(B, 2).await;
    let id = h.queue("other/prod", B, "v1.0.1").await;

    // Host A polls, however it asks: nothing of B's is given to it or claimed.
    let answer = h
        .work(A, &a, vec![running("other/prod", false)])
        .await
        .work();
    assert_eq!(answer.work, None);
    assert_eq!(answer.held_back, []);
    let state: String = sqlx::query_scalar("SELECT state FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "queued");

    // Host B is given it.
    let work = h.work(B, &b, Vec::new()).await.work().work.unwrap();
    assert_eq!(work.deploy_id, id);
    assert_eq!(work.deployment.as_ref(), "other/prod");
    assert_eq!(work.tag.as_ref(), "v1.0.1");
}

#[tokio::test]
async fn config_hash_mismatch_gives_no_work_and_says_why() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    h.queue("app/prod", A, "v1.0.1").await;
    let wrong = WorkRequest {
        config_hash: [9; 32],
        running: Vec::new(),
    };

    let answer = h.signed_post(A, &a, WORK, &wrong).await.work();
    assert_eq!(answer.work, None);
    assert_eq!(answer.held_back.len(), 1, "{answer:?}");
    assert_eq!(answer.held_back[0].deployment.as_ref(), "app/prod");
    assert!(
        answer.held_back[0].reason.contains("configuration"),
        "{answer:?}"
    );
    // It was not claimed.
    let state: String = sqlx::query_scalar("SELECT state FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "queued");

    // Recorded, once, however often the host polls.
    h.signed_post(A, &a, WORK, &wrong).await;
    let drift = |kinds: Vec<String>| kinds.iter().filter(|k| *k == "config_drift").count();
    assert_eq!(drift(h.audit_kinds().await), 1);
    assert_eq!(
        h.last_config_drift().await["reported_hash"],
        hex::encode([9; 32])
    );

    // A different wrong hash is news.
    let other = WorkRequest {
        config_hash: [8; 32],
        running: Vec::new(),
    };
    h.signed_post(A, &a, WORK, &other).await;
    assert_eq!(drift(h.audit_kinds().await), 2);

    // Once it matches again that is recorded too, and work flows.
    let work = h.work(A, &a, Vec::new()).await.work();
    assert!(work.work.is_some());
    assert_eq!(drift(h.audit_kinds().await), 3);
    assert_eq!(h.last_config_drift().await["drifted"], false);
}

#[tokio::test]
async fn a_mismatched_host_with_nothing_queued_is_still_told() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let wrong = WorkRequest {
        config_hash: [9; 32],
        running: vec![running("app/unknown", false)],
    };
    let answer = h.signed_post(A, &a, WORK, &wrong).await.work();
    let names: Vec<&str> = answer
        .held_back
        .iter()
        .map(|held| held.deployment.as_ref())
        .collect();
    assert_eq!(names, ["app/prod", "app/unknown"]);
}

#[tokio::test]
async fn work_long_poll_returns_when_work_arrives() {
    let h = Harness::with_limits(Limits {
        long_poll: Duration::from_secs(30),
        ..test_limits()
    })
    .await;
    let a = h.enrolled(A, 1).await;

    let poll = h.work(A, &a, Vec::new());
    let queue = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.queue("app/prod", A, "v1.0.1").await
    };
    let (answer, id) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(poll, queue) })
            .await
            .expect("the poll should end as soon as work is queued");
    assert_eq!(answer.work().work.unwrap().deploy_id, id);
}

#[tokio::test]
async fn work_queued_before_the_poll_is_answered_at_once() {
    let h = Harness::with_limits(Limits {
        long_poll: Duration::from_secs(30),
        ..test_limits()
    })
    .await;
    let a = h.enrolled(A, 1).await;
    let id = h.queue("app/prod", A, "v1.0.1").await;
    let answer = tokio::time::timeout(Duration::from_secs(5), h.work(A, &a, Vec::new()))
        .await
        .unwrap();
    assert_eq!(answer.work().work.unwrap().deploy_id, id);
}

#[tokio::test]
async fn work_for_another_host_does_not_end_a_poll_early() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let started = Instant::now();
    let poll = h.work(A, &a, Vec::new());
    let queue = async {
        tokio::time::sleep(Duration::from_millis(10)).await;
        h.queue("other/prod", B, "v1.0.1").await
    };
    let (answer, _) = tokio::join!(poll, queue);
    assert_eq!(answer.work().work, None);
    assert!(started.elapsed() >= test_limits().long_poll);
}

#[tokio::test]
async fn work_long_poll_times_out_empty() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let started = Instant::now();
    let answer = h.work(A, &a, Vec::new()).await.work();
    assert_eq!(answer.work, None);
    assert_eq!(answer.held_back, []);
    assert!(started.elapsed() >= test_limits().long_poll);
}

#[tokio::test]
async fn shutting_down_ends_a_long_poll_at_once() {
    let h = Harness::with_limits(Limits {
        long_poll: Duration::from_secs(30),
        ..test_limits()
    })
    .await;
    let a = h.enrolled(A, 1).await;
    let poll = h.work(A, &a, Vec::new());
    let stop = async {
        tokio::time::sleep(Duration::from_millis(50)).await;
        h.state.begin_shutdown();
    };
    let (answer, ()) =
        tokio::time::timeout(Duration::from_secs(5), async { tokio::join!(poll, stop) })
            .await
            .unwrap();
    assert_eq!(answer.work().work, None);
}

#[tokio::test]
async fn claimed_work_is_redelivered_after_a_reconnect() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let id = h.queue("app/prod", A, "v1.0.1").await;

    let first = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(first.deploy_id, id);
    let claimed = h.audit_kinds().await;
    assert_eq!(claimed.iter().filter(|k| *k == "deploy_claimed").count(), 1);

    // The agent crashed before acting on it, and asks again.
    let second = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(second, first);
    // Nothing changed, so nothing new is recorded.
    assert_eq!(h.audit_kinds().await, claimed);
}

#[tokio::test]
async fn one_deploy_at_a_time_per_host() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let first = h.queue("app/prod", A, "v1.0.1").await;
    let second = h.queue("app/stage", A, "v2.0.1").await;

    let work = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(work.deploy_id, first);
    let again = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(again.deploy_id, first);

    assert_eq!(
        h.report(A, &a, &deployed_report(first)).await.status,
        StatusCode::NO_CONTENT
    );
    let next = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(next.deploy_id, second);
}

#[tokio::test]
async fn a_drifted_deployment_is_held_back_until_it_clears() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    h.queue("app/prod", A, "v1.0.1").await;

    let answer = h.work(A, &a, vec![running("app/prod", true)]).await.work();
    assert_eq!(answer.work, None);
    assert_eq!(answer.held_back.len(), 1);
    assert!(answer.held_back[0].reason.contains("differs"), "{answer:?}");

    let answer = h.work(A, &a, vec![running("app/prod", false)]).await.work();
    assert!(answer.work.is_some());
    assert_eq!(answer.held_back, []);
}

#[tokio::test]
async fn running_state_is_stored_and_changes_are_audited_once() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let base = h.audit_kinds().await.len();
    let tail = |kinds: Vec<String>| kinds[base..].to_vec();

    h.work(A, &a, vec![running("app/prod", false)]).await;
    assert_eq!(tail(h.audit_kinds().await), ["running_changed"]);
    h.work(A, &a, vec![running("app/prod", false)]).await;
    assert_eq!(tail(h.audit_kinds().await), ["running_changed"]);

    h.work(A, &a, vec![running("app/prod", true)]).await;
    h.work(A, &a, vec![running("app/prod", true)]).await;
    assert_eq!(
        tail(h.audit_kinds().await),
        ["running_changed", "running_drift"]
    );

    // Phase and busy move during a deploy: stored, not audited.
    let mut deploying = running("app/prod", true);
    deploying.phase = Phase::Deploying;
    deploying.busy = true;
    h.work(A, &a, vec![deploying]).await;
    assert_eq!(
        tail(h.audit_kinds().await),
        ["running_changed", "running_drift"]
    );
    let row = sqlx::query("SELECT * FROM running_states")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("host"), A);
    assert_eq!(row.get::<String, _>("tag"), "v1.0.0");
    assert_eq!(row.get::<String, _>("phase"), "deploying");
    assert!(row.get::<bool, _>("busy"));
    assert!(row.get::<bool, _>("drift"));
}

#[tokio::test]
async fn a_host_cannot_state_another_hosts_deployment() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let b = h.enrolled(B, 2).await;
    let id = h.queue("other/prod", B, "v1.0.1").await;

    // Host A says B's deployment has drifted, which would hold B's deploy back
    // if it were believed. Only what it says about its own is kept.
    let answer = h
        .work(
            A,
            &a,
            vec![
                running("other/prod", true),
                running("nothing/here", true),
                running("app/prod", false),
            ],
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK);
    let stored: Vec<String> = sqlx::query_scalar("SELECT deployment FROM running_states")
        .fetch_all(h.store.pool())
        .await
        .unwrap();
    assert_eq!(stored, ["app/prod"]);

    let work = h.work(B, &b, Vec::new()).await.work().work.unwrap();
    assert_eq!(work.deploy_id, id);
}

#[tokio::test]
async fn repeating_a_deployment_cannot_flood_the_log() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let base = h.audit_kinds().await.len();
    // Flipping on every entry would write a row each, if each were looked at.
    let flapping: Vec<RunningState> = (0..200).map(|n| running("app/prod", n % 2 == 0)).collect();
    h.work(A, &a, flapping).await;
    assert!(h.audit_kinds().await.len() - base <= 2);
}
