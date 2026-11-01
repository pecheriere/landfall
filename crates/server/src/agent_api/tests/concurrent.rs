//! Races, with real threads on a real file: the in-memory store has one
//! connection, so it cannot have any.

use std::sync::Arc;

use axum::http::StatusCode;
use landfall_core::protocol::{DeployId, DeployReportBody, WorkRequest};
use tempfile::TempDir;
use tokio::task::JoinSet;

use super::{
    Answer, Harness, REPORT, WORK, deployed_report, signed_request, signing_key, test_limits,
};
use crate::store::Store;

const WRITERS: u8 = 8;

async fn harness() -> (TempDir, Arc<Harness>) {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let harness = Harness::on_store(store, test_limits());
    (dir, Arc::new(harness))
}

/// Every task's answer, once they have all finished.
async fn answers(mut tasks: JoinSet<Answer>) -> Vec<Answer> {
    let mut answers = Vec::new();
    while let Some(answer) = tasks.join_next().await {
        answers.push(answer.unwrap());
    }
    answers
}

fn count(kinds: &[String], kind: &str) -> usize {
    kinds.iter().filter(|k| *k == kind).count()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_code_enrols_one_key_however_many_race_for_it() {
    let (_dir, h) = harness().await;
    let code = h.code("host-a", false).await;

    let mut tasks = JoinSet::new();
    for seed in 1..=WRITERS {
        let (h, code) = (Arc::clone(&h), code.clone());
        tasks.spawn(async move { h.enrol_with("host-a", &signing_key(seed), code).await });
    }
    let answers = answers(tasks).await;

    let won = answers
        .iter()
        .filter(|a| a.status == StatusCode::NO_CONTENT)
        .count();
    assert_eq!(won, 1, "{answers:?}");
    for answer in answers
        .iter()
        .filter(|a| a.status != StatusCode::NO_CONTENT)
    {
        assert_eq!(answer.code(), "invalid_code");
    }
    assert_eq!(h.count("hosts").await, 1);
    assert_eq!(count(&h.audit_kinds().await, "host_enrolled"), 1);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

/// A claimed deploy, with the agent's key.
async fn queued_on_host_a(h: &Harness) -> (landfall_core::protocol::SigningKey, DeployId) {
    let key = h.enrolled("host-a", 1).await;
    let id = h.queue("app/prod", "host-a", "v1.0.1").await;
    (key, id)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_polls_claim_a_deploy_once() {
    let (_dir, h) = harness().await;
    let (key, id) = queued_on_host_a(&h).await;
    let body = serde_json::to_vec(&WorkRequest {
        config_hash: h.config_hash,
        running: Vec::new(),
    })
    .unwrap();

    let mut tasks = JoinSet::new();
    for _ in 0..WRITERS {
        let nonce = h.nonce().await;
        let request = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
        let h = Arc::clone(&h);
        tasks.spawn(async move { h.send(request).await });
    }
    for answer in answers(tasks).await {
        // Whoever is first takes it. A poll that a later one superseded before
        // it looked may be empty; none gets anything else.
        if let Some(work) = answer.work().work {
            assert_eq!(work.deploy_id, id);
        }
    }
    assert_eq!(count(&h.audit_kinds().await, "deploy_claimed"), 1);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn racing_reports_finish_a_deploy_once() {
    let (_dir, h) = harness().await;
    let (key, id) = queued_on_host_a(&h).await;
    assert!(
        h.work("host-a", &key, Vec::new())
            .await
            .work()
            .work
            .is_some()
    );

    let report: DeployReportBody = deployed_report(id);
    let body = serde_json::to_vec(&report).unwrap();
    let mut tasks = JoinSet::new();
    for _ in 0..WRITERS {
        let nonce = h.nonce().await;
        let request = signed_request("host-a", &key, REPORT, REPORT, &nonce, body.clone());
        let h = Arc::clone(&h);
        tasks.spawn(async move { h.send(request).await });
    }
    for answer in answers(tasks).await {
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");
    }
    assert_eq!(count(&h.audit_kinds().await, "deploy_finished"), 1);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}
