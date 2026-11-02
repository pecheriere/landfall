//! Racing against itself, on a real file with real connections.

use axum::http::StatusCode;
use landfall_core::intent::DeployIntent;

use super::{Answer, Harness};
use crate::store::Store;

/// A harness on a file, so that writers really do meet.
async fn on_a_file(dir: &tempfile::TempDir) -> Harness {
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    Harness::on(store, "")
}

fn wins(answers: &[Answer]) -> usize {
    answers
        .iter()
        .filter(|answer| answer.status == StatusCode::OK)
        .count()
}

async fn approve_at_once(h: &Harness, id: i64, intent: &DeployIntent) -> Vec<Answer> {
    let alice = h.session("alice").await;
    let bob = h.session("bob").await;
    let answers = tokio::join!(
        h.approve(id, &alice, &h.keys.alice, intent),
        h.approve(id, &bob, &h.keys.bob, intent),
        h.approve(id, &alice, &h.keys.alice, intent),
        h.approve(id, &bob, &h.keys.bob, intent),
    );
    vec![answers.0, answers.1, answers.2, answers.3]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_approvers_at_once_queue_one_deploy() {
    let dir = tempfile::tempdir().unwrap();
    let h = on_a_file(&dir).await;
    let (id, intent) = h.opened().await;
    let answers = approve_at_once(&h, id, &intent).await;
    assert_eq!(wins(&answers), 1, "{answers:?}");
    for answer in answers.iter().filter(|a| a.status != StatusCode::OK) {
        assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
        assert_eq!(answer.code(), "request_closed");
    }
    assert_eq!(h.count_deploys().await, 1);
    assert_eq!(h.audited("request_approved").await.len(), 1);
    assert_eq!(h.audited("approval_refused").await.len(), 3);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_report_and_approvals_at_once_go_one_way_or_the_other() {
    let dir = tempfile::tempdir().unwrap();
    let h = on_a_file(&dir).await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    let (answer, ()) = tokio::join!(
        h.approve(id, &alice, &h.keys.alice, &intent),
        h.reports(Some(("v1.0.1", '2'))),
    );
    if answer.status == StatusCode::OK {
        // It came first: the report finds nothing open, and the host has the last word.
        assert_eq!(h.request_state(id).await, "approved");
        assert_eq!(h.count_deploys().await, 1);
    } else {
        assert_eq!(answer.code(), "request_stale");
        assert_eq!(h.request_state(id).await, "stale");
        assert_eq!(h.count_deploys().await, 0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn requests_at_once_open_one() {
    let dir = tempfile::tempdir().unwrap();
    let h = on_a_file(&dir).await;
    h.ready().await;
    let carol = h.token("carol").await;
    let alice = h.token("alice").await;
    let (a, b, c) = tokio::join!(
        h.ask(&carol, "v1.1.0"),
        h.ask(&alice, "v1.1.0"),
        h.ask(&carol, "v1.1.0"),
    );
    let answers = [a, b, c];
    let opened = answers
        .iter()
        .filter(|a| a.status == StatusCode::CREATED)
        .count();
    assert_eq!(opened, 1, "{answers:?}");
    for answer in answers.iter().filter(|a| a.status != StatusCode::CREATED) {
        assert_eq!(answer.code(), "request_open");
    }
}
