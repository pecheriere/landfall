//! Getting an open request out of the way: by cancelling it, or by a rollback.

use axum::http::{Method, StatusCode};
use landfall_core::protocol::Phase;
use serde_json::json;

use super::{APPROVALS, Answer, Caller, HOST, Harness, PROD, digest, request_of};

impl Harness {
    async fn cancel(&self, id: i64, caller: &Caller) -> Answer {
        let path = format!("{APPROVALS}/{id}/cancel");
        self.call(Method::POST, &path, caller, Vec::new()).await
    }

    /// `carol` asks for `v1.1.0`, and this gives the request's number.
    async fn asked_by_carol(&self) -> i64 {
        let answer = self.ask(&self.token("carol").await, "v1.1.0").await;
        assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
        request_of(&answer.json()).0
    }
}

#[tokio::test]
async fn the_asker_an_approver_or_a_rollback_holder_can_cancel() {
    let h = Harness::new().await;
    h.ready().await;
    let cancellers = [
        h.token("carol").await,
        h.session("alice").await,
        h.session("bob").await,
        h.token("erin").await,
    ];
    for caller in &cancellers {
        let id = h.asked_by_carol().await;
        let answer = h.cancel(id, caller).await;
        assert_eq!(answer.status, StatusCode::OK, "{caller:?}: {answer:?}");
        assert_eq!(
            answer.json(),
            json!({ "request": id, "state": "cancelled" })
        );
        assert_eq!(h.request_state(id).await, "cancelled");
    }
    let rows = h.audited("request_cancelled").await;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["by"]["principal"], "carol");
    assert_eq!(rows[1]["by"]["principal"], "alice");
    assert_eq!(rows[1]["by"]["via"], "session");
    assert_eq!(rows[3]["by"]["via"], "token");
    assert!(
        rows[1]["reason"].as_str().unwrap().contains("alice"),
        "{}",
        rows[1]
    );
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test]
async fn nobody_else_can_cancel_and_each_try_is_audited() {
    let h = Harness::new().await;
    h.ready().await;
    let id = h.asked_by_carol().await;
    // They see it and may not.
    for caller in [h.token("dave").await, h.token("alice").await] {
        let answer = h.cancel(id, &caller).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{caller:?}");
        assert_eq!(answer.code(), "forbidden", "{caller:?}");
    }
    // No grant here: as if it weren't there, and the same for one that isn't.
    let otto = h.token("otto").await;
    let hidden = h.cancel(id, &otto).await;
    let absent = h.cancel(id + 1, &otto).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.status, hidden.status);
    assert_eq!(absent.body, hidden.body);

    assert_eq!(
        h.cancel(id, &Caller::Nobody).await.code(),
        "unauthenticated"
    );
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.audited("request_cancelled").await.len(), 0);
    let rows = h.audited("cancel_refused").await;
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[0]["by"]["principal"], "dave");
    assert_eq!(rows[0]["request"], id);
}

#[tokio::test]
async fn a_session_cancels_only_from_the_exact_origin() {
    let h = Harness::new().await;
    h.ready().await;
    let id = h.asked_by_carol().await;
    let session = h
        .store
        .begin_session_for_test("alice", 3600)
        .await
        .reveal_for_test();
    let evil = Caller::SessionFrom(session, Some("https://evil.example".to_owned()));
    assert_eq!(h.cancel(id, &evil).await.code(), "bad_origin");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}

#[tokio::test]
async fn a_cancelled_request_is_over_and_the_next_can_be_made() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    assert_eq!(h.cancel(id, &alice).await.status, StatusCode::OK);

    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "request_cancelled");
    assert_eq!(h.cancel(id, &alice).await.code(), "request_cancelled");
    assert_eq!(h.count_deploys().await, 0);
    assert_eq!(h.list(&alice).await.json()["approvals"], json!([]));
    // A report that moves what runs finds nothing to say about it.
    h.reports(Some(("v1.0.1", '2'))).await;
    assert_eq!(h.request_state(id).await, "cancelled");
    assert_eq!(h.audited("request_stale").await.len(), 0);

    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(asked.status, StatusCode::CREATED, "{asked:?}");
    assert_ne!(request_of(&asked.json()).1.nonce, intent.nonce);
}

#[tokio::test]
async fn only_an_open_request_can_be_cancelled() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    assert_eq!(
        h.approve(id, &alice, &h.keys.alice, &intent).await.status,
        StatusCode::OK
    );
    assert_eq!(h.cancel(id, &alice).await.code(), "request_closed");
    assert_eq!(h.request_state(id).await, "approved");
}

#[tokio::test]
async fn a_revoked_tokens_open_request_stays_until_someone_cancels_it() {
    let h = Harness::new().await;
    h.ready().await;
    let (token_id, token) = h
        .store
        .create_token(&"carol".parse().unwrap())
        .await
        .unwrap();
    let asked = h.ask(&Caller::Token(token.reveal()), "v1.1.0").await;
    let (id, _) = request_of(&asked.json());
    h.store.revoke_token(token_id).await.unwrap();

    let alice = h.token("alice").await;
    assert_eq!(h.ask(&alice, "v1.1.0").await.code(), "request_open");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    let bob = h.session("bob").await;
    assert_eq!(h.cancel(id, &bob).await.status, StatusCode::OK);
    assert_eq!(h.ask(&alice, "v1.1.0").await.status, StatusCode::CREATED);
}

/// `app/prod` runs `v1.1.0`, `v1.0.0` is there to go back to, and `carol` asked for `v1.2.0`.
async fn rollback_stage(h: &Harness) -> i64 {
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;
    let answer = h.ask(&h.token("carol").await, "v1.2.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    request_of(&answer.json()).0
}

#[tokio::test]
async fn a_rollback_supersedes_an_open_request() {
    let h = Harness::new().await;
    let open = rollback_stage(&h).await;
    let answer = h.ask(&h.token("erin").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (id, intent) = request_of(&answer.json());
    assert_eq!(intent.expected_running, Some(digest('1')));
    assert_eq!(h.request_state(open).await, "cancelled");
    assert_eq!(h.request_state(id).await, "awaiting_approval");

    let rows = h.audited("request_cancelled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["request"], open);
    assert_eq!(rows[0]["by"]["principal"], "erin");
    let reason = rows[0]["reason"].as_str().unwrap();
    assert!(
        reason.contains("rollback") && reason.contains("v1.0.0"),
        "{reason}"
    );
}

#[tokio::test]
async fn nothing_else_supersedes_an_open_request() {
    let h = Harness::new().await;
    let open = rollback_stage(&h).await;
    // A higher release, even from someone who can approve, or can both ask and roll back.
    h.verified(PROD, HOST, "v1.3.0", '3').await;
    for name in ["alice", "frank"] {
        assert_eq!(
            h.ask(&h.token(name).await, "v1.3.0").await.code(),
            "request_open",
            "{name}"
        );
    }
    // A lower one, from someone without the rollback grant.
    assert_eq!(
        h.ask(&h.token("carol").await, "v1.0.0").await.code(),
        "request_open"
    );
    assert_eq!(h.request_state(open).await, "awaiting_approval");
}

#[tokio::test]
async fn cancelling_one_past_its_time_finds_it_expired() {
    let h = Harness::new().await;
    h.ready().await;
    let id = h.asked_by_carol().await;
    h.clock.advance(crate::store::REQUEST_LIFETIME_SECS);
    let answer = h.cancel(id, &h.token("carol").await).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "request_expired");
    assert_eq!(h.request_state(id).await, "expired");
    assert_eq!(h.audited("request_expired").await.len(), 1);
    assert_eq!(h.audited("request_cancelled").await.len(), 0);
}

#[tokio::test]
async fn a_rollback_that_is_itself_refused_leaves_the_open_request_alone() {
    let h = Harness::new().await;
    let open = rollback_stage(&h).await;
    let erin = h.token("erin").await;
    h.reports_state(Some(("v1.1.0", '1')), true, Phase::Idle, false)
        .await;
    assert_eq!(h.ask(&erin, "v1.0.0").await.code(), "host_not_ready");
    assert_eq!(h.request_state(open).await, "awaiting_approval");
    assert_eq!(h.audited("request_cancelled").await.len(), 0);
}
