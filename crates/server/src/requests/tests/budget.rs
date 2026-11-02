//! What a principal's state changes cost, and that going over says so afterwards.

use axum::http::{Method, StatusCode, header};

use super::{Harness, PROD_REQUESTS};

/// How many of `count` calls refused for want of a grant got which answer.
async fn refused_calls(h: &Harness, name: &str, count: usize) -> (usize, usize) {
    let caller = h.token(name).await;
    let (mut refused, mut over) = (0, 0);
    for _ in 0..count {
        let answer = h
            .call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
            .await;
        match answer.status {
            StatusCode::NOT_FOUND | StatusCode::FORBIDDEN => refused += 1,
            StatusCode::TOO_MANY_REQUESTS => {
                assert_eq!(answer.code(), "rate_limited");
                assert!(answer.headers.contains_key(header::RETRY_AFTER));
                over += 1;
            }
            other => panic!("{other}: {answer:?}"),
        }
    }
    (refused, over)
}

#[tokio::test]
async fn a_thousand_refused_calls_leave_a_bounded_log_and_a_count_of_the_rest() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    let (refused, over) = refused_calls(&h, "otto", 1000).await;
    assert_eq!(refused, burst);
    assert_eq!(over, 1000 - burst);
    assert_eq!(h.audited("request_refused").await.len(), burst);
    // Nothing is said until it can be heard.
    assert_eq!(h.audited("access_throttled").await.len(), 0);

    h.clock.advance(10);
    let (refused, over) = refused_calls(&h, "otto", 1).await;
    assert_eq!((refused, over), (1, 0));
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["by"]["principal"], "otto");
    assert_eq!(rows[0]["dropped"], 1000 - burst);

    // Said once.
    refused_calls(&h, "otto", 1).await;
    assert_eq!(h.audited("access_throttled").await.len(), 1);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test]
async fn reads_write_nothing_and_cost_nothing() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    refused_calls(&h, "dave", burst + 1).await;
    let dave = h.token("dave").await;
    assert_eq!(h.list(&dave).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_stolen_token_does_not_spend_the_persons_budget_or_anyone_elses() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    // dave, and bob's token, each spend theirs.
    let dave = h.token("dave").await;
    let bob_token = h.token("bob").await;
    for _ in 0..=burst {
        h.call(Method::POST, PROD_REQUESTS, &dave, Vec::new()).await;
        h.call(Method::POST, PROD_REQUESTS, &bob_token, Vec::new())
            .await;
    }
    assert_eq!(
        h.call(Method::POST, PROD_REQUESTS, &bob_token, Vec::new())
            .await
            .code(),
        "rate_limited"
    );
    // bob in person can still approve.
    let bob = h.session("bob").await;
    let answer = h.approve(id, &bob, &h.keys.bob, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn bad_origins_are_within_the_budget_too() {
    let h = Harness::new().await;
    let session = h
        .store
        .begin_session_for_test("alice", 3600)
        .await
        .reveal_for_test();
    let caller = super::Caller::SessionFrom(session, None);
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    for _ in 0..burst + 5 {
        h.call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
            .await;
    }
    assert_eq!(h.audited("access_refused").await.len(), burst);
}

#[tokio::test]
async fn a_row_that_cannot_be_written_keeps_its_count() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    let caller = h.token("otto").await;
    for _ in 0..burst + 7 {
        h.call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
            .await;
    }
    h.clock.advance(10);
    // The row can't be written, for the length of one call.
    sqlx::query(
        "CREATE TRIGGER no_throttled BEFORE INSERT ON audit_events
         WHEN NEW.kind = 'access_throttled'
         BEGIN SELECT RAISE(ABORT, 'not now'); END",
    )
    .execute(h.store.pool())
    .await
    .unwrap();
    let answer = h
        .call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
        .await;
    assert!(answer.status.is_server_error(), "{answer:?}");
    sqlx::query("DROP TRIGGER no_throttled")
        .execute(h.store.pool())
        .await
        .unwrap();
    h.clock.advance(10);
    assert_eq!(
        h.call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
            .await
            .status,
        StatusCode::NOT_FOUND
    );
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["dropped"], 7);
}
