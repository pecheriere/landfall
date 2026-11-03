//! What a principal's state changes cost, and that going over says so afterwards.

use axum::http::{Extensions, Method, StatusCode, header};

use super::{Harness, PROD_REQUESTS};
use crate::auth::{Spender, flush_dropped, keep_flushing, spend_budget};

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
async fn the_budget_refills_at_one_a_second() {
    let h = Harness::new().await;
    assert_eq!(h.limits.principal_rate_per_second, 1);
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    assert_eq!(refused_calls(&h, "otto", burst + 1).await, (burst, 1));
    h.clock.advance(1);
    assert_eq!(refused_calls(&h, "otto", 2).await, (1, 1));
    h.clock.advance(3);
    assert_eq!(refused_calls(&h, "otto", 4).await, (3, 1));
}

#[tokio::test]
async fn the_count_names_no_token_as_it_is_the_whole_principals() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    refused_calls(&h, "otto", burst + 5).await;
    h.clock.advance(10);
    // Another of otto's tokens, which did nothing to earn this.
    refused_calls(&h, "otto", 1).await;
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["dropped"], 5);
    assert_eq!(
        rows[0]["by"],
        serde_json::json!({ "principal": "otto", "via": "token" })
    );
}

#[tokio::test]
async fn a_count_is_written_if_the_spender_goes_quiet() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    refused_calls(&h, "otto", burst + 5).await;
    flush_dropped(&h.state).await;
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["dropped"], 5);
    // Once: neither the next flush nor the next call says it again.
    flush_dropped(&h.state).await;
    h.clock.advance(10);
    refused_calls(&h, "otto", 1).await;
    assert_eq!(h.audited("access_throttled").await.len(), 1);
}

#[tokio::test]
async fn a_count_that_cannot_be_written_waits_for_the_next_flush() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    refused_calls(&h, "otto", burst + 5).await;
    let refuse_it = "CREATE TRIGGER no_throttled BEFORE INSERT ON audit_events
                     WHEN NEW.kind = 'access_throttled'
                     BEGIN SELECT RAISE(ABORT, 'not now'); END";
    sqlx::query(refuse_it)
        .execute(h.store.pool())
        .await
        .unwrap();
    flush_dropped(&h.state).await;
    sqlx::query("DROP TRIGGER no_throttled")
        .execute(h.store.pool())
        .await
        .unwrap();
    flush_dropped(&h.state).await;
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["dropped"], 5);
}

#[tokio::test]
async fn stopping_writes_what_is_left() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    refused_calls(&h, "otto", burst + 5).await;
    let (stop, stopped) = tokio::sync::watch::channel(false);
    let flushing = tokio::spawn(keep_flushing(
        h.state.clone(),
        std::time::Duration::from_hours(1),
        stopped,
    ));
    stop.send_replace(true);
    flushing.await.unwrap();
    assert_eq!(h.audited("access_throttled").await[0]["dropped"], 5);
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

/// A page on a sibling subdomain can send a person's cookie, so this must cost them nothing.
#[tokio::test]
async fn bad_origins_cost_no_budget_and_write_one_count() {
    let h = Harness::new().await;
    let session = h.store.begin_session_for_test("alice", 3600).await.reveal();
    let caller = super::Caller::SessionFrom(session.clone(), None);
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    for _ in 0..burst + 5 {
        let answer = h
            .call(Method::POST, PROD_REQUESTS, &caller, Vec::new())
            .await;
        assert_eq!(answer.code(), "bad_origin");
    }
    assert_eq!(h.audited("access_refused").await.len(), 0);
    assert_eq!(h.audited("access_throttled").await.len(), 0);

    // The whole budget is there for the real page.
    let real = super::Caller::Session(session);
    for _ in 0..burst {
        let answer = h.call(Method::POST, PROD_REQUESTS, &real, Vec::new()).await;
        assert_ne!(answer.status, StatusCode::TOO_MANY_REQUESTS, "{answer:?}");
    }

    crate::web::tend(&h.state).await;
    let rows = h.audited("access_refused").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["attempts"], burst + 5);
}

#[tokio::test]
async fn a_session_exhausts_only_itself() {
    let h = Harness::new().await;
    let burst = usize::try_from(h.limits.principal_burst).unwrap();
    let stolen = h.session("alice").await;
    for _ in 0..burst {
        h.call(Method::POST, PROD_REQUESTS, &stolen, Vec::new())
            .await;
    }
    let over = h
        .call(Method::POST, PROD_REQUESTS, &stolen, Vec::new())
        .await;
    assert_eq!(over.code(), "rate_limited");

    // The same person's other session, and their token, are untouched.
    for other in [h.session("alice").await, h.token("alice").await] {
        let answer = h
            .call(Method::POST, PROD_REQUESTS, &other, Vec::new())
            .await;
        assert_ne!(answer.status, StatusCode::TOO_MANY_REQUESTS, "{answer:?}");
    }

    flush_dropped(&h.state).await;
    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["by"]["via"], "session");
    assert_eq!(rows[0]["dropped"], 1);
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

/// Goes over a principal's sign-ins by 5, and gives what's needed for the next call to be back
/// within them, with those 5 to write down.
async fn five_refused_and_back_within_budget(h: &Harness) -> Spender {
    let spender = Spender::SignIns("otto".parse().unwrap());
    for _ in 0..15 {
        let _ = spend_budget(&h.state, &Extensions::new(), &spender).await;
    }
    h.clock.advance(300);
    spender
}

/// By a deadline, a client that left or a server stopping, it's all the same to the count.
#[tokio::test(flavor = "multi_thread")]
async fn a_handler_cut_off_writing_a_count_leaves_it_to_be_written() {
    let h = Harness::new().await;
    let spender = five_refused_and_back_within_budget(&h).await;
    // The write can't start yet, as with any other writer in the way.
    let busy = h.store.begin().await.unwrap();
    let extensions = Extensions::new();
    let cut_off = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        spend_budget(&h.state, &extensions, &spender),
    )
    .await;
    assert!(cut_off.is_err(), "it was meant to be waiting");
    drop(busy);

    flush_dropped(&h.state).await;

    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["dropped"], 5);
}

#[tokio::test]
async fn a_count_written_by_the_call_back_within_budget_is_written_once() {
    let h = Harness::new().await;
    let spender = five_refused_and_back_within_budget(&h).await;

    spend_budget(&h.state, &Extensions::new(), &spender)
        .await
        .unwrap();
    flush_dropped(&h.state).await;

    let rows = h.audited("access_throttled").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["dropped"], 5);
}
