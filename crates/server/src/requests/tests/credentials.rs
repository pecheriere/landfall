//! Tokens and sessions: what proves who is asking, and what stops proving it.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;
use sqlx::Row as _;

use super::{APPROVALS, Caller, Harness, ORIGIN, PROD_REQUESTS};

#[tokio::test]
async fn token_is_shown_once_and_stored_hashed() {
    let h = Harness::new().await;
    let (id, token) = h
        .store
        .create_token(&"alice".parse().unwrap())
        .await
        .unwrap();
    let text = token.reveal();
    assert!(text.starts_with("lf_"), "{text}");
    assert_eq!(text.len(), 3 + 64);
    let digits = text.strip_prefix("lf_").unwrap();

    let row = sqlx::query("SELECT id, token_hash, principal FROM api_tokens")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("id"), id);
    let stored: Vec<u8> = row.get("token_hash");
    assert_eq!(stored, token.hash());
    assert_ne!(hex::encode(&stored), digits);
    assert_eq!(row.get::<String, _>("principal"), "alice");

    // Not in the audit log, and not in Debug.
    let audited = h.audited("token_created").await;
    assert_eq!(audited, [json!({ "token": id, "principal": "alice" })]);
    assert!(!format!("{token:?}").contains(digits));

    // The token works, and nothing ever gives it again.
    let answer = h.list(&Caller::Token(text.clone())).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert!(!answer.text().contains(digits));
}

#[tokio::test]
async fn revoked_token_is_refused() {
    let h = Harness::new().await;
    let (id, token) = h
        .store
        .create_token(&"alice".parse().unwrap())
        .await
        .unwrap();
    let caller = Caller::Token(token.reveal());
    assert_eq!(h.list(&caller).await.status, StatusCode::OK);

    assert!(h.store.revoke_token(id).await.unwrap());
    let answer = h.list(&caller).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "unauthenticated");

    // A second revocation changes nothing, and an unknown one is an error.
    assert!(!h.store.revoke_token(id).await.unwrap());
    assert_eq!(h.audited("token_revoked").await.len(), 1);
    assert!(h.store.revoke_token(id + 1).await.is_err());
}

#[tokio::test]
async fn a_token_for_a_principal_no_longer_in_the_config_stops_working() {
    let h = Harness::new().await;
    let (_, gone) = h
        .store
        .create_token(&"mallory".parse().unwrap())
        .await
        .unwrap();
    let answer = h.list(&Caller::Token(gone.reveal())).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "unauthenticated");
}

#[tokio::test]
async fn every_bad_credential_gets_the_same_answer_as_none() {
    let h = Harness::new().await;
    let (id, revoked) = h
        .store
        .create_token(&"alice".parse().unwrap())
        .await
        .unwrap();
    h.store.revoke_token(id).await.unwrap();
    let (_, gone) = h
        .store
        .create_token(&"mallory".parse().unwrap())
        .await
        .unwrap();
    let expired = h.store.begin_session_for_test("alice", 10).await;
    h.clock.advance(10);

    let none = h.list(&Caller::Nobody).await;
    assert_eq!(none.status, StatusCode::UNAUTHORIZED);
    assert_eq!(none.headers[header::WWW_AUTHENTICATE], "Bearer");
    for caller in [
        Caller::Token(revoked.reveal()),
        Caller::Token(gone.reveal()),
        Caller::Token(format!("lf_{}", "0".repeat(64))),
        Caller::Token("not-a-token".to_owned()),
        Caller::Session(expired.reveal()),
        Caller::Session("0".repeat(64)),
        Caller::Session("not-a-session".to_owned()),
    ] {
        let answer = h.list(&caller).await;
        assert_eq!(answer.status, none.status, "{caller:?}");
        assert_eq!(answer.body, none.body, "{caller:?}");
        assert_eq!(
            answer.headers[header::WWW_AUTHENTICATE],
            none.headers[header::WWW_AUTHENTICATE]
        );
    }
    // Anyone can send these: they don't get to write to the audit log.
    assert_eq!(h.audited("access_refused").await.len(), 0);
}

#[tokio::test]
async fn a_session_works_like_a_token_for_what_is_safe() {
    let h = Harness::new().await;
    let session = h.store.begin_session_for_test("alice", 3600).await;
    // A plain read carries no Origin in a browser, and needs none.
    let caller = Caller::SessionFrom(session.reveal(), None);
    assert_eq!(h.list(&caller).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_state_change_with_a_session_takes_the_exact_origin() {
    let h = Harness::new().await;
    h.ready().await;
    let session = h.store.begin_session_for_test("alice", 3600).await.reveal();
    for origin in [
        None,
        Some("https://evil.example"),
        Some("https://landfall.example:444"),
        Some("https://landfall.example/"),
        Some("HTTPS://LANDFALL.EXAMPLE"),
        Some("http://landfall.example"),
        Some("null"),
    ] {
        let caller = Caller::SessionFrom(session.clone(), origin.map(str::to_owned));
        let answer = h.ask(&caller, "v1.1.0").await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{origin:?}");
        assert_eq!(answer.code(), "bad_origin", "{origin:?}");
    }
    // A bad origin writes nothing as it comes, and is one count afterwards.
    assert_eq!(h.audited("access_refused").await.len(), 0);
    crate::web::tend(&h.state).await;
    let rows = h.audited("access_refused").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["attempts"], 7);
    assert_eq!(rows[0]["by"]["principal"], "alice");
    assert_eq!(h.audited("deploy_requested").await.len(), 0);

    let answer = h
        .ask(
            &Caller::SessionFrom(session.clone(), Some(ORIGIN.to_owned())),
            "v1.1.0",
        )
        .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");

    // Twice over is no origin at all.
    let twice = Request::builder()
        .method(Method::POST)
        .uri(PROD_REQUESTS)
        .header(header::COOKIE, format!("__Host-landfall-session={session}"))
        .header(header::ORIGIN, ORIGIN)
        .header(header::ORIGIN, ORIGIN)
        .body(Body::from(r#"{"tag":"v1.1.0"}"#))
        .unwrap();
    assert_eq!(h.send(twice).await.code(), "bad_origin");
}

#[tokio::test]
async fn a_token_needs_no_origin_but_a_bad_one_changes_nothing() {
    let h = Harness::new().await;
    h.ready().await;
    let Caller::Token(token) = h.token("alice").await else {
        unreachable!()
    };
    let request = Request::builder()
        .method(Method::POST)
        .uri(PROD_REQUESTS)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ORIGIN, "https://evil.example")
        .body(Body::from(r#"{"tag":"v1.1.0"}"#))
        .unwrap();
    assert_eq!(h.send(request).await.status, StatusCode::CREATED);
}

#[tokio::test]
async fn two_credentials_at_once_are_none() {
    let h = Harness::new().await;
    let Caller::Token(token) = h.token("alice").await else {
        unreachable!()
    };
    let session = h.store.begin_session_for_test("bob", 3600).await.reveal();
    let both = Request::builder()
        .uri(APPROVALS)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::COOKIE, format!("__Host-landfall-session={session}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(both).await.code(), "unauthenticated");

    let same_cookie_twice = Request::builder()
        .uri(APPROVALS)
        .header(
            header::COOKIE,
            format!("__Host-landfall-session={session}; __Host-landfall-session={session}"),
        )
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(same_cookie_twice).await.code(), "unauthenticated");

    let two_headers = Request::builder()
        .uri(APPROVALS)
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(two_headers).await.code(), "unauthenticated");
}
