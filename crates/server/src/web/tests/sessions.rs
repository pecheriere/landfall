//! What sign-in hands out, and how it ends.

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use serde_json::json;

use super::{COOKIE_NAME, Harness, SIGN_IN_FINISH, SIGN_OUT, answer_of, sign_in_body};
use crate::agent_api::Limits;
use crate::store::SESSION_LIFETIME_SECS;

async fn list_status(app: &axum::Router, session: &str) -> StatusCode {
    answer_of(
        app,
        Request::builder()
            .uri("/api/v1/approvals")
            .header(header::COOKIE, format!("{COOKIE_NAME}={session}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await
    .status
}

#[tokio::test]
async fn session_cookie_has_the_required_attributes() {
    let h = Harness::new().await;
    let answer = h.try_sign_in(&h.alice).await;
    let cookie = answer.headers[header::SET_COOKIE].to_str().unwrap();
    let mut parts = cookie.split("; ");
    let (name, value) = parts.next().unwrap().split_once('=').unwrap();
    assert_eq!(name, COOKIE_NAME);
    assert_eq!(value.len(), 64);
    assert!(
        value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    );
    let mut attributes: Vec<&str> = parts.collect();
    attributes.sort_unstable();
    assert_eq!(
        attributes,
        [
            "HttpOnly",
            "Max-Age=43200",
            "Path=/",
            "SameSite=Strict",
            "Secure"
        ]
    );
    assert_eq!(SESSION_LIFETIME_SECS, 43_200);
    assert_eq!(answer.headers[header::CACHE_CONTROL], "no-store");

    // Only the hash is kept.
    let stored: Vec<u8> = sqlx::query_scalar("SELECT token_hash FROM sessions")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(stored.len(), 32);
    assert_ne!(hex::encode(&stored), value);
}

#[tokio::test]
async fn session_id_changes_at_sign_in() {
    let h = Harness::new().await;
    let first = h.signed_in(&h.alice).await;
    let second = h.signed_in(&h.alice).await;
    assert_ne!(first, second);

    // A cookie the client came with is never taken up, known or not, and a known one ends.
    let planted = "ab".repeat(32);
    let challenge = h.begin_sign_in().await;
    let answer = h
        .post(
            SIGN_IN_FINISH,
            Some(&planted),
            &sign_in_body(&h.alice, &challenge),
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_ne!(answer.session(), planted);
    assert_eq!(
        list_status(&h.app, &planted).await,
        StatusCode::UNAUTHORIZED
    );

    let challenge = h.begin_sign_in().await;
    let answer = h
        .post(
            SIGN_IN_FINISH,
            Some(&second),
            &sign_in_body(&h.alice, &challenge),
        )
        .await;
    assert_ne!(answer.session(), second);
    assert_eq!(list_status(&h.app, &second).await, StatusCode::UNAUTHORIZED);
    assert_eq!(list_status(&h.app, &first).await, StatusCode::OK);
    assert_eq!(list_status(&h.app, &answer.session()).await, StatusCode::OK);
}

#[tokio::test]
async fn signed_out_session_is_refused() {
    let h = Harness::new().await;
    let session = h.signed_in(&h.alice).await;
    let answer = h.post(SIGN_OUT, Some(&session), &json!({})).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");
    let cleared = answer.headers[header::SET_COOKIE].to_str().unwrap();
    assert!(
        cleared.starts_with(&format!("{COOKIE_NAME}=;")),
        "{cleared}"
    );
    assert!(cleared.contains("Max-Age=0"), "{cleared}");
    assert!(cleared.contains("Secure"), "{cleared}");
    assert!(cleared.contains("Path=/"), "{cleared}");

    assert_eq!(
        list_status(&h.app, &session).await,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(h.count("sessions").await, 0);
    // Keeping the old cookie and sending it again gets nothing.
    let again = h.post(SIGN_OUT, Some(&session), &json!({})).await;
    assert_eq!(again.status, StatusCode::UNAUTHORIZED);

    let rows = h.audited("signed_out").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["principal"], "alice");
}

#[tokio::test]
async fn a_token_has_no_session_to_end() {
    let h = Harness::new().await;
    let (_, token) = h
        .store
        .create_token(&"alice".parse().unwrap())
        .await
        .unwrap();
    let request = Request::builder()
        .method("POST")
        .uri(SIGN_OUT)
        .header(header::AUTHORIZATION, format!("Bearer {}", token.reveal()))
        .body(Body::empty())
        .unwrap();
    let answer = h.send(request).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "forbidden");
    // It proved who it is, so the refusal is in the log, and within its budget.
    let rows = h.audited("access_refused").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["by"]["principal"], "alice");
    assert_eq!(rows[0]["by"]["via"], "token");
}

#[tokio::test]
async fn a_session_ends_when_its_time_is_up_and_its_row_is_settled() {
    let h = Harness::new().await;
    let session = h.signed_in(&h.alice).await;
    h.clock.advance(SESSION_LIFETIME_SECS - 1);
    assert_eq!(list_status(&h.app, &session).await, StatusCode::OK);
    h.clock.advance(1);
    assert_eq!(
        list_status(&h.app, &session).await,
        StatusCode::UNAUTHORIZED
    );

    assert_eq!(h.count("sessions").await, 1);
    crate::web::tend(&h.state).await;
    assert_eq!(h.count("sessions").await, 0);
}

#[tokio::test]
async fn expired_invites_are_settled_too() {
    let h = Harness::new().await;
    h.invite("gina").await;
    h.clock.advance(60 * 60);
    crate::web::tend(&h.state).await;
    assert_eq!(h.count("passkey_invites").await, 0);
}

#[tokio::test]
async fn signing_in_again_and_again_keeps_a_bounded_number_of_sessions() {
    let h = Harness::with_limits(Limits {
        ceremony_burst: 1000,
        ..Limits::default()
    })
    .await;
    let first = h.signed_in(&h.alice).await;
    for _ in 0..40 {
        h.clock.advance(1);
        h.signed_in(&h.alice).await;
    }
    assert!(h.count("sessions").await <= 16);
    assert_eq!(list_status(&h.app, &first).await, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn a_session_for_someone_gone_from_the_file_stops_working() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let session = h.signed_in(&gina).await;
    assert_eq!(list_status(&h.app, &session).await, StatusCode::OK);

    let without_gina = super::config_text(&h.alice).replace(
        "[[grant]]\nprincipal = \"gina\"\ndeployments = [\"app/prod\"]\ncan = [\"view\", \"request\"]\n",
        "",
    );
    let app = h.reloaded(&without_gina);
    assert_eq!(list_status(&app, &session).await, StatusCode::UNAUTHORIZED);
}
