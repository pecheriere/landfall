//! Anyone can send these, so anyone sending a lot of them must cost little.

use std::net::SocketAddr;

use axum::extract::ConnectInfo;
use axum::http::{StatusCode, header};
use landfall_approval::SoftwareAuthenticator;
use serde_json::json;

use super::{Harness, ORIGIN, SIGN_IN_BEGIN, SIGN_IN_FINISH, post_request, sign_in_body};
use crate::agent_api::Limits;

fn from(ip: &str, body: &serde_json::Value, path: &str) -> axum::http::Request<axum::body::Body> {
    let mut request = post_request(path, Some(ORIGIN), None, body);
    let peer: SocketAddr = format!("{ip}:1000").parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    request
}

#[tokio::test]
async fn a_source_over_its_allowance_is_told_to_wait_and_others_arent() {
    let h = Harness::with_limits(Limits {
        ceremony_rate_per_second: 1,
        ceremony_burst: 3,
        ..Limits::default()
    })
    .await;
    for _ in 0..3 {
        let answer = h.send(from("192.0.2.1", &json!({}), SIGN_IN_BEGIN)).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    let over = h.send(from("192.0.2.1", &json!({}), SIGN_IN_BEGIN)).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(over.code(), "rate_limited");
    assert!(over.headers.contains_key(header::RETRY_AFTER));

    let other = h.send(from("192.0.2.2", &json!({}), SIGN_IN_BEGIN)).await;
    assert_eq!(other.status, StatusCode::OK);
    h.clock.advance(1);
    let later = h.send(from("192.0.2.1", &json!({}), SIGN_IN_BEGIN)).await;
    assert_eq!(later.status, StatusCode::OK);
}

/// A real tap isn't wasted by someone else's flood, behind a proxy that makes them one source.
#[tokio::test]
async fn a_finish_with_a_live_challenge_gets_through_any_flood() {
    let h = Harness::with_limits(Limits {
        ceremony_rate_per_second: 1,
        ceremony_burst: 3,
        ..Limits::default()
    })
    .await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();
    let signing_in = h.begin_sign_in().await;
    let registering = h.begin_registration(&code).await;
    h.begin_sign_in().await;
    let flood = h.post(SIGN_IN_BEGIN, None, &json!({})).await;
    assert_eq!(flood.status, StatusCode::TOO_MANY_REQUESTS);

    let finished = h
        .post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &signing_in))
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");
    let finished = h
        .post(
            super::REGISTER_FINISH,
            None,
            &super::attestation_body(
                &code,
                &key,
                &landfall_approval::Ceremony::new(super::RP_ID, ORIGIN, &registering),
            ),
        )
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");
}

#[tokio::test]
async fn a_bad_finish_pays_for_itself() {
    let h = Harness::with_limits(Limits {
        ceremony_rate_per_second: 1,
        ceremony_burst: 3,
        ..Limits::default()
    })
    .await;
    let unknown = sign_in_body(&h.alice, &[9; 32]);
    for _ in 0..3 {
        let answer = h.post(SIGN_IN_FINISH, None, &unknown).await;
        assert_eq!(answer.code(), "sign_in_refused");
    }
    let over = h.post(SIGN_IN_FINISH, None, &unknown).await;
    assert_eq!(over.status, StatusCode::TOO_MANY_REQUESTS);

    // As does each other way of being bad, whichever route it comes by.
    for (path, body) in [
        (SIGN_IN_FINISH, json!([])),
        (super::REGISTER_FINISH, json!({})),
        (
            super::REGISTER_FINISH,
            json!({ "code": "0", "attestation_object": "", "client_data_json": "" }),
        ),
    ] {
        h.clock.advance(1);
        let first = h.post(path, None, &body).await;
        assert_ne!(first.status, StatusCode::TOO_MANY_REQUESTS, "{path} {body}");
        let second = h.post(path, None, &body).await;
        assert_eq!(
            second.status,
            StatusCode::TOO_MANY_REQUESTS,
            "{path} {body}"
        );
    }
}

#[tokio::test]
async fn a_full_table_answers_at_once_and_time_alone_empties_it() {
    let h = Harness::with_limits(Limits {
        max_sign_in_challenges: 2,
        ..Limits::default()
    })
    .await;
    h.begin_sign_in().await;
    h.begin_sign_in().await;
    let full = h.post(SIGN_IN_BEGIN, None, &json!({})).await;
    assert_eq!(full.code(), "ceremonies_busy");

    h.clock.advance(5 * 60 - 1);
    let full = h.post(SIGN_IN_BEGIN, None, &json!({})).await;
    assert_eq!(full.code(), "ceremonies_busy");
    h.clock.advance(1);
    h.begin_sign_in().await;
    h.begin_sign_in().await;
    assert_eq!(h.state.ceremonies().held().0, 2);
}

#[tokio::test]
async fn a_flood_of_ceremonies_leaves_the_agents_allowance_alone() {
    let h = Harness::with_limits(Limits {
        ceremony_rate_per_second: 1,
        ceremony_burst: 1,
        source_rate_per_second: 1,
        source_burst: 1,
        ..Limits::default()
    })
    .await;
    for _ in 0..5 {
        h.post(SIGN_IN_BEGIN, None, &json!({})).await;
    }
    assert_eq!(h.get("/agent/v1/nonce").await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_full_table_refuses_the_new_and_keeps_every_challenge_it_has() {
    let h = Harness::with_limits(Limits {
        max_sign_in_challenges: 4,
        ..Limits::default()
    })
    .await;
    let real_person = h.begin_sign_in().await;
    for n in 1..4 {
        let ip = format!("192.0.2.{n}");
        let answer = h.send(from(&ip, &json!({}), SIGN_IN_BEGIN)).await;
        assert_eq!(answer.status, StatusCode::OK);
    }
    for n in 10..20 {
        let ip = format!("192.0.2.{n}");
        let answer = h.send(from(&ip, &json!({}), SIGN_IN_BEGIN)).await;
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(answer.code(), "ceremonies_busy");
        assert!(answer.headers.contains_key(header::RETRY_AFTER));
    }
    // The one who began first still gets to finish.
    let finished = h
        .post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &real_person))
        .await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");

    // Time clears the rest.
    h.clock.advance(5 * 60);
    let answer = h.send(from("192.0.2.10", &json!({}), SIGN_IN_BEGIN)).await;
    assert_eq!(answer.status, StatusCode::OK);
}

#[tokio::test]
async fn beginning_writes_nothing_to_the_database() {
    let h = Harness::with_limits(Limits {
        ceremony_burst: 1000,
        ..Limits::default()
    })
    .await;
    let code = h.invite("gina").await;
    let rows = h.count("audit_events").await;
    for _ in 0..100 {
        h.begin_sign_in().await;
        h.begin_registration(&code).await;
        h.post("/passkeys/register/begin", None, &json!({ "code": "0" }))
            .await;
    }
    assert_eq!(h.count("audit_events").await, rows);
}

#[tokio::test]
async fn refused_sign_ins_cost_no_session_budget_and_no_row() {
    let h = Harness::with_limits(Limits {
        ceremony_burst: 1000,
        principal_burst: 2,
        principal_rate_per_second: 1,
        ..Limits::default()
    })
    .await;
    let stranger = SoftwareAuthenticator::es256().unwrap();
    let rows = h.count("audit_events").await;
    for _ in 0..50 {
        // With a real person's credential id, and no way to sign for it.
        let challenge = h.begin_sign_in().await;
        let mut forged = landfall_approval::Ceremony::new(super::RP_ID, ORIGIN, &challenge);
        forged.credential_id = Some(h.alice.credential_id().to_vec());
        h.post(
            SIGN_IN_FINISH,
            None,
            &super::sign_in_ceremony_body(&stranger, &challenge, &forged),
        )
        .await;
    }
    assert_eq!(h.count("audit_events").await, rows);
    // The person's budget is whole: their sign-in and a state change by that session both go
    // through, in a burst of two.
    let session = h.signed_in(&h.alice).await;
    let out = h.post(super::SIGN_OUT, Some(&session), &json!({})).await;
    assert_eq!(out.status, StatusCode::NO_CONTENT, "{out:?}");
}

#[tokio::test]
async fn a_body_past_the_limit_is_refused_before_it_is_parsed() {
    let h = Harness::new().await;
    let huge = json!({ "code": "x".repeat(1024 * 1024) });
    let answer = h.post("/passkeys/register/begin", None, &huge).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    let huge = json!({ "challenge": "x".repeat(1024 * 1024) });
    let answer = h.post(SIGN_IN_FINISH, None, &huge).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
}
