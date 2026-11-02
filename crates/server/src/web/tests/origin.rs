//! Every state change wants the exact `Origin`, with or without a session.

use axum::http::{Request, StatusCode, header};
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use serde_json::json;

use super::{
    Answer, Harness, ORIGIN, REGISTER_BEGIN, REGISTER_FINISH, RP_ID, SIGN_IN_BEGIN, SIGN_IN_FINISH,
    SIGN_OUT, attestation_body, post_request, sign_in_body,
};

const WRONG: [Option<&str>; 8] = [
    None,
    Some("https://elsewhere.example"),
    Some("https://landfall.example/"),
    Some("https://landfall.example:444"),
    Some("http://landfall.example"),
    Some("https://LANDFALL.example"),
    Some("https://sub.landfall.example"),
    Some("null"),
];

fn refused(answer: &Answer) {
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "bad_origin");
    assert!(answer.headers.get(header::SET_COOKIE).is_none());
}

#[tokio::test]
async fn wrong_origin_is_refused_on_every_state_change() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();
    let session = h.signed_in(&h.alice).await;
    let registering = h.begin_registration(&code).await;
    let signing_in = h.begin_sign_in().await;
    let audit_rows_before = h.count("audit_events").await;

    let attestation = attestation_body(&code, &key, &Ceremony::new(RP_ID, ORIGIN, &registering));
    let assertion = sign_in_body(&h.alice, &signing_in);
    let begin_code = json!({ "code": code });
    let unauthenticated = [
        (REGISTER_BEGIN, &begin_code),
        (REGISTER_FINISH, &attestation),
        (SIGN_IN_BEGIN, &assertion),
        (SIGN_IN_FINISH, &assertion),
    ];
    for origin in WRONG {
        for (path, body) in unauthenticated {
            refused(&h.send(post_request(path, origin, None, body)).await);
        }
        refused(
            &h.send(post_request(SIGN_OUT, origin, Some(&session), &json!({})))
                .await,
        );
    }

    // Two of them, even if one is right.
    let mut twice = post_request(SIGN_IN_BEGIN, Some(ORIGIN), None, &json!({}));
    twice
        .headers_mut()
        .append(header::ORIGIN, "https://elsewhere.example".parse().unwrap());
    refused(&h.send(twice).await);

    // Nothing moved, and nothing was written.
    assert_eq!(h.count("sessions").await, 1);
    assert_eq!(h.count("passkey_invites").await, 1);
    assert_eq!(h.count("passkeys").await, 0);
    assert_eq!(h.count("audit_events").await, audit_rows_before);

    // Only someone with a session can be held to a refusal, and it comes to one count.
    crate::web::tend(&h.state).await;
    let rows = h.audited("access_refused").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["attempts"], WRONG.len());

    // The challenges weren't used up: the real page still finishes both.
    let finished = h.post(REGISTER_FINISH, None, &attestation).await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");
    let finished = h.post(SIGN_IN_FINISH, None, &assertion).await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");
}

/// A page on another site tries to sign its visitor in as the attacker.
#[tokio::test]
async fn a_login_from_another_site_gets_no_session() {
    let h = Harness::new().await;
    let attacker = h.registered("gina").await;
    let challenge = h.begin_sign_in().await;
    let body = sign_in_body(&attacker, &challenge);
    let answer = h
        .send(post_request(
            SIGN_IN_FINISH,
            Some("https://elsewhere.example"),
            None,
            &body,
        ))
        .await;
    refused(&answer);
    assert_eq!(h.count("sessions").await, 0);
}

/// `GET` can't do any of it: there is nothing there to do it.
#[tokio::test]
async fn no_ceremony_changes_state_on_get() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let session = h.signed_in(&h.alice).await;
    for path in [
        REGISTER_BEGIN,
        REGISTER_FINISH,
        SIGN_IN_BEGIN,
        SIGN_IN_FINISH,
        SIGN_OUT,
    ] {
        let request = Request::builder()
            .uri(path)
            .header(header::COOKIE, format!("__Host-landfall-session={session}"))
            .header(header::ORIGIN, ORIGIN)
            .body(axum::body::Body::empty())
            .unwrap();
        let answer = h.send(request).await;
        assert_eq!(answer.status, StatusCode::METHOD_NOT_ALLOWED, "{path}");
    }
    let begun = h.post(REGISTER_BEGIN, None, &json!({ "code": code })).await;
    assert_eq!(begun.status, StatusCode::OK);
    assert_eq!(h.count("sessions").await, 1);
}
