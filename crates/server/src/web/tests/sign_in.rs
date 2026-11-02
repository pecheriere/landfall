//! Signing in: whose key opens what, and what a refusal gives away.

use axum::http::{StatusCode, header};
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use serde_json::json;

use super::{
    Answer, Harness, ORIGIN, RP_ID, SIGN_IN_BEGIN, SIGN_IN_FINISH, answer_of, assertion_text, b64,
    config_text, post_request, sign_in_body, sign_in_ceremony_body,
};

const CHALLENGE_LIFETIME: i64 = 5 * 60;

#[tokio::test]
async fn sign_in_with_a_registered_passkey_works() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let answer = h.try_sign_in(&gina).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(answer.json()["principal"], "gina");

    // The cookie is what the API's extractor takes, and it is gina's view of things.
    let list = answer_of(
        &h.app,
        axum::http::Request::builder()
            .uri("/api/v1/approvals")
            .header(
                header::COOKIE,
                format!("__Host-landfall-session={}", answer.session()),
            )
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(list.status, StatusCode::OK, "{list:?}");

    let rows = h.audited("signed_in").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["principal"], "gina");
    assert_eq!(rows[0]["how"], "stored_key");
}

#[tokio::test]
async fn an_approver_signs_in_with_the_key_in_the_file_without_ever_registering_here() {
    let h = Harness::new().await;
    let answer = h.try_sign_in(&h.alice).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(answer.json()["principal"], "alice");
    assert_eq!(h.audited("signed_in").await[0]["how"], "configured_key");
}

#[tokio::test]
async fn a_key_the_file_doesnt_hold_for_an_approver_cannot_sign_in() {
    let h = Harness::new().await;
    // A leaked invite for an approver gets the holder a stored key, and no session.
    let thief = h.registered("alice").await;
    assert_eq!(h.try_sign_in(&thief).await.code(), "sign_in_refused");
    assert_eq!(h.count("sessions").await, 0);
    // And the real key still works.
    assert_eq!(h.try_sign_in(&h.alice).await.status, StatusCode::OK);

    crate::web::tend(&h.state).await;
    let rows = h.audited("sign_in_refused").await;
    assert_eq!(rows[0]["principal"], "alice");
    assert_eq!(rows[0]["attempts"], 1);
}

#[tokio::test]
async fn a_key_registered_before_the_file_names_its_person_cannot_sign_in_until_it_does() {
    let h = Harness::new().await;
    let newcomer = h.registered("newcomer").await;
    assert_eq!(h.try_sign_in(&newcomer).await.code(), "sign_in_refused");
    assert_eq!(h.count("sessions").await, 0);

    // The operator copies it into a grant, and the controller restarts.
    let file = format!(
        "{}\n[[grant]]\nprincipal = \"newcomer\"\ndeployments = [\"app/prod\"]\ncan = [\"view\"]\n",
        config_text(&h.alice)
    );
    let app = h.reloaded(&file);
    let begun = answer_of(
        &app,
        post_request(SIGN_IN_BEGIN, Some(ORIGIN), None, &json!({})),
    )
    .await;
    let challenge = super::challenge_of(&begun);
    let finished = answer_of(
        &app,
        post_request(
            SIGN_IN_FINISH,
            Some(ORIGIN),
            None,
            &sign_in_body(&newcomer, &challenge),
        ),
    )
    .await;
    assert_eq!(finished.status, StatusCode::OK, "{finished:?}");
}

/// An unknown credential is checked against this, so that it takes as long as a known one.
#[test]
fn the_key_for_an_unknown_credential_is_a_real_es256_key() {
    let key = landfall_approval::CoseKey::parse(&crate::web::sign_in::NOBODYS_KEY).unwrap();
    assert_eq!(key.algorithm(), landfall_approval::Algorithm::Es256);
}

/// All of an answer that a caller can read.
fn seen(answer: &Answer) -> String {
    let mut headers: Vec<_> = answer
        .headers
        .iter()
        .map(|(name, value)| format!("{name}: {value:?}"))
        .collect();
    headers.sort();
    format!("{} {:?} {headers:?}", answer.status, answer.body)
}

#[tokio::test]
async fn sign_in_with_an_unknown_credential_says_the_same_as_a_bad_one() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let stranger = SoftwareAuthenticator::es256().unwrap();

    // An unknown credential.
    let unknown = h.try_sign_in(&stranger).await;
    // A bad signature on a real credential: the file's, and the stored one.
    let challenge = h.begin_sign_in().await;
    let mut forged = Ceremony::new(RP_ID, ORIGIN, &challenge);
    forged.credential_id = Some(h.alice.credential_id().to_vec());
    let configured = h
        .post(
            SIGN_IN_FINISH,
            None,
            &sign_in_ceremony_body(&stranger, &challenge, &forged),
        )
        .await;
    let challenge = h.begin_sign_in().await;
    let mut forged = Ceremony::new(RP_ID, ORIGIN, &challenge);
    forged.credential_id = Some(gina.credential_id().to_vec());
    let stored = h
        .post(
            SIGN_IN_FINISH,
            None,
            &sign_in_ceremony_body(&stranger, &challenge, &forged),
        )
        .await;
    // A person the file doesn't name.
    let unnamed = h.try_sign_in(&h.registered("newcomer").await).await;
    // A challenge nobody gave.
    let unasked = h
        .post(SIGN_IN_FINISH, None, &sign_in_body(&gina, &[9; 32]))
        .await;
    // Fields that don't decode.
    let challenge = h.begin_sign_in().await;
    let undecodable = h
        .post(
            SIGN_IN_FINISH,
            None,
            &json!({
                "challenge": b64(&challenge),
                "assertion": {
                    "credential_id": "!",
                    "authenticator_data": "!",
                    "client_data_json": "!",
                    "signature": "!",
                },
            }),
        )
        .await;

    assert_eq!(unknown.status, StatusCode::FORBIDDEN, "{unknown:?}");
    assert_eq!(unknown.code(), "sign_in_refused");
    for other in [&configured, &stored, &unnamed, &unasked, &undecodable] {
        assert_eq!(seen(other), seen(&unknown), "{other:?}");
    }
    assert_eq!(h.count("sessions").await, 0);
}

#[tokio::test]
async fn beginning_a_sign_in_names_no_one() {
    let h = Harness::new().await;
    h.registered("gina").await;
    let answer = h.post(SIGN_IN_BEGIN, None, &json!({})).await;
    let options = &answer.json()["publicKey"];
    assert_eq!(options["userVerification"], "required");
    assert_eq!(options["allowCredentials"], json!([]));
    let text = String::from_utf8(answer.body.clone()).unwrap();
    assert!(!text.contains("gina"));
    assert!(!text.contains("alice"));
}

#[tokio::test]
async fn challenge_works_once() {
    let h = Harness::new().await;
    let challenge = h.begin_sign_in().await;
    let body = sign_in_body(&h.alice, &challenge);
    assert_eq!(
        h.post(SIGN_IN_FINISH, None, &body).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.post(SIGN_IN_FINISH, None, &body).await.code(),
        "sign_in_refused"
    );
    assert_eq!(h.count("sessions").await, 1);
}

#[tokio::test]
async fn a_failed_attempt_uses_the_challenge_up_too() {
    let h = Harness::new().await;
    let challenge = h.begin_sign_in().await;
    let stranger = SoftwareAuthenticator::es256().unwrap();
    h.post(SIGN_IN_FINISH, None, &sign_in_body(&stranger, &challenge))
        .await;
    assert_eq!(
        h.post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &challenge))
            .await
            .code(),
        "sign_in_refused"
    );
}

#[tokio::test]
async fn expired_challenge_is_refused() {
    let h = Harness::new().await;
    let challenge = h.begin_sign_in().await;
    h.clock.advance(CHALLENGE_LIFETIME - 1);
    let in_time = h
        .post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &challenge))
        .await;
    assert_eq!(in_time.status, StatusCode::OK);

    let challenge = h.begin_sign_in().await;
    h.clock.advance(CHALLENGE_LIFETIME);
    let late = h
        .post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &challenge))
        .await;
    assert_eq!(late.code(), "sign_in_refused");
}

#[tokio::test]
async fn an_assertion_with_any_field_wrong_is_refused() {
    type Break = fn(&mut Ceremony);
    let h = Harness::new().await;
    let cases: [(&str, Break); 6] = [
        ("another origin", |c| {
            c.origin = "https://elsewhere.example".to_owned();
        }),
        ("another relying party", |c| {
            c.rp_id = "elsewhere.example".to_owned();
        }),
        ("a registration's type", |c| {
            c.kind = Some("webauthn.create".to_owned());
        }),
        ("from a frame", |c| c.cross_origin = Some(true)),
        ("no user verification", |c| c.flags = Some(0x01)),
        ("another challenge", |c| c.challenge = vec![7; 32]),
    ];
    for (name, spoil) in cases {
        let challenge = h.begin_sign_in().await;
        let mut ceremony = Ceremony::new(RP_ID, ORIGIN, &challenge);
        spoil(&mut ceremony);
        let answer = h
            .post(
                SIGN_IN_FINISH,
                None,
                &sign_in_ceremony_body(&h.alice, &challenge, &ceremony),
            )
            .await;
        assert_eq!(answer.code(), "sign_in_refused", "{name}");
    }
    assert_eq!(h.count("sessions").await, 0);
}

#[tokio::test]
async fn a_finish_takes_exactly_the_fields_it_should() {
    let h = Harness::new().await;
    let challenge = h.begin_sign_in().await;
    let assertion = assertion_text(
        &h.alice
            .assertion(&Ceremony::new(RP_ID, ORIGIN, &challenge))
            .unwrap(),
    );
    let mut extra_in_assertion = assertion.clone();
    extra_in_assertion["user_handle"] = json!("x");
    for body in [
        json!({ "challenge": b64(&challenge), "assertion": extra_in_assertion }),
        json!({ "challenge": b64(&challenge), "assertion": assertion, "session": "x" }),
        json!({ "assertion": assertion }),
        json!([]),
    ] {
        let answer = h.post(SIGN_IN_FINISH, None, &body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(answer.code(), "bad_request");
    }
    // None of those used it up: nothing could say which it was for.
    assert_eq!(
        h.post(SIGN_IN_FINISH, None, &sign_in_body(&h.alice, &challenge))
            .await
            .status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn failures_against_a_principal_are_written_down_as_a_count_and_nobody_elses_are() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let stranger = SoftwareAuthenticator::es256().unwrap();
    for _ in 0..5 {
        let challenge = h.begin_sign_in().await;
        let mut forged = Ceremony::new(RP_ID, ORIGIN, &challenge);
        forged.credential_id = Some(gina.credential_id().to_vec());
        h.post(
            SIGN_IN_FINISH,
            None,
            &sign_in_ceremony_body(&stranger, &challenge, &forged),
        )
        .await;
        h.try_sign_in(&stranger).await;
    }
    // Nothing is written while they come, whoever sends them.
    assert_eq!(h.audited("sign_in_refused").await.len(), 0);
    crate::web::tend(&h.state).await;
    let rows = h.audited("sign_in_refused").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0]["principal"], "gina");
    assert_eq!(rows[0]["attempts"], 5);
    crate::web::tend(&h.state).await;
    assert_eq!(h.audited("sign_in_refused").await.len(), 1);
}
