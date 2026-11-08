//! Registering a passkey with an invite's code.

use axum::http::StatusCode;
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use serde_json::json;

use super::{
    Harness, ORIGIN, REGISTER_BEGIN, REGISTER_FINISH, RP_ID, attestation_body, b64, sign_in_body,
};
use crate::agent_api::Limits;
use crate::auth::{HumanProblem, PasskeyInvite};
use crate::store::{NewPasskey, Redeemed, Store};

const INVITE_LIFETIME: i64 = 60 * 60;
const CHALLENGE_LIFETIME: i64 = 5 * 60;

#[tokio::test]
async fn invite_works_once() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let answer = h
        .register(&code, &SoftwareAuthenticator::es256().unwrap())
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(h.count("passkey_invites").await, 0);

    let again = h.post(REGISTER_BEGIN, None, &json!({ "code": code })).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert_eq!(again.code(), "invite_refused");
    assert_eq!(h.count("passkeys").await, 1);
}

#[tokio::test]
async fn a_wrong_used_or_expired_code_gets_one_answer() {
    let h = Harness::new().await;
    let used = h.invite("gina").await;
    h.register(&used, &SoftwareAuthenticator::es256().unwrap())
        .await;
    let replaced = h.invite("dave").await;
    h.invite("dave").await;
    let expired = h.invite("carol").await;
    // Issuing another clears out what's past its time, so nothing does after this: carol's row
    // is still there, and it is its time that refuses it.
    h.clock.advance(INVITE_LIFETIME);
    assert_eq!(h.count("passkey_invites").await, 2);

    for code in [
        used.as_str(),
        expired.as_str(),
        replaced.as_str(),
        &"0".repeat(64),
        "not a code",
        "",
    ] {
        for (path, body) in [
            (REGISTER_BEGIN, json!({ "code": code })),
            (
                REGISTER_FINISH,
                json!({ "code": code, "attestation_object": "", "client_data_json": "" }),
            ),
        ] {
            let answer = h.post(path, None, &body).await;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{code} {answer:?}");
            assert_eq!(
                answer.json(),
                json!({
                    "code": "invite_refused",
                    "title": "this link is not valid; ask for a new one",
                    "status": 403,
                }),
            );
        }
    }
}

#[tokio::test]
async fn an_invite_is_good_until_the_last_second_of_its_hour() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    h.clock.advance(INVITE_LIFETIME - 1);
    let begun = h.post(REGISTER_BEGIN, None, &json!({ "code": code })).await;
    assert_eq!(begun.status, StatusCode::OK, "{begun:?}");
}

/// Expiring between the look at the code and the transaction that spends it.
#[tokio::test]
async fn redeeming_goes_by_the_clock_too() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap().key().unwrap();
    h.clock.advance(INVITE_LIFETIME);
    let outcome = h
        .store
        .redeem_invite(
            &PasskeyInvite::parse(&code).unwrap(),
            &NewPasskey {
                credential_id: &[1; 16],
                key: &key,
            },
        )
        .await
        .unwrap();
    assert_eq!(outcome, Redeemed::InviteGone);
    assert_eq!(h.count("passkeys").await, 0);
}

#[tokio::test]
async fn a_body_just_over_each_cap_is_refused_before_it_is_parsed() {
    use crate::web::registration::{MAX_BEGIN_BODY_BYTES, MAX_FINISH_BODY_BYTES};

    /// A JSON object of exactly `size` bytes, parsing or not.
    fn body_of(size: usize) -> Vec<u8> {
        let empty = r#"{"code":""}"#;
        format!("{{\"code\":\"{}\"}}", "x".repeat(size - empty.len())).into_bytes()
    }

    let h = Harness::new().await;
    for (path, cap) in [
        (REGISTER_BEGIN, MAX_BEGIN_BODY_BYTES),
        (REGISTER_FINISH, MAX_FINISH_BODY_BYTES),
        (
            super::SIGN_IN_BEGIN,
            crate::web::sign_in::MAX_BEGIN_BODY_BYTES,
        ),
        (
            super::SIGN_IN_FINISH,
            crate::web::sign_in::MAX_FINISH_BODY_BYTES,
        ),
    ] {
        for (size, too_large) in [(cap, false), (cap + 1, true)] {
            let request = axum::http::Request::builder()
                .method("POST")
                .uri(path)
                .header(axum::http::header::ORIGIN, ORIGIN)
                .body(axum::body::Body::from(body_of(size)))
                .unwrap();
            let answer = h.send(request).await;
            if too_large {
                assert_eq!(
                    answer.status,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "{path} {size}"
                );
            } else {
                assert_ne!(
                    answer.status,
                    StatusCode::PAYLOAD_TOO_LARGE,
                    "{path} {size}"
                );
            }
        }
    }
}

#[test]
fn a_sent_code_stays_out_of_debug() {
    use crate::web::registration::{BeginBody, FinishBody};
    let secret = "a".repeat(64);
    let begin: BeginBody = serde_json::from_value(json!({ "code": secret })).unwrap();
    let finish: FinishBody = serde_json::from_value(json!({
        "code": secret,
        "attestation_object": "",
        "client_data_json": "",
    }))
    .unwrap();
    for shown in [format!("{begin:?}"), format!("{finish:?}")] {
        assert!(!shown.contains(&secret), "{shown}");
        assert!(shown.contains("redacted"), "{shown}");
    }
}

#[tokio::test]
async fn begin_asks_for_what_this_verifier_can_use_and_no_more() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let answer = h.post(REGISTER_BEGIN, None, &json!({ "code": code })).await;
    let options = &answer.json()["publicKey"];
    assert_eq!(
        options["pubKeyCredParams"],
        json!([
            { "type": "public-key", "alg": -7 },
            { "type": "public-key", "alg": -8 },
        ])
    );
    assert_eq!(options["attestation"], "none");
    assert_eq!(options["rp"]["id"], RP_ID);
    assert_eq!(options["user"]["name"], "gina");
    assert_eq!(
        options["authenticatorSelection"],
        json!({ "residentKey": "required", "userVerification": "required" })
    );
    assert!(options.get("excludeCredentials").is_none());
}

#[tokio::test]
async fn registration_page_shows_key_and_fingerprint() {
    let h = Harness::new().await;
    let key = SoftwareAuthenticator::eddsa().unwrap();
    let code = h.invite("gina").await;
    let answer = h.register(&code, &key).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");

    let shown = answer.json();
    let public_key = key.key().unwrap();
    assert_eq!(shown["principal"], "gina");
    assert_eq!(shown["credential_id"], b64(key.credential_id()));
    assert_eq!(shown["public_key"], b64(public_key.as_bytes()));
    assert_eq!(shown["fingerprint"], public_key.fingerprint());
    // What the operator copies loads as it is.
    let file = format!("[approvers]\n{}\n", shown["config_line"].as_str().unwrap());
    let config = landfall_approval::parse_config(file.as_bytes()).unwrap();
    let approver = config.approver(&"gina".parse().unwrap()).unwrap();
    assert_eq!(approver.credential_id(), key.credential_id());
    assert_eq!(approver.public_key(), public_key.as_bytes());

    // The page has somewhere to put each, and the script fills them by textContent.
    let page = h.get("/passkeys/register").await;
    let (html, script) = (
        String::from_utf8(page.body).unwrap(),
        include_str!("../static/landfall.js"),
    );
    for id in ["credential-id", "public-key", "fingerprint", "config-line"] {
        assert!(html.contains(&format!("id=\"{id}\"")), "{id}");
        assert!(script.contains(&format!("\"{id}\"")), "{id}");
    }
}

#[tokio::test]
async fn a_failed_finish_leaves_the_invite_usable() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();

    let challenge = h.begin_registration(&code).await;
    let mut wrong = Ceremony::new(RP_ID, "https://elsewhere.example", &challenge);
    let answer = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&code, &key, &wrong),
        )
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{answer:?}");
    assert_eq!(answer.code(), "registration_refused");
    assert_eq!(h.count("passkeys").await, 0);
    assert_eq!(h.count("passkey_invites").await, 1);

    // The challenge was used up by trying, so a new attempt starts with a new one.
    wrong.origin = ORIGIN.to_owned();
    let replayed = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&code, &key, &wrong),
        )
        .await;
    assert_eq!(replayed.code(), "registration_refused");
    assert_eq!(h.register(&code, &key).await.status, StatusCode::OK);
}

#[tokio::test]
async fn an_expired_challenge_cannot_finish_a_registration() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();
    let challenge = h.begin_registration(&code).await;
    h.clock.advance(CHALLENGE_LIFETIME);
    let answer = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&code, &key, &Ceremony::new(RP_ID, ORIGIN, &challenge)),
        )
        .await;
    assert_eq!(answer.code(), "registration_refused");
}

#[tokio::test]
async fn a_sign_in_challenge_cannot_finish_a_registration_nor_the_reverse() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();

    h.begin_registration(&code).await;
    let sign_in = h.begin_sign_in().await;
    let answer = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&code, &key, &Ceremony::new(RP_ID, ORIGIN, &sign_in)),
        )
        .await;
    assert_eq!(answer.code(), "registration_refused");

    let registering = h.begin_registration(&code).await;
    let answer = h
        .post(
            super::SIGN_IN_FINISH,
            None,
            &sign_in_body(&h.alice, &registering),
        )
        .await;
    assert_eq!(answer.code(), "sign_in_refused");
}

#[tokio::test]
async fn one_invites_challenge_cannot_finish_anothers() {
    let h = Harness::new().await;
    let (mine, theirs) = (h.invite("gina").await, h.invite("carol").await);
    let key = SoftwareAuthenticator::es256().unwrap();
    let challenge = h.begin_registration(&theirs).await;
    let answer = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&mine, &key, &Ceremony::new(RP_ID, ORIGIN, &challenge)),
        )
        .await;
    assert_eq!(answer.code(), "registration_refused");
    assert_eq!(h.count("passkeys").await, 0);
}

#[tokio::test]
async fn someone_elses_credential_id_is_refused_and_spends_nothing() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;

    // Another person's stored credential id, and an approver's from the file, with a key of
    // the sender's.
    for taken in [
        gina.credential_id().to_vec(),
        h.alice.credential_id().to_vec(),
    ] {
        let code = h.invite("carol").await;
        let challenge = h.begin_registration(&code).await;
        let mut ceremony = Ceremony::new(RP_ID, ORIGIN, &challenge);
        ceremony.credential_id = Some(taken);
        let forged = SoftwareAuthenticator::es256().unwrap();
        let answer = h
            .post(
                REGISTER_FINISH,
                None,
                &attestation_body(&code, &forged, &ceremony),
            )
            .await;
        assert_eq!(answer.code(), "registration_refused", "{answer:?}");
        assert_eq!(h.count("passkey_invites").await, 1);
        assert_eq!(h.count("passkeys").await, 1);
    }
}

#[tokio::test]
async fn an_approver_may_register_the_files_key_and_no_other_under_that_id() {
    let h = Harness::new().await;
    let code = h.invite("alice").await;

    // Their own credential id, with a key the file doesn't hold for it.
    let challenge = h.begin_registration(&code).await;
    let mut ceremony = Ceremony::new(RP_ID, ORIGIN, &challenge);
    ceremony.credential_id = Some(h.alice.credential_id().to_vec());
    let other = SoftwareAuthenticator::es256().unwrap();
    let answer = h
        .post(
            REGISTER_FINISH,
            None,
            &attestation_body(&code, &other, &ceremony),
        )
        .await;
    assert_eq!(answer.code(), "registration_refused", "{answer:?}");
    assert_eq!(h.count("passkeys").await, 0);

    // The very key the file holds.
    let answer = h.register(&code, &h.alice).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(h.count("passkeys").await, 1);
}

#[tokio::test]
async fn registering_again_replaces_the_key_and_ends_the_sessions() {
    let h = Harness::new().await;
    let first = h.registered("gina").await;
    let session = h.signed_in(&first).await;
    let second = h.registered("gina").await;

    assert_eq!(h.count("passkeys").await, 1);
    let refused = h.post(super::SIGN_OUT, Some(&session), &json!({})).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(h.try_sign_in(&first).await.code(), "sign_in_refused");
    assert_eq!(h.try_sign_in(&second).await.status, StatusCode::OK);

    let rows = h.audited("passkey_registered").await;
    assert_eq!(rows[1]["principal"], "gina");
    assert_eq!(
        rows[1]["replaced_fingerprint"],
        first.key().unwrap().fingerprint()
    );
}

#[tokio::test]
async fn redeeming_is_single_use_under_concurrency() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let code = store
        .issue_passkey_invite(&"gina".parse().unwrap())
        .await
        .unwrap()
        .reveal();
    let mut attempts = tokio::task::JoinSet::new();
    for n in 0..8_u8 {
        let (store, code) = (store.clone(), code.clone());
        let key = SoftwareAuthenticator::es256().unwrap().key().unwrap();
        attempts.spawn(async move {
            let invite = PasskeyInvite::parse(&code).unwrap();
            let passkey = NewPasskey {
                credential_id: &[n; 16],
                key: &key,
            };
            store.redeem_invite(&invite, &passkey).await.unwrap()
        });
    }
    let mut done = 0;
    while let Some(outcome) = attempts.join_next().await {
        if matches!(outcome.unwrap(), Redeemed::Registered { .. }) {
            done += 1;
        }
    }
    assert_eq!(done, 1);
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM passkeys")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1);
}

#[tokio::test]
async fn a_registration_is_audited_with_no_secret_and_failures_are_counted() {
    let h = Harness::new().await;
    let code = h.invite("gina").await;
    let key = SoftwareAuthenticator::es256().unwrap();

    let challenge = h.begin_registration(&code).await;
    let bad = Ceremony::new(RP_ID, "https://elsewhere.example", &challenge);
    h.post(REGISTER_FINISH, None, &attestation_body(&code, &key, &bad))
        .await;
    h.register(&code, &key).await;

    let rows = h.audited("passkey_registered").await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["principal"], "gina");
    assert_eq!(rows[0]["fingerprint"], key.key().unwrap().fingerprint());

    assert_eq!(h.audited("registration_refused").await.len(), 0);
    crate::web::tend(&h.state).await;
    let refused = h.audited("registration_refused").await;
    assert_eq!(refused.len(), 1);
    assert_eq!(refused[0]["principal"], "gina");
    assert_eq!(refused[0]["attempts"], 1);

    let everything: Vec<String> = sqlx::query_scalar("SELECT detail FROM audit_events")
        .fetch_all(h.store.pool())
        .await
        .unwrap();
    assert!(!everything.iter().any(|detail| detail.contains(&code)));
}

#[tokio::test]
async fn with_no_approval_settings_it_refuses_clearly() {
    let alice = SoftwareAuthenticator::es256().unwrap();
    let h = Harness::on(
        Store::open_in_memory().await.unwrap(),
        "",
        Limits::default(),
        alice,
    );
    for path in [
        REGISTER_BEGIN,
        REGISTER_FINISH,
        super::SIGN_IN_BEGIN,
        super::SIGN_IN_FINISH,
    ] {
        let answer = h.post(path, None, &json!({})).await;
        assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(answer.code(), HumanProblem::ApprovalsNotConfigured.code());
    }
    // The pages load, and say so when they try.
    assert_eq!(h.get("/sign-in").await.status, StatusCode::OK);
}
