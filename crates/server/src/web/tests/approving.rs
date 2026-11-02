//! A real sign-in's session, through to an approval: it takes a fresh assertion every time.

use axum::http::StatusCode;
use landfall_approval::Ceremony;
use landfall_core::ids::HostId;
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};
use serde_json::{Value, json};

use super::{Harness, ORIGIN, RP_ID, assertion_text};
use crate::store::{ReleaseDecision, Seen};

const PROD: &str = "app/prod";
const HOST: &str = "host-a";
const ASK: &str = "/api/v1/deployments/app/prod/requests";

/// `app/prod` runs `v1.0.0`, and `v1.1.0` is verified. `gina` asks for it. Gives the request.
async fn open_request(h: &Harness, gina_session: &str) -> Value {
    let running_digest = format!("sha256:{}", "0".repeat(64)).parse().unwrap();
    let state = RunningState {
        deployment: PROD.parse().unwrap(),
        deployed: Some(DeployedRelease {
            tag: "v1.0.0".parse().unwrap(),
            digest: running_digest,
        }),
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    let host: HostId = HOST.parse().unwrap();
    h.store
        .record_host_state(&host, None, &[&state])
        .await
        .unwrap();
    let commit = "1".repeat(40).parse().unwrap();
    let digest = format!("sha256:{}", "1".repeat(64)).parse().unwrap();
    let seen = Seen {
        tag_object: "object",
        config_hash: h.state.config().hash(),
        commit: Some(&commit),
        digest: Some(&digest),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (&PROD.parse().unwrap(), &host, &"v1.1.0".parse().unwrap()),
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver",
            Some(&seen),
        )
        .await
        .unwrap();
    let answer = h
        .post(ASK, Some(gina_session), &json!({ "tag": "v1.1.0" }))
        .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    answer.json()
}

fn body_for(h: &Harness, challenge: &[u8]) -> Value {
    json!({
        "assertion": assertion_text(
            &h.alice
                .assertion(&Ceremony::new(RP_ID, ORIGIN, challenge))
                .unwrap()
        ),
    })
}

#[tokio::test]
async fn a_session_alone_approves_nothing_and_a_fresh_assertion_does() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let gina_session = h.signed_in(&gina).await;
    let request = open_request(&h, &gina_session).await;
    let (id, challenge) = (
        request["id"].as_i64().unwrap(),
        super::from_b64(request["challenge"].as_str().unwrap()),
    );
    let approve = format!("/api/v1/approvals/{id}");

    let alice_session = h.signed_in(&h.alice).await;

    // Their sign-in's own tap is no approval: its challenge is the sign-in's.
    let sign_in_challenge = h.begin_sign_in().await;
    let answer = h
        .post(
            &approve,
            Some(&alice_session),
            &body_for(&h, &sign_in_challenge),
        )
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "assertion_refused");

    // No assertion at all gets nowhere.
    let answer = h.post(&approve, Some(&alice_session), &json!({})).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);

    // Nor does gina, with a session and no `approve`.
    let answer = h
        .post(&approve, Some(&gina_session), &body_for(&h, &challenge))
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.code(), "forbidden");

    // Alice's signature over the intent, on alice's session, does.
    let answer = h
        .post(&approve, Some(&alice_session), &body_for(&h, &challenge))
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn an_approval_assertion_opens_no_session() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let session = h.signed_in(&gina).await;
    let request = open_request(&h, &session).await;
    let challenge = super::from_b64(request["challenge"].as_str().unwrap());
    let assertion = h
        .alice
        .assertion(&Ceremony::new(RP_ID, ORIGIN, &challenge))
        .unwrap();
    let answer = h
        .post(
            super::SIGN_IN_FINISH,
            None,
            &json!({ "challenge": super::b64(&challenge), "assertion": assertion_text(&assertion) }),
        )
        .await;
    assert_eq!(answer.code(), "sign_in_refused");
}

#[tokio::test]
async fn a_session_holds_no_power_beyond_its_grants() {
    let h = Harness::new().await;
    let gina = h.registered("gina").await;
    let session = h.signed_in(&gina).await;
    let request = open_request(&h, &session).await;
    assert_eq!(request["can_approve"], false);

    let elsewhere = h
        .post(
            "/api/v1/deployments/other/prod/requests",
            Some(&session),
            &json!({ "tag": "v1.1.0" }),
        )
        .await;
    assert_eq!(elsewhere.status, StatusCode::NOT_FOUND, "{elsewhere:?}");
}
