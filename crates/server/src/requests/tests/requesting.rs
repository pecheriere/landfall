//! Asking for a deploy: what must be true, and what the controller fills in itself.

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_core::protocol::Phase;
use serde_json::json;

use super::{Caller, HOST, Harness, PROD, PROD_REQUESTS, digest, request_of};
use crate::store::{ReleaseDecision, Seen};

#[tokio::test]
async fn the_controller_builds_the_intent_itself() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    let answer = h.ask(&carol, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let view = answer.json();
    let (id, intent) = request_of(&view);
    assert_eq!(intent.deployment.as_ref(), PROD);
    assert_eq!(intent.tag.as_ref(), "v1.1.0");
    assert_eq!(intent.commit.as_ref(), "1".repeat(40));
    assert_eq!(intent.digest, digest('1'));
    assert_eq!(intent.expected_running, Some(digest('0')));
    assert_ne!(intent.nonce, [0; 32]);
    assert_eq!(view["host"], HOST);
    assert_eq!(view["requested_by"], "carol");
    assert_eq!(view["state"], "awaiting_approval");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    // A request isn't a deploy, and the watcher's stay free to go.
    assert_eq!(h.count_deploys().await, 0);
    // The challenge a page would hand a passkey.
    let challenge = URL_SAFE_NO_PAD.encode(intent.challenge());
    assert_eq!(view["challenge"], challenge.as_str());
}

#[tokio::test]
async fn nothing_of_the_intent_comes_from_the_client() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    for extra in [
        "digest",
        "commit",
        "expected_running",
        "nonce",
        "deployment",
        "host",
    ] {
        let mut body = json!({ "tag": "v1.1.0" });
        body[extra] = json!("whatever");
        let answer = h.post(PROD_REQUESTS, &carol, &body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{extra}");
        assert_eq!(answer.code(), "bad_request", "{extra}");
    }
    assert_eq!(h.audited("deploy_requested").await.len(), 0);
}

#[tokio::test]
async fn each_request_has_its_own_nonce() {
    let h = Harness::new().await;
    let (id, first) = h.opened().await;
    h.reports(Some(("v1.0.1", '2'))).await;
    assert_eq!(h.request_state(id).await, "stale");
    let answer = h.ask(&h.token("carol").await, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (_, second) = request_of(&answer.json());
    assert_ne!(first.nonce, second.nonce);
    assert_eq!(second.expected_running, Some(digest('2')));
}

#[tokio::test]
async fn one_open_request_per_deployment() {
    let h = Harness::new().await;
    let (first, _) = h.opened().await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;
    let carol = h.token("carol").await;
    for tag in ["v1.1.0", "v1.2.0"] {
        let answer = h.ask(&carol, tag).await;
        assert_eq!(answer.status, StatusCode::CONFLICT, "{tag}");
        assert_eq!(answer.code(), "request_open", "{tag}");
    }
    assert_eq!(h.request_state(first).await, "awaiting_approval");
    assert_eq!(h.audited("deploy_requested").await.len(), 1);
}

#[tokio::test]
async fn a_request_for_a_release_never_verified_is_refused() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    // Never seen, and not even of the deployment's pattern.
    for tag in ["v9.9.9", "release-1"] {
        let answer = h.ask(&carol, tag).await;
        assert_eq!(answer.status, StatusCode::CONFLICT, "{tag}");
        assert_eq!(answer.code(), "release_not_verified", "{tag}");
    }
    // Not a tag at all.
    let answer = h
        .post(PROD_REQUESTS, &carol, &json!({ "tag": "v1\n" }))
        .await;
    assert_eq!(answer.code(), "bad_request");
    assert_eq!(h.audited("request_refused").await.len(), 3);
}

/// Records what the watcher writes for each of the ways a release isn't settled.
async fn record(
    h: &Harness,
    tag: &str,
    commit: Option<char>,
    digest_of: Option<char>,
    refused: bool,
) {
    let commit = commit.map(|fill| fill.to_string().repeat(40).parse().unwrap());
    let digest_of = digest_of.map(digest);
    let seen = Seen {
        tag_object: "object",
        config_hash: h.config.hash(),
        commit: commit.as_ref(),
        digest: digest_of.as_ref(),
        refused,
        detail: json!({}),
        origin: json!({}),
    };
    let decision = if refused {
        ReleaseDecision::Refused
    } else {
        ReleaseDecision::Manual
    };
    h.store
        .record_release(
            (
                &PROD.parse().unwrap(),
                &HOST.parse().unwrap(),
                &tag.parse().unwrap(),
            ),
            decision,
            "why",
            Some(&seen),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn a_release_verification_refused_or_left_unsettled_is_refused() {
    let h = Harness::new().await;
    h.reports(Some(("v1.0.0", '0'))).await;
    let carol = h.token("carol").await;
    record(&h, "v1.1.0", Some('1'), None, true).await;
    // It verified once, and was refused since: several runs, say. Its digest stays.
    record(&h, "v1.2.0", Some('2'), Some('2'), false).await;
    record(&h, "v1.2.0", Some('2'), None, true).await;
    record(&h, "v1.3.0", None, None, false).await;
    for tag in ["v1.1.0", "v1.2.0", "v1.3.0"] {
        let answer = h.ask(&carol, tag).await;
        assert_eq!(answer.code(), "release_not_verified", "{tag}");
    }

    // On hold, while the watcher waits for its material, or for it to say one run.
    h.verified(PROD, HOST, "v1.4.0", '4').await;
    h.store
        .set_hold(
            (&PROD.parse().unwrap(), &HOST.parse().unwrap()),
            Some(&"v1.4.0".parse().unwrap()),
            "two runs",
            false,
        )
        .await
        .unwrap();
    assert_eq!(h.ask(&carol, "v1.4.0").await.code(), "release_not_verified");
}

#[tokio::test]
async fn a_release_verified_under_another_configuration_waits_for_the_watcher() {
    let h = Harness::new().await;
    h.reports(Some(("v1.0.0", '0'))).await;
    let commit = "1".repeat(40).parse().unwrap();
    let digest_of = digest('1');
    let seen = Seen {
        tag_object: "object",
        config_hash: "another",
        commit: Some(&commit),
        digest: Some(&digest_of),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (
                &PROD.parse().unwrap(),
                &HOST.parse().unwrap(),
                &"v1.1.0".parse().unwrap(),
            ),
            ReleaseDecision::Manual,
            "why",
            Some(&seen),
        )
        .await
        .unwrap();
    let answer = h.ask(&h.token("carol").await, "v1.1.0").await;
    assert_eq!(answer.code(), "release_not_verified");
}

#[tokio::test]
async fn the_rule_refusals_stay_refused() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    // What is running already.
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    assert_eq!(h.ask(&carol, "v1.0.0").await.code(), "release_refused");
    // A pre-release, and the rule doesn't opt in.
    h.verified(PROD, HOST, "v1.2.0-rc.1", '2').await;
    assert_eq!(h.ask(&carol, "v1.2.0-rc.1").await.code(), "release_refused");
}

#[tokio::test]
async fn a_host_that_cannot_take_it_is_told_apart() {
    let h = Harness::new().await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let carol = h.token("carol").await;
    // It has said nothing, so nothing says what must be running.
    assert_eq!(h.ask(&carol, "v1.1.0").await.code(), "host_not_ready");

    for (drift, phase, busy) in [
        (true, Phase::Idle, false),
        (false, Phase::Deploying, true),
        (false, Phase::Deploying, false),
    ] {
        h.reports_state(Some(("v1.0.0", '0')), drift, phase, busy)
            .await;
        assert_eq!(h.ask(&carol, "v1.1.0").await.code(), "host_not_ready");
    }
    h.reports(Some(("v1.0.0", '0'))).await;
    h.store
        .enrol(
            &HOST.parse().unwrap(),
            &h.store
                .issue_enrol_code(&HOST.parse().unwrap(), false)
                .await
                .unwrap()
                .reveal()
                .parse()
                .unwrap(),
            &landfall_core::protocol::SigningKey::from_bytes(&[3; 32]).verifying_key(),
        )
        .await
        .unwrap();
    h.store
        .record_host_state(&HOST.parse().unwrap(), Some(&[1; 32]), &[])
        .await
        .unwrap();
    assert_eq!(h.ask(&carol, "v1.1.0").await.code(), "host_not_ready");
}

#[tokio::test]
async fn a_first_deploy_expects_nothing_running() {
    let h = Harness::new().await;
    h.reports(None).await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let answer = h.ask(&h.token("carol").await, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    assert_eq!(request_of(&answer.json()).1.expected_running, None);
}

#[tokio::test]
async fn a_deployment_with_a_deploy_active_is_busy() {
    let h = Harness::new().await;
    h.ready().await;
    h.verified(PROD, HOST, "v1.0.1", '2').await;
    let mut tx = h.store.begin().await.unwrap();
    h.store
        .queue_deploy(
            &mut tx,
            &crate::store::NewDeploy {
                deployment: PROD.parse().unwrap(),
                host: HOST.parse().unwrap(),
                tag: "v1.0.1".parse().unwrap(),
                digest: digest('2'),
                commit: "2".repeat(40).parse().unwrap(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert_eq!(
        h.ask(&h.token("carol").await, "v1.1.0").await.code(),
        "deployment_busy"
    );
}

#[tokio::test]
async fn a_downgrade_takes_the_rollback_grant() {
    let h = Harness::new().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    // carol may request, not roll back.
    let answer = h.ask(&h.token("carol").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    // erin may roll back, not ask for anything higher.
    let erin = h.token("erin").await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;
    let answer = h.ask(&erin, "v1.2.0").await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    let answer = h.ask(&erin, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    assert_eq!(
        request_of(&answer.json()).1.expected_running,
        Some(digest('1'))
    );
}

const PROMOTION: &str = r#"
[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "host-c"
compose = { dir = "/srv/staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "any", approvers = ["alice"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "1h" }
"#;

pub(super) async fn on_promotion() -> Harness {
    let store = crate::store::Store::open_in_memory().await.unwrap();
    Harness::on(store, PROMOTION)
}

#[tokio::test]
async fn promotion_holds_a_request_as_it_holds_the_watcher() {
    let h = on_promotion().await;
    h.ready().await;
    let carol = h.token("carol").await;
    let answer = h.ask(&carol, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "promotion_pending");

    let state = landfall_core::protocol::RunningState {
        deployment: "app/staging".parse().unwrap(),
        deployed: Some(landfall_core::protocol::DeployedRelease {
            tag: "v1.1.0".parse().unwrap(),
            digest: digest('1'),
        }),
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    let staging = "host-c".parse().unwrap();
    for _ in 0..7 {
        h.store
            .record_host_state(&staging, None, &[&state])
            .await
            .unwrap();
        h.clock.advance(10 * 60);
    }
    h.store
        .record_host_state(&staging, None, &[&state])
        .await
        .unwrap();
    let answer = h.ask(&carol, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
}

#[tokio::test]
async fn a_rollback_does_not_wait_for_promotion() {
    let h = on_promotion().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let answer = h.ask(&h.token("erin").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
}

#[tokio::test]
async fn a_request_for_another_deployment_uses_that_deployments_host() {
    let h = Harness::new().await;
    let state = landfall_core::protocol::RunningState {
        deployment: super::OTHER.parse().unwrap(),
        deployed: None,
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    h.store
        .record_host_state(&"host-b".parse().unwrap(), None, &[&state])
        .await
        .unwrap();
    h.verified(super::OTHER, "host-b", "v2.0.0", '2').await;
    let otto: Caller = h.token("otto").await;
    let answer = h
        .post(
            "/api/v1/deployments/other/prod/requests",
            &otto,
            &json!({ "tag": "v2.0.0" }),
        )
        .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    assert_eq!(answer.json()["host"], "host-b");
}
