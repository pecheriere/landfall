//! Approving: a fresh assertion, by this principal, for exactly this intent.

use axum::http::StatusCode;
use landfall_approval::{Assertion, CoseKey, Expect, verify};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployReportBody, ReportedOutcome};
use serde_json::{Value, json};

use super::{APPROVALS, HOST, Harness, ORIGIN, PROD, RP_ID, body_of, ceremony, digest, request_of};
use crate::report::BoundedReport;

#[tokio::test]
async fn approval_needs_a_fresh_assertion_by_this_principal() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;

    // No assertion at all.
    let path = format!("{APPROVALS}/{id}");
    let answer = h.post(&path, &alice, &json!({})).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{answer:?}");
    // The session alone proves nothing: another approver's passkey for this very intent.
    let answer = h.approve(id, &alice, &h.keys.bob, &intent).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "assertion_refused");
    // Another approver's credential id on alice's signature.
    let mut named = ceremony(&intent);
    named.credential_id = Some(h.keys.bob.credential_id().to_vec());
    let answer = h.post(&path, &alice, &body_of(&h.keys.alice, &named)).await;
    assert_eq!(answer.code(), "assertion_refused");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);

    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert!(answer.json()["deploy_id"].as_u64().is_some());
    assert_eq!(h.request_state(id).await, "approved");
    assert_eq!(h.count_deploys().await, 1);
}

#[tokio::test]
async fn assertion_for_another_intent_is_refused_by_the_controller_too() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    let path = format!("{APPROVALS}/{id}");

    let others = [
        DeployIntent {
            nonce: [9; 32],
            ..intent.clone()
        },
        DeployIntent {
            tag: "v1.2.0".parse().unwrap(),
            ..intent.clone()
        },
        DeployIntent {
            deployment: super::OTHER.parse().unwrap(),
            ..intent.clone()
        },
        DeployIntent {
            digest: digest('e'),
            ..intent.clone()
        },
        DeployIntent {
            expected_running: None,
            ..intent.clone()
        },
    ];
    for other in &others {
        let answer = h.approve(id, &alice, &h.keys.alice, other).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{other:?}");
        assert_eq!(answer.code(), "assertion_refused", "{other:?}");
    }
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    // Everything else about the ceremony is the host's list too.
    let mut bad_origin = ceremony(&intent);
    bad_origin.origin = "https://evil.example".to_owned();
    let mut bad_rp = ceremony(&intent);
    bad_rp.rp_id = "evil.example".to_owned();
    let mut no_presence = ceremony(&intent);
    no_presence.flags = Some(0);
    for bad in [bad_origin, bad_rp, no_presence] {
        let answer = h.post(&path, &alice, &body_of(&h.keys.alice, &bad)).await;
        assert_eq!(answer.code(), "assertion_refused", "{bad:?}");
    }
    assert_eq!(h.count_deploys().await, 0);
}

#[tokio::test]
async fn the_queued_row_carries_what_the_host_verifies() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let deploy_id = answer.json()["deploy_id"].as_u64().unwrap();

    let host = HOST.parse().unwrap();
    let pick = h.store.next_work(&host).await.unwrap();
    let work = pick.work.unwrap();
    assert_eq!(work.deploy_id.0, deploy_id);
    assert_eq!(work.tag, intent.tag);
    assert_eq!(work.digest, intent.digest);
    assert_eq!(work.commit, intent.commit);
    let approval = work.approval.as_ref().unwrap();
    assert_eq!(approval.intent, intent);
    // Exactly what the host checks, as it checks it.
    let assertion = Assertion::try_from(&approval.assertion).unwrap();
    verify(
        &assertion,
        &Expect {
            key: &CoseKey::parse(h.keys.alice.key().unwrap().as_bytes()).unwrap(),
            credential_id: h.keys.alice.credential_id(),
            rp_id: RP_ID,
            origin: ORIGIN,
            challenge: &intent.challenge(),
        },
    )
    .unwrap();
    // A delivery lost on the way comes again under the same number, as it was.
    let again = h.store.next_work(&host).await.unwrap().work.unwrap();
    assert_eq!(again, work);
}

#[tokio::test]
async fn an_automatic_deploy_carries_none() {
    let h = Harness::new().await;
    h.ready().await;
    let mut tx = h.store.begin().await.unwrap();
    h.store
        .queue_deploy(
            &mut tx,
            &crate::store::NewDeploy {
                deployment: PROD.parse().unwrap(),
                host: HOST.parse().unwrap(),
                tag: "v1.1.0".parse().unwrap(),
                digest: digest('1'),
                commit: "1".repeat(40).parse().unwrap(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    let work = h
        .store
        .next_work(&HOST.parse().unwrap())
        .await
        .unwrap()
        .work;
    assert_eq!(work.unwrap().approval, None);
}

#[tokio::test]
async fn the_database_refuses_half_an_approval_and_a_second_deploy_of_a_request() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    h.approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    let insert = |approval: Option<&'static str>, request: Option<i64>| {
        sqlx::query(
            "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, outcome,
                                  created_at, approval, request_id)
             SELECT deployment, host, tag, digest, commit_sha, 'finished', 'refused', 0, ?, ?
             FROM deploys LIMIT 1",
        )
        .bind(approval)
        .bind(request)
        .execute(h.store.pool())
    };
    assert!(insert(Some("{}"), None).await.is_err());
    assert!(insert(None, Some(id)).await.is_err());
    assert!(insert(Some("{}"), Some(id)).await.is_err());
}

/// What a host says of a deploy of `intent`.
fn report(deploy_id: u64, intent: &DeployIntent, outcome: ReportedOutcome) -> BoundedReport {
    BoundedReport::new(&DeployReportBody {
        deploy_id: landfall_core::protocol::DeployId(deploy_id),
        deployment: intent.deployment.clone(),
        tag: intent.tag.clone(),
        digest: intent.digest.clone(),
        outcome,
        steps: Vec::new(),
    })
}

#[tokio::test]
async fn a_retry_after_a_host_refused_takes_a_new_number_and_a_new_nonce() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    let first = h.approve(id, &alice, &h.keys.alice, &intent).await.json();
    let first_deploy = first["deploy_id"].as_u64().unwrap();
    let host = HOST.parse().unwrap();
    assert!(h.store.next_work(&host).await.unwrap().work.is_some());
    let outcome = ReportedOutcome::Refused {
        reason: "approval refused: whatever the reason".to_owned(),
    };
    h.store
        .finish_deploy(&host, &report(first_deploy, &intent, outcome))
        .await
        .unwrap();
    // Nothing goes round again by itself, and nothing can be approved twice.
    assert_eq!(h.store.next_work(&host).await.unwrap().work, None);
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "request_closed");

    // Asking again is a new intent, which a new assertion signs, under a new number.
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(asked.status, StatusCode::CREATED, "{asked:?}");
    let (second_id, second) = request_of(&asked.json());
    assert_ne!(second_id, id);
    assert_ne!(second.nonce, intent.nonce);
    assert_eq!(second.expected_running, intent.expected_running);

    let old = h.approve(second_id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(old.code(), "assertion_refused");
    let answer = h.approve(second_id, &alice, &h.keys.alice, &second).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let second_deploy = answer.json()["deploy_id"].as_u64().unwrap();
    assert!(second_deploy > first_deploy);
    let work = h.store.next_work(&host).await.unwrap().work.unwrap();
    assert_eq!(work.deploy_id.0, second_deploy);
    assert_eq!(work.approval.unwrap().intent, second);
}

#[tokio::test]
async fn approving_while_a_deploy_is_active_leaves_the_request_open() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
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

    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "deployment_busy");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}

#[tokio::test]
async fn approving_for_a_host_that_cannot_take_it_leaves_the_request_open() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    h.reports_state(
        Some(("v1.0.0", '0')),
        true,
        landfall_core::protocol::Phase::Idle,
        false,
    )
    .await;
    let alice = h.session("alice").await;
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.code(), "host_not_ready");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    h.reports(Some(("v1.0.0", '0'))).await;
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_request_past_its_time_cannot_be_approved_and_the_next_can_be_made() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    h.clock.advance(crate::store::REQUEST_LIFETIME_SECS);

    assert_eq!(
        h.list(&h.session("alice").await).await.json()["approvals"],
        json!([])
    );
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "request_expired");
    assert_eq!(h.request_state(id).await, "expired");
    assert_eq!(h.audited("request_expired").await.len(), 1);

    // Another one that nobody tried to approve doesn't keep the next one out.
    h.reports(Some(("v1.0.0", '0'))).await;
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    let (next, _) = request_of(&asked.json());
    h.clock.advance(crate::store::REQUEST_LIFETIME_SECS);
    h.reports(Some(("v1.0.0", '0'))).await;
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(asked.status, StatusCode::CREATED, "{asked:?}");
    assert_eq!(h.request_state(next).await, "expired");
}

#[tokio::test]
async fn an_approval_is_bounded_before_it_is_parsed_and_field_by_field() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    let path = format!("{APPROVALS}/{id}");

    let big = vec![b'x'; 2 * 1024 * 1024];
    let answer = h.call(axum::http::Method::POST, &path, &alice, big).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE, "{answer:?}");
    assert_eq!(answer.code(), "body_too_large");

    // Within the body's limit and past one field's.
    let mut body: Value = super::assertion_body(&h.keys.alice, &intent);
    body["assertion"]["signature"] = json!("A".repeat(4096));
    let answer = h.post(&path, &alice, &body).await;
    assert_eq!(answer.code(), "assertion_refused");

    // Not an assertion, a field too many, one too few.
    for bad in [
        json!({ "assertion": {} }),
        json!({ "assertion": "x" }),
        {
            let mut more = super::assertion_body(&h.keys.alice, &intent);
            more["extra"] = json!(1);
            more
        },
        {
            let mut more = super::assertion_body(&h.keys.alice, &intent);
            more["assertion"]["extra"] = json!(1);
            more
        },
    ] {
        let answer = h.post(&path, &alice, &bad).await;
        assert_eq!(answer.code(), "bad_request", "{bad}");
    }
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}
