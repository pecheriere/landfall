//! Every change and every refusal someone can be held to is in the log, with no secret.

use axum::http::StatusCode;
use landfall_approval::{Expect, verify};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployReportBody, Phase, ReportedOutcome};
use serde_json::{Value, json};

use super::{APPROVALS, Harness, ORIGIN, PROD, PROD_REQUESTS, RP_ID};
use crate::report::BoundedReport;
use crate::store::NewDeploy;

/// Every row's whole text.
async fn all_rows(h: &Harness) -> String {
    let rows: Vec<String> = sqlx::query_scalar(
        "SELECT kind || ' ' || COALESCE(deployment, '') || ' ' || detail FROM audit_events",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    rows.join("\n")
}

#[tokio::test]
async fn every_change_is_audited() {
    let h = Harness::new().await;
    let (token_id, token) = h
        .store
        .create_token(&"alice".parse().unwrap())
        .await
        .unwrap();
    let invite = h
        .store
        .issue_passkey_invite(&"alice".parse().unwrap())
        .await
        .unwrap();
    h.ready().await;
    let holder = super::Caller::Token(token.reveal());
    let asked = h.ask(&holder, "v1.1.0").await;
    let (id, intent) = super::request_of(&asked.json());
    let first = h.audited("deploy_requested").await;
    assert_eq!(first.len(), 1);
    assert_eq!(first[0]["by"]["principal"], "alice");
    assert_eq!(first[0]["by"]["via"], "token");
    assert_eq!(first[0]["by"]["token"], token_id);
    assert_eq!(first[0]["request"], id);
    assert_eq!(first[0]["tag"], "v1.1.0");
    assert_eq!(first[0]["nonce"], hex::encode(intent.nonce));

    let session = h.session("bob").await;
    let answer = h.approve(id, &session, &h.keys.bob, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let approved = h.audited("request_approved").await;
    assert_eq!(approved[0]["approver"], "bob");
    assert_eq!(approved[0]["deploy_id"], answer.json()["deploy_id"]);
    let queued = h.audited("deploy_queued").await;
    assert_eq!(queued[0]["request"], id);

    h.store.revoke_token(token_id).await.unwrap();
    let kinds = h.audit_kinds().await;
    for kind in [
        "token_created",
        "passkey_invite_issued",
        "deploy_requested",
        "request_approved",
        "deploy_queued",
        "token_revoked",
    ] {
        assert!(kinds.iter().any(|k| k == kind), "{kind}: {kinds:?}");
    }

    // Nothing secret anywhere in it.
    let rows = all_rows(&h).await;
    let digits = token.reveal();
    assert!(!rows.contains(&digits), "{rows}");
    assert!(
        !rows.contains(digits.strip_prefix("lf_").unwrap()),
        "{rows}"
    );
    assert!(!rows.contains(&invite.reveal()), "{rows}");
    assert!(!rows.contains(&hex::encode(token.hash())), "{rows}");
    assert!(!rows.contains("signature"), "{rows}");

    // And the chain holds with the new kinds in it.
    let report = h.store.verify_audit().await.unwrap();
    assert_eq!(report.first_bad, None);
}

#[tokio::test]
async fn refusals_by_a_principal_are_audited() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let refused = |rows: Vec<Value>, reason: &str| {
        let row = rows.last().unwrap().clone();
        assert!(
            row["reason"].as_str().unwrap().contains(reason),
            "{reason}: {row}"
        );
        row
    };

    // Asking, with no grant, with a grant and the wrong state, and for what can't be.
    let dave = h.token("dave").await;
    h.ask(&dave, "v1.1.0").await;
    let row = refused(h.audited("request_refused").await, "no grant");
    assert_eq!(row["by"]["principal"], "dave");
    assert_eq!(row["problem"], "forbidden");

    let otto = h.token("otto").await;
    h.ask(&otto, "v1.1.0").await;
    let row = refused(h.audited("request_refused").await, "no grant");
    assert_eq!(row["by"]["principal"], "otto");
    assert_eq!(row["problem"], "not_found");

    let carol = h.token("carol").await;
    h.ask(&carol, "v1.1.0").await;
    let row = refused(h.audited("request_refused").await, "already has a request");
    assert_eq!(row["problem"], "request_open");

    h.post(PROD_REQUESTS, &carol, &json!({ "tag": "v1", "x": 1 }))
        .await;
    refused(h.audited("request_refused").await, "not a valid request");

    let count = h.audited("request_refused").await.len();
    let hostile = "/api/v1/deployments/a%0Ab/%1B%5B31mc/requests";
    h.post(hostile, &otto, &json!({ "tag": "v1.1.0" })).await;
    let rows = h.audited("request_refused").await;
    assert_eq!(rows.len(), count + 1);
    let shown = rows.last().unwrap()["about"].as_str().unwrap().to_owned();
    assert!(shown.starts_with('"'), "{shown}");
    assert!(!shown.contains('\u{1b}'), "{shown}");
    assert!(!shown.contains('\n'), "{shown}");

    // Approving: a token, a person who can't, and a bad assertion.
    let token = h.token("alice").await;
    h.approve(id, &token, &h.keys.alice, &intent).await;
    let row = refused(h.audited("approval_refused").await, "no grant");
    assert_eq!(row["by"]["via"], "token");
    assert_eq!(row["request"], id);

    let alice = h.session("alice").await;
    h.approve(id, &alice, &h.keys.bob, &intent).await;
    let row = refused(h.audited("approval_refused").await, "credential id");
    assert_eq!(row["by"]["via"], "session");
    assert_eq!(row["problem"], "assertion_refused");

    // Hostile bytes in an assertion's text come out escaped.
    let mut body = super::assertion_body(&h.keys.alice, &intent);
    let evil = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        "{\"type\":\"webauthn.get\",\"challenge\":\"\u{1b}[31m\",\"origin\":\"x\"}",
    );
    body["assertion"]["client_data_json"] = json!(evil);
    h.post(&format!("{APPROVALS}/{id}"), &alice, &body).await;
    let rows = all_rows(&h).await;
    assert!(!rows.contains('\u{1b}'), "{rows}");

    assert_eq!(h.request_state(id).await, "awaiting_approval");
    let report = h.store.verify_audit().await.unwrap();
    assert_eq!(report.first_bad, None);
}

/// The reason of a real `verify` refusal of an assertion claiming `origin`.
fn verify_error(h: &Harness, intent: &DeployIntent, origin: &str) -> String {
    let mut lying = super::ceremony(intent);
    lying.origin = origin.to_owned();
    let assertion = h.keys.alice.assertion(&lying).unwrap();
    let error = verify(
        &assertion,
        &Expect {
            key: &h.keys.alice.key().unwrap(),
            credential_id: h.keys.alice.credential_id(),
            rp_id: RP_ID,
            origin: ORIGIN,
            challenge: &intent.challenge(),
        },
    )
    .unwrap_err();
    format!("approval refused: {error}")
}

/// A host refuses one deploy with `reason`, and this gives the audit row's reason.
async fn deploy_refused_row(h: &Harness, tag: &str, fill: char, reason: String) -> String {
    h.verified(PROD, super::HOST, tag, fill).await;
    let deploy = NewDeploy {
        deployment: PROD.parse().unwrap(),
        host: super::HOST.parse().unwrap(),
        tag: tag.parse().unwrap(),
        digest: super::digest(fill),
        commit: fill.to_string().repeat(40).parse().unwrap(),
    };
    let mut tx = h.store.begin().await.unwrap();
    let id = h.store.queue_deploy(&mut tx, &deploy).await.unwrap();
    tx.commit().await.unwrap();
    let host = super::HOST.parse().unwrap();
    assert!(h.store.next_work(&host).await.unwrap().work.is_some());
    let report = BoundedReport::new(&DeployReportBody {
        deploy_id: id,
        deployment: deploy.deployment,
        tag: deploy.tag,
        digest: deploy.digest,
        outcome: ReportedOutcome::Refused { reason },
        steps: Vec::new(),
    });
    h.store.finish_deploy(&host, &report).await.unwrap();
    let rows = h.audited("deploy_refused").await;
    rows.last().unwrap()["reason"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn origins_differing_late_read_differently_in_both_audit_rows() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // 240 characters each, differing only in the last: as much as the verifier keeps of one
    // is 255, and its own words and the configured origin come first.
    let origin = |last: char| format!("https://{}{last}", "a".repeat(231));
    let (first, second) = (origin('x'), origin('y'));

    let alice = h.session("alice").await;
    let mut seen = Vec::new();
    for claimed in [&first, &second] {
        let mut lying = super::ceremony(&intent);
        lying.origin.clone_from(claimed);
        let body = super::body_of(&h.keys.alice, &lying);
        let answer = h.post(&format!("{APPROVALS}/{id}"), &alice, &body).await;
        assert_eq!(answer.code(), "assertion_refused");
        let rows = h.audited("approval_refused").await;
        seen.push(rows.last().unwrap()["reason"].as_str().unwrap().to_owned());
    }
    assert_ne!(seen[0], seen[1]);
    assert!(seen[0].contains(first.as_str()), "{}", seen[0]);
    assert!(seen[1].contains(second.as_str()), "{}", seen[1]);

    let one = verify_error(&h, &intent, &first);
    let other = verify_error(&h, &intent, &second);
    let one = deploy_refused_row(&h, "v1.0.1", '2', one).await;
    let other = deploy_refused_row(&h, "v1.0.2", '3', other).await;
    assert_ne!(one, other);
    assert!(one.contains(first.as_str()), "{one}");
    assert!(other.contains(second.as_str()), "{other}");
}

#[tokio::test]
async fn staleness_and_expiry_are_audited() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    h.reports_state(Some(("v1.0.1", '2')), false, Phase::Idle, false)
        .await;
    let stale = h.audited("request_stale").await;
    assert_eq!(stale[0]["request"], id);
    assert!(
        stale[0]["reason"]
            .as_str()
            .unwrap()
            .contains("running digest")
    );

    let token = h.token("alice").await;
    let asked = h.ask(&token, "v1.1.0").await;
    let (second, _) = super::request_of(&asked.json());
    h.clock.advance(crate::store::REQUEST_LIFETIME_SECS);
    h.reports_state(Some(("v1.0.1", '2')), false, Phase::Idle, false)
        .await;
    h.ask(&token, "v1.1.0").await;
    let expired = h.audited("request_expired").await;
    assert_eq!(expired[0]["request"], second);
}

#[tokio::test]
async fn a_row_names_the_deployment_and_host_only_when_they_are_real() {
    let h = Harness::new().await;
    h.ready().await;
    let otto = h.token("otto").await;
    h.ask(&otto, "v1.1.0").await;
    let rows: Vec<(Option<String>, Option<String>)> =
        sqlx::query_as("SELECT deployment, host FROM audit_events WHERE kind = 'request_refused'")
            .fetch_all(h.store.pool())
            .await
            .unwrap();
    assert_eq!(
        rows,
        [(Some(PROD.to_owned()), Some(super::HOST.to_owned()))]
    );

    h.post(
        "/api/v1/deployments/no/such/requests",
        &otto,
        &json!({ "tag": "v1" }),
    )
    .await;
    let rows: Vec<(Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT deployment, host FROM audit_events WHERE kind = 'request_refused' ORDER BY seq DESC",
    )
    .fetch_all(h.store.pool())
    .await
    .unwrap();
    assert_eq!(rows[0], (None, None));
}
