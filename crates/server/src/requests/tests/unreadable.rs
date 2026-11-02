//! One request row nothing can read: only a database writer, corruption or a stricter
//! parser later on can make one, and it must cost that row and nothing else.

use axum::http::{Method, StatusCode};
use landfall_core::protocol::{
    DeployId, DeployReportBody, DeployedRelease, Phase, ReportedOutcome, RunningState,
};
use serde_json::json;

use super::{APPROVALS, HOST, Harness, OTHER, PROD, digest, request_of};
use crate::report::BoundedReport;
use crate::store::{NewDeploy, REQUEST_LIFETIME_SECS, StoreError};

/// Sets one column of a request to what its parser refuses.
async fn spoil(h: &Harness, id: i64, assignment: &str) {
    let statement = format!("UPDATE deploy_requests SET {assignment} WHERE id = ?");
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(id)
        .execute(h.store.pool())
        .await
        .unwrap();
}

const BAD_ASKER: &str = "requested_by = 'not a principal!'";

/// `otto` opens a request on `other/prod`, which runs on `host-b`, and it is spoiled.
async fn spoiled_on_other(h: &Harness) -> i64 {
    let state = RunningState {
        deployment: OTHER.parse().unwrap(),
        deployed: None,
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    h.store
        .record_host_state(&"host-b".parse().unwrap(), None, &[&state])
        .await
        .unwrap();
    h.verified(OTHER, "host-b", "v2.0.0", '2').await;
    let answer = h
        .post(
            "/api/v1/deployments/other/prod/requests",
            &h.token("otto").await,
            &json!({ "tag": "v2.0.0" }),
        )
        .await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (id, _) = request_of(&answer.json());
    spoil(h, id, BAD_ASKER).await;
    id
}

/// `host-a` deploys `tag`, and reports it `deployed`, which is what stales a request.
async fn host_a_deploys(h: &Harness, tag: &str, fill: char) {
    h.verified(PROD, HOST, tag, fill).await;
    let deploy = NewDeploy {
        deployment: PROD.parse().unwrap(),
        host: HOST.parse().unwrap(),
        tag: tag.parse().unwrap(),
        digest: digest(fill),
        commit: fill.to_string().repeat(40).parse().unwrap(),
    };
    let mut tx = h.store.begin().await.unwrap();
    let id: DeployId = h.store.queue_deploy(&mut tx, &deploy).await.unwrap();
    tx.commit().await.unwrap();
    let host = HOST.parse().unwrap();
    assert!(h.store.next_work(&host).await.unwrap().work.is_some());
    let report = BoundedReport::new(&DeployReportBody {
        deploy_id: id,
        deployment: deploy.deployment,
        tag: deploy.tag,
        digest: deploy.digest,
        outcome: ReportedOutcome::Deployed {},
        steps: Vec::new(),
    });
    h.store.finish_deploy(&host, &report).await.unwrap();
}

#[tokio::test]
async fn one_past_its_time_on_another_deployment_costs_a_report_nothing() {
    let h = Harness::new().await;
    h.reports(Some(("v1.0.0", '0'))).await;
    let spoiled = spoiled_on_other(&h).await;
    h.clock.advance(REQUEST_LIFETIME_SECS);

    // A report that finishes a deploy, and a poll with a moved running state.
    host_a_deploys(&h, "v1.0.1", '2').await;
    h.reports(Some(("v1.0.1", '2'))).await;
    h.reports(Some(("v1.0.2", '3'))).await;
    // A report is about its own deployment, and looks at nobody else's row.
    assert_eq!(h.request_state(spoiled).await, "awaiting_approval");
    assert_eq!(h.audited("request_expired").await.len(), 0);

    // Nor does the row stand in the way of what anyone asks of another deployment.
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(asked.status, StatusCode::CREATED, "{asked:?}");
    assert_eq!(h.request_state(spoiled).await, "expired");
    let (id, intent) = request_of(&asked.json());
    let cancel = format!("{APPROVALS}/{id}/cancel");
    let bob = h.session("bob").await;
    let cancelled = h.call(Method::POST, &cancel, &bob, Vec::new()).await;
    assert_eq!(cancelled.status, StatusCode::OK, "{cancelled:?}");
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    let (id, intent_now) = request_of(&asked.json());
    assert_ne!(intent.nonce, intent_now.nonce);
    let answer = h.approve(id, &bob, &h.keys.bob, &intent_now).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn the_tick_ends_one_and_audits_what_it_says_escaped_and_cut() {
    for assignment in [
        BAD_ASKER,
        "digest = 'not a digest\n\u{1b}[31m'",
        "expected_running = 'no'",
        "host = 'not a\nhost'",
        "commit_sha = 'x'",
        "digest = CAST(x'ff00' AS TEXT)",
    ] {
        let h = Harness::new().await;
        let (id, _) = h.opened().await;
        spoil(&h, id, assignment).await;
        h.clock.advance(REQUEST_LIFETIME_SECS);
        h.store.settle_expired_requests().await.unwrap();
        assert_eq!(h.request_state(id).await, "expired", "{assignment}");
        let rows = h.audited("request_expired").await;
        assert_eq!(rows.len(), 1, "{assignment}");
        assert_eq!(rows[0]["request"], id);
        assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
        let text = rows[0].to_string();
        assert!(!text.contains('\u{1b}'), "{text}");
    }
}

#[tokio::test]
async fn a_row_says_a_long_bad_value_quoted_and_cut_and_leaves_out_a_bad_host() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    let long = "x\n".repeat(5000);
    spoil(&h, id, &format!("digest = '{long}'")).await;
    spoil(&h, id, "host = 'not a\nhost'").await;
    h.clock.advance(REQUEST_LIFETIME_SECS);
    h.store.settle_expired_requests().await.unwrap();

    let rows = h.audited("request_expired").await;
    let shown = rows[0]["digest"].as_str().unwrap();
    assert!(shown.starts_with("\"x\\n"), "{shown}");
    assert!(shown.ends_with("\"..."), "{shown}");
    assert!(shown.len() < 200, "{shown}");
    assert!(rows[0]["host"].as_str().unwrap().starts_with('"'));
    // Columns the chain and queries go by only ever hold what is valid.
    let columns: (Option<String>, Option<String>) =
        sqlx::query_as("SELECT deployment, host FROM audit_events WHERE kind = 'request_expired'")
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(columns, (Some(PROD.to_owned()), None));
}

#[tokio::test]
async fn the_list_goes_without_it() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    let spoiled = spoiled_on_other(&h).await;
    let alice = h.session("alice").await;
    let list = h.list(&alice).await;
    assert_eq!(list.status, StatusCode::OK, "{list:?}");
    let shown = list.json();
    assert_eq!(shown["approvals"].as_array().unwrap().len(), 1);
    assert_eq!(shown["approvals"][0]["id"], id);
    // Its own deployment's list too.
    let otto = h.list(&h.token("otto").await).await;
    assert_eq!(otto.status, StatusCode::OK, "{otto:?}");
    assert_eq!(otto.json()["approvals"], json!([]));
    assert_eq!(h.request_state(spoiled).await, "awaiting_approval");
}

#[tokio::test]
async fn its_own_id_gets_a_clear_problem_for_who_may_know_of_it() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    spoil(&h, id, BAD_ASKER).await;
    let alice = h.session("alice").await;
    let approve = h.approve(id, &alice, &h.keys.alice, &intent).await;
    let cancel = format!("{APPROVALS}/{id}/cancel");
    let cancelled = h.call(Method::POST, &cancel, &alice, Vec::new()).await;
    for answer in [&approve, &cancelled] {
        assert_eq!(
            answer.status,
            StatusCode::INTERNAL_SERVER_ERROR,
            "{answer:?}"
        );
        assert_eq!(answer.code(), "request_unreadable");
        assert!(!answer.text().contains("not a principal"), "{answer:?}");
    }
    assert_eq!(h.audited("approval_refused").await[0]["request"], id);
    assert_eq!(h.audited("cancel_refused").await[0]["request"], id);
    assert_eq!(h.count_deploys().await, 0);

    // Someone with no grant there is told what they are of a row that isn't there.
    let otto = h.session("otto").await;
    let hidden = h.approve(id, &otto, &h.keys.zoe, &intent).await;
    let absent = h.approve(id + 1, &otto, &h.keys.zoe, &intent).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(hidden.body, absent.body);
}

#[tokio::test]
async fn a_change_on_its_own_deployment_still_records_the_report() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    spoil(&h, id, BAD_ASKER).await;
    h.reports(Some(("v1.0.1", '2'))).await;
    assert_eq!(h.request_state(id).await, "stale");
    assert_eq!(h.audited("request_stale").await[0]["request"], id);
    let digest_now: String =
        sqlx::query_scalar("SELECT digest FROM running_states WHERE deployment = ?")
            .bind(PROD)
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(digest_now, digest('2').as_ref());

    // So does a finished deploy, and when it is past its time as well.
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    spoil(&h, id, BAD_ASKER).await;
    host_a_deploys(&h, "v1.0.1", '2').await;
    assert_eq!(h.request_state(id).await, "stale");

    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    spoil(&h, id, BAD_ASKER).await;
    h.clock.advance(REQUEST_LIFETIME_SECS);
    let state = RunningState {
        deployment: PROD.parse().unwrap(),
        deployed: Some(DeployedRelease {
            tag: "v1.0.1".parse().unwrap(),
            digest: digest('2'),
        }),
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    h.store
        .record_host_state(&HOST.parse().unwrap(), None, &[&state])
        .await
        .unwrap();
    assert_eq!(h.request_state(id).await, "expired");
}

#[tokio::test]
async fn a_rollback_can_still_take_its_place() {
    let h = Harness::new().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;
    let asked = h.ask(&h.token("carol").await, "v1.2.0").await;
    let (id, _) = request_of(&asked.json());
    spoil(&h, id, BAD_ASKER).await;
    let answer = h.ask(&h.token("erin").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    assert_eq!(h.request_state(id).await, "cancelled");
    assert_eq!(h.audited("request_cancelled").await[0]["request"], id);
}

#[tokio::test]
async fn an_error_names_the_row_and_not_only_the_column() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    spoil(&h, id, BAD_ASKER).await;
    let error = h.store.request(id).await.unwrap_err();
    assert!(
        matches!(error, StoreError::UnreadableRequest { id: named, .. } if named == id),
        "{error}"
    );
    let text = error.to_string();
    assert!(text.contains(&id.to_string()), "{text}");
    assert!(text.contains("requested_by"), "{text}");
    // Bytes that aren't text are the same case, not a failure of the database.
    spoil(&h, id, "digest = CAST(x'ff00' AS TEXT)").await;
    let error = h.store.request(id).await.unwrap_err();
    assert!(
        matches!(error, StoreError::UnreadableRequest { .. }),
        "{error}"
    );
}
