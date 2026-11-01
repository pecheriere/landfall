use axum::http::StatusCode;
use landfall_core::protocol::{
    DeployId, DeployReportBody, MAX_BODY_BYTES, Phase, ReportedCheck, ReportedDetail,
    ReportedOutcome, ReportedStep, RunningState, WorkRequest,
};
use sqlx::Row as _;

use super::{Harness, WORK, deployed_report};
use crate::audit::MAX_DETAIL_BYTES;
use crate::report::{MAX_STORED_CHECKS, MAX_STORED_STEPS};

const A: &str = "host-a";
const B: &str = "host-b";

fn step(name: &str, failure: Option<&str>, detail: Option<ReportedDetail>) -> ReportedStep {
    ReportedStep {
        name: name.to_owned(),
        millis: 12,
        failure: failure.map(str::to_owned),
        detail,
    }
}

/// `host-a` enrolled, with a deploy of `app/prod` claimed.
async fn claimed(h: &Harness) -> (landfall_core::protocol::SigningKey, DeployId) {
    let a = h.enrolled(A, 1).await;
    let id = h.queue("app/prod", A, "v1.0.1").await;
    let work = h.work(A, &a, Vec::new()).await.work().work.unwrap();
    assert_eq!(work.deploy_id, id);
    (a, id)
}

#[tokio::test]
async fn a_report_finishes_the_deploy_and_stores_its_steps() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::RolledBack {
            reason: "health check failed".to_owned(),
        },
        steps: vec![
            step("pull", None, None),
            step(
                "checks",
                Some("unhealthy"),
                Some(ReportedDetail::Checks {
                    checks: vec![ReportedCheck {
                        check: "http 200".to_owned(),
                        attempts: 3,
                        millis: 1500,
                    }],
                }),
            ),
        ],
    };
    let answer = h.report(A, &a, &report).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");

    let row = sqlx::query("SELECT state, outcome, reason, finished_at FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("state"), "finished");
    assert_eq!(row.get::<String, _>("outcome"), "rolled_back");
    assert_eq!(row.get::<String, _>("reason"), "\"health check failed\"");
    assert_eq!(row.get::<i64, _>("finished_at"), 1_800_000_000);

    let steps = sqlx::query("SELECT * FROM deploy_steps ORDER BY position")
        .fetch_all(h.store.pool())
        .await
        .unwrap();
    assert_eq!(steps.len(), 2);
    assert_eq!(steps[0].get::<String, _>("name"), "\"pull\"");
    assert_eq!(steps[0].get::<Option<String>, _>("failure"), None);
    assert_eq!(steps[1].get::<i64, _>("millis"), 12);
    assert_eq!(steps[1].get::<String, _>("failure"), "\"unhealthy\"");
    let detail: serde_json::Value =
        serde_json::from_str(&steps[1].get::<String, _>("detail")).unwrap();
    assert_eq!(detail["checks"][0]["check"], "\"http 200\"");

    // The log names every step.
    let audit = h.last_audit_detail().await;
    assert_eq!(audit["outcome"], "rolled_back");
    assert_eq!(audit["steps"][0]["name"], "\"pull\"");
    assert_eq!(audit["steps"][1]["failure"], "\"unhealthy\"");
}

#[tokio::test]
async fn report_for_another_hosts_deploy_is_refused() {
    let h = Harness::new().await;
    let (_a, id) = claimed(&h).await;
    let b = h.enrolled(B, 2).await;
    let before = h.audit_kinds().await;

    let answer = h.report(B, &b, &deployed_report(id)).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
    assert_eq!(answer.code(), "unknown_deploy");

    let state: String = sqlx::query_scalar("SELECT state FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "claimed");

    // A signer can be held to this: on the record, under its name.
    let kinds = h.audit_kinds().await;
    assert_eq!(kinds[..before.len()], before);
    assert_eq!(kinds[before.len()..], ["report_refused"]);
    let row =
        sqlx::query("SELECT host, deployment, detail FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(row.get::<String, _>("host"), B);
    assert_eq!(row.get::<String, _>("deployment"), "app/prod");
    let detail = h.last_audit_detail().await;
    assert_eq!(detail["deploy_id"], id.0);
    assert_eq!(detail["reason"], "another host's deploy");
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);

    // The answer is the one for a deploy that does not exist: no probing.
    let missing = h.report(B, &b, &deployed_report(DeployId(999))).await;
    assert_eq!(missing.status, answer.status);
    assert_eq!(missing.body, answer.body);
    assert_eq!(h.last_audit_detail().await["reason"], "no such deploy");
}

/// The configuration has no cap on checks, and a refused report leaves the
/// deploy claimed, which blocks the host. So any number is accepted, and what is
/// stored is bounded.
#[tokio::test]
async fn a_step_with_many_checks_finishes_the_deploy() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    let check = ReportedCheck {
        check: "c".to_owned(),
        attempts: 1,
        millis: 1,
    };
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::Deployed {},
        steps: vec![step(
            "checks",
            None,
            Some(ReportedDetail::Checks {
                checks: vec![check; MAX_STORED_CHECKS + 1],
            }),
        )],
    };
    let answer = h.report(A, &a, &report).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");
    let state: String = sqlx::query_scalar("SELECT state FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "finished");
    assert_eq!(h.last_audit_detail().await["checks_dropped"], 1);
}

#[tokio::test]
async fn a_long_reason_is_kept_in_the_tables_and_short_in_the_log() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    let long = format!("{}cause", "x".repeat(900));
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::RolledBack {
            reason: long.clone(),
        },
        steps: vec![step("checks", Some(&long), None)],
    };
    assert_eq!(
        h.report(A, &a, &report).await.status,
        StatusCode::NO_CONTENT
    );
    let quoted = format!("{long:?}");
    let reason: String = sqlx::query_scalar("SELECT reason FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(reason, quoted);
    let failure: String = sqlx::query_scalar("SELECT failure FROM deploy_steps")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(failure, quoted);

    let audit = h.last_audit_detail().await;
    assert_eq!(audit["reason"], format!("\"{}\"...", "x".repeat(64)));
    assert_eq!(
        audit["steps"][0]["failure"],
        format!("\"{}\"...", "x".repeat(64))
    );
}

#[tokio::test]
async fn an_out_of_range_deploy_id_is_refused() {
    let h = Harness::new().await;
    let (a, _id) = claimed(&h).await;
    for id in [u64::MAX, u64::try_from(i64::MAX).unwrap() + 1] {
        let answer = h.report(A, &a, &deployed_report(DeployId(id))).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{id}");
        assert_eq!(answer.code(), "unknown_deploy", "{id}");
    }
    // The largest that fits is just another id with no deploy.
    let largest = DeployId(u64::try_from(i64::MAX).unwrap());
    assert_eq!(
        h.report(A, &a, &deployed_report(largest)).await.code(),
        "unknown_deploy"
    );
}

#[tokio::test]
async fn a_deploy_never_handed_out_cannot_be_reported() {
    let h = Harness::new().await;
    let a = h.enrolled(A, 1).await;
    let id = h.queue("app/prod", A, "v1.0.1").await;

    let answer = h.report(A, &a, &deployed_report(id)).await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(answer.code(), "not_claimed");
    let state: String = sqlx::query_scalar("SELECT state FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(state, "queued");
}

#[tokio::test]
async fn report_is_idempotent() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::Deployed {},
        steps: vec![step("pull", None, None)],
    };
    let first = h.report(A, &a, &report).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT);
    let log = h.audit_kinds().await;

    // The same report again, as after a lost acknowledgement.
    let again = h.report(A, &a, &report).await;
    assert_eq!(again.status, StatusCode::NO_CONTENT);
    assert_eq!(h.audit_kinds().await, log);
    assert_eq!(h.count("deploy_steps").await, 1);

    // A different one changes nothing: the first report stands.
    let differing = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::RollbackFailed {
            reason: "x".to_owned(),
            rollback_reason: "y".to_owned(),
        },
        steps: vec![step("a", None, None), step("b", None, None)],
    };
    assert_eq!(
        h.report(A, &a, &differing).await.status,
        StatusCode::NO_CONTENT
    );
    let outcome: String = sqlx::query_scalar("SELECT outcome FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(outcome, "deployed");
    assert_eq!(h.audit_kinds().await, log);
    assert_eq!(h.count("deploy_steps").await, 1);
}

#[tokio::test]
async fn a_refusal_has_its_own_audit_kind_and_finishes_the_deploy() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::Refused {
            reason: "minor release under a patch rule".to_owned(),
        },
        steps: Vec::new(),
    };
    assert_eq!(
        h.report(A, &a, &report).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        h.audit_kinds().await.last().map(String::as_str),
        Some("deploy_refused")
    );
    let audit = h.last_audit_detail().await;
    assert_eq!(audit["outcome"], "refused");
    assert_eq!(audit["reason"], "\"minor release under a patch rule\"");

    // The deployment is free for what comes next.
    let outcome: String =
        sqlx::query_scalar("SELECT outcome FROM deploys WHERE state = 'finished'")
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert_eq!(outcome, "refused");
    h.queue("app/prod", A, "v1.0.2").await;
}

#[tokio::test]
async fn the_largest_hostile_report_is_accepted_and_stored_bounded() {
    let h = Harness::new().await;
    let (a, id) = claimed(&h).await;
    // Under the body limit, past every storage limit, in the widest text a
    // quoted form can have.
    let text = "\u{10ffff}".repeat(200);
    let checks = vec![
        ReportedCheck {
            check: text.clone(),
            attempts: u32::MAX,
            millis: u64::MAX,
        };
        4
    ];
    let hostile = ReportedStep {
        name: text.clone(),
        millis: u64::MAX,
        failure: Some(text.clone()),
        detail: Some(ReportedDetail::Checks { checks }),
    };
    let report = DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::RollbackFailed {
            reason: text.clone(),
            rollback_reason: text.clone(),
        },
        steps: vec![hostile; MAX_STORED_STEPS + 3],
    };
    assert!(serde_json::to_vec(&report).unwrap().len() < MAX_BODY_BYTES);
    let answer = h.report(A, &a, &report).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");

    let audit = sqlx::query("SELECT detail FROM audit_events ORDER BY seq DESC LIMIT 1")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
        .get::<String, _>("detail");
    assert!(audit.len() < MAX_DETAIL_BYTES, "{}", audit.len());
    assert!(audit.contains("\\\\u{10ffff}"), "quoted and escaped");
    let detail: serde_json::Value = serde_json::from_str(&audit).unwrap();
    assert_eq!(detail["steps_dropped"], 3);

    assert_eq!(
        h.count("deploy_steps").await,
        i64::try_from(MAX_STORED_STEPS).unwrap()
    );
    let details: Vec<String> = sqlx::query_scalar("SELECT detail FROM deploy_steps")
        .fetch_all(h.store.pool())
        .await
        .unwrap();
    let stored: usize = details
        .iter()
        .map(|text| {
            let value: serde_json::Value = serde_json::from_str(text).unwrap();
            value["checks"].as_array().unwrap().len()
        })
        .sum();
    assert!(stored <= MAX_STORED_CHECKS);
    let millis: i64 = sqlx::query_scalar("SELECT millis FROM deploy_steps LIMIT 1")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(millis, i64::MAX);
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test]
async fn every_change_is_audited() {
    let h = Harness::new().await;
    let code = h.code(A, false).await;
    let code_text = code.to_hex();
    let key = super::signing_key(1);
    h.enrol_with(A, &key, code).await;
    let replacing = h.code(A, true).await;
    let a = super::signing_key(2);
    h.enrol_with(A, &a, replacing).await;

    let wrong = WorkRequest {
        config_hash: [9; 32],
        running: Vec::new(),
    };
    h.signed_post(A, &a, WORK, &wrong).await;

    let first = h.queue("app/prod", A, "v1.0.1").await;
    let running = |drift, phase| RunningState {
        deployment: "app/prod".parse().unwrap(),
        deployed: None,
        drift,
        phase,
        busy: false,
    };
    let answer = h.work(A, &a, vec![running(false, Phase::Idle)]).await;
    assert_eq!(answer.work().work.unwrap().deploy_id, first);
    h.report(A, &a, &deployed_report(first)).await;

    let second = h.queue("app/prod", A, "v1.0.2").await;
    h.work(A, &a, vec![running(false, Phase::Idle)]).await;
    let refused = DeployReportBody {
        deploy_id: second,
        outcome: ReportedOutcome::Refused {
            reason: "no".to_owned(),
        },
        steps: Vec::new(),
    };
    h.report(A, &a, &refused).await;
    h.work(A, &a, vec![running(true, Phase::Idle)]).await;

    assert_eq!(
        h.audit_kinds().await,
        [
            "enrol_code_issued",
            "host_enrolled",
            "enrol_code_issued",
            "host_enrolled",
            "config_drift",
            "deploy_queued",
            "config_drift",
            "deploy_claimed",
            "deploy_finished",
            "deploy_queued",
            "deploy_claimed",
            "deploy_refused",
            "running_drift",
        ]
    );
    assert_eq!(h.store.verify_audit().await.unwrap().first_bad, None);

    // Hosts are named on the rows about them, and nothing secret is anywhere.
    let log: Vec<(Option<String>, String)> = sqlx::query("SELECT host, detail FROM audit_events")
        .fetch_all(h.store.pool())
        .await
        .unwrap()
        .iter()
        .map(|row| (row.get("host"), row.get("detail")))
        .collect();
    assert!(log.iter().all(|(on, _)| on.as_deref() == Some(A)));
    assert!(log.iter().all(|(_, detail)| !detail.contains(&code_text)));
}
