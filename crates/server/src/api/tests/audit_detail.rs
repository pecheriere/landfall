//! What an audit row's detail and host show: per kind, only listed fields, and never a
//! deployment or a host the reader can't see, whatever the stored row says.

use axum::http::{Method, StatusCode};
use landfall_core::protocol::DeployReportBody;
use serde_json::{Value, json};

use super::audit::{every_row, page, seqs, write};
use super::hosts::{FLEET_VIEWER, Hosts, VIEWER};
use super::{BETA_VIEWER, Caller, FLEET_VIEWER as WORLD_FLEET_VIEWER, World, world_digest};
use crate::audit::EventKind;
use crate::report::BoundedReport;
use crate::store::{NewDeploy, ReleaseDecision};

/// The reason the watcher records for a release that waits for promotion from `source`.
fn promotion_reason(source: &str) -> String {
    format!(
        "waits for promotion: not yet reported healthy for long enough on {source}, or it has \
         gone quiet (enforced by the controller only)"
    )
}

#[tokio::test]
async fn promotion_source_is_not_named_in_audit() {
    let world = World::seed().await;
    let (beta, home) = ("app/beta".parse().unwrap(), "home-1".parse().unwrap());
    // As the watcher records them: a release that waits for `app/canary`, then one the rule
    // sends to an approver.
    for (tag, decision, reason) in [
        (
            "v3.0.0",
            ReleaseDecision::Manual,
            promotion_reason("app/canary"),
        ),
        (
            "v3.1.0",
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver".to_owned(),
        ),
    ] {
        world
            .store
            .record_release(
                (&beta, &home, &tag.parse().unwrap()),
                decision,
                &reason,
                None,
            )
            .await
            .unwrap();
    }
    let path = "/api/v1/audit?deployment=app/beta";
    for caller in [Caller::Token(BETA_VIEWER), Caller::Session(BETA_VIEWER)] {
        let answer = world.send(Method::GET, path, caller, None).await;
        let body = String::from_utf8(answer.body.clone()).unwrap();
        assert!(!body.contains("canary"), "{caller:?}: {body}");
        let (rows, _) = page(&answer);
        let decisions: Vec<&Value> = rows.iter().map(|row| &row["detail"]).collect();
        // The rule's own words are said again; the watcher's text about another deployment
        // isn't.
        assert_eq!(
            decisions,
            [
                &json!({
                    "tag": "v3.1.0",
                    "decision": "needs_approval",
                    "reason": "a higher version that needs an approver",
                    "digest": null,
                    "previous": null,
                }),
                &json!({
                    "tag": "v3.0.0",
                    "decision": "manual",
                    "digest": null,
                    "previous": null,
                }),
            ],
            "{caller:?}"
        );
    }
    // Not even for someone who may view both: what the API shows doesn't depend on the text.
    let answer = world
        .send(Method::GET, path, Caller::Token(WORLD_FLEET_VIEWER), None)
        .await;
    assert!(!String::from_utf8(answer.body).unwrap().contains("canary"));
}

/// A deploy of `v1.2.0` on `app/prod`, queued for `home-1` and handed to it.
async fn claimed_deploy(hosts: &Hosts) -> i64 {
    let (prod, home, tag) = (
        "app/prod".parse().unwrap(),
        "home-1".parse().unwrap(),
        "v1.2.0".parse().unwrap(),
    );
    hosts
        .store
        .record_release(
            (&prod, &home, &tag),
            ReleaseDecision::Manual,
            "asked for",
            None,
        )
        .await
        .unwrap();
    let new = NewDeploy {
        deployment: "app/prod".parse().unwrap(),
        host: "home-1".parse().unwrap(),
        tag: "v1.2.0".parse().unwrap(),
        digest: world_digest('2'),
        commit: "2".repeat(40).parse().unwrap(),
    };
    let mut tx = hosts.store.begin().await.unwrap();
    let id = hosts.store.queue_deploy(&mut tx, &new).await.unwrap();
    tx.commit().await.unwrap();
    let work = hosts
        .store
        .next_work(&"home-1".parse().unwrap())
        .await
        .unwrap();
    assert_eq!(work.work.unwrap().deploy_id, id);
    i64::try_from(id.0).unwrap()
}

/// `host` reports deploy `id` as a deploy of `deployment`, as a signed report says.
async fn report(hosts: &Hosts, host: &str, id: i64, deployment: &str) {
    let body: DeployReportBody = serde_json::from_value(json!({
        "deploy_id": id,
        "deployment": deployment,
        "tag": "v1.2.0",
        "digest": world_digest('2'),
        "outcome": { "kind": "deployed" },
        "steps": [],
    }))
    .unwrap();
    let refused = hosts
        .store
        .finish_deploy(&host.parse().unwrap(), &BoundedReport::new(&body))
        .await;
    assert!(refused.is_err(), "{refused:?}");
}

/// The `report_refused` rows `caller` sees.
async fn refused_reports(hosts: &Hosts, caller: Caller<'_>) -> Vec<Value> {
    let (rows, _) = every_row(hosts, "/api/v1/audit?kind=report_refused", caller).await;
    rows
}

#[tokio::test]
async fn refused_report_does_not_name_another_deployment() {
    let hosts = Hosts::seed().await;
    let id = claimed_deploy(&hosts).await;
    // `home-1` reports it as `app/other`'s, which `VIEWER` has no grant on.
    report(&hosts, "home-1", id, "app/other").await;
    let answer = hosts
        .get("/api/v1/audit?deployment=app/prod", Caller::Token(VIEWER))
        .await;
    let body = String::from_utf8(answer.body.clone()).unwrap();
    assert!(!body.contains("app/other"), "{body}");
    let rows = refused_reports(&hosts, Caller::Token(VIEWER)).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["deployment"], "app/prod");
    assert_eq!(rows[0]["host"], "home-1");
    assert_eq!(rows[0]["detail"], json!({ "deploy_id": id }));
}

#[tokio::test]
async fn a_row_names_only_a_host_one_may_see() {
    let hosts = Hosts::seed().await;
    let id = claimed_deploy(&hosts).await;
    // `home-2` signs a report of `home-1`'s deploy.
    report(&hosts, "home-2", id, "app/prod").await;
    let unseen = hosts
        .get("/api/v1/hosts/home-2", Caller::Token(VIEWER))
        .await;
    assert_eq!(unseen.status, StatusCode::NOT_FOUND);
    let rows = refused_reports(&hosts, Caller::Token(VIEWER)).await;
    assert_eq!(rows.len(), 1, "{rows:#?}");
    assert_eq!(rows[0]["deployment"], "app/prod");
    assert_eq!(rows[0]["host"], Value::Null);
    // The controller's own words, which name nothing.
    assert_eq!(
        rows[0]["detail"],
        json!({ "deploy_id": id, "reason": "another host's deploy" })
    );
    // Someone who may see `home-2` is told it.
    let rows = refused_reports(&hosts, Caller::Token(FLEET_VIEWER)).await;
    assert_eq!(rows[0]["host"], "home-2");
}

#[tokio::test]
async fn a_kind_this_version_does_not_know_is_quoted_with_no_detail() {
    let hosts = Hosts::seed().await;
    let good = write(
        &hosts,
        EventKind::DeployClaimed,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    sqlx::query(
        "INSERT INTO audit_events (ts, kind, deployment, host, detail, prev_hash, hash)
         VALUES (1, ?, 'app/prod', 'home-1', '{\"secret_of_a_newer_kind\": 1}', x'00', x'00')",
    )
    .bind("teleported\u{1b}[31m")
    .execute(hosts.store.pool())
    .await
    .unwrap();
    let (rows, _) = every_row(&hosts, "/api/v1/audit", Caller::Token(VIEWER)).await;
    assert_eq!(seqs(&rows)[1], good);
    assert_eq!(rows[0]["kind"], "\"teleported\\u{1b}[31m\"");
    assert_eq!(rows[0]["detail"], json!({}));
    assert_eq!(rows[1]["kind"], "deploy_claimed");
}

#[tokio::test]
async fn a_closed_request_names_its_deployment_and_host_as_the_reader_may_see_them() {
    let hosts = Hosts::seed().await;
    // As the store writes a request's end: here, one asked for on `home-2`, where `app/prod`
    // ran before the configuration moved it.
    let event = crate::audit::AuditEvent {
        kind: EventKind::RequestStale,
        deployment: Some("app/prod".parse().unwrap()),
        host: Some("home-2".parse().unwrap()),
        detail: json!({
            "request": 7,
            "deployment": "app/prod",
            "host": "home-2",
            "tag": "v1.3.0",
            "digest": world_digest('3'),
            "expected_running": world_digest('2'),
            "reason": "the deployment is on another host now, by the configuration",
        }),
    };
    hosts.store.record(&event).await.unwrap();
    let detail = |rows: &[Value]| rows[0]["detail"].clone();
    let (rows, _) = every_row(
        &hosts,
        "/api/v1/audit?kind=request_stale",
        Caller::Token(VIEWER),
    )
    .await;
    assert_eq!(rows[0]["host"], Value::Null);
    assert_eq!(
        detail(&rows),
        json!({
            "request": 7,
            "deployment": { "deployment": "app/prod" },
            "host": null,
            "tag": "v1.3.0",
            "digest": world_digest('3'),
            "expected_running": world_digest('2'),
            "reason": "the deployment is on another host now, by the configuration",
        })
    );
    let (rows, _) = every_row(
        &hosts,
        "/api/v1/audit?kind=request_stale",
        Caller::Token(FLEET_VIEWER),
    )
    .await;
    assert_eq!(rows[0]["host"], "home-2");
    assert_eq!(detail(&rows)["host"], "home-2");
}
