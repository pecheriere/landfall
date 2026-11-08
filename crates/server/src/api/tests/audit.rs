//! The audit log, as far as a principal may see it: `listAudit`.

use std::collections::BTreeSet;

use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::{Value, json};

use super::grants::{assert_documented, served_document};
use super::hosts::{ASKER, EDGE_VIEWER, FLEET_VIEWER, Hosts, VIEWER, deployment, preamble};
use super::{Answer, Caller};
use crate::audit::{AuditEvent, EventKind};

/// Writes a row of `kind` about `deployment` and `host`, as the controller does, and gives
/// its `seq`.
pub(super) async fn write(
    hosts: &Hosts,
    kind: EventKind,
    deployment: Option<&str>,
    host: Option<&str>,
) -> i64 {
    let event = AuditEvent {
        kind,
        deployment: deployment.map(|d| d.parse().unwrap()),
        host: host.map(|h| h.parse().unwrap()),
        detail: json!({ "tag": "v1.2.0", "n": 1 }),
    };
    hosts.store.record(&event).await.unwrap();
    sqlx::query_scalar("SELECT max(seq) FROM audit_events")
        .fetch_one(hosts.store.pool())
        .await
        .unwrap()
}

/// A page's items and its next cursor.
pub(super) fn page(answer: &Answer) -> (Vec<Value>, Option<String>) {
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    let cursor = body["next_cursor"].as_str().map(ToOwned::to_owned);
    (body["items"].as_array().unwrap().clone(), cursor)
}

/// Every row `caller` is listed at `path`, page after page, and the pages' lengths.
pub(super) async fn every_row(
    hosts: &Hosts,
    path: &str,
    caller: Caller<'_>,
) -> (Vec<Value>, Vec<usize>) {
    let mut rows = Vec::new();
    let mut lengths = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let sep = if path.contains('?') { '&' } else { '?' };
        let url = cursor
            .as_ref()
            .map_or_else(|| path.to_owned(), |c| format!("{path}{sep}cursor={c}"));
        let (items, next) = page(&hosts.get(&url, caller).await);
        lengths.push(items.len());
        rows.extend(items);
        match next {
            Some(next) => cursor = Some(next),
            None => return (rows, lengths),
        }
    }
}

pub(super) fn seqs(rows: &[Value]) -> Vec<i64> {
    rows.iter()
        .map(|row| row["seq"].as_i64().unwrap())
        .collect()
}

fn kinds(rows: &[Value]) -> BTreeSet<String> {
    rows.iter()
        .map(|row| row["kind"].as_str().unwrap().to_owned())
        .collect()
}

/// Whether `row` is about `app/prod`, or `home-1` alone: what [`VIEWER`] may see.
fn seen_by_viewer(row: &Value) -> bool {
    row["deployment"] == "app/prod"
        || (row["deployment"].is_null()
            && row["host"] == "home-1"
            && ["host_enrolled", "config_drift"].contains(&row["kind"].as_str().unwrap()))
}

#[tokio::test]
async fn audit_rows_follow_view_in_sql() {
    let hosts = Hosts::seed().await;
    // 60 rows the viewer may see, each followed by one they may not: the newest 50 of what
    // they may see sit among 50 they may not.
    let mut visible = Vec::new();
    for i in 0..60 {
        let seq = if i % 6 == 0 {
            let kind = if i % 12 == 0 {
                EventKind::HostEnrolled
            } else {
                EventKind::ConfigDrift
            };
            write(&hosts, kind, None, Some("home-1")).await
        } else {
            write(
                &hosts,
                EventKind::DeployQueued,
                Some("app/prod"),
                Some("home-1"),
            )
            .await
        };
        visible.push(seq);
        match i % 3 {
            0 => {
                write(
                    &hosts,
                    EventKind::DeployQueued,
                    Some("app/other"),
                    Some("home-1"),
                )
                .await
            }
            1 => write(&hosts, EventKind::TokenCreated, None, None).await,
            _ => write(&hosts, EventKind::ConfigDrift, None, Some("home-2")).await,
        };
    }
    visible.reverse();
    let doc = served_document().await;
    let first = hosts
        .get("/api/v1/audit?limit=50", Caller::Token(VIEWER))
        .await;
    assert_documented(&doc, "listAudit", "a page", &first);
    let (items, cursor) = page(&first);
    assert_eq!(items.len(), 50);
    assert_eq!(seqs(&items), visible[..50]);
    assert!(items.iter().all(seen_by_viewer), "{items:#?}");
    assert!(cursor.is_some());
    let (rows, lengths) = every_row(&hosts, "/api/v1/audit?limit=50", Caller::Token(VIEWER)).await;
    assert_eq!(lengths, [50, 10]);
    assert_eq!(seqs(&rows), visible);
    // Each row as stored.
    let row = &items[1];
    assert_eq!(row["deployment"], "app/prod");
    assert_eq!(row["host"], "home-1");
    assert_eq!(row["kind"], "deploy_queued");
    // A `deploy_queued` row shows the fields its kind lists, and nothing else it holds.
    assert_eq!(row["detail"], json!({ "tag": "v1.2.0" }));
    assert_eq!(row["ts"], super::hosts::NOW);
    assert_eq!(row.as_object().unwrap().len(), 6, "{row}");
}

#[tokio::test]
async fn host_rows_are_seen_through_a_deployment_on_that_host() {
    let hosts = Hosts::seed().await;
    for host in ["home-1", "home-2"] {
        write(&hosts, EventKind::HostEnrolled, None, Some(host)).await;
        write(&hosts, EventKind::ConfigDrift, None, Some(host)).await;
        // Kinds about a host alone that aren't on the list.
        write(&hosts, EventKind::RunningInconsistent, None, Some(host)).await;
        write(&hosts, EventKind::DeployRefused, None, Some(host)).await;
    }
    let host_rows = |rows: &[Value]| -> Vec<(String, String)> {
        rows.iter()
            .map(|row| {
                assert!(row["deployment"].is_null(), "{row}");
                let kind = row["kind"].as_str().unwrap().to_owned();
                (row["host"].as_str().unwrap().to_owned(), kind)
            })
            .collect()
    };
    let pair = |host: &str, kind: &str| (host.to_owned(), kind.to_owned());
    for (who, want) in [
        (
            VIEWER,
            vec![
                pair("home-1", "config_drift"),
                pair("home-1", "host_enrolled"),
            ],
        ),
        (
            EDGE_VIEWER,
            vec![
                pair("home-2", "config_drift"),
                pair("home-2", "host_enrolled"),
            ],
        ),
        (
            FLEET_VIEWER,
            vec![
                pair("home-2", "config_drift"),
                pair("home-2", "host_enrolled"),
                pair("home-1", "config_drift"),
                pair("home-1", "host_enrolled"),
            ],
        ),
        (ASKER, vec![]),
    ] {
        for caller in [Caller::Token(who), Caller::Session(who)] {
            let (rows, _) = every_row(&hosts, "/api/v1/audit", caller).await;
            assert_eq!(host_rows(&rows), want, "{caller:?}");
        }
    }
    // A host filter is that host's rows, through the same rule.
    let (rows, _) = every_row(
        &hosts,
        "/api/v1/audit?host=home-1",
        Caller::Token(FLEET_VIEWER),
    )
    .await;
    assert_eq!(
        host_rows(&rows),
        [
            pair("home-1", "config_drift"),
            pair("home-1", "host_enrolled")
        ]
    );
    let (rows, _) = every_row(
        &hosts,
        "/api/v1/audit?kind=host_enrolled",
        Caller::Token(VIEWER),
    )
    .await;
    assert_eq!(host_rows(&rows), [pair("home-1", "host_enrolled")]);
}

#[tokio::test]
async fn host_rows_of_enrolment_are_not_listed() {
    let hosts = Hosts::seed().await;
    write(&hosts, EventKind::EnrolCodeIssued, None, Some("home-1")).await;
    write(&hosts, EventKind::EnrolRefused, None, Some("home-1")).await;
    write(&hosts, EventKind::ReportRefused, None, Some("home-1")).await;
    let enrolled = write(&hosts, EventKind::HostEnrolled, None, Some("home-1")).await;
    for who in [VIEWER, FLEET_VIEWER, ASKER, EDGE_VIEWER] {
        for caller in [Caller::Token(who), Caller::Session(who)] {
            let (rows, _) = every_row(&hosts, "/api/v1/audit", caller).await;
            let shown = kinds(&rows);
            for kind in ["enrol_code_issued", "enrol_refused", "report_refused"] {
                assert!(!shown.contains(kind), "{caller:?}: {kind}");
                let path = format!("/api/v1/audit?kind={kind}&host=home-1");
                let (rows, _) = every_row(&hosts, &path, caller).await;
                assert!(rows.is_empty(), "{caller:?}: {path}");
            }
            let expected: &[i64] = if [VIEWER, FLEET_VIEWER].contains(&who) {
                &[enrolled]
            } else {
                &[]
            };
            assert_eq!(seqs(&rows), expected, "{caller:?}");
        }
    }
}

#[tokio::test]
async fn controller_wide_rows_are_never_listed() {
    let hosts = Hosts::seed().await;
    for kind in [
        EventKind::TokenCreated,
        EventKind::SignedIn,
        EventKind::AccessThrottled,
        EventKind::PasskeyRegistered,
    ] {
        write(&hosts, kind, None, None).await;
    }
    let queued = write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    for caller in [Caller::Token(FLEET_VIEWER), Caller::Session(FLEET_VIEWER)] {
        let (rows, _) = every_row(&hosts, "/api/v1/audit", caller).await;
        assert_eq!(seqs(&rows), [queued], "{caller:?}");
        for kind in [
            "token_created",
            "signed_in",
            "access_throttled",
            "passkey_registered",
        ] {
            let (rows, _) = every_row(&hosts, &format!("/api/v1/audit?kind={kind}"), caller).await;
            assert!(rows.is_empty(), "{caller:?}: {kind}");
        }
    }
    // Issuing the fixture's tokens wrote rows of its own, which aren't listed either.
    let written: i64 =
        sqlx::query_scalar("SELECT count(*) FROM audit_events WHERE kind = 'token_created'")
            .fetch_one(hosts.store.pool())
            .await
            .unwrap();
    assert!(written > 1);
}

#[tokio::test]
async fn audit_of_a_removed_deployment_is_not_listed() {
    let hosts = Hosts::seed().await;
    // `app/old` was once on `home-1`; the configuration no longer has it.
    write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/old"),
        Some("home-1"),
    )
    .await;
    write(
        &hosts,
        EventKind::DeployFinished,
        Some("app/old"),
        Some("home-1"),
    )
    .await;
    let queued = write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    for caller in [Caller::Token(FLEET_VIEWER), Caller::Session(FLEET_VIEWER)] {
        let (rows, _) = every_row(&hosts, "/api/v1/audit", caller).await;
        assert_eq!(seqs(&rows), [queued], "{caller:?}");
        let (rows, cursor) = page(&hosts.get("/api/v1/audit?deployment=app/old", caller).await);
        assert!(rows.is_empty() && cursor.is_none(), "{caller:?}");
    }
}

#[tokio::test]
async fn a_crafted_cursor_reaches_nothing_unseen() {
    let hosts = Hosts::seed().await;
    let mut seen = Vec::new();
    let mut unseen = Vec::new();
    for _ in 0..5 {
        seen.push(
            write(
                &hosts,
                EventKind::DeployQueued,
                Some("app/prod"),
                Some("home-1"),
            )
            .await,
        );
        unseen.push(
            write(
                &hosts,
                EventKind::DeployQueued,
                Some("app/other"),
                Some("home-1"),
            )
            .await,
        );
        unseen.push(write(&hosts, EventKind::SignedIn, None, None).await);
    }
    // A cursor that begins after an unseen row, as anyone could write one.
    let before = unseen[6];
    let cursor = URL_SAFE_NO_PAD.encode(format!("v1.audit.{before}"));
    let (rows, next) = page(
        &hosts
            .get(
                &format!("/api/v1/audit?cursor={cursor}"),
                Caller::Token(VIEWER),
            )
            .await,
    );
    let mut want: Vec<i64> = seen.iter().copied().filter(|seq| *seq < before).collect();
    want.reverse();
    assert_eq!(seqs(&rows), want);
    assert!(next.is_none());
    // One after the newest row reads like no cursor at all; one that isn't a number is refused.
    let past = URL_SAFE_NO_PAD.encode(format!("v1.audit.{}", i64::MAX));
    let (rows, _) = page(
        &hosts
            .get(
                &format!("/api/v1/audit?cursor={past}"),
                Caller::Token(VIEWER),
            )
            .await,
    );
    assert_eq!(rows.len(), seen.len());
    for after in ["x", "01", "-1"] {
        let cursor = URL_SAFE_NO_PAD.encode(format!("v1.audit.{after}"));
        let answer = hosts
            .get(
                &format!("/api/v1/audit?cursor={cursor}"),
                Caller::Token(VIEWER),
            )
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{after}");
    }
}

#[tokio::test]
async fn filter_on_an_unseen_deployment_is_an_empty_page() {
    let hosts = Hosts::seed().await;
    write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/other"),
        Some("home-1"),
    )
    .await;
    write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/edge"),
        Some("home-2"),
    )
    .await;
    write(&hosts, EventKind::ConfigDrift, None, Some("home-2")).await;
    let queued = write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    let empty = hosts
        .get(
            "/api/v1/audit?deployment=app/nowhere",
            Caller::Token(VIEWER),
        )
        .await;
    assert_eq!(page(&empty), (vec![], None));
    for (caller, query) in [
        (Caller::Token(VIEWER), "deployment=app/other"),
        (Caller::Token(VIEWER), "deployment=app/edge"),
        (Caller::Token(VIEWER), "host=home-2"),
        (Caller::Token(VIEWER), "host=home-9"),
        (Caller::Token(VIEWER), "deployment=app/prod&host=home-2"),
        (Caller::Session(VIEWER), "deployment=app/other"),
        (Caller::Token(ASKER), "deployment=app/prod"),
        (Caller::Token(ASKER), "host=home-1"),
    ] {
        let answer = hosts.get(&format!("/api/v1/audit?{query}"), caller).await;
        assert_eq!(answer.status, StatusCode::OK, "{caller:?} {query}");
        assert_eq!(answer.body, empty.body, "{caller:?} {query}");
    }
    // A filter on what one may see is that.
    for query in [
        "deployment=app/prod",
        "host=home-1",
        "deployment=app/prod&host=home-1",
    ] {
        let (rows, _) = page(
            &hosts
                .get(&format!("/api/v1/audit?{query}"), Caller::Token(VIEWER))
                .await,
        );
        assert_eq!(seqs(&rows), [queued], "{query}");
    }
    // A value that isn't an id at all is refused, as any malformed parameter is.
    for query in ["deployment=nope", "host=Not%20a%20host"] {
        let answer = hosts
            .get(&format!("/api/v1/audit?{query}"), Caller::Token(VIEWER))
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{query}");
    }
}

#[tokio::test]
async fn unknown_kind_is_refused() {
    let hosts = Hosts::seed().await;
    let queued = write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    write(
        &hosts,
        EventKind::DeployClaimed,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    let doc = served_document().await;
    for kind in ["teleported", "DEPLOY_QUEUED", "", "deploy_queued%00"] {
        let answer = hosts
            .get(&format!("/api/v1/audit?kind={kind}"), Caller::Token(VIEWER))
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{kind}");
        assert_eq!(answer.code(), "bad_request");
        assert_documented(&doc, "listAudit", kind, &answer);
    }
    let (rows, _) = page(
        &hosts
            .get("/api/v1/audit?kind=deploy_queued", Caller::Token(VIEWER))
            .await,
    );
    assert_eq!(seqs(&rows), [queued]);
}

#[tokio::test]
async fn tampered_detail_is_unreadable_not_an_error() {
    let hosts = Hosts::seed().await;
    let good = write(
        &hosts,
        EventKind::DeployQueued,
        Some("app/prod"),
        Some("home-1"),
    )
    .await;
    // Rows someone wrote into the file: a detail that isn't JSON, one that is JSON and not an
    // object, and one that isn't even text.
    let hostile = format!("not json \u{1b}[31m\r\n{}", "x".repeat(400));
    for detail in [
        hostile.as_bytes(),
        b"[1, 2]".as_slice(),
        b"\xff\xfe{".as_slice(),
    ] {
        sqlx::query(
            "INSERT INTO audit_events (ts, kind, deployment, host, detail, prev_hash, hash)
             VALUES (1, 'deploy_queued', 'app/prod', 'home-1', CAST(? AS TEXT), x'00', x'00')",
        )
        .bind(detail)
        .execute(hosts.store.pool())
        .await
        .unwrap();
    }
    let answer = hosts.get("/api/v1/audit", Caller::Token(VIEWER)).await;
    assert_documented(
        &served_document().await,
        "listAudit",
        "tampered rows",
        &answer,
    );
    let (rows, _) = page(&answer);
    assert_eq!(rows.len(), 4);
    assert_eq!(rows[3]["seq"], good);
    assert_eq!(rows[3]["detail"], json!({ "tag": "v1.2.0" }));
    let unreadable: Vec<&str> = rows[..3]
        .iter()
        .map(|row| {
            let detail = row["detail"].as_object().unwrap();
            assert_eq!(detail.len(), 1, "{row}");
            detail["unreadable"].as_str().unwrap()
        })
        .collect();
    assert_eq!(unreadable[1], "\"[1, 2]\"");
    let quoted = unreadable[2];
    assert!(
        quoted.starts_with("\"not json \\u{1b}[31m\\r\\n"),
        "{quoted}"
    );
    assert!(quoted.ends_with("\"..."), "{quoted}");
    assert!(!quoted.contains(['\u{1b}', '\r', '\n']));
    assert_eq!(
        quoted.matches('x').count(),
        256 - "not json \u{1b}[31m\r\n".chars().count()
    );
    assert!(unreadable[0].starts_with('"'), "{}", unreadable[0]);
}

/// A configuration of `count` deployments on `home-1`, all of which [`VIEWER`] may view.
fn wide_config(count: usize) -> String {
    let ids: Vec<String> = (0..count).map(|i| format!("app/d{i}")).collect();
    let mut text = preamble();
    for (i, id) in ids.iter().enumerate() {
        text.push_str(&deployment(id, i + 1, "home-1"));
    }
    let ids: Vec<&str> = ids.iter().map(String::as_str).collect();
    text.push_str(&super::deployments::grant(VIEWER, &ids, &["view"]));
    text
}

#[tokio::test]
async fn a_scope_over_400_branches_is_refused() {
    let doc = served_document().await;
    // Each deployment is a branch, and so is each kind of row about `home-1` alone.
    let fits = Hosts::seed_with(&wide_config(398), &[VIEWER]).await;
    let queued = write(
        &fits,
        EventKind::DeployQueued,
        Some("app/d397"),
        Some("home-1"),
    )
    .await;
    let (rows, _) = page(&fits.get("/api/v1/audit", Caller::Token(VIEWER)).await);
    assert_eq!(seqs(&rows), [queued]);
    let over = Hosts::seed_with(&wide_config(399), &[VIEWER]).await;
    let answer = over.get("/api/v1/audit", Caller::Token(VIEWER)).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{answer:?}");
    assert_eq!(answer.code(), "bad_request");
    let title = answer.json()["title"].as_str().unwrap().to_owned();
    assert!(
        title.contains("deployment") && title.contains("host"),
        "{title}"
    );
    assert_documented(&doc, "listAudit", "401 branches", &answer);
    // A filter makes the scope small enough: one deployment, or a kind no host row has.
    for query in ["deployment=app/d3", "kind=deploy_queued"] {
        let answer = over
            .get(&format!("/api/v1/audit?{query}"), Caller::Token(VIEWER))
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{query}: {answer:?}");
    }
}
