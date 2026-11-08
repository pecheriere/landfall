//! The hosts and the audit log as the API reads them: on indexes alone, however long the log.

use super::super::Store;
use super::super::views::{AuditBranches, AuditScope, HOSTS_BY_ID};
use super::latest_releases::plan;
use crate::audit::{AuditEvent, EventKind};

/// What `EXPLAIN QUERY PLAN` says of the audit query of `branches`, one line a step.
async fn audit_plan(store: &Store, branches: &AuditBranches<'_>) -> Vec<String> {
    branches
        .statement("EXPLAIN QUERY PLAN ", i64::MAX, 51)
        .fetch_all(store.pool())
        .await
        .unwrap()
        .iter()
        .map(|row| sqlx::Row::get::<String, _>(row, 3))
        .collect()
}

#[tokio::test]
async fn audit_page_uses_an_index() {
    let store = Store::open_in_memory().await.unwrap();
    // A log over several deployments and hosts, with rows about neither, so that the planner
    // has something to choose over.
    for i in 0..400 {
        let (kind, deployment, host) = match i % 5 {
            0 => (EventKind::DeployQueued, Some("app/prod"), Some("home-1")),
            1 => (
                EventKind::DeployFinished,
                Some("app/staging"),
                Some("home-1"),
            ),
            2 => (EventKind::RuleDecision, Some("app/other"), None),
            3 => (EventKind::ConfigDrift, None, Some("home-1")),
            _ => (EventKind::TokenCreated, None, None),
        };
        let event = AuditEvent {
            kind,
            deployment: deployment.map(|d| d.parse().unwrap()),
            host: host.map(|h| h.parse().unwrap()),
            detail: serde_json::json!({ "n": i }),
        };
        store.record(&event).await.unwrap();
    }
    sqlx::query("ANALYZE").execute(store.pool()).await.unwrap();
    let ids = ["app/prod", "app/staging", "app/other"].map(|d| d.parse().unwrap());
    let deployments: Vec<_> = ids.iter().collect();
    let home = "home-1".parse().unwrap();
    let hosts = [&home];
    let everything = AuditScope {
        deployments: &deployments,
        hosts: &hosts,
    };
    let one = AuditScope {
        deployments: &deployments[..1],
        hosts: &[],
    };
    for (name, scope, kind, want) in [
        (
            "unfiltered",
            everything,
            None,
            &[("audit_by_deployment ", 3), ("audit_by_host_alone", 2)][..],
        ),
        (
            "a kind rows about a host alone have",
            everything,
            Some("config_drift"),
            &[("audit_by_deployment_kind", 3), ("audit_by_host_alone", 1)][..],
        ),
        (
            "a kind they don't",
            everything,
            Some("deploy_queued"),
            &[("audit_by_deployment_kind", 3)][..],
        ),
        (
            "a deployment",
            one,
            None,
            &[("audit_by_deployment ", 1)][..],
        ),
    ] {
        let branches = AuditBranches::new(&scope, kind).unwrap();
        // Each branch is a co-routine reading its index in order and stopping at its limit;
        // merging them sorts at most that many rows a branch.
        let steps = audit_plan(&store, &branches).await;
        let searches: Vec<&String> = steps
            .iter()
            .filter(|step| step.contains("audit_events"))
            .collect();
        let total: usize = want.iter().map(|(_, count)| count).sum();
        assert_eq!(searches.len(), total, "{name}: {steps:#?}");
        for step in &searches {
            assert!(
                step.starts_with("SEARCH audit_events USING "),
                "{name}: {steps:#?}"
            );
            assert!(step.contains("seq<?"), "{name}: {step}");
        }
        for (index, count) in want {
            let using = searches.iter().filter(|step| step.contains(index)).count();
            assert_eq!(using, *count, "{name}: {index}: {steps:#?}");
        }
        assert!(
            steps.iter().all(|step| !step.contains("SCAN audit_events")),
            "{name}: {steps:#?}"
        );
    }
}

#[tokio::test]
async fn hosts_are_read_by_key() {
    let store = Store::open_in_memory().await.unwrap();
    for i in 0..50 {
        sqlx::query("INSERT INTO hosts (id, public_key, enrolled_at) VALUES (?, ?, 0)")
            .bind(format!("home-{i}"))
            .bind([u8::try_from(i).unwrap(); 32].as_slice())
            .execute(store.pool())
            .await
            .unwrap();
    }
    sqlx::query("ANALYZE").execute(store.pool()).await.unwrap();
    let steps = plan(&store, HOSTS_BY_ID, 1).await;
    for step in &steps {
        // The list of ids is scanned, as it should be; each host is searched for by its key.
        let fine = step == "SEARCH h USING INDEX sqlite_autoindex_hosts_1 (id=?)"
            || (step.starts_with("SCAN w") && step.contains("VIRTUAL TABLE"));
        assert!(fine, "{step}: {steps:#?}");
    }
    assert!(
        steps.iter().any(|step| step.starts_with("SEARCH h ")),
        "{steps:#?}"
    );
}
