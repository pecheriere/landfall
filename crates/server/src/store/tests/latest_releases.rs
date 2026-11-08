//! Each deployment's latest release: kept where releases are recorded, filled once from what
//! was recorded before, and read for a page of deployments on indexes alone.

use std::fs;

use landfall_core::ids::DeploymentId;
use sqlx::migrate::Migrator;

use super::super::history::RELEASE_ROWS;
use super::super::latest::{ACTIVE_DEPLOYS, HOLDS, LAST_FINISHED, LATEST_ROWS};
use super::super::{ReleaseDecision, Store, migrator};

async fn record(store: &Store, deployment: &str, tag: &str) {
    store
        .record_release(
            (
                &deployment.parse().unwrap(),
                &"home-1".parse().unwrap(),
                &tag.parse().unwrap(),
            ),
            ReleaseDecision::Manual,
            "beyond the rule's levels: it needs an operator",
            None,
        )
        .await
        .unwrap();
}

/// `deployment`'s latest release under a pattern of `prefix`.
async fn latest(store: &Store, deployment: &str, prefix: &str) -> Option<String> {
    let id: DeploymentId = deployment.parse().unwrap();
    let facts = store.latest_facts(&[(&id, prefix)]).await.unwrap();
    facts.rows.get(&id).map(|row| row.tag.to_string())
}

#[tokio::test]
async fn the_latest_is_the_highest_version_its_pattern_reads() {
    let store = Store::open_in_memory().await.unwrap();
    for tag in [
        "v1.9.0",
        "v1.10.0",
        "v1.11.0-rc.1",
        "vnext",
        "release-1",
        "release-3.0.0",
    ] {
        record(&store, "app/prod", tag).await;
    }
    record(&store, "app/staging", "v9.0.0").await;
    assert_eq!(
        latest(&store, "app/prod", "v").await.unwrap(),
        "v1.11.0-rc.1"
    );
    assert_eq!(
        latest(&store, "app/prod", "release-").await.unwrap(),
        "release-3.0.0"
    );
    // A pattern that reads none of them: the first tag in string order, as a list puts the
    // tags it can't read.
    assert_eq!(latest(&store, "app/prod", "x").await.unwrap(), "release-1");
    record(&store, "app/prod", "v1.11.0").await;
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.11.0");
    // A lower one recorded later changes nothing.
    record(&store, "app/prod", "v1.0.0").await;
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.11.0");
    assert_eq!(latest(&store, "app/other", "v").await, None);
}

#[tokio::test]
async fn a_tag_read_under_two_prefixes_counts_under_each() {
    let store = Store::open_in_memory().await.unwrap();
    for tag in ["v1.0.0-rc2.0.0", "v1.5.0"] {
        record(&store, "app/prod", tag).await;
    }
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.5.0");
    // `v1.0.0-rc*` reads `v1.0.0-rc2.0.0` as 2.0.0, and doesn't read `v1.5.0`.
    assert_eq!(
        latest(&store, "app/prod", "v1.0.0-rc").await.unwrap(),
        "v1.0.0-rc2.0.0"
    );
}

#[tokio::test]
async fn opening_fills_the_latest_from_releases_already_recorded_once() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();
    let store = Store::open_existing(&path).await.unwrap();
    let all = migrator();
    let before = Migrator::with_migrations(all.iter().take(6).cloned().collect());
    before.run(store.pool()).await.unwrap();
    for tag in ["v1.9.0", "v1.10.0", "vnext"] {
        sqlx::query(
            "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
             VALUES ('app/prod', ?, 'manual', 'beyond', 1000)",
        )
        .bind(tag)
        .execute(store.pool())
        .await
        .unwrap();
    }
    store.close().await;

    let store = Store::open(&path).await.unwrap();
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.10.0");
    assert_eq!(latest(&store, "app/prod", "x").await.unwrap(), "v1.10.0");
    // Once: a release written behind the store's back after it isn't picked up by opening
    // again, which shows the fill didn't run twice.
    sqlx::query(
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', 'v2.0.0', 'manual', 'beyond', 1000)",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store.close().await;
    let store = Store::open(&path).await.unwrap();
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.10.0");
}

#[tokio::test]
async fn opening_skips_a_release_it_cannot_read_and_fills_from_the_rest() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();
    let store = Store::open_existing(&path).await.unwrap();
    let all = migrator();
    let before = Migrator::with_migrations(all.iter().take(6).cloned().collect());
    before.run(store.pool()).await.unwrap();
    for (deployment, tag) in [
        ("app/prod", "v1.9.0".to_owned()),
        ("app/prod", "v1.10.0".to_owned()),
        // Rows no current code can read: a tag that isn't one, a deployment that isn't one,
        // and text that isn't UTF-8.
        ("app/prod", "bad tag\u{1b}[2J".to_owned()),
        ("not a deployment", "v9.0.0".to_owned()),
    ] {
        sqlx::query(
            "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
             VALUES (?, ?, 'manual', 'beyond', 1000)",
        )
        .bind(deployment)
        .bind(tag)
        .execute(store.pool())
        .await
        .unwrap();
    }
    sqlx::query(
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', CAST(x'ff' AS TEXT), 'manual', 'beyond', 1000)",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store.close().await;

    let store = Store::open(&path).await.unwrap();
    assert_eq!(latest(&store, "app/prod", "v").await.unwrap(), "v1.10.0");
    let pending: i64 = sqlx::query_scalar("SELECT count(*) FROM latest_unfilled")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(pending, 0);
    store.close().await;
    // And it opens again.
    Store::open(&path).await.unwrap();
}

/// What `EXPLAIN QUERY PLAN` says of `sql`, with `binds` text parameters, one line a step.
pub(super) async fn plan(store: &Store, sql: &str, binds: usize) -> Vec<String> {
    let explain = format!("EXPLAIN QUERY PLAN {sql}");
    let mut query = sqlx::query_as::<_, (i64, i64, i64, String)>(sqlx::AssertSqlSafe(explain));
    for _ in 0..binds {
        query = query.bind("[]");
    }
    query
        .fetch_all(store.pool())
        .await
        .unwrap()
        .into_iter()
        .map(|(.., detail)| detail)
        .collect()
}

#[tokio::test]
async fn a_page_of_summaries_reads_on_indexes_and_sorts_nothing() {
    let store = Store::open_in_memory().await.unwrap();
    // Some history, so that the planner has something to choose over.
    for i in 0..50 {
        record(&store, "app/prod", &format!("v1.{i}.0")).await;
    }
    sqlx::query("ANALYZE").execute(store.pool()).await.unwrap();
    for (name, sql, binds, index) in [
        ("latest rows", LATEST_ROWS, 1, "sqlite_autoindex_releases_1"),
        ("holds", HOLDS, 1, "sqlite_autoindex_release_holds_1"),
        (
            "active deploys",
            ACTIVE_DEPLOYS,
            1,
            "one_active_deploy_per_deployment",
        ),
        ("last finished", LAST_FINISHED, 1, "deploys_by_release"),
        ("release rows", RELEASE_ROWS, 2, "releases_by_first_seen"),
    ] {
        let steps = plan(&store, sql, binds).await;
        for step in &steps {
            // `json_each` is the page's own list, scanned as it should be; every table is
            // searched by key.
            let fine = step.starts_with("SEARCH")
                || step.starts_with("CORRELATED SCALAR SUBQUERY")
                || (step.starts_with("SCAN w") && step.contains("VIRTUAL TABLE"));
            assert!(fine, "{name}: {step}: {steps:#?}");
            assert!(!step.contains("TEMP B-TREE"), "{name} sorts: {steps:#?}");
        }
        assert!(
            steps.iter().any(|step| step.contains(index)),
            "{name} doesn't use {index}: {steps:#?}"
        );
    }
}
