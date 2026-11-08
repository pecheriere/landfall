//! The commit ranges migration, on a database that already holds releases.

use std::fs;

use sqlx::migrate::Migrator;

use super::super::{Clock as _, Store, SystemClock, migrator};

#[tokio::test]
async fn it_dates_old_releases_and_starts_comparing_from_now() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();

    let store = Store::open_existing(&path).await.unwrap();
    let all = migrator();
    let before = Migrator::with_migrations(all.iter().take(5).cloned().collect());
    before.run(store.pool()).await.unwrap();
    sqlx::query(
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', 'v1.0.0', 'auto', 'patch', 1000)",
    )
    .execute(store.pool())
    .await
    .unwrap();
    store.close().await;

    let started = SystemClock.now().unwrap();
    let store = Store::open(&path).await.unwrap();
    let first_seen: i64 = sqlx::query_scalar("SELECT first_seen_at FROM releases")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(first_seen, 1000);
    let since: Vec<i64> = sqlx::query_scalar("SELECT at FROM commits_since")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(since.len(), 1);
    assert!(
        (started..=SystemClock.now().unwrap()).contains(&since[0]),
        "{since:?}"
    );
    store.close().await;

    // It runs once: the time it began stays.
    let store = Store::open(&path).await.unwrap();
    let again: Vec<i64> = sqlx::query_scalar("SELECT at FROM commits_since")
        .fetch_all(store.pool())
        .await
        .unwrap();
    assert_eq!(again, since);
}

#[tokio::test]
async fn ranges_refuse_an_unknown_state() {
    let store = Store::open_in_memory().await.unwrap();
    let refused = sqlx::query(
        "INSERT INTO commit_ranges (repo, base_commit, head_commit, state, total, last_try)
         VALUES ('example/app', 'a', 'b', 'partial', NULL, 0)",
    )
    .execute(store.pool())
    .await;
    assert!(refused.is_err());
}
