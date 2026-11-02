//! The approvals migration, on a database that already holds what a running controller
//! wrote before it.

use std::fs;

use sqlx::migrate::Migrator;

use super::super::{Store, migrator};
use super::{append_events, chain};

#[tokio::test]
async fn it_adds_to_a_database_in_use_and_keeps_what_is_there() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();

    let store = Store::open_existing(&path).await.unwrap();
    let all = migrator();
    let before = Migrator::with_migrations(all.iter().take(2).cloned().collect());
    before.run(store.pool()).await.unwrap();
    append_events(&store, 3).await;
    for statement in [
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', 'v1.0.0', 'auto', 'patch', 0)",
        "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, created_at)
         VALUES ('app/prod', 'host-a', 'v1.0.0',
                 'sha256:0000000000000000000000000000000000000000000000000000000000000000',
                 '0000000000000000000000000000000000000000', 'queued', 0)",
    ] {
        sqlx::query(statement).execute(store.pool()).await.unwrap();
    }
    store.close().await;

    let store = Store::open(&path).await.unwrap();
    assert_eq!(chain(&store).await, (3, None));
    // A deploy queued before it carries no approval, and still goes out.
    let work = store.next_work(&"host-a".parse().unwrap()).await.unwrap();
    assert_eq!(work.work.unwrap().approval, None);
    store.close().await;

    // And it runs once.
    let store = Store::open(&path).await.unwrap();
    assert_eq!(chain(&store).await.1, None);
}
