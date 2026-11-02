mod approvals_migration;
mod read_only;

use std::fs::{self, Permissions};
use std::os::unix::fs::PermissionsExt as _;

use serde_json::json;
use sha2::Digest as _;
use sqlx::Row as _;

use super::{
    AuditEvent, AuditReport, EventKind, GENESIS, HostId, MAX_DETAIL_BYTES, ManualClock, RowFields,
    Sha256, SqliteExecutor, Store, StoreError, VERIFY_PAGE,
};

fn event(n: u32) -> AuditEvent {
    AuditEvent {
        kind: EventKind::DeployQueued,
        deployment: Some("app/prod".parse().unwrap()),
        host: Some("host-a".parse().unwrap()),
        detail: json!({ "n": n }),
    }
}

async fn append_events(store: &Store, count: u32) {
    for n in 1..=count {
        let mut tx = store.begin().await.unwrap();
        store.append(&mut tx, &event(n)).await.unwrap();
        tx.commit().await.unwrap();
    }
}

/// What someone with the database file can do: the triggers do not bind
/// them, so a test of the chain must get past them the same way.
async fn drop_append_only_triggers(store: &Store) {
    for name in ["audit_events_no_update", "audit_events_no_delete"] {
        sqlx::query(sqlx::AssertSqlSafe(format!("DROP TRIGGER {name}")))
            .execute(&store.pool)
            .await
            .unwrap();
    }
}

/// The rows and the first bad row of a walk of the chain.
async fn chain(store: &Store) -> (u64, Option<u64>) {
    let report = store.verify_audit().await.unwrap();
    (report.rows, report.first_bad)
}

async fn insert_release(store: &Store, deployment: &str, tag: &str) {
    sqlx::query(
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES (?, ?, 'auto', 'patch', 0)",
    )
    .bind(deployment)
    .bind(tag)
    .execute(&store.pool)
    .await
    .unwrap();
}

async fn insert_deploy(
    executor: impl SqliteExecutor<'_>,
    id: i64,
    deployment: &str,
    tag: &str,
    state: &str,
    outcome: Option<&str>,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO deploys (id, deployment, host, tag, digest, commit_sha, state, outcome, created_at)
         VALUES (?, ?, 'host-a', ?, 'sha256:aa', 'bb', ?, ?, 0)",
    )
    .bind(id)
    .bind(deployment)
    .bind(tag)
    .bind(state)
    .bind(outcome)
    .execute(executor)
    .await
    .map(drop)
}

#[tokio::test]
async fn hash_chain_links_each_row() {
    let store = Store::open_in_memory().await.unwrap();
    append_events(&store, 3).await;

    let rows = sqlx::query("SELECT seq, prev_hash, hash FROM audit_events ORDER BY seq")
        .fetch_all(&store.pool)
        .await
        .unwrap();
    assert_eq!(rows.len(), 3);
    let mut prev = GENESIS.to_vec();
    for (i, row) in rows.iter().enumerate() {
        assert_eq!(row.get::<i64, _>("seq"), i64::try_from(i + 1).unwrap());
        assert_eq!(row.get::<Vec<u8>, _>("prev_hash"), prev);
        prev = row.get("hash");
    }
    assert_eq!(chain(&store).await, (3, None));
    let report = store.verify_audit().await.unwrap();
    assert_eq!(report.head_seq, Some(3));
    assert_eq!(report.head_hash, Some(hex::encode(prev)));
}

#[tokio::test]
async fn an_empty_log_has_no_head() {
    let store = Store::open_in_memory().await.unwrap();
    assert_eq!(
        store.verify_audit().await.unwrap(),
        AuditReport {
            rows: 0,
            first_bad: None,
            head_seq: None,
            head_hash: None
        }
    );
}

/// The limit of the chain, which is why the head is printed: these verify
/// clean, and only a head kept from before shows they happened.
#[tokio::test]
async fn the_head_shows_what_the_chain_cannot() {
    for statements in [
        vec![
            "DELETE FROM audit_events WHERE seq > 2",
            "UPDATE sqlite_sequence SET seq = 2 WHERE name = 'audit_events'",
        ],
        vec![
            "DELETE FROM audit_events",
            "DELETE FROM sqlite_sequence WHERE name = 'audit_events'",
        ],
    ] {
        let store = Store::open_in_memory().await.unwrap();
        append_events(&store, 4).await;
        let kept = store.verify_audit().await.unwrap();
        drop_append_only_triggers(&store).await;
        for statement in statements {
            sqlx::query(statement).execute(&store.pool).await.unwrap();
        }
        let later = store.verify_audit().await.unwrap();
        assert_eq!(later.first_bad, None);
        assert_ne!(later.head_seq, kept.head_seq);
        assert_ne!(later.head_hash, kept.head_hash);
    }
}

#[tokio::test]
async fn the_hash_covers_the_row_as_stored() {
    let mut store = Store::open_in_memory().await.unwrap();
    store.clock = ManualClock::at(1_800_000_000);
    let mut tx = store.begin().await.unwrap();
    store.append(&mut tx, &event(1)).await.unwrap();
    tx.commit().await.unwrap();

    let row = sqlx::query("SELECT * FROM audit_events")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(row.get::<i64, _>("ts"), 1_800_000_000);
    assert_eq!(row.get::<String, _>("kind"), "deploy_queued");
    assert_eq!(row.get::<String, _>("deployment"), "app/prod");
    assert_eq!(row.get::<String, _>("host"), "host-a");
    assert_eq!(row.get::<String, _>("detail"), r#"{"n":1}"#);
    let want = RowFields {
        seq: 1,
        ts: 1_800_000_000,
        kind: b"deploy_queued",
        deployment: Some(b"app/prod"),
        host: Some(b"host-a"),
        detail: br#"{"n":1}"#,
    }
    .hash(&GENESIS);
    assert_eq!(row.get::<Vec<u8>, _>("hash"), want);
}

#[tokio::test]
async fn tampering_is_detected() {
    for (name, statements, rows, first_bad) in [
        (
            "edit detail",
            vec![r#"UPDATE audit_events SET detail = '{"n":99}' WHERE seq = 2"#],
            4,
            2,
        ),
        (
            "edit time",
            vec!["UPDATE audit_events SET ts = ts + 1 WHERE seq = 3"],
            4,
            3,
        ),
        (
            "clear a host",
            vec!["UPDATE audit_events SET host = NULL WHERE seq = 1"],
            4,
            1,
        ),
        (
            "invalid text in a field",
            vec!["UPDATE audit_events SET kind = CAST(X'FF' AS TEXT) WHERE seq = 2"],
            4,
            2,
        ),
        (
            "delete a row",
            vec!["DELETE FROM audit_events WHERE seq = 2"],
            3,
            3,
        ),
        (
            "delete the first row",
            vec!["DELETE FROM audit_events WHERE seq = 1"],
            3,
            2,
        ),
        (
            "delete the last row",
            vec!["DELETE FROM audit_events WHERE seq = 4"],
            3,
            4,
        ),
        ("delete every row", vec!["DELETE FROM audit_events"], 0, 1),
        (
            "swap two rows",
            vec![
                "UPDATE audit_events SET seq = 100 WHERE seq = 2",
                "UPDATE audit_events SET seq = 2 WHERE seq = 3",
                "UPDATE audit_events SET seq = 3 WHERE seq = 100",
            ],
            4,
            2,
        ),
        (
            "renumber a row",
            vec!["UPDATE audit_events SET seq = 5 WHERE seq = 4"],
            4,
            5,
        ),
        (
            "forge a row at the lowest seq",
            vec![
                "INSERT INTO audit_events (seq, ts, kind, detail, prev_hash, hash)
                 VALUES (-9223372036854775808, 0, 'forged', '{}', X'00', X'00')",
            ],
            5,
            1,
        ),
        (
            "lower the sequence record",
            vec!["UPDATE sqlite_sequence SET seq = 2 WHERE name = 'audit_events'"],
            4,
            5,
        ),
        (
            "delete the sequence record",
            vec!["DELETE FROM sqlite_sequence WHERE name = 'audit_events'"],
            4,
            5,
        ),
    ] {
        let store = Store::open_in_memory().await.unwrap();
        append_events(&store, 4).await;
        drop_append_only_triggers(&store).await;
        for statement in statements {
            sqlx::query(statement).execute(&store.pool).await.unwrap();
        }
        assert_eq!(chain(&store).await, (rows, Some(first_bad)), "{name}");
    }
}

#[tokio::test]
async fn appending_after_a_deleted_tail_does_not_hide_it() {
    let store = Store::open_in_memory().await.unwrap();
    append_events(&store, 3).await;
    drop_append_only_triggers(&store).await;
    sqlx::query("DELETE FROM audit_events WHERE seq = 3")
        .execute(&store.pool)
        .await
        .unwrap();
    append_events(&store, 1).await;
    assert_eq!(chain(&store).await, (3, Some(4)));
}

#[tokio::test]
async fn the_log_is_append_only_through_sql() {
    let store = Store::open_in_memory().await.unwrap();
    append_events(&store, 2).await;
    for statement in [
        "UPDATE audit_events SET ts = 0 WHERE seq = 1",
        "DELETE FROM audit_events WHERE seq = 2",
    ] {
        let error = sqlx::query(statement)
            .execute(&store.pool)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("append-only"), "{error}");
    }
    assert_eq!(store.verify_audit().await.unwrap().first_bad, None);
}

/// `INSERT OR REPLACE` deletes the row it replaces without firing a delete
/// trigger.
#[tokio::test]
async fn insert_or_replace_cannot_overwrite_a_row() {
    let store = Store::open_in_memory().await.unwrap();
    append_events(&store, 2).await;
    let error = sqlx::query(
        "INSERT OR REPLACE INTO audit_events (seq, ts, kind, detail, prev_hash, hash)
         VALUES (1, 0, 'forged', '{}', X'00', X'00')",
    )
    .execute(&store.pool)
    .await
    .unwrap_err();
    assert!(error.to_string().contains("append-only"), "{error}");
    assert_eq!(store.verify_audit().await.unwrap().first_bad, None);
}

#[tokio::test]
async fn audit_row_and_state_change_commit_together() {
    let store = Store::open_in_memory().await.unwrap();
    insert_release(&store, "app/prod", "v1").await;
    insert_deploy(&store.pool, 1, "app/prod", "v1", "queued", None)
        .await
        .unwrap();

    // A failing state change: the error leaves through `?` in real code,
    // which drops the transaction. The audit row must go with it.
    let mut tx = store.begin().await.unwrap();
    store.append(&mut tx, &event(1)).await.unwrap();
    let failed = insert_deploy(&mut *tx, 2, "app/prod", "v1", "queued", None).await;
    assert!(failed.is_err());
    drop(tx);
    assert_eq!(store.verify_audit().await.unwrap().rows, 0);

    // And a successful one commits both.
    let mut tx = store.begin().await.unwrap();
    insert_deploy(&mut *tx, 3, "app/prod", "v1", "finished", Some("failed"))
        .await
        .unwrap();
    store.append(&mut tx, &event(2)).await.unwrap();
    tx.commit().await.unwrap();
    assert_eq!(chain(&store).await, (1, None));
}

#[tokio::test]
async fn only_one_active_deploy_per_deployment() {
    let store = Store::open_in_memory().await.unwrap();
    insert_release(&store, "app/prod", "v1").await;
    insert_release(&store, "app/stage", "v1").await;
    let pool = &store.pool;

    insert_deploy(pool, 1, "app/prod", "v1", "queued", None)
        .await
        .unwrap();
    // A second active deploy is refused, queued or claimed.
    for (id, state) in [(2, "queued"), (3, "claimed")] {
        assert!(
            insert_deploy(pool, id, "app/prod", "v1", state, None)
                .await
                .is_err(),
            "{state}"
        );
    }
    // Another deployment and finished deploys are unaffected.
    insert_deploy(pool, 4, "app/stage", "v1", "claimed", None)
        .await
        .unwrap();
    insert_deploy(pool, 5, "app/prod", "v1", "finished", Some("deployed"))
        .await
        .unwrap();
    // Once the active one finishes, another may start.
    sqlx::query("UPDATE deploys SET state = 'finished', outcome = 'deployed' WHERE id = 1")
        .execute(pool)
        .await
        .unwrap();
    insert_deploy(pool, 6, "app/prod", "v1", "queued", None)
        .await
        .unwrap();
}

#[tokio::test]
async fn deploy_state_and_outcome_agree_and_references_hold() {
    let store = Store::open_in_memory().await.unwrap();
    let pool = &store.pool;
    // Foreign keys are on: there is no such release yet.
    assert!(
        insert_deploy(pool, 1, "app/prod", "v1", "queued", None)
            .await
            .is_err()
    );
    insert_release(&store, "app/prod", "v1").await;
    for (state, outcome) in [
        ("finished", None),
        ("queued", Some("deployed")),
        ("unknown", None),
    ] {
        assert!(
            insert_deploy(pool, 2, "app/prod", "v1", state, outcome)
                .await
                .is_err(),
            "{state} {outcome:?}"
        );
    }
}

#[tokio::test]
async fn db_file_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    append_events(&store, 1).await;

    for suffix in ["", "-wal", "-shm"] {
        let file = dir.path().join(format!("controller.db{suffix}"));
        let mode = fs::metadata(&file).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "{}", file.display());
    }
}

#[tokio::test]
async fn an_existing_loose_db_file_is_made_private() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();
    fs::set_permissions(&path, Permissions::from_mode(0o644)).unwrap();

    Store::open(&path).await.unwrap();
    let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[tokio::test]
async fn the_database_runs_in_wal_mode_with_foreign_keys() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let journal: String = sqlx::query_scalar("PRAGMA journal_mode")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(journal, "wal");
    let foreign_keys: i64 = sqlx::query_scalar("PRAGMA foreign_keys")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(foreign_keys, 1);
}

#[tokio::test]
async fn migrations_run_on_an_empty_file_and_are_idempotent() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    fs::write(&path, "").unwrap();

    let store = Store::open(&path).await.unwrap();
    append_events(&store, 2).await;
    store.pool.close().await;

    let store = Store::open(&path).await.unwrap();
    let names: Vec<String> = sqlx::query_scalar(
        "SELECT name FROM sqlite_master
         WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_sqlx_%'
         ORDER BY name",
    )
    .fetch_all(&store.pool)
    .await
    .unwrap();
    assert_eq!(
        names,
        [
            "api_tokens",
            "audit_events",
            "deploy_requests",
            "deploy_steps",
            "deploys",
            "enrol_codes",
            "hosts",
            "nonces",
            "passkey_invites",
            "passkeys",
            "release_holds",
            "releases",
            "replaced_releases",
            "running_states",
            "sessions"
        ]
    );
    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(applied, 4);
    assert_eq!(chain(&store).await, (2, None));
}

#[tokio::test]
async fn concurrent_writers_keep_one_chain() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let mut writers = Vec::new();
    for n in 0..16 {
        let store = store.clone();
        writers.push(tokio::spawn(async move {
            let mut tx = store.begin().await.unwrap();
            store.append(&mut tx, &event(n)).await.unwrap();
            tx.commit().await.unwrap();
        }));
    }
    for writer in writers {
        writer.await.unwrap();
    }
    assert_eq!(chain(&store).await, (16, None));
}

#[tokio::test]
async fn a_long_chain_verifies_across_pages() {
    let store = Store::open_in_memory().await.unwrap();
    let rows = u32::try_from(VERIFY_PAGE).unwrap() + 1;
    let mut tx = store.begin().await.unwrap();
    for n in 1..=rows {
        store.append(&mut tx, &event(n)).await.unwrap();
    }
    tx.commit().await.unwrap();
    assert_eq!(chain(&store).await, (u64::from(rows), None));
}

#[tokio::test]
async fn oversized_detail_is_refused() {
    let store = Store::open_in_memory().await.unwrap();
    let mut tx = store.begin().await.unwrap();
    let big = AuditEvent {
        detail: json!("x".repeat(MAX_DETAIL_BYTES)),
        ..event(1)
    };
    assert!(matches!(
        store.append(&mut tx, &big).await,
        Err(StoreError::DetailTooLarge(_))
    ));
}

#[tokio::test]
async fn enrol_code_is_stored_only_as_a_hash_and_audited_without_it() {
    let mut store = Store::open_in_memory().await.unwrap();
    store.clock = ManualClock::at(1_000);
    let host: HostId = "host-a".parse().unwrap();
    let code = store.issue_enrol_code(&host, false).await.unwrap();
    let text = code.reveal();
    assert_eq!(text.len(), 64);
    assert!(!format!("{code:?}").contains(&text));

    let row = sqlx::query("SELECT * FROM enrol_codes")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    let want: [u8; 32] = Sha256::digest(hex::decode(&text).unwrap()).into();
    assert_eq!(row.get::<Vec<u8>, _>("code_hash"), want);
    assert_eq!(row.get::<String, _>("host"), "host-a");
    assert_eq!(row.get::<i64, _>("replace"), 0);
    assert_eq!(row.get::<i64, _>("expires_at"), 1_000 + 3_600);

    let audit = sqlx::query("SELECT kind, host, detail FROM audit_events")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(audit.get::<String, _>("kind"), "enrol_code_issued");
    assert_eq!(audit.get::<String, _>("host"), "host-a");
    let detail: String = audit.get("detail");
    assert_eq!(detail, r#"{"expires_at":4600,"replace":false}"#);
}

#[tokio::test]
async fn a_new_code_replaces_the_hosts_outstanding_one() {
    let store = Store::open_in_memory().await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    let other: HostId = "host-b".parse().unwrap();
    let first = store.issue_enrol_code(&host, false).await.unwrap();
    store.issue_enrol_code(&other, false).await.unwrap();
    let second = store.issue_enrol_code(&host, false).await.unwrap();
    assert_ne!(first.reveal(), second.reveal());
    let hosts: Vec<String> = sqlx::query_scalar("SELECT host FROM enrol_codes ORDER BY host")
        .fetch_all(&store.pool)
        .await
        .unwrap();
    assert_eq!(hosts, ["host-a", "host-b"]);
}

#[tokio::test]
async fn an_enrolled_host_needs_replace() {
    let store = Store::open_in_memory().await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    sqlx::query("INSERT INTO hosts (id, public_key, enrolled_at) VALUES ('host-a', ?, 0)")
        .bind(vec![0_u8; 32])
        .execute(&store.pool)
        .await
        .unwrap();

    assert!(matches!(
        store.issue_enrol_code(&host, false).await,
        Err(StoreError::AlreadyEnrolled(_))
    ));
    assert_eq!(store.verify_audit().await.unwrap().rows, 0);

    store.issue_enrol_code(&host, true).await.unwrap();
    let replace: i64 = sqlx::query_scalar("SELECT replace FROM enrol_codes")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert_eq!(replace, 1);
    let detail: String = sqlx::query_scalar("SELECT detail FROM audit_events")
        .fetch_one(&store.pool)
        .await
        .unwrap();
    assert!(detail.contains(r#""replace":true"#), "{detail}");
}
