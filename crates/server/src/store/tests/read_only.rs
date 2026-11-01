//! Opening a database for inspection.

use std::fs;

use super::*;

/// A database with `rows` audit rows, closed so its WAL is checkpointed.
async fn closed_database(path: &Path, rows: u32) {
    let store = Store::open(path).await.unwrap();
    append_events(&store, rows).await;
    store.close().await;
}

fn set_mode(path: &Path, mode: u32) {
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

#[tokio::test]
async fn opening_a_missing_database_does_not_create_it() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typo.db");
    assert!(Store::open_existing(&path).await.is_err());
    assert!(Store::open_read_only(&path).await.is_err());
    assert!(!path.exists());
}

/// A copy in a directory nothing can be created in: the file stays as it was
/// and no file appears beside it.
#[tokio::test]
async fn a_read_only_copy_verifies_without_being_written() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("controller.db");
    closed_database(&source, 3).await;
    let copies = dir.path().join("copies");
    fs::create_dir(&copies).unwrap();
    let copy = copies.join("controller.db");
    fs::copy(&source, &copy).unwrap();
    let before = fs::read(&copy).unwrap();
    set_mode(&copy, 0o400);
    set_mode(&copies, 0o500);
    // Root ignores the mode, and `SQLite` then does create its files.
    let probe = copies.join("probe");
    let mode_binds = fs::File::create(&probe).is_err();

    let store = Store::open_read_only(&copy).await.unwrap();
    let report = store.verify_audit().await;
    store.close().await;

    set_mode(&copies, 0o700);
    assert_eq!(report.unwrap().rows, 3);
    assert_eq!(fs::read(&copy).unwrap(), before);
    if mode_binds {
        assert_eq!(names_in(&copies), ["controller.db"]);
    }
}

/// A read-only file in a directory that can be written: `SQLite` may put its
/// shared-memory files there, but the file itself is untouched.
#[tokio::test]
async fn a_read_only_file_verifies_without_being_written() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    closed_database(&path, 3).await;
    let before = fs::read(&path).unwrap();
    set_mode(&path, 0o400);

    let store = Store::open_read_only(&path).await.unwrap();
    let report = store.verify_audit().await.unwrap();
    store.close().await;

    assert_eq!(report.rows, 3);
    assert_eq!(fs::read(&path).unwrap(), before);
}

/// `immutable` would read past rows still in the WAL. The fallback is safe
/// because its error code only comes when there is no `-wal` file: with one,
/// full or empty, a read-only directory gives another error and no fallback,
/// so a copy taken while the controller ran says so rather than verify old
/// rows.
#[tokio::test]
async fn a_read_only_copy_with_a_wal_is_not_read_without_it() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("controller.db");
    let running = Store::open(&source).await.unwrap();
    append_events(&running, 3).await;
    let wal = fs::read(dir.path().join("controller.db-wal")).unwrap();
    assert!(wal.len() > 1);
    for (name, wal) in [("full", wal.as_slice()), ("empty", &[])] {
        let copies = dir.path().join(format!("copies-{name}"));
        fs::create_dir(&copies).unwrap();
        let copy = copies.join("controller.db");
        fs::copy(&source, &copy).unwrap();
        fs::write(copies.join("controller.db-wal"), wal).unwrap();
        set_mode(&copy, 0o400);
        set_mode(&copies, 0o500);
        let mode_binds = fs::File::create(copies.join("probe")).is_err();

        let opened = Store::open_read_only(&copy).await;
        set_mode(&copies, 0o700);
        // Root ignores the mode, and the plain read-only open then works.
        if mode_binds {
            let error = opened.unwrap_err();
            let StoreError::Database(error) = &error else {
                panic!("{name}: {error}");
            };
            let code = error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code);
            assert_eq!(code.as_deref(), Some("14"), "{name}");
        }
    }
    running.close().await;
}

#[tokio::test]
async fn read_only_sees_a_running_controllers_latest_rows() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let running = Store::open(&path).await.unwrap();
    append_events(&running, 2).await;

    let reader = Store::open_read_only(&path).await.unwrap();
    assert_eq!(chain(&reader).await, (2, None));
    append_events(&running, 1).await;
    assert_eq!(chain(&reader).await, (3, None));
    assert!(
        sqlx::query("DELETE FROM enrol_codes")
            .execute(&reader.pool)
            .await
            .is_err()
    );
}
