//! The controller's `SQLite` store and the audit log inside it.
//!
//! Every state change goes in a transaction from [`Store::begin`], together
//! with the audit row that records it through [`Store::append`]: both commit or
//! neither does.

use std::fmt;
use std::fs::{OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use landfall_core::ids::HostId;
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row as _, SqlSafeStr as _, Sqlite, SqliteExecutor, SqlitePool, Transaction};

use crate::audit::{AuditEvent, AuditReport, EventKind, GENESIS, MAX_DETAIL_BYTES, RowFields};

/// How long an enrolment code stays valid, in seconds.
const ENROL_CODE_LIFETIME_SECS: i64 = 60 * 60;

/// Connections kept to the database. `SQLite` has one writer at a time anyway;
/// these let reads run beside it.
const MAX_CONNECTIONS: u32 = 4;

/// How long a statement waits for another writer before failing.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);

/// Rows read at a time when verifying the chain, so a long log needs no
/// memory in proportion to its length.
const VERIFY_PAGE: i64 = 1000;

/// `SQLite`'s result code when a read needs a file created in a directory that
/// cannot take one.
const SQLITE_READONLY_DIRECTORY: &str = "1544";

/// One page of the audit log after `$condition`. Fields come back as bytes so
/// that invalid text in a tampered row is a hash mismatch, not a decoding error.
/// Two statements and not one with an optional bound, which would scan the
/// table from its start for every page.
macro_rules! audit_page {
    ($condition:literal) => {
        concat!(
            "SELECT seq, ts, CAST(kind AS BLOB), CAST(deployment AS BLOB),
                    CAST(host AS BLOB), CAST(detail AS BLOB), prev_hash, hash
             FROM audit_events ",
            $condition,
            " ORDER BY seq LIMIT ?"
        )
    };
}

/// Why the store could not do what was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// The database file could not be created or made private.
    #[error("database file {}: {source}", .path.display())]
    File {
        /// The file.
        path: PathBuf,
        /// The failure.
        source: io::Error,
    },
    /// The path exists and is not a regular file.
    #[error("database path {} is not a regular file", .0.display())]
    NotAFile(PathBuf),
    /// `SQLite` refused or failed a statement.
    #[error("database: {0}")]
    Database(#[from] sqlx::Error),
    /// The schema could not be brought up to date.
    #[error("database migration: {0}")]
    Migrate(#[from] MigrateError),
    /// The system clock is before 1970 or out of range.
    #[error("the system clock is unusable")]
    Clock,
    /// An event's `detail` is longer than [`MAX_DETAIL_BYTES`].
    #[error("audit detail of {0} bytes is over the limit")]
    DetailTooLarge(usize),
    /// An event's `detail` could not be serialised.
    #[error("audit detail: {0}")]
    Detail(#[from] serde_json::Error),
    /// The host has a key, and replacing it was not asked for.
    #[error("host {0} is already enrolled; replacing its key needs --replace")]
    AlreadyEnrolled(HostId),
    /// The operating system's random generator failed.
    #[error("random generator: {0}")]
    Random(getrandom::Error),
}

/// A one-time enrolment code. Only its SHA-256 is stored; the code itself is
/// shown once, by [`reveal`](Self::reveal), and `Debug` does not print it.
pub struct EnrolCode([u8; 32]);

impl EnrolCode {
    /// The code as the operator gives it to the host: 64 hex digits.
    #[must_use]
    pub fn reveal(&self) -> String {
        hex::encode(self.0)
    }
}

impl fmt::Debug for EnrolCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrolCode(<redacted>)")
    }
}

/// The controller's clock, as unix seconds.
fn system_clock() -> Result<i64, StoreError> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| StoreError::Clock)?;
    i64::try_from(elapsed.as_secs()).map_err(|_| StoreError::Clock)
}

/// The schema, built into the binary: the image holds no other files.
fn migrator() -> Migrator {
    Migrator::with_migrations(vec![Migration::new(
        1,
        "init".into(),
        MigrationType::Simple,
        include_str!("../migrations/0001_init.sql").into_sql_str(),
        false,
    )])
}

/// Creates the database file private to this user, or makes an existing one
/// so, before `SQLite` opens it. `SQLite` gives the `-wal` and `-shm` files the
/// main file's permissions.
fn prepare_private_file(path: &Path) -> Result<(), StoreError> {
    let file_error = |source| StoreError::File {
        path: path.to_owned(),
        source,
    };
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .open(path)
        .map_err(file_error)?;
    let meta = file.metadata().map_err(file_error)?;
    if !meta.is_file() {
        return Err(StoreError::NotAFile(path.to_owned()));
    }
    if meta.permissions().mode() & 0o077 != 0 {
        file.set_permissions(Permissions::from_mode(0o600))
            .map_err(file_error)?;
    }
    Ok(())
}

/// The controller's database. Cloning shares the connections.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    clock: fn() -> Result<i64, StoreError>,
}

impl Store {
    /// Opens the database at `path`, creating it private to this user if it
    /// is missing, and brings its schema up to date.
    ///
    /// # Errors
    /// [`StoreError`] if the file cannot be made private or opened, or the
    /// schema cannot be migrated.
    pub async fn open(path: &Path) -> Result<Self, StoreError> {
        prepare_private_file(path)?;
        let store = Self::connect(path).await?;
        migrator().run(&store.pool).await?;
        Ok(store)
    }

    /// Opens a database that must already exist, leaving its schema alone: a
    /// mistyped path must not become a new and apparently working one.
    ///
    /// # Errors
    /// [`StoreError`] if the file is missing or cannot be opened.
    pub async fn open_existing(path: &Path) -> Result<Self, StoreError> {
        Self::connect(path).await
    }

    /// Opens a database for reading only, for inspecting a log: the main file
    /// is not written, nor its schema or journal mode changed, and a running
    /// controller's latest rows are seen.
    ///
    /// # Errors
    /// [`StoreError`] if the file is missing or cannot be read.
    pub async fn open_read_only(path: &Path) -> Result<Self, StoreError> {
        match Self::connect_read_only(path, false).await {
            // A database in WAL mode needs a `-wal` file beside it, which a
            // read-only directory cannot take. This code says that file does not
            // exist, so the main file is all there is, and `immutable` reads it
            // without one. With a `-wal` file the error is another, and stays an
            // error: `immutable` would miss the rows in it.
            Err(StoreError::Database(error))
                if error
                    .as_database_error()
                    .and_then(sqlx::error::DatabaseError::code)
                    .is_some_and(|code| code == SQLITE_READONLY_DIRECTORY) =>
            {
                Self::connect_read_only(path, true).await
            }
            other => other,
        }
    }

    async fn connect_read_only(path: &Path, immutable: bool) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .read_only(true)
            .immutable(immutable)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await?;
        // Opening touches nothing: this first read is what can fail.
        sqlx::query("SELECT count(*) FROM sqlite_master")
            .execute(&pool)
            .await?;
        Ok(Self {
            pool,
            clock: system_clock,
        })
    }

    async fn connect(path: &Path) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(BUSY_TIMEOUT);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await?;
        Ok(Self {
            pool,
            clock: system_clock,
        })
    }

    /// A private in-memory database on one connection that never closes, since
    /// the data lives and dies with it.
    #[cfg(test)]
    pub(crate) async fn open_in_memory() -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .in_memory(true)
            .foreign_keys(true);
        let pool = SqlitePoolOptions::new()
            .max_connections(1)
            .min_connections(1)
            .idle_timeout(None)
            .max_lifetime(None)
            .connect_with(options)
            .await?;
        migrator().run(&pool).await?;
        Ok(Self {
            pool,
            clock: system_clock,
        })
    }

    /// Starts a write transaction. It takes the write lock at once, so reading
    /// the head of the chain and appending after it cannot interleave with
    /// another writer. Dropping it without committing rolls it back.
    ///
    /// # Errors
    /// [`StoreError::Database`] if the lock is not free within the busy timeout.
    pub async fn begin(&self) -> Result<Transaction<'_, Sqlite>, StoreError> {
        Ok(self.pool.begin_with("BEGIN IMMEDIATE").await?)
    }

    /// Closes every connection; later use fails.
    #[cfg(test)]
    pub(crate) async fn close(&self) {
        self.pool.close().await;
    }

    /// Moves everything from the WAL into the main file, so copying that file
    /// alone gives a whole backup.
    #[cfg(test)]
    pub(crate) async fn checkpoint_for_test(&self) {
        sqlx::query("PRAGMA wal_checkpoint(TRUNCATE)")
            .execute(&self.pool)
            .await
            .unwrap();
    }

    /// Edits the first audit row the way someone with the file could.
    #[cfg(test)]
    pub(crate) async fn tamper_for_test(&self) {
        for statement in [
            "DROP TRIGGER audit_events_no_update",
            "UPDATE audit_events SET ts = ts + 1 WHERE seq = 1",
        ] {
            sqlx::query(statement).execute(&self.pool).await.unwrap();
        }
    }

    /// Whether the database answers.
    ///
    /// # Errors
    /// [`StoreError::Database`] if it does not.
    pub async fn ping(&self) -> Result<(), StoreError> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        Ok(())
    }

    /// Appends `event` to the audit log inside `tx`.
    ///
    /// # Errors
    /// [`StoreError::DetailTooLarge`] for a `detail` over [`MAX_DETAIL_BYTES`];
    /// otherwise a clock or database failure. The caller's transaction then
    /// must not commit, which leaving through `?` ensures.
    pub async fn append(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        event: &AuditEvent,
    ) -> Result<(), StoreError> {
        let detail = serde_json::to_string(&event.detail)?;
        if detail.len() > MAX_DETAIL_BYTES {
            return Err(StoreError::DetailTooLarge(detail.len()));
        }
        let ts = (self.clock)()?;
        // The next `seq` follows the highest ever written, not the last row
        // left: rows deleted from the end stay a visible gap after this one.
        // Saturating: at the very end of the range the insert fails instead.
        let seq = highest_seq(&mut **tx).await?.saturating_add(1);
        let prev_hash: Vec<u8> =
            sqlx::query_scalar("SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1")
                .fetch_optional(&mut **tx)
                .await?
                .unwrap_or_else(|| GENESIS.to_vec());
        let deployment = event.deployment.as_ref().map(AsRef::<str>::as_ref);
        let host = event.host.as_ref().map(AsRef::<str>::as_ref);
        let kind = event.kind.as_str();
        let hash = RowFields {
            seq,
            ts,
            kind: kind.as_bytes(),
            deployment: deployment.map(str::as_bytes),
            host: host.map(str::as_bytes),
            detail: detail.as_bytes(),
        }
        .hash(&prev_hash);
        sqlx::query(
            "INSERT INTO audit_events (seq, ts, kind, deployment, host, detail, prev_hash, hash)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(seq)
        .bind(ts)
        .bind(kind)
        .bind(deployment)
        .bind(host)
        .bind(detail)
        .bind(prev_hash)
        .bind(hash.as_slice())
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// Walks the chain from its first row, in one read snapshot.
    ///
    /// # Errors
    /// [`StoreError::Database`] if the log cannot be read. A log that can be
    /// read and is wrong is a report with `first_bad` set, not an error.
    pub async fn verify_audit(&self) -> Result<AuditReport, StoreError> {
        // A read transaction: every page sees the same state of the log.
        let mut snapshot = self.pool.begin().await?;
        let mut walk = ChainWalk::new();
        let mut after: Option<i64> = None;
        loop {
            let page = match after {
                // No lower bound: any `seq` a forged row could have is walked.
                None => sqlx::query(audit_page!(""))
                    .bind(VERIFY_PAGE)
                    .fetch_all(&mut *snapshot),
                Some(seq) => sqlx::query(audit_page!("WHERE seq > ?"))
                    .bind(seq)
                    .bind(VERIFY_PAGE)
                    .fetch_all(&mut *snapshot),
            }
            .await?;
            let Some(last) = page.last() else { break };
            after = Some(last.try_get(0)?);
            for row in &page {
                walk.visit(row)?;
            }
        }
        let count: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
            .fetch_one(&mut *snapshot)
            .await?;
        Ok(walk.finish(highest_seq(&mut *snapshot).await?, count))
    }

    /// The `hash` of the audit row at `seq`, in lowercase hex, if there is one.
    ///
    /// # Errors
    /// [`StoreError::Database`] if the log cannot be read.
    pub async fn audit_hash_at(&self, seq: i64) -> Result<Option<String>, StoreError> {
        let hash: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT hash FROM audit_events WHERE seq = ?")
                .bind(seq)
                .fetch_optional(&self.pool)
                .await?;
        Ok(hash.map(hex::encode))
    }

    /// Issues a one-time enrolment code bound to `host`, valid for an hour. It
    /// replaces any code still outstanding for that host, and is recorded in
    /// the audit log, without the code.
    ///
    /// # Errors
    /// [`StoreError::AlreadyEnrolled`] if the host has a key and `replace` is
    /// false; otherwise a clock, random generator or database failure.
    pub async fn issue_enrol_code(
        &self,
        host: &HostId,
        replace: bool,
    ) -> Result<EnrolCode, StoreError> {
        let mut code = [0; 32];
        getrandom::fill(&mut code).map_err(StoreError::Random)?;
        let code_hash: [u8; 32] = Sha256::digest(code).into();
        let now = (self.clock)()?;
        let expires_at = now + ENROL_CODE_LIFETIME_SECS;
        let host_id = host.as_ref();

        let mut tx = self.begin().await?;
        let enrolled: Option<i64> = sqlx::query_scalar("SELECT 1 FROM hosts WHERE id = ?")
            .bind(host_id)
            .fetch_optional(&mut *tx)
            .await?;
        if enrolled.is_some() && !replace {
            return Err(StoreError::AlreadyEnrolled(host.clone()));
        }
        sqlx::query("DELETE FROM enrol_codes WHERE host = ? OR expires_at <= ?")
            .bind(host_id)
            .bind(now)
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO enrol_codes (code_hash, host, replace, expires_at) VALUES (?, ?, ?, ?)",
        )
        .bind(code_hash.as_slice())
        .bind(host_id)
        .bind(replace)
        .bind(expires_at)
        .execute(&mut *tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::EnrolCodeIssued,
            deployment: None,
            host: Some(host.clone()),
            detail: json!({ "replace": replace, "expires_at": expires_at }),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(EnrolCode(code))
    }
}

/// The highest `seq` ever written to the log, 0 before the first row:
/// AUTOINCREMENT's record, which deleting rows does not lower.
async fn highest_seq(executor: impl SqliteExecutor<'_>) -> Result<i64, sqlx::Error> {
    let highest: Option<i64> =
        sqlx::query_scalar("SELECT seq FROM sqlite_sequence WHERE name = 'audit_events'")
            .fetch_optional(executor)
            .await?;
    Ok(highest.unwrap_or(0))
}

/// Walking the chain row by row, in `seq` order.
struct ChainWalk {
    rows: u64,
    first_bad: Option<u64>,
    last_seq: i64,
    prev_hash: [u8; 32],
    /// The last row seen, good or not.
    head: Option<(i64, Vec<u8>)>,
}

/// A `seq` as `first_bad` reports it. Only a tampered row can have one below
/// zero, and it is then the first row walked, which is reported as row 1.
fn report_seq(seq: i64) -> u64 {
    u64::try_from(seq).unwrap_or(1)
}

impl ChainWalk {
    fn new() -> Self {
        Self {
            rows: 0,
            first_bad: None,
            last_seq: 0,
            prev_hash: GENESIS,
            head: None,
        }
    }

    /// Checks one row against the ones before it. Only the first failure is
    /// kept, and once there is one the rows are only counted: nothing after it
    /// can be said to follow from a good chain.
    fn visit(&mut self, row: &SqliteRow) -> Result<(), sqlx::Error> {
        self.rows += 1;
        let seq: i64 = row.try_get(0)?;
        let stored_hash: Vec<u8> = row.try_get(7)?;
        let head = self.head.insert((seq, stored_hash));
        if self.first_bad.is_some() {
            return Ok(());
        }
        let stored_hash = &head.1;
        let kind: Vec<u8> = row.try_get(2)?;
        let deployment: Option<Vec<u8>> = row.try_get(3)?;
        let host: Option<Vec<u8>> = row.try_get(4)?;
        let detail: Vec<u8> = row.try_get(5)?;
        let stored_prev: Vec<u8> = row.try_get(6)?;
        let hash = RowFields {
            seq,
            ts: row.try_get(1)?,
            kind: &kind,
            deployment: deployment.as_deref(),
            host: host.as_deref(),
            detail: &detail,
        }
        .hash(&self.prev_hash);
        let follows = self.last_seq.checked_add(1) == Some(seq)
            && stored_prev == self.prev_hash
            && *stored_hash == hash;
        if follows {
            self.last_seq = seq;
            self.prev_hash = hash;
        } else {
            self.first_bad = Some(report_seq(seq));
        }
        Ok(())
    }

    /// The report, given the highest `seq` the database remembers writing and
    /// its count of rows. The record past the last row means rows are missing
    /// from the end; below it, or gone, means the record was changed; a count
    /// other than the rows walked means some row was not walked.
    fn finish(self, highest: i64, count: i64) -> AuditReport {
        let disagrees = highest != self.last_seq || u64::try_from(count).ok() != Some(self.rows);
        let first_bad = self
            .first_bad
            .or_else(|| disagrees.then(|| report_seq(self.last_seq) + 1));
        let (head_seq, head_hash) = self
            .head
            .map(|(seq, hash)| (seq, hex::encode(hash)))
            .unzip();
        AuditReport {
            rows: self.rows,
            first_bad,
            head_seq,
            head_hash,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

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
        id: &str,
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
        store.clock = || Ok(1_800_000_000);
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
        insert_deploy(&store.pool, "d1", "app/prod", "v1", "queued", None)
            .await
            .unwrap();

        // A failing state change: the error leaves through `?` in real code,
        // which drops the transaction. The audit row must go with it.
        let mut tx = store.begin().await.unwrap();
        store.append(&mut tx, &event(1)).await.unwrap();
        let failed = insert_deploy(&mut *tx, "d2", "app/prod", "v1", "queued", None).await;
        assert!(failed.is_err());
        drop(tx);
        assert_eq!(store.verify_audit().await.unwrap().rows, 0);

        // And a successful one commits both.
        let mut tx = store.begin().await.unwrap();
        insert_deploy(&mut *tx, "d3", "app/prod", "v1", "finished", Some("failed"))
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

        insert_deploy(pool, "d1", "app/prod", "v1", "queued", None)
            .await
            .unwrap();
        // A second active deploy is refused, queued or claimed.
        for (id, state) in [("d2", "queued"), ("d3", "claimed")] {
            assert!(
                insert_deploy(pool, id, "app/prod", "v1", state, None)
                    .await
                    .is_err(),
                "{state}"
            );
        }
        // Another deployment and finished deploys are unaffected.
        insert_deploy(pool, "d4", "app/stage", "v1", "claimed", None)
            .await
            .unwrap();
        insert_deploy(pool, "d5", "app/prod", "v1", "finished", Some("deployed"))
            .await
            .unwrap();
        // Once the active one finishes, another may start.
        sqlx::query("UPDATE deploys SET state = 'finished', outcome = 'deployed' WHERE id = 'd1'")
            .execute(pool)
            .await
            .unwrap();
        insert_deploy(pool, "d6", "app/prod", "v1", "queued", None)
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn deploy_state_and_outcome_agree_and_references_hold() {
        let store = Store::open_in_memory().await.unwrap();
        let pool = &store.pool;
        // Foreign keys are on: there is no such release yet.
        assert!(
            insert_deploy(pool, "d1", "app/prod", "v1", "queued", None)
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
                insert_deploy(pool, "d2", "app/prod", "v1", state, outcome)
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
                "audit_events",
                "deploy_steps",
                "deploys",
                "enrol_codes",
                "hosts",
                "nonces",
                "releases"
            ]
        );
        let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(applied, 1);
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

    #[tokio::test]
    async fn enrol_code_is_stored_only_as_a_hash_and_audited_without_it() {
        let mut store = Store::open_in_memory().await.unwrap();
        store.clock = || Ok(1_000);
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
}
