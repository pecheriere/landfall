//! The controller's `SQLite` store and the audit log inside it.
//!
//! Every state change goes in a transaction from [`Store::begin`], together
//! with the audit row that records it through [`Store::append`]: both commit or
//! neither does.

mod agent;
mod auth;
mod ceremonies;
mod commits;
mod deploys;
pub(crate) mod history;
pub(crate) mod latest;
mod releases;
mod requests;
pub(crate) mod views;

use std::fmt;
use std::fs::{OpenOptions, Permissions};
use std::io;
use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use landfall_core::ids::{DeploymentId, HostId};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::migrate::{MigrateError, Migration, MigrationType, Migrator};
use sqlx::sqlite::{
    SqliteConnectOptions, SqliteJournalMode, SqlitePoolOptions, SqliteRow, SqliteSynchronous,
};
use sqlx::{Row as _, SqlSafeStr as _, Sqlite, SqliteExecutor, SqlitePool, Transaction};
use tokio::sync::watch;

pub use self::agent::NONCE_LIFETIME_SECS;
pub use self::ceremonies::SESSION_LIFETIME_SECS;
pub(crate) use self::ceremonies::{NewPasskey, Redeemed};
pub use self::commits::{CommitRange, NewRange, RangeState, WantedRange};
pub(crate) use self::deploys::REPORT_REFUSALS;
pub use self::deploys::{NewDeploy, ReportAck, WorkPick};
pub use self::releases::{
    FinishedDeploy, Hold, REPORT_FRESH_SECS, ReleaseDecision, Seen, StoredRelease, WatchView,
    WatchedRunning,
};
pub use self::requests::{
    NewRequest, REQUEST_LIFETIME_SECS, RequestSnapshot, RequestState, StoredRequest,
};
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
    /// The enrolment code is unknown, used, expired or for another host. These
    /// are one error so that the answer tells a guesser nothing.
    #[error("enrolment code refused")]
    InvalidCode,
    /// The public key is already enrolled to another host.
    #[error("public key is already enrolled to another host")]
    KeyInUse,
    /// Too many nonces are outstanding to issue another.
    #[error("too many outstanding nonces")]
    NonceTableFull,
    /// There is no such deploy for this host: it does not exist, it belongs to
    /// another host, or its id is out of range. These are one error so that a
    /// host cannot probe for other hosts' deploys.
    #[error("no such deploy for this host")]
    UnknownDeploy,
    /// The deploy was never handed to the host, so it cannot have finished.
    #[error("deploy was not claimed")]
    NotClaimed,
    /// A row holds a value the schema allows and the code cannot read: someone
    /// edited the file, or the code and the data disagree.
    #[error("database row is not readable: {0}")]
    Corrupt(&'static str),
    /// A deploy request holds a value the code cannot read. It names the row, for whoever
    /// has to look at it.
    #[error("deploy request {id} is not readable: {column}")]
    UnreadableRequest {
        /// Its number.
        id: i64,
        /// What can't be read of it.
        column: &'static str,
    },
    /// There is no API token with this id.
    #[error("there is no API token with this id")]
    UnknownToken,
}

impl StoreError {
    /// Whether this is only another writer in the way, gone by the time a retry
    /// comes: `SQLITE_BUSY`, with any extended code, or no connection free.
    #[must_use]
    pub fn is_busy(&self) -> bool {
        /// `SQLITE_BUSY`, in the low byte of every extended result code.
        const SQLITE_BUSY: i32 = 5;
        let Self::Database(error) = self else {
            return false;
        };
        matches!(error, sqlx::Error::PoolTimedOut)
            || error
                .as_database_error()
                .and_then(sqlx::error::DatabaseError::code)
                .and_then(|code| code.parse::<i32>().ok())
                .is_some_and(|code| code & 0xff == SQLITE_BUSY)
    }
}

/// The controller's clock, as unix seconds. A trait so that tests can move time
/// past an expiry.
pub trait Clock: fmt::Debug + Send + Sync {
    /// The time now.
    ///
    /// # Errors
    /// [`StoreError::Clock`] if the clock is unusable.
    fn now(&self) -> Result<i64, StoreError>;
}

/// The operating system's clock.
#[derive(Debug, Clone, Copy)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Result<i64, StoreError> {
        let elapsed = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| StoreError::Clock)?;
        i64::try_from(elapsed.as_secs()).map_err(|_| StoreError::Clock)
    }
}

/// A clock a test moves by hand.
#[cfg(test)]
#[derive(Debug)]
pub(crate) struct ManualClock(std::sync::atomic::AtomicI64);

#[cfg(test)]
impl ManualClock {
    pub(crate) fn at(now: i64) -> Arc<Self> {
        Arc::new(Self(std::sync::atomic::AtomicI64::new(now)))
    }

    pub(crate) fn advance(&self, seconds: i64) {
        self.0
            .fetch_add(seconds, std::sync::atomic::Ordering::SeqCst);
    }
}

#[cfg(test)]
impl Clock for ManualClock {
    fn now(&self) -> Result<i64, StoreError> {
        Ok(self.0.load(std::sync::atomic::Ordering::SeqCst))
    }
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

/// The schema, built into the binary: the image holds no other files.
fn migrator() -> Migrator {
    let migration = |version, name: &'static str, sql: &'static str| {
        Migration::new(
            version,
            name.into(),
            MigrationType::Simple,
            sql.into_sql_str(),
            false,
        )
    };
    Migrator::with_migrations(vec![
        migration(1, "init", include_str!("../migrations/0001_init.sql")),
        migration(2, "watcher", include_str!("../migrations/0002_watcher.sql")),
        migration(
            3,
            "approvals",
            include_str!("../migrations/0003_approvals.sql"),
        ),
        migration(
            4,
            "passkeys",
            include_str!("../migrations/0004_passkeys.sql"),
        ),
        migration(
            5,
            "read_indexes",
            include_str!("../migrations/0005_read_indexes.sql"),
        ),
        migration(
            6,
            "commit_ranges",
            include_str!("../migrations/0006_commit_ranges.sql"),
        ),
        migration(
            7,
            "latest_releases",
            include_str!("../migrations/0007_latest_releases.sql"),
        ),
        migration(
            8,
            "audit_indexes",
            include_str!("../migrations/0008_audit_indexes.sql"),
        ),
    ])
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

/// A row of the audit log, as it reads.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRow {
    /// Its place in the log.
    pub seq: i64,
    /// When it was written, in unix seconds.
    pub ts: i64,
    /// What it records.
    pub kind: String,
    /// The deployment it is about, if any.
    pub deployment: Option<String>,
    /// The host it is about, if any.
    pub host: Option<String>,
    /// Its detail, which should be JSON.
    pub detail: String,
}

/// The controller's database. Cloning shares the connections.
#[derive(Debug, Clone)]
pub struct Store {
    pool: SqlitePool,
    clock: Arc<dyn Clock>,
    /// Bumped when a deploy is queued, so that a long poll wakes for it.
    work_queued: watch::Sender<u64>,
}

impl Store {
    fn from_pool(pool: SqlitePool) -> Self {
        Self {
            pool,
            clock: Arc::new(SystemClock),
            work_queued: watch::channel(0).0,
        }
    }

    /// The controller's time now, in unix seconds.
    ///
    /// # Errors
    /// [`StoreError::Clock`] if the clock is unusable.
    pub fn now(&self) -> Result<i64, StoreError> {
        self.clock.now()
    }

    /// This store on another clock.
    #[cfg(test)]
    pub(crate) fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

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
        store.fill_latest().await?;
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
        Ok(Self::from_pool(pool))
    }

    /// This database again, on connections that give up on a lock at once: for
    /// a test to see what happens when another writer is in the way.
    #[cfg(test)]
    pub(crate) async fn open_impatient(path: &Path) -> Result<Self, StoreError> {
        Self::connect_waiting(path, Duration::ZERO).await
    }

    async fn connect(path: &Path) -> Result<Self, StoreError> {
        Self::connect_waiting(path, BUSY_TIMEOUT).await
    }

    async fn connect_waiting(path: &Path, busy_timeout: Duration) -> Result<Self, StoreError> {
        let options = SqliteConnectOptions::new()
            .filename(path)
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Full)
            .foreign_keys(true)
            .busy_timeout(busy_timeout);
        let pool = SqlitePoolOptions::new()
            .max_connections(MAX_CONNECTIONS)
            .connect_with(options)
            .await?;
        Ok(Self::from_pool(pool))
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
        let store = Self::from_pool(pool);
        store.fill_latest().await?;
        Ok(store)
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

    /// The connections, for a test to look at what was stored.
    #[cfg(test)]
    pub(crate) fn pool(&self) -> &SqlitePool {
        &self.pool
    }

    /// Closes every connection; later use fails. Closing the last one moves what is
    /// in the write-ahead log into the main file. Waits for connections in use.
    pub async fn close(&self) {
        self.pool.close().await;
    }

    /// Writes a copy of the whole database to `dest`, a file that is empty or new, in
    /// one read snapshot: a writer goes on meanwhile, and what it writes is not in
    /// the copy.
    ///
    /// # Errors
    /// [`StoreError::Database`] if the copy fails.
    pub async fn vacuum_into(&self, dest: &str) -> Result<(), StoreError> {
        sqlx::query("VACUUM INTO ?")
            .bind(dest)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// The newest `limit` rows of the audit log, of `deployment` if given, oldest of
    /// them first, as they are: for looking at, not for trusting, which is what
    /// [`verify_audit`](Self::verify_audit) is for. Text that isn't valid UTF-8 in a
    /// tampered row comes out replaced.
    ///
    /// # Errors
    /// [`StoreError::Database`] if the log cannot be read.
    pub async fn audit_rows(
        &self,
        deployment: Option<&DeploymentId>,
        limit: u32,
    ) -> Result<Vec<AuditRow>, StoreError> {
        let rows = sqlx::query(
            "SELECT seq, ts, CAST(kind AS BLOB), CAST(deployment AS BLOB), CAST(host AS BLOB),
                    CAST(detail AS BLOB)
             FROM audit_events
             WHERE ?1 IS NULL OR deployment = ?1
             ORDER BY seq DESC LIMIT ?2",
        )
        .bind(deployment.map(AsRef::<str>::as_ref))
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().rev().map(views::audit_row).collect()
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
        let ts = self.clock.now()?;
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
        let now = self.clock.now()?;
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
mod tests;
