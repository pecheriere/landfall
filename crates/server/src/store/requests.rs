//! Deploy requests: the intent an approver signs, and the deploy that signing queues.
//!
//! `migrations/0003_approvals.sql` has the states. Each function here is one step in the
//! caller's transaction, with its audit row, so that a step and its record commit together.
//! What a step may do, and what is told to whom, is [`crate::requests`]'s.

use std::str::FromStr;

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, DeployId};
use landfall_core::text::shown;
use serde_json::{Value, json};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, SqliteConnection, Transaction};

use super::deploys::{NewDeploy, parsed};
use super::releases::{StoredRelease, WatchedRunning, release_of, running_of};
use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};
use crate::logger::log;

/// How long a request waits for an approver, in seconds, by the controller's clock. The
/// host uses none of this: it goes by the nonce and the running digest. This is only so
/// that a request nobody signs doesn't keep the next one out for ever.
pub const REQUEST_LIFETIME_SECS: i64 = 24 * 60 * 60;

/// Where a request stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestState {
    /// Its intent waits for an approver's assertion.
    AwaitingApproval,
    /// A verified assertion queued its deploy.
    Approved,
    /// What it was made from changed. Ask again.
    Stale,
    /// It waited too long. Ask again.
    Expired,
    /// Someone cancelled it, or a rollback took its place. Ask again.
    Cancelled,
}

impl RequestState {
    pub(super) fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "approved" => Ok(Self::Approved),
            "stale" => Ok(Self::Stale),
            "expired" => Ok(Self::Expired),
            "cancelled" => Ok(Self::Cancelled),
            _ => Err(StoreError::Corrupt("request state")),
        }
    }
}

/// A `deploy_requests` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRequest {
    /// Its number.
    pub id: i64,
    /// The host the intent is for.
    pub host: HostId,
    /// What an approver signs.
    pub intent: DeployIntent,
    /// Where it stands.
    pub state: RequestState,
    /// Who asked.
    pub requested_by: PrincipalId,
    /// When.
    pub created_at: i64,
    /// When it stops being open.
    pub expires_at: i64,
    /// Whether it asked for a lower version than ran when it was made.
    pub is_rollback: bool,
}

/// A request to record.
#[derive(Debug, Clone)]
pub struct NewRequest<'a> {
    /// The host the intent is for.
    pub host: &'a HostId,
    /// What an approver will sign.
    pub intent: DeployIntent,
    /// Who asks.
    pub requested_by: &'a PrincipalId,
    /// Who asks, as the audit row names them.
    pub audited_by: Value,
    /// Whether it asks for a lower version than runs now.
    pub is_rollback: bool,
}

/// All that bears on a request for (deployment, tag), read in one transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestSnapshot {
    /// What its host last said, if its host, as the configuration has it now, said so.
    pub running: Option<WatchedRunning>,
    /// Whether its host's configuration differs from the controller's.
    pub config_drifted: bool,
    /// Whether it has a queued or claimed deploy.
    pub active_deploy: bool,
    /// Whether it has a request waiting for an approver.
    pub open_request: bool,
    /// What the watcher recorded of the release.
    pub release: Option<StoredRelease>,
}

const COLUMNS: &str = "id, deployment, host, tag, commit_sha, digest, expected_running,
                       is_rollback, nonce, state, requested_by, created_at, expires_at";

/// What the audit row of a request ending says of it: as bytes, since this must work on a
/// row nothing can read. Ending a request never parses it, so one row can't stop a report,
/// or anyone else's request, from going through.
const CLOSING_COLUMNS: &str =
    "id, CAST(deployment AS BLOB) AS deployment, CAST(host AS BLOB) AS host,
                               CAST(tag AS BLOB) AS tag, CAST(digest AS BLOB) AS digest,
                               CAST(expected_running AS BLOB) AS expected_running";

/// A row of `COLUMNS` read, or what is wrong with it, naming the row.
fn stored_request(row: &SqliteRow) -> Result<StoredRequest, StoreError> {
    let id: i64 = row.try_get("id")?;
    read_request(row, id).map_err(|error| match error {
        StoreError::Corrupt(column) => StoreError::UnreadableRequest { id, column },
        // Bytes in a text column that aren't text.
        StoreError::Database(sqlx::Error::ColumnDecode { .. }) => StoreError::UnreadableRequest {
            id,
            column: "a text column",
        },
        other => other,
    })
}

fn read_request(row: &SqliteRow, id: i64) -> Result<StoredRequest, StoreError> {
    let nonce: Vec<u8> = row.try_get("nonce")?;
    let expected_running = row
        .try_get::<Option<String>, _>("expected_running")?
        .map(|_| parsed(row, "expected_running"))
        .transpose()?;
    Ok(StoredRequest {
        host: parsed(row, "host")?,
        intent: DeployIntent {
            deployment: parsed(row, "deployment")?,
            tag: parsed(row, "tag")?,
            commit: parsed(row, "commit_sha")?,
            digest: parsed(row, "digest")?,
            expected_running,
            nonce: nonce.try_into().map_err(|_| StoreError::Corrupt("nonce"))?,
        },
        state: RequestState::parse(&row.try_get::<String, _>("state")?)?,
        requested_by: parsed(row, "requested_by")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
        is_rollback: row.try_get("is_rollback")?,
        id,
    })
}

/// A column of `CLOSING_COLUMNS` as text, whatever its bytes are.
fn raw_text(row: &SqliteRow, column: &str) -> Result<Option<String>, sqlx::Error> {
    let bytes: Option<Vec<u8>> = row.try_get(column)?;
    Ok(bytes.map(|bytes| String::from_utf8_lossy(&bytes).into_owned()))
}

/// What an audit row says of a stored value: as it is if it is what it should be, quoted and
/// cut if it isn't, since then anything could be in it.
fn audited_value<T: FromStr>(text: Option<&str>) -> Value {
    match text {
        None => Value::Null,
        Some(text) if text.parse::<T>().is_ok() => json!(text),
        Some(text) => json!(shown(text)),
    }
}

/// The audit row of a request ending for `reason`, which is the controller's own text, from
/// a row of `CLOSING_COLUMNS`. A column only holds what is valid: what isn't is in `detail`.
fn closing_event(kind: EventKind, row: &SqliteRow, reason: &str) -> Result<AuditEvent, StoreError> {
    let deployment = raw_text(row, "deployment")?;
    let host = raw_text(row, "host")?;
    Ok(AuditEvent {
        kind,
        deployment: deployment.as_deref().and_then(|text| text.parse().ok()),
        host: host.as_deref().and_then(|text| text.parse().ok()),
        detail: json!({
            "request": row.try_get::<i64, _>("id")?,
            "deployment": audited_value::<DeploymentId>(deployment.as_deref()),
            "host": audited_value::<HostId>(host.as_deref()),
            "tag": audited_value::<ReleaseTag>(raw_text(row, "tag")?.as_deref()),
            "digest": audited_value::<ImageDigest>(raw_text(row, "digest")?.as_deref()),
            "expected_running":
                audited_value::<ImageDigest>(raw_text(row, "expected_running")?.as_deref()),
            "reason": reason,
        }),
    })
}

impl Store {
    /// The request with this number, as it is now.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn request(&self, id: i64) -> Result<Option<StoredRequest>, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM deploy_requests WHERE id = ?"
        )))
        .bind(id)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(stored_request).transpose()
    }

    /// The deployment a request says it is of, if it says one, whatever else about the row
    /// can't be read: who may be told about a row nothing can read goes by this.
    ///
    /// # Errors
    /// A database failure.
    pub async fn request_deployment(&self, id: i64) -> Result<Option<DeploymentId>, StoreError> {
        let bytes: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT CAST(deployment AS BLOB) FROM deploy_requests WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await?;
        Ok(bytes.and_then(|bytes| String::from_utf8_lossy(&bytes).parse().ok()))
    }

    /// Every request waiting for an approver, not yet past its time at `now`, but for any
    /// nothing can read, which are logged by number and left for the next tick after their
    /// time to end. At most one for each deployment, so this needs no paging.
    ///
    /// # Errors
    /// A database failure.
    pub async fn open_requests(&self, now: i64) -> Result<Vec<StoredRequest>, StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM deploy_requests
             WHERE state = 'awaiting_approval' AND expires_at > ? ORDER BY id"
        )))
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        let mut open = Vec::with_capacity(rows.len());
        for row in &rows {
            match stored_request(row) {
                Ok(request) => open.push(request),
                Err(error @ StoreError::UnreadableRequest { .. }) => log(&error.to_string()),
                Err(error) => return Err(error),
            }
        }
        Ok(open)
    }

    /// What bears on a request for this release, in `tx`.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn request_snapshot(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        (deployment, host, tag): (&DeploymentId, &HostId, &ReleaseTag),
    ) -> Result<RequestSnapshot, StoreError> {
        let connection: &mut SqliteConnection = tx;
        let running = running_of(connection, deployment, host).await?;
        let drifted: Option<bool> =
            sqlx::query_scalar("SELECT drifted_config_hash IS NOT NULL FROM hosts WHERE id = ?")
                .bind(host.as_ref())
                .fetch_optional(&mut *connection)
                .await?;
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM deploys WHERE deployment = ? AND state IN ('queued', 'claimed')",
        )
        .bind(deployment.as_ref())
        .fetch_optional(&mut *connection)
        .await?;
        let open: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM deploy_requests WHERE deployment = ? AND state = 'awaiting_approval'",
        )
        .bind(deployment.as_ref())
        .fetch_optional(&mut *connection)
        .await?;
        Ok(RequestSnapshot {
            running,
            config_drifted: drifted.unwrap_or(false),
            active_deploy: active.is_some(),
            open_request: open.is_some(),
            release: release_of(connection, deployment, tag).await?,
        })
    }

    /// Whether the watcher has this release on hold, in `tx`.
    ///
    /// # Errors
    /// A database failure.
    pub async fn release_held(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<bool, StoreError> {
        let held: Option<i64> =
            sqlx::query_scalar("SELECT 1 FROM release_holds WHERE deployment = ? AND tag = ?")
                .bind(deployment.as_ref())
                .bind(tag.as_ref())
                .fetch_optional(&mut **tx)
                .await?;
        Ok(held.is_some())
    }

    /// Records a request, waiting for an approver, with its audit row.
    ///
    /// # Errors
    /// A clock, database or audit failure, including its deployment already having an open
    /// request, or the release not being recorded.
    pub async fn insert_request(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        request: &NewRequest<'_>,
    ) -> Result<StoredRequest, StoreError> {
        let now = self.clock.now()?;
        let intent = &request.intent;
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "INSERT INTO deploy_requests
                 (deployment, host, tag, commit_sha, digest, expected_running, is_rollback, nonce,
                  state, requested_by, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'awaiting_approval', ?, ?, ?)
             RETURNING {COLUMNS}"
        )))
        .bind(intent.deployment.as_ref())
        .bind(request.host.as_ref())
        .bind(intent.tag.as_ref())
        .bind(intent.commit.as_ref())
        .bind(intent.digest.as_ref())
        .bind(intent.expected_running.as_ref().map(AsRef::<str>::as_ref))
        .bind(request.is_rollback)
        .bind(intent.nonce.as_slice())
        .bind(request.requested_by.as_ref())
        .bind(now)
        .bind(now.saturating_add(REQUEST_LIFETIME_SECS))
        .fetch_one(&mut **tx)
        .await?;
        let stored = stored_request(&row)?;
        let event = AuditEvent {
            kind: EventKind::DeployRequested,
            deployment: Some(intent.deployment.clone()),
            host: Some(request.host.clone()),
            detail: json!({
                "request": stored.id,
                "by": request.audited_by,
                "tag": intent.tag,
                "commit": intent.commit,
                "digest": intent.digest,
                "expected_running": intent.expected_running,
                "nonce": hex::encode(intent.nonce),
            }),
        };
        self.append(tx, &event).await?;
        Ok(stored)
    }

    /// Ends every open request past its time at `now`, each with its audit row.
    ///
    /// # Errors
    /// A database or audit failure.
    pub async fn expire_requests(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        now: i64,
    ) -> Result<(), StoreError> {
        self.expire_of(tx, None, now).await
    }

    /// Ends the open requests past their time at `now`, of one deployment or of all, each with
    /// its audit row.
    async fn expire_of(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        deployment: Option<&DeploymentId>,
        now: i64,
    ) -> Result<(), StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests
             SET state = 'expired', closed_at = ?1, closed_reason = ?2
             WHERE state = 'awaiting_approval' AND expires_at <= ?1
                   AND (?3 IS NULL OR deployment = ?3)
             RETURNING {CLOSING_COLUMNS}"
        )))
        .bind(now)
        .bind(EXPIRED_REASON)
        .bind(deployment.map(AsRef::<str>::as_ref))
        .fetch_all(&mut **tx)
        .await?;
        for row in &rows {
            let event = closing_event(EventKind::RequestExpired, row, EXPIRED_REASON)?;
            self.append(tx, &event).await?;
        }
        Ok(())
    }

    /// Ends every open request past its time now, in a transaction of its own: for the
    /// watcher's tick, so that one nobody comes back to is still ended, and audited, near
    /// its time.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn settle_expired_requests(&self) -> Result<(), StoreError> {
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        self.expire_requests(&mut tx, now).await?;
        tx.commit().await?;
        Ok(())
    }

    /// Ends `deployment`'s open request if it was made for another running digest than
    /// `running`, with its audit row. In the transaction of the report that says so, so
    /// that nothing can approve it after that report stands. One past its time is expired
    /// first, whatever the report says: that is what became of it. This touches no other
    /// deployment's: a report is about its own, and must not fail for another's row. The
    /// watcher's tick and whoever asks next end those.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub(super) async fn stale_other_requests(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        deployment: &DeploymentId,
        running: Option<&str>,
        reason: &str,
    ) -> Result<(), StoreError> {
        let now = self.clock.now()?;
        self.expire_of(tx, Some(deployment), now).await?;
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests
             SET state = 'stale', closed_at = ?, closed_reason = ?
             WHERE deployment = ? AND state = 'awaiting_approval' AND expected_running IS NOT ?
             RETURNING {CLOSING_COLUMNS}"
        )))
        .bind(now)
        .bind(reason)
        .bind(deployment.as_ref())
        .bind(running)
        .fetch_all(&mut **tx)
        .await?;
        for row in &rows {
            let event = closing_event(EventKind::RequestStale, row, reason)?;
            self.append(tx, &event).await?;
        }
        Ok(())
    }

    /// Ends this one open request as stale, with its audit row.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn stale_request(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        request: &StoredRequest,
        reason: &str,
    ) -> Result<(), StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests SET state = 'stale', closed_at = ?, closed_reason = ?
             WHERE id = ? AND state = 'awaiting_approval'
             RETURNING {CLOSING_COLUMNS}"
        )))
        .bind(self.clock.now()?)
        .bind(reason)
        .bind(request.id)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Ok(());
        };
        let event = closing_event(EventKind::RequestStale, &row, reason)?;
        self.append(tx, &event).await
    }

    /// Cancels `deployment`'s open request, or with `only` just that one if it is, with its
    /// audit row naming who. Gives whether it ended one. `reason` is the controller's own
    /// text.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn cancel_open_request(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        (deployment, only): (&DeploymentId, Option<i64>),
        by: &Value,
        reason: &str,
    ) -> Result<bool, StoreError> {
        let row = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests
             SET state = 'cancelled', closed_at = ?, closed_reason = ?
             WHERE deployment = ?3 AND state = 'awaiting_approval' AND (?4 IS NULL OR id = ?4)
             RETURNING {CLOSING_COLUMNS}"
        )))
        .bind(self.clock.now()?)
        .bind(reason)
        .bind(deployment.as_ref())
        .bind(only)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else {
            return Ok(false);
        };
        let mut event = closing_event(EventKind::RequestCancelled, &row, reason)?;
        event.detail["by"] = by.clone();
        self.append(tx, &event).await?;
        Ok(true)
    }

    /// The request's state as of `tx`.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn request_state(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        id: i64,
    ) -> Result<RequestState, StoreError> {
        let state: String = sqlx::query_scalar("SELECT state FROM deploy_requests WHERE id = ?")
            .bind(id)
            .fetch_one(&mut **tx)
            .await?;
        RequestState::parse(&state)
    }

    /// Moves `request` from waiting to approved and queues its deploy under a new number,
    /// carrying `approval`, with the audit rows of both. `None` if it wasn't waiting any
    /// more, and nothing has changed. After committing, call
    /// [`wake_agents`](Self::wake_agents).
    ///
    /// That of any number of approvals at once one gets through comes from
    /// [`begin`](Self::begin)'s `BEGIN IMMEDIATE`: the write lock is taken before the caller
    /// looks at the state, so the look and this update can't interleave with another
    /// writer's, and this update never finds the row changed since. The conditional update
    /// is a second layer under that, in case the look moves or a caller skips it, and the
    /// unique index on `deploys.request_id` a third.
    ///
    /// # Errors
    /// A clock, serialisation, database or audit failure, including the deployment having
    /// an active deploy.
    pub async fn approve_request(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        request: &StoredRequest,
        approver: &PrincipalId,
        approval: &Approval,
    ) -> Result<Option<DeployId>, StoreError> {
        let now = self.clock.now()?;
        let moved = sqlx::query(
            "UPDATE deploy_requests SET state = 'approved', approved_by = ?, closed_at = ?
             WHERE id = ? AND state = 'awaiting_approval'",
        )
        .bind(approver.as_ref())
        .bind(now)
        .bind(request.id)
        .execute(&mut **tx)
        .await?;
        if moved.rows_affected() != 1 {
            return Ok(None);
        }
        let intent = &request.intent;
        let deploy = NewDeploy {
            deployment: intent.deployment.clone(),
            host: request.host.clone(),
            tag: intent.tag.clone(),
            digest: intent.digest.clone(),
            commit: intent.commit.clone(),
        };
        let deploy_id = self
            .insert_deploy(tx, &deploy, Some((request.id, approval)))
            .await?;
        let event = AuditEvent {
            kind: EventKind::RequestApproved,
            deployment: Some(intent.deployment.clone()),
            host: Some(request.host.clone()),
            detail: json!({
                "request": request.id,
                "deploy_id": deploy_id,
                "approver": approver,
                "tag": intent.tag,
                "digest": intent.digest,
                "nonce": hex::encode(intent.nonce),
            }),
        };
        self.append(tx, &event).await?;
        Ok(Some(deploy_id))
    }
}

const EXPIRED_REASON: &str = "no approver signed it in time";

impl StoredRelease {
    /// The commit and digest of a release that verified and hasn't been refused since.
    #[must_use]
    pub fn settled(&self) -> Option<(&CommitSha, &ImageDigest)> {
        match (&self.commit, &self.digest, self.origin_refused) {
            (Some(commit), Some(digest), false) => Some((commit, digest)),
            _ => None,
        }
    }
}
