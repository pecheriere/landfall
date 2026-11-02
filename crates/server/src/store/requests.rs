//! Deploy requests: the intent an approver signs, and the deploy that signing queues.
//!
//! `migrations/0003_approvals.sql` has the states. Each function here is one step in the
//! caller's transaction, with its audit row, so that a step and its record commit together.
//! What a step may do, and what is told to whom, is [`crate::requests`]'s.

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, DeployId};
use serde_json::{Value, json};
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, SqliteConnection, Transaction};

use super::deploys::{NewDeploy, parsed};
use super::releases::{StoredRelease, WatchedRunning, release_of, running_of};
use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};

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
}

impl RequestState {
    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "awaiting_approval" => Ok(Self::AwaitingApproval),
            "approved" => Ok(Self::Approved),
            "stale" => Ok(Self::Stale),
            "expired" => Ok(Self::Expired),
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

const COLUMNS: &str = "id, deployment, host, tag, commit_sha, digest, expected_running, nonce,
                       state, requested_by, created_at, expires_at";

fn stored_request(row: &SqliteRow) -> Result<StoredRequest, StoreError> {
    let nonce: Vec<u8> = row.try_get("nonce")?;
    let expected_running = row
        .try_get::<Option<String>, _>("expected_running")?
        .map(|_| parsed(row, "expected_running"))
        .transpose()?;
    Ok(StoredRequest {
        id: row.try_get("id")?,
        host: parsed(row, "host")?,
        intent: DeployIntent {
            deployment: parsed(row, "deployment")?,
            tag: parsed(row, "tag")?,
            commit: parsed(row, "commit_sha")?,
            digest: parsed(row, "digest")?,
            expected_running,
            nonce: nonce
                .try_into()
                .map_err(|_| StoreError::Corrupt("request nonce"))?,
        },
        state: RequestState::parse(&row.try_get::<String, _>("state")?)?,
        requested_by: parsed(row, "requested_by")?,
        created_at: row.try_get("created_at")?,
        expires_at: row.try_get("expires_at")?,
    })
}

/// The audit row of a request ending for `reason`, which is the controller's own text.
fn closing_event(kind: EventKind, request: &StoredRequest, reason: &str) -> AuditEvent {
    AuditEvent {
        kind,
        deployment: Some(request.intent.deployment.clone()),
        host: Some(request.host.clone()),
        detail: json!({
            "request": request.id,
            "tag": request.intent.tag,
            "digest": request.intent.digest,
            "expected_running": request.intent.expected_running,
            "reason": reason,
        }),
    }
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

    /// Every request waiting for an approver, not yet past its time at `now`. At most one
    /// for each deployment, so this needs no paging.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn open_requests(&self, now: i64) -> Result<Vec<StoredRequest>, StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {COLUMNS} FROM deploy_requests
             WHERE state = 'awaiting_approval' AND expires_at > ? ORDER BY id"
        )))
        .bind(now)
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(stored_request).collect()
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
                 (deployment, host, tag, commit_sha, digest, expected_running, nonce, state,
                  requested_by, created_at, expires_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, 'awaiting_approval', ?, ?, ?)
             RETURNING {COLUMNS}"
        )))
        .bind(intent.deployment.as_ref())
        .bind(request.host.as_ref())
        .bind(intent.tag.as_ref())
        .bind(intent.commit.as_ref())
        .bind(intent.digest.as_ref())
        .bind(intent.expected_running.as_ref().map(AsRef::<str>::as_ref))
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
    /// A database or audit failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn expire_requests(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        now: i64,
    ) -> Result<(), StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests
             SET state = 'expired', closed_at = ?1, closed_reason = ?2
             WHERE state = 'awaiting_approval' AND expires_at <= ?1
             RETURNING {COLUMNS}"
        )))
        .bind(now)
        .bind(EXPIRED_REASON)
        .fetch_all(&mut **tx)
        .await?;
        for row in &rows {
            let event = closing_event(
                EventKind::RequestExpired,
                &stored_request(row)?,
                EXPIRED_REASON,
            );
            self.append(tx, &event).await?;
        }
        Ok(())
    }

    /// Ends `deployment`'s open request if it was made for another running digest than
    /// `running`, with its audit row. In the transaction of the report that says so, so
    /// that nothing can approve it after that report stands.
    ///
    /// # Errors
    /// A clock, database or audit failure, or [`StoreError::Corrupt`] for an unreadable
    /// row.
    pub(super) async fn stale_other_requests(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        deployment: &DeploymentId,
        running: Option<&str>,
        reason: &str,
    ) -> Result<(), StoreError> {
        let rows = sqlx::query(sqlx::AssertSqlSafe(format!(
            "UPDATE deploy_requests
             SET state = 'stale', closed_at = ?, closed_reason = ?
             WHERE deployment = ? AND state = 'awaiting_approval' AND expected_running IS NOT ?
             RETURNING {COLUMNS}"
        )))
        .bind(self.clock.now()?)
        .bind(reason)
        .bind(deployment.as_ref())
        .bind(running)
        .fetch_all(&mut **tx)
        .await?;
        for row in &rows {
            let event = closing_event(EventKind::RequestStale, &stored_request(row)?, reason);
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
        sqlx::query(
            "UPDATE deploy_requests SET state = 'stale', closed_at = ?, closed_reason = ?
             WHERE id = ? AND state = 'awaiting_approval'",
        )
        .bind(self.clock.now()?)
        .bind(reason)
        .bind(request.id)
        .execute(&mut **tx)
        .await?;
        let event = closing_event(EventKind::RequestStale, request, reason);
        self.append(tx, &event).await
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
    /// more, and nothing has changed: the update is conditional, so of any number of
    /// approvals at once, one gets through. After committing, call
    /// [`wake_agents`](Self::wake_agents).
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
