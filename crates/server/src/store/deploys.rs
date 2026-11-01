//! Deploys: queued by the controller, claimed by a host, finished by its report;
//! and what each host says is running.

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{DeployId, DeployWork, HeldBack, Phase, RunningState};
use serde_json::json;
use sqlx::sqlite::SqliteRow;
use sqlx::{Row as _, Sqlite, SqliteConnection, Transaction};
use tokio::sync::watch;

use super::{Store, StoreError};
use crate::audit::{AuditEvent, EventKind};
use crate::report::BoundedReport;

/// A deployment whose running state has drifted gets no new deploy until it
/// clears: the reason a host is given.
const DRIFT_REASON: &str = "the running state differs from what the agent deployed";

/// A deploy to queue.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDeploy {
    /// The deployment. Its release must already be recorded.
    pub deployment: DeploymentId,
    /// The host the configuration gives it to.
    pub host: HostId,
    /// The release tag.
    pub tag: ReleaseTag,
    /// The image digest to run.
    pub digest: ImageDigest,
    /// The commit the tag points at.
    pub commit: CommitSha,
}

/// What a host should do next.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct WorkPick {
    /// The deploy to run: one it claimed and has not reported comes first, so
    /// that a crashed agent is given it again under the same id.
    pub work: Option<DeployWork>,
    /// Deployments with a deploy waiting that is not being handed out.
    pub held_back: Vec<HeldBack>,
}

/// Whether a report changed anything.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReportAck {
    /// The deploy is now finished, with this report.
    Recorded,
    /// The deploy had already finished: the first report stands.
    AlreadyRecorded,
}

/// A wire deploy id as `SQLite` stores it, or [`StoreError::UnknownDeploy`] if no
/// row can have it.
fn stored_deploy_id(id: DeployId) -> Result<i64, StoreError> {
    i64::try_from(id.0).map_err(|_| StoreError::UnknownDeploy)
}

/// A stored deploy id as the wire carries it.
fn wire_deploy_id(id: i64) -> Result<DeployId, StoreError> {
    u64::try_from(id)
        .map(DeployId)
        .map_err(|_| StoreError::Corrupt("deploy id"))
}

/// A stored text column parsed into its validated type.
fn parsed<T: std::str::FromStr>(row: &SqliteRow, column: &'static str) -> Result<T, StoreError> {
    row.try_get::<String, _>(column)?
        .parse()
        .map_err(|_| StoreError::Corrupt(column))
}

fn deploy_work(row: &SqliteRow) -> Result<DeployWork, StoreError> {
    Ok(DeployWork {
        deploy_id: wire_deploy_id(row.try_get("id")?)?,
        deployment: parsed(row, "deployment")?,
        tag: parsed(row, "tag")?,
        digest: parsed(row, "digest")?,
        commit: parsed(row, "commit_sha")?,
    })
}

/// The stable name of a phase. `Phase` may grow: an unknown one is stored as
/// that rather than refused, since it describes the host and decides nothing.
fn phase_name(phase: Phase) -> &'static str {
    match phase {
        Phase::Idle => "idle",
        Phase::Preflight => "preflight",
        Phase::Deploying => "deploying",
        Phase::RollingBack => "rolling_back",
        Phase::Restored => "restored",
        Phase::RolledBack => "rolled_back",
        _ => "unknown",
    }
}

impl Store {
    /// Queues a deploy in `tx`, with its audit row. After committing, call
    /// [`wake_agents`](Self::wake_agents) so that a waiting host sees it.
    ///
    /// # Errors
    /// A database failure, including the deployment already having an active
    /// deploy or its release not being recorded; or a clock failure.
    pub async fn queue_deploy(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        deploy: &NewDeploy,
    ) -> Result<DeployId, StoreError> {
        let id: i64 = sqlx::query_scalar(
            "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, created_at)
             VALUES (?, ?, ?, ?, ?, 'queued', ?)
             RETURNING id",
        )
        .bind(deploy.deployment.as_ref())
        .bind(deploy.host.as_ref())
        .bind(deploy.tag.as_ref())
        .bind(deploy.digest.as_ref())
        .bind(deploy.commit.as_ref())
        .bind(self.clock.now()?)
        .fetch_one(&mut **tx)
        .await?;
        let event = AuditEvent {
            kind: EventKind::DeployQueued,
            deployment: Some(deploy.deployment.clone()),
            host: Some(deploy.host.clone()),
            detail: json!({
                "deploy_id": id,
                "tag": deploy.tag,
                "digest": deploy.digest,
                "commit": deploy.commit,
            }),
        };
        self.append(tx, &event).await?;
        wire_deploy_id(id)
    }

    /// Wakes every long poll to look for work again.
    pub fn wake_agents(&self) {
        self.work_queued.send_modify(|n| *n = n.wrapping_add(1));
    }

    /// A receiver that sees every [`wake_agents`](Self::wake_agents) from now
    /// on. Subscribe before looking for work, so that nothing queued in between
    /// is missed.
    #[must_use]
    pub fn subscribe_to_work(&self) -> watch::Receiver<u64> {
        self.work_queued.subscribe()
    }

    /// Picks what `host` should do next, claiming a queued deploy if that is
    /// what it is. Only `host`'s own deploys are looked at.
    ///
    /// # Errors
    /// A clock or database failure, or [`StoreError::Corrupt`] for an unreadable
    /// row.
    pub async fn next_work(&self, host: &HostId) -> Result<WorkPick, StoreError> {
        let mut tx = self.begin().await?;
        // One deploy at a time per host: a claimed one sorts first, and until
        // it is reported nothing else is handed out.
        let rows = sqlx::query(
            "SELECT d.id, d.deployment, d.tag, d.digest, d.commit_sha,
                    d.state = 'claimed' AS claimed, COALESCE(r.drift, 0) AS drift
             FROM deploys d
             LEFT JOIN running_states r ON r.deployment = d.deployment AND r.host = d.host
             WHERE d.host = ? AND d.state IN ('queued', 'claimed')
             ORDER BY claimed DESC, d.id",
        )
        .bind(host.as_ref())
        .fetch_all(&mut *tx)
        .await?;

        let mut pick = WorkPick::default();
        let mut claim = None;
        for row in &rows {
            let claimed: bool = row.try_get("claimed")?;
            let drifted: bool = row.try_get("drift")?;
            if !claimed && drifted {
                pick.held_back.push(HeldBack {
                    deployment: parsed(row, "deployment")?,
                    reason: DRIFT_REASON.to_owned(),
                });
            } else if pick.work.is_none() {
                let work = deploy_work(row)?;
                if !claimed {
                    claim = Some(work.clone());
                }
                pick.work = Some(work);
            }
        }
        if let Some(work) = claim {
            self.claim(&mut tx, host, &work).await?;
        }
        tx.commit().await?;
        Ok(pick)
    }

    async fn claim(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        host: &HostId,
        work: &DeployWork,
    ) -> Result<(), StoreError> {
        sqlx::query("UPDATE deploys SET state = 'claimed', claimed_at = ? WHERE id = ?")
            .bind(self.clock.now()?)
            .bind(stored_deploy_id(work.deploy_id)?)
            .execute(&mut **tx)
            .await?;
        let event = AuditEvent {
            kind: EventKind::DeployClaimed,
            deployment: Some(work.deployment.clone()),
            host: Some(host.clone()),
            detail: json!({ "deploy_id": work.deploy_id, "tag": work.tag }),
        };
        self.append(tx, &event).await
    }

    /// Records `report` for `host`, finishing the deploy. Idempotent by deploy
    /// id: a repeat changes nothing and records nothing, whatever it says.
    ///
    /// # Errors
    /// [`StoreError::UnknownDeploy`] if `host` has no such deploy;
    /// [`StoreError::NotClaimed`] if it was never handed out; otherwise a
    /// clock, database or audit failure.
    pub async fn finish_deploy(
        &self,
        host: &HostId,
        report: &BoundedReport,
    ) -> Result<ReportAck, StoreError> {
        let id = stored_deploy_id(report.deploy_id)?;
        let mut tx = self.begin().await?;
        let row =
            sqlx::query("SELECT deployment, tag, state FROM deploys WHERE id = ? AND host = ?")
                .bind(id)
                .bind(host.as_ref())
                .fetch_optional(&mut *tx)
                .await?
                .ok_or(StoreError::UnknownDeploy)?;
        match row.try_get::<String, _>("state")?.as_str() {
            "claimed" => {}
            "queued" => return Err(StoreError::NotClaimed),
            _ => return Ok(ReportAck::AlreadyRecorded),
        }
        sqlx::query(
            "UPDATE deploys
             SET state = 'finished', outcome = ?, reason = ?, rollback_reason = ?, finished_at = ?
             WHERE id = ?",
        )
        .bind(report.outcome)
        .bind(report.reason.as_deref())
        .bind(report.rollback_reason.as_deref())
        .bind(self.clock.now()?)
        .bind(id)
        .execute(&mut *tx)
        .await?;
        for (position, step) in (0_i64..).zip(&report.steps) {
            sqlx::query(
                "INSERT INTO deploy_steps (deploy_id, position, name, millis, failure, detail)
                 VALUES (?, ?, ?, ?, ?, ?)",
            )
            .bind(id)
            .bind(position)
            .bind(&step.name)
            .bind(step.millis)
            .bind(step.failure.as_deref())
            .bind(step.detail.as_deref())
            .execute(&mut *tx)
            .await?;
        }
        let tag: String = row.try_get("tag")?;
        let event = AuditEvent {
            kind: if report.refused {
                EventKind::DeployRefused
            } else {
                EventKind::DeployFinished
            },
            deployment: Some(parsed(&row, "deployment")?),
            host: Some(host.clone()),
            detail: report.audit_detail(&tag),
        };
        self.append(&mut tx, &event).await?;
        tx.commit().await?;
        Ok(ReportAck::Recorded)
    }

    /// Records what a `work` request says about the host: whether its
    /// configuration hash differs (`drifted_hash`) and the state of its
    /// deployments. `running` must hold only deployments the configuration
    /// gives this host, once each. Writes and audits only what changed, so a
    /// host polling in the same state costs no write. `phase` and `busy` are
    /// kept but not audited: they move throughout a deploy, whose own events
    /// are in the log.
    ///
    /// # Errors
    /// A clock or database failure.
    pub async fn record_host_state(
        &self,
        host: &HostId,
        drifted_hash: Option<&[u8; 32]>,
        running: &[&RunningState],
    ) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        self.record_config_drift(&mut tx, host, drifted_hash)
            .await?;
        for state in running {
            self.record_running(&mut tx, host, state).await?;
        }
        tx.commit().await?;
        Ok(())
    }

    async fn record_config_drift(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        host: &HostId,
        drifted_hash: Option<&[u8; 32]>,
    ) -> Result<(), StoreError> {
        let wanted = drifted_hash.map(<[u8; 32]>::as_slice);
        let stored: Option<Option<Vec<u8>>> =
            sqlx::query_scalar("SELECT drifted_config_hash FROM hosts WHERE id = ?")
                .bind(host.as_ref())
                .fetch_optional(&mut **tx)
                .await?;
        if stored.flatten().as_deref() == wanted {
            return Ok(());
        }
        sqlx::query("UPDATE hosts SET drifted_config_hash = ? WHERE id = ?")
            .bind(wanted)
            .bind(host.as_ref())
            .execute(&mut **tx)
            .await?;
        let event = AuditEvent {
            kind: EventKind::ConfigDrift,
            deployment: None,
            host: Some(host.clone()),
            detail: json!({
                "drifted": wanted.is_some(),
                "reported_hash": wanted.map(hex::encode),
            }),
        };
        self.append(tx, &event).await
    }

    async fn record_running(
        &self,
        tx: &mut Transaction<'_, Sqlite>,
        host: &HostId,
        state: &RunningState,
    ) -> Result<(), StoreError> {
        let tag = state.deployed.as_ref().map(|d| d.tag.as_ref());
        let digest = state.deployed.as_ref().map(|d| d.digest.as_ref());
        let phase = phase_name(state.phase);
        let stored = stored_running(tx, state).await?;
        let (old_tag, old_digest, old_drift) = stored.as_ref().map_or((None, None, false), |s| {
            (s.tag.as_deref(), s.digest.as_deref(), s.drift)
        });
        let same = stored.as_ref().is_some_and(|s| {
            s.tag.as_deref() == tag
                && s.digest.as_deref() == digest
                && s.drift == state.drift
                && s.phase == phase
                && s.busy == state.busy
                && s.host == host.as_ref()
        });
        if same {
            return Ok(());
        }
        let release_changed = old_tag != tag || old_digest != digest;
        let drift_changed = old_drift != state.drift;
        let event = |kind, detail| AuditEvent {
            kind,
            deployment: Some(state.deployment.clone()),
            host: Some(host.clone()),
            detail,
        };
        if release_changed {
            let detail = json!({ "tag": tag, "digest": digest, "previous_tag": old_tag });
            self.append(tx, &event(EventKind::RunningChanged, detail))
                .await?;
        }
        if drift_changed {
            let detail = json!({ "drift": state.drift });
            self.append(tx, &event(EventKind::RunningDrift, detail))
                .await?;
        }
        sqlx::query(
            "INSERT INTO running_states
                 (deployment, host, tag, digest, drift, phase, busy, updated_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)
             ON CONFLICT (deployment) DO UPDATE SET
                 host = excluded.host, tag = excluded.tag, digest = excluded.digest,
                 drift = excluded.drift, phase = excluded.phase, busy = excluded.busy,
                 updated_at = excluded.updated_at",
        )
        .bind(state.deployment.as_ref())
        .bind(host.as_ref())
        .bind(tag)
        .bind(digest)
        .bind(state.drift)
        .bind(phase)
        .bind(state.busy)
        .bind(self.clock.now()?)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }
}

/// A `running_states` row.
struct StoredRunning {
    host: String,
    tag: Option<String>,
    digest: Option<String>,
    drift: bool,
    phase: String,
    busy: bool,
}

async fn stored_running(
    connection: &mut SqliteConnection,
    state: &RunningState,
) -> Result<Option<StoredRunning>, StoreError> {
    let row = sqlx::query(
        "SELECT host, tag, digest, drift, phase, busy FROM running_states WHERE deployment = ?",
    )
    .bind(state.deployment.as_ref())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else { return Ok(None) };
    Ok(Some(StoredRunning {
        host: row.try_get("host")?,
        tag: row.try_get("tag")?,
        digest: row.try_get("digest")?,
        drift: row.try_get("drift")?,
        phase: row.try_get("phase")?,
        busy: row.try_get("busy")?,
    }))
}
