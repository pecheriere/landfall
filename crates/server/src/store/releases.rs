//! What the release watcher decided about each release, why anything is still
//! undecided, and what it reads to decide.
//!
//! A reason is kept quoted and up to
//! [`MAX_STORED_TEXT_CHARS`], and shown in the audit row in the short form,
//! [`shown`]: it may hold text from GitHub or a registry. Both are done here, so
//! that nothing the watcher writes can skip them.

use std::collections::HashMap;

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag};
use landfall_core::protocol::DeployId;
use landfall_core::text::{quoted, shown};
use serde_json::{Value, json};
use sqlx::Row as _;

use super::deploys::{NewDeploy, parsed};
use super::{Store, StoreError};
use crate::agent_api::log;
use crate::audit::{AuditEvent, EventKind};
use crate::report::MAX_STORED_TEXT_CHARS;

/// How recently a host must have reported for its deployment to count as healthy,
/// seconds. Long against its polling, so that a restart or a brief outage does not
/// hold a promotion back.
pub const REPORT_FRESH_SECS: i64 = 15 * 60;

/// The `tag` of a hold on a whole deployment; no release tag is empty.
const WHOLE_DEPLOYMENT: &str = "";

/// What was decided about a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReleaseDecision {
    /// A deploy without a human, if the host can take one.
    Auto,
    /// A deploy once an approver agrees.
    NeedsApproval,
    /// A deploy only on an operator's request.
    Manual,
    /// No deploy.
    Refused,
    /// Its host said not now: asked again after a wait.
    Deferred,
}

impl ReleaseDecision {
    fn as_str(self) -> &'static str {
        match self {
            Self::Auto => "auto",
            Self::NeedsApproval => "needs_approval",
            Self::Manual => "manual",
            Self::Refused => "refused",
            Self::Deferred => "deferred",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "auto" => Ok(Self::Auto),
            "needs_approval" => Ok(Self::NeedsApproval),
            "manual" => Ok(Self::Manual),
            "refused" => Ok(Self::Refused),
            "deferred" => Ok(Self::Deferred),
            _ => Err(StoreError::Corrupt("decision")),
        }
    }
}

/// A reason as the tables keep it.
fn stored_reason(reason: &str) -> String {
    quoted(reason, MAX_STORED_TEXT_CHARS)
}

/// A `releases` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredRelease {
    /// The release commit, if it got as far as having one.
    pub commit: Option<CommitSha>,
    /// The release's digest, if it was settled.
    pub digest: Option<ImageDigest>,
    /// What was decided.
    pub decision: ReleaseDecision,
    /// Whether verification refused it, for as long as its inputs stay the same.
    pub origin_refused: bool,
    reason: String,
    tag_object: Option<String>,
    config_hash: Option<String>,
}

impl StoredRelease {
    /// Whether this is what is already recorded.
    #[must_use]
    pub fn says(&self, decision: ReleaseDecision, reason: &str) -> bool {
        self.decision == decision && self.reason == stored_reason(reason)
    }

    /// Whether it was decided from this tag object and this configuration.
    #[must_use]
    pub fn has_inputs(&self, tag_object: &str, config_hash: &str) -> bool {
        self.tag_object.as_deref() == Some(tag_object)
            && self.config_hash.as_deref() == Some(config_hash)
    }
}

/// What a release was found to be, the first time, or when its inputs changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Seen<'a> {
    /// The object the tag's ref named.
    pub tag_object: &'a str,
    /// The configuration's hash.
    pub config_hash: &'a str,
    /// The release commit, if it got as far as having one.
    pub commit: Option<&'a CommitSha>,
    /// The release's digest, if it was settled. `None` leaves one already recorded
    /// as it is.
    pub digest: Option<&'a ImageDigest>,
    /// Whether verification refused it, for as long as these inputs stay.
    pub refused: bool,
    /// Where it came from, with hostile text in its short form: the
    /// `release_seen` row's detail.
    pub detail: Value,
    /// The same with the long form of that text: the `origin` column.
    pub origin: Value,
}

/// Something still undecided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hold {
    reason: String,
    /// When this reason began to stand.
    pub since: i64,
    /// When it was last tried.
    pub last_try: i64,
    /// Whether it is retried on the slow schedule from the start.
    pub slow: bool,
}

impl Hold {
    /// Whether this is what is already recorded.
    #[must_use]
    pub fn says(&self, reason: &str) -> bool {
        self.reason == stored_reason(reason)
    }
}

/// What a host last said about a deployment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchedRunning {
    /// The release deployed; `None` if none ever was.
    pub tag: Option<ReleaseTag>,
    /// Its digest.
    pub digest: Option<ImageDigest>,
    /// Whether the running container differs from what was deployed.
    pub drift: bool,
    /// The phase's stable name.
    pub phase: String,
    /// Whether the agent is running a deploy right now.
    pub busy: bool,
}

/// One release's finished deploys with one outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FinishedDeploy {
    /// The tag.
    pub tag: String,
    /// The digest.
    pub digest: String,
    /// The outcome's stable name.
    pub outcome: String,
    /// How many.
    pub count: i64,
    /// When the last of them finished.
    pub last_finished_at: i64,
}

/// What the store knows that bears on queueing a deployment's next release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WatchView {
    /// What its host last said about it, if its host, as the configuration has it
    /// now, has said anything.
    pub running: Option<WatchedRunning>,
    /// Whether its host's configuration differs from the controller's.
    pub config_drifted: bool,
    /// Whether it has a queued or claimed deploy.
    pub active_deploy: bool,
    /// Its finished deploys.
    pub finished: Vec<FinishedDeploy>,
}

impl Store {
    /// The recorded releases of `deployment`, by tag.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn releases_of(
        &self,
        deployment: &DeploymentId,
    ) -> Result<HashMap<String, StoredRelease>, StoreError> {
        let rows = sqlx::query(
            "SELECT tag, commit_sha, digest, decision, reason, tag_object, config_hash,
                    origin_refused
             FROM releases WHERE deployment = ?",
        )
        .bind(deployment.as_ref())
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let optional = |column: &'static str| row.try_get::<Option<String>, _>(column);
                let release = StoredRelease {
                    commit: optional("commit_sha")?
                        .map(|_| parsed(row, "commit_sha"))
                        .transpose()?,
                    digest: optional("digest")?
                        .map(|_| parsed(row, "digest"))
                        .transpose()?,
                    decision: ReleaseDecision::parse(&row.try_get::<String, _>("decision")?)?,
                    origin_refused: row.try_get("origin_refused")?,
                    reason: row.try_get("reason")?,
                    tag_object: optional("tag_object")?,
                    config_hash: optional("config_hash")?,
                };
                Ok((row.try_get("tag")?, release))
            })
            .collect()
    }

    /// Records what was decided about a release, with its audit rows, and ends any
    /// hold on it. A `seen` is a new look at it, and replaces what is known of its
    /// inputs and origin; without one only the decision changes. An unchanged
    /// decision adds no audit row.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn record_release(
        &self,
        (deployment, host, tag): (&DeploymentId, &HostId, &ReleaseTag),
        decision: ReleaseDecision,
        reason: &str,
        seen: Option<&Seen<'_>>,
    ) -> Result<(), StoreError> {
        let stored = stored_reason(reason);
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        let before =
            sqlx::query("SELECT decision, reason FROM releases WHERE deployment = ? AND tag = ?")
                .bind(deployment.as_ref())
                .bind(tag.as_ref())
                .fetch_optional(&mut *tx)
                .await?;
        let before: Option<(String, String)> = before
            .map(|row| Ok::<_, sqlx::Error>((row.try_get("decision")?, row.try_get("reason")?)))
            .transpose()?;
        let (commit, digest, object, config_hash, origin) = match seen {
            Some(seen) => (
                seen.commit.map(AsRef::<str>::as_ref),
                seen.digest.map(AsRef::<str>::as_ref),
                Some(seen.tag_object),
                Some(seen.config_hash),
                Some(seen.origin.to_string()),
            ),
            None => (None, None, None, None, None),
        };
        // Without a `seen`, whatever is known of its origin stays as it is. A commit
        // or digest already recorded is never overwritten by none.
        sqlx::query(
            "INSERT INTO releases
                 (deployment, tag, commit_sha, digest, decision, reason, seen_at,
                  tag_object, config_hash, origin, origin_refused)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?12)
             ON CONFLICT (deployment, tag) DO UPDATE SET
                 decision = excluded.decision,
                 reason = excluded.reason,
                 commit_sha = COALESCE(excluded.commit_sha, commit_sha),
                 digest = COALESCE(excluded.digest, digest),
                 tag_object = CASE WHEN ?11 THEN excluded.tag_object ELSE tag_object END,
                 config_hash = CASE WHEN ?11 THEN excluded.config_hash ELSE config_hash END,
                 origin = CASE WHEN ?11 THEN excluded.origin ELSE origin END,
                 origin_refused = CASE WHEN ?11 THEN excluded.origin_refused
                                       ELSE origin_refused END,
                 seen_at = CASE WHEN ?11 THEN excluded.seen_at ELSE seen_at END",
        )
        .bind(deployment.as_ref())
        .bind(tag.as_ref())
        .bind(commit)
        .bind(digest)
        .bind(decision.as_str())
        .bind(&stored)
        .bind(now)
        .bind(object)
        .bind(config_hash)
        .bind(origin)
        .bind(seen.is_some())
        .bind(seen.is_some_and(|seen| seen.refused))
        .execute(&mut *tx)
        .await?;
        sqlx::query("DELETE FROM release_holds WHERE deployment = ? AND tag = ?")
            .bind(deployment.as_ref())
            .bind(tag.as_ref())
            .execute(&mut *tx)
            .await?;

        let event = |kind, detail| AuditEvent {
            kind,
            deployment: Some(deployment.clone()),
            host: Some(host.clone()),
            detail,
        };
        if let Some(seen) = seen {
            self.append(&mut tx, &event(EventKind::ReleaseSeen, seen.detail.clone()))
                .await?;
        }
        let unchanged = before
            .as_ref()
            .is_some_and(|(d, r)| d == decision.as_str() && *r == stored);
        if !unchanged {
            let detail = json!({
                "tag": tag,
                "decision": decision.as_str(),
                "reason": shown(reason),
                "digest": seen.and_then(|s| s.digest),
                "previous": before.as_ref().map(|(d, _)| d),
            });
            self.append(&mut tx, &event(EventKind::RuleDecision, detail))
                .await?;
        }
        tx.commit().await?;
        if !unchanged {
            log(&format!(
                "decision: {deployment} {tag}: {}: {}",
                decision.as_str(),
                shown(reason)
            ));
        }
        Ok(())
    }

    /// The holds on `deployment`: by tag, and the one on the whole deployment
    /// separately.
    ///
    /// # Errors
    /// A database failure.
    pub async fn holds_of(
        &self,
        deployment: &DeploymentId,
    ) -> Result<(HashMap<String, Hold>, Option<Hold>), StoreError> {
        let rows = sqlx::query(
            "SELECT tag, reason, since, last_try, slow FROM release_holds WHERE deployment = ?",
        )
        .bind(deployment.as_ref())
        .fetch_all(&self.pool)
        .await?;
        let mut holds = HashMap::with_capacity(rows.len());
        let mut whole = None;
        for row in &rows {
            let tag: String = row.try_get("tag")?;
            let hold = Hold {
                reason: row.try_get("reason")?,
                since: row.try_get("since")?,
                last_try: row.try_get("last_try")?,
                slow: row.try_get("slow")?,
            };
            if tag == WHOLE_DEPLOYMENT {
                whole = Some(hold);
            } else {
                holds.insert(tag, hold);
            }
        }
        Ok((holds, whole))
    }

    /// Records why `tag`, or with `None` the whole deployment, cannot be decided
    /// yet, and whether it is `slow` to retry. A reason already standing only notes
    /// the try and adds no audit row.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn set_hold(
        &self,
        (deployment, host): (&DeploymentId, &HostId),
        tag: Option<&ReleaseTag>,
        reason: &str,
        slow: bool,
    ) -> Result<(), StoreError> {
        let stored = stored_reason(reason);
        let key = tag.map_or(WHOLE_DEPLOYMENT, AsRef::as_ref);
        let now = self.clock.now()?;
        let mut tx = self.begin().await?;
        let before: Option<String> =
            sqlx::query_scalar("SELECT reason FROM release_holds WHERE deployment = ? AND tag = ?")
                .bind(deployment.as_ref())
                .bind(key)
                .fetch_optional(&mut *tx)
                .await?;
        let unchanged = before.as_deref() == Some(stored.as_str());
        if unchanged {
            sqlx::query("UPDATE release_holds SET last_try = ? WHERE deployment = ? AND tag = ?")
                .bind(now)
                .bind(deployment.as_ref())
                .bind(key)
                .execute(&mut *tx)
                .await?;
        } else {
            sqlx::query(
                "INSERT INTO release_holds (deployment, tag, reason, since, last_try, slow)
                 VALUES (?, ?, ?, ?, ?, ?)
                 ON CONFLICT (deployment, tag) DO UPDATE SET
                     reason = excluded.reason, since = excluded.since,
                     last_try = excluded.last_try, slow = excluded.slow",
            )
            .bind(deployment.as_ref())
            .bind(key)
            .bind(&stored)
            .bind(now)
            .bind(now)
            .bind(slow)
            .execute(&mut *tx)
            .await?;
            let event = AuditEvent {
                kind: EventKind::ReleaseHeld,
                deployment: Some(deployment.clone()),
                host: Some(host.clone()),
                detail: json!({ "tag": tag, "reason": shown(reason) }),
            };
            self.append(&mut tx, &event).await?;
        }
        tx.commit().await?;
        if !unchanged {
            let what = tag.map_or("everything", AsRef::as_ref);
            log(&format!("hold: {deployment} {what}: {}", shown(reason)));
        }
        Ok(())
    }

    /// Ends the hold on `tag`, or with `None` on the whole deployment. A reason
    /// going away is not itself an event: what comes next is.
    ///
    /// # Errors
    /// A database failure.
    pub async fn clear_hold(
        &self,
        deployment: &DeploymentId,
        tag: Option<&ReleaseTag>,
    ) -> Result<(), StoreError> {
        sqlx::query("DELETE FROM release_holds WHERE deployment = ? AND tag = ?")
            .bind(deployment.as_ref())
            .bind(tag.map_or(WHOLE_DEPLOYMENT, AsRef::as_ref))
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// What bears on queueing `deployment`'s next release on `host`.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn watch_view(
        &self,
        deployment: &DeploymentId,
        host: &HostId,
    ) -> Result<WatchView, StoreError> {
        let mut connection = self.pool.acquire().await?;
        let running = running_of(&mut connection, deployment, host).await?;
        let config_drifted: Option<bool> =
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
        let rows = sqlx::query(
            "SELECT tag, digest, outcome, count(*) AS count,
                    COALESCE(max(finished_at), 0) AS last_finished_at
             FROM deploys
             WHERE deployment = ? AND state = 'finished'
             GROUP BY tag, digest, outcome",
        )
        .bind(deployment.as_ref())
        .fetch_all(&mut *connection)
        .await?;
        let finished = rows
            .iter()
            .map(|row| {
                Ok(FinishedDeploy {
                    tag: row.try_get("tag")?,
                    digest: row.try_get("digest")?,
                    outcome: row.try_get("outcome")?,
                    count: row.try_get("count")?,
                    last_finished_at: row.try_get("last_finished_at")?,
                })
            })
            .collect::<Result<_, sqlx::Error>>()?;
        Ok(WatchView {
            running,
            config_drifted: config_drifted.unwrap_or(false),
            active_deploy: active.is_some(),
            finished,
        })
    }

    /// Queues `deploy` if the deployment still is as `seen`, with no active deploy
    /// and its host's configuration matching: all of it looked at in the
    /// transaction that queues, since a host may have moved on since the watcher
    /// last looked. Wakes the agents if it queued.
    ///
    /// # Errors
    /// A clock, database or audit failure.
    pub async fn queue_if_unchanged(
        &self,
        deploy: &NewDeploy,
        seen: &WatchedRunning,
    ) -> Result<Option<DeployId>, StoreError> {
        let mut tx = self.begin().await?;
        let running = running_of(&mut tx, &deploy.deployment, &deploy.host).await?;
        let active: Option<i64> = sqlx::query_scalar(
            "SELECT 1 FROM deploys WHERE deployment = ? AND state IN ('queued', 'claimed')",
        )
        .bind(deploy.deployment.as_ref())
        .fetch_optional(&mut *tx)
        .await?;
        let drifted: Option<bool> =
            sqlx::query_scalar("SELECT drifted_config_hash IS NOT NULL FROM hosts WHERE id = ?")
                .bind(deploy.host.as_ref())
                .fetch_optional(&mut *tx)
                .await?;
        if running.as_ref() != Some(seen) || active.is_some() || drifted == Some(true) {
            return Ok(None);
        }
        let id = self.queue_deploy(&mut tx, deploy).await?;
        tx.commit().await?;
        self.wake_agents();
        Ok(Some(id))
    }

    /// Whether release (`tag`, `digest`) has been healthy on `source` for at
    /// least `seconds`, by this controller's clock from what `host`, whose it is,
    /// reported: since it was first reported running, if it still is and its host
    /// has reported within [`REPORT_FRESH_SECS`]; or, if a later release has
    /// replaced it, for as long as it was observed healthy up to its last report
    /// before that. A host's word is all this is: silence holds it back, does not
    /// start the time again, and does not count.
    ///
    /// # Errors
    /// A clock or database failure.
    pub async fn healthy_for(
        &self,
        (source, host): (&DeploymentId, &HostId),
        tag: &ReleaseTag,
        digest: &ImageDigest,
        seconds: u64,
    ) -> Result<bool, StoreError> {
        let wanted = i64::try_from(seconds).unwrap_or(i64::MAX);
        let row = sqlx::query(
            "SELECT tag, digest, drift, phase, healthy_since, last_report FROM running_states
             WHERE deployment = ? AND host = ?",
        )
        .bind(source.as_ref())
        .bind(host.as_ref())
        .fetch_optional(&self.pool)
        .await?;
        if let Some(row) = row {
            let current = row.try_get::<Option<String>, _>("tag")?.as_deref() == Some(tag.as_ref())
                && row.try_get::<Option<String>, _>("digest")?.as_deref() == Some(digest.as_ref());
            if current {
                let idle = row.try_get::<String, _>("phase")? == "idle";
                let drift: bool = row.try_get("drift")?;
                let since: Option<i64> = row.try_get("healthy_since")?;
                let last_report: Option<i64> = row.try_get("last_report")?;
                let now = self.clock.now()?;
                return Ok(idle
                    && !drift
                    && last_report.is_some_and(|at| now.saturating_sub(at) <= REPORT_FRESH_SECS)
                    && since.is_some_and(|since| now.saturating_sub(since) >= wanted));
            }
        }
        let observed: Option<i64> = sqlx::query_scalar(
            "SELECT healthy_secs FROM replaced_releases
             WHERE deployment = ? AND host = ? AND tag = ? AND digest = ?",
        )
        .bind(source.as_ref())
        .bind(host.as_ref())
        .bind(tag.as_ref())
        .bind(digest.as_ref())
        .fetch_optional(&self.pool)
        .await?;
        Ok(observed.is_some_and(|secs| secs >= wanted))
    }
}

/// What `host` last said about `deployment`, if it is that host's now.
async fn running_of(
    connection: &mut sqlx::SqliteConnection,
    deployment: &DeploymentId,
    host: &HostId,
) -> Result<Option<WatchedRunning>, StoreError> {
    let row = sqlx::query(
        "SELECT tag, digest, drift, phase, busy FROM running_states
         WHERE deployment = ? AND host = ?",
    )
    .bind(deployment.as_ref())
    .bind(host.as_ref())
    .fetch_optional(connection)
    .await?;
    let Some(row) = row else { return Ok(None) };
    let tag = row
        .try_get::<Option<String>, _>("tag")?
        .map(|_| parsed(&row, "tag"))
        .transpose()?;
    let digest = row
        .try_get::<Option<String>, _>("digest")?
        .map(|_| parsed(&row, "digest"))
        .transpose()?;
    Ok(Some(WatchedRunning {
        tag,
        digest,
        drift: row.try_get("drift")?,
        phase: row.try_get("phase")?,
        busy: row.try_get("busy")?,
    }))
}
