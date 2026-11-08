//! What the API reads to tell a deployment's releases and the story of one, and its deploys
//! and the steps of each: the releases recorded, the requests and deploys of each, and a
//! deployment's deploys. Reads only, each bounded and on an index.

use std::collections::HashMap;

use landfall_api::{DeployState, Outcome, RawJson};
use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_origin::fetch::MAX_LISTED_TAGS;
use serde_json::Value;
use sqlx::Row as _;
use sqlx::sqlite::SqliteRow;

use super::deploys::parsed;
use super::releases::stored_release;
use super::{RequestState, Store, StoreError, StoredRelease};

/// The columns [`stored_release`] reads, and when the release was first and last seen.
const RELEASE_COLUMNS: &str = "tag, commit_sha, digest, decision, reason, tag_object,
                               config_hash, origin_refused, first_seen_at, seen_at";

/// A deployment's releases first recorded most recently, at most a number: on the index
/// `releases_by_first_seen`, so that the cut is made without sorting its whole history.
pub(super) const RELEASE_ROWS: &str = "SELECT tag, commit_sha, digest, decision, reason,
         tag_object, config_hash, origin_refused, first_seen_at, seen_at
     FROM releases WHERE deployment = ?
     ORDER BY first_seen_at DESC, tag LIMIT ?";

/// A deploy's columns, with the request it came from by key: the start of every read of
/// deploys, as a macro so that each statement is one constant.
macro_rules! deploys_select {
    () => {
        "SELECT d.id, d.deployment, d.host, d.tag, d.digest, d.commit_sha, d.state, d.outcome,
                d.reason, d.rollback_reason, d.request_id, r.requested_by, r.created_at AS
                requested_at, r.approved_by, d.created_at, d.claimed_at, d.finished_at
         FROM deploys d LEFT JOIN deploy_requests r ON r.id = d.request_id"
    };
}

/// One deploy, by its number.
pub(super) const DEPLOY_BY_ID: &str = concat!(deploys_select!(), " WHERE d.id = ?");

/// A deployment's deploys below a number, newest first, at most a number: on the index
/// `deploys_by_deployment`.
pub(super) const DEPLOYS_OF_DEPLOYMENT: &str = concat!(
    deploys_select!(),
    " WHERE d.deployment = ? AND d.id < ? ORDER BY d.id DESC LIMIT ?"
);

/// A release's newest deploys, at most a number: on the index `deploys_by_release`.
pub(super) const DEPLOYS_OF_RELEASE: &str = concat!(
    deploys_select!(),
    " WHERE d.deployment = ? AND d.tag = ? ORDER BY d.id DESC LIMIT ?"
);

/// The steps of each deploy in a JSON list of numbers, by the table's key.
pub(super) const STEPS_OF: &str = "SELECT s.deploy_id, s.position, s.name, s.millis, s.failure,
         s.detail
     FROM json_each(?) w CROSS JOIN deploy_steps s ON s.deploy_id = w.value";

/// A release the watcher recorded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ReleaseRow {
    /// Its tag.
    pub(crate) tag: ReleaseTag,
    /// What the watcher recorded of it.
    pub(crate) release: StoredRelease,
    /// When it was first recorded.
    pub(crate) first_seen_at: i64,
    /// When it was last verified.
    pub(crate) seen_at: i64,
}

/// A request for a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestRow {
    /// Its number.
    pub(crate) id: i64,
    /// Where it stands.
    pub(crate) state: RequestState,
    /// Who asked.
    pub(crate) requested_by: PrincipalId,
    /// Who signed it, if anyone did.
    pub(crate) approved_by: Option<PrincipalId>,
    /// When it was asked.
    pub(crate) created_at: i64,
    /// Why it was closed unsigned, in the controller's words.
    pub(crate) closed_reason: Option<String>,
}

/// A deploy, with who asked for it and who signed that request, if it came from one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeployRow {
    /// Its number.
    pub(crate) id: i64,
    /// Its deployment.
    pub(crate) deployment: DeploymentId,
    /// The host it was sent to.
    pub(crate) host: HostId,
    /// The release's tag.
    pub(crate) tag: ReleaseTag,
    /// The digest sent.
    pub(crate) digest: ImageDigest,
    /// The release commit.
    pub(crate) commit: CommitSha,
    /// Where it stands.
    pub(crate) state: DeployState,
    /// How it went, once finished and if this version knows the stored name.
    pub(crate) outcome: Option<Outcome>,
    /// What its host said of it, quoted and bounded, if anything.
    pub(crate) reason: Option<String>,
    /// What its host said of going back, quoted and bounded, if anything.
    pub(crate) rollback_reason: Option<String>,
    /// The request it came from, if any.
    pub(crate) request_id: Option<i64>,
    /// Who asked for that request.
    pub(crate) requested_by: Option<PrincipalId>,
    /// When they asked.
    pub(crate) requested_at: Option<i64>,
    /// Who signed that request.
    pub(crate) approved_by: Option<PrincipalId>,
    /// When it was queued.
    pub(crate) created_at: i64,
    /// When its host took it.
    pub(crate) claimed_at: Option<i64>,
    /// When it finished.
    pub(crate) finished_at: Option<i64>,
}

/// One step a host reported of a deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StepRow {
    /// Where it comes in the deploy, from 0.
    pub(crate) position: u32,
    /// What was done, quoted.
    pub(crate) name: String,
    /// How long it took, in milliseconds.
    pub(crate) millis: i64,
    /// Why it failed, quoted and bounded, if it did.
    pub(crate) failure: Option<String>,
    /// More about it, as [`BoundedReport`](crate::report::BoundedReport) stored it.
    pub(crate) detail: Option<RawJson>,
}

/// The last finished deploy of a release with one digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LastFinished {
    /// How it went, by the outcome's stored name.
    pub(crate) outcome: String,
    /// What its host said of it, quoted and bounded, if anything.
    pub(crate) reason: Option<String>,
}

/// A finished deploy's outcome, by its stored name: `None` for a name this version doesn't
/// know, as a newer controller's database could hold, so that one such row doesn't stop an
/// answer.
pub(crate) fn outcome(name: &str) -> Option<Outcome> {
    Some(match name {
        "deployed" => Outcome::Deployed,
        "rolled_back" => Outcome::RolledBack,
        "nothing_changed" => Outcome::NothingChanged,
        "failed_no_previous" => Outcome::FailedNoPrevious,
        "rollback_failed" => Outcome::RollbackFailed,
        "refused" => Outcome::Refused,
        "deferred" => Outcome::Deferred,
        _ => return None,
    })
}

/// A deploy's state, by its stored name.
fn deploy_state(name: &str) -> Result<DeployState, StoreError> {
    Ok(match name {
        "queued" => DeployState::Queued,
        "claimed" => DeployState::Claimed,
        "finished" => DeployState::Finished,
        _ => return Err(StoreError::Corrupt("state")),
    })
}

/// An optional column that holds an identifier.
fn parsed_or_null<T: std::str::FromStr>(
    row: &SqliteRow,
    column: &'static str,
) -> Result<Option<T>, StoreError> {
    row.try_get::<Option<String>, _>(column)?
        .map(|_| parsed(row, column))
        .transpose()
}

/// A deploy, from a row of [`deploys_select`].
fn deploy_from(row: &SqliteRow) -> Result<DeployRow, StoreError> {
    Ok(DeployRow {
        id: row.try_get("id")?,
        deployment: parsed(row, "deployment")?,
        host: parsed(row, "host")?,
        tag: parsed(row, "tag")?,
        digest: parsed(row, "digest")?,
        commit: parsed(row, "commit_sha")?,
        state: deploy_state(&row.try_get::<String, _>("state")?)?,
        // An outcome this version doesn't know is shown as none: the row is still `finished`.
        outcome: row
            .try_get::<Option<String>, _>("outcome")?
            .as_deref()
            .and_then(outcome),
        reason: row.try_get("reason")?,
        rollback_reason: row.try_get("rollback_reason")?,
        request_id: row.try_get("request_id")?,
        requested_by: parsed_or_null(row, "requested_by")?,
        requested_at: row.try_get("requested_at")?,
        approved_by: parsed_or_null(row, "approved_by")?,
        created_at: row.try_get("created_at")?,
        claimed_at: row.try_get("claimed_at")?,
        finished_at: row.try_get("finished_at")?,
    })
}

/// A step, and the deploy it is of.
fn step_from(row: &SqliteRow) -> Result<(i64, StepRow), StoreError> {
    let position = u32::try_from(row.try_get::<i64, _>("position")?)
        .map_err(|_| StoreError::Corrupt("position"))?;
    let detail = row
        .try_get::<Option<String>, _>("detail")?
        .map(|text| serde_json::from_str::<RawJson>(&text))
        .transpose()?;
    let step = StepRow {
        position,
        name: row.try_get("name")?,
        millis: row.try_get("millis")?,
        failure: row.try_get("failure")?,
        detail,
    };
    Ok((row.try_get("deploy_id")?, step))
}

/// A release, from a row with [`RELEASE_COLUMNS`].
pub(super) fn release_from(row: &SqliteRow) -> Result<ReleaseRow, StoreError> {
    Ok(ReleaseRow {
        tag: parsed(row, "tag")?,
        release: stored_release(row)?,
        first_seen_at: row.try_get("first_seen_at")?,
        seen_at: row.try_get("seen_at")?,
    })
}

impl Store {
    /// `deployment`'s recorded releases, at most [`MAX_LISTED_TAGS`], the watcher's own
    /// bound on a deployment's tags: those first recorded most recently, when there are
    /// more, as their index gives them. Not in the order a list shows, the semantic
    /// versions', which no index holds.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn release_rows(
        &self,
        deployment: &DeploymentId,
    ) -> Result<Vec<ReleaseRow>, StoreError> {
        let limit = i64::try_from(MAX_LISTED_TAGS).unwrap_or(i64::MAX);
        sqlx::query(RELEASE_ROWS)
            .bind(deployment.as_ref())
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(release_from)
            .collect()
    }

    /// One recorded release, with where it came from as the watcher recorded it: the
    /// `origin` column, `None` if it has none.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn release_row(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<Option<(ReleaseRow, Option<Value>)>, StoreError> {
        let Some(row) = sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT {RELEASE_COLUMNS}, origin FROM releases WHERE deployment = ? AND tag = ?"
        )))
        .bind(deployment.as_ref())
        .bind(tag.as_ref())
        .fetch_optional(&self.pool)
        .await?
        else {
            return Ok(None);
        };
        let origin = row
            .try_get::<Option<String>, _>("origin")?
            .map(|text| serde_json::from_str(&text))
            .transpose()?;
        Ok(Some((release_from(&row)?, origin)))
    }

    /// The newest `limit` requests for `tag` of `deployment`, newest first.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn requests_of_release(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        limit: u32,
    ) -> Result<Vec<RequestRow>, StoreError> {
        sqlx::query(
            "SELECT id, state, requested_by, approved_by, created_at, closed_reason
             FROM deploy_requests WHERE deployment = ? AND tag = ?
             ORDER BY id DESC LIMIT ?",
        )
        .bind(deployment.as_ref())
        .bind(tag.as_ref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            Ok(RequestRow {
                id: row.try_get("id")?,
                state: RequestState::parse(&row.try_get::<String, _>("state")?)?,
                requested_by: parsed(row, "requested_by")?,
                approved_by: parsed_or_null(row, "approved_by")?,
                created_at: row.try_get("created_at")?,
                closed_reason: row.try_get("closed_reason")?,
            })
        })
        .collect()
    }

    /// The newest `limit` deploys of `tag` of `deployment`, newest first.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn deploys_of_release(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        limit: u32,
    ) -> Result<Vec<DeployRow>, StoreError> {
        sqlx::query(DEPLOYS_OF_RELEASE)
            .bind(deployment.as_ref())
            .bind(tag.as_ref())
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(deploy_from)
            .collect()
    }

    /// The deploy numbered `id`, if there is one and `check` passes its deployment, which is
    /// `None` when the stored id isn't one. `check` runs before anything else of the row is
    /// read, so that a row someone may not see answers as `check` says, readable or not.
    ///
    /// # Errors
    /// `check`'s refusal, a database failure, or [`StoreError::Corrupt`] for an unreadable row
    /// that `check` passed.
    pub(crate) async fn deploy<E: From<StoreError>>(
        &self,
        id: i64,
        check: impl FnOnce(Option<&DeploymentId>) -> Result<(), E>,
    ) -> Result<Option<DeployRow>, E> {
        let Some(row) = sqlx::query(DEPLOY_BY_ID)
            .bind(id)
            .fetch_optional(&self.pool)
            .await
            .map_err(StoreError::from)?
        else {
            return Ok(None);
        };
        let deployment: Option<DeploymentId> = parsed(&row, "deployment").ok();
        check(deployment.as_ref())?;
        Ok(Some(deploy_from(&row)?))
    }

    /// `deployment`'s deploys numbered below `before`, or all of them, newest first, at most
    /// `limit`.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn deploys_of_deployment(
        &self,
        deployment: &DeploymentId,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<DeployRow>, StoreError> {
        sqlx::query(DEPLOYS_OF_DEPLOYMENT)
            .bind(deployment.as_ref())
            .bind(before.unwrap_or(i64::MAX))
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
            .iter()
            .map(deploy_from)
            .collect()
    }

    /// The steps the host of deploy `id` reported, in order.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn deploy_steps(&self, id: i64) -> Result<Vec<StepRow>, StoreError> {
        Ok(self.steps_of(&[id]).await?.remove(&id).unwrap_or_default())
    }

    /// The steps of each of `ids`, in order, in one statement: for a page of deploys. A
    /// deploy holds at most [`MAX_STORED_STEPS`](crate::report::MAX_STORED_STEPS), so a page
    /// is bounded. One with none isn't in the map.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn steps_of(
        &self,
        ids: &[i64],
    ) -> Result<HashMap<i64, Vec<StepRow>>, StoreError> {
        let mut steps: HashMap<i64, Vec<StepRow>> = HashMap::new();
        for row in sqlx::query(STEPS_OF)
            .bind(serde_json::to_string(ids)?)
            .fetch_all(&self.pool)
            .await?
        {
            let (id, step) = step_from(&row)?;
            steps.entry(id).or_default().push(step);
        }
        for of_one in steps.values_mut() {
            of_one.sort_by_key(|step| step.position);
        }
        Ok(steps)
    }

    /// The last finished deploy of each of `tags` of `deployment`, by tag and digest: what
    /// the watcher goes by, since a moved tag's new digest has a history of its own.
    ///
    /// # Errors
    /// A database failure.
    pub(crate) async fn last_finished(
        &self,
        deployment: &DeploymentId,
        tags: &[&ReleaseTag],
    ) -> Result<HashMap<(String, String), LastFinished>, StoreError> {
        let wanted = serde_json::to_string(tags)?;
        // SQLite takes the other columns from the row with the greatest `id` of each group.
        sqlx::query(
            "SELECT tag, digest, outcome, reason, max(id) AS id FROM deploys
             WHERE deployment = ? AND state = 'finished'
               AND tag IN (SELECT value FROM json_each(?))
             GROUP BY tag, digest",
        )
        .bind(deployment.as_ref())
        .bind(wanted)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            let key = (row.try_get("tag")?, row.try_get("digest")?);
            let last = LastFinished {
                outcome: row.try_get("outcome")?,
                reason: row.try_get("reason")?,
            };
            Ok((key, last))
        })
        .collect()
    }

    /// The tag of `deployment`'s queued or claimed deploy, if it has one: at most one, by
    /// the table's index.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable tag.
    pub(crate) async fn active_deploy_tag(
        &self,
        deployment: &DeploymentId,
    ) -> Result<Option<ReleaseTag>, StoreError> {
        sqlx::query(
            "SELECT tag FROM deploys WHERE deployment = ? AND state IN ('queued', 'claimed')",
        )
        .bind(deployment.as_ref())
        .fetch_optional(&self.pool)
        .await?
        .map(|row| parsed(&row, "tag"))
        .transpose()
    }

    /// Since when releases first recorded have their commits fetched: when the migration
    /// that began it ran. `None` if it never did.
    ///
    /// # Errors
    /// A database failure.
    pub(crate) async fn commits_began(&self) -> Result<Option<i64>, StoreError> {
        Ok(
            sqlx::query_scalar::<_, Option<i64>>("SELECT min(at) FROM commits_since")
                .fetch_one(&self.pool)
                .await?,
        )
    }
}
