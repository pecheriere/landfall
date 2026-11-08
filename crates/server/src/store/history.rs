//! What the API reads to tell a deployment's releases and the story of one: the releases
//! recorded, and the requests and deploys of each. Reads only, each bounded and on an index.

use std::collections::HashMap;

use landfall_core::ids::{DeploymentId, PrincipalId, ReleaseTag};
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

/// A deploy of a release.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DeployRow {
    /// Its number.
    pub(crate) id: i64,
    /// `queued`, `claimed` or `finished`.
    pub(crate) state: String,
    /// How it went, by the outcome's stored name, once finished.
    pub(crate) outcome: Option<String>,
    /// When it was queued.
    pub(crate) created_at: i64,
    /// When it finished.
    pub(crate) finished_at: Option<i64>,
}

/// The last finished deploy of a release with one digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LastFinished {
    /// How it went, by the outcome's stored name.
    pub(crate) outcome: String,
    /// What its host said of it, quoted and bounded, if anything.
    pub(crate) reason: Option<String>,
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
                approved_by: row
                    .try_get::<Option<String>, _>("approved_by")?
                    .map(|_| parsed(row, "approved_by"))
                    .transpose()?,
                created_at: row.try_get("created_at")?,
                closed_reason: row.try_get("closed_reason")?,
            })
        })
        .collect()
    }

    /// The newest `limit` deploys of `tag` of `deployment`, newest first.
    ///
    /// # Errors
    /// A database failure.
    pub(crate) async fn deploys_of_release(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        limit: u32,
    ) -> Result<Vec<DeployRow>, StoreError> {
        sqlx::query(
            "SELECT id, state, outcome, created_at, finished_at
             FROM deploys WHERE deployment = ? AND tag = ?
             ORDER BY id DESC LIMIT ?",
        )
        .bind(deployment.as_ref())
        .bind(tag.as_ref())
        .bind(limit)
        .fetch_all(&self.pool)
        .await?
        .iter()
        .map(|row| {
            Ok(DeployRow {
                id: row.try_get("id")?,
                state: row.try_get("state")?,
                outcome: row.try_get("outcome")?,
                created_at: row.try_get("created_at")?,
                finished_at: row.try_get("finished_at")?,
            })
        })
        .collect()
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
