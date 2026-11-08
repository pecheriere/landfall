//! What the API reads to show deployments: what their hosts last said, and their holds.
//! Reads only, each bounded and on an index.

use std::collections::HashMap;
use std::str::FromStr;

use landfall_core::ids::{DeploymentId, HostId, ReleaseTag};
use sqlx::Row as _;
use sqlx::sqlite::SqliteRow;

use super::deploys::parsed;
use super::releases::hold_from;
use super::{Hold, Store, StoreError, WatchedRunning};

/// What a host last said about a deployment, with what a view of it shows beyond what the
/// watcher reads in its transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RunningRow {
    /// The host that said it. A report is the deployment's only if the configuration still
    /// pairs the two.
    pub(crate) host: HostId,
    /// What it said.
    pub(crate) running: WatchedRunning,
    /// How long the release has been observed healthy, in seconds, as of `last_report`.
    pub(crate) healthy_secs: Option<i64>,
    /// When the host last said anything about it.
    pub(crate) last_report: Option<i64>,
    /// Whether that host's configuration differs from the controller's.
    pub(crate) config_drift: bool,
}

impl Store {
    /// What the hosts last said about each of `ids` that any has reported, by deployment.
    /// One statement, on the table's key.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn running_states(
        &self,
        ids: &[&DeploymentId],
    ) -> Result<HashMap<DeploymentId, RunningRow>, StoreError> {
        let wanted = serde_json::to_string(ids)?;
        let rows = sqlx::query(
            "SELECT r.deployment, r.host, r.tag, r.digest, r.drift, r.phase, r.busy,
                    r.healthy_secs, r.last_report,
                    h.drifted_config_hash IS NOT NULL AS config_drift
             FROM running_states r LEFT JOIN hosts h ON h.id = r.host
             WHERE r.deployment IN (SELECT value FROM json_each(?))",
        )
        .bind(wanted)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let running = WatchedRunning {
                    tag: optional(row, "tag")?,
                    digest: optional(row, "digest")?,
                    drift: row.try_get("drift")?,
                    phase: row.try_get("phase")?,
                    busy: row.try_get("busy")?,
                };
                let found = RunningRow {
                    host: parsed(row, "host")?,
                    running,
                    healthy_secs: row.try_get("healthy_secs")?,
                    last_report: row.try_get("last_report")?,
                    config_drift: row.try_get("config_drift")?,
                };
                Ok((parsed(row, "deployment")?, found))
            })
            .collect()
    }

    /// The newest `limit` holds on `id`, by when each began, each with its tag or `None` for
    /// one on the whole deployment, and how many there are in all. Both from one snapshot.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable tag.
    pub async fn holds_of_deployment(
        &self,
        id: &DeploymentId,
        limit: u32,
    ) -> Result<(Vec<(Option<ReleaseTag>, Hold)>, u32), StoreError> {
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(
            "SELECT tag, reason, since, last_try, slow FROM release_holds
             WHERE deployment = ? ORDER BY since DESC, tag LIMIT ?",
        )
        .bind(id.as_ref())
        .bind(limit)
        .fetch_all(&mut *tx)
        .await?;
        let total: i64 =
            sqlx::query_scalar("SELECT count(*) FROM release_holds WHERE deployment = ?")
                .bind(id.as_ref())
                .fetch_one(&mut *tx)
                .await?;
        tx.commit().await?;
        let holds = rows
            .iter()
            .map(|row| {
                // A hold on the whole deployment has an empty tag, as no release tag is.
                let tag: String = row.try_get("tag")?;
                let tag = if tag.is_empty() {
                    None
                } else {
                    Some(parsed(row, "tag")?)
                };
                Ok((tag, hold_from(row)?))
            })
            .collect::<Result<_, StoreError>>()?;
        Ok((holds, u32::try_from(total).unwrap_or(u32::MAX)))
    }
}

/// A column that may be `NULL`, parsed when it isn't.
fn optional<T: FromStr>(row: &SqliteRow, column: &'static str) -> Result<Option<T>, StoreError> {
    row.try_get::<Option<String>, _>(column)?
        .map(|_| parsed(row, column))
        .transpose()
}
