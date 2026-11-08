//! Each deployment's latest release, as a list of its releases shows it first, kept where
//! releases are recorded, so that a page of deployments reads it by key whatever their
//! histories hold.
//!
//! Which release is latest depends on the configuration's tag pattern, which the store
//! doesn't have: the highest semantic version its pattern reads, or, when it reads none of
//! the deployment's tags, the first tag in string order. So the store keeps the highest
//! release under every prefix a pattern could have that reads it, in `highest_releases`,
//! and the first tag in `first_tags`, and a reader names its prefix. Both are kept in the
//! transaction that records a release, and filled once from the releases recorded before
//! them when the controller first opens the database after `0007`.

use std::collections::HashMap;

use landfall_core::ids::{DeploymentId, ReleaseTag, TagPattern};
use semver::Version;
use serde_json::json;
use sqlx::Row as _;
use sqlx::SqliteConnection;

use super::deploys::parsed;
use super::history::{LastFinished, ReleaseRow, release_from};
use super::releases::hold_from;
use super::{Hold, Store, StoreError};

/// Each deployment's latest release, from a JSON list of `[deployment, prefix]`: on the
/// primary keys of `releases`, `highest_releases` and `first_tags`. Here and below, `CROSS
/// JOIN` keeps the page's list outside, so that each table is searched by key for each item
/// of it, rather than scanned with the list looked up.
pub(super) const LATEST_ROWS: &str = "SELECT json_extract(w.value, '$[0]') AS latest_of,
         r.tag AS tag, r.commit_sha AS commit_sha, r.digest AS digest,
         r.decision AS decision, r.reason AS reason, r.tag_object AS tag_object,
         r.config_hash AS config_hash, r.origin_refused AS origin_refused,
         r.first_seen_at AS first_seen_at, r.seen_at AS seen_at
     FROM json_each(?) AS w
     CROSS JOIN releases AS r
       ON r.deployment = json_extract(w.value, '$[0]')
      AND r.tag = COALESCE(
              (SELECT h.tag FROM highest_releases AS h
               WHERE h.deployment = json_extract(w.value, '$[0]')
                 AND h.prefix = json_extract(w.value, '$[1]')),
              (SELECT f.tag FROM first_tags AS f
               WHERE f.deployment = json_extract(w.value, '$[0]')))";

/// The holds named by a JSON list of `[deployment, tag]`, the empty tag for a whole
/// deployment: on the primary key of `release_holds`.
pub(super) const HOLDS: &str = "SELECT h.deployment AS deployment, h.tag AS tag,
         h.reason AS reason, h.since AS since, h.last_try AS last_try, h.slow AS slow
     FROM json_each(?) AS w
     CROSS JOIN release_holds AS h
       ON h.deployment = json_extract(w.value, '$[0]')
      AND h.tag = json_extract(w.value, '$[1]')";

/// The queued or claimed deploy of each deployment of a JSON list: on the partial index that
/// keeps one a deployment, never on its history.
pub(super) const ACTIVE_DEPLOYS: &str = "SELECT d.deployment AS deployment, d.tag AS tag
     FROM json_each(?) AS w
     CROSS JOIN deploys AS d INDEXED BY one_active_deploy_per_deployment
       ON d.deployment = w.value
     WHERE d.state IN ('queued', 'claimed')";

/// The last finished deploy of each release of a JSON list of `[deployment, tag, digest]`:
/// on `deploys_by_release`, through that one release's deploys.
pub(super) const LAST_FINISHED: &str = "SELECT d.deployment AS deployment, d.tag AS tag,
         d.digest AS digest, d.outcome AS outcome, d.reason AS reason
     FROM json_each(?) AS w
     CROSS JOIN deploys AS d
       ON d.id = (SELECT max(x.id) FROM deploys AS x
                  WHERE x.deployment = json_extract(w.value, '$[0]')
                    AND x.tag = json_extract(w.value, '$[1]')
                    AND x.digest = json_extract(w.value, '$[2]')
                    AND x.state = 'finished')";

/// What a page of deployments' summaries need of their latest releases, read together.
#[derive(Debug, Default)]
pub(crate) struct LatestFacts {
    /// Each deployment's latest release, if it has one.
    pub(crate) rows: HashMap<DeploymentId, ReleaseRow>,
    /// The hold on that release, by its tag, and the one on the whole deployment.
    pub(crate) holds: HashMap<DeploymentId, (HashMap<String, Hold>, Option<Hold>)>,
    /// The tag of each deployment's queued or claimed deploy.
    pub(crate) active: HashMap<DeploymentId, ReleaseTag>,
    /// The last finished deploy of that release at its digest, by tag and digest.
    pub(crate) last: HashMap<DeploymentId, HashMap<(String, String), LastFinished>>,
}

/// Each prefix a tag pattern could have under which `tag` reads as a version, with the
/// pattern and the version. Usually one; a pre-release such as `v1.0.0-rc2.0.0` also reads
/// under `v1.0.0-rc`.
fn readings(tag: &ReleaseTag) -> impl Iterator<Item = (&str, TagPattern, Version)> {
    let text = tag.as_ref();
    (0..=text.len()).filter_map(move |end| {
        let prefix = text.get(..end)?;
        let pattern: TagPattern = format!("{prefix}*").parse().ok()?;
        let version = pattern.parse_tag(tag).ok()?;
        Some((prefix, pattern, version))
    })
}

/// Notes `tag` among `deployment`'s releases, on `connection`, which is the transaction that
/// records it.
///
/// # Errors
/// A database failure.
pub(super) async fn note_release(
    connection: &mut SqliteConnection,
    deployment: &DeploymentId,
    tag: &ReleaseTag,
) -> Result<(), StoreError> {
    for (prefix, pattern, version) in readings(tag) {
        let current: Option<String> = sqlx::query_scalar(
            "SELECT tag FROM highest_releases WHERE deployment = ? AND prefix = ?",
        )
        .bind(deployment.as_ref())
        .bind(prefix)
        .fetch_optional(&mut *connection)
        .await?;
        let higher_kept = current.is_some_and(|current| {
            current
                .parse::<ReleaseTag>()
                .ok()
                .and_then(|current| pattern.parse_tag(&current).ok())
                .is_some_and(|kept| kept >= version)
        });
        if higher_kept {
            continue;
        }
        sqlx::query(
            "INSERT INTO highest_releases (deployment, prefix, tag) VALUES (?, ?, ?)
             ON CONFLICT (deployment, prefix) DO UPDATE SET tag = excluded.tag",
        )
        .bind(deployment.as_ref())
        .bind(prefix)
        .bind(tag.as_ref())
        .execute(&mut *connection)
        .await?;
    }
    sqlx::query(
        "INSERT INTO first_tags (deployment, tag) VALUES (?, ?)
         ON CONFLICT (deployment) DO UPDATE SET tag = min(tag, excluded.tag)",
    )
    .bind(deployment.as_ref())
    .bind(tag.as_ref())
    .execute(&mut *connection)
    .await?;
    Ok(())
}

impl Store {
    /// Fills each deployment's latest release from the releases already recorded, if `0007`
    /// left that to do, in one transaction: once.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(super) async fn fill_latest(&self) -> Result<(), StoreError> {
        let mut tx = self.begin().await?;
        let pending: Option<i64> = sqlx::query_scalar("SELECT pending FROM latest_unfilled")
            .fetch_optional(&mut *tx)
            .await?;
        if pending.is_none() {
            return Ok(());
        }
        let rows = sqlx::query("SELECT deployment, tag FROM releases")
            .fetch_all(&mut *tx)
            .await?;
        for row in &rows {
            let deployment: DeploymentId = parsed(row, "deployment")?;
            let tag: ReleaseTag = parsed(row, "tag")?;
            note_release(&mut tx, &deployment, &tag).await?;
        }
        sqlx::query("DELETE FROM latest_unfilled")
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        Ok(())
    }

    /// What the summaries of `wanted` deployments need of their latest releases, each named
    /// with its tag pattern's prefix: a fixed number of statements on indexes, whatever the
    /// deployments' histories hold, from one snapshot.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub(crate) async fn latest_facts(
        &self,
        wanted: &[(&DeploymentId, &str)],
    ) -> Result<LatestFacts, StoreError> {
        let mut tx = self.pool.begin().await?;
        let mut facts = LatestFacts::default();
        let pairs: Vec<_> = wanted
            .iter()
            .map(|(id, prefix)| json!([id, prefix]))
            .collect();
        for row in sqlx::query(LATEST_ROWS)
            .bind(serde_json::to_string(&pairs)?)
            .fetch_all(&mut *tx)
            .await?
        {
            facts
                .rows
                .insert(parsed(&row, "latest_of")?, release_from(&row)?);
        }
        let held: Vec<_> = facts
            .rows
            .iter()
            .flat_map(|(id, row)| [json!([id, row.tag]), json!([id, ""])])
            .collect();
        for row in sqlx::query(HOLDS)
            .bind(serde_json::to_string(&held)?)
            .fetch_all(&mut *tx)
            .await?
        {
            let tag: String = row.try_get("tag")?;
            let (by_tag, whole) = facts.holds.entry(parsed(&row, "deployment")?).or_default();
            if tag.is_empty() {
                *whole = Some(hold_from(&row)?);
            } else {
                by_tag.insert(tag, hold_from(&row)?);
            }
        }
        let ids: Vec<&DeploymentId> = wanted.iter().map(|(id, _)| *id).collect();
        for row in sqlx::query(ACTIVE_DEPLOYS)
            .bind(serde_json::to_string(&ids)?)
            .fetch_all(&mut *tx)
            .await?
        {
            facts
                .active
                .insert(parsed(&row, "deployment")?, parsed(&row, "tag")?);
        }
        let releases: Vec<_> = facts
            .rows
            .iter()
            .filter_map(|(id, row)| Some(json!([id, row.tag, row.release.digest.as_ref()?])))
            .collect();
        for row in sqlx::query(LAST_FINISHED)
            .bind(serde_json::to_string(&releases)?)
            .fetch_all(&mut *tx)
            .await?
        {
            let key = (row.try_get("tag")?, row.try_get("digest")?);
            let last = LastFinished {
                outcome: row.try_get("outcome")?,
                reason: row.try_get("reason")?,
            };
            facts
                .last
                .entry(parsed(&row, "deployment")?)
                .or_default()
                .insert(key, last);
        }
        tx.commit().await?;
        Ok(facts)
    }
}
