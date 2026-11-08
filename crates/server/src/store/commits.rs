//! The commits between two verified releases, stored by repository and commit.
//!
//! A range goes from a base commit to a head commit, both of releases settled under the
//! current configuration. It is keyed by commit and not by tag, so a moved tag leaves
//! its old range behind and two deployments of one repository share a range. What is
//! stored came from GitHub and was made safe to keep where it was read
//! ([`landfall_origin::fetch::ListedCommit`]): ids validated, summaries quoted and cut,
//! logins checked against GitHub's grammar.

use std::collections::{HashMap, HashSet};

use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, DeploymentId, ReleaseTag, RepoName};
use landfall_origin::fetch::ListedCommit;
use semver::Version;
use sqlx::Row as _;

use super::deploys::parsed;
use super::{Store, StoreError};
use crate::watcher::commits::{COMMIT_RETRY_SECS, base_for};

/// What came of fetching a range.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RangeState {
    /// Its newest commits are listed.
    Listed,
    /// Too large for GitHub to list: a person reads it on GitHub.
    TooLarge,
    /// The base commit isn't an ancestor of the head: a rewritten history.
    BaseNotFound,
    /// It could not be fetched, and is tried again after a while.
    Unavailable,
}

impl RangeState {
    fn as_str(self) -> &'static str {
        match self {
            Self::Listed => "listed",
            Self::TooLarge => "too_large",
            Self::BaseNotFound => "base_not_found",
            Self::Unavailable => "unavailable",
        }
    }

    fn parse(text: &str) -> Result<Self, StoreError> {
        match text {
            "listed" => Ok(Self::Listed),
            "too_large" => Ok(Self::TooLarge),
            "base_not_found" => Ok(Self::BaseNotFound),
            "unavailable" => Ok(Self::Unavailable),
            _ => Err(StoreError::Corrupt("state")),
        }
    }
}

/// A stored range.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitRange {
    /// What came of fetching it.
    pub state: RangeState,
    /// GitHub's count of every commit in it, for a listed range.
    pub total: Option<u64>,
    /// When it was fetched.
    pub last_try: i64,
    /// Its newest commits, newest first: empty unless it is listed.
    pub commits: Vec<ListedCommit>,
}

/// A range to store.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NewRange<'a> {
    /// What came of fetching it.
    pub state: RangeState,
    /// GitHub's count of every commit in it, for a listed range.
    pub total: Option<u64>,
    /// Its newest commits, newest first.
    pub commits: &'a [ListedCommit],
}

/// A range that should be fetched: from the release below a settled release, to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WantedRange {
    /// A deployment of the repository, to fetch through.
    pub deployment: DeploymentId,
    /// The head's release tag.
    pub tag: ReleaseTag,
    /// The repository.
    pub repo: RepoName,
    /// The base's commit.
    pub base: CommitSha,
    /// The head's commit.
    pub head: CommitSha,
    /// Whether it is stored as unavailable, and this is a try again.
    pub retry: bool,
}

/// A repository's stored ranges, by `(base, head)`: their state and last try.
type StoredRanges = HashMap<(String, String), (RangeState, i64)>;

/// A settled release of a deployment, as `ranges_wanted` reads it.
struct SettledRow {
    tag: ReleaseTag,
    commit: CommitSha,
    first_seen_at: i64,
}

impl Store {
    /// The range of `repo` from `base` to `head`, if one is stored.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn commit_range(
        &self,
        repo: &RepoName,
        base: &CommitSha,
        head: &CommitSha,
    ) -> Result<Option<CommitRange>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let Some(row) = sqlx::query(
            "SELECT state, total, last_try FROM commit_ranges
             WHERE repo = ? AND base_commit = ? AND head_commit = ?",
        )
        .bind(repo.as_ref())
        .bind(base.as_ref())
        .bind(head.as_ref())
        .fetch_optional(&mut *tx)
        .await?
        else {
            return Ok(None);
        };
        let total = row
            .try_get::<Option<i64>, _>("total")?
            .map(|total| u64::try_from(total).map_err(|_| StoreError::Corrupt("total")))
            .transpose()?;
        let commits = sqlx::query(
            "SELECT sha, summary, author FROM range_commits
             WHERE repo = ? AND base_commit = ? AND head_commit = ?
             ORDER BY position",
        )
        .bind(repo.as_ref())
        .bind(base.as_ref())
        .bind(head.as_ref())
        .fetch_all(&mut *tx)
        .await?
        .iter()
        .map(|row| {
            Ok(ListedCommit {
                sha: parsed(row, "sha")?,
                summary: row.try_get("summary")?,
                author: row.try_get("author")?,
            })
        })
        .collect::<Result<_, StoreError>>()?;
        Ok(Some(CommitRange {
            state: RangeState::parse(&row.try_get::<String, _>("state")?)?,
            total,
            last_try: row.try_get("last_try")?,
            commits,
        }))
    }

    /// Stores the range of `repo` from `base` to `head`, replacing it and its commits
    /// in one transaction, as fetched now. It decides nothing, so it writes no audit
    /// row.
    ///
    /// # Errors
    /// A clock or database failure.
    pub async fn record_commit_range(
        &self,
        repo: &RepoName,
        base: &CommitSha,
        head: &CommitSha,
        range: &NewRange<'_>,
    ) -> Result<(), StoreError> {
        let now = self.clock.now()?;
        let total = range
            .total
            .map(|total| i64::try_from(total).unwrap_or(i64::MAX));
        let key = (repo.as_ref(), base.as_ref(), head.as_ref());
        let mut tx = self.begin().await?;
        sqlx::query(
            "DELETE FROM range_commits WHERE repo = ? AND base_commit = ? AND head_commit = ?",
        )
        .bind(key.0)
        .bind(key.1)
        .bind(key.2)
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "INSERT INTO commit_ranges (repo, base_commit, head_commit, state, total, last_try)
             VALUES (?, ?, ?, ?, ?, ?)
             ON CONFLICT (repo, base_commit, head_commit) DO UPDATE SET
                 state = excluded.state,
                 total = excluded.total,
                 last_try = excluded.last_try",
        )
        .bind(key.0)
        .bind(key.1)
        .bind(key.2)
        .bind(range.state.as_str())
        .bind(total)
        .bind(now)
        .execute(&mut *tx)
        .await?;
        for (position, commit) in (0_i64..).zip(range.commits) {
            sqlx::query(
                "INSERT INTO range_commits
                     (repo, base_commit, head_commit, position, sha, summary, author)
                 VALUES (?, ?, ?, ?, ?, ?, ?)",
            )
            .bind(key.0)
            .bind(key.1)
            .bind(key.2)
            .bind(position)
            .bind(commit.sha.as_ref())
            .bind(&commit.summary)
            .bind(commit.author.as_deref())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// The ranges to fetch, newest version first across deployments, each
    /// `(repo, base, head)` once: for each release settled under `config_hash` and
    /// first recorded since commits began to be compared, from the highest lower
    /// settled release of its deployment to it, when there is one and no range is
    /// stored for them, or only an unavailable one tried more than
    /// an hour (`COMMIT_RETRY_SECS`) before `now`.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable row.
    pub async fn ranges_wanted(
        &self,
        config: &Config,
        config_hash: &str,
        now: i64,
    ) -> Result<Vec<WantedRange>, StoreError> {
        let mut tx = self.pool.begin().await?;
        let Some(since) = sqlx::query_scalar::<_, Option<i64>>("SELECT min(at) FROM commits_since")
            .fetch_one(&mut *tx)
            .await?
        else {
            return Ok(Vec::new());
        };
        let mut stored: HashMap<RepoName, StoredRanges> = HashMap::new();
        let mut wanted: Vec<(Version, WantedRange)> = Vec::new();
        for d in config.deployments() {
            let settled = sqlx::query(
                "SELECT tag, commit_sha, first_seen_at FROM releases
                 WHERE deployment = ? AND config_hash = ? AND commit_sha IS NOT NULL
                   AND digest IS NOT NULL AND origin_refused = 0",
            )
            .bind(d.id().as_ref())
            .bind(config_hash)
            .fetch_all(&mut *tx)
            .await?
            .iter()
            .map(|row| {
                Ok(SettledRow {
                    tag: parsed(row, "tag")?,
                    commit: parsed(row, "commit_sha")?,
                    first_seen_at: row.try_get("first_seen_at")?,
                })
            })
            .collect::<Result<Vec<_>, StoreError>>()?;
            let pairs: Vec<(ReleaseTag, CommitSha)> = settled
                .iter()
                .map(|row| (row.tag.clone(), row.commit.clone()))
                .collect();
            let repo = d.repo().name();
            let ranges = match stored.entry(repo.clone()) {
                std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(stored_ranges(&mut tx, repo).await?)
                }
            };
            let pattern = d.origin().tags();
            for row in settled.iter().filter(|row| row.first_seen_at >= since) {
                let Ok(version) = pattern.parse_tag(&row.tag) else {
                    continue;
                };
                let Some((_, base)) = base_for(pattern, &row.tag, &pairs) else {
                    continue;
                };
                let key = (base.as_ref().to_owned(), row.commit.as_ref().to_owned());
                let retry = match ranges.get(&key) {
                    None => false,
                    Some((RangeState::Unavailable, last_try))
                        if now.saturating_sub(*last_try) > COMMIT_RETRY_SECS =>
                    {
                        true
                    }
                    Some(_) => continue,
                };
                wanted.push((
                    version,
                    WantedRange {
                        deployment: d.id().clone(),
                        tag: row.tag.clone(),
                        repo: repo.clone(),
                        base,
                        head: row.commit.clone(),
                        retry,
                    },
                ));
            }
        }
        wanted.sort_by(|(a, one), (b, other)| {
            b.cmp(a)
                .then_with(|| one.deployment.cmp(&other.deployment))
                .then_with(|| one.tag.cmp(&other.tag))
        });
        let mut seen = HashSet::new();
        Ok(wanted
            .into_iter()
            .map(|(_, range)| range)
            .filter(|range| {
                seen.insert((range.repo.clone(), range.base.clone(), range.head.clone()))
            })
            .collect())
    }
}

/// Every stored range of `repo`, by `(base, head)`, with its state and last try.
async fn stored_ranges(
    tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
    repo: &RepoName,
) -> Result<StoredRanges, StoreError> {
    sqlx::query(
        "SELECT base_commit, head_commit, state, last_try FROM commit_ranges WHERE repo = ?",
    )
    .bind(repo.as_ref())
    .fetch_all(&mut **tx)
    .await?
    .iter()
    .map(|row| {
        Ok((
            (row.try_get("base_commit")?, row.try_get("head_commit")?),
            (
                RangeState::parse(&row.try_get::<String, _>("state")?)?,
                row.try_get("last_try")?,
            ),
        ))
    })
    .collect()
}
