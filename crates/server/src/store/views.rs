//! What the API reads to show deployments: what their hosts last said, their holds, the
//! hosts, and the audit log as far as a principal may see it. Reads only, each bounded and on
//! an index.

use std::collections::HashMap;
use std::str::FromStr;

use landfall_core::ids::{DeploymentId, HostId, ReleaseTag};
use sqlx::sqlite::{SqliteArguments, SqliteRow};
use sqlx::{AssertSqlSafe, Row as _, Sqlite};

use super::deploys::parsed;
use super::releases::hold_from;
use super::{AuditRow, Hold, Store, StoreError, WatchedRunning};

/// The kinds of row about a host alone, with no deployment, that the API shows, to whoever may
/// view a deployment on that host. Enrolment codes, refused enrolments and refused reports stay
/// on the controller: they can name another host, or someone else's attempt.
pub(crate) const HOST_ROW_KINDS: [&str; 2] = ["host_enrolled", "config_drift"];

/// The most branches one audit query has: under `SQLite`'s default limit of 500 terms in a
/// compound `SELECT`, and at most four bound parameters each.
pub(crate) const MAX_AUDIT_BRANCHES: usize = 400;

/// A host, as the controller enrolled it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct HostRow {
    /// When it enrolled its key, in unix seconds.
    pub(crate) enrolled_at: i64,
    /// Whether its configuration differs from the controller's.
    pub(crate) config_drift: bool,
}

/// The hosts by id, each on the table's key: `CROSS JOIN` keeps the list of ids outside, so
/// that each is searched for rather than the table scanned.
pub(super) const HOSTS_BY_ID: &str =
    "SELECT h.id, h.enrolled_at, h.drifted_config_hash IS NOT NULL AS config_drift
     FROM json_each(?) AS w CROSS JOIN hosts h ON h.id = w.value";

/// What a principal may see of the audit log: the rows of each deployment they may view, and
/// the rows of [`HOST_ROW_KINDS`] about each host the configuration puts one of those on.
#[derive(Debug, Clone, Copy)]
pub(crate) struct AuditScope<'a> {
    /// The deployments.
    pub(crate) deployments: &'a [&'a DeploymentId],
    /// The hosts.
    pub(crate) hosts: &'a [&'a HostId],
}

/// One branch of the audit query, each read newest first from an index of its own.
#[derive(Debug, Clone, Copy)]
enum Branch<'a> {
    /// A deployment's rows, of the query's kind if it has one.
    Deployment(&'a DeploymentId),
    /// A host's rows of one kind, with no deployment.
    Host(&'a HostId, &'static str),
}

/// The columns of a row of the log as [`audit_row`] reads them: text as bytes, so that a row
/// someone wrote invalid text into reads, replaced, rather than failing the page.
macro_rules! audit_columns {
    () => {
        "seq, ts, CAST(kind AS BLOB) AS kind, CAST(deployment AS BLOB) AS deployment,
         CAST(host AS BLOB) AS host, CAST(detail AS BLOB) AS detail"
    };
}

// Each branch names its index. Left to itself, the planner can prefer walking the whole log
// down from the cursor by `seq` and filtering, which reads rows in proportion to the log rather
// than to the page; with `INDEXED BY`, a branch that can't use its index fails instead.

/// A deployment's branch, newest first on `audit_by_deployment`.
const DEPLOYMENT_BRANCH: &str = concat!(
    "SELECT * FROM (SELECT ",
    audit_columns!(),
    " FROM audit_events INDEXED BY audit_by_deployment
     WHERE deployment = ? AND seq < ? ORDER BY seq DESC LIMIT ?)"
);

/// A deployment's branch of one kind, newest first on `audit_by_deployment_kind`.
const DEPLOYMENT_KIND_BRANCH: &str = concat!(
    "SELECT * FROM (SELECT ",
    audit_columns!(),
    " FROM audit_events INDEXED BY audit_by_deployment_kind
     WHERE deployment = ? AND kind = ? AND seq < ? ORDER BY seq DESC LIMIT ?)"
);

/// A host's branch of one kind, with no deployment, newest first on `audit_by_host_alone`.
const HOST_BRANCH: &str = concat!(
    "SELECT * FROM (SELECT ",
    audit_columns!(),
    " FROM audit_events INDEXED BY audit_by_host_alone
     WHERE deployment IS NULL AND host = ? AND kind = ? AND seq < ? ORDER BY seq DESC LIMIT ?)"
);

/// The audit query for a scope and a kind: one branch for each deployment, and one for each
/// host and each of [`HOST_ROW_KINDS`] the kind allows, under [`MAX_AUDIT_BRANCHES`]. A row
/// with neither a deployment nor a host is in no branch.
#[derive(Debug, Clone)]
pub(crate) struct AuditBranches<'a> {
    branches: Vec<Branch<'a>>,
    kind: Option<&'a str>,
}

impl<'a> AuditBranches<'a> {
    /// The branches `scope` needs for rows of `kind`, or of any kind; `None` when there are
    /// more than [`MAX_AUDIT_BRANCHES`].
    pub(crate) fn new(scope: &AuditScope<'a>, kind: Option<&'a str>) -> Option<Self> {
        let host_kinds: Vec<&'static str> = HOST_ROW_KINDS
            .into_iter()
            .filter(|allowed| kind.is_none_or(|kind| kind == *allowed))
            .collect();
        let branches: Vec<Branch<'a>> = scope
            .deployments
            .iter()
            .map(|deployment| Branch::Deployment(deployment))
            .chain(
                scope
                    .hosts
                    .iter()
                    .flat_map(|host| host_kinds.iter().map(move |kind| Branch::Host(host, kind))),
            )
            .collect();
        (branches.len() <= MAX_AUDIT_BRANCHES).then_some(Self { branches, kind })
    }

    /// The statement, after `prefix`, with its parameters bound: rows before `before`, newest
    /// first, at most `limit`, and at most `limit` read from each branch's index.
    pub(super) fn statement(
        &self,
        prefix: &str,
        before: i64,
        limit: u32,
    ) -> sqlx::query::Query<'_, Sqlite, SqliteArguments> {
        let deployment_branch = if self.kind.is_some() {
            DEPLOYMENT_KIND_BRANCH
        } else {
            DEPLOYMENT_BRANCH
        };
        let branches: Vec<&str> = self
            .branches
            .iter()
            .map(|branch| match branch {
                Branch::Deployment(_) => deployment_branch,
                Branch::Host(..) => HOST_BRANCH,
            })
            .collect();
        let sql = format!(
            "{prefix}{} ORDER BY seq DESC LIMIT ?",
            branches.join(" UNION ALL ")
        );
        // Only placeholders: every value is bound.
        let mut query = sqlx::query(AssertSqlSafe(sql));
        for branch in &self.branches {
            query = match *branch {
                Branch::Deployment(deployment) => {
                    let query = query.bind(deployment.as_ref());
                    match self.kind {
                        Some(kind) => query.bind(kind),
                        None => query,
                    }
                }
                Branch::Host(host, kind) => query.bind(host.as_ref()).bind(kind),
            };
            query = query.bind(before).bind(limit);
        }
        query.bind(limit)
    }
}

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

impl Store {
    /// Each of `ids` that has enrolled, by id. One statement, on the table's key.
    ///
    /// # Errors
    /// A database failure, or [`StoreError::Corrupt`] for an unreadable id.
    pub(crate) async fn hosts(
        &self,
        ids: &[&HostId],
    ) -> Result<HashMap<HostId, HostRow>, StoreError> {
        let rows = sqlx::query(HOSTS_BY_ID)
            .bind(serde_json::to_string(ids)?)
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let host = HostRow {
                    enrolled_at: row.try_get("enrolled_at")?,
                    config_drift: row.try_get("config_drift")?,
                };
                Ok((parsed(row, "id")?, host))
            })
            .collect()
    }

    /// The newest `limit` rows of the log before `before`, or from the newest, in `branches`,
    /// newest first. Each branch reads at most `limit` rows from its index, and no branches
    /// read nothing.
    ///
    /// # Errors
    /// A database failure.
    pub(crate) async fn audit_page(
        &self,
        branches: &AuditBranches<'_>,
        before: Option<i64>,
        limit: u32,
    ) -> Result<Vec<AuditRow>, StoreError> {
        if branches.branches.is_empty() {
            return Ok(Vec::new());
        }
        let rows = branches
            .statement("", before.unwrap_or(i64::MAX), limit)
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(audit_row).collect()
    }
}

/// A row of the log, from its [`audit_columns`] in that order. Text that isn't valid UTF-8
/// comes out replaced.
pub(super) fn audit_row(row: &SqliteRow) -> Result<AuditRow, StoreError> {
    let text = |bytes: Vec<u8>| String::from_utf8_lossy(&bytes).into_owned();
    Ok(AuditRow {
        seq: row.try_get(0)?,
        ts: row.try_get(1)?,
        kind: text(row.try_get(2)?),
        deployment: row.try_get::<Option<Vec<u8>>, _>(3)?.map(text),
        host: row.try_get::<Option<Vec<u8>>, _>(4)?.map(text),
        detail: text(row.try_get(5)?),
    })
}

/// A column that may be `NULL`, parsed when it isn't.
fn optional<T: FromStr>(row: &SqliteRow, column: &'static str) -> Result<Option<T>, StoreError> {
    row.try_get::<Option<String>, _>(column)?
        .map(|_| parsed(row, column))
        .transpose()
}
