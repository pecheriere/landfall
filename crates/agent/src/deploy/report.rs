//! What a deploy or recovery did, step by step, and how it ended.

use std::time::Duration;

use jiff::Timestamp;
use landfall_core::ids::{DeploymentId, ImageDigest, ReleaseTag};
use serde::{Deserialize, Serialize};

use crate::checks::CheckReport;
use crate::journal::Priority;
use crate::safefs::SnapshotStats;

/// How a deploy that started ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Outcome {
    /// The release is running and passed its checks.
    Deployed,
    /// The deploy failed; the previous version and its data are back.
    RolledBack {
        /// Why the deploy failed.
        reason: String,
    },
    /// The deploy was interrupted before it touched the service: the previous
    /// override is back, and the service was neither stopped, started nor
    /// checked.
    NothingChanged {
        /// Why the deploy did not go ahead.
        reason: String,
    },
    /// The deploy failed and there is no previous version to start, so the
    /// service is stopped.
    FailedNoPrevious {
        /// Why the deploy failed.
        reason: String,
    },
    /// The deploy failed and so did the rollback: the service is in an unknown
    /// state and deploys stay blocked until `recover` succeeds.
    RollbackFailed {
        /// Why the deploy failed.
        reason: String,
        /// Why the rollback failed.
        rollback_reason: String,
    },
}

impl Outcome {
    /// How loudly the journal says it.
    #[must_use]
    pub fn priority(&self) -> Priority {
        match self {
            Self::Deployed => Priority::Info,
            Self::RolledBack { .. } | Self::NothingChanged { .. } => Priority::Warning,
            Self::FailedNoPrevious { .. } => Priority::Error,
            Self::RollbackFailed { .. } => Priority::Critical,
        }
    }
}

/// How a step ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum StepResult {
    /// It did what it should.
    Ok,
    /// It did not.
    Failed {
        /// Why; anything a container said is quoted and truncated.
        reason: String,
    },
}

/// What one post-deploy check took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckTiming {
    /// The check's description.
    pub check: String,
    /// How many times it was evaluated.
    pub attempts: u32,
    /// Time spent evaluating it, without the pauses between rounds.
    pub millis: u64,
}

impl From<&CheckReport> for CheckTiming {
    fn from(report: &CheckReport) -> Self {
        Self {
            check: report.check.clone(),
            attempts: report.attempts,
            millis: millis(report.elapsed),
        }
    }
}

/// More about what a step did.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StepDetail {
    /// A run of the post-deploy checks, whether it passed or not.
    Checks {
        /// One per check, in configuration order.
        checks: Vec<CheckTiming>,
    },
    /// A backup that completed.
    Backup {
        /// What it copied.
        stats: SnapshotStats,
    },
}

/// The step that removes the marker: if it failed, deploys stay blocked.
pub(super) const CLEAR_STEP: &str = "clear_in_progress";

/// One recorded step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Step {
    /// What was done.
    pub name: String,
    /// When it started.
    pub started_at: Timestamp,
    /// How long it took.
    pub millis: u64,
    /// How it ended.
    pub result: StepResult,
    /// More about it, for the steps that have more to say.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<StepDetail>,
}

/// The record of a deploy, or a recovery, that started.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeployReport {
    /// The deployment.
    pub deployment: DeploymentId,
    /// The release that was being deployed.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
    /// How it ended.
    pub outcome: Outcome,
    /// Every step, in order.
    pub steps: Vec<Step>,
    /// When it began.
    pub started_at: Timestamp,
    /// When it ended.
    pub finished_at: Timestamp,
}

impl DeployReport {
    /// Whether the deployment's marker is still there, so that deploys stay
    /// refused until `recover` succeeds: the rollback failed, or the service is
    /// as the outcome says and only the marker could not be removed.
    #[must_use]
    pub fn leaves_deploys_blocked(&self) -> bool {
        matches!(self.outcome, Outcome::RollbackFailed { .. })
            || self.steps.iter().any(|step| {
                step.name == CLEAR_STEP && matches!(step.result, StepResult::Failed { .. })
            })
    }
}

pub(super) fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}
