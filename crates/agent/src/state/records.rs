//! The records the agent keeps: what is deployed, in progress, claimed and finished.

use jiff::Timestamp;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{DeployId, DeployReportBody};
use serde::{Deserialize, Serialize};

/// What is running for a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployed {
    /// The deploy that recorded this, as in [`InProgress::deploy_id`].
    pub deploy_id: String,
    /// The release tag.
    pub tag: ReleaseTag,
    /// The version the tag parses to.
    pub version: semver::Version,
    /// The image digest that was started.
    pub digest: ImageDigest,
    /// The commit the tag points at.
    pub commit: CommitSha,
    /// When the deploy finished.
    pub deployed_at: Timestamp,
}

/// How far an unfinished deploy got, which is what `recover` goes by. Each
/// value is on disk before the work it announces starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Checking the project and pulling the image. No service has been
    /// touched; only the override can be out of place.
    Preflight,
    /// Going forward: the service may have been touched. The deploy has finished only if [`Deployed`] names its
    /// id: that is written once the checks have passed.
    Deploying,
    /// Going back. A [`Deployed`] that names this deploy means nothing here:
    /// the record can have been left by a write reported as failed, and the
    /// release is on its way out.
    RollingBack,
    /// Going back, and the backup has been restored in full: the override and
    /// the record were put back before it. What remains is to start the
    /// previous version and check it. It may well be running by now and have
    /// written to its data, so the service is not stopped and the backup is
    /// not restored again. A restore that did not finish stays [`Self::RollingBack`].
    Restored,
    /// Back, and checked. Only the marker is left to remove; restoring again
    /// would discard what the previous version wrote since.
    RolledBack,
}

/// A backup that is complete, and what it holds. The paths are the ones it was
/// taken of, whatever the configuration says by the time it is restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedBackup {
    /// The backup's directory name.
    pub id: String,
    /// The paths it holds, relative to the compose directory.
    pub paths: Vec<String>,
}

/// A deploy that has started and not finished. While it exists, further
/// deploys of the deployment are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InProgress {
    /// Tells this deploy from every other one, also of the same release.
    pub deploy_id: String,
    /// How far it got.
    pub phase: Phase,
    /// The release being deployed.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
    /// Whether there is a previous version to start: the compose project gave
    /// the service an image before the deploy. On a first deploy from a base
    /// file without one, rollback stops the service instead.
    pub previous_can_start: bool,
    /// The backup taken for this deploy, if any.
    pub backup: Option<RecordedBackup>,
    /// When the deploy began.
    pub started_at: Timestamp,
}

/// The controller's deploy a deployment is working on, written before the
/// engine starts and removed once the report is safely in the outbox. It is
/// what ties the controller's number to the agent's own deploy: only one can
/// exist per deployment and none is written while a marker is there, so the
/// marker or the report the engine leaves after a crash, or after a `recover`,
/// is this deploy's. Only the daemon writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerClaim {
    /// The controller's id for the deploy.
    pub deploy_id: DeployId,
    /// The release the deploy is of.
    pub tag: ReleaseTag,
    /// Its verified image digest.
    pub digest: ImageDigest,
    /// The engine's report files that existed when the claim was made. Whatever
    /// the engine reports for this deploy is not among them, whatever the clock
    /// did in between.
    pub reports_before: Vec<String>,
}

/// How a controller's deploy ended, and what it was of: a record goes by number and
/// release, as a controller whose database was rebuilt uses numbers again.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishedDeploy {
    /// The deployment it was for.
    pub deployment: DeploymentId,
    /// The release it was of.
    pub tag: ReleaseTag,
    /// Its image digest, as it was asked for.
    pub digest: ImageDigest,
    /// How it ended.
    pub report: DeployReportBody,
}

/// A release that failed on this host and isn't retried automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedRelease {
    /// The release tag.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
}

/// How long verification of one work item has been unable to run. The time is
/// summed from the monotonic clock, one poll to the next, so a wall clock that
/// jumps doesn't move it, and time the agent was stopped doesn't count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationWait {
    /// The controller's id for the deploy.
    pub deploy_id: DeployId,
    /// How long so far.
    pub waited_millis: u64,
}
