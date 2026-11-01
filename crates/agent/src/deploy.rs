//! The deploy sequence and rollback (design 7.2): pull, back up, switch,
//! check, and on any failure put back the previous version and its data,
//! recording every step.

use std::fmt::Display;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use jiff::tz::TimeZone;
use landfall_core::config::{Backup, Deployment};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_origin::release::ReleaseOrigin;
use serde::Serialize;

use crate::checks::{CheckOptions, CheckReport, quote, run_checks};
use crate::compose::{self, Pin};
use crate::docker::{Docker, DockerError};
use crate::journal::{self, Priority};
use crate::safefs::{self, RelPath, Root, SafeFsError, SnapshotStats};
use crate::state::{
    DeployLock, Deployed, DeploymentState, InProgress, Phase, RecordedBackup, StateError,
};

/// Timing and retention of the engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EngineOptions {
    /// Timing of the post-deploy checks.
    pub checks: CheckOptions,
    /// How many backups to keep per deployment.
    pub backups_kept: usize,
    /// How long a backup, or a removal of old ones, may run.
    pub backup_deadline: Duration,
    /// How long a restore may run.
    pub restore_deadline: Duration,
    /// How long one small file operation may run: an override or a state file.
    pub file_deadline: Duration,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            checks: CheckOptions::default(),
            backups_kept: 3,
            backup_deadline: Duration::from_secs(3600),
            restore_deadline: Duration::from_secs(3600),
            file_deadline: Duration::from_secs(60),
        }
    }
}

/// A release to deploy. It can only be built from a verified origin; rule and
/// approval checks stay with the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployPlan {
    deployment: DeploymentId,
    tag: ReleaseTag,
    version: semver::Version,
    digest: ImageDigest,
    commit: CommitSha,
    image: String,
}

impl DeployPlan {
    /// The plan for release `tag` of `deployment`, pinned to the digest and
    /// commit that `origin` verified.
    #[must_use]
    pub fn from_verified(
        deployment: &Deployment,
        tag: &ReleaseTag,
        version: semver::Version,
        origin: &ReleaseOrigin,
    ) -> Self {
        let digest = origin.attestation.digest.clone();
        Self {
            deployment: deployment.id().clone(),
            tag: tag.clone(),
            version,
            image: compose::image_ref(deployment.repo().name(), &digest),
            digest,
            commit: origin.commit.clone(),
        }
    }

    /// A plan without an origin, for tests.
    ///
    /// # Panics
    ///
    /// When an argument is not a valid value.
    #[cfg(test)]
    pub(crate) fn for_test(deployment: &Deployment, tag: &str, digest: &str, commit: &str) -> Self {
        let digest: ImageDigest = digest.parse().expect("a valid test digest");
        Self {
            deployment: deployment.id().clone(),
            tag: tag.parse().expect("a valid test tag"),
            version: semver::Version::new(1, 2, 3),
            image: compose::image_ref(deployment.repo().name(), &digest),
            digest,
            commit: commit.parse().expect("a valid test commit"),
        }
    }

    /// The deployment this plan is for.
    #[must_use]
    pub fn deployment(&self) -> &DeploymentId {
        &self.deployment
    }

    /// The release tag.
    #[must_use]
    pub fn tag(&self) -> &ReleaseTag {
        &self.tag
    }

    /// The version the tag parses to.
    #[must_use]
    pub fn version(&self) -> &semver::Version {
        &self.version
    }

    /// The image index digest.
    #[must_use]
    pub fn digest(&self) -> &ImageDigest {
        &self.digest
    }

    /// The commit of the release.
    #[must_use]
    pub fn commit(&self) -> &CommitSha {
        &self.commit
    }

    /// The image reference, pinned by digest.
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }
}

/// How a deploy that started ended.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
const CLEAR_STEP: &str = "clear_in_progress";

/// One recorded step.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
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

/// A file operation of the engine that did not finish well.
#[derive(Debug, thiserror::Error)]
pub enum FileFailure {
    /// The agent's own state.
    #[error(transparent)]
    State(#[from] StateError),
    /// The compose directory or a backup.
    #[error(transparent)]
    SafeFs(#[from] SafeFsError),
    /// It ran past its deadline. It cannot be cancelled and may still be
    /// running, so its result is unknown; it is never taken for success.
    #[error("{op}: still running after {after:?}; its result is unknown")]
    Deadline {
        /// What was being done.
        op: &'static str,
        /// The deadline that applied.
        after: Duration,
    },
    /// Its thread panicked.
    #[error("{op}: the thread doing it panicked")]
    Panicked {
        /// What was being done.
        op: &'static str,
    },
    /// The state has no previous override, which a deploy saves first.
    #[error("the previous override was not saved")]
    NoPreviousOverride,
    /// The state has no earlier deployed record, which a deploy saves first.
    #[error("what was deployed before this deploy was not saved")]
    NoPreviousDeployed,
}

/// A deploy that never started: no service was touched and no backup taken.
/// Everything the attempt changed has been put back, other than a placeholder
/// override where there was none, unless the error is
/// [`DeployError::LeftBlocked`]. Anything after that is a [`DeployReport`].
#[derive(Debug, thiserror::Error)]
pub enum DeployError {
    /// Another process holds the deployment's lock.
    #[error("deployment {0} is busy: another agent process holds its lock")]
    Busy(DeploymentId),
    /// An earlier deploy did not finish.
    #[error(
        "deployment {deployment}: the deploy of {tag} did not finish; run `landfall-agent recover --deployment {deployment}`"
    )]
    Interrupted {
        /// The deployment.
        deployment: DeploymentId,
        /// The release of the unfinished deploy.
        tag: ReleaseTag,
    },
    /// `recover` found nothing unfinished.
    #[error("deployment {0} has no interrupted deploy to recover")]
    NothingToRecover(DeploymentId),
    /// The plan was made for another deployment.
    #[error("the plan is for deployment {plan}, not {deployment}")]
    PlanMismatch {
        /// The plan's deployment.
        plan: DeploymentId,
        /// The deployment asked for.
        deployment: DeploymentId,
    },
    /// A file operation failed.
    #[error("deployment {deployment}: {source}")]
    File {
        /// The deployment.
        deployment: DeploymentId,
        /// The failure.
        source: FileFailure,
    },
    /// A declared backup path is not usable.
    #[error("deployment {deployment}: backup path: {source}")]
    BackupPath {
        /// The deployment.
        deployment: DeploymentId,
        /// The failure.
        source: SafeFsError,
    },
    /// The compose project does not have the service.
    #[error("deployment {deployment}: the compose project has no service {service:?}")]
    NoSuchService {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
    },
    /// The service is built from source, which is refused.
    #[error(
        "deployment {deployment}: service {service:?} has a `build` section; landfall only deploys pinned images, so remove it from the compose file"
    )]
    HasBuild {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
    },
    /// The project asks for more than one container of the service.
    #[error(
        "deployment {deployment}: service {service:?} asks for {replicas} containers; landfall deploys a service with one, so remove `scale` and `deploy.replicas` from the compose file"
    )]
    Scaled {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
        /// How many it asks for.
        replicas: u64,
    },
    /// The service runs in more than one container right now.
    #[error(
        "deployment {deployment}: service {service:?} has more than one running container, so landfall cannot tell which to check; scale it down with `docker compose up -d --no-deps --scale {service}=1 {service}`, or remove a second project running from this directory with `docker compose -p <other> down`"
    )]
    SeveralContainers {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
    },
    /// With the new override in place, the project does not resolve to the
    /// pinned image. What it does resolve to is not named: compose config is
    /// interpolated and can hold a secret.
    #[error(
        "deployment {deployment}: with {override_file} written, service {service:?} does not resolve to {pinned}; set `COMPOSE_FILE=compose.yaml:compose.landfall.yaml` in the stack's `.env`",
        override_file = compose::OVERRIDE_FILE
    )]
    OverrideNotApplied {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
        /// The pinned reference.
        pinned: String,
    },
    /// `docker compose` failed while checking the project.
    #[error("deployment {deployment}: {source}")]
    Compose {
        /// The deployment.
        deployment: DeploymentId,
        /// The failure.
        source: DockerError,
    },
    /// The image could not be pulled.
    #[error("deployment {deployment}: pulling {image}: {source}")]
    Pull {
        /// The deployment.
        deployment: DeploymentId,
        /// The pinned reference.
        image: String,
        /// The failure.
        source: DockerError,
    },
    /// The deploy did not start, and what it had changed could not be put
    /// straight: its in-progress marker stays until `recover`.
    #[error(
        "{}{failed} failed for deployment {deployment}: {source}; deploys stay blocked: run `landfall-agent recover --deployment {deployment}`",
        .refused.as_ref().map_or_else(String::new, |refused| format!("{refused}; "))
    )]
    LeftBlocked {
        /// The deployment.
        deployment: DeploymentId,
        /// Why the deploy was not started, when it was refused before this.
        refused: Option<Box<DeployError>>,
        /// What could not be done.
        failed: &'static str,
        /// Why.
        source: FileFailure,
    },
}

/// Deploys `plan`: preflight, `in-progress.json`, a check of the project with
/// the new override, pull, the marker's move to [`Phase::Deploying`], stop if
/// the backup asks for it, backup, override, `up`, image check and post-deploy
/// checks. A failure from that stop on rolls back. The report is written before
/// this returns, on every outcome, and the outcome goes to the journal.
///
/// # Errors
///
/// [`DeployError`] when the deploy never started: the deployment is locked or
/// has an interrupted deploy, the preflight refused, the pull failed, or a state
/// file could not be written. No service was touched. The override and the marker are as they were, other
/// than a placeholder override where there was none, unless the error is
/// [`DeployError::LeftBlocked`], which keeps the marker and names `recover`.
pub async fn run<D: Docker>(
    docker: &D,
    state: &DeploymentState,
    deployment: &Deployment,
    compose_dir: &Path,
    plan: &DeployPlan,
    options: &EngineOptions,
) -> Result<DeployReport, DeployError> {
    let result = async {
        if plan.deployment() != deployment.id() {
            return Err(DeployError::PlanMismatch {
                plan: plan.deployment().clone(),
                deployment: deployment.id().clone(),
            });
        }
        let engine = Engine {
            docker,
            state,
            deployment,
            dir: compose_dir,
            options,
            lock: take_lock(state, deployment.id()).await?,
            file_outran_deadline: AtomicBool::new(false),
        };
        engine.deploy(plan).await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

/// Finishes an interrupted deploy, going by the [`Phase`] of its marker:
///
/// - [`Phase::Preflight`]: the service was never touched, so the previous
///   override is put back and the marker removed, and nothing else is done.
/// - [`Phase::Deploying`], with a `deployed.json` that names this very deploy:
///   it passed its checks and only the clearing is left, so it is reported as
///   deployed. Without that record, it is rolled back.
/// - [`Phase::RollingBack`]: rolled back again from the start, whatever
///   `deployed.json` says.
/// - [`Phase::Restored`]: the backup is back in full, and the previous version
///   may have been running on it since, as after a rollback whose checks failed.
///   Only the start, the image check and the checks run again: stopping the
///   service and restoring would discard what it wrote.
/// - [`Phase::RolledBack`]: the previous version is back and has been checked,
///   so only the marker is removed. The backup is not restored again: that
///   would discard what the previous version wrote since.
///
/// The report is written and the outcome journalled as for [`run`]. A rollback
/// that fails again leaves the deploy interrupted, so this can be retried.
///
/// # Errors
///
/// [`DeployError::NothingToRecover`] when there is no interrupted deploy,
/// [`DeployError::Busy`] while something holds the lock, which includes a
/// restore that outlived its deadline, and [`DeployError::File`].
pub async fn recover<D: Docker>(
    docker: &D,
    state: &DeploymentState,
    deployment: &Deployment,
    compose_dir: &Path,
    options: &EngineOptions,
) -> Result<DeployReport, DeployError> {
    let result = async {
        let engine = Engine {
            docker,
            state,
            deployment,
            dir: compose_dir,
            options,
            lock: take_lock(state, deployment.id()).await?,
            file_outran_deadline: AtomicBool::new(false),
        };
        engine.recover().await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

/// What the override file in a compose directory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideFile {
    /// There is none.
    Missing,
    /// The placeholder: nothing is pinned yet.
    Placeholder,
    /// It pins the service's image.
    Pinned,
    /// It is not one the agent wrote for this service.
    Unrecognised,
}

/// How a service's running image compares with its override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// What the override file is.
    pub override_file: OverrideFile,
    /// The running container's image, only if it is the one pinned, quoted and
    /// truncated. Any other image can come from interpolated configuration
    /// (`image: ${IMG}`) and hold a secret, so it is not repeated.
    pub running_image: Option<String>,
    /// Whether the running container runs the pinned image. `None` when the
    /// service has no running container.
    pub running_image_matches: Option<bool>,
    /// Whether a running container differs from the override (design 7.1): it
    /// runs another image than the one pinned, the file isn't the agent's to go
    /// by, or the file is gone while a deploy is on record. With nothing pinned
    /// and nothing on record there is nothing to differ from, and a service
    /// that isn't running has not drifted: stopping one is an operator's call,
    /// and a deploy in progress stops it too.
    pub drift: bool,
}

/// Why a service's drift could not be read.
#[derive(Debug, thiserror::Error)]
pub enum DriftError {
    /// The compose directory or the override can't be read.
    #[error("reading the override: {0}")]
    Override(#[from] SafeFsError),
    /// Reading the override did not finish.
    #[error("reading the override: {0}")]
    File(#[source] FileFailure),
    /// Docker could not say what is running.
    #[error(transparent)]
    Docker(#[from] DockerError),
}

/// How long reading the override may take.
const DRIFT_READ_LIMIT: Duration = Duration::from_secs(60);

/// Compares the running image of `service` with what the override in `dir`
/// pins; `recorded` says a deploy of it is on record. It goes by the file itself
/// and by the container's labels, without `docker compose`: what `.env` makes of the project is exactly what can have
/// strayed from the override, and a stack the agent's user cannot read can
/// still be reported on. A caller that also sees a deploy in progress knows
/// that a difference is expected then.
///
/// # Errors
///
/// [`DriftError`] when the override or the container cannot be read.
pub async fn drift<D: Docker>(
    docker: &D,
    dir: &Path,
    service: &str,
    recorded: bool,
) -> Result<Drift, DriftError> {
    let owned = dir.to_owned();
    let file = on_thread_within(DRIFT_READ_LIMIT, move || read_override_file(&owned))
        .await
        .map_err(|unfinished| {
            DriftError::File(unfinished.failure("read override", DRIFT_READ_LIMIT))
        })??;
    let pin = file
        .as_deref()
        .map(|file| compose::pinned_image(file, service));
    let override_file = match pin {
        None => OverrideFile::Missing,
        Some(Pin::Nothing) => OverrideFile::Placeholder,
        Some(Pin::Image(_)) => OverrideFile::Pinned,
        Some(Pin::Unrecognised) => OverrideFile::Unrecognised,
    };
    let Some(id) = docker.container_at(dir, service).await? else {
        return Ok(Drift {
            override_file,
            running_image: None,
            running_image_matches: None,
            drift: false,
        });
    };
    let running = docker.inspect(&id).await?.image;
    let matches = matches!(pin, Some(Pin::Image(pinned)) if pinned == running);
    let drift = match pin {
        None => recorded,
        Some(Pin::Nothing) => false,
        Some(Pin::Image(_)) => !matches,
        Some(Pin::Unrecognised) => true,
    };
    Ok(Drift {
        override_file,
        running_image: matches.then(|| quote(&running)),
        running_image_matches: Some(matches),
        drift,
    })
}

/// The largest override the agent reads. It writes far less; the file is in a
/// directory others can write to.
const OVERRIDE_CAP: usize = 1024 * 1024;

/// The bytes of the override in `dir`, if there is one.
fn read_override_file(dir: &Path) -> Result<Option<Vec<u8>>, SafeFsError> {
    let root = Root::open(dir)?;
    let name = RelPath::new(compose::OVERRIDE_FILE)?;
    safefs::read_file(&root, &name, OVERRIDE_CAP)
}
const OVERRIDE_MODE: u32 = 0o644;
const WRONG_PREVIOUS_IMAGE: &str =
    "the container does not run the image the compose project resolves to";

/// The override this plan runs with.
fn render(plan: &DeployPlan, service: &str) -> Vec<u8> {
    compose::render_override(
        service,
        plan.image(),
        plan.deployment(),
        plan.tag(),
        plan.commit(),
    )
    .into_bytes()
}

/// The running image is not named: if `up` left the old container running, it
/// comes from interpolated configuration and can hold a secret.
fn not_pinned(pinned: &str) -> String {
    format!("the running image isn't the pinned one, {pinned}")
}

/// How a completed rollback ended.
fn rolled_back(marker: &InProgress, reason: String) -> Outcome {
    if marker.previous_can_start {
        Outcome::RolledBack { reason }
    } else {
        Outcome::FailedNoPrevious { reason }
    }
}

fn journal_refusal(result: &Result<DeployReport, DeployError>, deployment: &DeploymentId) {
    #[derive(Serialize)]
    struct Refused<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        error: String,
    }
    if let Err(error) = result {
        journal::emit(
            Priority::Error,
            &Refused {
                event: "deploy_refused",
                deployment,
                error: error.to_string(),
            },
        );
    }
}

async fn take_lock(
    state: &DeploymentState,
    deployment: &DeploymentId,
) -> Result<Arc<DeployLock>, DeployError> {
    let state = state.clone();
    match tokio::task::spawn_blocking(move || state.lock()).await {
        Ok(Ok(lock)) => Ok(Arc::new(lock)),
        Ok(Err(StateError::Busy(id))) => Err(DeployError::Busy(id)),
        Ok(Err(error)) => Err(DeployError::File {
            deployment: deployment.clone(),
            source: error.into(),
        }),
        Err(_) => Err(DeployError::File {
            deployment: deployment.clone(),
            source: FileFailure::Panicked { op: "take lock" },
        }),
    }
}

/// Why blocking work given to [`on_thread_within`] has no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unfinished {
    /// The thread doing it panicked.
    Panicked,
    /// It ran past its deadline and may still be running.
    Deadline,
}

impl Unfinished {
    fn failure(self, op: &'static str, after: Duration) -> FileFailure {
        match self {
            Self::Panicked => FileFailure::Panicked { op },
            Self::Deadline => FileFailure::Deadline { op, after },
        }
    }
}

/// Runs blocking work on a thread, waiting for it up to `deadline`. A thread
/// cannot be cancelled, so past the deadline the work may still be running.
pub(crate) async fn on_thread_within<T: Send + 'static>(
    deadline: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unfinished> {
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(work)).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(Unfinished::Panicked),
        Err(_) => Err(Unfinished::Deadline),
    }
}

/// Runs blocking file work on a thread of its own, up to `deadline`. Work past
/// the deadline is reported as a failure, and the thread keeps its share of the
/// deployment's lock until it ends, so no other process starts on the same
/// files in the meantime.
async fn off_thread<T, E>(
    lock: &Arc<DeployLock>,
    op: &'static str,
    deadline: Duration,
    work: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, FileFailure>
where
    T: Send + 'static,
    E: Into<FileFailure> + Send + 'static,
{
    #[cfg(test)]
    let (work, deadline) = faults::inject(op, deadline, work);
    let held = Arc::clone(lock);
    on_thread_within(deadline, move || {
        let _held = held;
        work()
    })
    .await
    .map_err(|unfinished| unfinished.failure(op, deadline))?
    .map_err(Into::into)
}

/// `time` as a plain name that sorts by time: fixed width, UTC. Backups are
/// pruned by this order. A year past 9999 would not sort; no clock is there.
fn timestamp_id(time: Timestamp) -> String {
    let utc = time.to_zoned(TimeZone::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}-{:02}-{:02}-{:09}Z",
        utc.year(),
        utc.month(),
        utc.day(),
        utc.hour(),
        utc.minute(),
        utc.second(),
        utc.subsec_nanosecond()
    )
}

fn millis(elapsed: Duration) -> u64 {
    u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX)
}

fn rel_paths(paths: &[String]) -> Result<Vec<RelPath>, SafeFsError> {
    paths.iter().map(|p| RelPath::new(p)).collect()
}

/// The steps of one deploy or recovery, each also sent to the journal.
struct Recorder {
    deployment: DeploymentId,
    tag: ReleaseTag,
    digest: ImageDigest,
    started_at: Timestamp,
    steps: Vec<Step>,
}

impl Recorder {
    fn new(deployment: &DeploymentId, tag: &ReleaseTag, digest: &ImageDigest) -> Self {
        Self {
            deployment: deployment.clone(),
            tag: tag.clone(),
            digest: digest.clone(),
            started_at: Timestamp::now(),
            steps: Vec::new(),
        }
    }

    /// Runs and records one step.
    async fn step<T, E: Display>(
        &mut self,
        name: &'static str,
        work: impl Future<Output = Result<T, E>>,
    ) -> Result<T, E> {
        self.step_detailed(name, async { (work.await, None) }).await
    }

    /// [`Self::step`] for work that also has details to record.
    async fn step_detailed<T, E: Display>(
        &mut self,
        name: &'static str,
        work: impl Future<Output = (Result<T, E>, Option<StepDetail>)>,
    ) -> Result<T, E> {
        #[derive(Serialize)]
        struct StepEvent<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            tag: &'a ReleaseTag,
            step: &'a Step,
        }
        let started_at = Timestamp::now();
        let clock = Instant::now();
        let (outcome, detail) = work.await;
        let step = Step {
            name: name.to_owned(),
            started_at,
            millis: millis(clock.elapsed()),
            result: match &outcome {
                Ok(_) => StepResult::Ok,
                Err(error) => StepResult::Failed {
                    reason: error.to_string(),
                },
            },
            detail,
        };
        let priority = if outcome.is_ok() {
            Priority::Info
        } else {
            Priority::Error
        };
        journal::emit(
            priority,
            &StepEvent {
                event: "deploy_step",
                deployment: &self.deployment,
                tag: &self.tag,
                step: &step,
            },
        );
        self.steps.push(step);
        outcome
    }

    /// [`Self::step`] for a step whose failure ends the sequence: the reason
    /// names it.
    async fn must<T, E: Display>(
        &mut self,
        name: &'static str,
        work: impl Future<Output = Result<T, E>>,
    ) -> Result<T, String> {
        self.must_detailed(name, async { (work.await, None) }).await
    }

    /// [`Self::must`] for work that also has details to record.
    async fn must_detailed<T, E: Display>(
        &mut self,
        name: &'static str,
        work: impl Future<Output = (Result<T, E>, Option<StepDetail>)>,
    ) -> Result<T, String> {
        self.step_detailed(name, work)
            .await
            .map_err(|error| format!("{name}: {error}"))
    }
}

/// What the preflight found out.
struct Preflight {
    /// The override in place, to put back on a rollback.
    previous: Vec<u8>,
    /// Whether the project has an image to start without the new override.
    previous_can_start: bool,
}

struct Engine<'a, D> {
    docker: &'a D,
    state: &'a DeploymentState,
    deployment: &'a Deployment,
    dir: &'a Path,
    options: &'a EngineOptions,
    lock: Arc<DeployLock>,
    /// Small file work ran past its deadline and may yet land. See
    /// [`Self::rollback`].
    file_outran_deadline: AtomicBool,
}

impl<D: Docker> Engine<'_, D> {
    fn service(&self) -> &str {
        self.deployment.compose().service()
    }

    fn file_error(&self, source: impl Into<FileFailure>) -> DeployError {
        DeployError::File {
            deployment: self.deployment.id().clone(),
            source: source.into(),
        }
    }

    /// Small file work, under the short deadline.
    async fn file<T, E>(
        &self,
        op: &'static str,
        work: impl FnOnce() -> Result<T, E> + Send + 'static,
    ) -> Result<T, FileFailure>
    where
        T: Send + 'static,
        E: Into<FileFailure> + Send + 'static,
    {
        let result = off_thread(&self.lock, op, self.options.file_deadline, work).await;
        if matches!(result, Err(FileFailure::Deadline { .. })) {
            self.file_outran_deadline.store(true, Ordering::SeqCst);
        }
        result
    }

    async fn read_override(&self) -> Result<Option<Vec<u8>>, FileFailure> {
        let dir = self.dir.to_owned();
        self.file("read override", move || read_override_file(&dir))
            .await
    }

    async fn write_override(&self, bytes: Vec<u8>) -> Result<(), FileFailure> {
        let dir = self.dir.to_owned();
        self.file("write override", move || {
            let root = Root::open(&dir)?;
            let name = RelPath::new(compose::OVERRIDE_FILE)?;
            safefs::write_atomic(&root, &name, &bytes, OVERRIDE_MODE)
        })
        .await
    }

    fn compose_error(&self, source: DockerError) -> DeployError {
        match source {
            DockerError::NoSuchService { service } => DeployError::NoSuchService {
                deployment: self.deployment.id().clone(),
                service,
            },
            DockerError::SeveralContainers { .. } => DeployError::SeveralContainers {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
            },
            source => DeployError::Compose {
                deployment: self.deployment.id().clone(),
                source,
            },
        }
    }

    /// What can be refused before the marker goes in: the backup's paths, and
    /// the project as it is. The only change is a placeholder override where
    /// there was none. This reads the project leniently, since a first deploy
    /// may start from a service without an image.
    async fn preflight(&self) -> Result<Preflight, DeployError> {
        if let Some(backup) = self.deployment.backup() {
            rel_paths(backup.paths()).map_err(|source| DeployError::BackupPath {
                deployment: self.deployment.id().clone(),
                source,
            })?;
        }
        let current = self.read_override().await.map_err(|e| self.file_error(e))?;
        let previous = if let Some(bytes) = current {
            bytes
        } else {
            let placeholder = compose::PLACEHOLDER.as_bytes().to_vec();
            self.write_override(placeholder.clone())
                .await
                .map_err(|e| self.file_error(e))?;
            placeholder
        };
        let base = self
            .docker
            .compose_service(self.dir, self.service())
            .await
            .map_err(|e| self.compose_error(e))?;
        if base.has_build {
            return Err(DeployError::HasBuild {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
            });
        }
        if base.replicas > 1 {
            return Err(DeployError::Scaled {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
                replicas: base.replicas,
            });
        }
        // Every step after this one needs to tell the service's one container,
        // which the project's name does. A second project running from this
        // directory has a container of its own and would be left out of that,
        // while it shares the directory's data with a backup and a restore.
        self.docker
            .container(self.dir, self.service())
            .await
            .map_err(|e| self.compose_error(e))?;
        self.docker
            .container_at(self.dir, self.service())
            .await
            .map_err(|e| self.compose_error(e))?;
        Ok(Preflight {
            previous,
            previous_can_start: base.image.is_some(),
        })
    }

    /// What a rollback goes back to, then the marker, which promises it. No
    /// marker was there when this runs and the new override has not been
    /// written, so `previous` cannot be the override of an unfinished deploy.
    /// The marker can be on disk even if the write reports a failure.
    async fn record_in_progress(
        &self,
        marker: &InProgress,
        previous: Vec<u8>,
    ) -> Result<(), DeployError> {
        let state = self.state.clone();
        let marker = marker.clone();
        let written = self
            .file("record in-progress", move || {
                state.set_previous_deployed(state.deployed()?.as_ref())?;
                state.set_previous_override(&previous)?;
                state.set_in_progress(&marker)
            })
            .await;
        self.settle_marker_write(written, "recording the deploy's start")
            .await
    }

    /// With the marker written: reads the project with the new override in
    /// place, held to everything `up` will require, then takes the override
    /// back out, as nothing else may see it before the backup. A refusal
    /// clears the marker; an override that cannot be put back keeps it.
    async fn verify_override(
        &self,
        plan: &DeployPlan,
        previous: Vec<u8>,
    ) -> Result<(), DeployError> {
        let checked = match self.write_override(render(plan, self.service())).await {
            // It may yet land, after anything done here to put it back.
            Err(source @ FileFailure::Deadline { .. }) => {
                return Err(self.left_blocked(None, "writing the new override", source));
            }
            // It may have landed: the rename comes before the last `fsync`.
            Err(source) => Err(self.file_error(source)),
            Ok(()) => {
                match self
                    .docker
                    .compose_service_checked(self.dir, self.service())
                    .await
                {
                    Ok(service) if service.image.as_deref() == Some(plan.image()) => Ok(()),
                    // What it did resolve to stays out of this: it can hold a secret.
                    Ok(_) => Err(DeployError::OverrideNotApplied {
                        deployment: self.deployment.id().clone(),
                        service: self.service().to_owned(),
                        pinned: plan.image().to_owned(),
                    }),
                    Err(error) => Err(self.compose_error(error)),
                }
            }
        };
        if let Err(source) = self.write_override(previous).await {
            return Err(self.left_blocked(
                checked.err(),
                "putting the previous override back",
                source,
            ));
        }
        match checked {
            Ok(()) => Ok(()),
            Err(refused) => Err(self.abandon(refused).await),
        }
    }

    fn left_blocked(
        &self,
        refused: Option<DeployError>,
        failed: &'static str,
        source: FileFailure,
    ) -> DeployError {
        DeployError::LeftBlocked {
            deployment: self.deployment.id().clone(),
            refused: refused.map(Box::new),
            failed,
            source,
        }
    }

    /// The checks and the pull are over and nothing was touched yet. The next
    /// step may touch the service, so from here on `recover` has to assume it
    /// did.
    async fn start_deploying(&self, marker: &InProgress) -> Result<(), DeployError> {
        let state = self.state.clone();
        let next = InProgress {
            phase: Phase::Deploying,
            ..marker.clone()
        };
        let written = self
            .file("mark deploying", move || state.set_in_progress(&next))
            .await;
        self.settle_marker_write(written, "recording that the deploy goes ahead")
            .await
    }

    /// A marker write before anything was touched: one that failed leaves at
    /// most the marker, which is cleared, and one past its deadline may yet
    /// land after a clear, so that keeps deploys blocked.
    async fn settle_marker_write(
        &self,
        written: Result<(), FileFailure>,
        failed: &'static str,
    ) -> Result<(), DeployError> {
        match written {
            Ok(()) => Ok(()),
            Err(source @ FileFailure::Deadline { .. }) => {
                Err(self.left_blocked(None, failed, source))
            }
            Err(source) => Err(self.abandon(self.file_error(source)).await),
        }
    }

    /// Nothing is left of a deploy that was refused but its marker.
    async fn abandon(&self, refused: DeployError) -> DeployError {
        let state = self.state.clone();
        let cleared = self
            .file("clear in-progress", move || state.clear_in_progress())
            .await;
        match cleared {
            Ok(()) => refused,
            Err(source) => {
                self.left_blocked(Some(refused), "clearing the in-progress marker", source)
            }
        }
    }

    async fn deploy(&self, plan: &DeployPlan) -> Result<DeployReport, DeployError> {
        let state = self.state.clone();
        let unfinished = self
            .file("read in-progress", move || state.in_progress())
            .await
            .map_err(|e| self.file_error(e))?;
        if let Some(unfinished) = unfinished {
            return Err(DeployError::Interrupted {
                deployment: self.deployment.id().clone(),
                tag: unfinished.tag,
            });
        }
        let mut rec = Recorder::new(self.deployment.id(), plan.tag(), plan.digest());
        let preflight = rec.step("preflight", self.preflight()).await?;
        let started_at = Timestamp::now();
        let mut marker = InProgress {
            deploy_id: timestamp_id(started_at),
            phase: Phase::Preflight,
            tag: plan.tag().clone(),
            digest: plan.digest().clone(),
            previous_can_start: preflight.previous_can_start,
            backup: None,
            started_at,
        };
        rec.step(
            "record_in_progress",
            self.record_in_progress(&marker, preflight.previous.clone()),
        )
        .await?;
        rec.step(
            "verify_override",
            self.verify_override(plan, preflight.previous),
        )
        .await?;
        let pulled = rec
            .step("pull", async {
                self.docker
                    .pull(plan.image())
                    .await
                    .map_err(|source| DeployError::Pull {
                        deployment: self.deployment.id().clone(),
                        image: plan.image().to_owned(),
                        source,
                    })
            })
            .await;
        if let Err(refused) = pulled {
            return Err(self.abandon(refused).await);
        }
        rec.step("mark_deploying", self.start_deploying(&marker))
            .await?;
        marker.phase = Phase::Deploying;

        // From here on, the report tells how it went.
        let outcome = match self.forward(plan, &mut rec, &mut marker).await {
            Ok(()) => {
                // The release is in and recorded: a failure to remove old
                // backups is in the report, and doesn't undo the deploy.
                self.prune_kept(&mut rec).await;
                Outcome::Deployed
            }
            Err(reason) => self.rollback_outcome(&mut rec, &marker, reason).await,
        };
        Ok(self.finish(rec, outcome).await)
    }

    async fn recover(&self) -> Result<DeployReport, DeployError> {
        let state = self.state.clone();
        let unfinished = self
            .file("read in-progress", move || state.in_progress())
            .await
            .map_err(|e| self.file_error(e))?;
        let Some(marker) = unfinished else {
            return Err(DeployError::NothingToRecover(self.deployment.id().clone()));
        };
        let mut rec = Recorder::new(self.deployment.id(), &marker.tag, &marker.digest);
        let finished = match marker.phase {
            Phase::Deploying => {
                let state = self.state.clone();
                let deployed = self
                    .file("read deployed", move || state.deployed())
                    .await
                    .map_err(|e| self.file_error(e))?;
                // The sequence writes this record once the checks have passed.
                deployed.is_some_and(|d| d.deploy_id == marker.deploy_id)
            }
            Phase::Preflight | Phase::RollingBack | Phase::Restored | Phase::RolledBack => false,
        };
        let outcome = if finished {
            self.prune_kept(&mut rec).await;
            Outcome::Deployed
        } else if marker.phase == Phase::Preflight {
            self.undo_preflight(&mut rec, &marker).await
        } else if marker.phase == Phase::RolledBack {
            self.clear_and_prune(&mut rec).await;
            rolled_back(
                &marker,
                format!(
                    "the deploy of {} had been rolled back; recover removed its marker",
                    marker.tag
                ),
            )
        } else {
            let reason = format!(
                "the deploy of {} was interrupted; rolled back by recover",
                marker.tag
            );
            self.rollback_outcome(&mut rec, &marker, reason).await
        };
        Ok(self.finish(rec, outcome).await)
    }

    /// Backup to checks. `marker.backup` names the backup only once it is
    /// complete and recorded, which is what a rollback goes by. A backup that
    /// fails is therefore never restored, and neither is one that could not
    /// be recorded: the new version has not run yet, so the data is as it was.
    async fn forward(
        &self,
        plan: &DeployPlan,
        rec: &mut Recorder,
        marker: &mut InProgress,
    ) -> Result<(), String> {
        if let Some(backup) = self.deployment.backup() {
            // Room for the copy about to be made, so a full disk is less
            // likely to fail it, while the service still runs. Failing here
            // stops nothing: the backup then finds out if there is room.
            let room = self.options.backups_kept.saturating_sub(1);
            let _ = rec
                .step(
                    "prune_before_backup",
                    self.prune("prune before backup", room),
                )
                .await;
            if backup.stop() {
                rec.must("stop", self.stop()).await?;
            }
            let id = timestamp_id(Timestamp::now());
            rec.must_detailed("backup", async {
                let copied = self.backup(backup, &id).await;
                let detail = copied
                    .as_ref()
                    .ok()
                    .map(|stats| StepDetail::Backup { stats: *stats });
                (copied, detail)
            })
            .await?;
            let mut with_backup = marker.clone();
            with_backup.backup = Some(RecordedBackup {
                id,
                paths: backup.paths().to_vec(),
            });
            let state = self.state.clone();
            let record = with_backup.clone();
            rec.must(
                "record_backup",
                self.file("record backup", move || state.set_in_progress(&record)),
            )
            .await?;
            *marker = with_backup;
        }
        rec.must(
            "write_override",
            self.write_override(render(plan, self.service())),
        )
        .await?;
        let since = Timestamp::now();
        rec.must("up", self.up()).await?;
        rec.must("verify_image", self.verify_pinned(plan.image()))
            .await?;
        rec.must_detailed("checks", self.check_pinned(plan.image(), since))
            .await?;
        let state = self.state.clone();
        let deployed = Deployed {
            deploy_id: marker.deploy_id.clone(),
            tag: plan.tag().clone(),
            version: plan.version().clone(),
            digest: plan.digest().clone(),
            commit: plan.commit().clone(),
            deployed_at: Timestamp::now(),
        };
        rec.must(
            "record_deployed",
            self.file("record deployed", move || state.set_deployed(&deployed)),
        )
        .await
    }

    async fn stop(&self) -> Result<(), DockerError> {
        self.docker.compose_stop(self.dir, self.service()).await
    }

    async fn up(&self) -> Result<(), DockerError> {
        self.docker.compose_up(self.dir, self.service()).await
    }

    /// Runs the checks, from `since`, the time just before the service was
    /// brought up. Returns the image the final round saw, and what each check
    /// took, either way.
    async fn checks(&self, since: Timestamp) -> (Result<String, String>, Option<StepDetail>) {
        let detail = |reports: &[CheckReport]| {
            Some(StepDetail::Checks {
                checks: reports.iter().map(CheckTiming::from).collect(),
            })
        };
        match run_checks(
            self.docker,
            self.dir,
            self.service(),
            self.deployment.checks(),
            since,
            &self.options.checks,
        )
        .await
        {
            Ok(summary) => (Ok(summary.image), detail(&summary.checks)),
            Err(failure) => {
                let detail = detail(&failure.checks);
                (Err(failure.to_string()), detail)
            }
        }
    }

    /// The checks, and the pinned image still running when they ended.
    async fn check_pinned(
        &self,
        pinned: &str,
        since: Timestamp,
    ) -> (Result<(), String>, Option<StepDetail>) {
        let (image, detail) = self.checks(since).await;
        let checked = image.and_then(|image| {
            if image == pinned {
                Ok(())
            } else {
                Err(not_pinned(pinned))
            }
        });
        (checked, detail)
    }

    /// The checks, and the previous image still running when they ended. As
    /// in [`Self::verify_previous`], neither image is named.
    async fn check_previous(
        &self,
        resolved: &str,
        since: Timestamp,
    ) -> (Result<(), String>, Option<StepDetail>) {
        let (image, detail) = self.checks(since).await;
        let checked = image.and_then(|image| {
            if image == resolved {
                Ok(())
            } else {
                Err(WRONG_PREVIOUS_IMAGE.to_owned())
            }
        });
        (checked, detail)
    }

    /// A snapshot failure of any kind is a failed backup. That includes a
    /// missing path: a container that keeps running could otherwise make a
    /// backup incomplete by deleting a file.
    async fn backup(&self, backup: &Backup, id: &str) -> Result<SnapshotStats, FileFailure> {
        let paths = rel_paths(backup.paths())?;
        let dir = self.dir.to_owned();
        let backups = self.state.backups_dir();
        let dest = backups.join(id);
        off_thread(
            &self.lock,
            "backup",
            self.options.backup_deadline,
            move || {
                match DirBuilder::new().mode(0o700).create(&backups) {
                    Ok(()) => {}
                    Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                    Err(source) => {
                        return Err(FileFailure::State(StateError::Io {
                            op: "create",
                            path: backups,
                            source,
                        }));
                    }
                }
                let source = Root::open(&dir)?;
                Ok(safefs::snapshot(&source, &paths, &dest)?)
            },
        )
        .await
    }

    /// Removes all but the newest `keep` backups, and never the one a marker
    /// on disk names: that is what a rollback or `recover` would restore.
    async fn prune(&self, op: &'static str, keep: usize) -> Result<(), FileFailure> {
        let backups = self.state.backups_dir();
        let state = self.state.clone();
        off_thread(&self.lock, op, self.options.backup_deadline, move || {
            let marker = state.in_progress()?;
            let named = marker.as_ref().and_then(|m| m.backup.as_ref());
            safefs::prune(&backups, keep, named.map(|backup| backup.id.as_str()))?;
            Ok::<(), FileFailure>(())
        })
        .await
    }

    /// Brings the backups down to the number kept. A failure is in the report
    /// and changes no outcome.
    async fn prune_kept(&self, rec: &mut Recorder) {
        let keep = self.options.backups_kept;
        let _ = rec
            .step("prune_backups", self.prune("prune backups", keep))
            .await;
    }

    /// The rollback is over: removes the marker and then, with nothing left
    /// that may need them, the backups beyond the number kept. Failed deploys
    /// take backups too.
    async fn clear_and_prune(&self, rec: &mut Recorder) {
        if self.clear_in_progress(rec).await {
            self.prune_kept(rec).await;
        }
    }

    /// The image of the service's container, as it says.
    async fn running_image(&self) -> Result<String, String> {
        let id = self
            .docker
            .container(self.dir, self.service())
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("service {} has no running container", quote(self.service())))?;
        let info = self.docker.inspect(&id).await.map_err(|e| e.to_string())?;
        Ok(info.image)
    }

    async fn verify_pinned(&self, pinned: &str) -> Result<(), String> {
        let running = self.running_image().await?;
        if running == pinned {
            Ok(())
        } else {
            Err(not_pinned(pinned))
        }
    }

    /// With the previous override back, the container must run what the
    /// project resolves to, which is returned. Neither is named in the error:
    /// this image comes from interpolated configuration and can hold a secret.
    async fn verify_previous(&self) -> Result<String, String> {
        let resolved = self
            .docker
            .compose_service(self.dir, self.service())
            .await
            .map_err(|e| e.to_string())?;
        let running = self.running_image().await?;
        if resolved.image.as_deref() == Some(running.as_str()) {
            Ok(running)
        } else {
            Err(WRONG_PREVIOUS_IMAGE.to_owned())
        }
    }

    /// Rolls back, clears the marker unless that failed, and says how it ended.
    async fn rollback_outcome(
        &self,
        rec: &mut Recorder,
        marker: &InProgress,
        reason: String,
    ) -> Outcome {
        match self.rollback(rec, marker).await {
            Ok(()) => {
                self.clear_and_prune(rec).await;
                rolled_back(marker, reason)
            }
            // The marker stays: deploys stay blocked, and `recover` can try
            // again from the same previous state and backup.
            Err(rollback_reason) => Outcome::RollbackFailed {
                reason,
                rollback_reason,
            },
        }
    }

    /// A deploy interrupted in its preflight: only the override can be out of
    /// place. The service was never touched, so it is left alone.
    async fn undo_preflight(&self, rec: &mut Recorder, marker: &InProgress) -> Outcome {
        let reason = format!(
            "the deploy of {} was interrupted before it touched the service; recover put the previous override back",
            marker.tag
        );
        match self.restore_previous_override(rec).await {
            Ok(()) => {
                let _ = self.clear_in_progress(rec).await;
                Outcome::NothingChanged { reason }
            }
            // The marker stays, and `recover` can try again.
            Err(rollback_reason) => Outcome::RollbackFailed {
                reason,
                rollback_reason,
            },
        }
    }

    async fn restore_previous_override(&self, rec: &mut Recorder) -> Result<(), String> {
        let state = self.state.clone();
        let previous = rec
            .must("read_previous_override", async {
                self.file("read previous override", move || state.previous_override())
                    .await?
                    .ok_or(FileFailure::NoPreviousOverride)
            })
            .await?;
        rec.must("restore_override", self.write_override(previous))
            .await
    }

    /// Writes the marker with `phase`.
    async fn mark(
        &self,
        rec: &mut Recorder,
        (step, op): (&'static str, &'static str),
        marker: &InProgress,
        phase: Phase,
    ) -> Result<(), String> {
        let state = self.state.clone();
        let next = InProgress {
            phase,
            ..marker.clone()
        };
        rec.must(step, self.file(op, move || state.set_in_progress(&next)))
            .await
    }

    /// Back to the previous state. Each step depends on the one before: with
    /// the service still running a restore could be outrun, and half-restored
    /// data is not to be started, so the first failure ends it.
    ///
    /// The marker says `RollingBack` before anything is undone: until then the
    /// release is as it was, so a record of it is still true. Small file work
    /// that outran its deadline may yet land on top of what this puts back. It
    /// keeps a share of the lock until it ends, so that is what `recover` waits
    /// for, and this stops rather than leave the wrong override or record
    /// behind what looks like a clean rollback.
    ///
    /// From [`Phase::Restored`] everything up to the start is done and only the
    /// rest runs. The marker takes that phase as soon as the restore has
    /// returned: from then on the previous version's data is what counts, and
    /// a failure further on can leave it running and writing for a long time.
    async fn rollback(&self, rec: &mut Recorder, marker: &InProgress) -> Result<(), String> {
        let restored = marker.phase == Phase::Restored;
        if !restored && marker.phase != Phase::RollingBack {
            self.mark(
                rec,
                ("mark_rolling_back", "mark rolling back"),
                marker,
                Phase::RollingBack,
            )
            .await?;
        }
        if self.file_outran_deadline.load(Ordering::SeqCst) {
            return Err(
                "a file write ran past its deadline and may still land; run recover once it has ended"
                    .to_owned(),
            );
        }
        let mut stopped = restored;
        if !restored {
            self.restore_previous_override(rec).await?;
            rec.must("restore_deployed", self.restore_deployed())
                .await?;
            if let Some(backup) = &marker.backup {
                rec.must("stop_for_restore", self.stop()).await?;
                stopped = true;
                rec.must("restore_backup", self.restore(backup)).await?;
                self.mark(
                    rec,
                    ("mark_restored", "mark restored"),
                    marker,
                    Phase::Restored,
                )
                .await?;
            }
        }
        if marker.previous_can_start {
            let since = Timestamp::now();
            rec.must("start_previous", self.up()).await?;
            let resolved = rec
                .must("verify_previous_image", self.verify_previous())
                .await?;
            rec.must_detailed("check_previous", self.check_previous(&resolved, since))
                .await?;
        } else if !stopped {
            rec.must("stop_service", self.stop()).await?;
        }
        self.mark(
            rec,
            ("mark_rolled_back", "mark rolled back"),
            marker,
            Phase::RolledBack,
        )
        .await
    }

    /// `deployed.json` as it was when the deploy started. A failed write of
    /// this release's record can have landed all the same.
    async fn restore_deployed(&self) -> Result<(), FileFailure> {
        let state = self.state.clone();
        self.file("restore deployed", move || {
            match state
                .previous_deployed()?
                .ok_or(FileFailure::NoPreviousDeployed)?
            {
                Some(deployed) => state.set_deployed(&deployed)?,
                None => state.clear_deployed()?,
            }
            Ok::<(), FileFailure>(())
        })
        .await
    }

    /// Restores the paths the backup was taken of: the configuration can have
    /// changed before a `recover`.
    async fn restore(&self, backup: &RecordedBackup) -> Result<(), FileFailure> {
        let paths = rel_paths(&backup.paths)?;
        let dir = self.dir.to_owned();
        let snapshot = self.state.backups_dir().join(&backup.id);
        off_thread(
            &self.lock,
            "restore backup",
            self.options.restore_deadline,
            move || {
                let target = Root::open(&dir)?;
                safefs::restore(&snapshot, &target, &paths)
            },
        )
        .await
    }

    /// A marker that could not be removed is in the report and keeps deploys
    /// blocked; what is running is still what the outcome says. Returns whether
    /// it is gone.
    async fn clear_in_progress(&self, rec: &mut Recorder) -> bool {
        let state = self.state.clone();
        rec.step(
            CLEAR_STEP,
            self.file("clear in-progress", move || state.clear_in_progress()),
        )
        .await
        .is_ok()
    }

    /// Clears the marker of a deploy that went through, writes the report and
    /// tells the journal.
    async fn finish(&self, mut rec: Recorder, outcome: Outcome) -> DeployReport {
        #[derive(Serialize)]
        struct Finished<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            tag: &'a ReleaseTag,
            digest: &'a ImageDigest,
            outcome: &'a Outcome,
        }
        #[derive(Serialize)]
        struct ReportNotWritten<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            error: String,
        }
        if outcome == Outcome::Deployed {
            let _ = self.clear_in_progress(&mut rec).await;
        }
        let report = DeployReport {
            deployment: rec.deployment,
            tag: rec.tag,
            digest: rec.digest,
            outcome,
            steps: rec.steps,
            started_at: rec.started_at,
            finished_at: Timestamp::now(),
        };
        let state = self.state.clone();
        let id = timestamp_id(report.started_at);
        let copy = report.clone();
        let written = self
            .file("write report", move || state.write_report(&id, &copy))
            .await;
        if let Err(error) = written {
            journal::emit(
                Priority::Error,
                &ReportNotWritten {
                    event: "deploy_report_not_written",
                    deployment: &report.deployment,
                    error: error.to_string(),
                },
            );
        }
        journal::emit(
            report.outcome.priority(),
            &Finished {
                event: "deploy_finished",
                deployment: &report.deployment,
                tag: &report.tag,
                digest: &report.digest,
                outcome: &report.outcome,
            },
        );
        report
    }
}

/// Test support: file work of the engine that fails on request. A thread that
/// dies part-way cannot be arranged any other way, and permissions don't stop
/// the root user the Linux run has.
#[cfg(test)]
mod faults {
    use std::collections::{HashMap, VecDeque};
    use std::io;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::sync::mpsc::Receiver;
    use std::time::Duration;

    use super::{FileFailure, StateError};

    /// What one run of a file operation does.
    pub(super) enum Fault {
        /// It works.
        Pass,
        /// It fails without doing anything.
        Fail,
        /// It does its work and reports a failure, as `write_atomic` does when
        /// the rename worked and the `fsync` after it did not.
        FailAfter,
        /// It is past its deadline at once, and does its work when released.
        Late(Receiver<()>),
    }

    type Plan = Mutex<HashMap<&'static str, VecDeque<Fault>>>;

    tokio::task_local! {
        static PLAN: Plan;
    }

    /// Runs `work` with these faults. Each list is for the runs of the named
    /// operation in order; runs past its end work.
    pub(super) async fn with_faults<T>(
        plan: impl IntoIterator<Item = (&'static str, Vec<Fault>)>,
        work: impl Future<Output = T>,
    ) -> T {
        let plan = plan
            .into_iter()
            .map(|(op, faults)| (op, VecDeque::from(faults)))
            .collect();
        PLAN.scope(Mutex::new(plan), work).await
    }

    /// The error of file work under [`inject`].
    pub(super) enum Injected<E> {
        /// The work's own.
        Real(E),
        /// The fault's.
        Fault,
    }

    impl<E: Into<FileFailure>> From<Injected<E>> for FileFailure {
        fn from(error: Injected<E>) -> Self {
            match error {
                Injected::Real(error) => error.into(),
                Injected::Fault => FileFailure::State(StateError::Io {
                    op: "inject",
                    path: PathBuf::from("injected"),
                    source: io::Error::other("injected fault"),
                }),
            }
        }
    }

    /// `work` with the next fault of `op`, and the deadline that goes with it.
    pub(super) fn inject<T, E>(
        op: &'static str,
        deadline: Duration,
        work: impl FnOnce() -> Result<T, E> + Send + 'static,
    ) -> (
        impl FnOnce() -> Result<T, Injected<E>> + Send + 'static,
        Duration,
    )
    where
        E: Into<FileFailure> + Send + 'static,
    {
        let fault = PLAN
            .try_with(|plan| {
                plan.lock()
                    .unwrap()
                    .get_mut(op)
                    .and_then(VecDeque::pop_front)
            })
            .ok()
            .flatten()
            .unwrap_or(Fault::Pass);
        let deadline = if matches!(fault, Fault::Late(_)) {
            Duration::ZERO
        } else {
            deadline
        };
        let work = move || match fault {
            Fault::Pass => work().map_err(Injected::Real),
            Fault::Fail => Err(Injected::Fault),
            Fault::FailAfter => work()
                .map_err(Injected::Real)
                .and_then(|_| Err(Injected::Fault)),
            Fault::Late(release) => {
                let _ = release.recv();
                work().map_err(Injected::Real)
            }
        };
        (work, deadline)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;
    use std::sync::{Arc, Mutex};

    use jiff::Timestamp;
    use landfall_core::config::{Deployment, parse};
    use landfall_origin::attestation::VerifiedAttestation;
    use serde_json::Value;

    use super::faults::{Fault, with_faults};
    use super::{
        DeployError, DeployPlan, DriftError, EngineOptions, Outcome, OverrideFile, ReleaseOrigin,
        StepDetail, StepResult, drift, recover, run, timestamp_id,
    };
    use crate::checks::CheckOptions;
    use crate::compose::{self, OVERRIDE_FILE, PLACEHOLDER};
    use crate::docker::{ContainerInfo, ServiceConfig};
    use crate::journal::Priority;
    use crate::safefs::{self, RelPath, Root};
    use crate::state::{Deployed, DeploymentState, InProgress, Phase, RecordedBackup, StateDir};
    use crate::testing::{Call, FakeDocker, running};
    use std::time::Duration;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PINNED: &str = "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OLD: &str = "ghcr.io/example/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PREVIOUS: &str = "# the previous override\nservices: {}\n";
    const STOP_TRUE: &str = "backup = { paths = [\"data\"], stop = true }\n";
    const STOP_FALSE: &str = "backup = { paths = [\"data\"], stop = false }\n";
    const DEPLOY_ID: &str = "2026-11-01T10-00-00-000000000Z";

    struct Fixture {
        _tmp: tempfile::TempDir,
        dir: PathBuf,
        state: DeploymentState,
        docker: FakeDocker,
        deployment: Deployment,
        plan: DeployPlan,
    }

    fn deployment(backup: &str) -> Deployment {
        deployment_with_checks(&format!("checks = [\"container-healthy\"]\n{backup}"))
    }

    /// A deployment with `rest` as the last lines of its table.
    fn deployment_with_checks(rest: &str) -> Deployment {
        let text = format!(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"app/prod\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = \"/srv/compose/app\", service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{rest}\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\ncan = [\"approve\"]\n"
        );
        parse(text.as_bytes()).unwrap().deployments()[0].clone()
    }

    /// A compose directory with a previous override and `data/db` holding
    /// "before", and an empty state directory.
    fn fixture(backup: &str) -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let dir = root.join("compose");
        fs::create_dir_all(dir.join("data")).unwrap();
        fs::write(dir.join("data/db"), "before").unwrap();
        fs::write(dir.join(OVERRIDE_FILE), PREVIOUS).unwrap();
        let state_root = root.join("state");
        fs::create_dir(&state_root).unwrap();
        let deployment = deployment(backup);
        let state = StateDir::open(&state_root)
            .unwrap()
            .deployment(deployment.id())
            .unwrap();
        let plan = DeployPlan::for_test(&deployment, "v1.2.3", DIGEST, COMMIT);
        Fixture {
            _tmp: tmp,
            dir,
            state,
            docker: FakeDocker::new(),
            deployment,
            plan,
        }
    }

    fn options() -> EngineOptions {
        EngineOptions {
            checks: CheckOptions {
                interval: Duration::from_millis(1),
                deadline: Duration::from_millis(500),
                http_timeout: Duration::from_millis(100),
                settle: Duration::from_millis(1),
            },
            ..EngineOptions::default()
        }
    }

    fn image(image: Option<&str>) -> ServiceConfig {
        ServiceConfig {
            image: image.map(str::to_owned),
            has_build: false,
            replicas: 1,
        }
    }

    /// A running container of `image`; without a healthcheck, the check of
    /// these deployments fails for good.
    fn container(image: &str, healthy: bool) -> ContainerInfo {
        let mut info = running(healthy.then_some("healthy"), &[]);
        image.clone_into(&mut info.image);
        info
    }

    /// The project resolves to `previous`, then to the pinned image while the
    /// new override is in place, and to `previous` once it is back.
    fn resolves(f: &Fixture, previous: Option<&str>) {
        f.docker.script_compose_service([
            Ok(image(previous)),
            Ok(image(Some(PINNED))),
            Ok(image(previous)),
        ]);
    }

    /// The deploy succeeds: the new image runs and is healthy.
    fn healthy_deploy(f: &Fixture) {
        resolves(f, Some(OLD));
        f.docker.script_inspect([Ok(container(PINNED, true))]);
    }

    /// The new image runs and fails its check for good; once the service is
    /// up for the second time, the previous image runs and is healthy.
    fn failing_check(f: &Fixture, previous: &str) {
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(previous, true))]);
    }

    /// The calls that change something, and the configuration reads, in order.
    /// Reads of the running state are left out: how many of those a check
    /// takes is its own business.
    fn changes(f: &Fixture) -> Vec<&'static str> {
        f.docker
            .calls()
            .iter()
            .filter_map(|call| match call {
                Call::Pull(_) => Some("pull"),
                Call::ComposeService { .. } | Call::ComposeServiceChecked { .. } => Some("config"),
                Call::ComposeUp { .. } => Some("up"),
                Call::ComposeStop { .. } => Some("stop"),
                _ => None,
            })
            .collect()
    }

    fn count_ups(f: &Fixture) -> usize {
        f.docker.count(|c| matches!(c, Call::ComposeUp { .. }))
    }

    fn count_stops(f: &Fixture) -> usize {
        f.docker.count(|c| matches!(c, Call::ComposeStop { .. }))
    }

    fn override_text(dir: &std::path::Path) -> String {
        fs::read_to_string(dir.join(OVERRIDE_FILE)).unwrap()
    }

    fn rendered(f: &Fixture) -> String {
        compose::render_override(
            "app",
            PINNED,
            f.deployment.id(),
            f.plan.tag(),
            f.plan.commit(),
        )
    }

    fn data(f: &Fixture) -> String {
        fs::read_to_string(f.dir.join("data/db")).unwrap()
    }

    /// What "the new version" does to the data: rewrites `data/db`, adds a file.
    fn migrate(dir: &std::path::Path) {
        fs::write(dir.join("data/db"), "migrated").unwrap();
        fs::write(dir.join("data/extra"), "new").unwrap();
    }

    /// On every `up` while the new override is in place, the data changes.
    fn new_version_migrates(f: &Fixture) {
        let dir = f.dir.clone();
        f.docker.on_call(move |call| {
            if matches!(call, Call::ComposeUp { .. }) && override_text(&dir).contains(PINNED) {
                migrate(&dir);
            }
        });
    }

    async fn deploy(f: &Fixture) -> Result<super::DeployReport, DeployError> {
        run(
            &f.docker,
            &f.state,
            &f.deployment,
            &f.dir,
            &f.plan,
            &options(),
        )
        .await
    }

    async fn deploy_with(
        f: &Fixture,
        options: &EngineOptions,
    ) -> Result<super::DeployReport, DeployError> {
        run(&f.docker, &f.state, &f.deployment, &f.dir, &f.plan, options).await
    }

    async fn recovered(f: &Fixture) -> Result<super::DeployReport, DeployError> {
        recover(&f.docker, &f.state, &f.deployment, &f.dir, &options()).await
    }

    fn backups(f: &Fixture) -> Vec<String> {
        let mut names: Vec<String> = match fs::read_dir(f.state.backups_dir()) {
            Ok(entries) => entries
                .map(|e| e.unwrap().file_name().into_string().unwrap())
                .collect(),
            Err(_) => Vec::new(),
        };
        names.sort();
        names
    }

    fn reports(f: &Fixture) -> Vec<Value> {
        let dir = f.state.backups_dir().with_file_name("reports");
        fs::read_dir(dir)
            .unwrap()
            .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
            .collect()
    }

    fn step_names(report: &super::DeployReport) -> Vec<&str> {
        report.steps.iter().map(|s| s.name.as_str()).collect()
    }

    #[tokio::test]
    async fn successful_deploy_runs_steps_in_order() {
        let f = fixture(STOP_TRUE);
        healthy_deploy(&f);
        fs::create_dir_all(f.state.backups_dir()).unwrap();
        for old in 1..=5 {
            fs::create_dir(
                f.state
                    .backups_dir()
                    .join(format!("2000-01-0{old}T00-00-00-000000000Z")),
            )
            .unwrap();
        }
        // What the override holds at each call that depends on it.
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        let dir = f.dir.clone();
        f.docker.on_call(move |call| {
            if !matches!(
                call,
                Call::Container { .. } | Call::ContainerAt { .. } | Call::Inspect(_)
            ) {
                log.lock().unwrap().push(override_text(&dir));
            }
        });

        let report = deploy(&f).await.unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(
            changes(&f),
            ["config", "config", "pull", "stop", "up"],
            "preflight twice, then pull, stop for the backup and up"
        );
        assert_eq!(
            f.docker
                .count(|c| matches!(c, Call::ComposeServiceChecked { .. })),
            1,
            "the read with the new override is held to what `up` requires"
        );
        assert_eq!(
            f.docker.count(|c| *c == Call::Pull(PINNED.to_owned())),
            1,
            "pulled by digest"
        );
        assert_eq!(
            step_names(&report),
            [
                "preflight",
                "record_in_progress",
                "verify_override",
                "pull",
                "mark_deploying",
                "prune_before_backup",
                "stop",
                "backup",
                "record_backup",
                "write_override",
                "up",
                "verify_image",
                "checks",
                "record_deployed",
                "prune_backups",
                "clear_in_progress",
            ]
        );
        assert!(report.steps.iter().all(|s| s.result == StepResult::Ok));
        let new = rendered(&f);
        assert_eq!(
            *seen.lock().unwrap(),
            [PREVIOUS, &new, PREVIOUS, PREVIOUS, &new],
            "config sees the previous then the new override, which is put back until after the backup"
        );
        assert_eq!(override_text(&f.dir), new);
        let deployed = f.state.deployed().unwrap().unwrap();
        assert_eq!(deployed.tag, *f.plan.tag());
        assert_eq!(deployed.digest, *f.plan.digest());
        assert_eq!(deployed.commit, *f.plan.commit());
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(
            f.state.previous_override().unwrap().as_deref(),
            Some(PREVIOUS.as_bytes())
        );
        let kept = backups(&f);
        assert_eq!(kept.len(), 3, "{kept:?}");
        assert!(
            kept[2].starts_with("20") && !kept[2].starts_with("2000"),
            "{kept:?}"
        );
        assert_eq!(
            fs::read_to_string(f.state.backups_dir().join(&kept[2]).join("data/db")).unwrap(),
            "before"
        );
        assert_eq!(reports(&f).len(), 1);
    }

    #[tokio::test]
    async fn failed_check_restores_image_and_data() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        // The data at each later call: unchanged until the restore, which
        // happens after the stop and before the second up.
        let at_up_or_stop = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&at_up_or_stop);
        let dir = f.dir.clone();
        f.docker.on_call(move |call| {
            let up = matches!(call, Call::ComposeUp { .. });
            if up && override_text(&dir).contains(PINNED) {
                migrate(&dir);
            }
            if up || matches!(call, Call::ComposeStop { .. }) {
                log.lock()
                    .unwrap()
                    .push(fs::read_to_string(dir.join("data/db")).unwrap());
            }
        });

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("checks")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            changes(&f),
            [
                "config", "config", "pull", "stop", "up", "stop", "up", "config"
            ]
        );
        assert_eq!(
            *at_up_or_stop.lock().unwrap(),
            ["before", "migrated", "migrated", "before"],
            "stop for backup, up, stop for restore, up"
        );
        assert_eq!(data(&f), "before");
        assert!(!f.dir.join("data/extra").exists(), "the restore removed it");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(
            f.state.deployed().unwrap(),
            None,
            "nothing new was recorded"
        );
    }

    #[tokio::test]
    async fn failed_up_rolls_back() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_compose_up([Err("no space"), Ok(())]);
        f.docker.script_inspect([Ok(container(OLD, true))]);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("up") && reason.contains("no space")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            changes(&f),
            [
                "config", "config", "pull", "stop", "up", "stop", "up", "config"
            ]
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_backup_restarts_without_restoring() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_inspect([Ok(container(OLD, true))]);
        // A socket in the tree fails the backup after `db` was copied.
        fs::write(f.dir.join("data/a"), "copied first").unwrap();
        let _socket = UnixListener::bind(f.dir.join("data/zz.sock")).unwrap();

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("backup") && reason.contains("zz.sock")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            changes(&f),
            ["config", "config", "pull", "stop", "up", "config"],
            "one stop for the backup and an up of the previous image; the new override is never written"
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(data(&f), "before");
        assert!(f.dir.join("data/zz.sock").exists(), "nothing was restored");
        assert!(
            !step_names(&report).contains(&"restore_backup"),
            "{:?}",
            step_names(&report)
        );
        assert_eq!(backups(&f), Vec::<String>::new(), "no partial copy stays");
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn missing_backup_path_is_a_failed_backup() {
        let f = fixture(STOP_FALSE);
        resolves(&f, Some(OLD));
        f.docker.script_inspect([Ok(container(OLD, true))]);
        fs::remove_dir_all(f.dir.join("data")).unwrap();

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("backup")),
            "{:?}",
            report.outcome
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.deployed().unwrap(), None);
    }

    #[tokio::test]
    async fn wrong_running_image_rolls_back() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container("example/other:latest", true))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason }
                if reason.contains("verify_image")
                    && reason.contains(PINNED)
                    && !reason.contains("example/other")),
            "{:?}",
            report.outcome
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(count_ups(&f), 2);
    }

    #[tokio::test]
    async fn image_swapped_during_the_checks_rolls_back() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        let verified_then_swapped = [
            Ok(container(PINNED, true)),
            Ok(container("example/other:latest", true)),
        ];
        f.docker.script_inspect_after_up(1, verified_then_swapped);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason }
                if reason.contains("checks")
                    && reason.contains(PINNED)
                    && !reason.contains("example/other")),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.deployed().unwrap(), None);
    }

    #[tokio::test]
    async fn previous_image_swapped_during_its_checks_is_a_failed_rollback() {
        let f = fixture("");
        resolves(&f, Some("example/app:token-s3cret"));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
        let verified_then_swapped = [
            Ok(container("example/app:token-s3cret", true)),
            Ok(container("something/else", true)),
        ];
        f.docker.script_inspect_after_up(2, verified_then_swapped);

        let report = deploy(&f).await.unwrap();

        let Outcome::RollbackFailed {
            rollback_reason, ..
        } = &report.outcome
        else {
            panic!("{:?}", report.outcome);
        };
        assert!(
            rollback_reason.contains("check_previous"),
            "{rollback_reason}"
        );
        assert!(!rollback_reason.contains("s3cret"), "{rollback_reason}");
    }

    #[tokio::test]
    async fn log_scan_starts_just_before_each_up() {
        let mut f = fixture("");
        f.deployment = deployment_with_checks(
            "checks = [\"container-healthy\", { no_log_match = \"panic\", within_secs = 1 }]\n",
        );
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, true))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);
        // A match in the new version's logs; none after the rollback.
        f.docker.script_logs_contain([Ok(true), Ok(false)]);
        let ups = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&ups);
        f.docker.on_call(move |call| {
            if matches!(call, Call::ComposeUp { .. }) {
                log.lock().unwrap().push(Timestamp::now());
            }
        });

        let before = Timestamp::now();
        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        let scans: Vec<Timestamp> = f
            .docker
            .calls()
            .iter()
            .filter_map(|c| match c {
                Call::LogsContain { since, .. } => Some(*since),
                _ => None,
            })
            .collect();
        let ups = ups.lock().unwrap();
        assert_eq!(ups.len(), 2);
        assert!(
            before <= scans[0] && scans[0] <= ups[0],
            "{scans:?} {ups:?}"
        );
        let last = *scans.last().unwrap();
        assert!(ups[0] <= last && last <= ups[1], "{scans:?} {ups:?}");
    }

    #[tokio::test]
    async fn running_image_is_never_named() {
        // `up` can leave the old container running, whose image comes from
        // interpolated configuration, and a container can claim anything.
        let f = fixture("");
        resolves(&f, Some(OLD));
        let hostile = format!("evil\n<2>token-s3cret{}", "x".repeat(16 * 1024 * 1024));
        f.docker
            .script_inspect_after_up(1, [Ok(container(&hostile, true))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);

        let report = deploy(&f).await.unwrap();

        let Outcome::RolledBack { reason } = &report.outcome else {
            panic!("{:?}", report.outcome);
        };
        assert!(
            reason.contains("the running image isn't the pinned one") && reason.contains(PINNED),
            "{reason}"
        );
        let written = serde_json::to_string(&reports(&f)).unwrap();
        assert!(!written.contains("s3cret"));
        assert!(written.len() < 64 * 1024, "{}", written.len());
    }

    #[tokio::test]
    async fn rollback_to_the_wrong_image_fails_without_naming_it() {
        let f = fixture("");
        resolves(&f, Some("example/app:token-s3cret"));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container("something/else", true))]);

        let report = deploy(&f).await.unwrap();

        let Outcome::RollbackFailed {
            rollback_reason, ..
        } = &report.outcome
        else {
            panic!("{:?}", report.outcome);
        };
        assert!(
            rollback_reason.contains("verify_previous_image"),
            "{rollback_reason}"
        );
        assert!(!rollback_reason.contains("s3cret"), "{rollback_reason}");
    }

    #[tokio::test]
    async fn failed_rollback_is_critical_and_blocks() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        f.docker.script_compose_up([Err("daemon gone")]);

        let report = deploy(&f).await.unwrap();

        let Outcome::RollbackFailed {
            reason,
            rollback_reason,
        } = &report.outcome
        else {
            panic!("{:?}", report.outcome);
        };
        assert!(reason.contains("daemon gone"), "{reason}");
        assert!(
            rollback_reason.contains("start_previous"),
            "{rollback_reason}"
        );
        assert_eq!(report.outcome.priority(), Priority::Critical);
        assert_ne!(f.state.in_progress().unwrap(), None);

        let refused = deploy(&f).await.unwrap_err();
        assert!(
            matches!(refused, DeployError::Interrupted { .. }),
            "{refused}"
        );
        assert!(refused.to_string().contains("recover"), "{refused}");
    }

    /// Whatever the failed `up` left is what runs: the agent adds no stop.
    #[tokio::test]
    async fn a_failed_up_of_the_previous_version_stops_nothing() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        f.docker.script_compose_up([Ok(()), Err("daemon gone")]);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("start_previous")),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_stops(&f), 0);
        assert_ne!(f.state.in_progress().unwrap(), None);
        assert!(report.leaves_deploys_blocked());
    }

    /// With a backup the service was stopped to restore it, before the `up`.
    /// That is the one stop on this path, and none follows the failure.
    #[tokio::test]
    async fn a_failed_up_after_a_restore_adds_no_stop_after_it() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        f.docker.script_compose_up([Ok(()), Err("daemon gone")]);

        let report = deploy(&f).await.unwrap();

        assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Restored
        );
        assert_eq!(
            changes(&f).last(),
            Some(&"up"),
            "the failed up is the last thing done to the service"
        );
    }

    #[tokio::test]
    async fn the_report_says_what_the_backup_copied_and_what_each_check_took() {
        let f = fixture(STOP_TRUE);
        healthy_deploy(&f);

        let report = deploy(&f).await.unwrap();

        let detail = |name: &str| {
            report
                .steps
                .iter()
                .find(|step| step.name == name)
                .and_then(|step| step.detail.clone())
        };
        let Some(StepDetail::Backup { stats }) = detail("backup") else {
            panic!("{report:?}");
        };
        assert_eq!((stats.files, stats.bytes), (1, 6));
        let Some(StepDetail::Checks { checks }) = detail("checks") else {
            panic!("{report:?}");
        };
        assert_eq!(checks.len(), 1);
        assert_eq!(checks[0].attempts, 2, "a pass and its confirmation");
        assert!(checks[0].check.starts_with("checks[0]"), "{checks:?}");
        assert_eq!(detail("up"), None);

        let json = serde_json::to_value(&report).unwrap();
        let steps = json["steps"].as_array().unwrap();
        let shown = steps.iter().find(|step| step["name"] == "checks").unwrap();
        assert_eq!(shown["detail"]["kind"], "checks");
        assert_eq!(shown["detail"]["checks"][0]["attempts"], 2);
        let plain = steps.iter().find(|step| step["name"] == "up").unwrap();
        assert!(plain.get("detail").is_none(), "{plain}");
    }

    #[tokio::test]
    async fn a_failed_run_of_the_checks_still_reports_what_they_took() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);

        let report = deploy(&f).await.unwrap();

        for name in ["checks", "check_previous"] {
            let step = report.steps.iter().find(|step| step.name == name).unwrap();
            let Some(StepDetail::Checks { checks }) = &step.detail else {
                panic!("{step:?}");
            };
            assert!(checks[0].attempts >= 1, "{name}: {checks:?}");
        }
    }

    #[tokio::test]
    async fn stop_failure_in_rollback_never_restores_or_starts() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_inspect([Ok(container(PINNED, false))]);
        f.docker.script_compose_stop([Ok(()), Err("will not stop")]);
        new_version_migrates(&f);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("will not stop")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            data(&f),
            "migrated",
            "a running container could outrun a restore"
        );
        assert_eq!(
            count_ups(&f),
            1,
            "nothing was started after the failed stop"
        );
        assert_ne!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn restore_failure_leaves_the_service_stopped() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_inspect([Ok(container(PINNED, false))]);
        // The backup disappears after the new version started.
        let backups_dir = f.state.backups_dir();
        f.docker.on_call(move |call| {
            if matches!(call, Call::ComposeUp { .. }) {
                fs::remove_dir_all(&backups_dir).unwrap();
            }
        });

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("restore_backup")),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_ups(&f), 1, "half-restored data is not started");
        assert_eq!(count_stops(&f), 2);
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::RollingBack,
            "the next recover has to restore again"
        );
    }

    #[tokio::test]
    async fn restore_past_its_deadline_is_a_failed_rollback() {
        let f = fixture(STOP_TRUE);
        for i in 0..300 {
            fs::write(f.dir.join(format!("data/file-{i}")), "x").unwrap();
        }
        resolves(&f, Some(OLD));
        f.docker.script_inspect([Ok(container(PINNED, false))]);

        let report = deploy_with(
            &f,
            &EngineOptions {
                restore_deadline: Duration::ZERO,
                ..options()
            },
        )
        .await
        .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("restore_backup")
                    && rollback_reason.contains("result is unknown")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            count_ups(&f),
            1,
            "nothing starts on top of a running restore"
        );
        assert_ne!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn off_thread_work_keeps_the_lock_past_its_deadline() {
        let f = fixture("");
        let lock = Arc::new(f.state.lock().unwrap());
        let (release, wait) = std::sync::mpsc::channel::<()>();
        let (finished, done) = tokio::sync::oneshot::channel();

        let result = super::off_thread(&lock, "slow", Duration::from_millis(5), move || {
            let _ = wait.recv();
            let _ = finished.send(());
            Ok::<(), crate::state::StateError>(())
        })
        .await;

        assert!(
            matches!(result, Err(super::FileFailure::Deadline { op: "slow", .. })),
            "never taken for success: {result:?}"
        );
        drop(lock);
        let busy = f.state.lock().unwrap_err();
        assert!(
            matches!(busy, crate::state::StateError::Busy(_)),
            "a new process must not start while the old work runs: {busy}"
        );
        release.send(()).unwrap();
        done.await.unwrap();
        // The thread lets go of the lock when it ends.
        for _ in 0..1000 {
            if f.state.lock().is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the lock was never released");
    }

    #[tokio::test]
    async fn first_deploy_failure_with_no_base_image_stops_service() {
        let f = fixture("");
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        resolves(&f, None);
        f.docker.script_inspect([Ok(container(PINNED, false))]);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
            "{:?}",
            report.outcome
        );
        assert_ne!(report.outcome.priority(), Priority::Critical);
        assert_eq!(override_text(&f.dir), PLACEHOLDER);
        assert_eq!(count_ups(&f), 1, "there is nothing to start");
        assert_eq!(count_stops(&f), 1);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn first_deploy_failure_with_a_backup_restores_and_stays_stopped() {
        let f = fixture(STOP_TRUE);
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        resolves(&f, None);
        f.docker.script_inspect([Ok(container(PINNED, false))]);
        new_version_migrates(&f);

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(data(&f), "before");
        assert_eq!(override_text(&f.dir), PLACEHOLDER);
        assert_eq!(
            changes(&f),
            ["config", "config", "pull", "stop", "up", "stop"],
            "stopped for the backup and the restore, and nothing started after"
        );
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn first_deploy_failure_with_base_image_starts_it() {
        let f = fixture("");
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        resolves(&f, Some("example/app:base"));
        failing_check(&f, "example/app:base");

        let report = deploy(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(override_text(&f.dir), PLACEHOLDER);
        assert_eq!(count_ups(&f), 2);
        assert_eq!(count_stops(&f), 0);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    /// The state an agent leaves behind when it dies after starting the new
    /// version: in-progress with a backup, the new override, changed data.
    fn interrupted(f: &Fixture) {
        f.state.set_previous_override(PREVIOUS.as_bytes()).unwrap();
        f.state
            .set_previous_deployed(f.state.deployed().unwrap().as_ref())
            .unwrap();
        fs::create_dir_all(f.state.backups_dir()).unwrap();
        let id = "2026-11-01T10-00-00-000000000Z";
        safefs::snapshot(
            &Root::open(&f.dir).unwrap(),
            &[RelPath::new("data").unwrap()],
            &f.state.backups_dir().join(id),
        )
        .unwrap();
        f.state
            .set_in_progress(&InProgress {
                deploy_id: DEPLOY_ID.to_owned(),
                phase: Phase::Deploying,
                tag: f.plan.tag().clone(),
                digest: f.plan.digest().clone(),
                previous_can_start: true,
                backup: Some(RecordedBackup {
                    id: id.to_owned(),
                    paths: vec!["data".to_owned()],
                }),
                started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
            })
            .unwrap();
        fs::write(f.dir.join(OVERRIDE_FILE), rendered(f)).unwrap();
        fs::write(f.dir.join("data/db"), "half migrated").unwrap();
    }

    #[tokio::test]
    async fn interrupted_deploy_blocks_until_recovered() {
        let f = fixture(STOP_TRUE);
        interrupted(&f);

        let err = deploy(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::Interrupted { .. }), "{err}");
        assert!(
            err.to_string()
                .contains("landfall-agent recover --deployment app/prod"),
            "{err}"
        );
        assert_eq!(f.docker.calls(), [], "refused before anything ran");
        assert_eq!(data(&f), "half migrated");

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();
        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("interrupted")),
            "{:?}",
            report.outcome
        );
        assert_eq!(changes(&f), ["stop", "up", "config"]);
        assert_eq!(data(&f), "before");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(reports(&f).len(), 1);

        healthy_deploy(&f);
        assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
    }

    #[tokio::test]
    async fn recover_after_a_failed_rollback_can_succeed() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        f.docker.script_compose_up([Err("daemon gone")]);
        let report = deploy(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));

        f.docker.script_compose_up([Ok(())]);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn recover_finishes_a_deploy_that_had_already_succeeded() {
        // The agent died after recording the deploy and before clearing the
        // marker: the release passed its checks, so it stays.
        let f = fixture("");
        f.state.set_previous_override(PREVIOUS.as_bytes()).unwrap();
        let started_at = "2026-11-01T10:00:00Z".parse().unwrap();
        f.state
            .set_in_progress(&InProgress {
                deploy_id: DEPLOY_ID.to_owned(),
                phase: Phase::Deploying,
                tag: f.plan.tag().clone(),
                digest: f.plan.digest().clone(),
                previous_can_start: true,
                backup: None,
                started_at,
            })
            .unwrap();
        // The id decides, not the clock, which here went backwards.
        f.state
            .set_deployed(&Deployed {
                deploy_id: DEPLOY_ID.to_owned(),
                tag: f.plan.tag().clone(),
                version: f.plan.version().clone(),
                digest: f.plan.digest().clone(),
                commit: f.plan.commit().clone(),
                deployed_at: "2026-11-01T09:59:00Z".parse().unwrap(),
            })
            .unwrap();
        let new = rendered(&f);
        fs::write(f.dir.join(OVERRIDE_FILE), &new).unwrap();

        let report = recovered(&f).await.unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(f.docker.calls(), []);
        assert_eq!(override_text(&f.dir), new);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn redeploy_of_the_same_digest_interrupted_is_rolled_back() {
        // deployed.json names the same release, from before this deploy, and
        // says it is later: the clock doesn't decide.
        let f = fixture(STOP_TRUE);
        f.state
            .set_deployed(&Deployed {
                tag: f.plan.tag().clone(),
                version: f.plan.version().clone(),
                digest: f.plan.digest().clone(),
                commit: f.plan.commit().clone(),
                deployed_at: "2026-11-01T11:00:00Z".parse().unwrap(),
                ..earlier_release(&f)
            })
            .unwrap();
        interrupted(&f);
        f.docker.script_compose_service([Ok(image(Some(PINNED)))]);
        f.docker.script_inspect([Ok(container(PINNED, true))]);

        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    /// The record of an earlier deploy, of an earlier release.
    fn earlier_release(f: &Fixture) -> Deployed {
        Deployed {
            deploy_id: "2026-10-01T10-00-00-000000000Z".to_owned(),
            tag: "v1.2.2".parse().unwrap(),
            version: semver::Version::new(1, 2, 2),
            digest: f.plan.digest().clone(),
            commit: f.plan.commit().clone(),
            deployed_at: "2026-10-01T10:01:00Z".parse().unwrap(),
        }
    }

    /// Runs a deploy up to the `nth` call that `pick` chooses, and kills it
    /// there, the way a dying process does: what is on disk stays, the lock
    /// goes, and nothing else runs.
    async fn crash_at(f: &Fixture, nth: usize, pick: fn(&Call) -> bool) {
        let seen = Arc::new(Mutex::new(0));
        let hit = Arc::new(Mutex::new(false));
        let reached = Arc::clone(&hit);
        f.docker.hang_when(move |call| {
            if !pick(call) {
                return false;
            }
            let mut seen = seen.lock().unwrap();
            *seen += 1;
            if *seen - 1 == nth {
                *reached.lock().unwrap() = true;
                return true;
            }
            false
        });
        let crashed = async {
            while !*hit.lock().unwrap() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        };
        tokio::select! {
            result = deploy(f) => panic!("the deploy finished: {result:?}"),
            () = crashed => {}
        }
        f.docker.hang_when(|_| false);
    }

    /// The lock is free again: late file work has ended.
    async fn late_work_has_ended(f: &Fixture) {
        for _ in 0..5000 {
            if f.state.lock().is_ok() {
                return;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        panic!("the lock was never released");
    }

    /// The new image passes its checks; the previous one does after an `up`.
    fn new_passes_then_previous_passes(f: &Fixture) {
        resolves(f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, true))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    }

    fn step_failed(report: &super::DeployReport, name: &str) -> bool {
        report
            .steps
            .iter()
            .any(|s| s.name == name && matches!(s.result, StepResult::Failed { .. }))
    }

    #[tokio::test]
    async fn crash_during_preflight_is_recovered_without_touching_the_service() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));

        crash_at(&f, 0, |c| matches!(c, Call::ComposeServiceChecked { .. })).await;

        assert_eq!(override_text(&f.dir), rendered(&f), "the new one is in");
        let marker = f.state.in_progress().unwrap().unwrap();
        assert_eq!(marker.phase, Phase::Preflight);
        assert_eq!(marker.backup, None);
        assert_eq!(
            f.state.previous_override().unwrap().as_deref(),
            Some(PREVIOUS.as_bytes()),
            "never the new release's override"
        );
        let refused = deploy(&f).await.unwrap_err();
        assert!(
            matches!(refused, DeployError::Interrupted { .. }),
            "{refused}"
        );

        let calls = f.docker.calls().len();
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::NothingChanged { .. }),
            "{:?}",
            report.outcome
        );
        assert_ne!(report.outcome.priority(), Priority::Critical);
        assert_eq!(
            f.docker.calls().len(),
            calls,
            "no stop, up, check or anything else"
        );
        assert_eq!(count_stops(&f), 0);
        assert_eq!(count_ups(&f), 0);
        assert_eq!(
            step_names(&report),
            [
                "read_previous_override",
                "restore_override",
                "clear_in_progress"
            ]
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(reports(&f)[0]["outcome"]["kind"], "nothing_changed");

        // The next deploy still goes back to the right override.
        healthy_deploy(&f);
        assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
        assert_eq!(
            f.state.previous_override().unwrap().as_deref(),
            Some(PREVIOUS.as_bytes())
        );
    }

    #[tokio::test]
    async fn preflight_recover_that_cannot_put_the_override_back_keeps_the_marker() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        crash_at(&f, 0, |c| matches!(c, Call::ComposeServiceChecked { .. })).await;

        let report = with_faults([("write override", vec![Fault::Fail])], recovered(&f))
            .await
            .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("restore_override")),
            "{:?}",
            report.outcome
        );
        assert_ne!(f.state.in_progress().unwrap(), None);

        let report = recovered(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn crash_during_the_pull_changes_nothing() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));

        crash_at(&f, 0, |c| matches!(c, Call::Pull(_))).await;

        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Preflight,
            "nothing is touched by a pull"
        );
        let calls = f.docker.calls().len();
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::NothingChanged { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.docker.calls().len(), calls, "no stop, up or check");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn crash_right_after_the_pull_may_have_touched_the_service() {
        // The stop for the backup is the first thing that touches it.
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));

        crash_at(&f, 0, |c| matches!(c, Call::ComposeStop { .. })).await;

        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Deploying,
            "on disk before the stop"
        );
    }

    #[tokio::test]
    async fn failed_record_in_progress_leaves_no_marker_behind() {
        // The rename landed and the directory `fsync` after it failed.
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);

        let err = with_faults([("record in-progress", vec![Fault::FailAfter])], deploy(&f))
            .await
            .unwrap_err();

        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(changes(&f), ["config"], "no new override read, no pull");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_record_in_progress_whose_clear_fails_names_recover() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);

        let err = with_faults(
            [
                ("record in-progress", vec![Fault::FailAfter]),
                ("clear in-progress", vec![Fault::Fail]),
            ],
            deploy(&f),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
        assert!(
            err.to_string().contains("recover --deployment app/prod"),
            "{err}"
        );
        assert_ne!(f.state.in_progress().unwrap(), None);

        let report = recovered(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn record_in_progress_past_its_deadline_blocks_and_recovers() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let (release, late) = std::sync::mpsc::channel();

        let err = with_faults(
            [("record in-progress", vec![Fault::Late(late)])],
            deploy(&f),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
        assert!(
            err.to_string().contains("recover --deployment app/prod"),
            "{err}"
        );
        assert_eq!(changes(&f), ["config"], "no new override read, no pull");
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
        assert_ne!(f.state.in_progress().unwrap(), None, "it did land");

        let report = recovered(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_move_to_deploying_is_a_refusal_before_anything_stops() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));

        let err = with_faults([("mark deploying", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap_err();

        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(changes(&f), ["config", "config", "pull"], "no stop or up");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn move_to_deploying_past_its_deadline_keeps_the_marker() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        let (release, late) = std::sync::mpsc::channel();

        let err = with_faults([("mark deploying", vec![Fault::Late(late)])], deploy(&f))
            .await
            .unwrap_err();

        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
        assert!(err.to_string().contains("recover"), "{err}");
        assert_eq!(changes(&f), ["config", "config", "pull"], "no stop or up");
        assert_ne!(f.state.in_progress().unwrap(), None);
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Deploying
        );
    }

    #[tokio::test]
    async fn corrupt_deployed_record_is_refused_before_the_override_changes() {
        let f = fixture(STOP_TRUE);
        f.state.set_deployed(&earlier_release(&f)).unwrap();
        let path = f.state.backups_dir().with_file_name("deployed.json");
        fs::write(path, "not json").unwrap();
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);

        let err = deploy(&f).await.unwrap_err();

        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(changes(&f), ["config"]);
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_put_back_keeps_the_marker_and_names_recover() {
        // Both when the preflight passed and when it refused.
        for second_read in [Ok(image(Some(PINNED))), Err("bad project")] {
            let refused = second_read.is_err();
            let f = fixture(STOP_TRUE);
            f.docker
                .script_compose_service([Ok(image(Some(OLD))), second_read]);

            let err = with_faults(
                [("write override", vec![Fault::Pass, Fault::Fail])],
                deploy(&f),
            )
            .await
            .unwrap_err();

            assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
            let text = err.to_string();
            assert!(
                text.contains("landfall-agent recover --deployment app/prod"),
                "{text}"
            );
            assert!(text.contains("previous override back"), "{text}");
            assert_eq!(text.contains("bad project"), refused, "{text}");
            assert_eq!(changes(&f), ["config", "config"], "no pull, stop or up");
            assert_eq!(override_text(&f.dir), rendered(&f));
            assert_ne!(f.state.in_progress().unwrap(), None);
            assert_eq!(
                f.state.previous_override().unwrap().as_deref(),
                Some(PREVIOUS.as_bytes())
            );
            let blocked = deploy(&f).await.unwrap_err();
            assert!(
                matches!(blocked, DeployError::Interrupted { .. }),
                "{blocked}"
            );

            let report = recovered(&f).await.unwrap();
            assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
            assert_eq!(count_ups(&f), 0);
            assert_eq!(override_text(&f.dir), PREVIOUS);
        }
    }

    #[tokio::test]
    async fn failed_write_of_the_new_override_is_put_back() {
        // The rename landed and the `fsync` after it failed.
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);

        let err = with_faults([("write override", vec![Fault::FailAfter])], deploy(&f))
            .await
            .unwrap_err();

        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(changes(&f), ["config"], "never read with it, nor pulled");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn new_override_past_its_deadline_blocks_rather_than_racing_it() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let (release, late) = std::sync::mpsc::channel();

        let err = with_faults([("write override", vec![Fault::Late(late)])], deploy(&f))
            .await
            .unwrap_err();

        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
        assert!(err.to_string().contains("recover"), "{err}");
        assert_ne!(f.state.in_progress().unwrap(), None);
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
        assert_eq!(override_text(&f.dir), rendered(&f), "it did land");

        recovered(&f).await.unwrap();
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn failed_clear_after_a_refusal_says_so_and_stays_blocked() {
        let f = fixture(STOP_TRUE);
        f.docker
            .script_compose_service([Ok(image(Some(OLD))), Err("bad project")]);

        let err = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap_err();

        let text = err.to_string();
        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{text}");
        assert!(text.contains("bad project"), "{text}");
        assert!(text.contains("marker"), "{text}");
        assert!(text.contains("recover --deployment app/prod"), "{text}");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_ne!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_clear_after_a_failed_pull_says_so_and_stays_blocked() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_pull([Err("manifest unknown")]);

        let err = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap_err();

        let text = err.to_string();
        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{text}");
        assert!(text.contains("manifest unknown"), "{text}");
        assert!(text.contains("recover --deployment app/prod"), "{text}");
        assert_ne!(f.state.in_progress().unwrap(), None);
        assert_eq!(count_stops(&f), 0);

        let report = recovered(&f).await.unwrap();
        assert!(
            matches!(report.outcome, Outcome::NothingChanged { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_stops(&f), 0);
        assert_eq!(count_ups(&f), 0);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_record_rolls_back_and_puts_the_earlier_record_back() {
        let f = fixture("");
        let earlier = earlier_release(&f);
        f.state.set_deployed(&earlier).unwrap();
        new_passes_then_previous_passes(&f);

        let report = with_faults([("record deployed", vec![Fault::FailAfter])], deploy(&f))
            .await
            .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("record_deployed")),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.deployed().unwrap(), Some(earlier));
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn failed_first_record_rolls_back_to_no_record() {
        let f = fixture("");
        new_passes_then_previous_passes(&f);

        let report = with_faults([("record deployed", vec![Fault::FailAfter])], deploy(&f))
            .await
            .unwrap();

        assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
        assert_eq!(f.state.deployed().unwrap(), None);
    }

    #[tokio::test]
    async fn record_left_behind_with_a_failed_rollback_never_recovers_to_deployed() {
        // The worst case: the release's record is on disk and matches, the
        // rollback failed, and it could not even put the earlier record back.
        let f = fixture("");
        let earlier = earlier_release(&f);
        f.state.set_deployed(&earlier).unwrap();
        new_passes_then_previous_passes(&f);

        let report = with_faults(
            [
                ("record deployed", vec![Fault::FailAfter]),
                ("restore deployed", vec![Fault::Fail]),
            ],
            deploy(&f),
        )
        .await
        .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("restore_deployed")),
            "{:?}",
            report.outcome
        );
        let left = f.state.deployed().unwrap().unwrap();
        let marker = f.state.in_progress().unwrap().unwrap();
        assert_eq!(left.deploy_id, marker.deploy_id, "it does match");
        assert_eq!(marker.phase, Phase::RollingBack);

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.deployed().unwrap(), Some(earlier));
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn record_landing_past_its_deadline_is_not_a_finished_deploy() {
        let f = fixture("");
        let earlier = earlier_release(&f);
        f.state.set_deployed(&earlier).unwrap();
        new_passes_then_previous_passes(&f);
        let (release, late) = std::sync::mpsc::channel();

        let report = with_faults([("record deployed", vec![Fault::Late(late)])], deploy(&f))
            .await
            .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("may still land")),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_ups(&f), 1, "nothing restarted under a late write");
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
        assert_ne!(f.state.deployed().unwrap(), Some(earlier.clone()));

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.deployed().unwrap(), Some(earlier));
    }

    #[tokio::test]
    async fn late_write_of_the_switch_stops_the_rollback() {
        // Preflight's write and put-back work; the third write is the switch.
        let f = fixture("");
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(OLD, true))]);
        let (release, late) = std::sync::mpsc::channel();

        let report = with_faults(
            [(
                "write override",
                vec![Fault::Pass, Fault::Pass, Fault::Late(late)],
            )],
            deploy(&f),
        )
        .await
        .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { reason, rollback_reason }
                if reason.contains("write_override") && rollback_reason.contains("may still land")),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_ups(&f), 0);
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::RollingBack
        );
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
        assert_eq!(override_text(&f.dir), rendered(&f), "it did land");

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let report = recovered(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn writes_of_the_rollback_past_their_deadline_fail_it() {
        for (op, runs_before, step) in [
            ("mark rolling back", 0, "mark_rolling_back"),
            ("write override", 3, "restore_override"),
            ("restore deployed", 0, "restore_deployed"),
            ("mark rolled back", 0, "mark_rolled_back"),
        ] {
            let f = fixture("");
            resolves(&f, Some(OLD));
            failing_check(&f, OLD);
            let (release, late) = std::sync::mpsc::channel();
            let mut faults: Vec<Fault> = (0..runs_before).map(|_| Fault::Pass).collect();
            faults.push(Fault::Late(late));

            let report = with_faults([(op, faults)], deploy(&f)).await.unwrap();

            assert!(
                matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                    if rollback_reason.contains(step)
                        && rollback_reason.contains("result is unknown")),
                "{op}: {:?}",
                report.outcome
            );
            assert_ne!(f.state.in_progress().unwrap(), None, "{op}");
            release.send(()).unwrap();
            late_work_has_ended(&f).await;
        }
    }

    #[tokio::test]
    async fn marker_that_cannot_say_rolling_back_undoes_nothing() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);

        let report = with_faults([("mark rolling back", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("mark_rolling_back")),
            "{:?}",
            report.outcome
        );
        assert_eq!(count_ups(&f), 1);
        assert_eq!(count_stops(&f), 1, "only the backup's");
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Deploying
        );
    }

    #[tokio::test]
    async fn rolled_back_phase_is_only_cleared_and_keeps_later_writes() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        new_version_migrates(&f);

        let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert!(step_failed(&report, "clear_in_progress"));
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::RolledBack
        );
        let blocked = deploy(&f).await.unwrap_err();
        assert!(
            matches!(blocked, DeployError::Interrupted { .. }),
            "{blocked}"
        );

        // The previous version is healthy and has moved on.
        fs::write(f.dir.join("data/db"), "written since").unwrap();
        let calls = f.docker.calls().len();
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            data(&f),
            "written since",
            "the backup is not restored again"
        );
        assert_eq!(f.docker.calls().len(), calls, "nothing is run");
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn rolled_back_phase_of_a_first_deploy_stays_failed_no_previous() {
        let f = fixture("");
        resolves(&f, None);
        f.docker.script_inspect([Ok(container(PINNED, false))]);

        let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();
        assert!(matches!(report.outcome, Outcome::FailedNoPrevious { .. }));

        let report = recovered(&f).await.unwrap();
        assert!(
            matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn failed_clear_after_a_deploy_blocks_until_recover_finishes_it() {
        let f = fixture("");
        healthy_deploy(&f);

        let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert!(step_failed(&report, "clear_in_progress"));
        assert!(report.leaves_deploys_blocked());
        let blocked = deploy(&f).await.unwrap_err();
        assert!(
            matches!(blocked, DeployError::Interrupted { .. }),
            "{blocked}"
        );

        let ups = count_ups(&f);
        let report = recovered(&f).await.unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(count_ups(&f), ups, "the release stays as it is");
        assert_eq!(override_text(&f.dir), rendered(&f));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn recover_restores_the_paths_the_backup_was_taken_of() {
        for later_config in ["", "backup = { paths = [\"other\"], stop = true }\n"] {
            let mut f = fixture(STOP_TRUE);
            interrupted(&f);
            f.deployment = deployment(later_config);
            f.docker.script_compose_service([Ok(image(Some(OLD)))]);
            f.docker.script_inspect([Ok(container(OLD, true))]);

            let report = recovered(&f).await.unwrap();

            assert!(
                matches!(report.outcome, Outcome::RolledBack { .. }),
                "{later_config}: {:?}",
                report.outcome
            );
            assert_eq!(data(&f), "before", "{later_config}");
        }
    }

    #[tokio::test]
    async fn failed_report_write_changes_no_outcome() {
        let deployed = fixture("");
        healthy_deploy(&deployed);
        let rolled_back = fixture("");
        resolves(&rolled_back, Some(OLD));
        failing_check(&rolled_back, OLD);

        for (f, kind) in [(&deployed, "deployed"), (&rolled_back, "rolled back")] {
            let report = with_faults([("write report", vec![Fault::Fail])], deploy(f))
                .await
                .unwrap();
            let expected = if kind == "deployed" {
                report.outcome == Outcome::Deployed
            } else {
                matches!(report.outcome, Outcome::RolledBack { .. })
            };
            assert!(expected, "{kind}: {:?}", report.outcome);
            assert_eq!(f.state.in_progress().unwrap(), None, "{kind}");
            assert_eq!(
                f.state.deployed().unwrap().is_some(),
                kind == "deployed",
                "{kind}"
            );
        }
    }

    #[tokio::test]
    async fn failed_prune_is_reported_and_changes_no_outcome() {
        let f = fixture(STOP_TRUE);
        healthy_deploy(&f);

        let report = with_faults([("prune backups", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert!(step_failed(&report, "prune_backups"));
        assert!(!report.leaves_deploys_blocked());
        assert_ne!(f.state.deployed().unwrap(), None);
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(override_text(&f.dir), rendered(&f));
    }

    #[tokio::test]
    async fn recover_from_a_crash_before_the_backup_restores_nothing() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));

        crash_at(&f, 0, |c| matches!(c, Call::ComposeStop { .. })).await;

        let marker = f.state.in_progress().unwrap().unwrap();
        assert_eq!(marker.phase, Phase::Deploying);
        assert_eq!(marker.backup, None);
        assert_eq!(override_text(&f.dir), PREVIOUS);

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert!(!step_names(&report).contains(&"restore_backup"));
        assert_eq!(count_ups(&f), 1, "the service is started again");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(data(&f), "before");
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn recover_from_a_crash_before_the_restore_rolls_back_again() {
        let f = fixture(STOP_TRUE);
        let earlier = earlier_release(&f);
        f.state.set_deployed(&earlier).unwrap();
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        new_version_migrates(&f);

        // The second stop is the rollback's, ahead of the restore.
        crash_at(&f, 1, |c| matches!(c, Call::ComposeStop { .. })).await;

        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::RollingBack
        );

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert!(step_names(&report).contains(&"restore_backup"));
        assert_eq!(data(&f), "before");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.deployed().unwrap(), Some(earlier));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn recover_from_a_restore_that_failed_part_way_restores_again() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
        new_version_migrates(&f);

        let report = with_faults([("restore backup", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::RollingBack
        );

        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert!(step_names(&report).contains(&"restore_backup"));
        assert_eq!(data(&f), "before");
    }

    #[tokio::test]
    async fn recover_after_the_restore_keeps_what_the_previous_version_wrote() {
        let f = fixture(STOP_TRUE);
        let earlier = earlier_release(&f);
        f.state.set_deployed(&earlier).unwrap();
        resolves(&f, Some(OLD));
        f.docker
            .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, false))]);
        new_version_migrates(&f);

        // The previous version is back and fails its checks.
        let report = deploy(&f).await.unwrap();
        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains("check_previous")),
            "{:?}",
            report.outcome
        );
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Restored
        );
        assert_eq!(data(&f), "before");

        // It runs on for hours, then its dependency is fixed.
        fs::write(f.dir.join("data/db"), "written since").unwrap();
        let stops = count_stops(&f);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker
            .script_inspect_after_up(3, [Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!(data(&f), "written since");
        assert_eq!(count_stops(&f), stops, "the service is not stopped");
        assert_eq!(
            step_names(&report),
            [
                "start_previous",
                "verify_previous_image",
                "check_previous",
                "mark_rolled_back",
                "clear_in_progress",
                "prune_backups",
            ]
        );
        assert_eq!(f.state.deployed().unwrap(), Some(earlier));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    #[tokio::test]
    async fn a_crash_right_after_the_restore_does_not_restore_again() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        new_version_migrates(&f);

        // The second `up` is the rollback's: the data is back by then.
        crash_at(&f, 1, |c| matches!(c, Call::ComposeUp { .. })).await;

        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Restored
        );
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker
            .script_inspect_after_up(3, [Ok(container(OLD, true))]);
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{:?}",
            report.outcome
        );
        assert!(!step_names(&report).contains(&"restore_backup"));
        assert_eq!(data(&f), "before");
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn restored_phase_of_a_first_deploy_starts_nothing() {
        let f = fixture(STOP_TRUE);
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        resolves(&f, None);
        f.docker.script_inspect([Ok(container(PINNED, false))]);

        let report = with_faults([("mark rolled back", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();
        assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
        assert_eq!(
            f.state.in_progress().unwrap().unwrap().phase,
            Phase::Restored
        );

        let (ups, stops) = (count_ups(&f), count_stops(&f));
        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
            "{:?}",
            report.outcome
        );
        assert_eq!((count_ups(&f), count_stops(&f)), (ups, stops));
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    /// `how_many` old backups, which sort before anything the deploy takes.
    fn old_backups(f: &Fixture, how_many: usize) -> Vec<String> {
        fs::create_dir_all(f.state.backups_dir()).unwrap();
        (1..=how_many)
            .map(|day| {
                let name = format!("2000-01-{day:02}T00-00-00-000000000Z");
                fs::create_dir(f.state.backups_dir().join(&name)).unwrap();
                name
            })
            .collect()
    }

    #[tokio::test]
    async fn room_is_made_before_the_backup() {
        let f = fixture(STOP_TRUE);
        old_backups(&f, 5);
        healthy_deploy(&f);
        // How many there are when the service stops for the backup.
        let at_stop = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&at_stop);
        let backups_dir = f.state.backups_dir();
        f.docker.on_call(move |call| {
            if matches!(call, Call::ComposeStop { .. }) {
                log.lock()
                    .unwrap()
                    .push(fs::read_dir(&backups_dir).unwrap().count());
            }
        });

        let report = deploy(&f).await.unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(
            *at_stop.lock().unwrap(),
            [2],
            "one short of the number kept"
        );
    }

    #[tokio::test]
    async fn a_failed_prune_before_the_backup_changes_nothing() {
        let f = fixture(STOP_TRUE);
        old_backups(&f, 5);
        healthy_deploy(&f);

        let report = with_faults([("prune before backup", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert!(step_failed(&report, "prune_before_backup"));
        assert_eq!(backups(&f).len(), 3, "the prune at the end still ran");
    }

    #[tokio::test]
    async fn a_completed_rollback_prunes_once_the_marker_is_gone() {
        let f = fixture(STOP_TRUE);
        old_backups(&f, 5);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);

        // The prune before the backup fails, which leaves this one the work.
        let report = with_faults([("prune before backup", vec![Fault::Fail])], deploy(&f))
            .await
            .unwrap();

        assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
        assert_eq!(backups(&f).len(), 3, "{:?}", backups(&f));
        let names = step_names(&report);
        let clear = names
            .iter()
            .position(|s| *s == "clear_in_progress")
            .unwrap();
        assert_eq!(names[clear + 1], "prune_backups", "{names:?}");
    }

    #[tokio::test]
    async fn a_rollback_whose_marker_stays_does_not_prune_until_recover_clears_it() {
        let f = fixture(STOP_TRUE);
        old_backups(&f, 5);
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        let report = with_faults(
            [
                ("prune before backup", vec![Fault::Fail]),
                ("clear in-progress", vec![Fault::Fail]),
            ],
            deploy(&f),
        )
        .await
        .unwrap();
        assert!(!step_names(&report).contains(&"prune_backups"));
        assert_eq!(backups(&f).len(), 6);

        let report = recovered(&f).await.unwrap();

        assert!(step_names(&report).contains(&"prune_backups"));
        assert_eq!(backups(&f).len(), 3);
    }

    #[tokio::test]
    async fn the_backup_a_marker_names_is_never_pruned() {
        // A deploy that finished, with only its clean-up left. Its backup is
        // the oldest here, and a later `recover` may yet be told to use it.
        let f = fixture(STOP_TRUE);
        let old = old_backups(&f, 2);
        fs::create_dir(f.state.backups_dir().join("2030-01-01T00-00-00-000000000Z")).unwrap();
        f.state
            .set_in_progress(&InProgress {
                deploy_id: DEPLOY_ID.to_owned(),
                phase: Phase::Deploying,
                tag: f.plan.tag().clone(),
                digest: f.plan.digest().clone(),
                previous_can_start: true,
                backup: Some(RecordedBackup {
                    id: old[0].clone(),
                    paths: vec!["data".to_owned()],
                }),
                started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
            })
            .unwrap();
        f.state
            .set_deployed(&Deployed {
                deploy_id: DEPLOY_ID.to_owned(),
                ..earlier_release(&f)
            })
            .unwrap();

        let report = recover(
            &f.docker,
            &f.state,
            &f.deployment,
            &f.dir,
            &EngineOptions {
                backups_kept: 1,
                ..options()
            },
        )
        .await
        .unwrap();

        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(
            backups(&f),
            [old[0].clone(), "2030-01-01T00-00-00-000000000Z".to_owned()],
            "the newest, and the one named"
        );
    }

    #[tokio::test]
    async fn recover_without_in_progress_is_an_error() {
        let f = fixture("");
        let err = recovered(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::NothingToRecover(_)), "{err}");
        assert_eq!(f.docker.calls(), []);
    }

    #[tokio::test]
    async fn missing_compose_file_entry_refuses_before_stop() {
        let f = fixture(STOP_TRUE);
        let secret = "registry.example/app:token-s3cret";
        f.docker
            .script_compose_service([Ok(image(Some(secret))), Ok(image(Some(secret)))]);

        let err = deploy(&f).await.unwrap_err();

        assert!(
            matches!(err, DeployError::OverrideNotApplied { .. }),
            "{err}"
        );
        let text = format!("{err} {err:?}");
        assert!(
            text.contains("COMPOSE_FILE=compose.yaml:compose.landfall.yaml")
                && text.contains(".env"),
            "{text}"
        );
        assert!(!text.contains("s3cret"), "{text}");
        assert_eq!(changes(&f), ["config", "config"], "no pull, stop or up");
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
    }

    /// A refusal in the preflight: nothing was run after it, and nothing is left.
    fn refused_before_anything_changed(f: &Fixture, err: &DeployError) {
        assert_eq!(changes(f), ["config"], "{err}");
        assert_eq!(override_text(&f.dir), PREVIOUS, "{err}");
        assert_eq!(f.state.in_progress().unwrap(), None, "{err}");
    }

    #[tokio::test]
    async fn a_service_asking_for_several_containers_is_refused_naming_the_fix() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(ServiceConfig {
            replicas: 2,
            ..image(Some(OLD))
        })]);
        let err = deploy(&f).await.unwrap_err();
        assert!(
            matches!(err, DeployError::Scaled { replicas: 2, .. }),
            "{err}"
        );
        assert!(err.to_string().contains("deploy.replicas"), "{err}");
        refused_before_anything_changed(&f, &err);
    }

    #[tokio::test]
    async fn several_running_containers_are_refused_naming_the_fix() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let id = crate::testing::container_id();
        f.docker.script_containers([Ok(vec![id.clone(), id])]);
        let err = deploy(&f).await.unwrap_err();
        assert!(
            matches!(err, DeployError::SeveralContainers { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("--scale app=1"), "{err}");
        refused_before_anything_changed(&f, &err);
    }

    #[tokio::test]
    async fn a_second_project_in_the_directory_is_refused() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        let id = crate::testing::container_id();
        // One of its own by the project's name, two by the directory.
        f.docker
            .script_containers([Ok(vec![id.clone()]), Ok(vec![id.clone(), id])]);
        let err = deploy(&f).await.unwrap_err();
        assert!(
            matches!(err, DeployError::SeveralContainers { .. }),
            "{err}"
        );
        refused_before_anything_changed(&f, &err);
    }

    #[tokio::test]
    async fn a_failing_container_lookup_is_refused_before_the_marker() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker.script_container([Err("daemon gone")]);
        let err = deploy(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::Compose { .. }), "{err}");
        refused_before_anything_changed(&f, &err);
    }

    #[tokio::test]
    async fn service_without_an_image_after_the_override_is_refused_too() {
        let f = fixture("");
        f.docker.script_compose_service([Ok(image(None))]);
        let err = deploy(&f).await.unwrap_err();
        assert!(
            matches!(err, DeployError::OverrideNotApplied { .. }),
            "{err}"
        );
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn failing_compose_during_preflight_puts_the_override_back() {
        let f = fixture("");
        f.docker
            .script_compose_service([Ok(image(Some(OLD))), Err("bad project")]);
        let err = deploy(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::Compose { .. }), "{err}");
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn build_service_is_refused() {
        let f = fixture(STOP_TRUE);
        f.docker.script_compose_service([Ok(ServiceConfig {
            image: None,
            has_build: true,
            replicas: 1,
        })]);

        let err = deploy(&f).await.unwrap_err();

        assert!(matches!(err, DeployError::HasBuild { .. }), "{err}");
        assert!(err.to_string().contains("build"), "{err}");
        assert_eq!(changes(&f), ["config"]);
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }

    #[tokio::test]
    async fn symlinked_override_is_refused() {
        let f = fixture("");
        let elsewhere = f.dir.join("elsewhere");
        fs::write(&elsewhere, "not ours").unwrap();
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.dir.join(OVERRIDE_FILE)).unwrap();

        let err = deploy(&f).await.unwrap_err();

        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(f.docker.calls(), []);
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "not ours");
    }

    #[tokio::test]
    async fn oversized_override_is_refused() {
        let f = fixture("");
        fs::write(f.dir.join(OVERRIDE_FILE), vec![b'#'; 2 * 1024 * 1024]).unwrap();
        let err = deploy(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::File { .. }), "{err}");
        assert_eq!(f.docker.calls(), []);
    }

    #[tokio::test]
    async fn pull_failure_changes_nothing() {
        let f = fixture(STOP_TRUE);
        resolves(&f, Some(OLD));
        f.docker.script_pull([Err("manifest unknown")]);

        let err = deploy(&f).await.unwrap_err();

        assert!(matches!(err, DeployError::Pull { .. }), "{err}");
        assert_eq!(changes(&f), ["config", "config", "pull"]);
        assert_eq!(override_text(&f.dir), PREVIOUS);
        assert_eq!(f.state.in_progress().unwrap(), None);
        assert_eq!(
            f.state.previous_override().unwrap().as_deref(),
            Some(PREVIOUS.as_bytes()),
            "the marker promised it; it is what is in place anyway"
        );
        assert_eq!(f.state.deployed().unwrap(), None);
        assert_eq!(backups(&f), Vec::<String>::new());
    }

    #[tokio::test]
    async fn no_backup_declared_never_stops() {
        let f = fixture("");
        healthy_deploy(&f);
        assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
        assert_eq!(count_stops(&f), 0);

        let f = fixture("");
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        let report = deploy(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
        assert_eq!(count_stops(&f), 0, "rollback has nothing to restore either");
    }

    #[tokio::test]
    async fn stop_false_backs_up_without_stopping() {
        let f = fixture(STOP_FALSE);
        healthy_deploy(&f);
        let report = deploy(&f).await.unwrap();
        assert_eq!(report.outcome, Outcome::Deployed);
        assert_eq!(count_stops(&f), 0);
        let kept = backups(&f);
        assert_eq!(kept.len(), 1, "{kept:?}");
        assert_eq!(
            fs::read_to_string(f.state.backups_dir().join(&kept[0]).join("data/db")).unwrap(),
            "before"
        );
    }

    #[tokio::test]
    async fn report_is_written_on_every_outcome() {
        let deployed = fixture("");
        healthy_deploy(&deployed);
        let rolled_back = fixture("");
        resolves(&rolled_back, Some(OLD));
        failing_check(&rolled_back, OLD);
        let no_previous = fixture("");
        resolves(&no_previous, None);
        no_previous
            .docker
            .script_inspect([Ok(container(PINNED, false))]);
        let rollback_failed = fixture("");
        resolves(&rollback_failed, Some(OLD));
        rollback_failed.docker.script_compose_up([Err("no")]);

        for (f, kind) in [
            (&deployed, "deployed"),
            (&rolled_back, "rolled_back"),
            (&no_previous, "failed_no_previous"),
            (&rollback_failed, "rollback_failed"),
        ] {
            let report = deploy(f).await.unwrap();
            assert!(report.finished_at >= report.started_at);
            let written = reports(f);
            assert_eq!(written.len(), 1, "{kind}");
            assert_eq!(written[0]["outcome"]["kind"], kind);
            assert_eq!(written[0]["deployment"], "app/prod");
            assert_eq!(written[0]["tag"], "v1.2.3");
            assert_eq!(written[0]["digest"], DIGEST);
            let steps = written[0]["steps"].as_array().unwrap();
            assert_eq!(steps[0]["name"], "preflight", "{kind}");
            assert_eq!(steps[0]["result"]["status"], "ok", "{kind}");
            assert_eq!(steps.len(), report.steps.len(), "{kind}");
        }
    }

    #[tokio::test]
    async fn concurrent_deploy_is_busy() {
        let f = fixture("");
        let held = f.state.lock().unwrap();
        let err = deploy(&f).await.unwrap_err();
        assert!(matches!(err, DeployError::Busy(_)), "{err}");
        assert_eq!(f.docker.calls(), []);
        drop(held);

        healthy_deploy(&f);
        let (first, second) = tokio::join!(deploy(&f), deploy(&f));
        let busy = [&first, &second]
            .iter()
            .filter(|r| matches!(r, Err(DeployError::Busy(_))))
            .count();
        let done = [&first, &second]
            .iter()
            .filter(|r| matches!(r, Ok(report) if report.outcome == Outcome::Deployed))
            .count();
        assert_eq!((busy, done), (1, 1), "{first:?} {second:?}");
    }

    #[tokio::test]
    async fn plan_for_another_deployment_is_refused() {
        let f = fixture("");
        let mut plan = f.plan.clone();
        plan.deployment = "other/prod".parse().unwrap();
        let err = run(
            &f.docker,
            &f.state,
            &f.deployment,
            &f.dir,
            &plan,
            &options(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DeployError::PlanMismatch { .. }), "{err}");
        assert_eq!(f.docker.calls(), []);
    }

    #[test]
    fn plan_takes_digest_and_commit_from_the_verified_origin() {
        let d = deployment("");
        let origin = ReleaseOrigin {
            commit: COMMIT.parse().unwrap(),
            tag: None,
            attestation: VerifiedAttestation {
                digest: DIGEST.parse().unwrap(),
                san: String::new(),
                commit: COMMIT.parse().unwrap(),
                git_ref: String::new(),
                repo_id: 1,
                owner_id: 2,
                run_url: String::new(),
                rekor_log_index: 0,
                integrated_time: 0,
            },
            platforms: Vec::new(),
        };
        let plan = DeployPlan::from_verified(
            &d,
            &"v1.2.3".parse().unwrap(),
            semver::Version::new(1, 2, 3),
            &origin,
        );
        assert_eq!(plan.image(), PINNED);
        assert_eq!(plan.digest().as_ref(), DIGEST);
        assert_eq!(plan.commit().as_ref(), COMMIT);
        assert_eq!(plan.deployment(), d.id());
    }

    #[test]
    fn ids_sort_by_time_and_are_plain_names() {
        let times = [
            "2026-01-02T03:04:05Z",
            "2026-01-02T03:04:05.000000001Z",
            "2026-01-02T03:04:05.1Z",
            "2026-01-02T03:04:06Z",
            "2026-10-01T00:00:00Z",
            "2027-01-01T00:00:00Z",
        ];
        let ids: Vec<String> = times
            .iter()
            .map(|t| timestamp_id(t.parse().unwrap()))
            .collect();
        let mut sorted = ids.clone();
        sorted.sort();
        assert_eq!(ids, sorted);
        for id in &ids {
            assert!(
                id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
                "{id}"
            );
        }
        assert_eq!(ids[0], "2026-01-02T03-04-05-000000000Z");
    }

    /// A fixture whose override pins `image`.
    fn pinned_to(image: &str) -> Fixture {
        let f = fixture("");
        let file = compose::render_override(
            "app",
            image,
            f.plan.deployment(),
            f.plan.tag(),
            f.plan.commit(),
        );
        fs::write(f.dir.join(OVERRIDE_FILE), file).unwrap();
        f
    }

    #[tokio::test]
    async fn drift_is_reported() {
        let f = pinned_to(PINNED);
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert!(seen.drift);
        assert_eq!(seen.override_file, OverrideFile::Pinned);
        assert_eq!(seen.running_image_matches, Some(false));
        assert_eq!(seen.running_image, None, "it can hold a secret");
    }

    #[tokio::test]
    async fn no_drift_when_images_match() {
        let f = pinned_to(PINNED);
        f.docker.script_inspect([Ok(container(PINNED, true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert!(!seen.drift);
        assert_eq!(seen.running_image_matches, Some(true));
        assert_eq!(seen.running_image, Some(format!("{PINNED:?}")));
    }

    #[tokio::test]
    async fn drift_never_asks_compose() {
        let f = pinned_to(PINNED);
        f.docker.script_inspect([Ok(container(PINNED, true))]);
        drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert_eq!(changes(&f), Vec::<&str>::new());
        assert_eq!(
            f.docker.count(|c| matches!(c, Call::Container { .. })),
            0,
            "the lookup by project loads the stack's files"
        );
    }

    #[tokio::test]
    async fn nothing_pinned_and_nothing_on_record_is_not_drift() {
        let f = fixture("");
        for (file, expected) in [
            (None, OverrideFile::Missing),
            (Some(PLACEHOLDER), OverrideFile::Placeholder),
        ] {
            match file {
                Some(text) => fs::write(f.dir.join(OVERRIDE_FILE), text).unwrap(),
                None => fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap(),
            }
            f.docker.script_inspect([Ok(container(OLD, true))]);
            let seen = drift(&f.docker, &f.dir, "app", false).await.unwrap();
            assert_eq!(seen.override_file, expected);
            assert!(!seen.drift, "{expected:?}");
            assert_eq!(seen.running_image, None, "{expected:?}");
            assert_eq!(seen.running_image_matches, Some(false), "{expected:?}");
        }
    }

    #[tokio::test]
    async fn a_missing_override_with_a_deploy_on_record_is_drift() {
        let f = fixture("");
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert_eq!(seen.override_file, OverrideFile::Missing);
        assert!(seen.drift);
        assert_eq!(seen.running_image, None);

        // Nothing running, nothing to differ.
        f.docker.script_container([Ok(None)]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert!(!seen.drift);
        assert_eq!(seen.running_image_matches, None);
    }

    #[tokio::test]
    async fn an_override_the_agent_did_not_write_is_drift_and_is_not_quoted() {
        let f = fixture("");
        fs::write(f.dir.join(OVERRIDE_FILE), "services: {} # SECRET=hunter2\n").unwrap();
        f.docker.script_inspect([Ok(container(PINNED, true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert_eq!(seen.override_file, OverrideFile::Unrecognised);
        assert!(seen.drift);
        assert!(!format!("{seen:?}").contains("hunter2"));
    }

    #[tokio::test]
    async fn a_stopped_service_has_not_drifted() {
        let f = pinned_to(PINNED);
        f.docker.script_container([Ok(None)]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert!(!seen.drift);
        assert_eq!(seen.running_image, None);
        assert_eq!(seen.running_image_matches, None);
    }

    #[tokio::test]
    async fn a_symlinked_override_is_not_followed_by_drift() {
        let f = fixture("");
        let elsewhere = f.dir.join("elsewhere");
        fs::write(&elsewhere, PLACEHOLDER).unwrap();
        fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
        std::os::unix::fs::symlink(&elsewhere, f.dir.join(OVERRIDE_FILE)).unwrap();
        let err = drift(&f.docker, &f.dir, "app", true).await.unwrap_err();
        assert!(matches!(err, DriftError::Override(_)), "{err}");
    }

    #[tokio::test]
    async fn a_long_pinned_image_is_quoted_and_truncated_by_drift() {
        let long = format!("ghcr.io/example/{}", "x".repeat(4096));
        let f = pinned_to(&long);
        f.docker.script_inspect([Ok(container(&long, true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        let shown = seen.running_image.unwrap();
        assert!(shown.starts_with("\"ghcr.io/example/"), "{shown}");
        assert!(shown.len() < 512, "{}", shown.len());
    }

    #[tokio::test]
    async fn an_image_that_is_not_the_pinned_one_is_never_shown() {
        let f = pinned_to(PINNED);
        f.docker
            .script_inspect([Ok(container("registry.example/app:hunter2", true))]);
        let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
        assert!(!format!("{seen:?}").contains("hunter2"), "{seen:?}");
        assert_eq!(seen.running_image_matches, Some(false));
    }

    /// Against a real Docker daemon, as in `checks.rs`.
    mod real {
        use super::{
            DeployError, DeployPlan, OVERRIDE_FILE, PREVIOUS, STOP_TRUE, StateDir, deployment, fs,
            options, run,
        };
        use crate::docker::{Docker, DockerCli};
        use crate::testing::{ComposeProject, TEST_IMAGE};

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_broken_compose_file_is_refused_before_stop() {
            let cli = DockerCli::new();
            let services = format!(
                "  app:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n"
            );
            let project = ComposeProject::new(&cli, &services).await;
            let dir = project.path().canonicalize().unwrap();
            let file = dir.join("compose.yaml");
            fs::write(
                dir.join(".env"),
                format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
            )
            .unwrap();
            fs::write(dir.join(OVERRIDE_FILE), PREVIOUS).unwrap();
            cli.compose_up(&dir, "app").await.unwrap();
            let id = cli.container(&dir, "app").await.unwrap().unwrap();
            let started = cli.inspect(&id).await.unwrap().started_at;

            // A file that `up` cannot use: the lenient read does not mind.
            fs::write(
                &file,
                format!(
                    "name: {}\nservices:\n{services}    networks: [missing]\n",
                    project.name
                ),
            )
            .unwrap();
            let lenient = cli.compose_service(&dir, "app").await;

            let state_root = tempfile::tempdir().unwrap();
            let d = deployment(STOP_TRUE);
            let state = StateDir::open(state_root.path())
                .unwrap()
                .deployment(d.id())
                .unwrap();
            let digest = format!("sha256:{}", "a".repeat(64));
            let plan = DeployPlan::for_test(&d, "v1.2.3", &digest, &"b".repeat(40));
            let result = run(&cli, &state, &d, &dir, &plan, &options()).await;

            lenient.expect("the lenient read lets the broken file through");
            let err = result.expect_err("a project `up` cannot use is refused");
            assert!(matches!(err, DeployError::Compose { .. }), "{err}");
            let after = cli.inspect(&id).await.unwrap();
            assert_eq!(after.status, "running");
            assert_eq!(after.started_at, started, "never stopped or restarted");
            assert_eq!(
                fs::read_to_string(dir.join(OVERRIDE_FILE)).unwrap(),
                PREVIOUS
            );
            assert_eq!(state.in_progress().unwrap(), None);
        }
    }
}
