//! The deploy sequence and rollback (design 7.2): pull, back up, switch,
//! check, and on any failure put back the previous version and its data,
//! recording every step.

use std::fmt::Display;
use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use jiff::Timestamp;
use jiff::tz::TimeZone;
use landfall_core::config::{Backup, Deployment};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_origin::release::ReleaseOrigin;
use serde::Serialize;

use crate::checks::{CheckFailure, CheckOptions, quote, run_checks};
use crate::compose;
use crate::docker::{Docker, DockerError};
use crate::journal::{self, Priority};
use crate::safefs::{self, RelPath, Root, SafeFsError};
use crate::state::{DeployLock, Deployed, DeploymentState, InProgress, StateError};

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
            Self::RolledBack { .. } => Priority::Warning,
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
    /// A backup was taken, and the configuration no longer says of what.
    #[error("the configuration no longer declares the backup's paths")]
    BackupNotDeclared,
}

/// A deploy that never started: nothing was changed. Anything after that is a
/// [`DeployReport`].
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
    /// The preflight was refused or failed, and the previous override could
    /// not be put back either.
    #[error("{refused}; putting the previous override back also failed: {source}")]
    PutBack {
        /// Why the deploy was not started.
        refused: Box<DeployError>,
        /// Why the override could not be put back.
        source: FileFailure,
    },
}

/// Deploys `plan`: preflight, pull, then with `in-progress.json` written
/// backup, override, `up`, image check and post-deploy checks. A failure after
/// `in-progress.json` rolls back. The report is written before this returns,
/// on every outcome, and the outcome goes to the journal.
///
/// # Errors
///
/// [`DeployError`] when the deploy never started: the deployment is locked or
/// has an interrupted deploy, the preflight refused, or the pull failed.
/// Nothing was changed, other than a placeholder override where there was none.
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
        };
        engine.deploy(plan).await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

/// Finishes an interrupted deploy: rolls it back, under the same rules as a
/// failed one, unless it had already been recorded as deployed. The report is
/// written and the outcome journalled as for [`run`]. A rollback that fails
/// again leaves the deploy interrupted, so this can be retried.
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
        };
        engine.recover().await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

/// The largest override the agent reads. It writes far less; the file is in a
/// directory others can write to.
const OVERRIDE_CAP: usize = 1024 * 1024;
const OVERRIDE_MODE: u32 = 0o644;
const WRONG_PREVIOUS_IMAGE: &str =
    "the container does not run the image the compose project resolves to";

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

/// Runs blocking file work on a thread of its own, up to `deadline`. A thread
/// cannot be cancelled, so past the deadline the work may still be running:
/// that is reported as a failure, and the thread keeps its share of the
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
    let held = Arc::clone(lock);
    let task = tokio::task::spawn_blocking(move || {
        let _held = held;
        work()
    });
    match tokio::time::timeout(deadline, task).await {
        Ok(Ok(result)) => result.map_err(Into::into),
        Ok(Err(_)) => Err(FileFailure::Panicked { op }),
        Err(_) => Err(FileFailure::Deadline {
            op,
            after: deadline,
        }),
    }
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

fn backup_paths(backup: &Backup) -> Result<Vec<RelPath>, SafeFsError> {
    backup.paths().iter().map(|p| RelPath::new(p)).collect()
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
        #[derive(Serialize)]
        struct StepEvent<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            tag: &'a ReleaseTag,
            step: &'a Step,
        }
        let started_at = Timestamp::now();
        let clock = Instant::now();
        let outcome = work.await;
        let step = Step {
            name: name.to_owned(),
            started_at,
            millis: u64::try_from(clock.elapsed().as_millis()).unwrap_or(u64::MAX),
            result: match &outcome {
                Ok(_) => StepResult::Ok,
                Err(error) => StepResult::Failed {
                    reason: error.to_string(),
                },
            },
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
        self.step(name, work)
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
        off_thread(&self.lock, op, self.options.file_deadline, work).await
    }

    async fn read_override(&self) -> Result<Option<Vec<u8>>, FileFailure> {
        let dir = self.dir.to_owned();
        self.file("read override", move || {
            let root = Root::open(&dir)?;
            let name = RelPath::new(compose::OVERRIDE_FILE)?;
            safefs::read_file(&root, &name, OVERRIDE_CAP)
        })
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
            source => DeployError::Compose {
                deployment: self.deployment.id().clone(),
                source,
            },
        }
    }

    /// Everything that can be refused before anything stops. The project is
    /// read with the override in place, then with the new one, which is then
    /// taken back out: nothing else may see it before the backup.
    async fn preflight(&self, plan: &DeployPlan) -> Result<Preflight, DeployError> {
        if let Some(backup) = self.deployment.backup() {
            backup_paths(backup).map_err(|source| DeployError::BackupPath {
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
        let new = compose::render_override(
            self.service(),
            plan.image(),
            plan.deployment(),
            plan.tag(),
            plan.commit(),
        );
        self.write_override(new.into_bytes())
            .await
            .map_err(|e| self.file_error(e))?;
        let resolved = self.docker.compose_service(self.dir, self.service()).await;
        let put_back = self.write_override(previous.clone()).await;
        let checked = match resolved {
            Ok(service) if service.image.as_deref() == Some(plan.image()) => Ok(()),
            // What it did resolve to stays out of this: it can hold a secret.
            Ok(_) => Err(DeployError::OverrideNotApplied {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
                pinned: plan.image().to_owned(),
            }),
            Err(error) => Err(self.compose_error(error)),
        };
        match (checked, put_back) {
            (Ok(()), Ok(())) => Ok(Preflight {
                previous,
                previous_can_start: base.image.is_some(),
            }),
            (Err(refused), Ok(())) => Err(refused),
            (Ok(()), Err(source)) => Err(self.file_error(source)),
            (Err(refused), Err(source)) => Err(DeployError::PutBack {
                refused: Box::new(refused),
                source,
            }),
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
        let preflight = rec.step("preflight", self.preflight(plan)).await?;
        rec.step("pull", async {
            self.docker
                .pull(plan.image())
                .await
                .map_err(|source| DeployError::Pull {
                    deployment: self.deployment.id().clone(),
                    image: plan.image().to_owned(),
                    source,
                })
        })
        .await?;
        let mut marker = InProgress {
            tag: plan.tag().clone(),
            digest: plan.digest().clone(),
            previous_can_start: preflight.previous_can_start,
            backup: None,
            started_at: Timestamp::now(),
        };
        // The previous override first: in-progress promises it can be restored.
        let state = self.state.clone();
        let first = marker.clone();
        let previous = preflight.previous;
        rec.step("record_in_progress", async {
            self.file("record in-progress", move || {
                state.set_previous_override(&previous)?;
                state.set_in_progress(&first)
            })
            .await
            .map_err(|e| self.file_error(e))
        })
        .await?;

        // From here on, the report tells how it went.
        let outcome = match self.forward(plan, &mut rec, &mut marker).await {
            Ok(()) => {
                // The release is in and recorded: a failure to remove old
                // backups is in the report, and doesn't undo the deploy.
                let _ = rec.step("prune_backups", self.prune()).await;
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
        let state = self.state.clone();
        let deployed = self
            .file("read deployed", move || state.deployed())
            .await
            .map_err(|e| self.file_error(e))?;
        let mut rec = Recorder::new(self.deployment.id(), &marker.tag, &marker.digest);
        // The sequence records the release and then clears the marker, so a
        // record of this very release made after the marker was written means
        // it passed its checks and only the clearing is left.
        let finished = deployed.is_some_and(|d| {
            d.digest == marker.digest && d.tag == marker.tag && d.deployed_at >= marker.started_at
        });
        let outcome = if finished {
            let _ = rec.step("prune_backups", self.prune()).await;
            Outcome::Deployed
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
            if backup.stop() {
                rec.must("stop", self.stop()).await?;
            }
            let id = timestamp_id(Timestamp::now());
            rec.must("backup", self.backup(backup, &id)).await?;
            let mut with_backup = marker.clone();
            with_backup.backup = Some(id);
            let state = self.state.clone();
            let record = with_backup.clone();
            rec.must(
                "record_backup",
                self.file("record backup", move || state.set_in_progress(&record)),
            )
            .await?;
            *marker = with_backup;
        }
        let new = compose::render_override(
            self.service(),
            plan.image(),
            plan.deployment(),
            plan.tag(),
            plan.commit(),
        );
        rec.must("write_override", self.write_override(new.into_bytes()))
            .await?;
        let since = Timestamp::now();
        rec.must("up", self.up()).await?;
        rec.must("verify_image", self.verify_pinned(plan.image()))
            .await?;
        rec.must("checks", self.check_pinned(plan.image(), since))
            .await?;
        let state = self.state.clone();
        let deployed = Deployed {
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
    /// brought up, and returns the image the final round saw.
    async fn checks(&self, since: Timestamp) -> Result<String, CheckFailure> {
        run_checks(
            self.docker,
            self.dir,
            self.service(),
            self.deployment.checks(),
            since,
            &self.options.checks,
        )
        .await
        .map(|summary| summary.image)
    }

    /// The checks, and the pinned image still running when they ended.
    async fn check_pinned(&self, pinned: &str, since: Timestamp) -> Result<(), String> {
        let image = self.checks(since).await.map_err(|e| e.to_string())?;
        if image == pinned {
            Ok(())
        } else {
            Err(format!(
                "the checks passed, on a container running {}, not {pinned}",
                quote(&image)
            ))
        }
    }

    /// The checks, and the previous image still running when they ended. As
    /// in [`Self::verify_previous`], neither image is named.
    async fn check_previous(&self, resolved: &str, since: Timestamp) -> Result<(), String> {
        let image = self.checks(since).await.map_err(|e| e.to_string())?;
        if image == resolved {
            Ok(())
        } else {
            Err(WRONG_PREVIOUS_IMAGE.to_owned())
        }
    }

    /// A snapshot failure of any kind is a failed backup. That includes a
    /// missing path: a container that keeps running could otherwise make a
    /// backup incomplete by deleting a file.
    async fn backup(&self, backup: &Backup, id: &str) -> Result<(), FileFailure> {
        let paths = backup_paths(backup)?;
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
                safefs::snapshot(&source, &paths, &dest)?;
                Ok(())
            },
        )
        .await
    }

    async fn prune(&self) -> Result<(), FileFailure> {
        let backups = self.state.backups_dir();
        let keep = self.options.backups_kept;
        off_thread(
            &self.lock,
            "prune backups",
            self.options.backup_deadline,
            move || safefs::prune(&backups, keep),
        )
        .await
    }

    /// The image of the service's container, as it says.
    async fn running_image(&self) -> Result<String, String> {
        let id = self
            .docker
            .container(self.dir, self.service())
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("service {} has no container", quote(self.service())))?;
        let info = self.docker.inspect(&id).await.map_err(|e| e.to_string())?;
        Ok(info.image)
    }

    async fn verify_pinned(&self, pinned: &str) -> Result<(), String> {
        let running = self.running_image().await?;
        if running == pinned {
            Ok(())
        } else {
            Err(format!(
                "the container runs {}, not {pinned}",
                quote(&running)
            ))
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
                self.clear_in_progress(rec).await;
                if marker.previous_can_start {
                    Outcome::RolledBack { reason }
                } else {
                    Outcome::FailedNoPrevious { reason }
                }
            }
            // The marker stays: deploys stay blocked, and `recover` can try
            // again from the same previous state and backup.
            Err(rollback_reason) => Outcome::RollbackFailed {
                reason,
                rollback_reason,
            },
        }
    }

    /// Back to the previous state. Each step depends on the one before: with
    /// the service still running a restore could be outrun, and half-restored
    /// data is not to be started, so the first failure ends it.
    async fn rollback(&self, rec: &mut Recorder, marker: &InProgress) -> Result<(), String> {
        let state = self.state.clone();
        let previous = rec
            .must("read_previous_override", async {
                self.file("read previous override", move || state.previous_override())
                    .await?
                    .ok_or(FileFailure::NoPreviousOverride)
            })
            .await?;
        rec.must("restore_override", self.write_override(previous))
            .await?;
        let mut stopped = false;
        if let Some(id) = &marker.backup {
            rec.must("stop_for_restore", self.stop()).await?;
            stopped = true;
            rec.must("restore_backup", self.restore(id)).await?;
        }
        if marker.previous_can_start {
            let since = Timestamp::now();
            rec.must("start_previous", self.up()).await?;
            let resolved = rec
                .must("verify_previous_image", self.verify_previous())
                .await?;
            rec.must("check_previous", self.check_previous(&resolved, since))
                .await?;
        } else if !stopped {
            rec.must("stop_service", self.stop()).await?;
        }
        Ok(())
    }

    async fn restore(&self, id: &str) -> Result<(), FileFailure> {
        // The configuration can have changed before a `recover`.
        let backup = self
            .deployment
            .backup()
            .ok_or(FileFailure::BackupNotDeclared)?;
        let paths = backup_paths(backup)?;
        let dir = self.dir.to_owned();
        let snapshot = self.state.backups_dir().join(id);
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
    /// blocked; what is running is still what the outcome says.
    async fn clear_in_progress(&self, rec: &mut Recorder) {
        let state = self.state.clone();
        let _ = rec
            .step(
                "clear_in_progress",
                self.file("clear in-progress", move || state.clear_in_progress()),
            )
            .await;
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
            self.clear_in_progress(&mut rec).await;
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

    use super::{
        DeployError, DeployPlan, EngineOptions, Outcome, ReleaseOrigin, StepResult, recover, run,
        timestamp_id,
    };
    use crate::checks::CheckOptions;
    use crate::compose::{self, OVERRIDE_FILE, PLACEHOLDER};
    use crate::docker::{ContainerInfo, ServiceConfig};
    use crate::journal::Priority;
    use crate::safefs::{self, RelPath, Root};
    use crate::state::{Deployed, DeploymentState, InProgress, StateDir};
    use crate::testing::{Call, FakeDocker, running};
    use std::time::Duration;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const PINNED: &str = "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OLD: &str = "ghcr.io/example/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const PREVIOUS: &str = "# the previous override\nservices: {}\n";
    const STOP_TRUE: &str = "backup = { paths = [\"data\"], stop = true }\n";
    const STOP_FALSE: &str = "backup = { paths = [\"data\"], stop = false }\n";

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
                Call::ComposeService { .. } => Some("config"),
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
            if !matches!(call, Call::Container { .. } | Call::Inspect(_)) {
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
            f.docker.calls()[2],
            Call::Pull(PINNED.to_owned()),
            "pulled by digest"
        );
        assert_eq!(
            step_names(&report),
            [
                "preflight",
                "pull",
                "record_in_progress",
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
                if reason.contains("verify_image") && reason.contains("example/other:latest")),
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
                if reason.contains("checks") && reason.contains("example/other:latest")),
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
    async fn hostile_running_image_is_quoted_and_truncated() {
        let f = fixture("");
        resolves(&f, Some(OLD));
        let hostile = format!("evil\n<2>forged{}", "x".repeat(16 * 1024 * 1024));
        f.docker
            .script_inspect_after_up(1, [Ok(container(&hostile, true))]);
        f.docker
            .script_inspect_after_up(2, [Ok(container(OLD, true))]);

        let report = deploy(&f).await.unwrap();

        let Outcome::RolledBack { reason } = &report.outcome else {
            panic!("{:?}", report.outcome);
        };
        assert!(reason.len() < 1024, "{}", reason.len());
        assert!(!reason.contains('\n'), "{reason}");
        let written = serde_json::to_string(&reports(&f)).unwrap();
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
        assert_ne!(f.state.in_progress().unwrap(), None);
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
                tag: f.plan.tag().clone(),
                digest: f.plan.digest().clone(),
                previous_can_start: true,
                backup: Some(id.to_owned()),
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
                tag: f.plan.tag().clone(),
                digest: f.plan.digest().clone(),
                previous_can_start: true,
                backup: None,
                started_at,
            })
            .unwrap();
        f.state
            .set_deployed(&Deployed {
                tag: f.plan.tag().clone(),
                version: f.plan.version().clone(),
                digest: f.plan.digest().clone(),
                commit: f.plan.commit().clone(),
                deployed_at: "2026-11-01T10:01:00Z".parse().unwrap(),
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
        // deployed.json names the same digest, but from before this deploy.
        let f = fixture(STOP_TRUE);
        f.state
            .set_deployed(&Deployed {
                tag: f.plan.tag().clone(),
                version: f.plan.version().clone(),
                digest: f.plan.digest().clone(),
                commit: f.plan.commit().clone(),
                deployed_at: "2026-11-01T09:00:00Z".parse().unwrap(),
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
        assert_eq!(f.state.previous_override().unwrap(), None);
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
}
