//! The deploy sequence and rollback (design 7.2): pull, back up, switch,
//! check, and on any failure put back the previous version and its data,
//! recording every step.

use std::fmt::Display;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use jiff::Timestamp;
use landfall_core::config::Deployment;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_origin::release::ReleaseOrigin;
use serde::Serialize;

use crate::checks::CheckOptions;
use crate::compose;
use crate::docker::{Docker, DockerError};
use crate::journal::{self, Priority};
use crate::safefs::{self, RelPath, Root};
use crate::state::{DeployLock, DeploymentState};
use files::{OVERRIDE_MODE, read_override_file};
use offload::off_thread;
use report::millis;

mod drift;
mod error;
#[cfg(test)]
mod faults;
mod files;
mod offload;
mod preflight;
mod recovery;
mod report;
mod rollback;
mod sequence;
#[cfg(test)]
mod tests;

pub use drift::{Drift, DriftError, OverrideFile, drift};
pub use error::{DeployError, FileFailure};
pub(crate) use offload::{Unfinished, on_thread_within};
pub use recovery::recover;
pub use report::{CheckTiming, DeployReport, Outcome, Step, StepDetail, StepResult};
pub use sequence::{run, run_holding};

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
    /// A backup or a prune ran past its deadline and may still be at work in
    /// the backups directory. See [`Self::prune`].
    backups_outran_deadline: AtomicBool,
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

    /// Work in the backups directory, under the backup's deadline.
    async fn on_backups<T, E>(
        &self,
        op: &'static str,
        work: impl FnOnce() -> Result<T, E> + Send + 'static,
    ) -> Result<T, FileFailure>
    where
        T: Send + 'static,
        E: Into<FileFailure> + Send + 'static,
    {
        let result = off_thread(&self.lock, op, self.options.backup_deadline, work).await;
        if matches!(result, Err(FileFailure::Deadline { .. })) {
            self.backups_outran_deadline.store(true, Ordering::SeqCst);
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
}
