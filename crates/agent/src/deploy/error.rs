//! Why a deploy never started or a file operation failed.

use std::time::Duration;

use landfall_core::ids::{DeploymentId, ReleaseTag};

use crate::compose;
use crate::docker::DockerError;
use crate::safefs::SafeFsError;
use crate::state::StateError;

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
    /// Work that ran past its deadline may still be running on the backups,
    /// and a prune would take its unfinished copy for a leftover.
    #[error("skipped: work that ran past its deadline may still be running on the backups")]
    PruneSkipped,
}

/// A deploy that never started: no service was touched and no backup taken.
/// Everything the attempt changed has been put back, other than a placeholder
/// override where there was none, unless the error is
/// [`DeployError::LeftBlocked`]. Anything after that is a [`DeployReport`](super::DeployReport).
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
    /// The project asks for another number of containers of the service than one.
    #[error(
        "deployment {deployment}: service {service:?} asks for {replicas} containers; landfall deploys a service with exactly one, so remove `scale` and `deploy.replicas` from the compose file"
    )]
    Scaled {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
        /// How many it asks for.
        replicas: u64,
    },
    /// A container started from this directory is not the project's: a backup
    /// or a restore would run under it while it writes.
    #[error(
        "deployment {deployment}: service {service:?} has a running container started from this directory that is not in the project the directory's files name now, and it would keep writing during a backup or a restore; remove it with `docker compose -p <other> down`, or put the project's name back"
    )]
    OutsideTheProject {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
    },
    /// The project's container of the service was started from elsewhere: a
    /// deploy would stop and replace what may be another stack's service.
    #[error(
        "deployment {deployment}: the running container of service {service:?} in this directory's project was started from {found}, not from this directory, so a deploy would stop and replace it; if that is another stack, give each its own project with a unique `name:` or `COMPOSE_PROJECT_NAME`, and if it is this one, keep its compose file in the compose directory and recreate the container from there"
    )]
    StartedElsewhere {
        /// The deployment.
        deployment: DeploymentId,
        /// The service.
        service: String,
        /// The directory its label names, quoted and truncated.
        found: String,
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
