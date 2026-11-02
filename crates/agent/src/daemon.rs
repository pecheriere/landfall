//! `landfall-agent run`: polls the controller for work and, when it may, deploys.
//!
//! The controller may be compromised: it can only ask. For every work item the
//! host goes by its own configuration and its own records: the
//! deployment must be this host's, with no unfinished deploy and no drift; the
//! deployment's rule must make the move from what
//! [`Deployed`](crate::state::Deployed) says to the tag `Auto`; and the release
//! must verify, with this host's trust root, to the digest and commit asked for.
//! Anything else is journalled and reported, and nothing runs: as refused when that
//! is final, and as deferred when its cause may pass.
//!
//! The report of a deploy goes in the outbox in the state directory before it is
//! sent, and leaves when the controller has acknowledged it. The
//! controller's number for the deploy is on disk before the engine starts
//! ([`ControllerClaim`]), so whatever a crash or a `recover` leaves behind is
//! reported under the right number. A claim with nothing to show for it means
//! the deploy never started: it is dropped, and the controller delivers the work
//! again under the same number.

use std::collections::BTreeMap;
use std::convert::Infallible;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use landfall_core::config::{self, Config, ConfigError, Deployment};
use landfall_core::ids::{DeploymentId, HostId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{
    DeployId, DeployReportBody, DeployWork, HeldBack, ReportedOutcome, SigningKey,
};
use landfall_core::text::shown;
use landfall_origin::fetch::FetchError;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::client::{Controller, ControllerError, ControllerUrl, HttpController};
use crate::compose::{self, ComposeError};
use crate::deploy::{self, DeployError, DeployPlan, EngineOptions, Unfinished};
use crate::docker::{Docker, DockerCli};
use crate::enrol::{self, EnrolError};
use crate::journal::{self, Priority};
use crate::state::{
    ControllerClaim, DeployLock, DeploymentState, FailedRelease, FinishedDeploy, StateDir,
    StateError,
};

mod control;
mod judge;
mod outbox;
mod running;
mod verifier;

pub use control::{Backoff, Pacing, Shutdown, ShutdownTrigger};
pub use verifier::{OriginVerifier, Verifier, VerifyFailure};

use judge::{Verdict, judge};
use outbox::Keep;
use running::{Memory, work_request};

/// Between polls that went well. The controller holds a poll with no work, so
/// this only matters if it answers at once.
const POLL_FLOOR: Duration = Duration::from_secs(1);
const BACKOFF_MIN: Duration = Duration::from_secs(1);
const BACKOFF_MAX: Duration = Duration::from_mins(5);
/// How often a running deploy's state goes to the controller.
const HEARTBEAT: Duration = Duration::from_secs(10);
/// How often a deployment's drift is looked at. A deploy always looks first.
const DRIFT_EVERY: Duration = Duration::from_mins(1);
/// See [`DaemonOptions::verification_bound`].
const VERIFICATION_BOUND: Duration = Duration::from_hours(1);
/// How long a read or write of the state directory may take.
const FILE_LIMIT: Duration = Duration::from_secs(60);
/// The most entries of `held_back` that reach the journal.
const MAX_HELD_BACK_SHOWN: usize = 16;

/// How the daemon runs.
#[derive(Debug)]
pub struct DaemonOptions {
    /// This host's deployments and their compose directories.
    pub dirs: BTreeMap<DeploymentId, PathBuf>,
    /// SHA-256 of the configuration file.
    pub config_hash: [u8; 32],
    /// Timing of the deploy engine.
    pub engine: EngineOptions,
    /// How often a running deploy's state goes to the controller.
    pub heartbeat: Duration,
    /// How often a deployment's drift is looked at.
    pub drift_every: Duration,
    /// How long verification that can't run, for any reason, is waited for before
    /// the work item is answered with not now, which frees the host.
    pub verification_bound: Duration,
    /// What stops the daemon.
    pub shutdown: Shutdown,
    memory: Memory,
}

impl DaemonOptions {
    /// The default timing, for `dirs`.
    #[must_use]
    pub fn new(
        dirs: BTreeMap<DeploymentId, PathBuf>,
        config_hash: [u8; 32],
        shutdown: Shutdown,
    ) -> Self {
        Self {
            dirs,
            config_hash,
            engine: EngineOptions::default(),
            heartbeat: HEARTBEAT,
            drift_every: DRIFT_EVERY,
            verification_bound: VERIFICATION_BOUND,
            shutdown,
            memory: Memory::default(),
        }
    }
}

/// What one [`step`] came to.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StepOutcome {
    /// The controller had nothing for this host.
    NoWork,
    /// A work item was dealt with: deployed, rolled back or refused.
    Finished {
        /// The controller's deploy.
        deploy_id: DeployId,
        /// How it ended, as reported.
        outcome: ReportedOutcome,
        /// Whether the controller acknowledged the report. If not, it is sent
        /// again, unless the controller refused it for good.
        delivered: bool,
    },
    /// A work item that had finished was delivered again, and was answered with
    /// its original report. Nothing ran.
    Replayed {
        /// The controller's deploy.
        deploy_id: DeployId,
        /// How it ended, the first time.
        outcome: ReportedOutcome,
        /// Whether the controller acknowledged the report this time.
        delivered: bool,
    },
    /// A work item can't be dealt with now, and nothing was reported: the
    /// controller delivers it again.
    Waiting {
        /// The controller's deploy.
        deploy_id: DeployId,
        /// Why.
        reason: String,
    },
    /// The controller could not be reached, or won't answer yet.
    Unavailable {
        /// Why.
        error: String,
    },
    /// The agent's own state stood in the way.
    Failed {
        /// Why.
        error: String,
    },
    /// A stop was asked for, and nothing is running.
    ShuttingDown,
}

/// Runs file work on a thread, so that a hung disk ends in an error.
async fn on_thread<T: Send + 'static>(
    op: &'static str,
    work: impl FnOnce() -> Result<T, StateError> + Send + 'static,
) -> Result<T, String> {
    match deploy::on_thread_within(FILE_LIMIT, work).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(error)) => Err(format!("{op}: {error}")),
        Err(Unfinished::Deadline) => Err(format!("{op}: still running after {FILE_LIMIT:?}")),
        Err(Unfinished::Panicked) => Err(format!("{op}: the thread doing it panicked")),
    }
}

fn deployment_state(state_dir: &Path, id: &DeploymentId) -> Result<DeploymentState, StateError> {
    StateDir::open(state_dir)?.deployment(id)
}

/// Sends the host's state while a deploy runs, so the controller can tell a
/// long deploy from a dead agent. What comes back is left alone: one deploy runs
/// at a time, and work the controller has claimed is delivered again.
async fn heartbeats<D: Docker, C: Controller>(
    docker: &D,
    controller: &C,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
    deploying: &DeploymentId,
) -> Infallible {
    #[derive(Serialize)]
    struct Missed {
        event: &'static str,
        error: String,
    }
    loop {
        tokio::time::sleep(options.heartbeat).await;
        let request = work_request(docker, config, state_dir, options, Some(deploying)).await;
        if let Err(error) = controller.work(&request).await {
            journal::emit(
                Priority::Info,
                &Missed {
                    event: "heartbeat_missed",
                    error: error.to_string(),
                },
            );
        }
    }
}

/// A work item the host has said yes to.
struct Approved<'a> {
    work: &'a DeployWork,
    plan: &'a DeployPlan,
    deployment: &'a Deployment,
    dir: &'a Path,
}

/// The claim, the engine beside its heartbeats, and the report.
async fn deploy_approved<D: Docker, C: Controller>(
    docker: &D,
    controller: &C,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
    approved: Approved<'_>,
) -> StepOutcome {
    #[derive(Serialize)]
    struct LeftBlocked<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        deploy_id: DeployId,
        error: String,
    }
    let Approved {
        work,
        plan,
        deployment,
        dir,
    } = approved;
    let id = deployment.id();
    let (root, owned, deploy_id, tag, digest) = (
        state_dir.to_owned(),
        id.clone(),
        work.deploy_id,
        plan.tag().clone(),
        plan.digest().clone(),
    );
    let claimed = on_thread("record claim", move || {
        let state = deployment_state(&root, &owned)?;
        state.set_claim(&ControllerClaim {
            deploy_id,
            tag,
            digest,
            reports_before: state.report_names()?,
        })?;
        Ok(state)
    })
    .await;
    let state = match claimed {
        Ok(state) => state,
        Err(error) => return StepOutcome::Failed { error },
    };
    let result = tokio::select! {
        biased;
        result = Box::pin(deploy::run(docker, &state, deployment, dir, plan, &options.engine)) => result,
        never = heartbeats(docker, controller, config, state_dir, options, id) => match never {},
    };
    options.memory.forget_drift(id);
    let body = match result {
        Ok(report) => {
            if outbox::is_failure(&report.outcome) {
                let release = FailedRelease {
                    tag: report.tag.clone(),
                    digest: report.digest.clone(),
                };
                outbox::remember_failure(state_dir, id, release).await;
            }
            outbox::reported(work.deploy_id, &report)
        }
        Err(error @ DeployError::LeftBlocked { .. }) => {
            // The marker stays, and with it the claim: `recover` ends this one.
            let reason = error.to_string();
            journal::emit(
                Priority::Critical,
                &LeftBlocked {
                    event: "deploy_left_blocked",
                    deployment: id,
                    deploy_id: work.deploy_id,
                    error: reason.clone(),
                },
            );
            return StepOutcome::Waiting {
                deploy_id: work.deploy_id,
                reason,
            };
        }
        Err(error @ DeployError::Busy(_)) => {
            // A `recover` by hand has the lock, and this never started. A claim
            // that can't be cleared now is settled at the next step.
            let copy = state.clone();
            let _ = on_thread("clear claim", move || copy.clear_claim()).await;
            return StepOutcome::Waiting {
                deploy_id: work.deploy_id,
                reason: error.to_string(),
            };
        }
        Err(error) => DeployReportBody {
            deploy_id: work.deploy_id,
            deployment: work.deployment.clone(),
            tag: work.tag.clone(),
            digest: work.digest.clone(),
            outcome: ReportedOutcome::NothingChanged {
                reason: outbox::bounded(&error.to_string()),
            },
            steps: Vec::new(),
        },
    };
    let keep = Keep::Finished {
        record: finished_record(work, &body),
        claimed: Some(id),
    };
    outbox::finish(controller, state_dir, body, keep).await
}

fn journal_held_back(held_back: &[HeldBack], options: &DaemonOptions) {
    #[derive(Serialize)]
    struct Held<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        reason: String,
    }
    let mut last = running::locked(&options.memory.held_back);
    if last.as_slice() == held_back {
        return;
    }
    held_back.clone_into(&mut last);
    for entry in held_back.iter().take(MAX_HELD_BACK_SHOWN) {
        journal::emit(
            Priority::Warning,
            &Held {
                event: "controller_holds_back",
                deployment: &entry.deployment,
                reason: shown(&entry.reason),
            },
        );
    }
}

/// What the ledger keeps of a work item that has ended with `body`.
fn finished_record(work: &DeployWork, body: &DeployReportBody) -> FinishedDeploy {
    FinishedDeploy {
        deployment: work.deployment.clone(),
        tag: work.tag.clone(),
        digest: work.digest.clone(),
        report: body.clone(),
    }
}

/// How a work item that didn't run is answered.
enum Answer {
    /// For good: on record, so that the same number gets this answer again.
    Refused,
    /// Not now, and nothing to remember: it is judged afresh if it comes again.
    Deferred,
}

/// Journals and reports that a work item won't run. Nothing has run.
async fn answer_work<C: Controller>(
    controller: &C,
    state_dir: &Path,
    work: &DeployWork,
    answer: Answer,
    (priority, reason): (Priority, &str),
) -> StepOutcome {
    #[derive(Serialize)]
    struct Answered<'a> {
        event: &'static str,
        deploy_id: DeployId,
        deployment: &'a DeploymentId,
        tag: &'a ReleaseTag,
        digest: &'a ImageDigest,
        reason: &'a str,
    }
    let reported = outbox::bounded(reason);
    let (event, outcome) = match answer {
        Answer::Refused => (
            "controller_work_refused",
            ReportedOutcome::Refused { reason: reported },
        ),
        Answer::Deferred => (
            "controller_work_deferred",
            ReportedOutcome::Deferred { reason: reported },
        ),
    };
    journal::emit(
        priority,
        &Answered {
            event,
            deploy_id: work.deploy_id,
            deployment: &work.deployment,
            tag: &work.tag,
            digest: &work.digest,
            reason,
        },
    );
    let body = DeployReportBody {
        deploy_id: work.deploy_id,
        deployment: work.deployment.clone(),
        tag: work.tag.clone(),
        digest: work.digest.clone(),
        outcome,
        steps: Vec::new(),
    };
    let keep = match answer {
        Answer::Refused => Keep::Finished {
            record: finished_record(work, &body),
            claimed: None,
        },
        Answer::Deferred => Keep::SendOnly,
    };
    outbox::finish(controller, state_dir, body, keep).await
}

/// Settles what earlier runs left. One deployment's trouble is journalled, and
/// stands in the way of neither the others nor the controller hearing from this
/// host.
async fn settle_claims(state_dir: &Path, options: &DaemonOptions) {
    #[derive(Serialize)]
    struct NotSettled<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        error: String,
    }
    for id in options.dirs.keys() {
        let (root, owned) = (state_dir.to_owned(), id.clone());
        let settled = on_thread("settle claim", move || outbox::settle_claim(&root, &owned)).await;
        match settled {
            // What `recover` left is looked at now, and not up to a minute from now.
            Ok(true) => options.memory.forget_drift(id),
            Ok(false) => {}
            Err(error) => journal::emit(
                Priority::Error,
                &NotSettled {
                    event: "claim_not_settled",
                    deployment: id,
                    error,
                },
            ),
        }
    }
}

/// A deploy that has finished never runs again: if the controller delivers it
/// again, it gets its original report. The ledger goes by number and release, so the
/// same number naming another release, as from a controller whose database was
/// rebuilt, is new, and is judged like any other: a controller could as well pick a
/// number it has not used.
async fn answer_finished<C: Controller>(
    controller: &C,
    state_dir: &Path,
    work: &DeployWork,
) -> Option<StepOutcome> {
    #[derive(Serialize)]
    struct AskedAgain {
        event: &'static str,
        deploy_id: DeployId,
    }
    let (root, deploy_id, asked) = (state_dir.to_owned(), work.deploy_id, work.clone());
    let found = on_thread("read finished", move || {
        StateDir::open(&root)?.finished(&asked)
    })
    .await;
    match found {
        Ok(None) => None,
        Ok(Some(entry)) => {
            journal::emit(
                Priority::Warning,
                &AskedAgain {
                    event: "finished_work_delivered_again",
                    deploy_id,
                },
            );
            let finished = outbox::finish(controller, state_dir, entry.report, Keep::SendOnly);
            Some(match finished.await {
                StepOutcome::Finished {
                    deploy_id,
                    outcome,
                    delivered,
                } => StepOutcome::Replayed {
                    deploy_id,
                    outcome,
                    delivered,
                },
                other => other,
            })
        }
        Err(error) => Some(StepOutcome::Failed { error }),
    }
}

/// One poll: settles what an earlier run left, delivers what is in the outbox,
/// then asks for work and deals with it. A stop ends the wait for an answer, but
/// not a deploy, which finishes and is reported first. While a report can't be
/// delivered no work is asked for: the controller isn't there to answer, and a
/// redelivered deploy could otherwise look new.
pub async fn step<D: Docker, C: Controller, V: Verifier>(
    docker: &D,
    controller: &C,
    verifier: &V,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
) -> StepOutcome {
    settle_claims(state_dir, options).await;
    if let Err(outcome) = outbox::flush(controller, state_dir).await {
        return outcome;
    }
    if options.shutdown.requested() {
        return StepOutcome::ShuttingDown;
    }
    let request = work_request(docker, config, state_dir, options, None).await;
    let answer = tokio::select! {
        biased;
        () = options.shutdown.wait() => return StepOutcome::ShuttingDown,
        answer = controller.work(&request) => answer,
    };
    let response = match answer {
        Ok(response) => response,
        Err(error) => {
            return StepOutcome::Unavailable {
                error: error.to_string(),
            };
        }
    };
    journal_held_back(&response.held_back, options);
    let Some(work) = response.work else {
        return StepOutcome::NoWork;
    };
    // The controller keeps claimed work, and delivers it to the next run.
    if options.shutdown.requested() {
        return StepOutcome::ShuttingDown;
    }
    if let Some(outcome) = answer_finished(controller, state_dir, &work).await {
        return outcome;
    }
    match judge(docker, verifier, config, state_dir, options, &work).await {
        // Verification can take a while, and a stop can have come meanwhile.
        Verdict::Go { .. } if options.shutdown.requested() => StepOutcome::ShuttingDown,
        Verdict::Go {
            plan,
            deployment,
            dir,
        } => {
            let approved = Approved {
                work: &work,
                plan: &plan,
                deployment,
                dir,
            };
            Box::pin(deploy_approved(
                docker, controller, config, state_dir, options, approved,
            ))
            .await
        }
        Verdict::Wait { reason } => StepOutcome::Waiting {
            deploy_id: work.deploy_id,
            reason,
        },
        Verdict::Refuse { priority, reason } => {
            let said = (priority, reason.as_str());
            answer_work(controller, state_dir, &work, Answer::Refused, said).await
        }
        Verdict::Defer { priority, reason } => {
            let said = (priority, reason.as_str());
            answer_work(controller, state_dir, &work, Answer::Deferred, said).await
        }
    }
}

/// Runs [`step`] until a stop is asked for, with a backoff while things fail.
pub async fn run_loop<D: Docker, C: Controller, V: Verifier>(
    docker: &D,
    controller: &C,
    verifier: &V,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
) {
    #[derive(Serialize)]
    struct Trouble<'a> {
        event: &'static str,
        error: &'a str,
    }
    let mut pacing = Pacing::new(
        POLL_FLOOR,
        Backoff::new(BACKOFF_MIN, BACKOFF_MAX),
        BACKOFF_MAX,
    );
    loop {
        let outcome = Box::pin(step(
            docker, controller, verifier, config, state_dir, options,
        ))
        .await;
        let trouble = |priority, event, error| {
            journal::emit(priority, &Trouble { event, error });
        };
        match &outcome {
            StepOutcome::ShuttingDown => return,
            StepOutcome::NoWork | StepOutcome::Finished { .. } | StepOutcome::Replayed { .. } => {}
            StepOutcome::Waiting { reason, .. } => {
                trouble(Priority::Warning, "work_waiting", reason);
            }
            StepOutcome::Unavailable { error } => {
                trouble(Priority::Warning, "controller_unavailable", error);
            }
            StepOutcome::Failed { error } => {
                trouble(Priority::Error, "daemon_step_failed", error);
            }
        }
        let pause = pacing.after(&outcome, Instant::now());
        tokio::select! {
            () = options.shutdown.wait() => return,
            () = tokio::time::sleep(pause) => {}
        }
    }
}

/// Why `run` could not start. Once it has, trouble goes to the journal and it
/// goes on trying.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum DaemonError {
    /// The configuration file could not be read.
    #[error("cannot read configuration {}: {source}", .path.display())]
    ReadConfig {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The configuration file is not valid.
    #[error("configuration {}: {source}", .path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        source: ConfigError,
    },
    /// The configuration has no deployment on this host.
    #[error("the configuration has no deployment on host {0}")]
    NoDeployments(HostId),
    /// The compose directories can't be used as configured.
    #[error(transparent)]
    Compose(#[from] ComposeError),
    /// The state directory can't be used.
    #[error(transparent)]
    State(#[from] StateError),
    /// The trust root's directory could not be created.
    #[error("cannot create the trust root's cache {}: {source}", .path.display())]
    TrustCache {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The host's key can't be used.
    #[error(transparent)]
    Key(#[from] EnrolError),
    /// The HTTP client could not be built.
    #[error(transparent)]
    Controller(#[from] ControllerError),
    /// The release fetcher could not be built.
    #[error("cannot build the release fetcher: {0}")]
    Fetcher(#[source] FetchError),
    /// `GITHUB_TOKEN` is set but cannot be used. The value is never shown.
    #[error("GITHUB_TOKEN is set but is not valid UTF-8 text or not a valid HTTP header value")]
    GitHubToken,
    /// Releases have no image for this host.
    #[error("no image platform for {os}/{arch}: the agent runs on Linux, on arm64 or amd64")]
    Platform {
        /// The operating system.
        os: &'static str,
        /// The processor.
        arch: &'static str,
    },
    /// The signal handlers could not be installed.
    #[error("cannot listen for signals: {0}")]
    Signals(#[source] io::Error),
}

/// What `run` checked before it starts polling. Its `Debug` holds no key.
struct Started {
    config: Config,
    dirs: BTreeMap<DeploymentId, PathBuf>,
    config_hash: [u8; 32],
    key: SigningKey,
    _lock: DeployLock,
}

impl std::fmt::Debug for Started {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Started").finish_non_exhaustive()
    }
}

/// What `run` refuses to start without: a valid configuration, every compose
/// directory there and each its deployment's alone, the state directory to
/// itself, and a key.
fn start_up(config_path: &Path, host: &HostId, state_dir: &Path) -> Result<Started, DaemonError> {
    let bytes = std::fs::read(config_path).map_err(|source| DaemonError::ReadConfig {
        path: config_path.to_owned(),
        source,
    })?;
    let config = config::parse(&bytes).map_err(|source| DaemonError::Config {
        path: config_path.to_owned(),
        source,
    })?;
    let dirs = compose::resolve_dirs(&config, host)?;
    if dirs.is_empty() {
        return Err(DaemonError::NoDeployments(host.clone()));
    }
    let state = StateDir::open(state_dir)?;
    let lock = state.lock_daemon()?;
    let key = enrol::load_key(&state)?;
    Ok(Started {
        config,
        dirs,
        config_hash: Sha256::digest(&bytes).into(),
        key,
        _lock: lock,
    })
}

/// `landfall-agent run`: polls until SIGTERM. A deploy in flight finishes first.
///
/// # Errors
///
/// [`DaemonError`] when it can't start.
pub async fn run(
    config_path: &Path,
    url: ControllerUrl,
    host: &HostId,
    state_dir: &Path,
) -> Result<(), DaemonError> {
    Box::pin(run_with(
        config_path,
        url,
        host,
        state_dir,
        &DockerCli::new(),
        OriginVerifier::new,
        EngineOptions::default(),
    ))
    .await
}

/// [`run`], with what it runs Docker and verifies releases with and the engine's
/// timing given, for the end-to-end tests: no test repository signs real releases.
/// `verifier` is given the directory of the trust root's cache, which exists by
/// then. Nothing on the command line leads here with anything but what `run` gives.
///
/// # Errors
///
/// [`DaemonError`] when it can't start.
pub async fn run_with<D: Docker, V: Verifier>(
    config_path: &Path,
    url: ControllerUrl,
    host: &HostId,
    state_dir: &Path,
    docker: &D,
    verifier: impl FnOnce(PathBuf) -> Result<V, DaemonError>,
    engine: EngineOptions,
) -> Result<(), DaemonError> {
    let started = start_up(config_path, host, state_dir)?;
    let cache_dir = state_dir.join("tuf");
    let created = std::fs::DirBuilder::new()
        .recursive(true)
        .create(&cache_dir);
    created.map_err(|source| DaemonError::TrustCache {
        path: cache_dir.clone(),
        source,
    })?;
    let controller = HttpController::new(url, host.clone(), started.key.clone())?;
    let verifier = verifier(cache_dir)?;
    let shutdown = Shutdown::on_signals().map_err(DaemonError::Signals)?;
    let mut options = DaemonOptions::new(started.dirs.clone(), started.config_hash, shutdown);
    options.engine = engine;
    Box::pin(run_loop(
        docker,
        &controller,
        &verifier,
        &started.config,
        state_dir,
        &options,
    ))
    .await;
    Ok(())
}

#[cfg(test)]
mod tests;
