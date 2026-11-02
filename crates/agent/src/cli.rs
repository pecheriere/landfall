//! The command line behind the `landfall-agent` binary: `status`, `recover`,
//! `enrol` and `run`. Results go to stdout as JSON and failures to the journal,
//! with the exit status saying which: 0 success, 1 rollback failed, 2 could not
//! run (usage included, which is clap's own status).

use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use landfall_core::config::{Config, ConfigError, Deployment};
use landfall_core::ids::{DeploymentId, HostId};
use serde::Serialize;

use crate::client::{ControllerUrl, UrlError};
use crate::compose::{self, ComposeError};
use crate::daemon::{self, DaemonError};
use crate::deploy::{self, DeployError, DeployReport, DriftError, EngineOptions, OverrideFile};
use crate::docker::{Docker, DockerCli};
use crate::enrol::{self, EnrolError, Enrolled};
use crate::journal::{self, Priority};
use crate::state::{Deployed, DeploymentState, Phase, StateDir, StateError};

/// Where the agent keeps its state unless told otherwise.
pub const DEFAULT_STATE_DIR: &str = "/var/lib/landfall-agent";

/// The command succeeded. For `recover`: the previous version is back, or
/// there is none to start and the service is stopped, or the deploy had in
/// fact finished, or it had never touched the service; and its marker is gone.
pub const EXIT_OK: u8 = 0;
/// `recover` ran and deploys stay blocked: the rollback failed, or the marker
/// could not be removed. Run it again.
pub const EXIT_BLOCKED: u8 = 1;
/// The command could not run: configuration, state, Docker or usage.
pub const EXIT_COULD_NOT_RUN: u8 = 2;

/// How long the process waits, on the way out, for file work that has outlived
/// its deadline. Dropping a runtime would wait for it without end, and a hung
/// disk must not keep the agent from reporting its exit status.
const SHUTDOWN_WAIT: Duration = Duration::from_secs(5);

/// How long reading a deployment's local files may take.
const LOCAL_READ_LIMIT: Duration = Duration::from_secs(60);

const EXIT_STATUS: &str = "\
Exit status:
  0  success
  1  recover ran and deploys stay blocked: the rollback failed, or its marker
     could not be removed; run it again
  2  could not run: usage, configuration, state or Docker; for status, some
     deployment could not be read (its line has the error); for enrol, the
     controller refused it; for run, it could not start";

/// Runs on each host: verifies and deploys releases, checks health, rolls back.
#[derive(Debug, Parser)]
#[command(name = "landfall-agent", version, about, after_help = EXIT_STATUS)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Print one JSON object per deployment of a host: its compose directory,
    /// what is recorded as deployed, whether a deploy is unfinished and in what
    /// phase, what the override file is, whether the running image is the one
    /// pinned, and whether it has drifted from the override, or the error that
    /// kept it from being read.
    Status(StatusArgs),
    /// Finish an interrupted deploy by rolling it back, and print its report.
    Recover(RecoverArgs),
    /// Generate this host's key if it has none, and enrol it with the
    /// controller. Prints the host and its public key.
    Enrol(EnrolArgs),
    /// Poll the controller for work, verify it, deploy it, report. Runs until
    /// SIGTERM, and a deploy in flight finishes first.
    Run(RunArgs),
}

#[derive(Debug, Args)]
struct EnrolArgs {
    /// The controller's URL.
    #[arg(long, value_name = "URL")]
    controller: String,
    /// The host the code was issued for.
    #[arg(long, value_name = "ID")]
    host: HostId,
    /// The file holding the code from `landfall-server enrol-code`.
    #[arg(long, value_name = "FILE")]
    code_file: PathBuf,
    /// The agent's state directory.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    /// Allow `http://` to a loopback address or a tailnet name: requests are
    /// signed, but work contents are visible.
    #[arg(long)]
    allow_insecure_controller: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    /// The fleet configuration file.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The controller's URL.
    #[arg(long, value_name = "URL")]
    controller: String,
    /// This host.
    #[arg(long, value_name = "ID")]
    host: HostId,
    /// The agent's state directory.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
    /// Allow `http://` to a loopback address or a tailnet name: requests are
    /// signed, but work contents are visible.
    #[arg(long)]
    allow_insecure_controller: bool,
}

#[derive(Debug, Args)]
struct StatusArgs {
    /// The fleet configuration file.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The host to report on.
    #[arg(long, value_name = "ID")]
    host: HostId,
    /// The agent's state directory.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
}

#[derive(Debug, Args)]
struct RecoverArgs {
    /// The fleet configuration file.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The deployment to recover.
    #[arg(long, value_name = "ID")]
    deployment: DeploymentId,
    /// The agent's state directory.
    #[arg(long, value_name = "DIR", default_value = DEFAULT_STATE_DIR)]
    state_dir: PathBuf,
}

/// Why a command could not run.
#[derive(Debug, thiserror::Error)]
pub enum CliError {
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
    /// The configuration has no such deployment.
    #[error("deployment {0} is not in the configuration")]
    UnknownDeployment(DeploymentId),
    /// The configuration has no deployment on the host.
    #[error("the configuration has no deployment on host {0}")]
    NoDeployments(HostId),
    /// The compose directories could not be resolved.
    #[error(transparent)]
    Compose(#[from] ComposeError),
    /// The agent's state could not be read.
    #[error(transparent)]
    State(#[from] StateError),
    /// The override or the running container could not be read.
    #[error("deployment {deployment}: {source}")]
    Drift {
        /// The deployment.
        deployment: DeploymentId,
        /// The failure.
        source: DriftError,
    },
    /// Reading the compose directory or the state did not finish.
    #[error("reading local files did not finish within {0:?}")]
    LocalRead(Duration),
    /// The recovery did not start.
    #[error(transparent)]
    Deploy(#[from] DeployError),
    /// The async runtime could not start.
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    /// The result could not be written to stdout.
    #[error("cannot write the result: {0}")]
    Output(#[source] io::Error),
    /// The controller's URL breaks the transport rule.
    #[error(transparent)]
    ControllerUrl(#[from] UrlError),
    /// Enrolment did not go through.
    #[error(transparent)]
    Enrol(#[from] EnrolError),
    /// The daemon could not start.
    #[error(transparent)]
    Daemon(#[from] DaemonError),
}

/// What `status` prints for one deployment. What could not be found out is
/// `null`, and `error` says why. The only thing in it a container has a say in
/// is `running_image`, which is quoted and truncated, and shown only when it
/// is the image pinned: any other can hold an interpolated secret.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeploymentStatus {
    /// The deployment.
    pub deployment: DeploymentId,
    /// The compose directory, resolved if it could be.
    pub dir: PathBuf,
    /// What is recorded as deployed, if anything.
    pub deployed: Option<Deployed>,
    /// Whether a deploy started and did not finish.
    pub in_progress: Option<bool>,
    /// How far an unfinished deploy got; `null` without one.
    pub phase: Option<Phase>,
    /// What the override file is.
    pub override_file: Option<OverrideFile>,
    /// The running container's image, quoted and truncated, if it is the one
    /// pinned.
    pub running_image: Option<String>,
    /// Whether the running container runs the pinned image; `null` when none
    /// is running.
    pub running_image_matches: Option<bool>,
    /// Whether the running image differs from the override.
    pub drift: Option<bool>,
    /// Why this deployment could not be read in full.
    pub error: Option<String>,
}

fn load_config(path: &Path) -> Result<Config, CliError> {
    let bytes = std::fs::read(path).map_err(|source| CliError::ReadConfig {
        path: path.to_owned(),
        source,
    })?;
    landfall_approval::parse_config(&bytes).map_err(|source| CliError::Config {
        path: path.to_owned(),
        source,
    })
}

/// Runs file work on a thread, so a hung disk ends in an error row.
async fn on_thread<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, CliError> + Send + 'static,
) -> Result<T, CliError> {
    deploy::on_thread_within(LOCAL_READ_LIMIT, work)
        .await
        .map_err(|_| CliError::LocalRead(LOCAL_READ_LIMIT))?
}

/// Fills in `row` as far as it can be read; the first failure ends it.
async fn fill_status<D: Docker>(
    docker: &D,
    deployment: &Deployment,
    state_dir: &Path,
    row: &mut DeploymentStatus,
) -> Result<(), CliError> {
    let id = deployment.id();
    let owned = deployment.clone();
    row.dir = on_thread(move || compose::resolve_dir(&owned).map_err(CliError::from)).await?;
    let (state_dir, state_id) = (state_dir.to_owned(), id.clone());
    let (deployed, in_progress) = on_thread(move || {
        let record = StateDir::open(&state_dir)?.deployment(&state_id)?;
        Ok((record.deployed()?, record.in_progress()?))
    })
    .await?;
    let recorded = deployed.is_some();
    row.deployed = deployed;
    row.in_progress = Some(in_progress.is_some());
    row.phase = in_progress.map(|marker| marker.phase);
    let seen = deploy::drift(docker, &row.dir, deployment.compose().service(), recorded)
        .await
        .map_err(|source| CliError::Drift {
            deployment: id.clone(),
            source,
        })?;
    row.override_file = Some(seen.override_file);
    row.running_image = seen.running_image;
    row.running_image_matches = seen.running_image_matches;
    row.drift = Some(seen.drift);
    Ok(())
}

/// One row per deployment of `host`. One that can't be read gets an error in
/// its row and doesn't stop the others.
async fn statuses<D: Docker>(
    docker: &D,
    config: &Config,
    host: &HostId,
    state_dir: &Path,
) -> Result<Vec<DeploymentStatus>, CliError> {
    let mut rows = Vec::new();
    for deployment in config.deployments_for_host(host) {
        let mut row = DeploymentStatus {
            deployment: deployment.id().clone(),
            dir: PathBuf::from(deployment.compose().dir()),
            deployed: None,
            in_progress: None,
            phase: None,
            override_file: None,
            running_image: None,
            running_image_matches: None,
            drift: None,
            error: None,
        };
        if let Err(error) = fill_status(docker, deployment, state_dir, &mut row).await {
            row.error = Some(error.to_string());
        }
        rows.push(row);
    }
    if rows.is_empty() {
        return Err(CliError::NoDeployments(host.clone()));
    }
    Ok(rows)
}

/// The exit status of a `status` that printed `rows`.
#[must_use]
pub fn status_exit_code(rows: &[DeploymentStatus]) -> u8 {
    if rows.iter().any(|row| row.error.is_some()) {
        EXIT_COULD_NOT_RUN
    } else {
        EXIT_OK
    }
}

fn journal_status_errors(rows: &[DeploymentStatus]) {
    #[derive(Serialize)]
    struct Unreadable<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        error: &'a str,
    }
    for row in rows {
        if let Some(error) = &row.error {
            journal::emit(
                Priority::Error,
                &Unreadable {
                    event: "status_unreadable",
                    deployment: &row.deployment,
                    error,
                },
            );
        }
    }
}

/// Finds what `recover` works on.
fn recover_target<'a>(
    config: &'a Config,
    id: &DeploymentId,
    state_dir: &Path,
) -> Result<(&'a Deployment, PathBuf, DeploymentState), CliError> {
    let deployment = config
        .deployment(id)
        .ok_or_else(|| CliError::UnknownDeployment(id.clone()))?;
    // Only this one: another deployment's missing directory must not keep an
    // operator from recovering this one.
    let dir = compose::resolve_dir(deployment)?;
    let state = StateDir::open(state_dir)?.deployment(id)?;
    Ok((deployment, dir, state))
}

/// The exit status of a `recover` that ran.
#[must_use]
pub fn recover_exit_code(report: &DeployReport) -> u8 {
    if report.leaves_deploys_blocked() {
        EXIT_BLOCKED
    } else {
        EXIT_OK
    }
}

/// Runs `future` to its end on a runtime of its own, then gives what is left
/// on the runtime's blocking threads `wait` to finish. A thread that has not
/// finished by then is abandoned, to die with the process.
fn block_on_bounded<F: Future>(future: F, wait: Duration) -> Result<F::Output, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    let output = runtime.block_on(future);
    runtime.shutdown_timeout(wait);
    Ok(output)
}

fn write_status(out: &mut impl Write, rows: &[DeploymentStatus]) -> io::Result<()> {
    for row in rows {
        serde_json::to_writer(&mut *out, row)?;
        writeln!(out)?;
    }
    out.flush()
}

fn write_report(out: &mut impl Write, report: &DeployReport) -> io::Result<()> {
    serde_json::to_writer_pretty(&mut *out, report)?;
    writeln!(out)?;
    out.flush()
}

fn write_enrolled(out: &mut impl Write, enrolled: &Enrolled) -> io::Result<()> {
    serde_json::to_writer(&mut *out, enrolled)?;
    writeln!(out)?;
    out.flush()
}

/// Runs the command on real Docker, writing its result to `out`.
fn execute(cli: Cli, out: &mut impl Write) -> Result<u8, CliError> {
    let docker = DockerCli::new();
    match cli.command {
        Command::Status(args) => {
            let config = load_config(&args.config)?;
            let rows = block_on_bounded(
                statuses(&docker, &config, &args.host, &args.state_dir),
                SHUTDOWN_WAIT,
            )??;
            write_status(out, &rows).map_err(CliError::Output)?;
            journal_status_errors(&rows);
            Ok(status_exit_code(&rows))
        }
        Command::Recover(args) => {
            let config = load_config(&args.config)?;
            let (deployment, dir, state) =
                recover_target(&config, &args.deployment, &args.state_dir)?;
            let options = EngineOptions::default();
            let report = block_on_bounded(
                deploy::recover(&docker, &state, deployment, &dir, &options),
                SHUTDOWN_WAIT,
            )??;
            write_report(out, &report).map_err(CliError::Output)?;
            Ok(recover_exit_code(&report))
        }
        Command::Enrol(args) => {
            let url = ControllerUrl::parse(&args.controller, args.allow_insecure_controller)?;
            let enrolled = block_on_bounded(
                enrol::enrol(&url, &args.host, &args.state_dir, &args.code_file),
                SHUTDOWN_WAIT,
            )??;
            write_enrolled(out, &enrolled).map_err(CliError::Output)?;
            Ok(EXIT_OK)
        }
        Command::Run(args) => {
            let url = ControllerUrl::parse(&args.controller, args.allow_insecure_controller)?;
            block_on_bounded(
                daemon::run(&args.config, url, &args.host, &args.state_dir),
                SHUTDOWN_WAIT,
            )??;
            Ok(EXIT_OK)
        }
    }
}

/// Runs the command and returns the process's exit status. A failure goes to
/// the journal.
#[must_use]
pub fn run(cli: Cli) -> u8 {
    #[derive(Serialize)]
    struct Failed {
        event: &'static str,
        error: String,
    }
    match execute(cli, &mut io::stdout().lock()) {
        Ok(code) => code,
        Err(error) => {
            journal::emit(
                Priority::Error,
                &Failed {
                    event: "agent_command_failed",
                    error: error.to_string(),
                },
            );
            EXIT_COULD_NOT_RUN
        }
    }
}

#[cfg(test)]
mod tests;
