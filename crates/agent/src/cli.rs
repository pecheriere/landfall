//! The command line behind the `landfall-agent` binary: `status` and
//! `recover`. Results go to stdout as JSON and failures to the journal, with
//! the exit status saying which: 0 success, 1 rollback failed, 2 could not run
//! (usage included, which is clap's own status).

use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use landfall_core::config::{self, Config, ConfigError, Deployment};
use landfall_core::ids::{DeploymentId, HostId};
use serde::Serialize;

use crate::compose::{self, ComposeError};
use crate::deploy::{self, DeployError, DeployReport, DriftError, EngineOptions, OverrideFile};
use crate::docker::{Docker, DockerCli};
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
     deployment could not be read (its line has the error)";

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
    config::parse(&bytes).map_err(|source| CliError::Config {
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
mod tests {
    use std::fs;
    use std::sync::mpsc;
    use std::time::Instant;

    use clap::error::ErrorKind;
    use clap::{CommandFactory, Parser};
    use jiff::Timestamp;
    use serde_json::Value;

    use super::{
        Cli, CliError, Command, DEFAULT_STATE_DIR, Deployed, EXIT_BLOCKED, EXIT_COULD_NOT_RUN,
        EXIT_OK, block_on_bounded, execute, load_config, recover_exit_code, recover_target,
        status_exit_code, statuses, write_status,
    };
    use crate::compose::{OVERRIDE_FILE, PLACEHOLDER, render_override};
    use crate::deploy::{self, DeployError, EngineOptions, Outcome, Step, StepResult};
    use crate::docker::{ContainerInfo, ServiceConfig};
    use crate::state::{DeploymentState, InProgress, Phase};
    use crate::testing::{FakeDocker, running};
    use std::time::Duration;

    const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const IMAGE: &str = "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    struct Fixture {
        _tmp: tempfile::TempDir,
        compose: std::path::PathBuf,
        state_dir: std::path::PathBuf,
        config_file: std::path::PathBuf,
    }

    /// A fleet with deployment `app/prod` on `home-1`, its directories and
    /// its configuration file.
    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let root = tmp.path().canonicalize().unwrap();
        let compose = root.join("compose");
        fs::create_dir(&compose).unwrap();
        let state_dir = root.join("state");
        fs::create_dir(&state_dir).unwrap();
        let config_file = root.join("fleet.toml");
        fs::write(&config_file, fleet(&compose)).unwrap();
        Fixture {
            _tmp: tmp,
            compose,
            state_dir,
            config_file,
        }
    }

    fn fleet(compose: &std::path::Path) -> String {
        format!(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"app/prod\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [{{ command = [\"true\"] }}]\n\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\ncan = [\"approve\"]\n",
            compose.to_str().unwrap()
        )
    }

    fn container(image: &str) -> ContainerInfo {
        let mut info = running(None, &[]);
        image.clone_into(&mut info.image);
        info
    }

    fn deployed() -> Deployed {
        Deployed {
            deploy_id: "previous".to_owned(),
            tag: "v1.2.3".parse().unwrap(),
            version: semver::Version::new(1, 2, 3),
            digest: DIGEST.parse().unwrap(),
            commit: COMMIT.parse().unwrap(),
            deployed_at: Timestamp::UNIX_EPOCH,
        }
    }

    fn marker() -> InProgress {
        InProgress {
            deploy_id: "interrupted".to_owned(),
            phase: Phase::Deploying,
            tag: "v1.2.4".parse().unwrap(),
            digest: DIGEST.parse().unwrap(),
            previous_can_start: true,
            backup: None,
            started_at: Timestamp::now(),
        }
    }

    fn state_of(f: &Fixture) -> DeploymentState {
        crate::state::StateDir::open(&f.state_dir)
            .unwrap()
            .deployment(&"app/prod".parse().unwrap())
            .unwrap()
    }

    /// Runs `status` on the fake and returns the lines it prints, parsed, and
    /// the exit status.
    async fn status_lines(f: &Fixture, docker: &FakeDocker) -> (Vec<Value>, u8) {
        let config = load_config(&f.config_file).unwrap();
        let host = "home-1".parse().unwrap();
        let rows = statuses(docker, &config, &host, &f.state_dir)
            .await
            .unwrap();
        let mut out = Vec::new();
        write_status(&mut out, &rows).unwrap();
        let lines = String::from_utf8(out)
            .unwrap()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (lines, status_exit_code(&rows))
    }

    fn write_pinned(f: &Fixture, image: &str) {
        let tag = "v1.2.3".parse().unwrap();
        let file = render_override(
            "app",
            image,
            &"app/prod".parse().unwrap(),
            &tag,
            &COMMIT.parse().unwrap(),
        );
        fs::write(f.compose.join(OVERRIDE_FILE), file).unwrap();
    }

    #[test]
    fn command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn usage_errors_exit_with_could_not_run() {
        for args in [
            &["landfall-agent", "nonsense"][..],
            &["landfall-agent", "status", "--host", "home-1"],
            &["landfall-agent", "recover", "--config", "fleet.toml"],
            &[
                "landfall-agent",
                "status",
                "--config",
                "f",
                "--host",
                "No Such",
            ],
        ] {
            let err = Cli::try_parse_from(args).unwrap_err();
            assert_ne!(err.kind(), ErrorKind::DisplayHelp);
            assert_eq!(err.exit_code(), i32::from(EXIT_COULD_NOT_RUN), "{args:?}");
        }
    }

    #[test]
    fn state_dir_has_a_default() {
        let cli = Cli::try_parse_from([
            "landfall-agent",
            "recover",
            "--config",
            "fleet.toml",
            "--deployment",
            "app/prod",
        ])
        .unwrap();
        let Command::Recover(args) = cli.command else {
            panic!("not recover");
        };
        assert_eq!(args.state_dir.to_str(), Some(DEFAULT_STATE_DIR));
    }

    #[test]
    fn help_documents_the_exit_status() {
        let help = Cli::command().render_long_help().to_string();
        for line in ["0  success", "1  recover ran", "2  could not run"] {
            assert!(help.contains(line), "{line:?} missing from:\n{help}");
        }
    }

    #[test]
    fn exit_codes_follow_the_outcome() {
        let report = |outcome| deploy::DeployReport {
            deployment: "app/prod".parse().unwrap(),
            tag: "v1.2.3".parse().unwrap(),
            digest: DIGEST.parse().unwrap(),
            outcome,
            steps: Vec::new(),
            started_at: Timestamp::UNIX_EPOCH,
            finished_at: Timestamp::UNIX_EPOCH,
        };
        let reason = || "why".to_owned();
        for outcome in [
            Outcome::Deployed,
            Outcome::RolledBack { reason: reason() },
            Outcome::NothingChanged { reason: reason() },
            Outcome::FailedNoPrevious { reason: reason() },
        ] {
            assert_eq!(recover_exit_code(&report(outcome)), EXIT_OK);
        }
        let failed = Outcome::RollbackFailed {
            reason: reason(),
            rollback_reason: reason(),
        };
        assert_eq!(recover_exit_code(&report(failed)), EXIT_BLOCKED);
    }

    #[test]
    fn a_marker_that_could_not_be_removed_is_not_success() {
        let step = |name: &str, result| Step {
            name: name.to_owned(),
            started_at: Timestamp::UNIX_EPOCH,
            millis: 0,
            result,
            detail: None,
        };
        let failed = || StepResult::Failed {
            reason: "why".to_owned(),
        };
        let report = |steps| deploy::DeployReport {
            deployment: "app/prod".parse().unwrap(),
            tag: "v1.2.3".parse().unwrap(),
            digest: DIGEST.parse().unwrap(),
            outcome: Outcome::RolledBack {
                reason: "why".to_owned(),
            },
            steps,
            started_at: Timestamp::UNIX_EPOCH,
            finished_at: Timestamp::UNIX_EPOCH,
        };
        assert_eq!(
            recover_exit_code(&report(vec![step("clear_in_progress", failed())])),
            EXIT_BLOCKED
        );
        assert_eq!(
            recover_exit_code(&report(vec![
                step("clear_in_progress", StepResult::Ok),
                step("prune_backups", failed()),
            ])),
            EXIT_OK,
            "a failed prune leaves nothing blocked"
        );
    }

    #[test]
    fn recover_is_not_blocked_by_another_deployments_missing_directory() {
        let f = fixture();
        let gone = f.state_dir.with_file_name("gone");
        let second = format!(
            "[[deployment]]\nid = \"app/gone\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [{{ command = [\"true\"] }}]\n",
            gone.to_str().unwrap()
        );
        fs::write(
            &f.config_file,
            fleet(&f.compose).replace("[[grant]]", &format!("{second}[[grant]]")),
        )
        .unwrap();
        let config = load_config(&f.config_file).unwrap();

        let (deployment, dir, _) =
            recover_target(&config, &"app/prod".parse().unwrap(), &f.state_dir).unwrap();
        assert_eq!(deployment.id().as_ref(), "app/prod");
        assert_eq!(dir, f.compose);

        let err = recover_target(&config, &"app/gone".parse().unwrap(), &f.state_dir)
            .err()
            .unwrap();
        assert!(matches!(err, CliError::Compose(_)), "{err}");
    }

    #[test]
    fn a_missing_configuration_could_not_run() {
        let f = fixture();
        let cli = Cli::try_parse_from([
            "landfall-agent",
            "status",
            "--config",
            f.state_dir.join("absent").to_str().unwrap(),
            "--host",
            "home-1",
        ])
        .unwrap();
        let err = execute(cli, &mut Vec::new()).unwrap_err();
        assert!(matches!(err, CliError::ReadConfig { .. }), "{err}");
    }

    #[tokio::test]
    async fn a_host_without_deployments_could_not_run() {
        let f = fixture();
        let config = load_config(&f.config_file).unwrap();
        let err = statuses(
            &FakeDocker::new(),
            &config,
            &"home-2".parse().unwrap(),
            &f.state_dir,
        )
        .await
        .unwrap_err();
        assert!(matches!(err, CliError::NoDeployments(_)), "{err}");
    }

    #[test]
    fn recover_refuses_an_unknown_deployment() {
        let f = fixture();
        let config = load_config(&f.config_file).unwrap();
        let err = recover_target(&config, &"app/other".parse().unwrap(), &f.state_dir)
            .err()
            .unwrap();
        assert!(matches!(err, CliError::UnknownDeployment(_)), "{err}");
    }

    #[tokio::test]
    async fn status_reports_a_deployment_as_json() {
        let f = fixture();
        state_of(&f).set_deployed(&deployed()).unwrap();
        state_of(&f).set_in_progress(&marker()).unwrap();
        write_pinned(&f, IMAGE);
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(container(IMAGE))]);

        let (lines, code) = status_lines(&f, &docker).await;

        assert_eq!(code, EXIT_OK);
        assert_eq!(lines.len(), 1);
        let row = &lines[0];
        assert_eq!(row["deployment"], "app/prod");
        assert_eq!(row["dir"], f.compose.to_str().unwrap());
        assert_eq!(row["deployed"]["tag"], "v1.2.3");
        assert_eq!(row["in_progress"], true);
        assert_eq!(row["phase"], "deploying");
        assert_eq!(row["override_file"], "pinned");
        assert_eq!(row["running_image"], format!("{IMAGE:?}"));
        assert_eq!(row["running_image_matches"], true);
        assert_eq!(row["drift"], false);
        assert_eq!(row["error"], Value::Null);
    }

    #[tokio::test]
    async fn a_missing_override_is_a_state_not_a_failure() {
        let f = fixture();
        let docker = FakeDocker::new();
        docker.script_container([Ok(None)]);

        let (lines, code) = status_lines(&f, &docker).await;

        assert_eq!(code, EXIT_OK);
        let row = &lines[0];
        assert_eq!(row["override_file"], "missing");
        assert_eq!(row["phase"], Value::Null);
        assert_eq!(row["running_image"], Value::Null);
        assert_eq!(row["running_image_matches"], Value::Null);
        assert_eq!(row["drift"], false);
        assert_eq!(row["error"], Value::Null);
        assert_eq!(row["deployed"], Value::Null);
    }

    #[tokio::test]
    async fn one_bad_deployment_gets_an_error_row_and_the_others_are_reported() {
        let f = fixture();
        write_pinned(&f, IMAGE);
        let gone = f.state_dir.with_file_name("gone");
        let second = format!(
            "[[deployment]]\nid = \"app/gone\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [{{ command = [\"true\"] }}]\n",
            gone.to_str().unwrap()
        );
        let fleet = fleet(&f.compose).replace("[[grant]]", &format!("{second}[[grant]]"));
        fs::write(&f.config_file, fleet).unwrap();
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(container(IMAGE))]);

        let (lines, code) = status_lines(&f, &docker).await;

        assert_eq!(code, EXIT_COULD_NOT_RUN);
        assert_eq!(lines.len(), 2);
        let good = lines
            .iter()
            .find(|row| row["deployment"] == "app/prod")
            .unwrap();
        assert_eq!(good["drift"], false);
        assert_eq!(good["error"], Value::Null);
        let bad = lines
            .iter()
            .find(|row| row["deployment"] == "app/gone")
            .unwrap();
        assert_eq!(bad["drift"], Value::Null);
        assert_eq!(bad["in_progress"], Value::Null);
        assert_eq!(bad["dir"], gone.to_str().unwrap());
        assert!(
            bad["error"].as_str().unwrap().contains("cannot be used"),
            "{bad}"
        );
    }

    #[tokio::test]
    async fn an_unusable_state_directory_is_an_error_row() {
        let f = fixture();
        fs::remove_dir(&f.state_dir).unwrap();
        let (lines, code) = status_lines(&f, &FakeDocker::new()).await;
        assert_eq!(code, EXIT_COULD_NOT_RUN);
        assert!(
            lines[0]["error"].as_str().unwrap().contains("state"),
            "{}",
            lines[0]
        );
        assert_eq!(lines[0]["dir"], f.compose.to_str().unwrap());
    }

    #[tokio::test]
    async fn docker_failure_is_an_error_row() {
        let f = fixture();
        let docker = FakeDocker::new();
        docker.script_container([Err("daemon gone")]);
        let (lines, code) = status_lines(&f, &docker).await;
        assert_eq!(code, EXIT_COULD_NOT_RUN);
        assert!(lines[0]["error"].as_str().unwrap().contains("daemon gone"));
        assert_eq!(lines[0]["override_file"], Value::Null);
        assert_eq!(lines[0]["in_progress"], false);
    }

    #[tokio::test]
    async fn status_holds_no_container_text_beyond_a_quoted_truncated_image() {
        let f = fixture();
        write_pinned(&f, IMAGE);
        let docker = FakeDocker::new();
        let hostile = format!("evil\n{{\"drift\":false}}{}", "x".repeat(100_000));
        let mut info = container(&hostile);
        info.status = "status-text".to_owned();
        info.health = Some("health-text".to_owned());
        docker.script_inspect([Ok(info)]);

        let (lines, _) = status_lines(&f, &docker).await;

        let row = &lines[0];
        assert_eq!(row["drift"], true);
        assert_eq!(row["running_image"], Value::Null);
        assert_eq!(row["running_image_matches"], false);
        let text = row.to_string();
        assert!(text.len() < 1024, "{}", text.len());
        for absent in ["status-text", "health-text", "evil"] {
            assert!(!text.contains(absent), "{text}");
        }
    }

    #[tokio::test]
    async fn status_reports_the_phase_of_an_unfinished_deploy() {
        let f = fixture();
        write_pinned(&f, IMAGE);
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(container(IMAGE))]);
        for (phase, shown) in [
            (Phase::Preflight, "preflight"),
            (Phase::RollingBack, "rolling_back"),
            (Phase::Restored, "restored"),
            (Phase::RolledBack, "rolled_back"),
        ] {
            state_of(&f)
                .set_in_progress(&InProgress { phase, ..marker() })
                .unwrap();
            let (lines, _) = status_lines(&f, &docker).await;
            assert_eq!(lines[0]["phase"], shown);
        }
    }

    #[tokio::test]
    async fn a_missing_override_with_a_deploy_on_record_is_reported_as_drift() {
        let f = fixture();
        state_of(&f).set_deployed(&deployed()).unwrap();
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(container(IMAGE))]);

        let (lines, _) = status_lines(&f, &docker).await;

        assert_eq!(lines[0]["override_file"], "missing");
        assert_eq!(lines[0]["drift"], true);
    }

    /// The compose directory after an agent died mid-deploy.
    fn interrupted(f: &Fixture) -> DeploymentState {
        let state = state_of(f);
        fs::write(f.compose.join(OVERRIDE_FILE), "# half way\n").unwrap();
        state.set_previous_override(PLACEHOLDER.as_bytes()).unwrap();
        state.set_previous_deployed(None).unwrap();
        state.set_in_progress(&marker()).unwrap();
        state
    }

    fn engine_options() -> EngineOptions {
        let mut options = EngineOptions::default();
        options.checks.interval = Duration::from_millis(1);
        options.checks.deadline = Duration::from_millis(500);
        options.checks.settle = Duration::from_millis(1);
        options
    }

    #[tokio::test]
    async fn recover_that_rolls_back_exits_ok() {
        let f = fixture();
        let state = interrupted(&f);
        let config = load_config(&f.config_file).unwrap();
        let docker = FakeDocker::new();
        docker.script_compose_service([Ok(ServiceConfig {
            image: Some(IMAGE.to_owned()),
            has_build: false,
            replicas: 1,
        })]);
        docker.script_inspect([Ok(container(IMAGE))]);
        docker.script_exec([Ok(true)]);

        let report = deploy::recover(
            &docker,
            &state,
            &config.deployments()[0],
            &f.compose,
            &engine_options(),
        )
        .await
        .unwrap();

        assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
        assert_eq!(recover_exit_code(&report), EXIT_OK);
    }

    #[tokio::test]
    async fn recover_whose_rollback_fails_exits_1() {
        let f = fixture();
        let state = interrupted(&f);
        let config = load_config(&f.config_file).unwrap();
        let docker = FakeDocker::new();
        docker.script_compose_up([Err("daemon gone")]);

        let report = deploy::recover(
            &docker,
            &state,
            &config.deployments()[0],
            &f.compose,
            &engine_options(),
        )
        .await
        .unwrap();

        assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
        assert_eq!(recover_exit_code(&report), EXIT_BLOCKED);
    }

    #[tokio::test]
    async fn recover_with_nothing_interrupted_could_not_run() {
        let f = fixture();
        let config = load_config(&f.config_file).unwrap();
        let err = deploy::recover(
            &FakeDocker::new(),
            &state_of(&f),
            &config.deployments()[0],
            &f.compose,
            &engine_options(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, DeployError::NothingToRecover(_)), "{err}");
    }

    #[test]
    fn a_hung_blocking_thread_does_not_hold_up_the_exit() {
        // Held until the test ends: the thread never finishes on its own.
        let (_hold, hung) = mpsc::channel::<()>();
        let started = Instant::now();
        let output = block_on_bounded(
            async {
                drop(tokio::task::spawn_blocking(move || {
                    let _ = hung.recv();
                }));
                7
            },
            Duration::from_millis(50),
        )
        .unwrap();
        assert_eq!(output, 7);
        assert!(started.elapsed() < Duration::from_secs(10));
    }
}
