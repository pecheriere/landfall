use std::fs;
use std::sync::mpsc;
use std::time::Duration;
use std::time::Instant;

use clap::error::ErrorKind;
use clap::{CommandFactory, Parser};
use jiff::Timestamp;
use landfall_core::config::ConfigError;
use serde_json::Value;

use super::{
    Cli, CliError, Command, DEFAULT_STATE_DIR, Deployed, EXIT_BLOCKED, EXIT_COULD_NOT_RUN, EXIT_OK,
    block_on_bounded, execute, load_config, recover_exit_code, recover_target, status_exit_code,
    statuses, write_status,
};
use crate::compose::{OVERRIDE_FILE, PLACEHOLDER, render_override};
use crate::deploy::{self, DeployError, EngineOptions, Outcome, Step, StepResult};
use crate::docker::{ContainerInfo, ServiceConfig};
use crate::state::{DeploymentState, InProgress, Phase};
use crate::testing::{FakeDocker, running};

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const IMAGE: &str =
    "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

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
         [approval]\nrp_id = \"landfall.example\"\norigin = \"https://landfall.example\"\n\
         [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea\" }}\n\
         [[deployment]]\nid = \"app/prod\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ auto = \"any\", approvers = [\"operator\"] }}\nchecks = [{{ command = [\"true\"] }}]\n\
         [[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\ncan = [\"approve\"]\n",
        compose.to_str().unwrap()
    )
}

#[test]
fn a_key_the_verifier_would_refuse_is_refused_at_load() {
    let f = fixture();
    let bad = fs::read_to_string(&f.config_file).unwrap().replace(
        "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
        "cHVibGljLWtleQ",
    );
    fs::write(&f.config_file, bad).unwrap();
    let err = load_config(&f.config_file).unwrap_err();
    assert!(
        matches!(
            &err,
            CliError::Config { source: ConfigError::InvalidApprover { approver, .. }, .. }
                if approver.to_string() == "operator"
        ),
        "{err}"
    );
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
fn run_and_enrol_take_what_the_operations_guide_says() {
    let cli = Cli::try_parse_from([
        "landfall-agent",
        "run",
        "--config",
        "fleet.toml",
        "--controller",
        "https://controller.example",
        "--host",
        "home-1",
    ])
    .unwrap();
    let Command::Run(args) = cli.command else {
        panic!("not run");
    };
    assert!(!args.allow_insecure_controller);
    assert_eq!(args.state_dir.to_str(), Some(DEFAULT_STATE_DIR));

    let cli = Cli::try_parse_from([
        "landfall-agent",
        "enrol",
        "--controller",
        "http://localhost:8080",
        "--host",
        "home-1",
        "--code-file",
        "code",
        "--allow-insecure-controller",
    ])
    .unwrap();
    let Command::Enrol(args) = cli.command else {
        panic!("not enrol");
    };
    assert!(args.allow_insecure_controller);
}

#[test]
fn enrol_takes_no_code_on_the_command_line() {
    let err = Cli::try_parse_from([
        "landfall-agent",
        "enrol",
        "--controller",
        "https://controller.example",
        "--host",
        "home-1",
        "--code",
        "5e5e",
    ])
    .unwrap_err();
    assert_eq!(err.kind(), ErrorKind::UnknownArgument);
}

#[test]
fn an_http_controller_without_the_flag_could_not_run() {
    let f = fixture();
    let cli = Cli::try_parse_from([
        "landfall-agent",
        "run",
        "--config",
        f.config_file.to_str().unwrap(),
        "--controller",
        "http://localhost:8080",
        "--host",
        "home-1",
        "--state-dir",
        f.state_dir.to_str().unwrap(),
    ])
    .unwrap();
    let err = execute(cli, &mut Vec::new()).unwrap_err();
    assert!(matches!(err, CliError::ControllerUrl(_)), "{err}");
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
