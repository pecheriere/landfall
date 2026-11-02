//! Against a real Docker daemon: `cargo test -p landfall-agent --locked
//! -- --ignored docker`. These use `command` checks, because a Docker
//! bridge network cannot be reached from every host that runs them.

use std::time::Duration;

use jiff::Timestamp;
use landfall_core::config::Check;

use super::super::{CheckOptions, run_checks};
use super::no_log_match;
use crate::docker::Docker;
use crate::docker::DockerCli;
use crate::testing::{ComposeProject, TEST_IMAGE};

/// A project with a service `app` running `script`, and the time just
/// before it was brought up.
async fn project(cli: &DockerCli, restart: &str, script: &str) -> (ComposeProject, Timestamp) {
    let services = format!(
        "  app:\n    image: {TEST_IMAGE}\n    restart: '{restart}'\n    command: [sh, -c, '{script}']\n    stop_grace_period: 1s\n"
    );
    let project = ComposeProject::new(cli, &services).await;
    let since = Timestamp::now();
    cli.compose_up(project.path(), "app").await.unwrap();
    (project, since)
}

fn alive() -> Check {
    Check::Command {
        argv: vec!["true".to_owned()],
    }
}

fn options(deadline: u64, settle: u64) -> CheckOptions {
    CheckOptions {
        interval: Duration::from_millis(200),
        deadline: Duration::from_secs(deadline),
        http_timeout: Duration::from_secs(1),
        settle: Duration::from_secs(settle),
    }
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_healthy_container_passes() {
    let cli = DockerCli::new();
    let (project, since) = project(&cli, "no", "sleep 300").await;
    let summary = run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(2)],
        since,
        &options(30, 2),
    )
    .await
    .unwrap();
    assert_eq!(summary.image, TEST_IMAGE);
    assert_eq!(summary.checks[0].attempts, 2);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_container_that_exits_inside_the_window_fails() {
    let cli = DockerCli::new();
    let (project, since) = project(&cli, "no", "sleep 2").await;
    let failure = run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(5)],
        since,
        &options(10, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "container", "{failure}");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_crash_loop_inside_the_window_fails() {
    let cli = DockerCli::new();
    let (project, since) = project(&cli, "always", "sleep 2; exit 1").await;
    run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(4)],
        since,
        &options(20, 1),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_crash_loop_without_a_log_window_fails() {
    let cli = DockerCli::new();
    let (project, since) = project(&cli, "always", "sleep 2; exit 1").await;
    run_checks(
        &cli,
        project.path(),
        "app",
        &[alive()],
        since,
        &options(20, 4),
    )
    .await
    .unwrap_err();
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_panic_before_a_restart_counts() {
    let cli = DockerCli::new();
    // Panics once, on its first start, then stays up: the file
    // survives a restart of the container.
    let script =
        "if [ -e /tmp/seen ]; then sleep 300; fi; touch /tmp/seen; sleep 3; echo panic; exit 1";
    let (project, since) = project(&cli, "always", script).await;
    let failure = run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(6)],
        since,
        &options(30, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.check, "checks[1] no_log_match \"panic\"",
        "{failure}"
    );
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_panic_before_the_first_look_counts() {
    let cli = DockerCli::new();
    // Panics at once on its first start, and its second start comes
    // whole seconds later, so the line is before any start seen below.
    let script =
        "if [ -e /tmp/seen ]; then sleep 300; fi; touch /tmp/seen; echo panic; sleep 2; exit 1";
    let (project, since) = project(&cli, "always", script).await;
    let id = cli.container(project.path(), "app").await.unwrap().unwrap();
    let mut restarts = String::new();
    for _ in 0..150 {
        let out = std::process::Command::new("docker")
            .args(["inspect", "--format", "{{.RestartCount}}", id.as_ref()])
            .output()
            .unwrap();
        restarts = String::from_utf8(out.stdout).unwrap().trim().to_owned();
        if restarts == "1" {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(restarts, "1", "the container did not restart");
    let failure = run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(1)],
        since,
        &options(30, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.check, "checks[1] no_log_match \"panic\"",
        "{failure}"
    );
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_old_log_lines_of_a_reused_container_do_not_count() {
    let cli = DockerCli::new();
    // Logs the line on its first start only; the file survives a stop.
    let script = "if [ ! -e /tmp/seen ]; then touch /tmp/seen; echo panic; fi; sleep 300";
    let (project, first_up) = project(&cli, "no", script).await;
    let id = cli.container(project.path(), "app").await.unwrap().unwrap();
    let mut logged = false;
    for _ in 0..150 {
        logged = cli
            .logs_contain(&id, first_up, Timestamp::now(), "panic")
            .await
            .unwrap();
        if logged {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(logged, "the container did not log the line");

    // Scans are to the second: `since` must be in a later one.
    tokio::time::sleep(Duration::from_secs(2)).await;
    let since = Timestamp::now();
    cli.compose_stop(project.path(), "app").await.unwrap();
    cli.compose_up(project.path(), "app").await.unwrap();
    assert_eq!(
        cli.container(project.path(), "app").await.unwrap(),
        Some(id.clone()),
        "the container was not reused"
    );
    assert!(
        cli.logs_contain(&id, first_up, Timestamp::now(), "panic")
            .await
            .unwrap(),
        "the old line is still in its log"
    );

    run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(1)],
        since,
        &options(30, 1),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_untouched_container_is_observed_for_the_whole_window() {
    let cli = DockerCli::new();
    // A window of 3 s from its start is over when `since` is taken, 4 s
    // in. The line comes at 6 s, inside the 3 s from `since`.
    let (project, _) = project(&cli, "no", "sleep 6; echo panic; sleep 300").await;
    tokio::time::sleep(Duration::from_secs(4)).await;
    let id = cli.container(project.path(), "app").await.unwrap().unwrap();
    let started = cli.inspect(&id).await.unwrap().started_at;

    // A second `up` finds nothing to change.
    let since = Timestamp::now();
    cli.compose_up(project.path(), "app").await.unwrap();
    let same = cli.inspect(&id).await.unwrap().started_at;
    assert_eq!(same, started, "the container was left untouched");

    let failure = run_checks(
        &cli,
        project.path(),
        "app",
        &[alive(), no_log_match(3)],
        since,
        &options(30, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.check, "checks[1] no_log_match \"panic\"",
        "{failure}"
    );
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_line_in_the_window_fails_and_a_later_one_does_not() {
    let cli = DockerCli::new();
    let (inside, since) = project(&cli, "no", "sleep 1; echo panic; sleep 300").await;
    let failure = run_checks(
        &cli,
        inside.path(),
        "app",
        &[alive(), no_log_match(3)],
        since,
        &options(30, 1),
    )
    .await
    .unwrap_err();
    assert_eq!(
        failure.check, "checks[1] no_log_match \"panic\"",
        "{failure}"
    );

    // Logged before the second round scans, but after the window.
    let (later, since) = project(&cli, "no", "sleep 5; echo panic; sleep 300").await;
    run_checks(
        &cli,
        later.path(),
        "app",
        &[alive(), no_log_match(2)],
        since,
        &options(30, 6),
    )
    .await
    .unwrap();
}
