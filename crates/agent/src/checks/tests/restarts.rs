//! Restarts and replaced containers, and what the summary says.

use std::time::Duration;

use jiff::SignedDuration;
use jiff::Timestamp;
use tokio::time::Instant;

use super::super::{CheckOptions, run_checks};
use super::{LOCALHOST, before_up, command, dir, http, no_log_match, restarted, serve, short};
use crate::docker::ContainerId;
use crate::testing::{Call, FakeDocker, container_id, running};

#[tokio::test(start_paused = true)]
async fn container_that_exits_during_a_log_window_fails() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    // The driver lists running containers: an exited one is gone from it.
    docker.script_container([Ok(Some(container_id())), Ok(None)]);
    docker.script_exec([Ok(true)]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[command(), no_log_match(5)],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "container");
    assert_eq!(failure.reason, "service \"app\" has no running container");
}

#[tokio::test(start_paused = true)]
async fn restart_during_a_log_window_is_seen_and_the_earlier_logs_count() {
    let docker = FakeDocker::new();
    let up = running(None, &[]);
    let again = restarted(&up, 3);
    docker.script_inspect([Ok(up.clone()), Ok(again.clone())]);
    docker.script_exec([Ok(true)]);
    // Nothing in the first incarnation's scan, then the panic turns up.
    docker.script_logs_contain([Ok(false), Ok(true)]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[command(), no_log_match(5)],
        up.started_at,
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[1] no_log_match \"panic\"");
    let scans: Vec<(Timestamp, Timestamp)> = docker
        .calls()
        .into_iter()
        .filter_map(|c| match c {
            Call::LogsContain { since, until, .. } => Some((since, until)),
            _ => None,
        })
        .collect();
    let five = SignedDuration::from_secs(5);
    assert_eq!(
        scans,
        [
            (up.started_at, up.started_at.checked_add(five).unwrap()),
            (up.started_at, again.started_at.checked_add(five).unwrap()),
        ],
        "from since to the end of the current window"
    );
}

#[tokio::test(start_paused = true)]
async fn logs_are_scanned_from_since() {
    // The container panicked and restarted before the agent looked at it.
    let docker = FakeDocker::new();
    let info = running(None, &[]);
    let since = info
        .started_at
        .checked_sub(SignedDuration::from_secs(60))
        .unwrap();
    docker.script_inspect([Ok(info.clone())]);
    docker.script_exec([Ok(true)]);
    docker.script_logs_contain([Ok(true)]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[command(), no_log_match(5)],
        since,
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[1] no_log_match \"panic\"");
    assert!(
        docker.calls().contains(&Call::LogsContain {
            id: crate::testing::container_id(),
            since,
            until: info
                .started_at
                .checked_add(SignedDuration::from_secs(5))
                .unwrap(),
            needle: "panic".to_owned(),
        })
    );
}

#[tokio::test(start_paused = true)]
async fn replaced_container_starts_over() {
    let docker = FakeDocker::new();
    let other: ContainerId = "ba9876543210".parse().unwrap();
    docker.script_container([
        Ok(Some(crate::testing::container_id())),
        Ok(Some(other.clone())),
    ]);
    docker.script_inspect([Ok(running(None, &[]))]);
    docker.script_exec([Ok(true)]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[command()],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(summary.checks[0].attempts, 3, "one wasted, then two on it");
}

#[tokio::test]
async fn address_that_changes_during_a_round_is_retried() {
    let (port, seen) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
    let docker = FakeDocker::new();
    let up = running(None, &[("app", Some(LOCALHOST))]);
    let mut moved = up.clone();
    moved.networks.insert("app".to_owned(), None);
    docker.script_inspect([Ok(up.clone()), Ok(moved), Ok(up)]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[http(port, 200)],
        before_up(),
        &short(),
    )
    .await
    .unwrap();
    assert_eq!(summary.checks[0].attempts, 3);
    assert_eq!(seen.lock().unwrap().len(), 3);
}

#[tokio::test(start_paused = true)]
async fn crash_loop_fails_even_without_a_log_window() {
    // Each start lasts for one whole round, which passes, and is gone
    // after the settle time.
    let docker = FakeDocker::new();
    let up = running(None, &[]);
    docker.script_inspect((0..200).flat_map(|i| {
        let start = restarted(&up, i);
        [Ok(start.clone()), Ok(start)]
    }));
    docker.script_exec([Ok(true)]);
    let options = CheckOptions::default();
    let start = Instant::now();
    let failure = run_checks(&docker, dir(), "app", &[command()], before_up(), &options)
        .await
        .unwrap_err();
    assert!(failure.reason.contains("keeps restarting"), "{failure}");
    assert!(start.elapsed() <= options.deadline, "{:?}", start.elapsed());
}

#[tokio::test(start_paused = true)]
async fn settling_starts_over_when_the_start_changes() {
    let docker = FakeDocker::new();
    let up = running(None, &[]);
    let again = restarted(&up, 12);
    docker.script_inspect([Ok(up.clone()), Ok(up), Ok(again)]);
    docker.script_exec([Ok(true)]);
    let options = CheckOptions::default();
    let start = Instant::now();
    let summary = run_checks(&docker, dir(), "app", &[command()], before_up(), &options)
        .await
        .unwrap();
    assert_eq!(summary.checks[0].attempts, 3);
    assert_eq!(start.elapsed(), options.settle * 2);
}

#[tokio::test(start_paused = true)]
async fn settling_starts_over_when_the_second_round_fails() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    docker.script_exec([Ok(true), Ok(false), Ok(true)]);
    let options = CheckOptions::default();
    let start = Instant::now();
    let summary = run_checks(&docker, dir(), "app", &[command()], before_up(), &options)
        .await
        .unwrap();
    assert_eq!(summary.checks[0].attempts, 4);
    assert_eq!(start.elapsed(), options.settle * 2 + options.interval);
}

#[tokio::test(start_paused = true)]
async fn first_pass_too_close_to_the_deadline_fails() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    docker.script_exec([Ok(true)]);
    let options = CheckOptions {
        deadline: Duration::from_secs(10),
        ..CheckOptions::default()
    };
    let failure = run_checks(&docker, dir(), "app", &[command()], before_up(), &options)
        .await
        .unwrap_err();
    assert!(failure.reason.contains("too close"), "{failure}");
}

#[tokio::test(start_paused = true)]
async fn summary_has_the_image_of_the_final_round() {
    let docker = FakeDocker::new();
    let up = running(None, &[]);
    let mut swapped = up.clone();
    swapped.image = "ghcr.io/example/app@sha256:11".to_owned();
    docker.script_inspect([Ok(up), Ok(swapped)]);
    docker.script_exec([Ok(true)]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[command()],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(summary.image, "ghcr.io/example/app@sha256:11");
}
