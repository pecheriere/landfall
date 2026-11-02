//! The command check and the log window.

use std::time::Duration;

use jiff::SignedDuration;
use jiff::Timestamp;
use landfall_core::config::Check;
use tokio::time::Instant;

use super::super::{CheckOptions, run_checks};
use super::{before_up, dir, inspects, no_log_match};
use crate::testing::{Call, FakeDocker, running};

#[tokio::test(start_paused = true)]
async fn command_exit_nonzero_retries_then_fails() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    docker.script_exec([Ok(false)]);
    let argv = vec!["/bin/check".to_owned(), "--now".to_owned()];
    let options = CheckOptions {
        interval: Duration::from_secs(10),
        deadline: Duration::from_secs(30),
        ..CheckOptions::default()
    };
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::Command { argv: argv.clone() }],
        before_up(),
        &options,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[0] command \"/bin/check\"");
    assert_eq!(failure.reason, "exited with a non-zero status");
    assert_eq!(
        failure.checks.len(),
        1,
        "what it took goes with the failure"
    );
    assert!(failure.checks[0].attempts > 1, "{:?}", failure.checks);
    let execs = docker.count(|c| matches!(c, Call::Exec { argv: a, .. } if *a == argv));
    assert_eq!(execs, 3, "at 0 s, 10 s and 20 s");
}

#[tokio::test(start_paused = true)]
async fn command_that_passes_after_retries_is_reported() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    docker.script_exec([Err("busy"), Ok(false), Ok(true)]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::Command {
            argv: vec!["true".to_owned()],
        }],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(summary.checks[0].attempts, 4);
}

#[tokio::test(start_paused = true)]
async fn log_match_fails_after_window() {
    let docker = FakeDocker::new();
    let info = running(Some("healthy"), &[]);
    let started = info.started_at;
    docker.script_inspect([Ok(info)]);
    docker.script_logs_contain([Ok(true)]);
    let start = Instant::now();
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[
            Check::ContainerHealthy,
            Check::NoLogMatch {
                pattern: "panic".to_owned(),
                within_secs: 20,
            },
        ],
        started,
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[1] no_log_match \"panic\"");
    assert!(failure.reason.contains("within 20 s"), "{failure}");
    assert!(
        start.elapsed() >= Duration::from_secs(19),
        "{:?}",
        start.elapsed()
    );
    assert!(docker.calls().contains(&Call::LogsContain {
        id: crate::testing::container_id(),
        since: started,
        until: started.checked_add(SignedDuration::from_secs(20)).unwrap(),
        needle: "panic".to_owned(),
    }));
}

#[tokio::test(start_paused = true)]
async fn quiet_log_window_passes() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[
            Check::ContainerHealthy,
            Check::NoLogMatch {
                pattern: "panic".to_owned(),
                within_secs: 5,
            },
        ],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert!(summary.checks[1].elapsed >= Duration::from_secs(4));
}

#[tokio::test(start_paused = true)]
async fn log_window_that_closed_after_since_does_not_wait() {
    let docker = FakeDocker::new();
    let mut info = running(Some("healthy"), &[]);
    info.started_at = Timestamp::now()
        .checked_sub(jiff::SignedDuration::from_secs(600))
        .unwrap();
    docker.script_inspect([Ok(info)]);
    let options = CheckOptions::default();
    let start = Instant::now();
    run_checks(
        &docker,
        dir(),
        "app",
        &[
            Check::ContainerHealthy,
            Check::NoLogMatch {
                pattern: "panic".to_owned(),
                within_secs: 30,
            },
        ],
        before_up(),
        &options,
    )
    .await
    .unwrap();
    assert_eq!(start.elapsed(), options.settle, "only the settle time");
}

#[tokio::test(start_paused = true)]
async fn untouched_container_is_observed_for_the_whole_window() {
    // `up` left the container running: it started before `since`, and its
    // window from that start closed before `since` too.
    let docker = FakeDocker::new();
    let since = Timestamp::now();
    let mut info = running(Some("healthy"), &[]);
    info.started_at = since.checked_sub(SignedDuration::from_secs(600)).unwrap();
    docker.script_inspect([Ok(info)]);
    let start = Instant::now();
    run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy, no_log_match(30)],
        since,
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    let until = since.checked_add(SignedDuration::from_secs(30)).unwrap();
    assert!(
        docker.calls().contains(&Call::LogsContain {
            id: crate::testing::container_id(),
            since,
            until,
            needle: "panic".to_owned(),
        }),
        "{:?}",
        docker.calls()
    );
    assert!(
        start.elapsed() >= Duration::from_secs(29),
        "waited for the window: {:?}",
        start.elapsed()
    );
}

#[tokio::test(start_paused = true)]
async fn log_window_waits_for_the_observing_checks() {
    let docker = FakeDocker::new();
    docker.script_inspect([
        Ok(running(Some("starting"), &[])),
        Ok(running(Some("healthy"), &[])),
    ]);
    run_checks(
        &docker,
        dir(),
        "app",
        &[
            Check::NoLogMatch {
                pattern: "panic".to_owned(),
                within_secs: 1,
            },
            Check::ContainerHealthy,
        ],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    let calls = docker.calls();
    let logs = calls
        .iter()
        .filter(|c| matches!(c, Call::LogsContain { .. }))
        .count();
    assert_eq!(logs, 2, "scanned in the two rounds where it was healthy");
}

#[tokio::test(start_paused = true)]
async fn all_observing_checks_must_pass_in_one_round() {
    let docker = FakeDocker::new();
    docker.script_inspect([
        Ok(running(Some("healthy"), &[])),
        Ok(running(Some("unhealthy"), &[])),
        Ok(running(Some("healthy"), &[])),
    ]);
    docker.script_exec([Ok(false), Ok(true)]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[
            Check::ContainerHealthy,
            Check::Command {
                argv: vec!["probe".to_owned()],
            },
        ],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(
        summary.checks[0].attempts, 4,
        "health re-checked every round"
    );
    assert_eq!(
        summary.checks[1].attempts, 3,
        "skipped in the round health failed"
    );
}

#[tokio::test(start_paused = true)]
async fn deadline_is_respected() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("starting"), &[]))]);
    let options = CheckOptions {
        interval: Duration::from_secs(10),
        deadline: Duration::from_secs(25),
        ..CheckOptions::default()
    };
    let start = Instant::now();
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy],
        before_up(),
        &options,
    )
    .await
    .unwrap_err();
    assert_eq!(failure.reason, "health is \"starting\"");
    assert_eq!(start.elapsed(), Duration::from_secs(25));
    assert_eq!(inspects(&docker), 3, "at 0 s, 10 s and 20 s");
}
