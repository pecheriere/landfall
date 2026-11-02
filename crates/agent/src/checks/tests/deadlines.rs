//! What the deadline cuts off.

use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use jiff::SignedDuration;
use landfall_core::config::Check;
use tokio::time::Instant;

use super::super::{CheckOptions, run_checks};
use super::{before_up, command, dir, no_log_match, restarted, short};
use crate::testing::{Call, FakeDocker, running};

#[tokio::test(start_paused = true)]
async fn a_blocked_call_ends_at_the_deadline_naming_the_check() {
    let docker = FakeDocker::new();
    docker.hang_when(|c| matches!(c, Call::Exec { .. }));
    docker.script_inspect([Ok(running(None, &[]))]);
    let options = CheckOptions {
        deadline: Duration::from_secs(30),
        ..CheckOptions::default()
    };
    let start = Instant::now();
    let failure = run_checks(&docker, dir(), "app", &[command()], before_up(), &options)
        .await
        .unwrap_err();
    assert_eq!(start.elapsed(), options.deadline);
    assert_eq!(failure.check, "checks[0] command \"/bin/check\"");
    assert_eq!(failure.reason, "no answer before the deadline");
}

#[tokio::test(start_paused = true)]
async fn a_call_cut_off_by_the_deadline_keeps_the_earlier_failure() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("starting"), &[]))]);
    let seen = Arc::new(Mutex::new(0));
    let inspected = Arc::clone(&seen);
    docker.on_call(move |c| {
        if matches!(c, Call::Inspect(_)) {
            *inspected.lock().unwrap() += 1;
        }
    });
    let hang = Arc::clone(&seen);
    docker.hang_when(move |c| matches!(c, Call::Inspect(_)) && *hang.lock().unwrap() >= 2);
    let options = CheckOptions {
        deadline: Duration::from_secs(30),
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
    assert_eq!(start.elapsed(), options.deadline);
    assert_eq!(failure.reason, "health is \"starting\"");
}

/// In real time: the second round must find the window closed, and paused
/// time would not move the wall clock the window is measured on.
#[tokio::test]
async fn a_log_window_longer_than_the_deadline_can_pass() {
    let docker = FakeDocker::new();
    let mut info = running(None, &[]);
    info.started_at = info
        .started_at
        .checked_sub(SignedDuration::from_secs(299))
        .unwrap();
    docker.script_inspect([Ok(info)]);
    docker.script_exec([Ok(true)]);
    let options = CheckOptions {
        deadline: Duration::from_millis(500),
        ..short()
    };
    let start = Instant::now();
    run_checks(
        &docker,
        dir(),
        "app",
        &[command(), no_log_match(300)],
        before_up(),
        &options,
    )
    .await
    .unwrap();
    assert!(start.elapsed() > options.deadline, "{:?}", start.elapsed());
}

#[tokio::test(start_paused = true)]
async fn a_crash_loop_cannot_wait_for_window_after_window() {
    let docker = FakeDocker::new();
    let up = running(None, &[]);
    docker.script_inspect((0..200).map(|i| Ok(restarted(&up, i))));
    docker.script_exec([Ok(true)]);
    let options = CheckOptions {
        deadline: Duration::from_secs(30),
        ..CheckOptions::default()
    };
    let start = Instant::now();
    run_checks(
        &docker,
        dir(),
        "app",
        &[command(), no_log_match(100)],
        before_up(),
        &options,
    )
    .await
    .unwrap_err();
    assert!(
        start.elapsed() <= options.deadline + Duration::from_secs(100),
        "{:?}",
        start.elapsed()
    );
}
