//! Starting, stopping, pacing, and what the controller is told along the way.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use landfall_core::protocol::{
    DeployId, HeldBack, Phase, ReportedOutcome, RunningState, WorkResponse,
};
use sha2::{Digest as _, Sha256};

use super::super::{Backoff, DaemonError, Shutdown, StepOutcome, run_loop, start_up};
use super::{
    Answer, FakeController, FakeVerifier, PATCH_RULE, answer, bare_fixture, container, deployed_at,
    deployment_text, fixture, fleet, id, marker, poll, state_of, touched, work,
};
use crate::compose::ComposeError;
use crate::enrol;
use crate::journal::{Priority, capture};
use crate::state::{StateDir, StateError};
use crate::testing::Call;

#[tokio::test]
async fn drift_is_read_no_more_often_than_asked_and_changes_reach_the_journal() {
    let mut f = fixture(PATCH_RULE);
    f.options.drift_every = Duration::from_secs(3600);
    let controller = FakeController::default();
    let verifier = FakeVerifier::passes();
    for _ in 0..3 {
        assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    }
    assert_eq!(f.docker.count(|c| matches!(c, Call::ContainerAt { .. })), 1);

    f.options.drift_every = Duration::ZERO;
    f.docker
        .script_inspect_after_up(0, [Ok(container("ghcr.io/example/app@sha256:ff", true))]);
    assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    assert!(controller.requests().last().unwrap().running[0].drift);
    let events = capture::events("drift_changed");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, Priority::Warning);
    assert_eq!(events[0].1["drift"], true);
}

#[tokio::test]
async fn running_state_comes_from_the_marker_and_the_record() {
    let f = bare_fixture(PATCH_RULE);
    let controller = FakeController::default();
    let verifier = FakeVerifier::passes();

    // Never deployed: it is listed, with a null record.
    poll(&f, &controller, &verifier).await;
    let first = controller.requests()[0].clone();
    assert_eq!(first.config_hash, [9; 32]);
    assert_eq!(
        first.running,
        [RunningState {
            deployment: id(),
            deployed: None,
            drift: false,
            phase: Phase::Idle,
            busy: false,
        }]
    );

    // Every phase, as the marker has it, none of them running here.
    for (phase, wire) in [
        (crate::state::Phase::Preflight, Phase::Preflight),
        (crate::state::Phase::Deploying, Phase::Deploying),
        (crate::state::Phase::RollingBack, Phase::RollingBack),
        (crate::state::Phase::Restored, Phase::Restored),
        (crate::state::Phase::RolledBack, Phase::RolledBack),
    ] {
        state_of(&f).set_in_progress(&marker(phase)).unwrap();
        poll(&f, &controller, &verifier).await;
        let last = controller.requests().last().unwrap().running[0].clone();
        assert_eq!(last.phase, wire);
        assert!(!last.busy);
        assert_eq!(last.deployed, None, "a blocked first deploy has no record");
    }

    state_of(&f).clear_in_progress().unwrap();
    state_of(&f)
        .set_deployed(&deployed_at("v1.2.3", 1, 2, 3))
        .unwrap();
    poll(&f, &controller, &verifier).await;
    let last = controller.requests().last().unwrap().running[0].clone();
    assert_eq!(last.phase, Phase::Idle);
    assert_eq!(last.deployed.unwrap().tag.as_ref(), "v1.2.3");
}

#[tokio::test]
async fn a_running_deploy_is_busy_in_what_the_controller_is_told() {
    let mut f = fixture(PATCH_RULE);
    f.options.heartbeat = Duration::from_millis(5);
    // Long enough for a few heartbeats between the checks' two rounds.
    f.options.engine.checks.settle = Duration::from_millis(100);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;
    assert!(
        matches!(
            &outcome,
            StepOutcome::Finished {
                outcome: ReportedOutcome::Deployed {},
                ..
            }
        ),
        "{outcome:?}"
    );

    let requests = controller.requests();
    assert!(!requests[0].running[0].busy, "before the deploy");
    assert!(
        requests
            .iter()
            .any(|request| request.running[0].busy && request.running[0].phase == Phase::Deploying),
        "a heartbeat during the deploy says so, with the marker's phase"
    );

    assert_eq!(
        poll(&f, &controller, &FakeVerifier::passes()).await,
        StepOutcome::NoWork
    );
    let last = controller.requests().last().unwrap().running[0].clone();
    assert!(!last.busy, "after the deploy");
    assert_eq!(last.phase, Phase::Idle);
    assert_eq!(last.deployed.unwrap().tag.as_ref(), "v1.2.4");
}

#[tokio::test]
async fn work_delivered_again_during_a_deploy_is_left_alone() {
    let mut f = fixture(PATCH_RULE);
    f.options.heartbeat = Duration::from_millis(5);
    f.options.engine.checks.settle = Duration::from_millis(100);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(8, "v1.2.5"))),
    ]);

    poll(&f, &controller, &FakeVerifier::passes()).await;

    assert_eq!(f.docker.count(|c| matches!(c, Call::ComposeUp { .. })), 1);
    assert_eq!(controller.reports().len(), 1);
    assert_eq!(controller.reports()[0].deploy_id, DeployId(7));
}

#[tokio::test]
async fn held_back_reasons_are_quoted_and_said_once() {
    let f = fixture(PATCH_RULE);
    let held = WorkResponse {
        work: None,
        held_back: vec![HeldBack {
            deployment: id(),
            reason: format!("hash\n<2>forged{}", "x".repeat(10_000)),
        }],
    };
    let controller = FakeController::with([Answer::Work(held.clone()), Answer::Work(held)]);
    let verifier = FakeVerifier::passes();
    poll(&f, &controller, &verifier).await;
    poll(&f, &controller, &verifier).await;
    let events = capture::events("controller_holds_back");
    assert_eq!(events.len(), 1);
    let reason = events[0].1["reason"].as_str().unwrap();
    assert!(!reason.contains('\n') && reason.len() < 128, "{reason}");
}

#[tokio::test]
async fn an_unreachable_controller_is_said_and_nothing_runs() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::default();
    controller.set_down(true);
    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;
    assert!(
        matches!(outcome, StepOutcome::Unavailable { .. }),
        "{outcome:?}"
    );
    assert_eq!(touched(&f.docker), []);
}

#[test]
fn backoff_grows_and_resets() {
    let (min, max) = (Duration::from_secs(1), Duration::from_secs(16));
    let mut backoff = Backoff::new(min, max);
    for full in [1, 2, 4, 8, 16, 16, 16].map(Duration::from_secs) {
        let delay = backoff.next_delay();
        assert!(delay >= full / 2 && delay <= full, "{delay:?} for {full:?}");
    }
    backoff.reset();
    assert!(backoff.next_delay() <= min);
}

#[test]
fn backoff_is_jittered() {
    let mut delays = Vec::new();
    for _ in 0..8 {
        delays.push(Backoff::new(Duration::from_secs(64), Duration::from_secs(64)).next_delay());
    }
    delays.dedup();
    assert!(delays.len() > 1, "{delays:?}");
}

#[tokio::test]
async fn a_stop_during_a_deploy_lets_it_finish_and_report_first() {
    let mut f = fixture(PATCH_RULE);
    let (trigger, shutdown) = Shutdown::channel();
    f.options.shutdown = shutdown;
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            trigger.stop();
        }
    });
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    Box::pin(run_loop(
        &f.docker,
        &controller,
        &FakeVerifier::passes(),
        &f.config,
        &f.state_dir,
        &f.options,
    ))
    .await;

    let reports = controller.reports();
    assert_eq!(reports.len(), 1, "the deploy finished and was reported");
    assert_eq!(reports[0].outcome, ReportedOutcome::Deployed {});
    assert_eq!(state_of(&f).in_progress().unwrap(), None);
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.4"
    );
}

#[tokio::test]
async fn a_stop_ends_a_poll_that_is_waiting_for_an_answer() {
    let mut f = fixture(PATCH_RULE);
    let (trigger, shutdown) = Shutdown::channel();
    f.options.shutdown = shutdown;
    let controller = FakeController::with([Answer::Hang]);
    let verifier = FakeVerifier::passes();

    let (outcome, ()) = tokio::join!(poll(&f, &controller, &verifier), async {
        tokio::task::yield_now().await;
        trigger.stop();
    });

    assert_eq!(outcome, StepOutcome::ShuttingDown);
}

#[tokio::test]
async fn no_deploy_starts_once_a_stop_is_asked_for() {
    let mut f = fixture(PATCH_RULE);
    let (trigger, shutdown) = Shutdown::channel();
    f.options.shutdown = shutdown;
    trigger.stop();
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;
    assert_eq!(outcome, StepOutcome::ShuttingDown);
    assert_eq!(touched(&f.docker), []);
}

#[tokio::test]
async fn sigterm_waits_for_the_deploy() {
    // A real signal into this very process: the handler is installed first, so
    // it can't take the test run down.
    let mut f = fixture(PATCH_RULE);
    f.options.shutdown = Shutdown::on_signals().unwrap();
    let pid = rustix::process::getpid();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            rustix::process::kill_process(pid, rustix::process::Signal::TERM).unwrap();
        }
    });
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let finished = tokio::time::timeout(
        Duration::from_secs(30),
        Box::pin(run_loop(
            &f.docker,
            &controller,
            &FakeVerifier::passes(),
            &f.config,
            &f.state_dir,
            &f.options,
        )),
    )
    .await;

    assert!(finished.is_ok(), "the signal ended the loop");
    let reports = controller.reports();
    assert_eq!(reports.len(), 1, "after the deploy it found in flight");
    assert_eq!(reports[0].outcome, ReportedOutcome::Deployed {});
}

fn write_fleet(dir: &Path, deployments: &[(&str, &Path)]) -> PathBuf {
    let text: String = deployments
        .iter()
        .map(|(id, path)| deployment_text(id, path, PATCH_RULE))
        .collect();
    let ids = deployments
        .iter()
        .map(|(id, _)| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let file = dir.join("fleet.toml");
    fs::write(&file, fleet(&text, &ids)).unwrap();
    file
}

#[test]
fn a_key_the_verifier_would_refuse_refuses_to_start() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let file = write_fleet(tmp.path(), &[("app/prod", &real)]);
    let bad = fs::read_to_string(&file).unwrap().replace(
        "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea",
        "cHVibGljLWtleQ",
    );
    fs::write(&file, bad).unwrap();
    let err = start_up(&file, &"home-1".parse().unwrap(), tmp.path()).unwrap_err();
    assert!(
        matches!(
            &err,
            DaemonError::Config {
                source: landfall_core::config::ConfigError::InvalidApprover { approver, .. },
                ..
            } if approver.to_string() == "operator"
        ),
        "{err}"
    );
}

#[test]
fn aliased_directories_refuse_to_start() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let file = write_fleet(tmp.path(), &[("app/prod", &real), ("app/stage", &link)]);
    let err = start_up(&file, &"home-1".parse().unwrap(), tmp.path()).unwrap_err();
    assert!(
        matches!(err, DaemonError::Compose(ComposeError::Aliased { .. })),
        "{err}"
    );
}

#[test]
fn missing_directory_refuses_to_start() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let gone = tmp.path().join("gone");
    let file = write_fleet(tmp.path(), &[("app/prod", &real), ("app/stage", &gone)]);
    let err = start_up(&file, &"home-1".parse().unwrap(), tmp.path()).unwrap_err();
    assert!(
        matches!(err, DaemonError::Compose(ComposeError::Unusable { .. })),
        "{err}"
    );
}

#[test]
fn a_host_with_no_deployments_refuses_to_start() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let file = write_fleet(tmp.path(), &[("app/prod", &real)]);
    let err = start_up(&file, &"home-2".parse().unwrap(), tmp.path()).unwrap_err();
    assert!(matches!(err, DaemonError::NoDeployments(_)), "{err}");
}

#[test]
fn a_host_that_is_not_enrolled_refuses_to_start() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let file = write_fleet(tmp.path(), &[("app/prod", &real)]);
    let err = start_up(&file, &"home-1".parse().unwrap(), tmp.path()).unwrap_err();
    assert!(
        matches!(err, DaemonError::Key(enrol::EnrolError::NotEnrolled(_))),
        "{err}"
    );
}

#[test]
fn a_second_daemon_refuses_to_start_and_the_hash_is_of_the_files_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let real = tmp.path().join("real");
    fs::create_dir(&real).unwrap();
    let file = write_fleet(tmp.path(), &[("app/prod", &real)]);
    let state = StateDir::open(tmp.path()).unwrap();
    enrol::load_or_create_key(&state).unwrap();
    let host = "home-1".parse().unwrap();

    let started = start_up(&file, &host, tmp.path()).unwrap();
    let want: [u8; 32] = Sha256::digest(fs::read(&file).unwrap()).into();
    assert_eq!(started.config_hash, want);

    let err = start_up(&file, &host, tmp.path()).unwrap_err();
    assert!(
        matches!(err, DaemonError::State(StateError::DaemonBusy(_))),
        "{err}"
    );
}
