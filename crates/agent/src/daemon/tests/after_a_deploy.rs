//! What must hold once a deploy has ended, or can't start: a controller can't run
//! a release in circles, a report isn't lost to an answer that isn't the API's,
//! and nothing wedges the host for ever or stops it from reporting.

use std::fs;
use std::time::{Duration, Instant};

use landfall_core::protocol::{
    DeployId, DeployReportBody, MAX_BODY_BYTES, ReportedOutcome, ReportedStep,
};
use reqwest::StatusCode;

use super::super::{Backoff, Pacing, Shutdown, StepOutcome, VerifyFailure};
use super::{
    COMMIT, FakeController, FakeVerifier, NEW, NEW_DIGEST, OLD, PATCH_RULE, answer, claim,
    container, fixture, image, options_for, origin, outbox, poll, state_of, touched, work,
};
use crate::journal::{Priority, capture};
use crate::state::StateDir;
use crate::testing::Call;

fn ups(f: &super::Fixture) -> usize {
    f.docker.count(|c| matches!(c, Call::ComposeUp { .. }))
}

fn finished(outcome: &StepOutcome) -> &ReportedOutcome {
    match outcome {
        StepOutcome::Finished { outcome, .. } | StepOutcome::Replayed { outcome, .. } => outcome,
        other => panic!("not finished: {other:?}"),
    }
}

#[tokio::test]
async fn a_controller_cannot_drive_a_release_round_deploy_and_rollback() {
    let f = fixture(PATCH_RULE);
    // The release fails its check for good; the previous version comes back.
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(8, "v1.2.4"))),
    ]);
    let verifier = FakeVerifier::passes();

    let first = poll(&f, &controller, &verifier).await;
    assert!(
        matches!(finished(&first), ReportedOutcome::RolledBack { .. }),
        "{first:?}"
    );
    assert_eq!(ups(&f), 2, "the deploy's and the rollback's");

    // The same number again: its original report, and nothing runs.
    let again = poll(&f, &controller, &verifier).await;
    assert!(matches!(again, StepOutcome::Replayed { .. }), "{again:?}");
    assert_eq!(finished(&again), finished(&first));
    assert_eq!(ups(&f), 2);
    assert_eq!(capture::events("finished_work_delivered_again").len(), 1);

    // A new number for the same release: refused, and nothing runs.
    let renamed = poll(&f, &controller, &verifier).await;
    let ReportedOutcome::Refused { reason } = finished(&renamed) else {
        panic!("not refused: {renamed:?}");
    };
    assert!(reason.contains("isn't retried"), "{reason}");
    assert_eq!(ups(&f), 2);
    assert_eq!(verifier.calls(), 1, "and it costs no fetch");

    let reports = controller.reports();
    assert_eq!(
        reports.iter().map(|r| r.deploy_id.0).collect::<Vec<_>>(),
        [7, 7, 8]
    );
    assert_eq!(reports[0], reports[1], "the original report");

    // A newer release is another matter.
    f.docker
        .script_compose_service([Ok(image(OLD)), Ok(image(NEW)), Ok(image(OLD))]);
    f.docker
        .script_inspect_after_up(3, [Ok(container(NEW, true))]);
    let controller = FakeController::with([answer(Some(work(9, "v1.2.5")))]);
    let newer = poll(&f, &controller, &verifier).await;
    assert_eq!(finished(&newer), &ReportedOutcome::Deployed {});
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.5"
    );
}

#[tokio::test]
async fn a_release_that_failed_stays_refused_after_a_restart() {
    let f = fixture(PATCH_RULE);
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    poll(&f, &controller, &FakeVerifier::passes()).await;

    // Nothing but the state directory is carried over.
    let again = FakeController::with([answer(Some(work(8, "v1.2.4")))]);
    let options = options_for(f.options.dirs.clone());
    let outcome = Box::pin(super::super::step(
        &f.docker,
        &again,
        &FakeVerifier::passes(),
        &f.config,
        &f.state_dir,
        &options,
    ))
    .await;
    assert!(
        matches!(finished(&outcome), ReportedOutcome::Refused { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_deploy_whose_report_was_refused_for_good_is_answered_with_it_not_refused() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    *controller.report_rejected.lock().unwrap() = true;
    let verifier = FakeVerifier::passes();
    poll(&f, &controller, &verifier).await;
    assert_eq!(outbox(&f), []);

    // It comes back, once the controller knows better.
    *controller.report_rejected.lock().unwrap() = false;
    controller
        .answers
        .lock()
        .unwrap()
        .push_back(answer(Some(work(7, "v1.2.4"))));
    let outcome = poll(&f, &controller, &verifier).await;

    assert_eq!(finished(&outcome), &ReportedOutcome::Deployed {});
    assert_eq!(
        controller.reports()[0].outcome,
        ReportedOutcome::Deployed {}
    );
    assert!(
        controller.reports()[0].steps.iter().any(|s| s.name == "up"),
        "the original report, not a new one"
    );
    assert_eq!(ups(&f), 1);
}

#[tokio::test]
async fn an_answer_that_is_not_the_apis_keeps_the_report() {
    for status in [StatusCode::NOT_FOUND, StatusCode::FORBIDDEN] {
        let f = fixture(PATCH_RULE);
        let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
        *controller.report_status.lock().unwrap() = Some(status);
        let verifier = FakeVerifier::passes();

        let outcome = poll(&f, &controller, &verifier).await;

        assert!(
            matches!(
                outcome,
                StepOutcome::Finished {
                    delivered: false,
                    ..
                }
            ),
            "{outcome:?}"
        );
        assert_eq!(outbox(&f).len(), 1, "{status}");
        assert_eq!(capture::events("report_rejected").len(), 0);
        let outcome = poll(&f, &controller, &verifier).await;
        assert!(
            matches!(outcome, StepOutcome::Unavailable { .. }),
            "{outcome:?}"
        );
        assert_eq!(outbox(&f).len(), 1, "{status}");

        *controller.report_status.lock().unwrap() = None;
        assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
        assert_eq!(
            controller.reports()[0].outcome,
            ReportedOutcome::Deployed {}
        );
    }
}

fn pacing() -> Pacing {
    let backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(64));
    Pacing::new(Duration::from_secs(1), backoff, Duration::from_secs(300))
}

fn refused() -> StepOutcome {
    StepOutcome::Finished {
        deploy_id: DeployId(7),
        outcome: ReportedOutcome::Refused {
            reason: "no".to_owned(),
        },
        delivered: true,
    }
}

#[test]
fn a_delivered_refusal_cannot_repeat_every_second() {
    let mut pacing = pacing();
    let now = Instant::now();
    for full in [1, 2, 4, 8, 16, 32, 64, 64].map(Duration::from_secs) {
        let delay = pacing.after(&refused(), now);
        assert!(delay >= full / 2 && delay <= full, "{delay:?} for {full:?}");
        // Answers of no work between them don't start it over.
        assert_eq!(
            pacing.after(&StepOutcome::NoWork, now),
            Duration::from_secs(1)
        );
    }
}

#[test]
fn the_backoff_starts_over_after_a_quiet_spell_or_a_deploy() {
    let deployed = StepOutcome::Finished {
        deploy_id: DeployId(7),
        outcome: ReportedOutcome::Deployed {},
        delivered: true,
    };
    let now = Instant::now();
    for reset in [0, 1] {
        let mut pacing = pacing();
        for _ in 0..6 {
            pacing.after(&refused(), now);
        }
        if reset == 0 {
            pacing.after(&StepOutcome::NoWork, now + Duration::from_secs(300));
        } else {
            assert_eq!(pacing.after(&deployed, now), Duration::from_secs(1));
        }
        assert!(pacing.after(&refused(), now) <= Duration::from_secs(1));
    }
}

#[test]
fn a_rollback_or_an_undelivered_report_makes_the_backoff_grow() {
    let mut pacing = pacing();
    let now = Instant::now();
    let rolled_back = StepOutcome::Finished {
        deploy_id: DeployId(7),
        outcome: ReportedOutcome::RolledBack {
            reason: "no".to_owned(),
        },
        delivered: true,
    };
    let undelivered = StepOutcome::Finished {
        deploy_id: DeployId(8),
        outcome: ReportedOutcome::Deployed {},
        delivered: false,
    };
    pacing.after(&rolled_back, now);
    pacing.after(&undelivered, now);
    assert!(pacing.after(&rolled_back, now) >= Duration::from_secs(2));
}

#[test]
fn resets_on_one_report_keep_the_backoff_growing_up_to_its_bound() {
    let mut pacing = pacing();
    let now = Instant::now();
    let reset = StepOutcome::Unavailable {
        error: "connection reset".to_owned(),
    };
    for full in [1, 2, 4, 8, 16, 32, 64, 64, 64].map(Duration::from_secs) {
        let delay = pacing.after(&reset, now);
        assert!(delay >= full / 2 && delay <= full, "{delay:?} for {full:?}");
    }
}

#[tokio::test]
async fn nothing_over_the_limit_leaves_the_outbox_however_it_got_there() {
    let f = fixture(PATCH_RULE);
    let text = "\u{1}".repeat(4096);
    let oversized = DeployReportBody {
        deploy_id: DeployId(7),
        outcome: ReportedOutcome::Deployed {},
        steps: vec![
            ReportedStep {
                name: "checks".to_owned(),
                millis: 1,
                failure: Some(text),
                detail: None,
            };
            100
        ],
    };
    assert!(serde_json::to_vec(&oversized).unwrap().len() > MAX_BODY_BYTES);
    StateDir::open(&f.state_dir)
        .unwrap()
        .outbox_put(&oversized)
        .unwrap();
    let controller = FakeController::default();

    assert_eq!(
        poll(&f, &controller, &FakeVerifier::passes()).await,
        StepOutcome::NoWork
    );

    let sent = controller.reports();
    assert_eq!(sent.len(), 1);
    assert!(serde_json::to_vec(&sent[0]).unwrap().len() <= MAX_BODY_BYTES);
    assert_eq!(sent[0].deploy_id, DeployId(7));
    assert_eq!(sent[0].steps.last().unwrap().name, "report_trimmed");
    assert_eq!(outbox(&f), []);
}

fn missing() -> FakeVerifier {
    FakeVerifier::answering(Err(VerifyFailure::Missing(
        "image index: 404 not found".to_owned(),
    )))
}

#[tokio::test]
async fn a_release_that_stays_missing_is_refused_after_the_bound() {
    let mut f = fixture(PATCH_RULE);
    f.options.verification_bound = Duration::from_millis(50);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
    ]);
    let verifier = missing();

    let outcome = poll(&f, &controller, &verifier).await;
    assert!(
        matches!(outcome, StepOutcome::Waiting { .. }),
        "{outcome:?}"
    );
    assert_eq!(controller.reports(), []);

    tokio::time::sleep(Duration::from_millis(60)).await;
    let outcome = poll(&f, &controller, &verifier).await;

    let ReportedOutcome::Refused { reason } = finished(&outcome) else {
        panic!("not refused: {outcome:?}");
    };
    assert!(reason.contains("404"), "{reason}");
    assert_eq!(controller.reports().len(), 1);
    assert_eq!(touched(&f.docker), []);
    assert_eq!(
        state_of(&f).verification_wait().unwrap(),
        None,
        "the wait is over"
    );
    assert!(
        !capture::events("verification_still_waiting").is_empty(),
        "and the journal heard"
    );
}

#[tokio::test]
async fn a_release_missing_within_the_bound_goes_on_waiting() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
    ]);
    let verifier = missing();
    for _ in 0..2 {
        let outcome = poll(&f, &controller, &verifier).await;
        assert!(
            matches!(outcome, StepOutcome::Waiting { .. }),
            "{outcome:?}"
        );
    }
    assert_eq!(controller.reports(), []);
}

#[tokio::test]
async fn an_unreachable_registry_is_waited_for_past_the_bound_and_said_each_period() {
    let mut f = fixture(PATCH_RULE);
    f.options.verification_bound = Duration::from_millis(20);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
    ]);
    let verifier =
        FakeVerifier::answering(Err(VerifyFailure::Unavailable("rate limit".to_owned())));

    for _ in 0..3 {
        let outcome = poll(&f, &controller, &verifier).await;
        assert!(
            matches!(outcome, StepOutcome::Waiting { .. }),
            "{outcome:?}"
        );
        tokio::time::sleep(Duration::from_millis(30)).await;
    }

    assert_eq!(controller.reports(), []);
    let events = capture::events("verification_still_waiting");
    assert_eq!(events.len(), 2, "{events:?}");
    assert_eq!(events[0].0, Priority::Warning);
}

#[tokio::test]
async fn the_wait_survives_a_restart_and_goes_by_no_wall_clock() {
    let mut f = fixture(PATCH_RULE);
    f.options.verification_bound = Duration::from_mins(60);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    poll(&f, &controller, &missing()).await;
    // 59 minutes and a bit already waited, by the last run.
    let mut wait = state_of(&f).verification_wait().unwrap().unwrap();
    wait.waited_millis = 3_600_000 - 20;
    state_of(&f).set_verification_wait(&wait).unwrap();

    let mut restarted = options_for(f.options.dirs.clone());
    restarted.verification_bound = Duration::from_mins(60);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
    ]);
    let verifier = missing();
    let step = |options| {
        Box::pin(super::super::step(
            &f.docker,
            &controller,
            &verifier,
            &f.config,
            &f.state_dir,
            options,
        ))
    };
    // Time a stopped agent didn't see doesn't count: the first look adds nothing.
    let outcome = step(&restarted).await;
    assert!(
        matches!(outcome, StepOutcome::Waiting { .. }),
        "{outcome:?}"
    );
    tokio::time::sleep(Duration::from_millis(30)).await;
    let outcome = step(&restarted).await;
    assert!(
        matches!(finished(&outcome), ReportedOutcome::Refused { .. }),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn a_wait_counts_for_its_own_deploy_only_and_ends_when_it_verifies() {
    let mut f = fixture(PATCH_RULE);
    f.options.verification_bound = Duration::from_mins(60);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    poll(&f, &controller, &missing()).await;
    let mut wait = state_of(&f).verification_wait().unwrap().unwrap();
    wait.waited_millis = 3_600_000;
    state_of(&f).set_verification_wait(&wait).unwrap();

    // Another number starts from nothing.
    let controller = FakeController::with([answer(Some(work(8, "v1.2.4")))]);
    let outcome = poll(&f, &controller, &missing()).await;
    assert!(
        matches!(outcome, StepOutcome::Waiting { .. }),
        "{outcome:?}"
    );

    // It verifies after all.
    let controller = FakeController::with([answer(Some(work(8, "v1.2.4")))]);
    let verifier = FakeVerifier::answering(Ok(origin(NEW_DIGEST, COMMIT)));
    let outcome = poll(&f, &controller, &verifier).await;
    assert_eq!(finished(&outcome), &ReportedOutcome::Deployed {});
    assert_eq!(state_of(&f).verification_wait().unwrap(), None);
}

#[tokio::test]
async fn a_stop_during_verification_starts_no_deploy() {
    let mut f = fixture(PATCH_RULE);
    let (trigger, shutdown) = Shutdown::channel();
    f.options.shutdown = shutdown;
    let verifier = FakeVerifier::passes();
    *verifier.stop.lock().unwrap() = Some(trigger);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &verifier).await;

    assert_eq!(outcome, StepOutcome::ShuttingDown);
    assert_eq!(verifier.calls(), 1);
    assert_eq!(touched(&f.docker), []);
    assert_eq!(state_of(&f).claim().unwrap(), None);
    assert_eq!(controller.reports(), []);
}

#[tokio::test]
async fn a_corrupt_report_or_claim_is_set_aside_and_the_host_goes_on_reporting() {
    let f = fixture(PATCH_RULE);
    let root = StateDir::open(&f.state_dir).unwrap();
    let good = landfall_core::protocol::DeployReportBody {
        deploy_id: DeployId(2),
        outcome: ReportedOutcome::Deployed {},
        steps: Vec::new(),
    };
    root.outbox_put(&good).unwrap();
    fs::write(f.state_dir.join("outbox/1.json"), "{").unwrap();
    state_of(&f).set_claim(&claim(3)).unwrap();
    let claim_file = f.state_dir.join("app__prod/controller-claim.json");
    fs::write(&claim_file, "{").unwrap();
    let controller = FakeController::default();

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    assert_eq!(outcome, StepOutcome::NoWork);
    assert_eq!(controller.reports(), [good], "the good report went out");
    assert_eq!(controller.requests().len(), 1, "and the host was heard");
    assert!(f.state_dir.join("outbox/1.json.corrupt.1").exists());
    assert!(claim_file.with_extension("json.corrupt.1").exists());
}

#[tokio::test]
async fn trouble_with_one_deployments_claim_does_not_stop_the_poll() {
    let f = fixture(PATCH_RULE);
    state_of(&f).set_claim(&claim(3)).unwrap();
    // A marker that can't be read, which settling has to look at.
    fs::write(f.state_dir.join("app__prod/in-progress.json"), "{").unwrap();
    let controller = FakeController::default();

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    assert_eq!(outcome, StepOutcome::NoWork);
    assert_eq!(controller.requests().len(), 1);
    assert_eq!(capture::events("claim_not_settled").len(), 1);
    assert_eq!(capture::events("claim_not_settled")[0].0, Priority::Error);
}
