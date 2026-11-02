//! That losing the evidence of a failure doesn't let the release run again, and
//! that a replayed number buys nothing: neither a reset backoff nor another
//! release's report.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use landfall_core::protocol::{DeployId, DeployReportBody, MAX_BODY_BYTES, Phase, ReportedOutcome};

use super::super::running::work_request;
use super::super::{Backoff, Pacing, StepOutcome};
use super::{
    FakeController, FakeVerifier, Fixture, NEW, OLD, PATCH_RULE, answer, claim, container, fixture,
    id, image, poll, state_of, work,
};
use crate::deploy;
use crate::journal::{Priority, capture};
use crate::state::{FailedRelease, StateDir};
use crate::testing::Call;

fn ups(f: &Fixture) -> usize {
    f.docker.count(|c| matches!(c, Call::ComposeUp { .. }))
}

/// `v1.2.4` is deployed as id 7 and rolls back: two `up`s.
async fn failed_deploy(f: &Fixture) {
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let outcome = poll(f, &controller, &FakeVerifier::passes()).await;
    assert!(
        matches!(
            &outcome,
            StepOutcome::Finished {
                outcome: ReportedOutcome::RolledBack { .. },
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(ups(f), 2);
}

fn report_file(f: &Fixture) -> PathBuf {
    let state = state_of(f);
    let names = state.report_names().unwrap();
    assert_eq!(names.len(), 1, "{names:?}");
    state.report_path(&names[0])
}

/// The ledger's one record of this number.
fn ledger_file(f: &Fixture, deploy_id: u64) -> PathBuf {
    let prefix = format!("{deploy_id}-");
    let found: Vec<PathBuf> = fs::read_dir(f.state_dir.join("finished"))
        .unwrap()
        .map(|entry| entry.unwrap())
        .filter(|entry| entry.file_name().to_str().unwrap().starts_with(&prefix))
        .map(|entry| entry.path())
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    found.into_iter().next().unwrap()
}

/// Asks for `item` and returns how it was answered. Nothing may run.
async fn answered(f: &Fixture, item: landfall_core::protocol::DeployWork) -> ReportedOutcome {
    let before = ups(f);
    let controller = FakeController::with([answer(Some(item))]);
    let verifier = FakeVerifier::passes();
    let outcome = poll(f, &controller, &verifier).await;
    assert_eq!(ups(f), before, "{outcome:?}");
    assert_eq!(verifier.calls(), 0, "{outcome:?}");
    let StepOutcome::Finished { outcome, .. } = outcome else {
        panic!("not answered: {outcome:?}");
    };
    outcome
}

/// Asks for `item` and returns why it was refused. Nothing may run.
async fn refused(f: &Fixture, item: landfall_core::protocol::DeployWork) -> String {
    match answered(f, item).await {
        ReportedOutcome::Refused { reason } => reason,
        outcome => panic!("not refused: {outcome:?}"),
    }
}

const FAILED_HERE: &str = "failed on this host";

#[tokio::test]
async fn a_corrupt_report_does_not_let_a_failed_release_run_again() {
    let f = fixture(PATCH_RULE);
    failed_deploy(&f).await;
    fs::write(report_file(&f), "{").unwrap();
    let reason = refused(&f, work(8, "v1.2.4")).await;
    assert!(reason.contains(FAILED_HERE), "the record knows: {reason}");
}

#[tokio::test]
async fn a_report_that_cannot_be_opened_does_not_let_a_failed_release_run_again() {
    let f = fixture(PATCH_RULE);
    failed_deploy(&f).await;
    let file = report_file(&f);
    // Root reads through mode 000, so a directory stands in for it there too.
    fs::set_permissions(&file, fs::Permissions::from_mode(0o000)).unwrap();
    let reason = refused(&f, work(8, "v1.2.4")).await;
    assert!(reason.contains(FAILED_HERE), "{reason}");
    fs::remove_file(&file).unwrap();
    fs::create_dir(&file).unwrap();
    let reason = refused(&f, work(9, "v1.2.4")).await;
    assert!(reason.contains(FAILED_HERE), "{reason}");
}

#[tokio::test]
async fn a_corrupt_report_and_ledger_do_not_let_the_same_number_run_again() {
    let f = fixture(PATCH_RULE);
    failed_deploy(&f).await;
    fs::write(report_file(&f), "{").unwrap();
    fs::write(ledger_file(&f, 7), "{").unwrap();
    let reason = refused(&f, work(7, "v1.2.4")).await;
    assert!(reason.contains(FAILED_HERE), "{reason}");
}

#[tokio::test]
async fn a_report_never_written_does_not_let_a_failed_release_run_again() {
    let f = fixture(PATCH_RULE);
    // A file where the engine's reports go, from just before it writes: the
    // daemon has only the outcome the engine handed it.
    let reports = f.state_dir.join("app__prod/reports");
    let blocker = reports.clone();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            fs::write(&blocker, "not a directory").unwrap();
        }
    });
    failed_deploy(&f).await;
    fs::remove_file(&reports).unwrap();
    assert_eq!(state_of(&f).report_names().unwrap().len(), 0);

    let reason = refused(&f, work(8, "v1.2.4")).await;
    assert!(reason.contains(FAILED_HERE), "{reason}");
}

/// Puts `tag` off as unknowable, naming `file`, with the journal saying how to clear
/// it.
async fn assert_fails_closed(f: &Fixture, deploy_id: u64, tag: &str, file: &std::path::Path) {
    let seen = capture::events("failure_evidence_unreadable").len();
    let outcome = answered(f, work(deploy_id, tag)).await;
    let ReportedOutcome::Deferred { reason } = outcome else {
        panic!("not deferred: {outcome:?}");
    };
    assert!(reason.contains("can't tell"), "{reason}");
    assert!(reason.contains(file.to_str().unwrap()), "{reason}");
    let events = capture::events("failure_evidence_unreadable");
    assert_eq!(events.len(), seen + 1);
    let (priority, event) = events.last().unwrap();
    assert_eq!(*priority, Priority::Error);
    assert_eq!(event["file"], file.to_str().unwrap());
    assert!(event["clear"].as_str().unwrap().contains("removing it"));
}

#[tokio::test]
async fn an_unreadable_report_puts_off_what_it_could_be_about_and_can_be_cleared() {
    let f = fixture(PATCH_RULE);
    failed_deploy(&f).await;
    let (report, record) = (report_file(&f), state_of(&f).failed_releases_path());
    fs::remove_file(&record).unwrap();
    fs::write(&report, "{").unwrap();
    // It could be the report of this very release, or of the next.
    assert_fails_closed(&f, 8, "v1.2.4", &report).await;
    assert_fails_closed(&f, 9, "v1.2.5", &report).await;
    assert_eq!(ups(&f), 2);

    // Clearing it forgets, as the line says.
    fs::remove_file(&report).unwrap();
    f.docker
        .script_compose_service([Ok(image(OLD)), Ok(image(NEW)), Ok(image(OLD))]);
    f.docker
        .script_inspect_after_up(3, [Ok(container(NEW, true))]);
    let controller = FakeController::with([answer(Some(work(10, "v1.2.5")))]);
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
}

#[tokio::test]
async fn an_unreadable_record_puts_off_rather_than_counting_as_no_failure() {
    let f = fixture(PATCH_RULE);
    failed_deploy(&f).await;
    let record = state_of(&f).failed_releases_path();
    fs::write(&record, "{").unwrap();
    assert_fails_closed(&f, 8, "v1.2.5", &record).await;
    assert_eq!(fs::read_to_string(&record).unwrap(), "{", "left as it is");
}

#[tokio::test]
async fn a_report_found_after_a_crash_goes_on_the_record() {
    let f = fixture(PATCH_RULE);
    let state = state_of(&f);
    let taken = claim(7);
    state.set_claim(&taken).unwrap();
    let report = deploy::DeployReport {
        deployment: id(),
        tag: taken.tag.clone(),
        digest: taken.digest.clone(),
        outcome: deploy::Outcome::RolledBack {
            reason: "check failed".to_owned(),
        },
        steps: Vec::new(),
        started_at: jiff::Timestamp::UNIX_EPOCH,
        finished_at: jiff::Timestamp::UNIX_EPOCH,
    };
    state.write_report("found", &report).unwrap();
    let controller = FakeController::default();

    poll(&f, &controller, &FakeVerifier::passes()).await;

    assert_eq!(
        state.failed_releases().unwrap(),
        [FailedRelease {
            tag: taken.tag,
            digest: taken.digest,
        }]
    );
}

#[tokio::test]
async fn a_release_that_deployed_is_not_on_the_record() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    poll(&f, &controller, &FakeVerifier::passes()).await;
    assert_eq!(state_of(&f).failed_releases().unwrap(), []);
}

#[tokio::test]
async fn a_number_on_record_naming_another_release_is_judged_like_any_other() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    poll(&f, &controller, &FakeVerifier::passes()).await;
    assert_eq!(ups(&f), 1);
    let on_record = fs::read(ledger_file(&f, 7)).unwrap();

    // What this host would refuse from any number, it refuses from this one.
    let other_digest = format!("sha256:{}", "e".repeat(64));
    let mut other_deployment = work(7, "v1.2.4");
    other_deployment.deployment = "app/stage".parse().unwrap();
    let mut other_release = work(7, "v1.2.5");
    other_release.digest = other_digest.parse().unwrap();
    let verifier = FakeVerifier::passes();
    for (item, says) in [
        (other_deployment, "not a deployment of this host"),
        (other_release, "verifies to digest"),
        (work(7, "v2.0.0"), "manual"),
    ] {
        let controller = FakeController::with([answer(Some(item))]);
        let outcome = poll(&f, &controller, &verifier).await;
        let StepOutcome::Finished {
            outcome: ReportedOutcome::Refused { reason },
            ..
        } = &outcome
        else {
            panic!("not refused: {outcome:?}");
        };
        assert!(reason.contains(says), "{reason}");
        assert_eq!(ups(&f), 1);
    }

    // What it would run from any number, it runs from this one.
    f.docker
        .script_compose_service([Ok(image(NEW)), Ok(image(NEW)), Ok(image(NEW))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(NEW, true))]);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.5")))]);
    let outcome = poll(&f, &controller, &verifier).await;
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
    assert_eq!(ups(&f), 2);
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.5"
    );

    // The release it was for still gets its report, and runs no more than it did.
    let kept: Vec<_> = fs::read_dir(f.state_dir.join("finished"))
        .unwrap()
        .map(|entry| fs::read(entry.unwrap().path()).unwrap())
        .collect();
    assert!(kept.contains(&on_record), "the old record stays as it was");
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let outcome = poll(&f, &controller, &verifier).await;
    assert_eq!(ups(&f), 2);
    assert!(
        matches!(
            &outcome,
            StepOutcome::Replayed {
                outcome: ReportedOutcome::Deployed {},
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[test]
fn a_replay_or_a_rejected_report_cannot_reset_the_backoff() {
    let backoff = Backoff::new(Duration::from_secs(1), Duration::from_secs(64));
    let mut pacing = Pacing::new(Duration::from_secs(1), backoff, Duration::from_secs(300));
    let now = Instant::now();
    let refused = StepOutcome::Finished {
        deploy_id: DeployId(8),
        outcome: ReportedOutcome::Refused {
            reason: "no".to_owned(),
        },
        delivered: true,
    };
    let replay = StepOutcome::Replayed {
        deploy_id: DeployId(7),
        outcome: ReportedOutcome::Deployed {},
        delivered: true,
    };
    let rejected = StepOutcome::Finished {
        deploy_id: DeployId(9),
        outcome: ReportedOutcome::Deployed {},
        delivered: false,
    };
    // Each counts as trouble and doubles what comes next, as the worst case of the
    // reproduction: refusal, replay, refusal, and so on.
    let mut full = Duration::from_secs(1);
    for outcome in [&refused, &replay, &refused, &rejected, &refused, &replay] {
        let delay = pacing.after(outcome, now);
        assert!(delay >= full / 2 && delay <= full, "{delay:?} for {full:?}");
        full *= 2;
    }
}

#[tokio::test]
async fn a_replay_of_a_deployed_id_is_told_from_a_deploy() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([
        answer(Some(work(7, "v1.2.4"))),
        answer(Some(work(7, "v1.2.4"))),
    ]);
    let verifier = FakeVerifier::passes();
    let first = poll(&f, &controller, &verifier).await;
    assert!(matches!(first, StepOutcome::Finished { .. }), "{first:?}");
    let again = poll(&f, &controller, &verifier).await;
    assert!(matches!(again, StepOutcome::Replayed { .. }), "{again:?}");
}

#[tokio::test]
async fn a_rejected_report_is_not_delivered() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    *controller.report_rejected.lock().unwrap() = true;
    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;
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
}

#[tokio::test]
async fn a_two_mebibyte_reason_is_cut_to_fit() {
    let f = fixture(PATCH_RULE);
    for reason in ["x".repeat(2 << 20), "\u{1}".repeat(2 << 20)] {
        let oversized = DeployReportBody {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::NothingChanged { reason },
            steps: Vec::new(),
        };
        StateDir::open(&f.state_dir)
            .unwrap()
            .outbox_put(&oversized)
            .unwrap();
        let controller = FakeController::default();

        poll(&f, &controller, &FakeVerifier::passes()).await;

        let sent = controller.reports();
        assert_eq!(sent.len(), 1);
        let wire = serde_json::to_vec(&sent[0]).unwrap();
        assert!(wire.len() <= MAX_BODY_BYTES, "{}", wire.len());
        assert!(matches!(
            sent[0].outcome,
            ReportedOutcome::NothingChanged { .. }
        ));
    }
}

#[tokio::test]
async fn a_running_deploy_before_its_marker_is_not_called_idle() {
    let f = fixture(PATCH_RULE);
    let request = work_request(&f.docker, &f.config, &f.state_dir, &f.options, Some(&id())).await;
    assert!(request.running[0].busy);
    assert_eq!(request.running[0].phase, Phase::Deploying);
    let request = work_request(&f.docker, &f.config, &f.state_dir, &f.options, None).await;
    assert!(!request.running[0].busy);
    assert_eq!(request.running[0].phase, Phase::Idle);
}
