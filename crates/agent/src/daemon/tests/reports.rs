//! That a deploy's report gets to the controller, once, under the controller's
//! number, whatever happens on the way.

use std::fs;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;
use landfall_core::protocol::{
    DeployId, DeployReportBody, MAX_BODY_BYTES, ReportedDetail, ReportedOutcome, WorkRequest,
    WorkResponse,
};
use reqwest::StatusCode;

use super::super::outbox::{bounded, reported};
use super::super::{StepOutcome, step};
use super::{
    FakeController, FakeVerifier, Fixture, NEW, NEW_DIGEST, OLD, PATCH_RULE, answer, claim,
    container, deployed_at, engine_options, fixture, id, image, marker, options_for, outbox, poll,
    state_of, work,
};
use crate::client::{Controller, ControllerError};
use crate::compose::OVERRIDE_FILE;
use crate::deploy;
use crate::docker::ServiceConfig;
use crate::journal::{Priority, capture};
use crate::testing::Call;

#[tokio::test]
async fn a_release_the_rule_allows_is_deployed_and_reported() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let verifier = FakeVerifier::passes();

    let outcome = poll(&f, &controller, &verifier).await;

    assert_eq!(
        outcome,
        StepOutcome::Finished {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::Deployed {},
            delivered: true,
        }
    );
    assert_eq!(verifier.calls(), 1);
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.4"
    );
    assert_eq!(state_of(&f).claim().unwrap(), None);
    let reports = controller.reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].deploy_id, DeployId(7));
    assert!(reports[0].steps.iter().any(|s| s.name == "up"));
    assert!(reports[0].steps.iter().all(|s| s.failure.is_none()));
    assert_eq!(outbox(&f), []);
    assert_eq!(f.docker.count(|c| matches!(c, Call::ComposeUp { .. })), 1);
    assert_eq!(
        f.docker.count(|c| *c == Call::Pull(NEW.to_owned())),
        1,
        "the verified digest is what gets pulled"
    );
}

#[tokio::test]
async fn a_failed_deploy_reports_its_rollback_with_its_steps() {
    let f = fixture(PATCH_RULE);
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    let reports = controller.reports();
    assert!(
        matches!(reports[0].outcome, ReportedOutcome::RolledBack { .. }),
        "{outcome:?}"
    );
    let checks = reports[0]
        .steps
        .iter()
        .find(|s| s.name == "checks")
        .unwrap();
    assert!(checks.failure.is_some());
    assert!(matches!(checks.detail, Some(ReportedDetail::Checks { .. })));
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.3"
    );
}

#[tokio::test]
async fn a_deploy_the_engine_refuses_to_start_says_nothing_changed() {
    let f = fixture(PATCH_RULE);
    f.docker.script_compose_service([Ok(ServiceConfig {
        image: Some(OLD.to_owned()),
        has_build: true,
        replicas: 1,
    })]);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    poll(&f, &controller, &FakeVerifier::passes()).await;

    let reports = controller.reports();
    assert!(
        matches!(&reports[0].outcome, ReportedOutcome::NothingChanged { reason } if reason.contains("build")),
        "{reports:?}"
    );
    assert_eq!(state_of(&f).claim().unwrap(), None);
}

/// A controller that goes down once the service has been brought up.
struct OutageAfterUp {
    inner: FakeController,
    up: Arc<Mutex<bool>>,
}

impl Controller for OutageAfterUp {
    async fn work(&self, request: &WorkRequest) -> Result<WorkResponse, ControllerError> {
        let down = *self.up.lock().unwrap();
        self.inner.set_down(down);
        self.inner.work(request).await
    }

    async fn report(&self, report: &DeployReportBody) -> Result<(), ControllerError> {
        let down = *self.up.lock().unwrap();
        self.inner.set_down(down);
        self.inner.report(report).await
    }
}

async fn poll_through(
    f: &Fixture,
    controller: &OutageAfterUp,
    verifier: &FakeVerifier,
) -> StepOutcome {
    Box::pin(step(
        &f.docker,
        controller,
        verifier,
        &f.config,
        &f.state_dir,
        &f.options,
    ))
    .await
}

#[tokio::test]
async fn report_survives_a_controller_outage() {
    let f = fixture(PATCH_RULE);
    let up = Arc::new(Mutex::new(false));
    let flag = Arc::clone(&up);
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            *flag.lock().unwrap() = true;
        }
    });
    let controller = OutageAfterUp {
        inner: FakeController::with([answer(Some(work(7, "v1.2.4")))]),
        up,
    };
    let verifier = FakeVerifier::passes();

    let outcome = poll_through(&f, &controller, &verifier).await;

    // The deploy finished, whatever happened to the controller.
    assert_eq!(
        outcome,
        StepOutcome::Finished {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::Deployed {},
            delivered: false,
        }
    );
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.4"
    );
    assert_eq!(controller.inner.reports(), []);
    let kept = outbox(&f);
    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].deploy_id, DeployId(7));

    // Still down: nothing is asked for, and the report stays.
    let asked = controller.inner.requests().len();
    let outcome = poll_through(&f, &controller, &verifier).await;
    assert!(
        matches!(outcome, StepOutcome::Unavailable { .. }),
        "{outcome:?}"
    );
    assert_eq!(controller.inner.requests().len(), asked);
    assert_eq!(outbox(&f).len(), 1);

    // Back: delivered once, and gone.
    *controller.up.lock().unwrap() = false;
    for _ in 0..3 {
        let outcome = poll_through(&f, &controller, &verifier).await;
        assert_eq!(outcome, StepOutcome::NoWork);
    }
    let reports = controller.inner.reports();
    assert_eq!(reports.len(), 1, "once");
    assert_eq!(reports[0].deploy_id, DeployId(7));
    assert_eq!(outbox(&f), []);
}

#[tokio::test]
async fn report_is_sent_once_after_a_restart() {
    let f = fixture(PATCH_RULE);
    let down = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    *down.report_status.lock().unwrap() = Some(StatusCode::SERVICE_UNAVAILABLE);
    let verifier = FakeVerifier::passes();
    let outcome = poll(&f, &down, &verifier).await;
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
    assert_eq!(outbox(&f).len(), 1);

    // A new process: nothing is carried over but the state directory.
    let restarted = FakeController::default();
    let options = options_for(f.options.dirs.clone());
    for _ in 0..2 {
        let outcome = Box::pin(step(
            &f.docker,
            &restarted,
            &verifier,
            &f.config,
            &f.state_dir,
            &options,
        ))
        .await;
        assert_eq!(outcome, StepOutcome::NoWork);
    }
    let reports = restarted.reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].deploy_id, DeployId(7));
    assert_eq!(reports[0].outcome, ReportedOutcome::Deployed {});
    assert!(reports[0].steps.iter().any(|s| s.name == "up"));
}

#[tokio::test]
async fn a_refusal_survives_an_outage_too() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.3.0")))]);
    *controller.report_status.lock().unwrap() = Some(StatusCode::BAD_GATEWAY);
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
    assert!(matches!(
        outbox(&f)[0].outcome,
        ReportedOutcome::Refused { .. }
    ));
}

#[tokio::test]
async fn a_report_the_controller_refuses_for_good_is_dropped_loudly() {
    let f = fixture(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    *controller.report_rejected.lock().unwrap() = true;

    let outcome = poll(&f, &controller, &verifier).await;

    assert!(
        matches!(
            outcome,
            StepOutcome::Finished {
                delivered: true,
                ..
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(outbox(&f), []);
    let events = capture::events("report_rejected");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, Priority::Error);
    assert_eq!(*controller.report_attempts.lock().unwrap(), 1);
    // The engine's own record stays.
    assert_eq!(state_of(&f).report_names().unwrap().len(), 1);
}

/// The state a crash leaves: the engine marked the deploy and died.
#[tokio::test]
async fn a_report_after_a_crash_and_a_recover_names_the_controllers_deploy() {
    let f = fixture(PATCH_RULE);
    let state = state_of(&f);
    state.set_claim(&claim(7)).unwrap();
    state
        .set_previous_override(fs::read(f.compose.join(OVERRIDE_FILE)).unwrap().as_slice())
        .unwrap();
    state
        .set_previous_deployed(state.deployed().unwrap().as_ref())
        .unwrap();
    state
        .set_in_progress(&marker(crate::state::Phase::Deploying))
        .unwrap();

    // The daemon comes back: it says so, and waits.
    let controller = FakeController::default();
    let verifier = FakeVerifier::passes();
    assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    assert_eq!(controller.reports(), []);
    let seen = controller.requests();
    assert_eq!(
        seen[0].running[0].phase,
        landfall_core::protocol::Phase::Deploying
    );
    assert!(!seen[0].running[0].busy, "interrupted, not running");
    assert_eq!(
        state.claim().unwrap().map(|c| c.deploy_id),
        Some(DeployId(7))
    );

    // The operator runs `recover`, which knows nothing of the controller.
    let deployment = f.config.deployment(&id()).unwrap();
    f.docker.script_compose_service([Ok(image(OLD))]);
    f.docker
        .script_inspect_after_up(1, [Ok(container(OLD, true))]);
    let report = deploy::recover(&f.docker, &state, deployment, &f.compose, &engine_options())
        .await
        .unwrap();
    assert!(
        matches!(report.outcome, deploy::Outcome::RolledBack { .. }),
        "{report:?}"
    );

    // The next poll reports it under the controller's number.
    assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    let reports = controller.reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].deploy_id, DeployId(7));
    assert!(
        matches!(reports[0].outcome, ReportedOutcome::RolledBack { .. }),
        "{:?}",
        reports[0].outcome
    );
    assert!(!reports[0].steps.is_empty(), "with its steps");
    assert_eq!(state.claim().unwrap(), None);

    // And only once.
    assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    assert_eq!(controller.reports().len(), 1);
}

#[tokio::test]
async fn a_claim_is_left_alone_while_recover_holds_the_lock() {
    let f = fixture(PATCH_RULE);
    let state = state_of(&f);
    state.set_claim(&claim(7)).unwrap();
    let held = state.lock().unwrap();
    let controller = FakeController::default();

    assert_eq!(
        poll(&f, &controller, &FakeVerifier::passes()).await,
        StepOutcome::NoWork
    );

    assert_eq!(
        state.claim().unwrap().map(|c| c.deploy_id),
        Some(DeployId(7))
    );
    drop(held);
}

#[tokio::test]
async fn a_crash_after_the_record_but_before_the_report_is_reported_as_deployed() {
    let f = fixture(PATCH_RULE);
    let state = state_of(&f);
    let taken = claim(7);
    state.set_claim(&taken).unwrap();
    let mut record = deployed_at("v1.2.4", 1, 2, 4);
    record.digest = taken.digest.clone();
    state.set_deployed(&record).unwrap();
    let controller = FakeController::default();

    assert_eq!(
        poll(&f, &controller, &FakeVerifier::passes()).await,
        StepOutcome::NoWork
    );

    let reports = controller.reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(reports[0].deploy_id, DeployId(7));
    assert_eq!(reports[0].outcome, ReportedOutcome::Deployed {});
}

#[tokio::test]
async fn a_crash_after_the_engines_report_sends_that_report() {
    let f = fixture(PATCH_RULE);
    let state = state_of(&f);
    let mut taken = claim(7);
    taken.reports_before = vec!["older.json".to_owned()];
    state.set_claim(&taken).unwrap();
    // Before the claim by the list, however late its clock says it was.
    let older = deploy::DeployReport {
        deployment: id(),
        tag: taken.tag.clone(),
        digest: taken.digest.clone(),
        outcome: deploy::Outcome::Deployed,
        steps: Vec::new(),
        started_at: Timestamp::now(),
        finished_at: Timestamp::now(),
    };
    state.write_report("older", &older).unwrap();
    // After the claim by the list, on a clock that has gone back to 1970.
    let report = deploy::DeployReport {
        outcome: deploy::Outcome::RolledBack {
            reason: "check failed".to_owned(),
        },
        started_at: Timestamp::UNIX_EPOCH,
        finished_at: Timestamp::UNIX_EPOCH,
        ..older.clone()
    };
    state.write_report("newer", &report).unwrap();
    let other_release = deploy::DeployReport {
        tag: "v9.9.9".parse().unwrap(),
        started_at: Timestamp::now(),
        ..older
    };
    state.write_report("other", &other_release).unwrap();
    let controller = FakeController::default();

    poll(&f, &controller, &FakeVerifier::passes()).await;

    let reports = controller.reports();
    assert_eq!(reports.len(), 1);
    assert_eq!(
        reports[0].outcome,
        ReportedOutcome::RolledBack {
            reason: "check failed".to_owned()
        }
    );
}

#[tokio::test]
async fn a_claim_with_nothing_to_show_is_dropped_and_the_work_runs_when_delivered_again() {
    let f = fixture(PATCH_RULE);
    state_of(&f).set_claim(&claim(7)).unwrap();
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    assert_eq!(
        outcome,
        StepOutcome::Finished {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::Deployed {},
            delivered: true,
        }
    );
    assert_eq!(controller.reports().len(), 1);
}

#[test]
fn a_report_stays_under_the_limits_of_the_wire() {
    let long = "x".repeat(100_000);
    let report = deploy::DeployReport {
        deployment: id(),
        tag: "v1.2.4".parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        outcome: deploy::Outcome::RollbackFailed {
            reason: long.clone(),
            rollback_reason: long.clone(),
        },
        steps: vec![deploy::Step {
            name: "checks".to_owned(),
            started_at: Timestamp::UNIX_EPOCH,
            millis: 1,
            result: deploy::StepResult::Failed {
                reason: long.clone(),
            },
            detail: Some(deploy::StepDetail::Checks {
                checks: vec![
                    deploy::CheckTiming {
                        check: long.clone(),
                        attempts: 1,
                        millis: 1,
                    };
                    1000
                ],
            }),
        }],
        started_at: Timestamp::UNIX_EPOCH,
        finished_at: Timestamp::UNIX_EPOCH,
    };
    let wire = serde_json::to_vec(&reported(DeployId(7), &report)).unwrap();
    assert!(wire.len() < 1024 * 1024, "{}", wire.len());
    // What the controller's parser holds it to.
    serde_json::from_slice::<DeployReportBody>(&wire).unwrap();
    assert_eq!(bounded("short"), "short");
    assert!(bounded(&long).ends_with("..."));
}

/// A report of `steps` steps, each saying `text` in a failure and in 64 checks.
fn wordy_report(steps: usize, text: &str) -> deploy::DeployReport {
    let step = deploy::Step {
        name: "checks".to_owned(),
        started_at: Timestamp::UNIX_EPOCH,
        millis: 1,
        result: deploy::StepResult::Failed {
            reason: text.to_owned(),
        },
        detail: Some(deploy::StepDetail::Checks {
            checks: vec![
                deploy::CheckTiming {
                    check: text.to_owned(),
                    attempts: 1,
                    millis: 1,
                };
                64
            ],
        }),
    };
    deploy::DeployReport {
        deployment: id(),
        tag: "v1.2.4".parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        outcome: deploy::Outcome::RollbackFailed {
            reason: text.to_owned(),
            rollback_reason: text.to_owned(),
        },
        steps: vec![step; steps],
        started_at: Timestamp::UNIX_EPOCH,
        finished_at: Timestamp::UNIX_EPOCH,
    }
}

#[test]
fn a_body_over_the_limit_loses_details_first_and_says_so() {
    // Control characters serialise to six bytes each, and this emoji to four.
    for text in ["\u{1}".repeat(5000), "\u{1F600}".repeat(5000)] {
        let body = reported(DeployId(7), &wordy_report(8, &text));
        let wire = serde_json::to_vec(&body).unwrap();
        assert!(wire.len() <= MAX_BODY_BYTES, "{}", wire.len());
        assert!(body.steps[..8].iter().all(|step| step.detail.is_none()));
        assert_eq!(body.steps[8].name, "report_trimmed");
        assert!(matches!(
            body.outcome,
            ReportedOutcome::RollbackFailed { .. }
        ));
        assert_eq!(
            serde_json::from_slice::<DeployReportBody>(&wire).unwrap(),
            body
        );
    }
}

#[test]
fn a_body_still_over_the_limit_loses_what_the_steps_say() {
    let text = "\u{1}".repeat(5000);
    let body = reported(DeployId(7), &wordy_report(100, &text));
    let wire = serde_json::to_vec(&body).unwrap();
    assert!(wire.len() <= MAX_BODY_BYTES, "{}", wire.len());
    assert!(
        body.steps[0]
            .failure
            .as_deref()
            .is_some_and(|failure| failure.contains("withheld")),
        "{:?}",
        body.steps[0]
    );
    assert_eq!(body.steps.last().unwrap().name, "report_trimmed");
}

#[test]
fn a_body_that_small_steps_can_not_save_keeps_its_outcome() {
    let text = "\u{1}".repeat(5000);
    let mut report = wordy_report(1, &text);
    report.steps[0].name = text.clone();
    report.steps = vec![report.steps[0].clone(); 400];
    let body = reported(DeployId(7), &report);
    let wire = serde_json::to_vec(&body).unwrap();
    assert!(wire.len() <= MAX_BODY_BYTES, "{}", wire.len());
    assert_eq!(body.steps.len(), 1);
    assert_eq!(body.steps[0].name, "report_trimmed");
    assert!(matches!(
        body.outcome,
        ReportedOutcome::RollbackFailed { .. }
    ));
}
