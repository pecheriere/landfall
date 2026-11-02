//! What the controller can't make this host do: for each, nothing runs, and the
//! journal and the report say why.

use std::fs;
use std::time::Duration;

use landfall_core::protocol::{DeployId, Phase, ReportedOutcome};

use super::super::{StepOutcome, VerifyFailure};
use super::{
    COMMIT, FakeController, FakeVerifier, NEW_DIGEST, OLD, PATCH_RULE, answer, assert_deferred,
    assert_refused, bare_fixture, claim, container, fixture, marker, origin, poll, state_of,
    touched, work,
};
use crate::journal::{Priority, capture};

#[tokio::test]
async fn controller_cannot_force_a_non_auto_deploy() {
    for (rule, tag, says) in [
        // A minor under a patch rule, with an approval level and without.
        (PATCH_RULE, "v1.3.0", "approval"),
        ("auto = \"patch\"", "v1.3.0", "manual"),
        // A major.
        (PATCH_RULE, "v2.0.0", "manual"),
        // A downgrade, under a rule that allows any step up.
        ("auto = \"any\"", "v1.2.2", "downgrade"),
        // The version already running.
        ("auto = \"any\"", "v1.2.3", "already running"),
        // A pre-release, which the rule doesn't opt in to.
        ("auto = \"any\"", "v1.3.0-rc.1", "pre-release"),
    ] {
        let f = fixture(rule);
        let verifier = FakeVerifier::passes();
        let (reason, priority) = assert_refused(&f, &verifier, work(7, tag)).await;
        assert!(reason.contains(says), "{tag} under {rule}: {reason}");
        assert_eq!(priority, Priority::Critical, "{tag} under {rule}");
        assert_eq!(verifier.calls(), 0, "a refused request costs no fetch");
        assert_eq!(
            state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
            "v1.2.3",
            "{tag} under {rule}"
        );
    }
}

#[tokio::test]
async fn the_first_deploy_of_a_deployment_cannot_be_forced() {
    let f = bare_fixture("auto = \"any\"");
    let verifier = FakeVerifier::passes();
    let (reason, priority) = assert_refused(&f, &verifier, work(7, "v1.2.4")).await;
    assert!(reason.contains("first deploy"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

#[tokio::test]
async fn a_tag_outside_the_deployments_pattern_is_refused() {
    let f = fixture(PATCH_RULE);
    let (reason, priority) =
        assert_refused(&f, &FakeVerifier::passes(), work(7, "release-1.2.4")).await;
    assert!(reason.contains("tag pattern"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

#[tokio::test]
async fn work_for_a_deployment_of_another_host_is_refused() {
    let f = fixture(PATCH_RULE);
    let mut item = work(7, "v1.2.4");
    item.deployment = "other/prod".parse().unwrap();
    let (reason, priority) = assert_refused(&f, &FakeVerifier::passes(), item).await;
    assert!(reason.contains("other/prod"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert!(
        !f.state_dir.join("other__prod").exists(),
        "a name from the controller makes no directory"
    );
}

#[tokio::test]
async fn failed_verification_runs_nothing() {
    let f = fixture(PATCH_RULE);
    let verifier =
        FakeVerifier::answering(Err(VerifyFailure::Refused("tag signature: no".to_owned())));
    let (reason, priority) = assert_refused(&f, &verifier, work(7, "v1.2.4")).await;
    assert!(reason.contains("tag signature"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert_eq!(verifier.calls(), 1);
}

#[tokio::test]
async fn a_digest_or_commit_other_than_the_verified_one_is_refused() {
    let other = "dddddddddddddddddddddddddddddddddddddddd";
    let other_digest = format!("sha256:{}", "e".repeat(64));
    for verified in [origin(&other_digest, COMMIT), origin(NEW_DIGEST, other)] {
        let f = fixture(PATCH_RULE);
        let verifier = FakeVerifier::answering(Ok(verified));
        let (reason, priority) = assert_refused(&f, &verifier, work(7, "v1.2.4")).await;
        assert!(reason.contains("verifies to"), "{reason}");
        assert_eq!(priority, Priority::Critical);
    }
}

#[tokio::test]
async fn verification_that_cannot_run_waits_and_reports_nothing() {
    let f = fixture(PATCH_RULE);
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let verifier =
        FakeVerifier::answering(Err(VerifyFailure::Unavailable("registry down".to_owned())));

    let outcome = poll(&f, &controller, &verifier).await;

    assert!(
        matches!(&outcome, StepOutcome::Waiting { deploy_id: DeployId(7), reason }
            if reason.contains("registry down")),
        "{outcome:?}"
    );
    assert_eq!(controller.reports(), []);
    assert_eq!(touched(&f.docker), []);
    assert_eq!(state_of(&f).claim().unwrap(), None);
}

#[tokio::test]
async fn in_progress_marker_blocks_work() {
    let f = fixture(PATCH_RULE);
    state_of(&f)
        .set_in_progress(&marker(crate::state::Phase::Deploying))
        .unwrap();
    let verifier = FakeVerifier::passes();
    let (reason, priority) = assert_deferred(&f, &verifier, work(8, "v1.2.5")).await;
    assert!(reason.contains("recover"), "{reason}");
    assert_eq!(priority, Priority::Error);
    assert_eq!(verifier.calls(), 0);
}

#[tokio::test]
async fn a_clock_behind_the_release_defers_it_without_a_wait() {
    let f = fixture(PATCH_RULE);
    let verifier =
        FakeVerifier::answering(Err(VerifyFailure::ClockBehind("in the future".to_owned())));
    let (reason, priority) = assert_deferred(&f, &verifier, work(7, "v1.2.4")).await;
    assert!(reason.contains("clock"), "{reason}");
    assert_eq!(priority, Priority::Warning);
    assert_eq!(state_of(&f).verification_wait().unwrap(), None);
}

#[tokio::test]
async fn a_controllers_number_for_another_release_is_not_the_interrupted_deploy() {
    let f = fixture(PATCH_RULE);
    let mut taken = claim(7);
    taken.tag = "v1.2.9".parse().unwrap();
    state_of(&f).set_claim(&taken).unwrap();
    state_of(&f)
        .set_in_progress(&marker(crate::state::Phase::Deploying))
        .unwrap();
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    assert!(
        matches!(&outcome, StepOutcome::Finished { outcome: ReportedOutcome::Deferred { reason }, .. }
            if reason.contains("recover")),
        "{outcome:?}"
    );
    assert_eq!(touched(&f.docker), []);
    assert_eq!(state_of(&f).claim().unwrap(), Some(taken), "it stays");
}

#[tokio::test]
async fn the_interrupted_deploy_itself_waits_for_recover_rather_than_being_refused() {
    let f = fixture(PATCH_RULE);
    let taken = claim(7);
    state_of(&f).set_claim(&taken).unwrap();
    state_of(&f)
        .set_in_progress(&marker(crate::state::Phase::Deploying))
        .unwrap();
    // The controller delivers claimed work again after a reconnect.
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);

    let outcome = poll(&f, &controller, &FakeVerifier::passes()).await;

    assert!(
        matches!(&outcome, StepOutcome::Waiting { deploy_id: DeployId(7), reason }
            if reason.contains("recover")),
        "{outcome:?}"
    );
    assert_eq!(controller.reports(), []);
    assert_eq!(state_of(&f).claim().unwrap(), Some(taken));
}

#[tokio::test]
async fn drift_blocks_work() {
    let f = fixture(PATCH_RULE);
    // What runs is not what the override pins.
    f.docker
        .script_inspect_after_up(0, [Ok(container("ghcr.io/example/app@sha256:ff", true))]);
    let verifier = FakeVerifier::passes();
    let (reason, priority) = assert_deferred(&f, &verifier, work(7, "v1.2.4")).await;
    assert!(reason.contains("drifted"), "{reason}");
    assert_eq!(priority, Priority::Error);
    assert_eq!(verifier.calls(), 0);
}

#[tokio::test]
async fn drift_that_cleared_is_seen_at_once_by_a_deploy() {
    let mut f = fixture(PATCH_RULE);
    // A long time between looks, as far as requests go.
    f.options.drift_every = Duration::from_secs(3600);
    f.docker.script_inspect_after_up(
        0,
        [
            Ok(container("ghcr.io/example/app@sha256:ff", true)),
            Ok(container(OLD, true)),
        ],
    );
    let controller = FakeController::with([answer(None), answer(Some(work(7, "v1.2.4")))]);
    let verifier = FakeVerifier::passes();

    assert_eq!(poll(&f, &controller, &verifier).await, StepOutcome::NoWork);
    assert!(controller.requests()[0].running[0].drift);
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
}

#[tokio::test]
async fn drift_that_cannot_be_read_blocks_work() {
    let f = fixture(PATCH_RULE);
    f.docker.script_container([Err("daemon gone")]);
    let (reason, _) = assert_deferred(&f, &FakeVerifier::passes(), work(7, "v1.2.4")).await;
    assert!(reason.contains("daemon gone"), "{reason}");
}

#[tokio::test]
async fn state_that_cannot_be_read_is_listed_as_not_fit_to_deploy_to() {
    let f = fixture(PATCH_RULE);
    fs::write(f.state_dir.join("app__prod/deployed.json"), "{").unwrap();
    let controller = FakeController::with([answer(Some(work(7, "v1.2.4")))]);
    let verifier = FakeVerifier::passes();

    let outcome = poll(&f, &controller, &verifier).await;

    let sent = controller.requests()[0].running[0].clone();
    assert!(sent.drift);
    assert_eq!(sent.phase, Phase::Deploying);
    assert!(!sent.busy);
    assert_eq!(capture::events("state_unreadable")[0].0, Priority::Critical);
    assert!(
        matches!(&outcome, StepOutcome::Finished { outcome: ReportedOutcome::Deferred { reason }, .. }
            if reason.contains("corrupt")),
        "{outcome:?}"
    );
    assert_eq!(touched(&f.docker), []);
}
