//! When an approval is spent: only once everything has been checked, under the
//! deployment's lock, and before anything changes.

use std::collections::BTreeMap;
use std::fs;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployWork, ReportedOutcome};

use super::super::approval::journal_nonce_log;
use super::super::{Shutdown, StepOutcome, VerifyFailure};
use super::approvals::{
    Keys, OTHER_DIGEST, asked, assert_deployed, bare_keyed, carrying, intent, keyed, signed, spent,
};
use super::{
    COMMIT, FakeVerifier, NEW_DIGEST, OLD_DIGEST, PATCH_RULE, assert_deferred, assert_refused,
    claim, container, deployed_at, id, marker, origin, state_of, touched, when_the_engine_starts,
};
use crate::compose::OVERRIDE_FILE;
use crate::deploy::{self, DeployError, DeployPlan};
use crate::journal::{Priority, capture};
use crate::state::{DeployLock, Deployed, FailedRelease, NonceSpend, Phase, StateDir, StateError};
use crate::testing::Call;

fn approved_minor(keys: &Keys, number: u64) -> DeployWork {
    carrying(
        number,
        signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), 1)),
    )
}

#[tokio::test]
async fn the_nonce_is_on_disk_before_anything_changes_and_the_lock_is_held_from_there() {
    let (f, keys) = bare_keyed(PATCH_RULE);
    let log = StateDir::open(&f.state_dir).unwrap();
    let state = state_of(&f);
    let seen = Arc::new(Mutex::new(Vec::new()));
    let copy = Arc::clone(&seen);
    f.docker.on_call(move |call| {
        // These change what runs, or come after what the engine writes.
        if matches!(
            call,
            Call::Pull(_)
                | Call::ComposeService { .. }
                | Call::ComposeServiceChecked { .. }
                | Call::ComposeUp { .. }
                | Call::ComposeStop { .. }
        ) {
            let spent = log.nonce_used(&[1; 32]).unwrap();
            let locked = state.lock().is_err();
            copy.lock().unwrap().push((spent, locked));
        }
    });
    let approval = signed(&keys.operator, &intent("v1.2.3", None, 1));

    let outcome = asked(&f, &FakeVerifier::passes(), carrying(7, approval)).await;

    assert_deployed(&outcome);
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(
        seen.iter().all(|(spent, locked)| *spent && *locked),
        "{seen:?}"
    );
}

/// With the lock let go anywhere between the spending and the engine, and the engine taking
/// its own, everything else about a deploy looks the same.
#[tokio::test]
async fn the_lock_the_nonce_was_spent_under_is_the_one_the_engine_starts_with() {
    let (f, keys) = keyed(PATCH_RULE);
    let (log, state) = (StateDir::open(&f.state_dir).unwrap(), state_of(&f));
    let seen = Arc::new(Mutex::new(Vec::new()));
    let copy = Arc::clone(&seen);
    when_the_engine_starts(move || {
        copy.lock().unwrap().push((
            log.nonce_used(&[1; 32]).unwrap(),
            matches!(state.lock(), Err(StateError::Busy(_))),
        ));
    });

    let outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;

    assert_deployed(&outcome);
    assert_eq!(*seen.lock().unwrap(), [(true, true)]);
}

#[tokio::test]
async fn a_deploy_handed_another_lock_never_starts() {
    let (f, _keys) = keyed(PATCH_RULE);
    let root = StateDir::open(&f.state_dir).unwrap();
    let deployment = f.config.deployment(&id()).unwrap();
    let plan = DeployPlan::from_verified(
        deployment,
        &"v1.2.4".parse().unwrap(),
        semver::Version::new(1, 2, 4),
        &origin(NEW_DIGEST, COMMIT),
    );
    let other = root.deployment(&"app/stage".parse().unwrap()).unwrap();
    for lock in [other.lock().unwrap(), root.lock_daemon().unwrap()] {
        let result = deploy::run_holding(
            &f.docker,
            &state_of(&f),
            deployment,
            &f.compose,
            &plan,
            &f.options.engine,
            Some(lock),
        )
        .await;
        assert!(
            matches!(result, Err(DeployError::WrongLock(_))),
            "{result:?}"
        );
    }
    assert_eq!(f.docker.calls(), []);
}

#[tokio::test]
async fn a_nonce_that_cannot_be_recorded_changes_nothing() {
    let (mut f, keys) = bare_keyed(PATCH_RULE);
    // On a first deploy, the engine's first act is to write an override.
    fs::remove_file(f.compose.join(OVERRIDE_FILE)).unwrap();
    f.options.engine = super::engine_options();
    let log = StateDir::open(&f.state_dir).unwrap().nonce_log_path();
    let verifier = FakeVerifier::passes();
    // It reads well when it's looked at first, and is torn by the time it's written to.
    let during = log.clone();
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        fs::write(&during, "torn").unwrap();
    }));
    let seen = capture::events("nonce_log_unusable").len();
    let spending = capture::events("approval_about_to_be_spent").len();
    let approval = signed(&keys.operator, &intent("v1.2.3", None, 1));

    let (reason, priority) = assert_refused(&f, &verifier, carrying(7, approval)).await;

    assert!(reason.contains("nonce log"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert_eq!(capture::events("nonce_log_unusable").len(), seen + 1);
    // The journal went first: nothing got onto the disk, and it has said so already.
    assert_eq!(
        capture::events("approval_about_to_be_spent").len(),
        spending + 1
    );
    assert!(!f.compose.join(OVERRIDE_FILE).exists(), "no file changed");
    assert_eq!(
        f.docker.count(|c| matches!(c, Call::ComposeService { .. })),
        0
    );
}

#[tokio::test]
async fn verification_that_refuses_or_cannot_run_spends_nothing() {
    let (f, keys) = keyed(PATCH_RULE);
    let refusing =
        FakeVerifier::answering(Err(VerifyFailure::Refused("tag signature: no".to_owned())));
    let (reason, priority) = assert_refused(&f, &refusing, approved_minor(&keys, 7)).await;
    assert!(reason.contains("tag signature"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert!(!spent(&f, 1));

    let away = FakeVerifier::answering(Err(VerifyFailure::Unavailable("registry".to_owned())));
    let outcome = asked(&f, &away, approved_minor(&keys, 8)).await;
    assert!(
        matches!(outcome, StepOutcome::Waiting { .. }),
        "{outcome:?}"
    );
    assert!(!spent(&f, 1));

    // So the same approval goes through once the registry is back.
    let outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 8)).await;
    assert_deployed(&outcome);
    assert!(spent(&f, 1));
}

#[tokio::test]
async fn what_holds_a_deploy_up_spends_nothing() {
    // Drift.
    let (f, keys) = keyed(PATCH_RULE);
    f.docker
        .script_inspect_after_up(0, [Ok(container("ghcr.io/example/app@sha256:ff", true))]);
    let (reason, _) = assert_deferred(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    assert!(reason.contains("drifted"), "{reason}");
    assert!(!spent(&f, 1));

    // Evidence of a failure that can't be read: it could be anything, approval or none.
    let (f, keys) = keyed(PATCH_RULE);
    fs::write(state_of(&f).failed_releases_path(), "{").unwrap();
    let (reason, _) = assert_deferred(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    assert!(reason.contains("can't tell"), "{reason}");
    assert!(!spent(&f, 1));

    // An interrupted deploy, whose record says nothing about what runs.
    let (f, keys) = keyed(PATCH_RULE);
    state_of(&f)
        .set_in_progress(&marker(Phase::Deploying))
        .unwrap();
    let (reason, _) = assert_deferred(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    assert!(reason.contains("recover"), "{reason}");
    assert!(!spent(&f, 1));

    // The same, on a first deploy: `None` on record means nothing while a marker's there.
    let (f, keys) = bare_keyed(PATCH_RULE);
    state_of(&f)
        .set_in_progress(&marker(Phase::Deploying))
        .unwrap();
    let approval = signed(&keys.operator, &intent("v1.2.4", None, 1));
    let (reason, _) = assert_deferred(&f, &FakeVerifier::passes(), carrying(7, approval)).await;
    assert!(reason.contains("recover"), "{reason}");
    assert!(!spent(&f, 1));
}

#[tokio::test]
async fn the_record_is_compared_again_under_the_lock() {
    // Verification takes a while. What the record says after it is what counts: it
    // moved here, so the approval is for a state this host has left.
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let state = state_of(&f);
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        let moved = Deployed {
            digest: OTHER_DIGEST.parse().unwrap(),
            ..deployed_at("v1.2.3", 1, 2, 3)
        };
        state.set_deployed(&moved).unwrap();
    }));
    let (reason, priority) = assert_refused(&f, &verifier, approved_minor(&keys, 7)).await;
    assert!(reason.contains(OTHER_DIGEST), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert!(!spent(&f, 1));

    // Or a marker came meanwhile: not now, and the approval stays good.
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let state = state_of(&f);
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        state.set_in_progress(&marker(Phase::Deploying)).unwrap();
    }));
    let outcome = asked(&f, &verifier, approved_minor(&keys, 7)).await;
    assert!(
        matches!(&outcome, StepOutcome::Finished { outcome: ReportedOutcome::Deferred { reason }, .. }
            if reason.contains("recover")),
        "{outcome:?}"
    );
    assert!(!spent(&f, 1));
    assert_eq!(touched(&f.docker), []);

    // Or the rule's answer changed with the record: same digest, now the version asked for.
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let state = state_of(&f);
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        state.set_deployed(&deployed_at("v1.3.0", 1, 3, 0)).unwrap();
    }));
    let (reason, priority) = assert_refused(&f, &verifier, approved_minor(&keys, 7)).await;
    assert!(reason.contains("already running"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert!(!spent(&f, 1));
}

#[tokio::test]
async fn a_nonce_spent_after_the_first_look_is_refused_at_the_last() {
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let root = StateDir::open(&f.state_dir).unwrap();
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        assert_eq!(root.spend_nonce(&[1; 32]).unwrap(), NonceSpend::Recorded);
    }));
    let (reason, priority) = assert_refused(&f, &verifier, approved_minor(&keys, 7)).await;
    assert!(reason.contains("already"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

#[tokio::test]
async fn a_recover_holding_the_lock_leaves_the_approval_good() {
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let state = state_of(&f);
    let held: Arc<Mutex<Option<DeployLock>>> = Arc::new(Mutex::new(None));
    let slot = Arc::clone(&held);
    *verifier.during.lock().unwrap() = Some(Box::new(move || {
        *slot.lock().unwrap() = Some(state.lock().unwrap());
    }));

    let outcome = asked(&f, &verifier, approved_minor(&keys, 7)).await;

    assert!(
        matches!(&outcome, StepOutcome::Waiting { reason, .. } if reason.contains("busy")),
        "{outcome:?}"
    );
    assert!(!spent(&f, 1));
    assert_eq!(touched(&f.docker), []);
    assert_eq!(state_of(&f).claim().unwrap(), None);

    drop(held.lock().unwrap().take());
    let mut outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    // A flock can outlive its holder for a moment: see `once_released` in the state tests.
    for _ in 0..1000 {
        if !matches!(outcome, StepOutcome::Waiting { .. }) {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    }
    assert_deployed(&outcome);
    assert!(spent(&f, 1));
}

/// Something run by hand holds the nonce log's lock, past any deadline. Nothing may wait for it,
/// as a thread blocked there while spending would hold the deployment's lock until it is let go.
async fn a_held_log_makes_the_work_wait(hold: impl Fn(&fs::File)) {
    let (f, keys) = keyed(PATCH_RULE);
    let root = StateDir::open(&f.state_dir).unwrap();
    assert_eq!(root.spend_nonce(&[9; 32]).unwrap(), NonceSpend::Recorded);
    let holder = fs::File::open(root.nonce_log_path()).unwrap();
    hold(&holder);
    let log_before = fs::read(root.nonce_log_path()).unwrap();
    let unusable = capture::events("nonce_log_unusable").len();

    let started = Instant::now();
    let outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;

    assert!(
        started.elapsed() < Duration::from_secs(10),
        "it waited for the lock: {:?}",
        started.elapsed()
    );
    assert!(
        matches!(&outcome, StepOutcome::Waiting { reason, .. } if reason.contains("nonce log")),
        "{outcome:?}"
    );
    assert_eq!(fs::read(root.nonce_log_path()).unwrap(), log_before);
    assert_eq!(touched(&f.docker), []);
    assert_eq!(capture::events("nonce_log_unusable").len(), unusable);
    // With the log still held, no thread is left with the deployment's lock. A flock can outlive
    // its holder for a moment: see `once_released` in the state tests.
    let state = state_of(&f);
    let mut free = state.lock();
    for _ in 0..1000 {
        if free.is_ok() {
            break;
        }
        tokio::time::sleep(Duration::from_millis(5)).await;
        free = state.lock();
    }
    assert!(free.is_ok(), "the deployment's lock was left behind");
    drop(free);

    // Once it's let go the same approval goes through.
    drop(holder);
    let outcome = asked(&f, &FakeVerifier::passes(), approved_minor(&keys, 7)).await;
    assert_deployed(&outcome);
    assert!(spent(&f, 1));
}

/// Held to write, it stops the first look.
#[tokio::test]
async fn a_nonce_log_locked_to_write_makes_the_work_wait() {
    a_held_log_makes_the_work_wait(|holder| holder.lock().unwrap()).await;
}

/// Held to read, the first look passes, and spending is what finds it.
#[tokio::test]
async fn a_nonce_log_locked_to_read_makes_the_work_wait_with_the_deployments_lock_let_go() {
    a_held_log_makes_the_work_wait(|holder| holder.lock_shared().unwrap()).await;
}

#[tokio::test]
async fn a_stop_during_verification_spends_nothing() {
    let (mut f, keys) = keyed(PATCH_RULE);
    let (trigger, shutdown) = Shutdown::channel();
    f.options.shutdown = shutdown;
    let verifier = FakeVerifier::passes();
    *verifier.stop.lock().unwrap() = Some(trigger);

    let outcome = asked(&f, &verifier, approved_minor(&keys, 7)).await;

    assert_eq!(outcome, StepOutcome::ShuttingDown);
    assert!(!spent(&f, 1));
    assert_eq!(touched(&f.docker), []);
}

#[tokio::test]
async fn a_nonce_spent_for_one_deployment_is_spent_for_the_others() {
    let (mut f, keys) = keyed(PATCH_RULE);
    // The log is the host's: this nonce went on another deployment here.
    let _: NonceSpend = StateDir::open(&f.state_dir)
        .unwrap()
        .spend_nonce(&[1; 32])
        .unwrap();
    let stage: landfall_core::ids::DeploymentId = "app/stage".parse().unwrap();
    f.options = super::options_for(BTreeMap::from([
        (id(), f.compose.clone()),
        (stage.clone(), f.compose.with_file_name("stage")),
    ]));
    let approval = signed(
        &keys.backup,
        &DeployIntent {
            deployment: stage.clone(),
            ..intent("v1.2.4", None, 1)
        },
    );
    let item = DeployWork {
        deployment: stage,
        ..carrying(7, approval)
    };

    let (reason, priority) = assert_refused(&f, &FakeVerifier::passes(), item).await;

    assert!(reason.contains("already"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

#[tokio::test]
async fn a_nonce_log_that_cannot_be_used_is_journalled_at_start() {
    let (f, _keys) = keyed(PATCH_RULE);
    let seen = capture::events("nonce_log_unusable").len();
    journal_nonce_log(&StateDir::open(&f.state_dir).unwrap());
    assert_eq!(
        capture::events("nonce_log_unusable").len(),
        seen,
        "no log is fine"
    );

    let root = StateDir::open(&f.state_dir).unwrap();
    // Held by something, at start: nothing known to be wrong, so nothing to say.
    let good = root.nonce_log_path();
    fs::write(&good, "").unwrap();
    let holder = fs::File::open(&good).unwrap();
    holder.lock().unwrap();
    journal_nonce_log(&root);
    assert_eq!(capture::events("nonce_log_unusable").len(), seen);
    drop(holder);

    fs::write(root.nonce_log_path(), "torn").unwrap();
    journal_nonce_log(&root);
    let events = capture::events("nonce_log_unusable");
    assert_eq!(events.len(), seen + 1);
    assert_eq!(events.last().unwrap().0, Priority::Critical);
}

#[tokio::test]
async fn a_retried_release_that_a_crash_cut_short_still_comes_off_the_record() {
    let (f, _keys) = keyed(PATCH_RULE);
    let state = state_of(&f);
    let taken = claim(7);
    state.set_claim(&taken).unwrap();
    state
        .add_failed_release(&FailedRelease {
            tag: taken.tag.clone(),
            digest: taken.digest.clone(),
        })
        .unwrap();
    // The engine finished: the claim names what's now on record, with no report.
    let mut deployed = deployed_at("v1.2.4", 1, 2, 4);
    deployed.digest = NEW_DIGEST.parse().unwrap();
    state.set_deployed(&deployed).unwrap();

    let outcome = super::poll(
        &f,
        &super::FakeController::default(),
        &FakeVerifier::passes(),
    )
    .await;

    assert_eq!(outcome, StepOutcome::NoWork);
    assert_eq!(state.failed_releases().unwrap(), []);
}
