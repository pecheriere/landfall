//! Running a non-automatic deploy on a person's approval, verified on this host, and
//! everything a controller without the passkey can try instead.

use std::collections::BTreeMap;
use std::fs;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Ceremony, SoftwareAuthenticator, parse_config};
use landfall_core::ids::ImageDigest;
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, AssertionText, DeployId, DeployWork, ReportedOutcome};

use super::super::StepOutcome;
use super::super::outbox::{FailureEvidence, failure_evidence};
use super::{
    COMMIT, FakeController, FakeVerifier, Fixture, ID, NEW, NEW_DIGEST, OLD, OLD_DIGEST,
    PATCH_RULE, answer, assert_refused, bare_fixture, container, fixture, id, image, options_for,
    poll, state_of, work,
};
use crate::journal::{Priority, capture};
use crate::state::{NonceSpend, StateDir};
use crate::testing::{Call, test_nonce};

pub(super) const RP_ID: &str = "landfall.example";
pub(super) const ORIGIN: &str = "https://landfall.example";
pub(super) const OTHER_DIGEST: &str =
    "sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee";
const OTHER_COMMIT: &str = "dddddddddddddddddddddddddddddddddddddddd";
const STAGE: &str = "app/stage";

/// The approvers of a fixture's configuration: `operator` is `app/prod`'s, `backup` only
/// `app/stage`'s, and `stranger` is in no configuration.
pub(super) struct Keys {
    pub(super) operator: SoftwareAuthenticator,
    pub(super) backup: SoftwareAuthenticator,
    pub(super) stranger: SoftwareAuthenticator,
}

fn approver_entry(name: &str, key: &SoftwareAuthenticator) -> String {
    format!(
        "{name} = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
        URL_SAFE_NO_PAD.encode(key.credential_id()),
        URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
    )
}

fn deployment_entry(id: &str, dir: &str, rule: &str, approver: &str) -> String {
    format!(
        "[[deployment]]\nid = \"{id}\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {dir:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ {rule}, approvers = [\"{approver}\"] }}\nchecks = [\"container-healthy\"]\n\
         [[grant]]\nprincipal = \"{approver}\"\ndeployments = [\"{id}\"]\ncan = [\"approve\"]\n"
    )
}

/// Puts the generated keys in `f`'s configuration.
fn with_keys(mut f: Fixture, rule: &str) -> (Fixture, Keys) {
    let keys = Keys {
        operator: SoftwareAuthenticator::es256().unwrap(),
        backup: SoftwareAuthenticator::eddsa().unwrap(),
        stranger: SoftwareAuthenticator::es256().unwrap(),
    };
    let stage = f.compose.with_file_name("stage");
    fs::create_dir(&stage).unwrap();
    let text = format!(
        "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
         [approval]\nrp_id = \"{RP_ID}\"\norigin = \"{ORIGIN}\"\n\
         [approvers]\n{}{}{}{}",
        approver_entry("operator", &keys.operator),
        approver_entry("backup", &keys.backup),
        deployment_entry(ID, f.compose.to_str().unwrap(), rule, "operator"),
        deployment_entry(STAGE, stage.to_str().unwrap(), rule, "backup"),
    );
    f.config = parse_config(text.as_bytes()).unwrap();
    (f, keys)
}

/// `app/prod` at v1.2.3 under `rule`, with keys.
pub(super) fn keyed(rule: &str) -> (Fixture, Keys) {
    with_keys(fixture(rule), rule)
}

/// `app/prod`, never deployed, under `rule`, with keys.
pub(super) fn bare_keyed(rule: &str) -> (Fixture, Keys) {
    with_keys(bare_fixture(rule), rule)
}

/// What an honest controller asks a person to approve.
pub(super) fn intent(tag: &str, expected_running: Option<&str>, label: &str) -> DeployIntent {
    DeployIntent {
        deployment: id(),
        tag: tag.parse().unwrap(),
        commit: COMMIT.parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        expected_running: expected_running.map(|digest| digest.parse().unwrap()),
        nonce: test_nonce(label),
    }
}

fn text_of(assertion: &landfall_approval::Assertion) -> AssertionText {
    serde_json::from_value(serde_json::to_value(assertion).unwrap()).unwrap()
}

/// What a real ceremony over `intent` gives, by this key.
pub(super) fn signed(key: &SoftwareAuthenticator, intent: &DeployIntent) -> Approval {
    signed_with(
        key,
        intent,
        &Ceremony::new(RP_ID, ORIGIN, &intent.challenge()),
    )
}

fn signed_with(
    key: &SoftwareAuthenticator,
    intent: &DeployIntent,
    ceremony: &Ceremony,
) -> Approval {
    Approval {
        intent: intent.clone(),
        assertion: text_of(&key.assertion(ceremony).unwrap()),
    }
}

/// The work item an honest controller sends with `approval`.
pub(super) fn carrying(deploy_id: u64, approval: Approval) -> DeployWork {
    DeployWork {
        tag: approval.intent.tag.clone(),
        approval: Some(approval),
        ..work(deploy_id, "v0.0.1")
    }
}

pub(super) fn spent(f: &Fixture, label: &str) -> bool {
    StateDir::open(&f.state_dir)
        .unwrap()
        .nonce_used(&test_nonce(label))
        .unwrap()
}

pub(super) async fn asked(f: &Fixture, verifier: &FakeVerifier, item: DeployWork) -> StepOutcome {
    let controller = FakeController::with([answer(Some(item))]);
    poll(f, &controller, verifier).await
}

/// [`assert_refused`], on a fixture that has run deploys before this.
async fn refused_later(f: &Fixture, item: DeployWork) -> (String, Priority) {
    let before = f.docker.calls().len();
    let outcome = asked(f, &FakeVerifier::passes(), item).await;
    let StepOutcome::Finished {
        outcome: ReportedOutcome::Refused { reason },
        ..
    } = outcome
    else {
        panic!("not refused: {outcome:?}");
    };
    let touching = f.docker.calls()[before..]
        .iter()
        .filter(|call| {
            matches!(
                call,
                Call::Pull(_) | Call::ComposeUp { .. } | Call::ComposeStop { .. }
            )
        })
        .count();
    assert_eq!(touching, 0, "{reason}");
    let events = capture::events("controller_work_refused");
    (reason, events.last().unwrap().0)
}

#[track_caller]
pub(super) fn assert_deployed(outcome: &StepOutcome) {
    assert!(
        matches!(
            outcome,
            StepOutcome::Finished {
                outcome: ReportedOutcome::Deployed {},
                ..
            }
        ),
        "{outcome:?}"
    );
}

#[tokio::test]
async fn first_deploy_with_an_approval_runs() {
    let (f, keys) = bare_keyed(PATCH_RULE);
    let approval = signed(&keys.operator, &intent("v1.2.3", None, "first"));
    let outcome = asked(&f, &FakeVerifier::passes(), carrying(7, approval)).await;
    assert_deployed(&outcome);
    let deployed = state_of(&f).deployed().unwrap().unwrap();
    assert_eq!(deployed.tag.as_ref(), "v1.2.3");
    assert_eq!(deployed.digest.as_ref(), NEW_DIGEST);
    assert!(spent(&f, "first"));
    let events = capture::events("approval_about_to_be_spent");
    let (_, event) = events.last().unwrap();
    assert_eq!(event["approver"], "operator", "whose approval it was");
}

#[tokio::test]
async fn minor_under_an_approve_rule_runs() {
    let (f, keys) = keyed(PATCH_RULE);
    let approval = signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), "first"));
    let outcome = asked(&f, &FakeVerifier::passes(), carrying(7, approval)).await;
    assert_deployed(&outcome);
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.3.0"
    );
}

#[tokio::test]
async fn downgrade_with_an_approval_runs() {
    for tag in ["v1.2.2", "v2.0.0"] {
        // A downgrade is the manual rollback, and a major is plain manual.
        let (f, keys) = keyed(PATCH_RULE);
        let approval = signed(&keys.operator, &intent(tag, Some(OLD_DIGEST), "first"));
        let outcome = asked(&f, &FakeVerifier::passes(), carrying(7, approval)).await;
        assert_deployed(&outcome);
        assert_eq!(state_of(&f).deployed().unwrap().unwrap().tag.as_ref(), tag);
    }
}

/// `v1.2.4`, automatic under the patch rule, rolls back on this host.
pub(super) async fn fail_automatically(f: &Fixture) {
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let outcome = asked(f, &FakeVerifier::passes(), work(6, "v1.2.4")).await;
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
    assert_eq!(state_of(f).failed_releases().unwrap().len(), 1);
}

/// The next deploy goes to the new image and stays healthy, with `ups` `up`s behind it.
pub(super) fn script_a_good_deploy(f: &Fixture, ups: usize) {
    f.docker
        .script_compose_service([Ok(image(OLD)), Ok(image(NEW)), Ok(image(OLD))]);
    f.docker
        .script_inspect_after_up(ups, [Ok(container(OLD, true))]);
    f.docker
        .script_inspect_after_up(ups + 1, [Ok(container(NEW, true))]);
}

#[tokio::test]
async fn failed_release_retried_with_an_approval_runs_and_clears_the_record() {
    let (f, keys) = keyed(PATCH_RULE);
    fail_automatically(&f).await;
    let verifier = FakeVerifier::passes();

    // Asked again by itself, it stays refused, and a worthless approval is no better.
    let (reason, priority) = refused_later(&f, work(7, "v1.2.4")).await;
    assert!(reason.contains("failed on this host"), "{reason}");
    assert_eq!(priority, Priority::Error);
    let forged = signed(&keys.stranger, &intent("v1.2.4", Some(OLD_DIGEST), "first"));
    let (_, priority) = refused_later(&f, carrying(8, forged)).await;
    assert_eq!(priority, Priority::Critical);

    // The manual retry: automatic by its rule, and it takes an approval anyway.
    script_a_good_deploy(&f, 2);
    let approval = signed(&keys.operator, &intent("v1.2.4", Some(OLD_DIGEST), "first"));
    let outcome = asked(&f, &verifier, carrying(9, approval)).await;
    assert_deployed(&outcome);
    assert_eq!(
        state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.4"
    );

    assert_eq!(state_of(&f).failed_releases().unwrap(), []);
    // And the engine's report of that failure no longer counts against it either.
    let evidence = failure_evidence(
        &state_of(&f),
        &"v1.2.4".parse().unwrap(),
        &NEW_DIGEST.parse().unwrap(),
    );
    assert!(matches!(evidence, FailureEvidence::None));
}

#[tokio::test]
async fn a_retry_that_fails_again_stays_on_the_record() {
    let (f, keys) = keyed(PATCH_RULE);
    fail_automatically(&f).await;
    f.docker
        .script_inspect_after_up(3, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(4, [Ok(container(OLD, true))]);
    let approval = signed(&keys.operator, &intent("v1.2.4", Some(OLD_DIGEST), "first"));
    let _ = asked(&f, &FakeVerifier::passes(), carrying(9, approval)).await;
    assert_eq!(state_of(&f).failed_releases().unwrap().len(), 1);
    let evidence = failure_evidence(
        &state_of(&f),
        &"v1.2.4".parse().unwrap(),
        &NEW_DIGEST.parse().unwrap(),
    );
    assert!(matches!(evidence, FailureEvidence::Failed));
}

/// `honest` with one field changed, for each field but the nonce: what it's called, and
/// the intent.
fn each_field_changed(honest: &DeployIntent) -> Vec<(&'static str, DeployIntent)> {
    let other_digest: ImageDigest = OTHER_DIGEST.parse().unwrap();
    let changed = |change: &dyn Fn(&mut DeployIntent)| {
        let mut intent = honest.clone();
        change(&mut intent);
        intent
    };
    vec![
        (
            "deployment",
            changed(&|i| i.deployment = STAGE.parse().unwrap()),
        ),
        ("tag", changed(&|i| i.tag = "v1.3.1".parse().unwrap())),
        (
            "commit",
            changed(&|i| i.commit = OTHER_COMMIT.parse().unwrap()),
        ),
        ("digest", changed(&|i| i.digest = other_digest.clone())),
        (
            "running",
            changed(&|i| i.expected_running = Some(other_digest.clone())),
        ),
        ("running", changed(&|i| i.expected_running = None)),
    ]
}

/// What a controller with no passkey can come up with, and what the refusal has to say.
fn forgeries(keys: &Keys, honest: &DeployIntent) -> Vec<(String, DeployWork, &'static str)> {
    let real = signed(&keys.operator, honest);
    let tag = honest.tag.as_ref();
    let mut named_by_stranger = Ceremony::new(RP_ID, ORIGIN, &honest.challenge());
    named_by_stranger.credential_id = Some(keys.operator.credential_id().to_vec());
    let mut oversized = real.clone();
    oversized.assertion.client_data_json = "A".repeat(512 * 1024);
    let mut forged = vec![
        ("no assertion".to_owned(), work(0, tag), "no approval"),
        (
            "a key that isn't in the configuration".to_owned(),
            carrying(0, signed(&keys.stranger, honest)),
            "no approver",
        ),
        (
            "that key, naming a credential that is".to_owned(),
            carrying(0, signed_with(&keys.stranger, honest, &named_by_stranger)),
            "signature",
        ),
        (
            "an approver of another deployment on this host".to_owned(),
            carrying(0, signed(&keys.backup, honest)),
            "backup",
        ),
        (
            "fields too long for anything real, before they're decoded".to_owned(),
            carrying(0, oversized),
            "longer than the 16384 bytes",
        ),
        (
            "a nonce changed under the real signature".to_owned(),
            DeployWork {
                approval: Some(Approval {
                    intent: DeployIntent {
                        nonce: test_nonce("changed"),
                        ..honest.clone()
                    },
                    assertion: real.assertion.clone(),
                }),
                ..work(0, tag)
            },
            "challenge",
        ),
        (
            "a nonce this host has used, properly signed".to_owned(),
            carrying(
                0,
                signed(&keys.operator, &intent(tag, Some(OLD_DIGEST), "used")),
            ),
            "already",
        ),
    ];
    for (field, changed) in each_field_changed(honest) {
        // A real signature over another intent, carried with this work.
        forged.push((
            format!("signed for another {field}"),
            DeployWork {
                approval: Some(signed(&keys.operator, &changed)),
                ..work(0, tag)
            },
            if field == "running" { "running" } else { field },
        ));
        // The intent changed under the real signature, the work matching it.
        forged.push((
            format!("{field} changed under the signature"),
            DeployWork {
                deployment: changed.deployment.clone(),
                tag: changed.tag.clone(),
                commit: changed.commit.clone(),
                digest: changed.digest.clone(),
                approval: Some(Approval {
                    intent: changed,
                    assertion: real.assertion.clone(),
                }),
                ..work(0, tag)
            },
            match field {
                "deployment" => "not a deployment",
                "running" => "running",
                _ => "challenge",
            },
        ));
    }
    forged
}

/// Each of these is refused for good, at critical priority. Nothing runs, and the real
/// approval is still good at the end: the nonce it carries wasn't spent by any of them.
#[tokio::test]
async fn controller_cannot_forge_an_approval() {
    const LABEL: &str = "first";
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let honest = intent("v1.3.0", Some(OLD_DIGEST), LABEL);
    let root = StateDir::open(&f.state_dir).unwrap();
    assert_eq!(
        root.spend_nonce(&test_nonce("used")).unwrap(),
        NonceSpend::Recorded
    );

    let mut number = 100;
    for (name, mut item, says) in forgeries(&keys, &honest) {
        number += 1;
        item.deploy_id = DeployId(number);
        let (reason, priority) = assert_refused(&f, &verifier, item).await;
        assert!(reason.contains(says), "{name}: {reason}");
        assert_eq!(priority, Priority::Critical, "{name}");
        assert!(!spent(&f, LABEL), "{name}");
        assert_eq!(verifier.calls(), 0, "{name}: a refusal costs no fetch");
    }

    // The approver did sign a digest or a commit, and the work says the same. It takes the
    // host's own verification to say that the release is no such thing.
    for (field, changed) in each_field_changed(&honest) {
        let says = match field {
            "digest" => "verifies to digest",
            "commit" => "verifies to commit",
            _ => continue,
        };
        number += 1;
        let item = DeployWork {
            digest: changed.digest.clone(),
            commit: changed.commit.clone(),
            ..carrying(number, signed(&keys.operator, &changed))
        };
        let (reason, priority) = assert_refused(&f, &verifier, item).await;
        assert!(reason.contains(says), "{field}: {reason}");
        assert_eq!(priority, Priority::Critical, "{field}");
        assert!(!spent(&f, LABEL), "{field}");
    }

    // After all of that, the real one works.
    number += 1;
    let real = signed(&keys.operator, &honest);
    assert_deployed(&asked(&f, &verifier, carrying(number, real)).await);
    assert!(spent(&f, LABEL));
}

#[tokio::test]
async fn approval_for_another_running_digest_is_refused() {
    let verifier = FakeVerifier::passes();

    // On record is one digest, and it signed for another, or for a first deploy.
    for expected in [Some(OTHER_DIGEST), None] {
        let (f, keys) = keyed(PATCH_RULE);
        let approval = signed(&keys.operator, &intent("v1.3.0", expected, "first"));
        let (reason, priority) = assert_refused(&f, &verifier, carrying(7, approval)).await;
        assert!(reason.contains("running"), "{reason}");
        assert!(reason.contains(OLD_DIGEST), "{reason}");
        assert_eq!(priority, Priority::Critical);
        assert!(!spent(&f, "first"));
    }

    // Nothing on record, and it signed for something running: `None` matches only `None`.
    let (f, keys) = bare_keyed(PATCH_RULE);
    let approval = signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), "first"));
    let (reason, priority) = assert_refused(&f, &verifier, carrying(7, approval)).await;
    assert!(reason.contains("nothing"), "{reason}");
    assert_eq!(priority, Priority::Critical);
    assert!(!spent(&f, "first"));
    assert_eq!(state_of(&f).deployed().unwrap(), None);
}

/// A run of `v1.3.0` on this approval that rolls back, which leaves what was running as
/// it was, so that nothing but the nonce can tell the second try from the first.
async fn approved_and_rolled_back(f: &Fixture, keys: &Keys) -> Approval {
    f.docker
        .script_inspect_after_up(1, [Ok(container(NEW, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let approval = signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), "first"));
    let outcome = asked(f, &FakeVerifier::passes(), carrying(7, approval.clone())).await;
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
    assert_eq!(
        state_of(f).deployed().unwrap().unwrap().digest.as_ref(),
        OLD_DIGEST
    );
    approval
}

#[tokio::test]
async fn replayed_nonce_is_refused() {
    let (f, keys) = keyed(PATCH_RULE);
    let approval = approved_and_rolled_back(&f, &keys).await;

    let (reason, priority) = refused_later(&f, carrying(8, approval)).await;

    assert!(reason.contains("already"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

#[tokio::test]
async fn replayed_nonce_is_refused_after_a_restart() {
    let (mut f, keys) = keyed(PATCH_RULE);
    let approval = approved_and_rolled_back(&f, &keys).await;

    // Nothing of the run before is in memory.
    f.options = options_for(BTreeMap::from([(id(), f.compose.clone())]));

    let (reason, priority) = refused_later(&f, carrying(8, approval)).await;
    assert!(reason.contains("already"), "{reason}");
    assert_eq!(priority, Priority::Critical);
}

/// The process dies at the engine's first look at Docker: the approval is on disk, and
/// what runs hasn't been touched.
#[tokio::test]
async fn crash_after_recording_the_nonce_spends_the_approval() {
    let (f, keys) = keyed(PATCH_RULE);
    let override_before = fs::read(f.compose.join(crate::compose::OVERRIDE_FILE)).unwrap();
    let approval = signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), "first"));

    let reached = std::sync::Arc::new(tokio::sync::Notify::new());
    let signal = std::sync::Arc::clone(&reached);
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeService { .. }) {
            signal.notify_one();
        }
    });
    f.docker
        .hang_when(|call| matches!(call, Call::ComposeService { .. }));
    let controller = FakeController::with([answer(Some(carrying(7, approval.clone())))]);
    let verifier = FakeVerifier::passes();
    tokio::select! {
        () = reached.notified() => {}
        outcome = poll(&f, &controller, &verifier) => panic!("it finished: {outcome:?}"),
    }

    // The future is gone, as the process would be. Docker answers the next one.
    f.docker.hang_when(|_| false);
    assert!(spent(&f, "first"), "the approval is spent");
    let events = capture::events("approval_about_to_be_spent");
    let (_, line) = events.last().expect("the journal has a line for the crash");
    assert_eq!(line["nonce"], hex::encode(test_nonce("first")));
    assert_eq!(
        f.docker.count(|c| matches!(
            c,
            Call::Pull(_) | Call::ComposeUp { .. } | Call::ComposeStop { .. }
        )),
        0,
        "the service wasn't touched"
    );
    assert_eq!(
        fs::read(f.compose.join(crate::compose::OVERRIDE_FILE)).unwrap(),
        override_before
    );
    assert_eq!(state_of(&f).in_progress().unwrap(), None);

    // The controller delivers its claimed work again, to the next run.
    let mut restarted = f;
    restarted.options = options_for(BTreeMap::from([(id(), restarted.compose.clone())]));
    let verifier = FakeVerifier::passes();
    let mut outcome = asked(&restarted, &verifier, carrying(7, approval.clone())).await;
    // A flock can outlive its holder for a moment: see `once_released` in the state tests.
    for _ in 0..1000 {
        if !matches!(outcome, StepOutcome::Waiting { .. }) {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(5)).await;
        outcome = asked(&restarted, &verifier, carrying(7, approval.clone())).await;
    }

    let StepOutcome::Finished {
        outcome: ReportedOutcome::Refused { reason },
        ..
    } = &outcome
    else {
        panic!("not refused: {outcome:?}");
    };
    assert!(reason.contains("already"), "{reason}");
    assert_eq!(
        restarted.docker.count(|c| matches!(
            c,
            Call::Pull(_) | Call::ComposeUp { .. } | Call::ComposeStop { .. }
        )),
        0
    );
    let state = state_of(&restarted);
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.3");
    assert_eq!(state.in_progress().unwrap(), None);
    assert_eq!(state.claim().unwrap(), None, "a clear state");
}

#[tokio::test]
async fn auto_ignores_an_attached_assertion() {
    let honest = intent("v1.2.4", Some(OLD_DIGEST), "first");
    let garbage = Approval {
        intent: DeployIntent {
            tag: "v9.9.9".parse().unwrap(),
            ..honest.clone()
        },
        assertion: AssertionText {
            credential_id: "!".to_owned(),
            authenticator_data: "not base64".to_owned(),
            client_data_json: "x".repeat(2 << 20),
            signature: String::new(),
        },
    };
    // Garbage, and a real approval, which isn't spent on a deploy that doesn't need one.
    let real = |keys: &Keys| signed(&keys.operator, &honest);
    let attachments: [&dyn Fn(&Keys) -> Approval; 2] = [&|_| garbage.clone(), &real];
    for attached in attachments {
        let (f, keys) = keyed(PATCH_RULE);
        let item = DeployWork {
            approval: Some(attached(&keys)),
            ..work(7, "v1.2.4")
        };
        let seen = capture::events("controller_work_refused").len();
        let outcome = asked(&f, &FakeVerifier::passes(), item).await;
        assert_deployed(&outcome);
        assert_eq!(
            state_of(&f).deployed().unwrap().unwrap().tag.as_ref(),
            "v1.2.4"
        );
        assert_eq!(capture::events("controller_work_refused").len(), seen);
        assert!(
            !StateDir::open(&f.state_dir)
                .unwrap()
                .nonce_log_path()
                .exists()
        );
    }

    // And it parses, so that it gets this far: a field's text is only looked at when
    // the approval is.
    let wire = serde_json::to_string(&DeployWork {
        approval: Some(garbage.clone()),
        ..work(7, "v1.2.4")
    })
    .unwrap();
    assert!(serde_json::from_str::<DeployWork>(&wire).is_ok());
}

#[tokio::test]
async fn prerelease_and_same_version_stay_refused() {
    for (tag, says) in [
        ("v1.3.0-rc.1", "pre-release"),
        ("v1.2.3", "already running"),
    ] {
        let (f, keys) = keyed(PATCH_RULE);
        let verifier = FakeVerifier::passes();
        let approval = signed(&keys.operator, &intent(tag, Some(OLD_DIGEST), "first"));
        let (reason, priority) = assert_refused(&f, &verifier, carrying(7, approval)).await;
        assert!(reason.contains(says), "{reason}");
        assert_eq!(priority, Priority::Critical);
        assert_eq!(verifier.calls(), 0);
        assert!(!spent(&f, "first"), "{tag}");
    }
}

#[tokio::test]
async fn corrupt_nonce_log_refuses_approvals() {
    for bad in [
        // Torn by a crash in the middle of an append.
        format!("{}\n{}", "a".repeat(64), "b".repeat(20)),
        "this is no log\n".to_owned(),
    ] {
        let (f, keys) = keyed(PATCH_RULE);
        let log = StateDir::open(&f.state_dir).unwrap().nonce_log_path();
        fs::write(&log, &bad).unwrap();
        let seen = capture::events("nonce_log_unusable").len();
        let verifier = FakeVerifier::passes();
        let approval = signed(&keys.operator, &intent("v1.3.0", Some(OLD_DIGEST), "first"));

        let (reason, priority) = assert_refused(&f, &verifier, carrying(7, approval)).await;

        assert!(reason.contains("nonce log"), "{reason}");
        assert_eq!(priority, Priority::Critical);
        assert_eq!(verifier.calls(), 0);
        let events = capture::events("nonce_log_unusable");
        assert_eq!(events.len(), seen + 1);
        let (priority, event) = events.last().unwrap();
        assert_eq!(*priority, Priority::Critical);
        assert_eq!(event["file"], log.to_str().unwrap());
        assert_eq!(
            fs::read_to_string(&log).unwrap(),
            bad,
            "left for the operator"
        );

        // An automatic deploy has nothing to do with it.
        let outcome = asked(&f, &verifier, work(8, "v1.2.4")).await;
        assert_deployed(&outcome);
        assert_eq!(fs::read_to_string(&log).unwrap(), bad);
    }
}

/// A host's refusal of an approval is how a lying controller shows, so two different
/// origins have to read differently in the journal, well past the 64 characters of the
/// short form.
#[tokio::test]
async fn refused_approval_is_critical_in_the_journal() {
    let (f, keys) = keyed(PATCH_RULE);
    let verifier = FakeVerifier::passes();
    let honest = intent("v1.3.0", Some(OLD_DIGEST), "first");
    let long = "a".repeat(120);
    let mut reasons = Vec::new();
    for (number, ending) in [(7, "one"), (8, "two")] {
        let origin = format!("https://{long}.{ending}.example");
        let ceremony = Ceremony::new(RP_ID, &origin, &honest.challenge());
        let approval = signed_with(&keys.operator, &honest, &ceremony);
        let seen = capture::events("controller_work_refused").len();

        let (reason, priority) = assert_refused(&f, &verifier, carrying(number, approval)).await;

        assert_eq!(priority, Priority::Critical);
        assert!(reason.contains(&origin), "{reason}");
        let events = capture::events("controller_work_refused");
        assert_eq!(events.len(), seen + 1);
        let (journalled, event) = events.last().unwrap();
        assert_eq!(*journalled, Priority::Critical);
        assert_eq!(event["reason"], reason.as_str());
        assert!(event["reason"].as_str().unwrap().contains(&origin));
        reasons.push(reason);
    }
    assert_ne!(reasons[0], reasons[1]);
}
