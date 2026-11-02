//! A deploy that takes a person's approval: what this host checks of it, and when it is
//! spent.
//!
//! The controller carries an approval and can't make one: it has no passkey. So everything
//! here goes by this host's configuration, its records and its own verification. The order
//! is what keeps a controller from burning a real approval:
//!
//! 1. [`gate`], before verification and with no lock: the intent against the work and
//!    the record, the assertion against the key of an approver of this deployment, and the
//!    nonce log, read only. All of it costs no outbound request, and refusing it spends
//!    nothing.
//! 2. The release's verification, in [`judge`](super::judge), which binds the commit and
//!    digest the intent names to what this host found out for itself.
//! 3. [`commit`], under the deployment's lock: the record and the rule again, then the
//!    nonce is appended and `fsync`ed. Only an approval that has passed everything is
//!    spent, and a controller can't produce one of those.
//! 4. The engine starts with that lock still held, so nothing runs between the check of
//!    the record and the deploy, and a `recover` by hand finds the lock taken. If the lock
//!    is held when step 3 comes, nothing is spent, and the work waits.
//!
//! From step 3 on the approval is spent whatever comes next, a crash included: it works
//! once, whichever way the deploy ends. The journal says so just before the append, so a
//! crash right after it leaves a line for that nonce, and a later refusal of it can be
//! told from a replay of something that ran.

use std::path::Path;

use landfall_approval::{Assertion, CoseKey, Expect, verify};
use landfall_core::config::{Approver, Config, Deployment, Rule};
use landfall_core::ids::{DeploymentId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, AssertionText, DeployWork};
use landfall_core::rule::{Decision, decide};
use landfall_core::text::quoted;
use serde::Serialize;

use super::judge::{GoAhead, Ready, Stop, defer, held_up, not_auto, refuse};
use super::on_thread;
use crate::journal::{self, Priority};
use crate::state::{DeployLock, NONCE_LOG, NonceSpend, StateDir, StateError};

/// How much of a credential id off the wire a refusal keeps.
const SHOWN_CREDENTIAL_ID: usize = 128;
/// How to get a log that can't be used going again, which only the operator can do.
const CLEAR: &str = "see \"The nonce log\" in docs/operations.md; approvals stay refused until it is put right, and automatic deploys go on";

/// What an approval has to do with this work item.
pub(super) enum Gate {
    /// Nothing: none is looked at. Either the rule makes this automatic and it isn't on the
    /// record of failures, or it is on that record and no approval came with it, which
    /// [`judge`](super::judge) refuses next, going by that record.
    NoApproval,
    /// It goes on this approval, which has been verified and not yet spent.
    Approved(Box<Cleared>),
}

/// An approval that passed everything [`gate`] checks.
#[derive(Clone)]
pub(super) struct Cleared {
    intent: DeployIntent,
    approver: PrincipalId,
    version: semver::Version,
}

/// What the rule says, for the deploy the work names.
pub(super) struct Asked<'a> {
    pub(super) work: &'a DeployWork,
    pub(super) deployment: &'a Deployment,
    /// Why this isn't automatic, if it isn't.
    pub(super) not_auto: Option<String>,
    /// It failed on this host, so it can only be retried by a person.
    pub(super) on_failure_record: bool,
    pub(super) version: &'a semver::Version,
    /// What the host has on record as running.
    pub(super) running: Option<&'a ImageDigest>,
}

/// Decides how this deploy may start, and refuses it if the approval it takes isn't good.
/// A deploy the rule makes automatic ignores whatever approval is attached, and a garbled
/// one changes nothing about it. One on the record of failures has to be retried by a
/// person: without an approval, what the record says is its answer.
pub(super) async fn gate(
    config: &Config,
    state_dir: &Path,
    asked: Asked<'_>,
) -> Result<Gate, Stop> {
    let Asked {
        work,
        deployment,
        not_auto,
        on_failure_record,
        version,
        running,
    } = asked;
    let approval = match (&not_auto, &work.approval) {
        (None, _) if !on_failure_record => return Ok(Gate::NoApproval),
        (None, None) => return Ok(Gate::NoApproval),
        (Some(why), None) => {
            return Err(refuse(
                Priority::Critical,
                format!("{why}, and no approval came with it"),
            ));
        }
        (_, Some(approval)) => approval,
    };
    let approver = clear(config, deployment, approval, work, running)
        .map_err(|why| refuse(Priority::Critical, format!("approval refused: {why}")))?;
    let (root, nonce) = (state_dir.to_owned(), approval.intent.nonce);
    let used = on_thread("read the nonce log", move || {
        Ok(StateDir::open(&root)?.nonce_used(&nonce))
    })
    .await;
    match used {
        Ok(Ok(false)) => {}
        Ok(Ok(true)) => return Err(replayed(&work.deployment, &nonce)),
        Ok(Err(error)) => return Err(unusable_log(&error, state_dir)),
        Err(error) => return Err(defer(Priority::Error, error)),
    }
    Ok(Gate::Approved(Box::new(Cleared {
        intent: approval.intent.clone(),
        approver,
        version: version.clone(),
    })))
}

fn replayed(id: &DeploymentId, nonce: &[u8; 32]) -> Stop {
    refuse(
        Priority::Critical,
        format!(
            "approval refused: {id}: nonce {} was already spent on this host, and this delivery changed nothing on the service; it may be a replay, a redelivery after a crash, or a return to a digest it named earlier, and it takes a new approval",
            hex::encode(nonce),
        ),
    )
}

/// Which field of the intent says something else than the work.
fn differs_from_work(intent: &DeployIntent, work: &DeployWork) -> Option<String> {
    fn differ<T: std::fmt::Display + PartialEq>(
        field: &str,
        signed: &T,
        asked: &T,
    ) -> Option<String> {
        (signed != asked)
            .then(|| format!("it is for {field} {signed}, and the work asks for {asked}"))
    }
    differ("deployment", &intent.deployment, &work.deployment)
        .or_else(|| differ("tag", &intent.tag, &work.tag))
        .or_else(|| differ("commit", &intent.commit, &work.commit))
        .or_else(|| differ("digest", &intent.digest, &work.digest))
}

/// `None` only matches `None`: a first deploy's approval is for a host with nothing on
/// record, and one for something running needs that very digest.
fn differs_from_record(intent: &DeployIntent, running: Option<&ImageDigest>) -> Option<String> {
    let named =
        |digest: Option<&ImageDigest>| digest.map_or("nothing".to_owned(), ToString::to_string);
    (intent.expected_running.as_ref() != running).then(|| {
        format!(
            "it is for a host running {}, and this host has {} on record as running",
            named(intent.expected_running.as_ref()),
            named(running),
        )
    })
}

/// The approver of this deployment holding this credential. Only the deployment's own list
/// counts: the key of another deployment's approver is no better here than anyone's.
fn approver_of<'a>(
    config: &'a Config,
    rule: &Rule,
    credential_id: &[u8],
    text: &AssertionText,
) -> Result<(&'a PrincipalId, &'a Approver), String> {
    let holds = |approver: &&Approver| approver.credential_id() == credential_id;
    for name in rule.approvers() {
        if let Some((name, approver)) = config.approvers().get_key_value(name)
            && holds(&approver)
        {
            return Ok((name, approver));
        }
    }
    let shown = quoted(&text.credential_id, SHOWN_CREDENTIAL_ID);
    match config
        .approvers()
        .iter()
        .find(|(_, approver)| holds(approver))
    {
        Some((name, _)) => Err(format!(
            "credential {shown} is {name}'s, who is no approver of this deployment"
        )),
        None => Err(format!(
            "no approver in this host's configuration has credential {shown}"
        )),
    }
}

/// Everything about an approval that needs nothing but what's in hand. On success, who
/// approved.
fn clear(
    config: &Config,
    deployment: &Deployment,
    approval: &Approval,
    work: &DeployWork,
    running: Option<&ImageDigest>,
) -> Result<PrincipalId, String> {
    let intent = &approval.intent;
    if let Some(why) =
        differs_from_work(intent, work).or_else(|| differs_from_record(intent, running))
    {
        return Err(why);
    }
    let Some(settings) = config.approval() else {
        return Err("this host's configuration has no [approval] settings".to_owned());
    };
    let assertion = Assertion::try_from(&approval.assertion).map_err(|error| error.to_string())?;
    let (name, approver) = approver_of(
        config,
        deployment.rule(),
        &assertion.credential_id,
        &approval.assertion,
    )?;
    let key = CoseKey::parse(approver.public_key())
        .map_err(|error| format!("{name}'s key in this host's configuration: {error}"))?;
    verify(
        &assertion,
        &Expect {
            key: &key,
            credential_id: approver.credential_id(),
            rp_id: settings.rp_id(),
            origin: settings.origin(),
            challenge: &intent.challenge(),
        },
    )
    .map_err(|error| error.to_string())?;
    Ok(name.clone())
}

fn journal_unusable(error: &StateError, file: &Path) {
    #[derive(Serialize)]
    struct Unusable<'a> {
        event: &'static str,
        file: &'a Path,
        error: String,
        clear: &'static str,
    }
    journal::emit(
        Priority::Critical,
        &Unusable {
            event: "nonce_log_unusable",
            file,
            error: error.to_string(),
            clear: CLEAR,
        },
    );
}

fn unusable_log(error: &StateError, state_dir: &Path) -> Stop {
    journal_unusable(error, &state_dir.join(NONCE_LOG));
    refuse(
        Priority::Critical,
        format!(
            "approval refused: this host's nonce log can't say whether it was used: {error}; {CLEAR}"
        ),
    )
}

/// Says in the journal if the log can't be used, so that an operator hears at start, and
/// not only when an approval is refused for it. It stops nothing: automatic deploys don't
/// need it.
pub(super) fn journal_nonce_log(root: &StateDir) {
    if let Err(error) = root.check_nonce_log() {
        journal_unusable(&error, &root.nonce_log_path());
    }
}

/// The last look, under the lock the engine goes on to hold.
fn last_look(
    state_dir: &Path,
    work: &DeployWork,
    rule: &Rule,
    cleared: &Cleared,
) -> Result<Result<DeployLock, Stop>, StateError> {
    let state = StateDir::open(state_dir)?.deployment(&work.deployment)?;
    let lock = match state.lock() {
        Ok(lock) => lock,
        Err(error @ StateError::Busy(_)) => {
            return Ok(Err(Stop::Wait {
                reason: error.to_string(),
            }));
        }
        Err(error) => return Err(error),
    };
    if let Some(stop) = held_up(work, state.in_progress()?.as_ref(), state.claim()?.as_ref()) {
        return Ok(Err(stop));
    }
    let deployed = state.deployed()?;
    let running = deployed.as_ref().map(|deployed| &deployed.digest);
    if let Some(why) = differs_from_record(&cleared.intent, running) {
        return Ok(Err(refuse(
            Priority::Critical,
            format!("approval refused: {why}"),
        )));
    }
    let version = deployed.as_ref().map(|deployed| &deployed.version);
    let decision = decide(rule, version, &cleared.version);
    if let (Decision::Refused(_), Some(why)) =
        (decision, not_auto(decision, version, &cleared.version))
    {
        return Ok(Err(refuse(Priority::Critical, why)));
    }
    Ok(Ok(lock))
}

/// Comes before the append, so that an approval spent by a crash has a line in the journal
/// saying whose it was and what it was for.
fn journal_spending(cleared: &Cleared) {
    #[derive(Serialize)]
    struct Spending<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        tag: &'a ReleaseTag,
        digest: &'a ImageDigest,
        expected_running: Option<&'a ImageDigest>,
        approver: &'a PrincipalId,
        nonce: String,
    }
    let intent = &cleared.intent;
    journal::emit(
        Priority::Info,
        &Spending {
            event: "approval_about_to_be_spent",
            deployment: &intent.deployment,
            tag: &intent.tag,
            digest: &intent.digest,
            expected_running: intent.expected_running.as_ref(),
            approver: &cleared.approver,
            nonce: hex::encode(intent.nonce),
        },
    );
}

/// The last look under the lock, the line in the journal, and the nonce on disk.
async fn spend(
    cleared: &Cleared,
    deployment: &Deployment,
    state_dir: &Path,
    work: &DeployWork,
) -> Result<DeployLock, Stop> {
    let (root, asked, rule, copy) = (
        state_dir.to_owned(),
        work.clone(),
        deployment.rule().clone(),
        cleared.clone(),
    );
    let looked = on_thread("take the last look at the approval", move || {
        last_look(&root, &asked, &rule, &copy)
    })
    .await;
    let lock = match looked {
        Ok(lock) => lock?,
        Err(error) => return Err(defer(Priority::Error, error)),
    };
    journal_spending(cleared);
    let (root, nonce) = (state_dir.to_owned(), cleared.intent.nonce);
    let spent = on_thread("spend the approval", move || {
        Ok((StateDir::open(&root)?.spend_nonce(&nonce), lock))
    })
    .await;
    match spent {
        Ok((Ok(NonceSpend::Recorded), lock)) => Ok(lock),
        Ok((Ok(NonceSpend::AlreadyUsed), _)) => Err(replayed(&work.deployment, &nonce)),
        Ok((Err(error), _)) => Err(unusable_log(&error, state_dir)),
        Err(error) => Err(defer(Priority::Error, error)),
    }
}

/// The point of no return for a deploy on an approval. See the module's docs.
pub(super) async fn commit<'a>(
    go: GoAhead<'a>,
    state_dir: &Path,
    work: &DeployWork,
) -> Result<Ready<'a>, Stop> {
    let GoAhead {
        plan,
        deployment,
        dir,
        gate,
    } = go;
    let lock = match gate {
        Gate::NoApproval => None,
        Gate::Approved(cleared) => Some(spend(&cleared, deployment, state_dir, work).await?),
    };
    Ok(Ready {
        plan,
        deployment,
        dir,
        lock,
    })
}
