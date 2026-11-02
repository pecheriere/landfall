//! Everything this host requires of a work item before anything runs. The
//! controller may be compromised, so this goes by the host's own configuration
//! and records only.

use std::path::Path;

use landfall_core::config::{Config, Deployment};
use landfall_core::ids::DeploymentId;
use landfall_core::protocol::DeployWork;
use landfall_core::rule::{Decision, Refusal, decide};
use landfall_origin::release::ReleaseOrigin;
use serde::Serialize;

use super::approval::{self, Asked, Gate};
use super::outbox::{FailureEvidence, failure_evidence};
use super::running::{fresh_drift, locked};
use super::{DaemonOptions, Verifier, VerifyFailure, deployment_state, on_thread};
use crate::deploy::DeployPlan;
use crate::docker::Docker;
use crate::journal::{self, Priority};
use crate::state::{ControllerClaim, DeployLock, InProgress, VerificationWait};

/// A work item that has passed everything the host requires of it, an approval's spending
/// aside.
pub(super) struct GoAhead<'a> {
    pub(super) plan: Box<DeployPlan>,
    pub(super) deployment: &'a Deployment,
    pub(super) dir: &'a Path,
    pub(super) gate: Gate,
}

/// A work item the engine may start on.
pub(super) struct Ready<'a> {
    pub(super) plan: Box<DeployPlan>,
    pub(super) deployment: &'a Deployment,
    pub(super) dir: &'a Path,
    /// The deployment's lock, held since an approval was spent. `None` for a deploy that
    /// took no approval, whose engine takes the lock itself.
    pub(super) lock: Option<DeployLock>,
}

/// Why a work item doesn't run.
pub(super) enum Stop {
    /// It may not, and that is the answer for good: its rule, its approval, a failed
    /// verification result, or the record of failures on this host.
    Refuse { priority: Priority, reason: String },
    /// Not now, and the controller is told: the claim ends, so that the host's other
    /// deployments can go, and the controller may ask again later.
    Defer { priority: Priority, reason: String },
    /// Not yet, and nothing is reported: the controller delivers it again.
    Wait { reason: String },
}

pub(super) fn refuse(priority: Priority, reason: String) -> Stop {
    Stop::Refuse { priority, reason }
}

pub(super) fn defer(priority: Priority, reason: String) -> Stop {
    Stop::Defer { priority, reason }
}

/// Why this rule's answer is not `Auto`, if it isn't. Matching every decision
/// is what keeps a new one from falling through to a deploy.
pub(super) fn not_auto(
    decision: Decision,
    running: Option<&semver::Version>,
    candidate: &semver::Version,
) -> Option<String> {
    let from = running.map_or_else(|| "nothing".to_owned(), ToString::to_string);
    match decision {
        Decision::Auto => None,
        Decision::NeedsApproval => Some(format!(
            "the rule asks for an approval to go from {from} to {candidate}"
        )),
        Decision::Manual if running.is_none() => Some(format!(
            "the first deploy of a deployment is manual, and {candidate} would be its first"
        )),
        Decision::Manual if running.is_some_and(|running| candidate < running) => Some(format!(
            "{candidate} is a downgrade from {from}, which is manual"
        )),
        Decision::Manual => Some(format!(
            "the rule makes going from {from} to {candidate} manual"
        )),
        Decision::Refused(Refusal::Prerelease) => Some(format!(
            "{candidate} is a pre-release, and the rule doesn't opt in to those"
        )),
        Decision::Refused(Refusal::AlreadyRunning) => {
            Some(format!("{candidate} is the version already running"))
        }
    }
}

/// What an unfinished deploy, or what is left of one, says about this work.
pub(super) fn held_up(
    work: &DeployWork,
    marker: Option<&InProgress>,
    claim: Option<&ControllerClaim>,
) -> Option<Stop> {
    let id = &work.deployment;
    // The number alone isn't enough: a controller whose database was rebuilt uses
    // numbers again.
    let ours = claim.is_some_and(|claim| {
        claim.deploy_id == work.deploy_id && claim.tag == work.tag && claim.digest == work.digest
    });
    match marker {
        // The controller delivers claimed work again: this is the deploy that
        // was interrupted, and `recover` will end it.
        Some(marker) if ours => Some(Stop::Wait {
            reason: format!(
                "this deploy of {} was interrupted; run `landfall-agent recover --deployment {id}`",
                marker.tag
            ),
        }),
        Some(marker) => Some(defer(
            Priority::Error,
            format!(
                "the deploy of {} did not finish; run `landfall-agent recover --deployment {id}`",
                marker.tag
            ),
        )),
        None if claim.is_some() => Some(Stop::Wait {
            reason: "what is left of an earlier deploy isn't settled yet".to_owned(),
        }),
        None => None,
    }
}

/// What the verified release must say to be what the controller asked for.
fn differs_from_asked(work: &DeployWork, origin: &ReleaseOrigin) -> Option<String> {
    if origin.attestation.digest != work.digest {
        return Some(format!(
            "{} verifies to digest {}, not the {} asked for",
            work.tag, origin.attestation.digest, work.digest
        ));
    }
    if origin.commit != work.commit {
        return Some(format!(
            "{} verifies to commit {}, not the {} asked for",
            work.tag, origin.commit, work.commit
        ));
    }
    None
}

/// Adds the time since the last look to how long this work item's verification
/// has been unable to run, and returns the total. The sum goes by the monotonic
/// clock and is kept on disk, so it survives a restart and the wall clock has no say
/// in it.
async fn note_wait(
    state_dir: &Path,
    options: &DaemonOptions,
    work: &DeployWork,
) -> Result<u64, String> {
    let now = std::time::Instant::now();
    let since_last = locked(&options.memory.verification_seen)
        .replace((work.deploy_id, now))
        .filter(|(id, _)| *id == work.deploy_id)
        .map_or(0, |(_, last)| {
            u64::try_from(now.duration_since(last).as_millis()).unwrap_or(u64::MAX)
        });
    let (root, id, deploy_id) = (
        state_dir.to_owned(),
        work.deployment.clone(),
        work.deploy_id,
    );
    on_thread("record the wait", move || {
        let state = deployment_state(&root, &id)?;
        let mut wait = state
            .verification_wait()?
            .filter(|wait| wait.deploy_id == deploy_id)
            .unwrap_or(VerificationWait {
                deploy_id,
                waited_millis: 0,
            });
        wait.waited_millis = wait.waited_millis.saturating_add(since_last);
        state.set_verification_wait(&wait)?;
        Ok(wait.waited_millis)
    })
    .await
}

/// Verification has come to an answer, so the wait is over.
async fn forget_wait(state_dir: &Path, options: &DaemonOptions, id: &DeploymentId) {
    *locked(&options.memory.verification_seen) = None;
    let (root, owned) = (state_dir.to_owned(), id.clone());
    // A record left behind only counts for the same deploy, which has its answer.
    let _ = on_thread("clear the wait", move || {
        deployment_state(&root, &owned)?.clear_verification_wait()
    })
    .await;
}

/// What verification that could not run comes to. It may yet: a registry that is
/// away may be back, a release may still be publishing, and a wrong answer may be
/// put right. While this waits the claim blocks every deployment of the host, so it
/// waits only for so long, and then the controller is told not now, which frees the
/// host. The controller's next tries are paced by its own growing wait. A wait that
/// can't be recorded has no bound to go by, so it ends at once.
async fn waiting_verdict(
    state_dir: &Path,
    options: &DaemonOptions,
    work: &DeployWork,
    error: &str,
    what: &str,
) -> Stop {
    let waited = match note_wait(state_dir, options, work).await {
        Ok(waited) => waited,
        Err(record) => {
            return defer(
                Priority::Error,
                format!("{what}: {error}; the wait can't be recorded: {record}"),
            );
        }
    };
    let bound = u64::try_from(options.verification_bound.as_millis()).unwrap_or(u64::MAX);
    if waited >= bound {
        forget_wait(state_dir, options, &work.deployment).await;
        return defer(
            Priority::Warning,
            format!(
                "{what} after waiting {:?}: {error}",
                options.verification_bound
            ),
        );
    }
    Stop::Wait {
        reason: format!("{what}: {error}"),
    }
}

/// What this host knows of the release having failed here says no, or that it can't
/// tell yet. What runs is the digest asked for or nothing, as verification sees to
/// later, so a name of the controller's choosing can't get around this.
fn held_by_evidence(evidence: FailureEvidence, work: &DeployWork) -> Option<Stop> {
    #[derive(Serialize)]
    struct Unreadable<'a> {
        event: &'static str,
        file: &'a Path,
        error: &'a str,
        clear: &'static str,
    }
    const CLEAR: &str = "read or restore the file if you can; removing it clears this, and forgets any failure it recorded, so a release that failed can then deploy again";
    match evidence {
        FailureEvidence::None => None,
        FailureEvidence::Failed => Some(refuse(
            Priority::Error,
            format!(
                "{} with digest {} failed on this host and was rolled back; it isn't retried automatically, a newer release is",
                work.tag, work.digest
            ),
        )),
        FailureEvidence::Unreadable { file, error } => {
            journal::emit(
                Priority::Error,
                &Unreadable {
                    event: "failure_evidence_unreadable",
                    file: &file,
                    error: &error,
                    clear: CLEAR,
                },
            );
            Some(defer(
                Priority::Error,
                format!(
                    "can't tell whether {} failed on this host: {} can't be read: {error}; {CLEAR}",
                    work.tag,
                    file.display()
                ),
            ))
        }
    }
}

/// The release's verification by this host, which must come to what the work names.
async fn verified<V: Verifier>(
    verifier: &V,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
    work: &DeployWork,
) -> Result<ReleaseOrigin, Stop> {
    let id = &work.deployment;
    let origin = match verifier.verify(config, id, &work.tag).await {
        Ok(origin) => origin,
        Err(VerifyFailure::Refused(error)) => {
            forget_wait(state_dir, options, id).await;
            return Err(refuse(Priority::Critical, format!("verification: {error}")));
        }
        Err(VerifyFailure::Missing(error)) => {
            let what = "the release is not to be found";
            return Err(waiting_verdict(state_dir, options, work, &error, what).await);
        }
        Err(VerifyFailure::Unavailable(error)) => {
            let what = "verification could not run";
            return Err(waiting_verdict(state_dir, options, work, &error, what).await);
        }
        Err(VerifyFailure::ClockBehind(error)) => {
            forget_wait(state_dir, options, id).await;
            return Err(defer(
                Priority::Warning,
                format!(
                    "this host's clock is behind the release; it deploys once the clock is synchronised: {error}"
                ),
            ));
        }
    };
    forget_wait(state_dir, options, id).await;
    if let Some(reason) = differs_from_asked(work, &origin) {
        return Err(refuse(Priority::Critical, reason));
    }
    Ok(origin)
}

/// Goes through everything this host requires of a work item, cheapest first:
/// the rule and an approval come before verification, so a request either refuses costs
/// no outbound request.
pub(super) async fn judge<'a, D: Docker, V: Verifier>(
    docker: &D,
    verifier: &V,
    config: &'a Config,
    state_dir: &Path,
    options: &'a DaemonOptions,
    work: &DeployWork,
) -> Result<GoAhead<'a>, Stop> {
    let id: &DeploymentId = &work.deployment;
    let (Some(deployment), Some(dir)) = (config.deployment(id), options.dirs.get(id)) else {
        return Err(refuse(
            Priority::Critical,
            format!("{id} is not a deployment of this host"),
        ));
    };
    let (root, owned, tag, digest) = (
        state_dir.to_owned(),
        id.clone(),
        work.tag.clone(),
        work.digest.clone(),
    );
    let read = on_thread("read state", move || {
        let state = deployment_state(&root, &owned)?;
        // The marker first. A `recover` writes the record and then removes the marker,
        // and nothing else writes the record while the daemon isn't deploying. So with no
        // marker seen here, what is read after it is what `recover` left, and not what
        // it was about to replace.
        let marker = state.in_progress()?;
        Ok((
            state.deployed()?,
            marker,
            state.claim()?,
            failure_evidence(&state, &tag, &digest),
        ))
    })
    .await;
    let (deployed, marker, claim, evidence) =
        read.map_err(|error| defer(Priority::Error, error))?;
    if let Some(stop) = held_up(work, marker.as_ref(), claim.as_ref()) {
        return Err(stop);
    }
    let version = deployment
        .origin()
        .tags()
        .parse_tag(&work.tag)
        .map_err(|error| refuse(Priority::Critical, format!("tag pattern: {error}")))?;
    let running = deployed.as_ref().map(|deployed| &deployed.version);
    let decision = decide(deployment.rule(), running, &version);
    let not_auto = not_auto(decision, running, &version);
    // An approval doesn't override these: to deploy the same release again takes another
    // release, and a pre-release takes a rule that opts in.
    if let (Decision::Refused(_), Some(reason)) = (decision, &not_auto) {
        return Err(refuse(Priority::Critical, reason.clone()));
    }
    let asked = Asked {
        work,
        deployment,
        not_auto,
        on_failure_record: matches!(evidence, FailureEvidence::Failed),
        version: &version,
        running: deployed.as_ref().map(|deployed| &deployed.digest),
    };
    let gate = approval::gate(config, state_dir, asked).await?;
    // With an approval, a release on the record of failures is the manual retry.
    let retried = matches!(gate, Gate::Approved(_)) && matches!(evidence, FailureEvidence::Failed);
    if !retried && let Some(stop) = held_by_evidence(evidence, work) {
        return Err(stop);
    }
    match fresh_drift(docker, deployment, dir, deployed.is_some(), options).await {
        Ok(false) => {}
        Ok(true) => {
            return Err(defer(
                Priority::Error,
                format!(
                    "{id} has drifted: what runs is not what the agent deployed, so it gets no deploys until that clears"
                ),
            ));
        }
        Err(error) => {
            return Err(defer(
                Priority::Error,
                format!("{id}: what runs could not be read: {error}"),
            ));
        }
    }
    let origin = verified(verifier, config, state_dir, options, work).await?;
    Ok(GoAhead {
        plan: Box::new(DeployPlan::from_verified(
            deployment, &work.tag, version, &origin,
        )),
        deployment,
        dir,
        gate,
    })
}
