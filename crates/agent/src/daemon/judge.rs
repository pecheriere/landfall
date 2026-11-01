//! Everything this host requires of a work item before anything runs. The
//! controller may be compromised, so this goes by the host's own configuration
//! and records only.

use std::path::Path;

use landfall_core::config::{Config, Deployment};
use landfall_core::ids::DeploymentId;
use landfall_core::protocol::DeployWork;
use landfall_core::rule::{Decision, Refusal, decide};
use landfall_origin::release::ReleaseOrigin;

use super::running::fresh_drift;
use super::{DaemonOptions, Verifier, VerifyFailure, deployment_state, on_thread};
use crate::deploy::DeployPlan;
use crate::docker::Docker;
use crate::journal::Priority;
use crate::state::{ControllerClaim, InProgress};

/// What the host thinks of a work item.
pub(super) enum Verdict<'a> {
    /// It may run.
    Go {
        plan: Box<DeployPlan>,
        deployment: &'a Deployment,
        dir: &'a Path,
    },
    /// It may not, and that is the answer.
    Refuse { priority: Priority, reason: String },
    /// Not now, and nothing is reported.
    Wait { reason: String },
}

fn refuse<'a>(priority: Priority, reason: String) -> Verdict<'a> {
    Verdict::Refuse { priority, reason }
}

/// Why this rule's answer is not `Auto`, if it isn't. Matching every decision
/// is what keeps a new one from falling through to a deploy.
fn not_auto(
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
fn held_up<'a>(
    work: &DeployWork,
    marker: Option<&InProgress>,
    claim: Option<&ControllerClaim>,
) -> Option<Verdict<'a>> {
    let id = &work.deployment;
    let ours = claim.is_some_and(|claim| claim.deploy_id == work.deploy_id);
    match marker {
        // The controller delivers claimed work again: this is the deploy that
        // was interrupted, and `recover` will end it.
        Some(marker) if ours => Some(Verdict::Wait {
            reason: format!(
                "this deploy of {} was interrupted; run `landfall-agent recover --deployment {id}`",
                marker.tag
            ),
        }),
        Some(marker) => Some(refuse(
            Priority::Error,
            format!(
                "the deploy of {} did not finish; run `landfall-agent recover --deployment {id}`",
                marker.tag
            ),
        )),
        None if claim.is_some() => Some(Verdict::Wait {
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

/// Goes through everything this host requires of a work item, cheapest first:
/// the rule comes before verification, so a request the rule refuses costs no
/// outbound request.
pub(super) async fn judge<'a, D: Docker, V: Verifier>(
    docker: &D,
    verifier: &V,
    config: &'a Config,
    state_dir: &Path,
    options: &'a DaemonOptions,
    work: &DeployWork,
) -> Verdict<'a> {
    let id: &DeploymentId = &work.deployment;
    let (Some(deployment), Some(dir)) = (config.deployment(id), options.dirs.get(id)) else {
        return refuse(
            Priority::Critical,
            format!("{id} is not a deployment of this host"),
        );
    };
    let (root, owned) = (state_dir.to_owned(), id.clone());
    let read = on_thread("read state", move || {
        let state = deployment_state(&root, &owned)?;
        Ok((state.deployed()?, state.in_progress()?, state.claim()?))
    })
    .await;
    let (deployed, marker, claim) = match read {
        Ok(read) => read,
        Err(error) => return refuse(Priority::Error, error),
    };
    if let Some(verdict) = held_up(work, marker.as_ref(), claim.as_ref()) {
        return verdict;
    }
    let version = match deployment.origin().tags().parse_tag(&work.tag) {
        Ok(version) => version,
        Err(error) => return refuse(Priority::Critical, format!("tag pattern: {error}")),
    };
    let running = deployed.as_ref().map(|deployed| &deployed.version);
    let decision = decide(deployment.rule(), running, &version);
    if let Some(reason) = not_auto(decision, running, &version) {
        return refuse(Priority::Critical, reason);
    }
    match fresh_drift(docker, deployment, dir, deployed.is_some(), options).await {
        Ok(false) => {}
        Ok(true) => {
            return refuse(
                Priority::Error,
                format!(
                    "{id} has drifted: what runs is not what the agent deployed, so it gets no automatic deploys until that clears"
                ),
            );
        }
        Err(error) => {
            return refuse(
                Priority::Error,
                format!("{id}: what runs could not be read: {error}"),
            );
        }
    }
    let origin = match verifier.verify(config, id, &work.tag).await {
        Ok(origin) => origin,
        Err(VerifyFailure::Refused(error)) => {
            return refuse(Priority::Critical, format!("verification: {error}"));
        }
        Err(VerifyFailure::Unavailable(error)) => {
            return Verdict::Wait {
                reason: format!("verification could not run: {error}"),
            };
        }
    };
    if let Some(reason) = differs_from_asked(work, &origin) {
        return refuse(Priority::Critical, reason);
    }
    Verdict::Go {
        plan: Box::new(DeployPlan::from_verified(
            deployment, &work.tag, version, &origin,
        )),
        deployment,
        dir,
    }
}
