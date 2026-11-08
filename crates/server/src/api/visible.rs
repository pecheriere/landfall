//! What a principal may be told about a deployment.
//!
//! A principal with no grant on a deployment is told nothing of it: not that it exists, and
//! not its name where another deployment's view would show it. One with some grant may know
//! it exists, and is refused what that grant doesn't allow with `403` rather than `404`.
//! Seeing a deployment's state takes `view`. A host is seen through the deployments on it:
//! only those a principal may view, and not at all without one.

use landfall_api::DeploymentRef;
use landfall_core::config::{Config, Deployment, Permission};
use landfall_core::ids::{DeploymentId, HostId};

use crate::auth::{HumanProblem, Principal, can, sees};

/// A 403 for someone who may know this deployment exists, and for anyone else the same 404
/// as for one that doesn't.
pub(crate) fn visibility(
    config: &Config,
    principal: &Principal,
    deployment: Option<&DeploymentId>,
) -> HumanProblem {
    if deployment.is_some_and(|d| sees(config, principal, d)) {
        HumanProblem::Forbidden
    } else {
        HumanProblem::NotFound
    }
}

/// `id`, as a view this principal reads may name it: by its id if they may view it, and
/// otherwise as one they can't, never by name.
pub(crate) fn shown_deployment(
    config: &Config,
    principal: &Principal,
    id: &DeploymentId,
) -> DeploymentRef {
    if can(config, principal, id, Permission::View) {
        DeploymentRef::Seen(id.clone())
    } else {
        DeploymentRef::Unseen
    }
}

/// The deployment a path names as `raw`, if this principal may view it: `None` is a path that
/// didn't decode, which names nothing, as one that isn't an id doesn't. Otherwise the refusal
/// [`viewable_by_id`] gives.
pub(crate) fn viewable<'a>(
    config: &'a Config,
    principal: &Principal,
    raw: Option<String>,
) -> Result<&'a Deployment, HumanProblem> {
    let id = raw.and_then(|raw| raw.parse::<DeploymentId>().ok());
    viewable_by_id(config, principal, id.as_ref())
}

/// The deployment `id` names, if the configuration has it and this principal may view it.
/// Otherwise the refusal [`visibility`] gives: one the configuration no longer has is `404`
/// to everyone, whatever its rows in the database.
pub(crate) fn viewable_by_id<'a>(
    config: &'a Config,
    principal: &Principal,
    id: Option<&DeploymentId>,
) -> Result<&'a Deployment, HumanProblem> {
    let deployment = id.and_then(|id| config.deployment(id));
    deployment
        .filter(|d| can(config, principal, d.id(), Permission::View))
        .ok_or_else(|| visibility(config, principal, deployment.map(Deployment::id)))
}

/// The deployments this principal may view, in the configuration's order.
pub(crate) fn viewable_deployments<'a>(
    config: &'a Config,
    principal: &'a Principal,
) -> impl Iterator<Item = &'a Deployment> {
    config
        .deployments()
        .iter()
        .filter(move |d| can(config, principal, d.id(), Permission::View))
}

/// The deployments the configuration puts on the host `raw` names that this principal may
/// view, in the configuration's order, if there is one. Otherwise `403` if they hold some other
/// grant on a deployment there, and the same `404` as for a host no deployment names if they
/// hold none: a path that isn't a host id names nothing.
pub(crate) fn viewable_on_host<'a>(
    config: &'a Config,
    principal: &'a Principal,
    raw: Option<String>,
) -> Result<Vec<&'a Deployment>, HumanProblem> {
    let Some(host) = raw.and_then(|raw| raw.parse::<HostId>().ok()) else {
        return Err(HumanProblem::NotFound);
    };
    let shown: Vec<&Deployment> = viewable_deployments(config, principal)
        .filter(|d| *d.host() == host)
        .collect();
    if shown.is_empty() {
        let known = config
            .deployments()
            .iter()
            .filter(|d| *d.host() == host)
            .map(Deployment::id)
            .find(|id| sees(config, principal, id));
        return Err(visibility(config, principal, known));
    }
    Ok(shown)
}
