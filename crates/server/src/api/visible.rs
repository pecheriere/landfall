//! What a principal may be told about a deployment.
//!
//! A principal with no grant on a deployment is told nothing of it: not that it exists, and
//! not its name where another deployment's view would show it. One with some grant may know
//! it exists, and is refused what that grant doesn't allow with `403` rather than `404`.
//! Seeing a deployment's state takes `view`.

use landfall_api::DeploymentRef;
use landfall_core::config::{Config, Deployment, Permission};
use landfall_core::ids::DeploymentId;

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
/// [`visibility`] gives.
pub(crate) fn viewable<'a>(
    config: &'a Config,
    principal: &Principal,
    raw: Option<String>,
) -> Result<&'a Deployment, HumanProblem> {
    let deployment = raw
        .and_then(|raw| raw.parse::<DeploymentId>().ok())
        .and_then(|id| config.deployment(&id));
    deployment
        .filter(|d| can(config, principal, d.id(), Permission::View))
        .ok_or_else(|| visibility(config, principal, deployment.map(Deployment::id)))
}
