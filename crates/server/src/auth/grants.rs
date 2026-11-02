//! What a principal may do: [`can`], and nothing else says.

use landfall_core::config::{Config, Grant, Permission};
use landfall_core::ids::{DeploymentId, PrincipalId};

use super::principal::Principal;

/// The configuration's grants of `principal` on `deployment`.
fn grants_on<'a>(
    config: &'a Config,
    principal: &'a PrincipalId,
    deployment: &'a DeploymentId,
) -> impl Iterator<Item = &'a Grant> {
    config
        .grants()
        .iter()
        .filter(move |grant| grant.principal() == principal)
        .filter(move |grant| grant.deployments().contains(deployment))
}

/// Whether `principal` may do this to `deployment`. Denied unless a grant says so. Grants
/// apply to tokens and sessions alike, but `approve` is for a person: a token can never
/// approve, whatever the configuration says. It also takes an approver the deployment's
/// rule lists, which is who the host will accept; loading a configuration already
/// refuses a grant that says otherwise.
pub(crate) fn can(
    config: &Config,
    principal: &Principal,
    deployment: &DeploymentId,
    permission: Permission,
) -> bool {
    let id = principal.id();
    let granted = grants_on(config, id, deployment).any(|grant| grant.can().contains(&permission));
    match permission {
        Permission::View | Permission::Request | Permission::Rollback => granted,
        Permission::Approve => {
            granted
                && principal.is_human()
                && config.approver(id).is_some()
                && config
                    .deployment(deployment)
                    .is_some_and(|d| d.rule().approvers().contains(id))
        }
    }
}

/// Whether `principal` has any grant on `deployment`, and so may be told it exists.
pub(crate) fn sees(config: &Config, principal: &Principal, deployment: &DeploymentId) -> bool {
    grants_on(config, principal.id(), deployment)
        .next()
        .is_some()
}

/// Whether the configuration names this principal: a grant or `[approvers]`. A token of
/// anyone else no longer works, grant or not.
pub(crate) fn named_in_config(config: &Config, id: &PrincipalId) -> bool {
    config.approver(id).is_some() || config.grants().iter().any(|grant| grant.principal() == id)
}
