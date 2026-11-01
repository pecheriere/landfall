//! Fleet configuration: one TOML file per fleet.
//!
//! The file is deserialised into private raw structs (every one with
//! `deny_unknown_fields`, so a typo is an error), then converted and validated
//! into the public types. A [`Config`] therefore only exists validated: its
//! fields are private and there is no mutator, so downstream code can read a
//! configuration but neither build nor alter one.
//!
//! ```compile_fail,E0451
//! use std::collections::BTreeMap;
//! use landfall_core::config::Config;
//!
//! // Struct literals are refused: the fields are private.
//! let _ = Config {
//!     signers: BTreeMap::new(),
//!     approvers: BTreeMap::new(),
//!     deployments: vec![],
//!     grants: vec![],
//!     hash: String::new(),
//! };
//! ```
//!
//! ```compile_fail,E0616
//! # fn demo(config: landfall_core::config::Config) {
//! let mut config = config;
//! // And a parsed configuration cannot be edited afterwards: the field is private.
//! config.deployments.clear();
//! # }
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod raw;
mod signer;

pub use signer::SignerKey;

use crate::ids::{DeploymentId, HostId, PrincipalId, RepoName, TagPattern};

/// Why a configuration file was refused. Every variant names the deployment
/// (or section) and the offending value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The file is not UTF-8.
    #[error("configuration is not UTF-8: invalid byte at offset {offset}")]
    NotUtf8 {
        /// Offset of the first byte that is not valid UTF-8.
        offset: usize,
    },
    /// The text is not valid TOML, has an unknown key, or a value of the wrong type.
    #[error("configuration is not valid: {0}")]
    Toml(String),
    /// A field has a malformed value.
    #[error("deployment {deployment}: {field} {value:?} is invalid: {reason}")]
    Invalid {
        /// The deployment the value belongs to.
        deployment: DeploymentId,
        /// The offending key.
        field: String,
        /// The offending value.
        value: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// Rule 1: two deployments share an id.
    #[error("deployment id {0} is defined more than once")]
    DuplicateDeployment(DeploymentId),
    /// A `[signers]` value is not a usable tag-signing key.
    #[error("signer {signer}: {reason}")]
    InvalidSigner {
        /// The signer's name in `[signers]`.
        signer: PrincipalId,
        /// Why the key is refused.
        reason: String,
    },
    /// Two `[signers]` names hold the same key.
    #[error("signers {first} and {second} hold the same key")]
    DuplicateSignerKey {
        /// The first name, in name order.
        first: PrincipalId,
        /// The second name.
        second: PrincipalId,
    },
    /// Rule 2: an origin signer is not in `[signers]`.
    #[error("deployment {deployment}: origin signer {signer} is not in [signers]")]
    UnknownSigner {
        /// The deployment.
        deployment: DeploymentId,
        /// The unknown signer.
        signer: PrincipalId,
    },
    /// Rule 2: `origin.signers` is listed although `origin.signed_tags` is off.
    #[error(
        "deployment {0}: origin.signers is set but origin.signed_tags is false; remove the signers or turn signed_tags on"
    )]
    SignersWithoutSignedTags(DeploymentId),
    /// Rule 2: an origin has no signers.
    #[error("deployment {0}: origin.signers is empty; list at least one signer")]
    NoSigners(DeploymentId),
    /// Rule 3: `rule.approvers` is empty.
    #[error(
        "deployment {0}: rule.approvers is empty; first deploys, downgrades and major releases always need an approval"
    )]
    NoApprovers(DeploymentId),
    /// Rule 3: an approver is not in `[approvers]`.
    #[error("deployment {deployment}: approver {approver} is not in [approvers]")]
    UnknownApprover {
        /// The deployment.
        deployment: DeploymentId,
        /// The unknown approver.
        approver: PrincipalId,
    },
    /// Rule 4: `approve` is not broader than `auto`.
    #[error(
        "deployment {deployment}: rule.approve = \"{approve}\" must be broader than rule.auto = \"{auto}\" (patch < minor < any)"
    )]
    ApproveNotBroader {
        /// The deployment.
        deployment: DeploymentId,
        /// The `auto` level.
        auto: Level,
        /// The `approve` level.
        approve: Level,
    },
    /// Rule 5: no checks.
    #[error("deployment {0}: checks is empty; a deployment needs at least one check")]
    NoChecks(DeploymentId),
    /// Rule 5: no check observes the service (only `no_log_match` checks).
    #[error(
        "deployment {0}: no check observes the service; add \"container-healthy\", an http check or a command check"
    )]
    NoObservingCheck(DeploymentId),
    /// Rule 6: promotion target does not exist.
    #[error("deployment {deployment}: promote_to.deployment {target} does not exist")]
    UnknownPromotion {
        /// The deployment.
        deployment: DeploymentId,
        /// The missing target.
        target: DeploymentId,
    },
    /// Rule 6: a deployment promotes to itself.
    #[error("deployment {0}: promote_to.deployment points at itself")]
    SelfPromotion(DeploymentId),
    /// Rule 6: the promotion target belongs to another repository.
    #[error(
        "deployment {deployment}: promote_to.deployment {target} has repo.id {target_repo_id}, not {repo_id}"
    )]
    PromotionRepoMismatch {
        /// The deployment.
        deployment: DeploymentId,
        /// The target.
        target: DeploymentId,
        /// The deployment's `repo.id`.
        repo_id: u64,
        /// The target's `repo.id`.
        target_repo_id: u64,
    },
    /// Rule 6: the promotion chain starting at `deployment` loops back.
    #[error(
        "deployment {deployment}: promote_to chain forms a cycle: {}",
        Chain(.chain)
    )]
    PromotionCycle {
        /// The deployment whose chain was followed.
        deployment: DeploymentId,
        /// The cycle, its first deployment repeated at the end.
        chain: Vec<DeploymentId>,
    },
    /// Rule 7: a grant names a deployment that does not exist.
    #[error("grant for {principal}: deployment {deployment} does not exist")]
    UnknownGrantDeployment {
        /// The grant's principal.
        principal: PrincipalId,
        /// The missing deployment.
        deployment: DeploymentId,
    },
    /// Rule 7: a grant lists no deployments or no permissions.
    #[error("grant for {principal}: {field} is empty; list at least one")]
    EmptyGrant {
        /// The grant's principal.
        principal: PrincipalId,
        /// `deployments` or `can`.
        field: &'static str,
    },
    /// Rule 7: `approve` granted to someone who is not an approver.
    #[error("grant for {principal}: can include \"approve\" but {principal} is not in [approvers]")]
    ApproveWithoutApprover {
        /// The grant's principal.
        principal: PrincipalId,
    },
    /// Rule 8: two deployments use the same compose directory on one host.
    #[error(
        "deployment {deployment}: compose directory {dir:?} on host {host} is already used by {other}"
    )]
    DuplicateComposeDir {
        /// The later deployment.
        deployment: DeploymentId,
        /// The earlier deployment.
        other: DeploymentId,
        /// The host.
        host: HostId,
        /// The compose directory.
        dir: String,
    },
}

/// Displays a promotion cycle as `a -> b -> a`.
struct Chain<'a>(&'a [DeploymentId]);

impl fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, id) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(" -> ")?;
            }
            write!(f, "{id}")?;
        }
        Ok(())
    }
}

/// A validated fleet configuration. It can only be obtained from [`parse`]
/// and has no mutators, so every value in it passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Trusted tag-signing keys, by name.
    signers: BTreeMap<PrincipalId, SignerKey>,
    /// Passkey approvers, by name.
    approvers: BTreeMap<PrincipalId, Approver>,
    /// Every deployment, in file order.
    deployments: Vec<Deployment>,
    /// Who may do what.
    grants: Vec<Grant>,
    /// Lowercase hex SHA-256 of the file bytes it was parsed from.
    hash: String,
}

impl Config {
    /// The tag-signing key named `id` in `[signers]`.
    #[must_use]
    pub fn signer(&self, id: &PrincipalId) -> Option<&SignerKey> {
        self.signers.get(id)
    }

    /// The deployment with this id.
    #[must_use]
    pub fn deployment(&self, id: &DeploymentId) -> Option<&Deployment> {
        self.deployments.iter().find(|d| &d.id == id)
    }

    /// The deployments that run on `host`.
    pub fn deployments_for_host<'a>(
        &'a self,
        host: &'a HostId,
    ) -> impl Iterator<Item = &'a Deployment> {
        self.deployments.iter().filter(move |d| &d.host == host)
    }
}

/// A passkey approver. Both values are opaque base64url text here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    /// `WebAuthn` credential id.
    credential_id: String,
    /// COSE public key.
    public_key: String,
}

/// One deployed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// `<name>/<stage>`.
    id: DeploymentId,
    /// The source repository.
    repo: Repo,
    /// The host it runs on.
    host: HostId,
    /// Where its compose project lives.
    compose: Compose,
    /// Which releases are trusted.
    origin: Origin,
    /// When a deploy may start.
    rule: Rule,
    /// Post-deploy checks, at least one.
    checks: Vec<Check>,
    /// Backup taken before a deploy.
    backup: Option<Backup>,
    /// Promotion to another deployment once healthy.
    promote_to: Option<Promotion>,
}

/// A GitHub repository, pinned by immutable ids as well as name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Repo {
    /// `<owner>/<repo>`.
    name: RepoName,
    /// GitHub repository id.
    id: u64,
    /// GitHub owner id.
    owner_id: u64,
}

/// A compose service on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compose {
    /// Absolute directory of the compose project, without `..`.
    dir: String,
    /// Service name, `[a-z0-9][a-z0-9_.-]*`.
    service: String,
}

/// Where a release must come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Release workflow path under `.github/workflows/`.
    workflow: String,
    /// Which tags are releases.
    tags: TagPattern,
    /// Whether the release tag must carry a trusted signer's signature.
    signed_tags: bool,
    /// Trusted signers, each a key of `[signers]`; non-empty exactly when
    /// `signed_tags` is on.
    signers: Vec<PrincipalId>,
}

/// How far a version may jump. Ordered `Patch < Minor < Any`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Level {
    /// Patch bumps only.
    Patch,
    /// Up to minor bumps.
    Minor,
    /// Any bump, major included.
    Any,
}

impl fmt::Display for Level {
    /// The configuration spelling: `patch`, `minor` or `any`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Patch => "patch",
            Self::Minor => "minor",
            Self::Any => "any",
        })
    }
}

/// When a deploy may start.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rule {
    /// Deploy without a human up to this level.
    auto: Option<Level>,
    /// Deploy with an approval up to this level.
    approve: Option<Level>,
    /// Who may approve; non-empty, each a key of `[approvers]`.
    approvers: Vec<PrincipalId>,
    /// Whether prerelease versions are eligible.
    prereleases: bool,
}

/// A post-deploy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The container's Docker healthcheck reports healthy.
    ContainerHealthy,
    /// An HTTP probe on a Docker network.
    Http {
        /// Request path: `/` then visible ASCII only (0x21 to 0x7E).
        path: String,
        /// Docker network to probe from, `[A-Za-z0-9][A-Za-z0-9_.-]*`, at
        /// most 128 bytes.
        network: String,
        /// TCP port of the container, 1 to 65535.
        port: u16,
        /// Expected status code, 100 to 599.
        expect: u16,
    },
    /// A command run in the container; exit 0 is healthy.
    Command {
        /// Program and arguments.
        argv: Vec<String>,
    },
    /// No log line may contain `pattern` for `within_secs` after the deploy.
    /// It does not observe the service on its own, so a deployment also needs
    /// one of the other checks.
    NoLogMatch {
        /// Plain substring to look for (not a regex), on a single line and at
        /// most [`LOG_PATTERN_LIMIT`] bytes.
        pattern: String,
        /// Observation window in seconds, at most [`WITHIN_SECS_LIMIT`].
        within_secs: u32,
    },
}

/// The longest `no_log_match` pattern, in bytes.
pub const LOG_PATTERN_LIMIT: usize = 4096;

/// The longest `no_log_match` window, in seconds. A deploy waits for it.
pub const WITHIN_SECS_LIMIT: u32 = 3600;

/// Files copied before a deploy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    /// Paths relative to the compose directory; non-empty, no `..`.
    paths: Vec<String>,
    /// Stop the service while copying (default true).
    stop: bool,
}

/// Promote to another deployment once healthy long enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    /// The deployment promoted to.
    deployment: DeploymentId,
    /// How long this one must stay healthy, in seconds.
    healthy_for_secs: u64,
}

/// What a grant allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Permission {
    /// See the deployment.
    View,
    /// Request a manual deploy.
    Request,
    /// Approve a deploy; only for principals in `[approvers]`.
    Approve,
    /// Roll back.
    Rollback,
}

/// A principal's permissions on some deployments. Grants for the same
/// principal combine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Who.
    principal: PrincipalId,
    /// On which deployments.
    deployments: Vec<DeploymentId>,
    /// What they may do.
    can: Vec<Permission>,
}

/// Read accessors for a validated value. Fields are private on purpose: a
/// `Config` only comes out of [`parse`].
macro_rules! getters {
    ($ty:ty, $this:ident { $($(#[$m:meta])* $name:ident: $ret:ty => $expr:expr),* $(,)? }) => {
        impl $ty {
            $(
                $(#[$m])*
                #[must_use]
                pub fn $name(&self) -> $ret {
                    let $this = self;
                    $expr
                }
            )*
        }
    };
}

getters!(Config, c {
    /// Trusted tag-signing keys, by name.
    signers: &BTreeMap<PrincipalId, SignerKey> => &c.signers,
    /// Passkey approvers, by name.
    approvers: &BTreeMap<PrincipalId, Approver> => &c.approvers,
    /// Every deployment, in file order.
    deployments: &[Deployment] => &c.deployments,
    /// Who may do what.
    grants: &[Grant] => &c.grants,
    /// Lowercase hex SHA-256 of exactly the bytes given to [`parse`];
    /// agents and the controller compare these to detect configuration drift.
    hash: &str => &c.hash,
});
getters!(Approver, a {
    /// `WebAuthn` credential id (opaque base64url text).
    credential_id: &str => &a.credential_id,
    /// COSE public key (opaque base64url text).
    public_key: &str => &a.public_key,
});
getters!(Deployment, d {
    /// `<name>/<stage>`.
    id: &DeploymentId => &d.id,
    /// The source repository.
    repo: &Repo => &d.repo,
    /// The host it runs on.
    host: &HostId => &d.host,
    /// Where its compose project lives.
    compose: &Compose => &d.compose,
    /// Which releases are trusted.
    origin: &Origin => &d.origin,
    /// When a deploy may start.
    rule: &Rule => &d.rule,
    /// Post-deploy checks; never empty.
    checks: &[Check] => &d.checks,
    /// Backup taken before a deploy.
    backup: Option<&Backup> => d.backup.as_ref(),
    /// Promotion to another deployment once healthy.
    promote_to: Option<&Promotion> => d.promote_to.as_ref(),
});
getters!(Repo, r {
    /// `<owner>/<repo>`.
    name: &RepoName => &r.name,
    /// GitHub repository id.
    id: u64 => r.id,
    /// GitHub owner id.
    owner_id: u64 => r.owner_id,
});
getters!(Compose, c {
    /// Absolute, canonical directory of the compose project.
    dir: &str => &c.dir,
    /// Service name.
    service: &str => &c.service,
});
getters!(Origin, o {
    /// Release workflow path.
    workflow: &str => &o.workflow,
    /// Which tags are releases.
    tags: &TagPattern => &o.tags,
    /// Whether the release tag must be signed by one of `signers`.
    signed_tags: bool => o.signed_tags,
    /// Trusted signers; each exists in `[signers]`; empty exactly when
    /// `signed_tags` is off.
    signers: &[PrincipalId] => &o.signers,
});
getters!(Rule, r {
    /// Deploy without a human up to this level.
    auto: Option<Level> => r.auto,
    /// Deploy with an approval up to this level.
    approve: Option<Level> => r.approve,
    /// Who may approve; each exists in `[approvers]`, never empty.
    approvers: &[PrincipalId] => &r.approvers,
    /// Whether prerelease versions are eligible.
    prereleases: bool => r.prereleases,
});
getters!(Backup, b {
    /// Canonical relative paths; never empty.
    paths: &[String] => &b.paths,
    /// Whether the service is stopped while copying.
    stop: bool => b.stop,
});
getters!(Promotion, p {
    /// The deployment promoted to; exists and is not part of a cycle.
    deployment: &DeploymentId => &p.deployment,
    /// How long the source must stay healthy, in seconds.
    healthy_for_secs: u64 => p.healthy_for_secs,
});
getters!(Grant, g {
    /// Who.
    principal: &PrincipalId => &g.principal,
    /// On which deployments; never empty, all exist.
    deployments: &[DeploymentId] => &g.deployments,
    /// What they may do; never empty.
    can: &[Permission] => &g.can,
});

/// Lowercase hex SHA-256 of `bytes`.
fn sha256_hex(bytes: &[u8]) -> String {
    crate::hex::encode(&Sha256::digest(bytes))
}

/// Parses and validates a configuration file from its exact bytes, which
/// [`Config::hash`] then identifies.
///
/// # Errors
///
/// [`ConfigError::NotUtf8`] when the bytes are not UTF-8,
/// [`ConfigError::Toml`] for syntax, unknown keys and wrongly typed values,
/// otherwise the variant of the first validation rule that fails.
pub fn parse(bytes: &[u8]) -> Result<Config, ConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ConfigError::NotUtf8 {
        offset: e.valid_up_to(),
    })?;
    let config = raw::build(text, sha256_hex(bytes))?;
    validate(&config)?;
    Ok(config)
}

/// Rules 2 to 6 for one deployment (the chain check in rule 6 is separate).
fn validate_deployment(config: &Config, d: &Deployment) -> Result<(), ConfigError> {
    // Rule 2.
    if d.origin.signed_tags && d.origin.signers.is_empty() {
        return Err(ConfigError::NoSigners(d.id.clone()));
    }
    if !d.origin.signed_tags && !d.origin.signers.is_empty() {
        return Err(ConfigError::SignersWithoutSignedTags(d.id.clone()));
    }
    if let Some(signer) = d
        .origin
        .signers
        .iter()
        .find(|s| !config.signers.contains_key(*s))
    {
        return Err(ConfigError::UnknownSigner {
            deployment: d.id.clone(),
            signer: signer.clone(),
        });
    }
    // Rule 3.
    if d.rule.approvers.is_empty() {
        return Err(ConfigError::NoApprovers(d.id.clone()));
    }
    if let Some(approver) = d
        .rule
        .approvers
        .iter()
        .find(|a| !config.approvers.contains_key(*a))
    {
        return Err(ConfigError::UnknownApprover {
            deployment: d.id.clone(),
            approver: approver.clone(),
        });
    }
    // Rule 4.
    if let (Some(auto), Some(approve)) = (d.rule.auto, d.rule.approve)
        && approve <= auto
    {
        return Err(ConfigError::ApproveNotBroader {
            deployment: d.id.clone(),
            auto,
            approve,
        });
    }
    // Rule 5.
    if d.checks.is_empty() {
        return Err(ConfigError::NoChecks(d.id.clone()));
    }
    if d.checks
        .iter()
        .all(|c| matches!(c, Check::NoLogMatch { .. }))
    {
        return Err(ConfigError::NoObservingCheck(d.id.clone()));
    }
    // Rule 6, per deployment.
    if let Some(promotion) = &d.promote_to {
        if promotion.deployment == d.id {
            return Err(ConfigError::SelfPromotion(d.id.clone()));
        }
        let Some(target) = config.deployment(&promotion.deployment) else {
            return Err(ConfigError::UnknownPromotion {
                deployment: d.id.clone(),
                target: promotion.deployment.clone(),
            });
        };
        if target.repo.id != d.repo.id {
            return Err(ConfigError::PromotionRepoMismatch {
                deployment: d.id.clone(),
                target: target.id.clone(),
                repo_id: d.repo.id,
                target_repo_id: target.repo.id,
            });
        }
    }
    Ok(())
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    let mut dirs: HashMap<(&HostId, &str), &DeploymentId> = HashMap::new();
    for d in &config.deployments {
        // Rule 1.
        if !seen.insert(&d.id) {
            return Err(ConfigError::DuplicateDeployment(d.id.clone()));
        }
        validate_deployment(config, d)?;
        // Rule 8.
        if let Some(other) = dirs.insert((&d.host, d.compose.dir.as_str()), &d.id) {
            return Err(ConfigError::DuplicateComposeDir {
                deployment: d.id.clone(),
                other: other.clone(),
                host: d.host.clone(),
                dir: d.compose.dir.clone(),
            });
        }
    }

    // Rule 6, chains.
    for d in &config.deployments {
        if let Some(chain) = promotion_cycle(config, d) {
            return Err(ConfigError::PromotionCycle {
                deployment: d.id.clone(),
                chain,
            });
        }
    }

    // Rule 7.
    for grant in &config.grants {
        for (field, empty) in [
            ("deployments", grant.deployments.is_empty()),
            ("can", grant.can.is_empty()),
        ] {
            if empty {
                return Err(ConfigError::EmptyGrant {
                    principal: grant.principal.clone(),
                    field,
                });
            }
        }
        if let Some(missing) = grant
            .deployments
            .iter()
            .find(|id| config.deployment(id).is_none())
        {
            return Err(ConfigError::UnknownGrantDeployment {
                principal: grant.principal.clone(),
                deployment: missing.clone(),
            });
        }
        if grant.can.contains(&Permission::Approve)
            && !config.approvers.contains_key(&grant.principal)
        {
            return Err(ConfigError::ApproveWithoutApprover {
                principal: grant.principal.clone(),
            });
        }
    }
    Ok(())
}

/// Follows the promotion chain from `start`. When it loops, returns the
/// loop, its first deployment repeated at the end (`b -> c -> b`).
fn promotion_cycle(config: &Config, start: &Deployment) -> Option<Vec<DeploymentId>> {
    let mut path = vec![&start.id];
    let mut current = start;
    while let Some(next) = current
        .promote_to
        .as_ref()
        .and_then(|p| config.deployment(&p.deployment))
    {
        if let Some(position) = path.iter().position(|id| **id == next.id) {
            let mut chain: Vec<DeploymentId> =
                path[position..].iter().map(|id| (*id).clone()).collect();
            chain.push(next.id.clone());
            return Some(chain);
        }
        path.push(&next.id);
        current = next;
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = [{ http = "/health", network = "app_app", port = 8080, expect = 200 }]
backup = { paths = ["state"], stop = true }

[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "24h" }

[[grant]]
principal = "operator"
deployments = ["app/prod", "app/staging"]
can = ["view", "request", "approve", "rollback"]
"#;

    fn id(s: &str) -> DeploymentId {
        s.parse().unwrap()
    }

    fn parse_str(text: &str) -> Result<Config, ConfigError> {
        parse(text.as_bytes())
    }

    fn edited(from: &str, to: &str) -> String {
        assert!(EXAMPLE.contains(from), "fixture lacks {from:?}");
        EXAMPLE.replacen(from, to, 1)
    }

    fn fixture_key(file: &str) -> String {
        std::fs::read_to_string(format!(
            "{}/tests/fixtures/tag/{file}",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap()
    }

    fn with_signer(value: &str) -> String {
        EXAMPLE.replacen(
            &format!("maintainer = {:?}", fixture_key("signer.pub").trim_end()),
            &format!("maintainer = {value:?}"),
            1,
        )
    }

    #[test]
    fn signer_keys_are_parsed() {
        let config = parse_str(EXAMPLE).unwrap();
        let maintainer: PrincipalId = "maintainer".parse().unwrap();
        let key = config.signer(&maintainer).unwrap();
        assert_eq!(
            key.fingerprint(),
            "SHA256:aN9xB/PG8u3ubV37qOIeOe3nPDkWfAzfFl+We+g5ASA"
        );
        assert!(config.signer(&"nobody".parse().unwrap()).is_none());

        // The comment is ignored: the same key with one is the same key.
        let commented = with_signer(&format!(
            "{} laptop key",
            fixture_key("signer.pub").trim_end()
        ));
        let other = parse_str(&commented).unwrap();
        assert_eq!(other.signer(&maintainer), Some(key));
    }

    #[test]
    fn non_ed25519_signer_is_rejected() {
        let err = parse_str(&with_signer(&fixture_key("ecdsa.pub"))).unwrap_err();
        let ConfigError::InvalidSigner { signer, reason } = &err else {
            panic!("{err}");
        };
        assert_eq!(signer.to_string(), "maintainer");
        assert!(reason.contains("ecdsa-sha2-nistp256"), "{reason}");
    }

    #[test]
    fn garbage_signer_is_rejected() {
        for garbage in [
            "",
            "not a key",
            "ssh-ed25519",
            "ssh-ed25519 AAAA",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly",
        ] {
            let err = parse_str(&with_signer(garbage)).unwrap_err();
            assert!(
                matches!(&err, ConfigError::InvalidSigner { signer, .. } if signer.to_string() == "maintainer"),
                "{garbage:?}: {err}"
            );
        }
    }

    #[test]
    fn duplicate_signer_keys_are_rejected() {
        let key = fixture_key("signer.pub");
        let text = EXAMPLE.replacen(
            "[approvers]",
            &format!(
                "backup = {:?}\n\n[approvers]",
                format!("{} spare", key.trim_end())
            ),
            1,
        );
        assert_eq!(
            parse_str(&text).unwrap_err(),
            ConfigError::DuplicateSignerKey {
                first: "backup".parse().unwrap(),
                second: "maintainer".parse().unwrap(),
            }
        );
    }

    #[test]
    fn signed_tags_defaults_to_true() {
        let config = parse_str(EXAMPLE).unwrap();
        let prod = config.deployment(&id("app/prod")).unwrap();
        assert!(prod.origin().signed_tags());
    }

    #[test]
    fn unsigned_deployment_needs_no_signers() {
        let text = edited(
            "tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "tags = \"v*\", signed_tags = false }\nrule = { auto = \"patch\"",
        );
        let config = parse_str(&text).unwrap();
        let prod = config.deployment(&id("app/prod")).unwrap();
        assert!(!prod.origin().signed_tags());
        assert_eq!(prod.origin().signers(), &[]);
        // An explicit empty list is accepted too.
        let explicit = edited(
            "tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "tags = \"v*\", signed_tags = false, signers = [] }\nrule = { auto = \"patch\"",
        );
        assert!(parse_str(&explicit).is_ok());
        // signed_tags on (the default) still needs signers.
        let err = parse_str(&edited(
            "signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "signed_tags = true }\nrule = { auto = \"patch\"",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoSigners(_)), "{err}");
    }

    #[test]
    fn signers_with_signed_tags_off_is_rejected() {
        let err = parse_str(&edited(
            "signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            "signers = [\"maintainer\"], signed_tags = false }\nrule = { auto = \"patch\"",
        ))
        .unwrap_err();
        assert_eq!(err, ConfigError::SignersWithoutSignedTags(id("app/prod")));
    }

    #[test]
    fn example_parses() {
        let config = parse_str(EXAMPLE).unwrap();
        let prod = config.deployment(&id("app/prod")).unwrap();
        assert_eq!(prod.rule().auto(), Some(Level::Patch));
        assert_eq!(prod.rule().approve(), Some(Level::Minor));
        assert!(!prod.rule().prereleases());
        assert_eq!(prod.compose().service(), "app");
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(staging.promote_to().unwrap().healthy_for_secs(), 86_400);
        let host: HostId = "home-1".parse().unwrap();
        assert_eq!(config.deployments_for_host(&host).count(), 2);
        let other: HostId = "home-2".parse().unwrap();
        assert_eq!(config.deployments_for_host(&other).count(), 0);
        assert_eq!(config.grants()[0].can().len(), 4);
    }

    #[test]
    fn unknown_fields_are_errors() {
        let text = edited(
            "checks = [\"container-healthy\"]",
            "checks = [\"container-healthy\"]\nrul = { auto = \"patch\" }",
        );
        let err = parse_str(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
        assert!(err.to_string().contains("rul"), "{err}");
    }

    #[test]
    fn each_validation_rule_is_enforced() {
        // 1: duplicate ids.
        let err = parse_str(&edited("id = \"app/staging\"", "id = \"app/prod\"")).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateDeployment(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 2: unknown or empty origin signers.
        let err = parse_str(&edited(
            "signers = [\"maintainer\"]",
            "signers = [\"nobody\"]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownSigner { .. }), "{err}");
        assert!(err.to_string().contains("app/prod") && err.to_string().contains("nobody"));
        let err = parse_str(&edited("signers = [\"maintainer\"]", "signers = []")).unwrap_err();
        assert!(matches!(err, ConfigError::NoSigners(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 3: approvers always non-empty and known.
        let err = parse_str(&edited(
            "approvers = [\"operator\"] }\nchecks = [\"container",
            "approvers = [] }\nchecks = [\"container",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoApprovers(_)), "{err}");
        assert!(err.to_string().contains("app/staging"));
        let err = parse_str(&edited(
            "approve = \"minor\", approvers = [\"operator\"]",
            "approve = \"minor\", approvers = [\"ghost\"]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownApprover { .. }), "{err}");
        assert!(err.to_string().contains("app/prod") && err.to_string().contains("ghost"));

        // 4: approve must be broader than auto.
        let err = parse_str(&edited("approve = \"minor\"", "approve = \"patch\"")).unwrap_err();
        assert!(
            matches!(err, ConfigError::ApproveNotBroader { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("app/prod"));

        // 5: checks non-empty.
        let err = parse_str(&edited(
            "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
            "checks = []",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoChecks(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 6: promotion target unknown, itself, or a cycle.
        let err = parse_str(&edited(
            "deployment = \"app/prod\", healthy_for",
            "deployment = \"app/none\", healthy_for",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownPromotion { .. }), "{err}");
        assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/none"));
        let err = parse_str(&edited(
            "deployment = \"app/prod\", healthy_for",
            "deployment = \"app/staging\", healthy_for",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::SelfPromotion(_)), "{err}");
        assert!(err.to_string().contains("app/staging"));
        let cyclic = edited(
            "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
            "checks = [\"container-healthy\"]\npromote_to = { deployment = \"app/staging\", healthy_for = \"1h\" }",
        );
        let err = parse_str(&cyclic).unwrap_err();
        assert!(matches!(err, ConfigError::PromotionCycle { .. }), "{err}");
        assert!(
            err.to_string()
                .contains("app/prod -> app/staging -> app/prod"),
            "{err}"
        );

        // 7: grants.
        let err = parse_str(&edited(
            "deployments = [\"app/prod\", \"app/staging\"]",
            "deployments = [\"app/none\"]",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownGrantDeployment { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("app/none") && err.to_string().contains("operator"));
        let err = parse_str(&edited(
            "principal = \"operator\"",
            "principal = \"maintainer\"",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::ApproveWithoutApprover { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("maintainer"));

        // 8: one deployment per host and compose directory.
        let err = parse_str(&edited(
            "dir = \"/srv/compose/app-staging\"",
            "dir = \"/srv/compose/app\"",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateComposeDir { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/prod"));
    }

    #[test]
    fn http_check_requires_a_port() {
        let err = parse_str(&with_staging_checks(
            "[{ http = \"/h\", network = \"app\", expect = 200 }]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
        let err = err.to_string();
        assert!(err.contains("port") && err.contains("app/staging"), "{err}");
    }

    #[test]
    fn port_zero_is_rejected() {
        for port in ["0", "65536", "-1"] {
            let check =
                format!("[{{ http = \"/h\", network = \"app\", port = {port}, expect = 200 }}]");
            assert!(parse_str(&with_staging_checks(&check)).is_err(), "{port}");
        }
        for port in ["1", "65535"] {
            let check =
                format!("[{{ http = \"/h\", network = \"app\", port = {port}, expect = 200 }}]");
            assert!(parse_str(&with_staging_checks(&check)).is_ok(), "{port}");
        }
    }

    #[test]
    fn two_deployments_cannot_share_a_directory() {
        let err = parse_str(&edited(
            "dir = \"/srv/compose/app-staging\", service = \"app\"",
            "dir = \"/srv/compose/app\", service = \"other\"",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::DuplicateComposeDir { .. }),
            "{err}"
        );
        let err = err.to_string();
        assert!(
            err.contains("app/staging") && err.contains("app/prod"),
            "{err}"
        );
        assert!(err.contains("/srv/compose/app"), "{err}");
    }

    #[test]
    fn malformed_values_name_the_deployment() {
        for (from, to) in [
            ("dir = \"/srv/compose/app\"", "dir = \"srv/compose/app\""),
            ("dir = \"/srv/compose/app\"", "dir = \"/srv/../app\""),
            (
                "service = \"app\" }\norigin = { workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
                "service = \"App\" }\norigin = { workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            ),
            (
                "workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
                "workflow = \"release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"",
            ),
            ("paths = [\"state\"]", "paths = [\"/etc\"]"),
            ("paths = [\"state\"]", "paths = [\"a/../b\"]"),
            ("paths = [\"state\"]", "paths = []"),
            ("healthy_for = \"24h\"", "healthy_for = \"24\""),
            ("healthy_for = \"24h\"", "healthy_for = \"0h\""),
        ] {
            let err = parse_str(&edited(from, to)).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid { .. }), "{to}: {err}");
            assert!(err.to_string().contains("app/"), "{err}");
        }
    }

    #[test]
    fn durations_use_minutes_hours_days() {
        for (text, secs) in [("90m", 5_400), ("2h", 7_200), ("1d", 86_400)] {
            let config = parse_str(&edited(
                "healthy_for = \"24h\"",
                &format!("healthy_for = \"{text}\""),
            ))
            .unwrap();
            let staging = config.deployment(&id("app/staging")).unwrap();
            assert_eq!(staging.promote_to().unwrap().healthy_for_secs(), secs);
        }
    }

    #[test]
    fn checks_parse_in_both_forms() {
        let all = "checks = [\"container-healthy\", { http = \"/health\", network = \"app\", port = 8080, expect = 200 }, { command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"panicked\", within_secs = 30 }]";
        let config = parse_str(&edited("checks = [\"container-healthy\"]", all)).unwrap();
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(
            staging.checks(),
            vec![
                Check::ContainerHealthy,
                Check::Http {
                    path: "/health".into(),
                    network: "app".into(),
                    port: 8080,
                    expect: 200
                },
                Check::Command {
                    argv: vec!["/app".into(), "healthcheck".into()]
                },
                Check::NoLogMatch {
                    pattern: "panicked".into(),
                    within_secs: 30
                },
            ]
        );
        for bad in [
            "{ http = \"/h\", command = [\"x\"] }",
            "{ http = \"/h\" }",
            "{ command = [] }",
            "{ no_log_match = \"x\" }",
            "{}",
            "\"unknown\"",
        ] {
            let text = edited(
                "checks = [\"container-healthy\"]",
                &format!("checks = [{bad}]"),
            );
            let err = parse_str(&text).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ConfigError::Invalid { deployment, field, .. }
                        if deployment.as_ref() == "app/staging" && field == "checks[0]"
                ),
                "{bad}: {err}"
            );
        }
    }

    #[test]
    fn sha256_hex_matches_the_empty_input_vector() {
        assert_eq!(
            sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_covers_exactly_the_file_bytes() {
        let config = parse_str(EXAMPLE).unwrap();
        assert_eq!(config.hash(), sha256_hex(EXAMPLE.as_bytes()));
        // Same meaning, different bytes: a different hash.
        let spaced = format!("{EXAMPLE}\n");
        let other = parse_str(&spaced).unwrap();
        assert_ne!(other.hash(), config.hash());
    }

    #[test]
    fn non_utf8_bytes_are_refused() {
        let mut bytes = EXAMPLE.as_bytes().to_vec();
        bytes.insert(10, 0xff);
        assert_eq!(
            parse(&bytes).unwrap_err(),
            ConfigError::NotUtf8 { offset: 10 }
        );
    }

    #[test]
    fn unknown_key_in_a_check_table_is_named() {
        let text = edited(
            "checks = [\"container-healthy\"]",
            "checks = [{ http = \"/h\", netwrok = \"app\", expect = 200 }]",
        );
        let err = parse_str(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)), "{err}");
        assert!(err.to_string().contains("netwrok"), "{err}");
    }

    #[test]
    fn check_errors_name_the_entry_and_the_keys() {
        let text = edited(
            "checks = [\"container-healthy\"]",
            "checks = [\"container-healthy\", \"container-healthy\", { http = \"/h\", command = [\"x\"] }]",
        );
        let err = parse_str(&text).unwrap_err().to_string();
        assert!(err.contains("app/staging"), "{err}");
        assert!(err.contains("checks[2]"), "{err}");
        assert!(err.contains("http") && err.contains("command"), "{err}");
        assert!(!err.contains("{...}"), "{err}");

        let text = edited("checks = [\"container-healthy\"]", "checks = [\"healthy\"]");
        let err = parse_str(&text).unwrap_err().to_string();
        assert!(
            err.contains("checks[0]") && err.contains("healthy"),
            "{err}"
        );
    }

    #[test]
    fn compose_dir_must_be_canonical() {
        // Spellings of the same directory as app/prod's must not slip past
        // the one-service-per-host rule.
        for dir in [
            "/srv/compose/app/",
            "/srv//compose/app",
            "/srv/./compose/app",
            "/srv/compose/app/.",
            "/srv/compose/../compose/app",
            "/",
            "//",
        ] {
            let text = edited(
                "dir = \"/srv/compose/app-staging\"",
                &format!("dir = \"{dir}\""),
            );
            let err = parse_str(&text).unwrap_err();
            assert!(
                matches!(&err, ConfigError::Invalid { field, .. } if field == "compose.dir"),
                "{dir}: {err}"
            );
        }
    }

    #[test]
    fn backup_paths_must_be_canonical() {
        for path in ["state/", "a//b", "./state", "state/."] {
            let text = edited("paths = [\"state\"]", &format!("paths = [\"{path}\"]"));
            assert!(
                matches!(parse_str(&text), Err(ConfigError::Invalid { .. })),
                "{path}"
            );
        }
    }

    #[test]
    fn log_checks_stay_within_what_the_agent_can_run() {
        let long = "x".repeat(LOG_PATTERN_LIMIT + 1);
        for bad in [
            format!("[\"container-healthy\", {{ no_log_match = \"{long}\", within_secs = 1 }}]"),
            "[\"container-healthy\", { no_log_match = \"a\\nb\", within_secs = 1 }]".to_owned(),
            "[\"container-healthy\", { no_log_match = \"x\", within_secs = 3601 }]".to_owned(),
        ] {
            let err = parse_str(&with_staging_checks(&bad)).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ConfigError::Invalid { deployment, field, .. }
                        if deployment.as_ref() == "app/staging" && field == "checks[1]"
                ),
                "{err}"
            );
        }
        let longest = "x".repeat(LOG_PATTERN_LIMIT);
        let at_the_limits = format!(
            "[\"container-healthy\", {{ no_log_match = \"{longest}\", within_secs = 3600 }}]"
        );
        assert!(parse_str(&with_staging_checks(&at_the_limits)).is_ok());
    }

    /// The fixture with app/staging's check list replaced by `checks`.
    fn with_staging_checks(checks: &str) -> String {
        edited(
            "checks = [\"container-healthy\"]",
            &format!("checks = {checks}"),
        )
    }

    #[test]
    fn a_deployment_needs_a_check_that_observes_the_service() {
        let text = with_staging_checks("[{ no_log_match = \"panicked\", within_secs = 30 }]");
        let err = parse_str(&text).unwrap_err();
        assert_eq!(err, ConfigError::NoObservingCheck(id("app/staging")));
        assert!(err.to_string().contains("app/staging"), "{err}");
        for observing in [
            "[\"container-healthy\", { no_log_match = \"panicked\", within_secs = 30 }]",
            "[{ command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"x\", within_secs = 1 }]",
            "[{ no_log_match = \"x\", within_secs = 1 }, { http = \"/\", network = \"app\", port = 8080, expect = 204 }]",
        ] {
            assert!(
                parse_str(&with_staging_checks(observing)).is_ok(),
                "{observing}"
            );
        }
    }

    #[test]
    fn http_checks_validate_path_network_and_status() {
        for (check, field, value) in [
            (
                "{ http = \"/h\", network = \"app\", port = 8080, expect = 0 }",
                "checks[0].expect",
                "0",
            ),
            (
                "{ http = \"/h\", network = \"app\", port = 8080, expect = 99 }",
                "checks[0].expect",
                "99",
            ),
            (
                "{ http = \"/h\", network = \"app\", port = 8080, expect = 600 }",
                "checks[0].expect",
                "600",
            ),
            (
                "{ http = \"/h\\r\\nX: y\", network = \"app\", port = 8080, expect = 200 }",
                "checks[0].http",
                "/h\r\nX: y",
            ),
            (
                "{ http = \"/a b\", network = \"app\", port = 8080, expect = 200 }",
                "checks[0].http",
                "/a b",
            ),
            (
                "{ http = \"/caf\u{e9}\", network = \"app\", port = 8080, expect = 200 }",
                "checks[0].http",
                "/caf\u{e9}",
            ),
            (
                "{ http = \"health\", network = \"app\", port = 8080, expect = 200 }",
                "checks[0].http",
                "health",
            ),
            (
                "{ http = \"/h\", network = \"n n\", port = 8080, expect = 200 }",
                "checks[0].network",
                "n n",
            ),
            (
                "{ http = \"/h\", network = \"\", port = 8080, expect = 200 }",
                "checks[0].network",
                "",
            ),
            (
                "{ http = \"/h\", network = \"-net\", port = 8080, expect = 200 }",
                "checks[0].network",
                "-net",
            ),
        ] {
            let err = parse_str(&with_staging_checks(&format!("[{check}]"))).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ConfigError::Invalid { field: f, value: v, .. } if f == field && v == value
                ),
                "{check}: {err}"
            );
        }
        let long = format!("n{}", "x".repeat(128));
        let err = parse_str(&with_staging_checks(&format!(
            "[{{ http = \"/h\", network = \"{long}\", port = 8080, expect = 200 }}]"
        )))
        .unwrap_err();
        assert!(matches!(err, ConfigError::Invalid { .. }), "{err}");
        let at_limit = format!("n{}", "x".repeat(127));
        for check in [
            "{ http = \"/h?a=1&b=%20\", network = \"app_net.1-x\", port = 8080, expect = 100 }"
                .to_owned(),
            format!("{{ http = \"/\", network = \"{at_limit}\", port = 8080, expect = 599 }}"),
        ] {
            assert!(
                parse_str(&with_staging_checks(&format!("[{check}]"))).is_ok(),
                "{check}"
            );
        }
    }

    #[test]
    fn workflow_is_a_file_directly_in_the_workflows_directory() {
        let from = "workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }\nrule = { auto = \"patch\"";
        for bad in [
            ".github/workflows/.yml",
            ".github/workflows/a/b.yml",
            ".github/workflows/a b@refs.yml",
            ".github/workflows/release.json",
            ".github/workflows/../workflows/release.yml",
            "x/.github/workflows/release.yml",
        ] {
            let to = from.replace(".github/workflows/release.yml", bad);
            let err = parse_str(&edited(from, &to)).unwrap_err();
            assert!(
                matches!(
                    &err,
                    ConfigError::Invalid { field, value, .. }
                        if field == "origin.workflow" && value == bad
                ),
                "{bad}: {err}"
            );
            assert!(!err.to_string().contains("without '..'"), "{err}");
        }
        for ok in [
            ".github/workflows/release.yaml",
            ".github/workflows/Release_v2.1-x.yml",
        ] {
            let to = from.replace(".github/workflows/release.yml", ok);
            assert!(parse_str(&edited(from, &to)).is_ok(), "{ok}");
        }
    }

    #[test]
    fn promotion_cycle_reports_the_loop() {
        // app/canary -> app/staging -> app/prod -> app/staging: the error is
        // reported for app/canary and names only the loop.
        let canary = r#"
[[deployment]]
id = "app/canary"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-canary", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/staging", healthy_for = "1h" }

[[deployment]]
id = "app/prod""#;
        let text = edited("\n[[deployment]]\nid = \"app/prod\"", canary);
        let text = text.replacen(
            "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]",
            "checks = [{ http = \"/health\", network = \"app_app\", port = 8080, expect = 200 }]\npromote_to = { deployment = \"app/staging\", healthy_for = \"1h\" }",
            1,
        );
        let err = parse_str(&text).unwrap_err();
        assert_eq!(
            err,
            ConfigError::PromotionCycle {
                deployment: id("app/canary"),
                chain: vec![id("app/staging"), id("app/prod"), id("app/staging")],
            }
        );
        assert!(
            err.to_string().ends_with(
                "app/canary: promote_to chain forms a cycle: app/staging -> app/prod -> app/staging"
            ),
            "{err}"
        );
    }

    #[test]
    fn promotion_stays_within_one_repository() {
        let text = edited(
            "id = \"app/staging\"\nrepo = { name = \"example/app\", id = 1234",
            "id = \"app/staging\"\nrepo = { name = \"example/app\", id = 4321",
        );
        let err = parse_str(&text).unwrap_err();
        assert_eq!(
            err,
            ConfigError::PromotionRepoMismatch {
                deployment: id("app/staging"),
                target: id("app/prod"),
                repo_id: 4321,
                target_repo_id: 1234,
            }
        );
        assert!(err.to_string().contains("app/staging"), "{err}");
    }

    #[test]
    fn grants_must_list_deployments_and_permissions() {
        let principal: PrincipalId = "operator".parse().unwrap();
        let err = parse_str(&edited(
            "deployments = [\"app/prod\", \"app/staging\"]",
            "deployments = []",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::EmptyGrant {
                principal: principal.clone(),
                field: "deployments"
            }
        );
        assert!(err.to_string().contains("operator"), "{err}");
        let err = parse_str(&edited(
            "can = [\"view\", \"request\", \"approve\", \"rollback\"]",
            "can = []",
        ))
        .unwrap_err();
        assert_eq!(
            err,
            ConfigError::EmptyGrant {
                principal,
                field: "can"
            }
        );
    }

    #[test]
    fn approve_not_broader_names_levels_in_config_spelling() {
        let err = parse_str(&edited("approve = \"minor\"", "approve = \"patch\"")).unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("rule.approve = \"patch\"") && text.contains("rule.auto = \"patch\""),
            "{text}"
        );
        assert!(!text.contains("Patch"), "{text}");
        assert_eq!(Level::Minor.to_string(), "minor");
        assert_eq!(Level::Any.to_string(), "any");
    }
}
