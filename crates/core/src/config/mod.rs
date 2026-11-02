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
//!     approval: None,
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

pub use approval::{Approval, Approver, KeyCheck, MAX_CREDENTIAL_ID_LEN};
use serde::Deserialize;
use sha2::{Digest, Sha256};
pub use signer::SignerKey;
use thiserror::Error;

use crate::ids::{DeploymentId, HostId, PrincipalId, RepoName, TagPattern};
use crate::text::shown;

#[cfg(test)]
mod tests;

mod approval;

mod raw;

mod signer;

/// Why a configuration file was refused. Every variant names the deployment
/// (or section) and the offending value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
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
    /// There are deployments and no `[approval]`: any of them can need an approval, since
    /// a first deploy always does.
    #[error(
        "[approval] is missing; a first deploy always needs an approval, so set rp_id and origin"
    )]
    MissingApproval,
    /// `approval.origin` is not an origin as a browser writes it.
    #[error("approval.origin {}: {reason}", shown(.origin))]
    InvalidApprovalOrigin {
        /// The value in the file.
        origin: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// `approval.rp_id` is not exactly the hostname of `approval.origin`.
    #[error(
        "approval.rp_id {} must be exactly the hostname of approval.origin, {}",
        shown(.rp_id),
        shown(.host)
    )]
    RpIdNotOriginHost {
        /// The value in the file.
        rp_id: String,
        /// The hostname of `approval.origin`.
        host: String,
    },
    /// An `[approvers]` value can't be used. Never repeats the key.
    #[error("approver {approver}: {reason}")]
    InvalidApprover {
        /// The approver's name in `[approvers]`.
        approver: PrincipalId,
        /// Why the value is refused.
        reason: String,
    },
    /// Two `[approvers]` names hold the same credential id.
    #[error("approvers {first} and {second} hold the same credential id")]
    DuplicateCredentialId {
        /// The first name, in name order.
        first: PrincipalId,
        /// The second name.
        second: PrincipalId,
    },
    /// Two `[approvers]` names hold the same key.
    #[error("approvers {first} and {second} hold the same public key")]
    DuplicateApproverKey {
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
    /// Rule 7: `approve` granted on a deployment whose `rule.approvers` doesn't list the
    /// principal. The rule is what the host checks, so the two can't be let disagree.
    #[error(
        "grant for {principal}: can include \"approve\" on {deployment}, but rule.approvers of {deployment} does not list {principal}"
    )]
    ApproveNotListed {
        /// The grant's principal.
        principal: PrincipalId,
        /// The deployment.
        deployment: DeploymentId,
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
    /// The relying party approvals are checked against.
    approval: Option<Approval>,
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

    /// The approver named `id` in `[approvers]`.
    #[must_use]
    pub fn approver(&self, id: &PrincipalId) -> Option<&Approver> {
        self.approvers.get(id)
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
    /// The relying party approvals are checked against: there whenever a deployment is.
    approval: Option<&Approval> => c.approval.as_ref(),
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
/// [`Config::hash`] then identifies. `check` judges each approver's key; a program loads
/// its configuration with `landfall_approval::parse_config`, which supplies the
/// verifier's own.
///
/// # Errors
///
/// [`ConfigError::NotUtf8`] when the bytes are not UTF-8,
/// [`ConfigError::Toml`] for syntax, unknown keys and wrongly typed values,
/// otherwise the variant of the first validation rule that fails.
pub fn parse(bytes: &[u8], check: KeyCheck) -> Result<Config, ConfigError> {
    let text = std::str::from_utf8(bytes).map_err(|e| ConfigError::NotUtf8 {
        offset: e.valid_up_to(),
    })?;
    let config = raw::build(text, sha256_hex(bytes), check)?;
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
    if !config.deployments.is_empty() && config.approval.is_none() {
        return Err(ConfigError::MissingApproval);
    }
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
        if grant.can.contains(&Permission::Approve) {
            validate_approve_grant(config, grant)?;
        }
    }
    Ok(())
}

/// `approve` is for someone in `[approvers]`, on deployments whose rule lists them.
fn validate_approve_grant(config: &Config, grant: &Grant) -> Result<(), ConfigError> {
    if !config.approvers.contains_key(&grant.principal) {
        return Err(ConfigError::ApproveWithoutApprover {
            principal: grant.principal.clone(),
        });
    }
    let unlisted = grant
        .deployments
        .iter()
        .filter_map(|id| config.deployment(id))
        .find(|d| !d.rule.approvers.contains(&grant.principal));
    match unlisted {
        Some(deployment) => Err(ConfigError::ApproveNotListed {
            principal: grant.principal.clone(),
            deployment: deployment.id.clone(),
        }),
        None => Ok(()),
    }
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
