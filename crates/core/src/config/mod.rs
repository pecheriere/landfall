//! Fleet configuration: one TOML file per fleet.
//!
//! The file is deserialised into private raw structs (every one with
//! `deny_unknown_fields`, so a typo is an error), then converted and validated
//! into the public types. A [`Config`] therefore only exists validated: its
//! fields are private and there is no mutator, so downstream code can read a
//! configuration but neither build nor alter one.
//!
//! ```compile_fail
//! use std::collections::BTreeMap;
//! use landfall_core::config::Config;
//!
//! // Struct literals are refused: the fields are private.
//! let _ = Config { signers: BTreeMap::new(), approvers: BTreeMap::new(), deployments: vec![], grants: vec![] };
//! ```
//!
//! ```compile_fail
//! # fn demo(config: landfall_core::config::Config) {
//! let mut config = config;
//! // And a parsed configuration cannot be edited afterwards.
//! config.deployments().clear();
//! # }
//! ```

use std::collections::{BTreeMap, HashMap, HashSet};

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

mod raw;

use crate::ids::{DeploymentId, HostId, PrincipalId, RepoName, TagPattern};

/// Why a configuration file was refused. Every variant names the deployment
/// (or section) and the offending value.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum ConfigError {
    /// The text is not valid TOML, has an unknown key, or a value of the wrong type.
    #[error("configuration is not valid: {0}")]
    Toml(String),
    /// A field has a malformed value.
    #[error("deployment {deployment}: {field} {value:?} is invalid: {reason}")]
    Invalid {
        /// The deployment the value belongs to.
        deployment: String,
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
    /// Rule 2: an origin signer is not in `[signers]`.
    #[error("deployment {deployment}: origin signer {signer} is not in [signers]")]
    UnknownSigner {
        /// The deployment.
        deployment: DeploymentId,
        /// The unknown signer.
        signer: PrincipalId,
    },
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
        "deployment {deployment}: rule.approve = {approve:?} must be broader than rule.auto = {auto:?}"
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
    /// Rule 6: promotion chain loops back.
    #[error("deployment {0}: promote_to chain forms a cycle")]
    PromotionCycle(DeploymentId),
    /// Rule 7: a grant names a deployment that does not exist.
    #[error("grant for {principal}: deployment {deployment} does not exist")]
    UnknownGrantDeployment {
        /// The grant's principal.
        principal: PrincipalId,
        /// The missing deployment.
        deployment: DeploymentId,
    },
    /// Rule 7: `approve` granted to someone who is not an approver.
    #[error("grant for {principal}: can include \"approve\" but {principal} is not in [approvers]")]
    ApproveWithoutApprover {
        /// The grant's principal.
        principal: PrincipalId,
    },
    /// Rule 8: two deployments own the same compose service on one host.
    #[error(
        "deployment {deployment}: compose service {service:?} in {dir:?} on host {host} is already owned by {other}"
    )]
    DuplicateService {
        /// The later deployment.
        deployment: DeploymentId,
        /// The earlier deployment.
        other: DeploymentId,
        /// The host.
        host: HostId,
        /// The compose directory.
        dir: String,
        /// The compose service.
        service: String,
    },
}

/// A validated fleet configuration. It can only be obtained from [`parse`]
/// and has no mutators, so every value in it passed validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Trusted tag-signing keys, by name (SSH public key text).
    signers: BTreeMap<PrincipalId, String>,
    /// Passkey approvers, by name.
    approvers: BTreeMap<PrincipalId, Approver>,
    /// Every deployment, in file order.
    deployments: Vec<Deployment>,
    /// Who may do what.
    grants: Vec<Grant>,
}

impl Config {
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
    /// Trusted signers, each a key of `[signers]`; non-empty.
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

/// When a deploy may start.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    /// Deploy without a human up to this level.
    #[serde(default)]
    auto: Option<Level>,
    /// Deploy with an approval up to this level.
    #[serde(default)]
    approve: Option<Level>,
    /// Who may approve; non-empty, each a key of `[approvers]`.
    approvers: Vec<PrincipalId>,
    /// Whether prerelease versions are eligible.
    #[serde(default)]
    prereleases: bool,
}

/// A post-deploy check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Check {
    /// The container's Docker healthcheck reports healthy.
    ContainerHealthy,
    /// An HTTP probe on a Docker network.
    Http {
        /// Request path, starting with `/`.
        path: String,
        /// Docker network to probe from.
        network: String,
        /// Expected status code.
        expect: u16,
    },
    /// A command run in the container; exit 0 is healthy.
    Command {
        /// Program and arguments.
        argv: Vec<String>,
    },
    /// The logs must not match `pattern` for `within_secs` after the deploy.
    NoLogMatch {
        /// Pattern to look for.
        pattern: String,
        /// Observation window in seconds.
        within_secs: u32,
    },
}

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

/// A principal's permissions on some deployments.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
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
    signers: &BTreeMap<PrincipalId, String> => &c.signers,
    /// Passkey approvers, by name.
    approvers: &BTreeMap<PrincipalId, Approver> => &c.approvers,
    /// Every deployment, in file order.
    deployments: &[Deployment] => &c.deployments,
    /// Who may do what.
    grants: &[Grant] => &c.grants,
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
    /// Trusted signers; each exists in `[signers]`, never empty.
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
    /// On which deployments; all exist.
    deployments: &[DeploymentId] => &g.deployments,
    /// What they may do.
    can: &[Permission] => &g.can,
});

/// Lowercase hex SHA-256 of the raw file bytes; agents and the controller
/// compare these to detect configuration drift.
#[must_use]
pub fn config_hash(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    Sha256::digest(bytes)
        .iter()
        .flat_map(|b| {
            [
                char::from(HEX[usize::from(b >> 4)]),
                char::from(HEX[usize::from(b & 0x0f)]),
            ]
        })
        .collect()
}

/// Parses and validates a configuration file.
///
/// # Errors
///
/// [`ConfigError::Toml`] for syntax, unknown keys and wrongly typed values,
/// otherwise the variant of the first validation rule that fails.
pub fn parse(text: &str) -> Result<Config, ConfigError> {
    let config = raw::build(text)?;
    validate(&config)?;
    Ok(config)
}

/// Rules 2 to 6 for one deployment (the chain check in rule 6 is separate).
fn validate_deployment(config: &Config, d: &Deployment) -> Result<(), ConfigError> {
    // Rule 2.
    if d.origin.signers.is_empty() {
        return Err(ConfigError::NoSigners(d.id.clone()));
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
    // Rule 6, per deployment.
    if let Some(promotion) = &d.promote_to {
        if promotion.deployment == d.id {
            return Err(ConfigError::SelfPromotion(d.id.clone()));
        }
        if config.deployment(&promotion.deployment).is_none() {
            return Err(ConfigError::UnknownPromotion {
                deployment: d.id.clone(),
                target: promotion.deployment.clone(),
            });
        }
    }
    Ok(())
}

fn validate(config: &Config) -> Result<(), ConfigError> {
    let mut seen = HashSet::new();
    let mut services: HashMap<(&HostId, &str, &str), &DeploymentId> = HashMap::new();
    for d in &config.deployments {
        // Rule 1.
        if !seen.insert(&d.id) {
            return Err(ConfigError::DuplicateDeployment(d.id.clone()));
        }
        validate_deployment(config, d)?;
        // Rule 8.
        if let Some(other) = services.insert(
            (&d.host, d.compose.dir.as_str(), d.compose.service.as_str()),
            &d.id,
        ) {
            return Err(ConfigError::DuplicateService {
                deployment: d.id.clone(),
                other: other.clone(),
                host: d.host.clone(),
                dir: d.compose.dir.clone(),
                service: d.compose.service.clone(),
            });
        }
    }

    // Rule 6, chains: still promoting after more steps than there are
    // deployments means the chain loops.
    for d in &config.deployments {
        let mut current = d;
        for _ in 0..config.deployments.len() {
            match current
                .promote_to
                .as_ref()
                .and_then(|p| config.deployment(&p.deployment))
            {
                Some(next) => current = next,
                None => break,
            }
        }
        if current.promote_to.is_some() {
            return Err(ConfigError::PromotionCycle(d.id.clone()));
        }
    }

    // Rule 7.
    for grant in &config.grants {
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

#[cfg(test)]
mod tests {
    use super::*;

    const EXAMPLE: &str = r#"
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = [{ http = "/health", network = "app", expect = 200 }]
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

    fn edited(from: &str, to: &str) -> String {
        assert!(EXAMPLE.contains(from), "fixture lacks {from:?}");
        EXAMPLE.replacen(from, to, 1)
    }

    #[test]
    fn example_parses() {
        let config = parse(EXAMPLE).unwrap();
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
        let err = parse(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)));
        assert!(err.to_string().contains("rul"), "{err}");
    }

    #[test]
    fn each_validation_rule_is_enforced() {
        // 1: duplicate ids.
        let err = parse(&edited("id = \"app/staging\"", "id = \"app/prod\"")).unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateDeployment(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 2: unknown or empty origin signers.
        let err = parse(&edited(
            "signers = [\"maintainer\"]",
            "signers = [\"nobody\"]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownSigner { .. }), "{err}");
        assert!(err.to_string().contains("app/prod") && err.to_string().contains("nobody"));
        let err = parse(&edited("signers = [\"maintainer\"]", "signers = []")).unwrap_err();
        assert!(matches!(err, ConfigError::NoSigners(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 3: approvers always non-empty and known.
        let err = parse(&edited(
            "approvers = [\"operator\"] }\nchecks = [\"container",
            "approvers = [] }\nchecks = [\"container",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoApprovers(_)), "{err}");
        assert!(err.to_string().contains("app/staging"));
        let err = parse(&edited(
            "approve = \"minor\", approvers = [\"operator\"]",
            "approve = \"minor\", approvers = [\"ghost\"]",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownApprover { .. }), "{err}");
        assert!(err.to_string().contains("app/prod") && err.to_string().contains("ghost"));

        // 4: approve must be broader than auto.
        let err = parse(&edited("approve = \"minor\"", "approve = \"patch\"")).unwrap_err();
        assert!(
            matches!(err, ConfigError::ApproveNotBroader { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("app/prod"));

        // 5: checks non-empty.
        let err = parse(&edited(
            "checks = [{ http = \"/health\", network = \"app\", expect = 200 }]",
            "checks = []",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::NoChecks(_)), "{err}");
        assert!(err.to_string().contains("app/prod"));

        // 6: promotion target unknown, itself, or a cycle.
        let err = parse(&edited(
            "deployment = \"app/prod\", healthy_for",
            "deployment = \"app/none\", healthy_for",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::UnknownPromotion { .. }), "{err}");
        assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/none"));
        let err = parse(&edited(
            "deployment = \"app/prod\", healthy_for",
            "deployment = \"app/staging\", healthy_for",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::SelfPromotion(_)), "{err}");
        assert!(err.to_string().contains("app/staging"));
        let cyclic = edited(
            "checks = [{ http = \"/health\", network = \"app\", expect = 200 }]",
            "checks = [\"container-healthy\"]\npromote_to = { deployment = \"app/staging\", healthy_for = \"1h\" }",
        );
        let err = parse(&cyclic).unwrap_err();
        assert!(matches!(err, ConfigError::PromotionCycle(_)), "{err}");
        assert!(err.to_string().contains("app/"));

        // 7: grants.
        let err = parse(&edited(
            "deployments = [\"app/prod\", \"app/staging\"]",
            "deployments = [\"app/none\"]",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::UnknownGrantDeployment { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("app/none") && err.to_string().contains("operator"));
        let err = parse(&edited(
            "principal = \"operator\"",
            "principal = \"maintainer\"",
        ))
        .unwrap_err();
        assert!(
            matches!(err, ConfigError::ApproveWithoutApprover { .. }),
            "{err}"
        );
        assert!(err.to_string().contains("maintainer"));

        // 8: one service per host, compose dir and service.
        let err = parse(&edited(
            "dir = \"/srv/compose/app-staging\"",
            "dir = \"/srv/compose/app\"",
        ))
        .unwrap_err();
        assert!(matches!(err, ConfigError::DuplicateService { .. }), "{err}");
        assert!(err.to_string().contains("app/staging") && err.to_string().contains("app/prod"));
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
            let err = parse(&edited(from, to)).unwrap_err();
            assert!(matches!(err, ConfigError::Invalid { .. }), "{to}: {err}");
            assert!(err.to_string().contains("app/"), "{err}");
        }
    }

    #[test]
    fn durations_use_minutes_hours_days() {
        for (text, secs) in [("90m", 5_400), ("2h", 7_200), ("1d", 86_400)] {
            let config = parse(&edited(
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
        let all = "checks = [\"container-healthy\", { http = \"/health\", network = \"app\", expect = 200 }, { command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"panicked\", within_secs = 30 }]";
        let config = parse(&edited("checks = [\"container-healthy\"]", all)).unwrap();
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(
            staging.checks(),
            vec![
                Check::ContainerHealthy,
                Check::Http {
                    path: "/health".into(),
                    network: "app".into(),
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
            assert!(parse(&text).is_err(), "{bad} should be refused");
        }
    }

    #[test]
    fn config_hash_is_sha256_hex() {
        assert_eq!(
            config_hash(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn unknown_key_in_a_check_table_is_named() {
        let text = edited(
            "checks = [\"container-healthy\"]",
            "checks = [{ http = \"/h\", netwrok = \"app\", expect = 200 }]",
        );
        let err = parse(&text).unwrap_err();
        assert!(matches!(err, ConfigError::Toml(_)), "{err}");
        assert!(err.to_string().contains("netwrok"), "{err}");
    }

    #[test]
    fn check_errors_name_the_entry_and_the_keys() {
        let text = edited(
            "checks = [\"container-healthy\"]",
            "checks = [\"container-healthy\", \"container-healthy\", { http = \"/h\", command = [\"x\"] }]",
        );
        let err = parse(&text).unwrap_err().to_string();
        assert!(err.contains("app/staging"), "{err}");
        assert!(err.contains("checks[2]"), "{err}");
        assert!(err.contains("http") && err.contains("command"), "{err}");
        assert!(!err.contains("{...}"), "{err}");

        let text = edited("checks = [\"container-healthy\"]", "checks = [\"healthy\"]");
        let err = parse(&text).unwrap_err().to_string();
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
            let err = parse(&text).unwrap_err();
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
                matches!(parse(&text), Err(ConfigError::Invalid { .. })),
                "{path}"
            );
        }
    }
}
