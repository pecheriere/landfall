//! Fleet configuration: one TOML file per fleet.
//!
//! The file is deserialised into private raw structs (every one with
//! `deny_unknown_fields`, so a typo is an error), then converted and validated
//! into the public types. A [`Config`] therefore only exists validated.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::str::FromStr;

use serde::Deserialize;
use sha2::{Digest, Sha256};
use thiserror::Error;

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
        field: &'static str,
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

/// A validated fleet configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Trusted tag-signing keys, by name (SSH public key text).
    pub signers: BTreeMap<PrincipalId, String>,
    /// Passkey approvers, by name.
    pub approvers: BTreeMap<PrincipalId, Approver>,
    /// Every deployment, in file order.
    pub deployments: Vec<Deployment>,
    /// Who may do what.
    pub grants: Vec<Grant>,
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
    pub credential_id: String,
    /// COSE public key.
    pub public_key: String,
}

/// One deployed service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Deployment {
    /// `<name>/<stage>`.
    pub id: DeploymentId,
    /// The source repository.
    pub repo: Repo,
    /// The host it runs on.
    pub host: HostId,
    /// Where its compose project lives.
    pub compose: Compose,
    /// Which releases are trusted.
    pub origin: Origin,
    /// When a deploy may start.
    pub rule: Rule,
    /// Post-deploy checks, at least one.
    pub checks: Vec<Check>,
    /// Backup taken before a deploy.
    pub backup: Option<Backup>,
    /// Promotion to another deployment once healthy.
    pub promote_to: Option<Promotion>,
}

/// A GitHub repository, pinned by immutable ids as well as name.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Repo {
    /// `<owner>/<repo>`.
    pub name: RepoName,
    /// GitHub repository id.
    pub id: u64,
    /// GitHub owner id.
    pub owner_id: u64,
}

/// A compose service on the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Compose {
    /// Absolute directory of the compose project, without `..`.
    pub dir: String,
    /// Service name, `[a-z0-9][a-z0-9_.-]*`.
    pub service: String,
}

/// Where a release must come from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Origin {
    /// Release workflow path under `.github/workflows/`.
    pub workflow: String,
    /// Which tags are releases.
    pub tags: TagPattern,
    /// Trusted signers, each a key of `[signers]`; non-empty.
    pub signers: Vec<PrincipalId>,
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
    pub auto: Option<Level>,
    /// Deploy with an approval up to this level.
    #[serde(default)]
    pub approve: Option<Level>,
    /// Who may approve; non-empty, each a key of `[approvers]`.
    pub approvers: Vec<PrincipalId>,
    /// Whether prerelease versions are eligible.
    #[serde(default)]
    pub prereleases: bool,
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
    pub paths: Vec<String>,
    /// Stop the service while copying (default true).
    pub stop: bool,
}

/// Promote to another deployment once healthy long enough.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Promotion {
    /// The deployment promoted to.
    pub deployment: DeploymentId,
    /// How long this one must stay healthy, in seconds.
    pub healthy_for_secs: u64,
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
    pub principal: PrincipalId,
    /// On which deployments.
    pub deployments: Vec<DeploymentId>,
    /// What they may do.
    pub can: Vec<Permission>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    #[serde(default)]
    signers: BTreeMap<PrincipalId, String>,
    #[serde(default)]
    approvers: BTreeMap<PrincipalId, Approver>,
    #[serde(default, rename = "deployment")]
    deployments: Vec<RawDeployment>,
    #[serde(default, rename = "grant")]
    grants: Vec<Grant>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawDeployment {
    id: DeploymentId,
    repo: Repo,
    host: HostId,
    compose: RawCompose,
    origin: RawOrigin,
    rule: Rule,
    checks: Vec<RawCheck>,
    #[serde(default)]
    backup: Option<RawBackup>,
    #[serde(default)]
    promote_to: Option<RawPromotion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCompose {
    dir: String,
    service: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawOrigin {
    workflow: String,
    tags: TagPattern,
    signers: Vec<PrincipalId>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RawCheck {
    Named(String),
    Table(RawCheckTable),
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCheckTable {
    http: Option<String>,
    network: Option<String>,
    expect: Option<u16>,
    command: Option<Vec<String>>,
    no_log_match: Option<String>,
    within_secs: Option<u32>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawBackup {
    paths: Vec<String>,
    #[serde(default = "default_true")]
    stop: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawPromotion {
    deployment: DeploymentId,
    healthy_for: String,
}

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
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
    let deployments = raw
        .deployments
        .into_iter()
        .map(convert_deployment)
        .collect::<Result<Vec<_>, _>>()?;
    let config = Config {
        signers: raw.signers,
        approvers: raw.approvers,
        deployments,
        grants: raw.grants,
    };
    validate(&config)?;
    Ok(config)
}

fn invalid(
    deployment: &DeploymentId,
    field: &'static str,
    value: &str,
    reason: &'static str,
) -> ConfigError {
    ConfigError::Invalid {
        deployment: deployment.to_string(),
        field,
        value: value.to_owned(),
        reason,
    }
}

/// Whether `path` has a `..` component.
fn has_parent_component(path: &str) -> bool {
    path.split('/').any(|part| part == "..")
}

fn is_service_name(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes
        .first()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        && bytes.iter().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'.' | b'-')
        })
}

fn convert_deployment(raw: RawDeployment) -> Result<Deployment, ConfigError> {
    let id = raw.id;

    let compose = raw.compose;
    if !compose.dir.starts_with('/') || has_parent_component(&compose.dir) {
        return Err(invalid(
            &id,
            "compose.dir",
            &compose.dir,
            "must be an absolute path without '..'",
        ));
    }
    if !is_service_name(&compose.service) {
        return Err(invalid(
            &id,
            "compose.service",
            &compose.service,
            "must match [a-z0-9][a-z0-9_.-]*",
        ));
    }

    let workflow = raw.origin.workflow;
    if !workflow.starts_with(".github/workflows/")
        || !matches!(workflow.rsplit_once('.'), Some((_, "yml" | "yaml")))
        || has_parent_component(&workflow)
    {
        return Err(invalid(
            &id,
            "origin.workflow",
            &workflow,
            "must be .github/workflows/<name>.yml or .yaml without '..'",
        ));
    }

    let checks = raw
        .checks
        .into_iter()
        .map(|check| convert_check(&id, check))
        .collect::<Result<Vec<_>, _>>()?;

    let backup = raw
        .backup
        .map(|backup| {
            if backup.paths.is_empty() {
                return Err(invalid(&id, "backup.paths", "[]", "must not be empty"));
            }
            if let Some(path) = backup
                .paths
                .iter()
                .find(|p| p.is_empty() || p.starts_with('/') || has_parent_component(p))
            {
                return Err(invalid(
                    &id,
                    "backup.paths",
                    path,
                    "must be a relative path without '..'",
                ));
            }
            Ok(Backup {
                paths: backup.paths,
                stop: backup.stop,
            })
        })
        .transpose()?;

    let promote_to = raw
        .promote_to
        .map(|promotion| {
            let healthy_for_secs = parse_duration(&promotion.healthy_for).ok_or_else(|| {
                invalid(
                    &id,
                    "promote_to.healthy_for",
                    &promotion.healthy_for,
                    "must be <n>m, <n>h or <n>d with n above zero",
                )
            })?;
            Ok(Promotion {
                deployment: promotion.deployment,
                healthy_for_secs,
            })
        })
        .transpose()?;

    Ok(Deployment {
        id,
        repo: raw.repo,
        host: raw.host,
        compose: Compose {
            dir: compose.dir,
            service: compose.service,
        },
        origin: Origin {
            workflow,
            tags: raw.origin.tags,
            signers: raw.origin.signers,
        },
        rule: raw.rule,
        checks,
        backup,
        promote_to,
    })
}

/// `<n>m`, `<n>h` or `<n>d` with `n` above zero, in seconds.
fn parse_duration(text: &str) -> Option<u64> {
    let unit = match text.chars().last()? {
        'm' => 60,
        'h' => 3_600,
        'd' => 86_400,
        _ => return None,
    };
    let digits = &text[..text.len() - 1];
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    u64::from_str(digits)
        .ok()
        .filter(|n| *n > 0)
        .and_then(|n| n.checked_mul(unit))
}

fn convert_check(id: &DeploymentId, raw: RawCheck) -> Result<Check, ConfigError> {
    let table = match raw {
        RawCheck::Named(name) if name == "container-healthy" => {
            return Ok(Check::ContainerHealthy);
        }
        RawCheck::Named(name) => {
            return Err(invalid(id, "checks", &name, "unknown check name"));
        }
        RawCheck::Table(table) => table,
    };
    let bad = |reason| invalid(id, "checks", "{...}", reason);
    match table {
        RawCheckTable {
            http: Some(path),
            network: Some(network),
            expect: Some(expect),
            command: None,
            no_log_match: None,
            within_secs: None,
        } => {
            if !path.starts_with('/') || network.is_empty() {
                return Err(bad("http needs a path starting with '/' and a network"));
            }
            Ok(Check::Http {
                path,
                network,
                expect,
            })
        }
        RawCheckTable {
            http: None,
            network: None,
            expect: None,
            command: Some(argv),
            no_log_match: None,
            within_secs: None,
        } => {
            if argv.first().is_none_or(String::is_empty) {
                return Err(bad("command needs a non-empty argv"));
            }
            Ok(Check::Command { argv })
        }
        RawCheckTable {
            http: None,
            network: None,
            expect: None,
            command: None,
            no_log_match: Some(pattern),
            within_secs: Some(within_secs),
        } => {
            if pattern.is_empty() || within_secs == 0 {
                return Err(bad(
                    "no_log_match needs a pattern and within_secs above zero",
                ));
            }
            Ok(Check::NoLogMatch {
                pattern,
                within_secs,
            })
        }
        _ => Err(bad(
            "must set exactly one of http (with network, expect), command, or no_log_match (with within_secs)",
        )),
    }
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
        assert_eq!(prod.rule.auto, Some(Level::Patch));
        assert_eq!(prod.rule.approve, Some(Level::Minor));
        assert!(!prod.rule.prereleases);
        assert_eq!(prod.compose.service, "app");
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(
            staging.promote_to.as_ref().unwrap().healthy_for_secs,
            86_400
        );
        let host: HostId = "home-1".parse().unwrap();
        assert_eq!(config.deployments_for_host(&host).count(), 2);
        let other: HostId = "home-2".parse().unwrap();
        assert_eq!(config.deployments_for_host(&other).count(), 0);
        assert_eq!(config.grants[0].can.len(), 4);
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
            assert_eq!(staging.promote_to.as_ref().unwrap().healthy_for_secs, secs);
        }
    }

    #[test]
    fn checks_parse_in_both_forms() {
        let all = "checks = [\"container-healthy\", { http = \"/health\", network = \"app\", expect = 200 }, { command = [\"/app\", \"healthcheck\"] }, { no_log_match = \"panicked\", within_secs = 30 }]";
        let config = parse(&edited("checks = [\"container-healthy\"]", all)).unwrap();
        let staging = config.deployment(&id("app/staging")).unwrap();
        assert_eq!(
            staging.checks,
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
}
