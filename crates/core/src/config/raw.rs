//! Raw deserialisation structs and their conversion into the public types.
//!
//! Everything here is private to the configuration module: the public types
//! have private fields, so this is the only place that builds them, and
//! [`super::parse`] validates the result before anyone sees it.

use std::collections::BTreeMap;
use std::fmt;
use std::str::FromStr;

use serde::de::value::MapAccessDeserializer;
use serde::de::{self, MapAccess, Visitor};
use serde::{Deserialize, Deserializer};

use super::{
    Approver, Backup, Check, Compose, Config, ConfigError, Deployment, Grant, Origin, Promotion,
    Repo, Rule,
};
use crate::ids::{DeploymentId, HostId, PrincipalId, TagPattern};

/// Parses the text into a [`Config`] that is not validated yet.
pub(super) fn build(text: &str) -> Result<Config, ConfigError> {
    let raw: RawConfig = toml::from_str(text).map_err(|e| ConfigError::Toml(e.to_string()))?;
    let deployments = raw
        .deployments
        .into_iter()
        .map(convert_deployment)
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Config {
        signers: raw.signers,
        approvers: raw.approvers,
        deployments,
        grants: raw.grants,
    })
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

enum RawCheck {
    Named(String),
    Table(RawCheckTable),
}

/// Hand-written so that an unknown key inside a check table is reported by
/// name, which an untagged enum cannot do.
impl<'de> Deserialize<'de> for RawCheck {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct CheckVisitor;

        impl<'de> Visitor<'de> for CheckVisitor {
            type Value = RawCheck;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(
                    "\"container-healthy\" or a table with one of http, command, no_log_match",
                )
            }

            fn visit_str<E: de::Error>(self, name: &str) -> Result<RawCheck, E> {
                Ok(RawCheck::Named(name.to_owned()))
            }

            fn visit_map<A: MapAccess<'de>>(self, map: A) -> Result<RawCheck, A::Error> {
                RawCheckTable::deserialize(MapAccessDeserializer::new(map)).map(RawCheck::Table)
            }
        }

        deserializer.deserialize_any(CheckVisitor)
    }
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

fn invalid(
    deployment: &DeploymentId,
    field: &str,
    value: &str,
    reason: &'static str,
) -> ConfigError {
    ConfigError::Invalid {
        deployment: deployment.to_string(),
        field: field.to_owned(),
        value: value.to_owned(),
        reason,
    }
}

/// Whether `path` is a canonical relative path: non-empty components, none
/// of them `.` or `..`. A trailing, leading or doubled `/` shows up as an
/// empty component, so two spellings of one path cannot both pass.
fn is_canonical_relative(path: &str) -> bool {
    path.split('/')
        .all(|part| !part.is_empty() && part != "." && part != "..")
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
    if !compose
        .dir
        .strip_prefix('/')
        .is_some_and(is_canonical_relative)
    {
        return Err(invalid(
            &id,
            "compose.dir",
            &compose.dir,
            "must be an absolute canonical path: no trailing or doubled '/', no '.' or '..' components",
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
        || !is_canonical_relative(&workflow)
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
        .enumerate()
        .map(|(index, check)| convert_check(&id, index, check))
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
                .find(|p| !is_canonical_relative(p))
            {
                return Err(invalid(
                    &id,
                    "backup.paths",
                    path,
                    "must be a canonical relative path: no leading, trailing or doubled '/', no '.' or '..' components",
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

fn convert_check(id: &DeploymentId, index: usize, raw: RawCheck) -> Result<Check, ConfigError> {
    let field = format!("checks[{index}]");
    let table = match raw {
        RawCheck::Named(name) if name == "container-healthy" => {
            return Ok(Check::ContainerHealthy);
        }
        RawCheck::Named(name) => {
            return Err(invalid(
                id,
                &field,
                &name,
                "unknown check name; the only string form is \"container-healthy\"",
            ));
        }
        RawCheck::Table(table) => table,
    };
    let keys = table.keys();
    let bad = |reason| invalid(id, &field, &keys, reason);
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

impl RawCheckTable {
    /// The keys that are set, for error messages.
    fn keys(&self) -> String {
        let mut keys = Vec::new();
        for (key, set) in [
            ("http", self.http.is_some()),
            ("network", self.network.is_some()),
            ("expect", self.expect.is_some()),
            ("command", self.command.is_some()),
            ("no_log_match", self.no_log_match.is_some()),
            ("within_secs", self.within_secs.is_some()),
        ] {
            if set {
                keys.push(key);
            }
        }
        if keys.is_empty() {
            "{}".to_owned()
        } else {
            format!("{{ {} }}", keys.join(", "))
        }
    }
}
