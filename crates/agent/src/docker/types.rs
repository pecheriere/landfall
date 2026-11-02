//! What the driver reports about containers and services.

use std::collections::BTreeMap;
use std::fmt;
use std::net::IpAddr;
use std::str::FromStr;

use jiff::Timestamp;

/// A container id: 12 to 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerId(String);

/// The text is not a container id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a container id: expected 12 to 64 lowercase hex digits")]
pub struct ContainerIdError;

impl FromStr for ContainerId {
    type Err = ContainerIdError;

    fn from_str(s: &str) -> Result<Self, ContainerIdError> {
        let ok = (12..=64).contains(&s.len())
            && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ContainerIdError)
        }
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ContainerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// What the agent reads of a service in the resolved compose project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// The image the project resolves to, if the service has one.
    pub image: Option<String>,
    /// Whether the service has a `build` section (refused by the agent).
    pub has_build: bool,
    /// How many containers the project asks for: `scale` or `deploy.replicas`,
    /// whichever is not 1 if one isn't, and 1 with neither.
    pub replicas: u64,
}

/// What the agent reads of a container; its environment is not among it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// `.Config.Image`: the image reference the container was created with.
    pub image: String,
    /// `.State.Status`: `running`, `exited`, ...
    pub status: String,
    /// `.State.Health.Status`, absent without a healthcheck.
    pub health: Option<String>,
    /// When the container last started.
    pub started_at: Timestamp,
    /// Attached networks and the container's IP on each, if it has one.
    pub networks: BTreeMap<String, Option<IpAddr>>,
}

/// What the agent reads of a container that has the service's name, in whichever
/// project. The names of other projects stay out of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceContainer {
    /// The container.
    pub id: ContainerId,
    /// Whether it is up, as `docker ps` without `--all` counts it: a paused or
    /// restarting one is. A state not known to mean down counts as up.
    pub running: bool,
    /// Whether it has the project's name.
    pub in_project: bool,
    /// The working directory compose labelled it with, as the label spells it;
    /// `None` without that label. Whoever started the container chose it: it
    /// is quoted wherever it is shown.
    pub working_dir: Option<String>,
}
