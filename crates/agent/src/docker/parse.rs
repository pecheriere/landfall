//! Reading the JSON `docker` prints, keeping out what may hold a secret.

use std::collections::BTreeMap;
use std::net::IpAddr;

use jiff::Timestamp;
use serde::Deserialize;
use serde::de::IgnoredAny;

use super::{
    ContainerId, ContainerIdError, ContainerInfo, DockerError, ServiceConfig, ServiceContainer,
};

/// The only parts of `docker compose config --format json` that are read.
/// Every other field, secrets included, is skipped without being kept.
#[derive(Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    services: BTreeMap<String, ServiceDoc>,
}

#[derive(Deserialize)]
struct ServiceDoc {
    image: Option<String>,
    build: Option<IgnoredAny>,
    scale: Option<u64>,
    deploy: Option<DeployDoc>,
}

#[derive(Deserialize)]
struct DeployDoc {
    replicas: Option<u64>,
}

/// Reads `service` out of `docker compose config --format json`. Errors say
/// nothing about the input, which holds secrets.
pub(super) fn parse_config(raw: &[u8], service: &str) -> Result<ServiceConfig, DockerError> {
    let doc: ConfigDoc = serde_json::from_slice(raw).map_err(|_| DockerError::BadOutput {
        command: "docker compose config",
        reason: "not the expected JSON",
    })?;
    let svc = doc
        .services
        .get(service)
        .ok_or_else(|| DockerError::NoSuchService {
            service: service.to_owned(),
        })?;
    Ok(ServiceConfig {
        image: svc.image.clone(),
        has_build: svc.build.is_some(),
        replicas: svc
            .scale
            .into_iter()
            .chain(svc.deploy.as_ref().and_then(|deploy| deploy.replicas))
            .find(|asked| *asked != 1)
            .unwrap_or(1),
    })
}

/// The project's name out of `docker compose config --format json`. As in
/// [`parse_config`], errors say nothing about the input.
pub(super) fn parse_project_name(raw: &[u8]) -> Result<String, DockerError> {
    #[derive(Deserialize)]
    struct NameDoc {
        name: Option<String>,
    }
    const LABEL: &str = "docker compose config";
    let doc: NameDoc = serde_json::from_slice(raw).map_err(|_| DockerError::BadOutput {
        command: LABEL,
        reason: "not the expected JSON",
    })?;
    doc.name
        .filter(|name| !name.is_empty())
        .ok_or(DockerError::BadOutput {
            command: LABEL,
            reason: "the project has no name",
        })
}

/// `docker inspect --format INSPECT_FORMAT`, as emitted.
#[derive(Deserialize)]
struct InspectDoc {
    image: String,
    status: String,
    health: Option<String>,
    started_at: String,
    networks: Vec<Option<(String, String, String)>>,
}

fn bad_inspect(reason: &'static str) -> DockerError {
    DockerError::BadOutput {
        command: "docker inspect",
        reason,
    }
}

pub(super) fn parse_inspect(raw: &[u8]) -> Result<ContainerInfo, DockerError> {
    let doc: InspectDoc =
        serde_json::from_slice(raw).map_err(|_| bad_inspect("not the expected JSON"))?;
    let started_at = doc
        .started_at
        .parse::<Timestamp>()
        .map_err(|_| bad_inspect("unreadable start time"))?;
    let mut networks = BTreeMap::new();
    for (name, v4, v6) in doc.networks.into_iter().flatten() {
        // Docker keeps the IPv4 and the global IPv6 address apart: IPv4
        // wins when both are there.
        let address = if v4.is_empty() { v6 } else { v4 };
        let ip = if address.is_empty() {
            None
        } else {
            Some(
                address
                    .parse::<IpAddr>()
                    .map_err(|_| bad_inspect("unreadable network address"))?,
            )
        };
        networks.insert(name, ip);
    }
    Ok(ContainerInfo {
        image: doc.image,
        status: doc.status,
        health: doc.health,
        started_at,
        networks,
    })
}

/// Reads `docker ps --format SERVICE_CONTAINER_FORMAT`, one container per line.
/// Errors quote nothing: labels are anyone's who can start a container.
pub(super) fn parse_service_containers(
    raw: &[u8],
    project: &str,
) -> Result<Vec<ServiceContainer>, DockerError> {
    let bad = |reason| DockerError::BadOutput {
        command: "docker ps",
        reason,
    };
    let text = std::str::from_utf8(raw).map_err(|_| bad("not UTF-8"))?;
    text.lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let (id, state, in_project, working_dir): (String, String, String, String) =
                serde_json::from_str(line).map_err(|_| bad("not the expected JSON"))?;
            Ok(ServiceContainer {
                id: id
                    .parse()
                    .map_err(|_: ContainerIdError| bad("not a container id"))?,
                running: !matches!(state.as_str(), "exited" | "created" | "dead" | "removing"),
                in_project: in_project == project,
                working_dir: Some(working_dir).filter(|dir| !dir.is_empty()),
            })
        })
        .collect()
}

pub(super) fn parse_container(raw: &[u8]) -> Result<Option<ContainerId>, DockerError> {
    let text = std::str::from_utf8(raw).map_err(|_| DockerError::BadOutput {
        command: "docker ps",
        reason: "not UTF-8",
    })?;
    let mut ids = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(first) = ids.next() else {
        return Ok(None);
    };
    if ids.next().is_some() {
        return Err(DockerError::SeveralContainers {
            command: "docker ps",
        });
    }
    first
        .parse()
        .map(Some)
        .map_err(|_: ContainerIdError| DockerError::BadOutput {
            command: "docker ps",
            reason: "not a container id",
        })
}
