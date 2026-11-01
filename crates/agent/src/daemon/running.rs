//! What the controller is told about this host: the marker, the record and the
//! drift of each of its deployments, and whether the daemon is running a deploy.

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Instant;

use landfall_core::config::{Config, Deployment};
use landfall_core::ids::DeploymentId;
use landfall_core::protocol::{DeployedRelease, HeldBack, Phase, RunningState, WorkRequest};
use serde::Serialize;

use super::{DaemonOptions, deployment_state, on_thread};
use crate::deploy;
use crate::docker::Docker;
use crate::journal::{self, Priority};

#[derive(Debug, Clone, Copy)]
struct SeenDrift {
    drifted: bool,
    at: Instant,
}

/// What the daemon remembers from one step to the next.
#[derive(Debug, Default)]
pub(super) struct Memory {
    drift: Mutex<BTreeMap<DeploymentId, SeenDrift>>,
    pub(super) held_back: Mutex<Vec<HeldBack>>,
}

pub(super) fn locked<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

impl Memory {
    /// What runs has changed: the next request looks again.
    pub(super) fn forget_drift(&self, id: &DeploymentId) {
        locked(&self.drift).remove(id);
    }
}

fn wire_phase(phase: crate::state::Phase) -> Phase {
    match phase {
        crate::state::Phase::Preflight => Phase::Preflight,
        crate::state::Phase::Deploying => Phase::Deploying,
        crate::state::Phase::RollingBack => Phase::RollingBack,
        crate::state::Phase::Restored => Phase::Restored,
        crate::state::Phase::RolledBack => Phase::RolledBack,
    }
}

/// Looks at a deployment's drift now and remembers it. One that can't be read
/// counts as drifted, so that no deploy goes by a guess.
pub(super) async fn fresh_drift<D: Docker>(
    docker: &D,
    deployment: &Deployment,
    dir: &Path,
    recorded: bool,
    options: &DaemonOptions,
) -> Result<bool, String> {
    #[derive(Serialize)]
    struct DriftChanged<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        drift: bool,
        error: Option<&'a str>,
    }
    let service = deployment.compose().service();
    let seen = deploy::drift(docker, dir, service, recorded)
        .await
        .map(|drift| drift.drift)
        .map_err(|error| error.to_string());
    let drifted = seen.as_ref().map_or(true, |drifted| *drifted);
    let before = locked(&options.memory.drift).insert(
        deployment.id().clone(),
        SeenDrift {
            drifted,
            at: Instant::now(),
        },
    );
    if before.map_or(drifted, |seen| seen.drifted != drifted) {
        journal::emit(
            if drifted {
                Priority::Warning
            } else {
                Priority::Info
            },
            &DriftChanged {
                event: "drift_changed",
                deployment: deployment.id(),
                drift: drifted,
                error: seen.as_ref().err().map(String::as_str),
            },
        );
    }
    seen
}

/// One deployment as the host sees it now.
async fn running_state<D: Docker>(
    docker: &D,
    deployment: &Deployment,
    dir: &Path,
    state_dir: &Path,
    options: &DaemonOptions,
    deploying: Option<&DeploymentId>,
) -> RunningState {
    #[derive(Serialize)]
    struct Unreadable<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        error: &'a str,
    }
    let id = deployment.id();
    let busy = deploying == Some(id);
    let (root, owned) = (state_dir.to_owned(), id.clone());
    let read = on_thread("read state", move || {
        let state = deployment_state(&root, &owned)?;
        Ok((state.deployed()?, state.in_progress()?))
    })
    .await;
    let (deployed, marker) = match read {
        Ok(read) => read,
        Err(error) => {
            journal::emit(
                Priority::Critical,
                &Unreadable {
                    event: "state_unreadable",
                    deployment: id,
                    error: &error,
                },
            );
            // The wire has no word for this. The closest true thing: something
            // is off here, and nothing may be deployed to it.
            return RunningState {
                deployment: id.clone(),
                deployed: None,
                drift: true,
                phase: Phase::Deploying,
                busy,
            };
        }
    };
    let remembered = locked(&options.memory.drift).get(id).copied();
    let drift = match remembered {
        // A deploy changes what runs: its drift is looked at when it is done.
        _ if busy => remembered.is_some_and(|seen| seen.drifted),
        Some(seen) if seen.at.elapsed() < options.drift_every => seen.drifted,
        _ => fresh_drift(docker, deployment, dir, deployed.is_some(), options)
            .await
            .unwrap_or(true),
    };
    RunningState {
        deployment: id.clone(),
        deployed: deployed.map(|deployed| DeployedRelease {
            tag: deployed.tag,
            digest: deployed.digest,
        }),
        drift,
        phase: marker.map_or(Phase::Idle, |marker| wire_phase(marker.phase)),
        busy,
    }
}

/// A work request listing every deployment of this host.
pub(super) async fn work_request<D: Docker>(
    docker: &D,
    config: &Config,
    state_dir: &Path,
    options: &DaemonOptions,
    deploying: Option<&DeploymentId>,
) -> WorkRequest {
    let mut running = Vec::with_capacity(options.dirs.len());
    for (id, dir) in &options.dirs {
        if let Some(deployment) = config.deployment(id) {
            running
                .push(running_state(docker, deployment, dir, state_dir, options, deploying).await);
        }
    }
    WorkRequest {
        config_hash: options.config_hash,
        running,
    }
}
