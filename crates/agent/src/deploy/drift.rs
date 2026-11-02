//! Whether a service's running image still matches its override.

use std::path::Path;
use std::time::Duration;

use serde::Serialize;

use super::files::read_override_file;
use super::{FileFailure, on_thread_within};
use crate::checks::quote;
use crate::compose::{self, Pin};
use crate::docker::{Docker, DockerError};
use crate::safefs::SafeFsError;

/// What the override file in a compose directory is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum OverrideFile {
    /// There is none.
    Missing,
    /// The placeholder: nothing is pinned yet.
    Placeholder,
    /// It pins the service's image.
    Pinned,
    /// It is not one the agent wrote for this service.
    Unrecognised,
}

/// How a service's running image compares with its override.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Drift {
    /// What the override file is.
    pub override_file: OverrideFile,
    /// The running container's image, only if it is the one pinned, quoted and
    /// truncated. Any other image can come from interpolated configuration
    /// (`image: ${IMG}`) and hold a secret, so it is not repeated.
    pub running_image: Option<String>,
    /// Whether the running container runs the pinned image. `None` when the
    /// service has no running container.
    pub running_image_matches: Option<bool>,
    /// Whether a running container differs from the override (design 7.1): it
    /// runs another image than the one pinned, the file isn't the agent's to go
    /// by, or the file is gone while a deploy is on record. With nothing pinned
    /// and nothing on record there is nothing to differ from, and a service
    /// that isn't running has not drifted: stopping one is an operator's call,
    /// and a deploy in progress stops it too.
    pub drift: bool,
}

/// Why a service's drift could not be read.
#[derive(Debug, thiserror::Error)]
pub enum DriftError {
    /// The compose directory or the override can't be read.
    #[error("reading the override: {0}")]
    Override(#[from] SafeFsError),
    /// Reading the override did not finish.
    #[error("reading the override: {0}")]
    File(#[source] FileFailure),
    /// Docker could not say what is running.
    #[error(transparent)]
    Docker(#[from] DockerError),
}

/// How long reading the override may take.
const DRIFT_READ_LIMIT: Duration = Duration::from_secs(60);

/// Compares the running image of `service` with what the override in `dir`
/// pins; `recorded` says a deploy of it is on record. It goes by the file itself
/// and by the container's labels, without `docker compose`: what `.env` makes of the project is exactly what can have
/// strayed from the override, and a stack the agent's user cannot read can
/// still be reported on. A caller that also sees a deploy in progress knows
/// that a difference is expected then.
///
/// # Errors
///
/// [`DriftError`] when the override or the container cannot be read.
pub async fn drift<D: Docker>(
    docker: &D,
    dir: &Path,
    service: &str,
    recorded: bool,
) -> Result<Drift, DriftError> {
    let owned = dir.to_owned();
    let file = on_thread_within(DRIFT_READ_LIMIT, move || read_override_file(&owned))
        .await
        .map_err(|unfinished| {
            DriftError::File(unfinished.failure("read override", DRIFT_READ_LIMIT))
        })??;
    let pin = file
        .as_deref()
        .map(|file| compose::pinned_image(file, service));
    let override_file = match pin {
        None => OverrideFile::Missing,
        Some(Pin::Nothing) => OverrideFile::Placeholder,
        Some(Pin::Image(_)) => OverrideFile::Pinned,
        Some(Pin::Unrecognised) => OverrideFile::Unrecognised,
    };
    let Some(id) = docker.container_at(dir, service).await? else {
        return Ok(Drift {
            override_file,
            running_image: None,
            running_image_matches: None,
            drift: false,
        });
    };
    let running = docker.inspect(&id).await?.image;
    let matches = matches!(pin, Some(Pin::Image(pinned)) if pinned == running);
    let drift = match pin {
        None => recorded,
        Some(Pin::Nothing) => false,
        Some(Pin::Image(_)) => !matches,
        Some(Pin::Unrecognised) => true,
    };
    Ok(Drift {
        override_file,
        running_image: matches.then(|| quote(&running)),
        running_image_matches: Some(matches),
        drift,
    })
}
