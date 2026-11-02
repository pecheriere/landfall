//! Finishing a deploy that was interrupted.

use std::path::Path;
use std::sync::atomic::AtomicBool;

use landfall_core::config::Deployment;

use super::rollback::rolled_back;
use super::sequence::{journal_refusal, take_lock};
use super::{DeployError, DeployReport, Engine, EngineOptions, Outcome, Recorder};
use crate::docker::Docker;
use crate::state::{DeploymentState, Phase};

/// Finishes an interrupted deploy, going by the [`Phase`] of its marker:
///
/// - [`Phase::Preflight`]: the service was never touched, so the previous
///   override is put back and the marker removed, and nothing else is done.
/// - [`Phase::Deploying`], with a `deployed.json` that names this very deploy:
///   it passed its checks and only the clearing is left, so it is reported as
///   deployed. Without that record, it is rolled back.
/// - [`Phase::RollingBack`]: rolled back again from the start, whatever
///   `deployed.json` says.
/// - [`Phase::Restored`]: the backup is back in full, and the previous version
///   may have been running on it since, as after a rollback whose checks failed.
///   Only the start, the image check and the checks run again: stopping the
///   service and restoring would discard what it wrote. With no previous version
///   to start, the service is stopped instead. This assumes that only the
///   previous version touched the data since the restore.
/// - [`Phase::RolledBack`]: the previous version is back and has been checked,
///   so only the marker is removed. The backup is not restored again: that
///   would discard what the previous version wrote since.
///
/// The report is written and the outcome journalled as for [`run`]. A rollback
/// that fails again leaves the deploy interrupted, so this can be retried.
///
/// # Errors
///
/// [`DeployError::NothingToRecover`] when there is no interrupted deploy,
/// [`DeployError::Busy`] while something holds the lock, which includes a
/// restore that outlived its deadline, and [`DeployError::File`].
pub async fn recover<D: Docker>(
    docker: &D,
    state: &DeploymentState,
    deployment: &Deployment,
    compose_dir: &Path,
    options: &EngineOptions,
) -> Result<DeployReport, DeployError> {
    let result = async {
        let engine = Engine {
            docker,
            state,
            deployment,
            dir: compose_dir,
            options,
            lock: take_lock(state, deployment.id()).await?,
            file_outran_deadline: AtomicBool::new(false),
            backups_outran_deadline: AtomicBool::new(false),
        };
        engine.recover().await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

impl<D: Docker> Engine<'_, D> {
    async fn recover(&self) -> Result<DeployReport, DeployError> {
        let state = self.state.clone();
        let unfinished = self
            .file("read in-progress", move || state.in_progress())
            .await
            .map_err(|e| self.file_error(e))?;
        let Some(marker) = unfinished else {
            return Err(DeployError::NothingToRecover(self.deployment.id().clone()));
        };
        let mut rec = Recorder::new(self.deployment.id(), &marker.tag, &marker.digest);
        let finished = match marker.phase {
            Phase::Deploying => {
                let state = self.state.clone();
                let deployed = self
                    .file("read deployed", move || state.deployed())
                    .await
                    .map_err(|e| self.file_error(e))?;
                // The sequence writes this record once the checks have passed.
                deployed.is_some_and(|d| d.deploy_id == marker.deploy_id)
            }
            Phase::Preflight | Phase::RollingBack | Phase::Restored | Phase::RolledBack => false,
        };
        let outcome = if finished {
            self.prune_kept(&mut rec).await;
            Outcome::Deployed
        } else if marker.phase == Phase::Preflight {
            self.undo_preflight(&mut rec, &marker).await
        } else if marker.phase == Phase::RolledBack {
            self.clear_and_prune(&mut rec).await;
            rolled_back(
                &marker,
                format!(
                    "the deploy of {} had been rolled back; recover removed its marker",
                    marker.tag
                ),
            )
        } else {
            let reason = format!(
                "the deploy of {} was interrupted; rolled back by recover",
                marker.tag
            );
            self.rollback_outcome(&mut rec, &marker, reason).await
        };
        Ok(self.finish(rec, outcome).await)
    }
}
