//! The preflight: what must hold before the service is touched.

use super::files::{labelled_with, rel_paths, render};
use super::{DeployError, DeployPlan, Engine, FileFailure, Preflight};
use crate::checks::quote;
use crate::compose;
use crate::docker::Docker;
use crate::state::{InProgress, Phase};

impl<D: Docker> Engine<'_, D> {
    /// What can be refused before the marker goes in: the backup's paths, and
    /// the project as it is. The only change is a placeholder override where
    /// there was none. This reads the project leniently, since a first deploy
    /// may start from a service without an image.
    pub(super) async fn preflight(&self) -> Result<Preflight, DeployError> {
        if let Some(backup) = self.deployment.backup() {
            rel_paths(backup.paths()).map_err(|source| DeployError::BackupPath {
                deployment: self.deployment.id().clone(),
                source,
            })?;
        }
        let current = self.read_override().await.map_err(|e| self.file_error(e))?;
        let previous = if let Some(bytes) = current {
            bytes
        } else {
            let placeholder = compose::PLACEHOLDER.as_bytes().to_vec();
            self.write_override(placeholder.clone())
                .await
                .map_err(|e| self.file_error(e))?;
            placeholder
        };
        let base = self
            .docker
            .compose_service(self.dir, self.service())
            .await
            .map_err(|e| self.compose_error(e))?;
        if base.has_build {
            return Err(DeployError::HasBuild {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
            });
        }
        if base.replicas != 1 {
            return Err(DeployError::Scaled {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
                replicas: base.replicas,
            });
        }
        self.refuse_what_stands_in_the_way().await?;
        Ok(Preflight {
            previous,
            previous_can_start: base.image.is_some(),
        })
    }

    /// Every step after the preflight goes by the project's name and the service,
    /// so this looks at every container with the service's name:
    ///
    /// - One of the project, running or stopped, started from another directory:
    ///   the project's name is shared, and this deploy would replace it.
    /// - One running from this directory under another project's name: the steps
    ///   after this would leave it out, while it shares the directory's data with
    ///   a backup and a restore.
    /// - More than one running in all of those.
    ///
    /// A stack elsewhere with another project that only shares the service's
    /// name is none of this deployment's business, whatever its label says.
    async fn refuse_what_stands_in_the_way(&self) -> Result<(), DeployError> {
        let found = self
            .docker
            .service_containers(self.dir, self.service())
            .await
            .map_err(|e| self.compose_error(e))?;
        let dir = self.dir.to_owned();
        let labels: Vec<Option<String>> = found.iter().map(|c| c.working_dir.clone()).collect();
        let here = self
            .file("compare working directories", move || {
                labelled_with(&dir, &labels)
            })
            .await
            .map_err(|e| self.file_error(e))?;
        let mut running_in_project = 0_usize;
        let mut running_outside = false;
        for (container, here) in found.iter().zip(here) {
            if container.in_project && !here {
                return Err(DeployError::StartedElsewhere {
                    deployment: self.deployment.id().clone(),
                    service: self.service().to_owned(),
                    found: container
                        .working_dir
                        .as_deref()
                        .map_or_else(|| "no directory it labels".to_owned(), quote),
                });
            }
            running_in_project += usize::from(container.in_project && container.running);
            running_outside |= here && container.running && !container.in_project;
        }
        if running_in_project > 1 || (running_outside && running_in_project > 0) {
            return Err(DeployError::SeveralContainers {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
            });
        }
        if running_outside {
            return Err(DeployError::OutsideTheProject {
                deployment: self.deployment.id().clone(),
                service: self.service().to_owned(),
            });
        }
        Ok(())
    }

    /// What a rollback goes back to, then the marker, which promises it. No
    /// marker was there when this runs and the new override has not been
    /// written, so `previous` cannot be the override of an unfinished deploy.
    /// The marker can be on disk even if the write reports a failure.
    pub(super) async fn record_in_progress(
        &self,
        marker: &InProgress,
        previous: Vec<u8>,
    ) -> Result<(), DeployError> {
        let state = self.state.clone();
        let marker = marker.clone();
        let written = self
            .file("record in-progress", move || {
                state.set_previous_deployed(state.deployed()?.as_ref())?;
                state.set_previous_override(&previous)?;
                state.set_in_progress(&marker)
            })
            .await;
        self.settle_marker_write(written, "recording the deploy's start")
            .await
    }

    /// With the marker written: reads the project with the new override in
    /// place, held to everything `up` will require, then takes the override
    /// back out, as nothing else may see it before the backup. A refusal
    /// clears the marker; an override that cannot be put back keeps it.
    pub(super) async fn verify_override(
        &self,
        plan: &DeployPlan,
        previous: Vec<u8>,
    ) -> Result<(), DeployError> {
        let checked = match self.write_override(render(plan, self.service())).await {
            // It may yet land, after anything done here to put it back.
            Err(source @ FileFailure::Deadline { .. }) => {
                return Err(self.left_blocked(None, "writing the new override", source));
            }
            // It may have landed: the rename comes before the last `fsync`.
            Err(source) => Err(self.file_error(source)),
            Ok(()) => {
                match self
                    .docker
                    .compose_service_checked(self.dir, self.service())
                    .await
                {
                    Ok(service) if service.image.as_deref() == Some(plan.image()) => Ok(()),
                    // What it did resolve to stays out of this: it can hold a secret.
                    Ok(_) => Err(DeployError::OverrideNotApplied {
                        deployment: self.deployment.id().clone(),
                        service: self.service().to_owned(),
                        pinned: plan.image().to_owned(),
                    }),
                    Err(error) => Err(self.compose_error(error)),
                }
            }
        };
        if let Err(source) = self.write_override(previous).await {
            return Err(self.left_blocked(
                checked.err(),
                "putting the previous override back",
                source,
            ));
        }
        match checked {
            Ok(()) => Ok(()),
            Err(refused) => Err(self.abandon(refused).await),
        }
    }

    fn left_blocked(
        &self,
        refused: Option<DeployError>,
        failed: &'static str,
        source: FileFailure,
    ) -> DeployError {
        DeployError::LeftBlocked {
            deployment: self.deployment.id().clone(),
            refused: refused.map(Box::new),
            failed,
            source,
        }
    }

    /// The checks and the pull are over and nothing was touched yet. The next
    /// step may touch the service, so from here on `recover` has to assume it
    /// did.
    pub(super) async fn start_deploying(&self, marker: &InProgress) -> Result<(), DeployError> {
        let state = self.state.clone();
        let next = InProgress {
            phase: Phase::Deploying,
            ..marker.clone()
        };
        let written = self
            .file("mark deploying", move || state.set_in_progress(&next))
            .await;
        self.settle_marker_write(written, "recording that the deploy goes ahead")
            .await
    }

    /// A marker write before anything was touched: one that failed leaves at
    /// most the marker, which is cleared, and one past its deadline may yet
    /// land after a clear, so that keeps deploys blocked.
    async fn settle_marker_write(
        &self,
        written: Result<(), FileFailure>,
        failed: &'static str,
    ) -> Result<(), DeployError> {
        match written {
            Ok(()) => Ok(()),
            Err(source @ FileFailure::Deadline { .. }) => {
                Err(self.left_blocked(None, failed, source))
            }
            Err(source) => Err(self.abandon(self.file_error(source)).await),
        }
    }

    /// Nothing is left of a deploy that was refused but its marker.
    pub(super) async fn abandon(&self, refused: DeployError) -> DeployError {
        let state = self.state.clone();
        let cleared = self
            .file("clear in-progress", move || state.clear_in_progress())
            .await;
        match cleared {
            Ok(()) => refused,
            Err(source) => {
                self.left_blocked(Some(refused), "clearing the in-progress marker", source)
            }
        }
    }
}
