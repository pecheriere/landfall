//! The deploy sequence: pull, back up, switch, check.

use std::fs::DirBuilder;
use std::io;
use std::os::unix::fs::DirBuilderExt as _;
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use jiff::Timestamp;
use landfall_core::config::{Backup, Deployment};
use landfall_core::ids::DeploymentId;
use serde::Serialize;

use super::files::{rel_paths, render, timestamp_id};
use super::{
    CheckTiming, DeployError, DeployPlan, DeployReport, Engine, EngineOptions, FileFailure,
    Outcome, Recorder, StepDetail,
};
use crate::checks::{CheckReport, quote, run_checks};
use crate::docker::{Docker, DockerError};
use crate::journal::{self, Priority};
use crate::safefs::{self, Root, SnapshotStats};
use crate::state::{
    DeployLock, Deployed, DeploymentState, InProgress, Phase, RecordedBackup, StateError,
};

/// Deploys `plan`: preflight, `in-progress.json`, a check of the project with
/// the new override, pull, the marker's move to [`Phase::Deploying`], stop if
/// the backup asks for it, backup, override, `up`, image check and post-deploy
/// checks. A failure from that stop on rolls back. The report is written before
/// this returns, on every outcome, and the outcome goes to the journal.
///
/// # Errors
///
/// [`DeployError`] when the deploy never started: the deployment is locked or
/// has an interrupted deploy, the preflight refused, the pull failed, or a state
/// file could not be written. No service was touched. The override and the marker are as they were, other
/// than a placeholder override where there was none, unless the error is
/// [`DeployError::LeftBlocked`], which keeps the marker and names `recover`.
pub async fn run<D: Docker>(
    docker: &D,
    state: &DeploymentState,
    deployment: &Deployment,
    compose_dir: &Path,
    plan: &DeployPlan,
    options: &EngineOptions,
) -> Result<DeployReport, DeployError> {
    run_holding(docker, state, deployment, compose_dir, plan, options, None).await
}

/// [`run`], going on with the deployment's lock if the caller holds it already: what the
/// caller checked under it is then still so when this starts, and nothing can come
/// between. It must be `state`'s lock.
///
/// # Errors
///
/// As [`run`].
pub async fn run_holding<D: Docker>(
    docker: &D,
    state: &DeploymentState,
    deployment: &Deployment,
    compose_dir: &Path,
    plan: &DeployPlan,
    options: &EngineOptions,
    lock: Option<DeployLock>,
) -> Result<DeployReport, DeployError> {
    let result = async {
        if plan.deployment() != deployment.id() {
            return Err(DeployError::PlanMismatch {
                plan: plan.deployment().clone(),
                deployment: deployment.id().clone(),
            });
        }
        let lock = match lock {
            Some(lock) => Arc::new(lock),
            None => take_lock(state, deployment.id()).await?,
        };
        let engine = Engine {
            docker,
            state,
            deployment,
            dir: compose_dir,
            options,
            lock,
            file_outran_deadline: AtomicBool::new(false),
            backups_outran_deadline: AtomicBool::new(false),
        };
        engine.deploy(plan).await
    }
    .await;
    journal_refusal(&result, deployment.id());
    result
}

const WRONG_PREVIOUS_IMAGE: &str =
    "the container does not run the image the compose project resolves to";

/// The running image is not named: if `up` left the old container running, it
/// comes from interpolated configuration and can hold a secret.
fn not_pinned(pinned: &str) -> String {
    format!("the running image isn't the pinned one, {pinned}")
}

pub(super) fn journal_refusal(
    result: &Result<DeployReport, DeployError>,
    deployment: &DeploymentId,
) {
    #[derive(Serialize)]
    struct Refused<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        error: String,
    }
    if let Err(error) = result {
        journal::emit(
            Priority::Error,
            &Refused {
                event: "deploy_refused",
                deployment,
                error: error.to_string(),
            },
        );
    }
}

pub(super) async fn take_lock(
    state: &DeploymentState,
    deployment: &DeploymentId,
) -> Result<Arc<DeployLock>, DeployError> {
    let state = state.clone();
    match tokio::task::spawn_blocking(move || state.lock()).await {
        Ok(Ok(lock)) => Ok(Arc::new(lock)),
        Ok(Err(StateError::Busy(id))) => Err(DeployError::Busy(id)),
        Ok(Err(error)) => Err(DeployError::File {
            deployment: deployment.clone(),
            source: error.into(),
        }),
        Err(_) => Err(DeployError::File {
            deployment: deployment.clone(),
            source: FileFailure::Panicked { op: "take lock" },
        }),
    }
}

impl<D: Docker> Engine<'_, D> {
    async fn deploy(&self, plan: &DeployPlan) -> Result<DeployReport, DeployError> {
        let state = self.state.clone();
        let unfinished = self
            .file("read in-progress", move || state.in_progress())
            .await
            .map_err(|e| self.file_error(e))?;
        if let Some(unfinished) = unfinished {
            return Err(DeployError::Interrupted {
                deployment: self.deployment.id().clone(),
                tag: unfinished.tag,
            });
        }
        let mut rec = Recorder::new(self.deployment.id(), plan.tag(), plan.digest());
        let preflight = rec.step("preflight", self.preflight()).await?;
        let started_at = Timestamp::now();
        let mut marker = InProgress {
            deploy_id: timestamp_id(started_at),
            phase: Phase::Preflight,
            tag: plan.tag().clone(),
            digest: plan.digest().clone(),
            previous_can_start: preflight.previous_can_start,
            backup: None,
            started_at,
        };
        rec.step(
            "record_in_progress",
            self.record_in_progress(&marker, preflight.previous.clone()),
        )
        .await?;
        rec.step(
            "verify_override",
            self.verify_override(plan, preflight.previous),
        )
        .await?;
        let pulled = rec
            .step("pull", async {
                self.docker
                    .pull(plan.image())
                    .await
                    .map_err(|source| DeployError::Pull {
                        deployment: self.deployment.id().clone(),
                        image: plan.image().to_owned(),
                        source,
                    })
            })
            .await;
        if let Err(refused) = pulled {
            return Err(self.abandon(refused).await);
        }
        rec.step("mark_deploying", self.start_deploying(&marker))
            .await?;
        marker.phase = Phase::Deploying;

        // From here on, the report tells how it went.
        let outcome = match self.forward(plan, &mut rec, &mut marker).await {
            Ok(()) => {
                // The release is in and recorded: a failure to remove old
                // backups is in the report, and doesn't undo the deploy.
                self.prune_kept(&mut rec).await;
                Outcome::Deployed
            }
            Err(reason) => self.rollback_outcome(&mut rec, &marker, reason).await,
        };
        Ok(self.finish(rec, outcome).await)
    }

    /// Backup to checks. `marker.backup` names the backup only once it is
    /// complete and recorded, which is what a rollback goes by. A backup that
    /// fails is therefore never restored, and neither is one that could not
    /// be recorded: the new version has not run yet, so the data is as it was.
    async fn forward(
        &self,
        plan: &DeployPlan,
        rec: &mut Recorder,
        marker: &mut InProgress,
    ) -> Result<(), String> {
        if let Some(backup) = self.deployment.backup() {
            // Room for the copy about to be made, so a full disk is less
            // likely to fail it, while the service still runs. Failing here
            // stops nothing: the backup then finds out if there is room.
            // At least one stays: the new copy doesn't exist yet.
            let room = self.options.backups_kept.saturating_sub(1).max(1);
            let _ = rec
                .step(
                    "prune_before_backup",
                    self.prune("prune before backup", room),
                )
                .await;
            if backup.stop() {
                rec.must("stop", self.stop()).await?;
            }
            let id = timestamp_id(Timestamp::now());
            rec.must_detailed("backup", async {
                let copied = self.backup(backup, &id).await;
                let detail = copied
                    .as_ref()
                    .ok()
                    .map(|stats| StepDetail::Backup { stats: *stats });
                (copied, detail)
            })
            .await?;
            let mut with_backup = marker.clone();
            with_backup.backup = Some(RecordedBackup {
                id,
                paths: backup.paths().to_vec(),
            });
            let state = self.state.clone();
            let record = with_backup.clone();
            rec.must(
                "record_backup",
                self.file("record backup", move || state.set_in_progress(&record)),
            )
            .await?;
            *marker = with_backup;
        }
        rec.must(
            "write_override",
            self.write_override(render(plan, self.service())),
        )
        .await?;
        let since = Timestamp::now();
        rec.must("up", self.up()).await?;
        rec.must("verify_image", self.verify_pinned(plan.image()))
            .await?;
        rec.must_detailed("checks", self.check_pinned(plan.image(), since))
            .await?;
        let state = self.state.clone();
        let deployed = Deployed {
            deploy_id: marker.deploy_id.clone(),
            tag: plan.tag().clone(),
            version: plan.version().clone(),
            digest: plan.digest().clone(),
            commit: plan.commit().clone(),
            deployed_at: Timestamp::now(),
        };
        rec.must(
            "record_deployed",
            self.file("record deployed", move || state.set_deployed(&deployed)),
        )
        .await
    }

    pub(super) async fn stop(&self) -> Result<(), DockerError> {
        self.docker.compose_stop(self.dir, self.service()).await
    }

    pub(super) async fn up(&self) -> Result<(), DockerError> {
        self.docker.compose_up(self.dir, self.service()).await
    }

    /// Runs the checks, from `since`, the time just before the service was
    /// brought up. Returns the image the final round saw, and what each check
    /// took, either way.
    async fn checks(&self, since: Timestamp) -> (Result<String, String>, Option<StepDetail>) {
        let detail = |reports: &[CheckReport]| {
            Some(StepDetail::Checks {
                checks: reports.iter().map(CheckTiming::from).collect(),
            })
        };
        match run_checks(
            self.docker,
            self.dir,
            self.service(),
            self.deployment.checks(),
            since,
            &self.options.checks,
        )
        .await
        {
            Ok(summary) => (Ok(summary.image), detail(&summary.checks)),
            Err(failure) => {
                let detail = detail(&failure.checks);
                (Err(failure.to_string()), detail)
            }
        }
    }

    /// The checks, and the pinned image still running when they ended.
    async fn check_pinned(
        &self,
        pinned: &str,
        since: Timestamp,
    ) -> (Result<(), String>, Option<StepDetail>) {
        let (image, detail) = self.checks(since).await;
        let checked = image.and_then(|image| {
            if image == pinned {
                Ok(())
            } else {
                Err(not_pinned(pinned))
            }
        });
        (checked, detail)
    }

    /// The checks, and the previous image still running when they ended. As
    /// in [`Self::verify_previous`], neither image is named.
    pub(super) async fn check_previous(
        &self,
        resolved: &str,
        since: Timestamp,
    ) -> (Result<(), String>, Option<StepDetail>) {
        let (image, detail) = self.checks(since).await;
        let checked = image.and_then(|image| {
            if image == resolved {
                Ok(())
            } else {
                Err(WRONG_PREVIOUS_IMAGE.to_owned())
            }
        });
        (checked, detail)
    }

    /// A snapshot failure of any kind is a failed backup. That includes a
    /// missing path: a container that keeps running could otherwise make a
    /// backup incomplete by deleting a file.
    pub(super) async fn backup(
        &self,
        backup: &Backup,
        id: &str,
    ) -> Result<SnapshotStats, FileFailure> {
        let paths = rel_paths(backup.paths())?;
        let dir = self.dir.to_owned();
        let backups = self.state.backups_dir();
        let dest = backups.join(id);
        self.on_backups("backup", move || {
            match DirBuilder::new().mode(0o700).create(&backups) {
                Ok(()) => {}
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
                Err(source) => {
                    return Err(FileFailure::State(StateError::Io {
                        op: "create",
                        path: backups,
                        source,
                    }));
                }
            }
            let source = Root::open(&dir)?;
            Ok(safefs::snapshot(&source, &paths, &dest)?)
        })
        .await
    }

    /// Removes all but the newest `keep` backups, and never the one a marker
    /// on disk names: that is what a rollback or `recover` would restore. Skipped
    /// once a deadline has fired in this run: the work may still be running, and
    /// the `.partial` of a snapshot would look like a leftover. The next run
    /// has to take the lock, so it starts when that work has ended.
    async fn prune(&self, op: &'static str, keep: usize) -> Result<(), FileFailure> {
        if self.file_outran_deadline.load(Ordering::SeqCst)
            || self.backups_outran_deadline.load(Ordering::SeqCst)
        {
            return Err(FileFailure::PruneSkipped);
        }
        let backups = self.state.backups_dir();
        let state = self.state.clone();
        self.on_backups(op, move || {
            let marker = state.in_progress()?;
            let named = marker.as_ref().and_then(|m| m.backup.as_ref());
            safefs::prune(&backups, keep, named.map(|backup| backup.id.as_str()))?;
            Ok::<(), FileFailure>(())
        })
        .await
    }

    /// Brings the backups down to the number kept. A failure is in the report
    /// and changes no outcome.
    pub(super) async fn prune_kept(&self, rec: &mut Recorder) {
        let keep = self.options.backups_kept;
        let _ = rec
            .step("prune_backups", self.prune("prune backups", keep))
            .await;
    }

    /// The rollback is over: removes the marker and then, with nothing left
    /// that may need them, the backups beyond the number kept. Failed deploys
    /// take backups too.
    pub(super) async fn clear_and_prune(&self, rec: &mut Recorder) {
        if self.clear_in_progress(rec).await {
            self.prune_kept(rec).await;
        }
    }

    /// The image of the service's container, as it says.
    pub(super) async fn running_image(&self) -> Result<String, String> {
        let id = self
            .docker
            .container(self.dir, self.service())
            .await
            .map_err(|e| e.to_string())?
            .ok_or_else(|| format!("service {} has no running container", quote(self.service())))?;
        let info = self.docker.inspect(&id).await.map_err(|e| e.to_string())?;
        Ok(info.image)
    }

    async fn verify_pinned(&self, pinned: &str) -> Result<(), String> {
        let running = self.running_image().await?;
        if running == pinned {
            Ok(())
        } else {
            Err(not_pinned(pinned))
        }
    }

    /// With the previous override back, the container must run what the
    /// project resolves to, which is returned. Neither is named in the error:
    /// this image comes from interpolated configuration and can hold a secret.
    pub(super) async fn verify_previous(&self) -> Result<String, String> {
        let resolved = self
            .docker
            .compose_service(self.dir, self.service())
            .await
            .map_err(|e| e.to_string())?;
        let running = self.running_image().await?;
        if resolved.image.as_deref() == Some(running.as_str()) {
            Ok(running)
        } else {
            Err(WRONG_PREVIOUS_IMAGE.to_owned())
        }
    }
}
