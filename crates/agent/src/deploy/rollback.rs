//! Putting the previous version and its data back.

use std::sync::atomic::Ordering;

use jiff::Timestamp;
use landfall_core::ids::{DeploymentId, ImageDigest, ReleaseTag};
use serde::Serialize;

use super::files::{rel_paths, timestamp_id};
use super::offload::off_thread;
use super::report::CLEAR_STEP;
use super::{DeployReport, Engine, FileFailure, Outcome, Recorder};
use crate::docker::Docker;
use crate::journal::{self, Priority};
use crate::safefs::{self, Root};
use crate::state::{InProgress, Phase, RecordedBackup};

/// How a completed rollback ended.
pub(super) fn rolled_back(marker: &InProgress, reason: String) -> Outcome {
    if marker.previous_can_start {
        Outcome::RolledBack { reason }
    } else {
        Outcome::FailedNoPrevious { reason }
    }
}

impl<D: Docker> Engine<'_, D> {
    /// Rolls back, clears the marker unless that failed, and says how it ended.
    pub(super) async fn rollback_outcome(
        &self,
        rec: &mut Recorder,
        marker: &InProgress,
        reason: String,
    ) -> Outcome {
        match self.rollback(rec, marker).await {
            Ok(()) => {
                self.clear_and_prune(rec).await;
                rolled_back(marker, reason)
            }
            // The marker stays: deploys stay blocked, and `recover` can try
            // again from the same previous state and backup.
            Err(rollback_reason) => Outcome::RollbackFailed {
                reason,
                rollback_reason,
            },
        }
    }

    /// A deploy interrupted in its preflight: only the override can be out of
    /// place. The service was never touched, so it is left alone.
    pub(super) async fn undo_preflight(&self, rec: &mut Recorder, marker: &InProgress) -> Outcome {
        let reason = format!(
            "the deploy of {} was interrupted before it touched the service; recover put the previous override back",
            marker.tag
        );
        match self.restore_previous_override(rec).await {
            Ok(()) => {
                let _ = self.clear_in_progress(rec).await;
                Outcome::NothingChanged { reason }
            }
            // The marker stays, and `recover` can try again.
            Err(rollback_reason) => Outcome::RollbackFailed {
                reason,
                rollback_reason,
            },
        }
    }

    async fn restore_previous_override(&self, rec: &mut Recorder) -> Result<(), String> {
        let state = self.state.clone();
        let previous = rec
            .must("read_previous_override", async {
                self.file("read previous override", move || state.previous_override())
                    .await?
                    .ok_or(FileFailure::NoPreviousOverride)
            })
            .await?;
        rec.must("restore_override", self.write_override(previous))
            .await
    }

    /// Writes the marker with `phase`.
    async fn mark(
        &self,
        rec: &mut Recorder,
        (step, op): (&'static str, &'static str),
        marker: &InProgress,
        phase: Phase,
    ) -> Result<(), String> {
        let state = self.state.clone();
        let next = InProgress {
            phase,
            ..marker.clone()
        };
        rec.must(step, self.file(op, move || state.set_in_progress(&next)))
            .await
    }

    /// Back to the previous state. Each step depends on the one before: with
    /// the service still running a restore could be outrun, and half-restored
    /// data is not to be started, so the first failure ends it.
    ///
    /// The marker says `RollingBack` before anything is undone: until then the
    /// release is as it was, so a record of it is still true. Small file work
    /// that outran its deadline may yet land on top of what this puts back. It
    /// keeps a share of the lock until it ends, so that is what `recover` waits
    /// for, and this stops rather than leave the wrong override or record
    /// behind what looks like a clean rollback.
    ///
    /// From [`Phase::Restored`] everything up to the start is done and only the
    /// rest runs. The marker takes that phase as soon as the restore has
    /// returned: from then on the previous version's data is what counts, and
    /// a failure further on can leave it running and writing for a long time.
    /// With no previous version there are no writes of it to lose, so the service
    /// is stopped from that phase too: a container may have come back since.
    async fn rollback(&self, rec: &mut Recorder, marker: &InProgress) -> Result<(), String> {
        let restored = marker.phase == Phase::Restored;
        if !restored && marker.phase != Phase::RollingBack {
            self.mark(
                rec,
                ("mark_rolling_back", "mark rolling back"),
                marker,
                Phase::RollingBack,
            )
            .await?;
        }
        if self.file_outran_deadline.load(Ordering::SeqCst) {
            return Err(
                "a file write ran past its deadline and may still land; run recover once it has ended"
                    .to_owned(),
            );
        }
        let mut stopped = false;
        if !restored {
            self.restore_previous_override(rec).await?;
            rec.must("restore_deployed", self.restore_deployed())
                .await?;
            if let Some(backup) = &marker.backup {
                rec.must("stop_for_restore", self.stop()).await?;
                stopped = true;
                rec.must("restore_backup", self.restore(backup)).await?;
                self.mark(
                    rec,
                    ("mark_restored", "mark restored"),
                    marker,
                    Phase::Restored,
                )
                .await?;
            }
        }
        if marker.previous_can_start {
            let since = Timestamp::now();
            rec.must("start_previous", self.up()).await?;
            let resolved = rec
                .must("verify_previous_image", self.verify_previous())
                .await?;
            rec.must_detailed("check_previous", self.check_previous(&resolved, since))
                .await?;
        } else if !stopped {
            rec.must("stop_service", self.stop()).await?;
        }
        self.mark(
            rec,
            ("mark_rolled_back", "mark rolled back"),
            marker,
            Phase::RolledBack,
        )
        .await
    }

    /// `deployed.json` as it was when the deploy started. A failed write of
    /// this release's record can have landed all the same.
    async fn restore_deployed(&self) -> Result<(), FileFailure> {
        let state = self.state.clone();
        self.file("restore deployed", move || {
            match state
                .previous_deployed()?
                .ok_or(FileFailure::NoPreviousDeployed)?
            {
                Some(deployed) => state.set_deployed(&deployed)?,
                None => state.clear_deployed()?,
            }
            Ok::<(), FileFailure>(())
        })
        .await
    }

    /// Restores the paths the backup was taken of: the configuration can have
    /// changed before a `recover`.
    async fn restore(&self, backup: &RecordedBackup) -> Result<(), FileFailure> {
        let paths = rel_paths(&backup.paths)?;
        let dir = self.dir.to_owned();
        let snapshot = self.state.backups_dir().join(&backup.id);
        off_thread(
            &self.lock,
            "restore backup",
            self.options.restore_deadline,
            move || {
                let target = Root::open(&dir)?;
                safefs::restore(&snapshot, &target, &paths)
            },
        )
        .await
    }

    /// A marker that could not be removed is in the report and keeps deploys
    /// blocked; what is running is still what the outcome says. Returns whether
    /// it is gone.
    pub(super) async fn clear_in_progress(&self, rec: &mut Recorder) -> bool {
        let state = self.state.clone();
        rec.step(
            CLEAR_STEP,
            self.file("clear in-progress", move || state.clear_in_progress()),
        )
        .await
        .is_ok()
    }

    /// Clears the marker of a deploy that went through, writes the report and
    /// tells the journal.
    pub(super) async fn finish(&self, mut rec: Recorder, outcome: Outcome) -> DeployReport {
        #[derive(Serialize)]
        struct Finished<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            tag: &'a ReleaseTag,
            digest: &'a ImageDigest,
            outcome: &'a Outcome,
        }
        #[derive(Serialize)]
        struct ReportNotWritten<'a> {
            event: &'static str,
            deployment: &'a DeploymentId,
            error: String,
        }
        if outcome == Outcome::Deployed {
            let _ = self.clear_in_progress(&mut rec).await;
        }
        let report = DeployReport {
            deployment: rec.deployment,
            tag: rec.tag,
            digest: rec.digest,
            outcome,
            steps: rec.steps,
            started_at: rec.started_at,
            finished_at: Timestamp::now(),
        };
        let state = self.state.clone();
        let id = timestamp_id(report.started_at);
        let copy = report.clone();
        let written = self
            .file("write report", move || state.write_report(&id, &copy))
            .await;
        if let Err(error) = written {
            journal::emit(
                Priority::Error,
                &ReportNotWritten {
                    event: "deploy_report_not_written",
                    deployment: &report.deployment,
                    error: error.to_string(),
                },
            );
        }
        journal::emit(
            report.outcome.priority(),
            &Finished {
                event: "deploy_finished",
                deployment: &report.deployment,
                tag: &report.tag,
                digest: &report.digest,
                outcome: &report.outcome,
            },
        );
        report
    }
}
