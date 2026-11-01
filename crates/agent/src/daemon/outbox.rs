//! Reports on their way to the controller: the engine's report in the wire's
//! terms, what a crash or a `recover` left of a deploy, the outbox, and the
//! ledger of what has finished.

use std::path::Path;

use landfall_core::ids::DeploymentId;
use landfall_core::protocol::{
    DeployId, DeployReportBody, MAX_BODY_BYTES, ReportedCheck, ReportedDetail, ReportedOutcome,
    ReportedStep,
};
use serde::Serialize;

use super::{StepOutcome, on_thread};
use crate::client::Controller;
use crate::deploy::{DeployReport, Outcome, StepDetail, StepResult};
use crate::journal::{self, Priority};
use crate::state::{ControllerClaim, DeploymentState, StateDir, StateError};

/// The longest text of a report, in characters. What fits in a body is up to
/// [`fit_to_the_wire`]: a character can take many bytes once serialised.
const MAX_REPORT_TEXT: usize = 4096;
/// The step that says a report had to be trimmed.
const TRIMMED_STEP: &str = "report_trimmed";

pub(super) fn bounded(text: &str) -> String {
    let mut cut: String = text.chars().take(MAX_REPORT_TEXT).collect();
    if cut.len() < text.len() {
        cut.push_str("...");
    }
    cut
}

fn reported_outcome(outcome: &Outcome) -> ReportedOutcome {
    match outcome {
        Outcome::Deployed => ReportedOutcome::Deployed {},
        Outcome::RolledBack { reason } => ReportedOutcome::RolledBack {
            reason: bounded(reason),
        },
        Outcome::NothingChanged { reason } => ReportedOutcome::NothingChanged {
            reason: bounded(reason),
        },
        Outcome::FailedNoPrevious { reason } => ReportedOutcome::FailedNoPrevious {
            reason: bounded(reason),
        },
        Outcome::RollbackFailed {
            reason,
            rollback_reason,
        } => ReportedOutcome::RollbackFailed {
            reason: bounded(reason),
            rollback_reason: bounded(rollback_reason),
        },
    }
}

fn reported_detail(detail: &StepDetail) -> ReportedDetail {
    match detail {
        StepDetail::Checks { checks } => ReportedDetail::Checks {
            checks: checks
                .iter()
                .map(|check| ReportedCheck {
                    check: bounded(&check.check),
                    attempts: check.attempts,
                    millis: check.millis,
                })
                .collect(),
        },
        StepDetail::Backup { stats } => ReportedDetail::Backup {
            files: stats.files,
            directories: stats.directories,
            symlinks: stats.symlinks,
            bytes: stats.bytes,
        },
    }
}

fn fits(body: &DeployReportBody) -> bool {
    serde_json::to_vec(body).is_ok_and(|wire| wire.len() <= MAX_BODY_BYTES)
}

fn trimmed_step() -> ReportedStep {
    ReportedStep {
        name: TRIMMED_STEP.to_owned(),
        millis: 0,
        failure: None,
        detail: None,
    }
}

/// A body over the API's limit would be refused every time, so it is cut down
/// until it fits: first the steps' details, then what the steps say beyond their
/// names, then the steps. A last step says it was done. The outcome stays, and it
/// fits: two bounded reasons are far under the limit however they serialise.
fn fit_to_the_wire(mut body: DeployReportBody) -> DeployReportBody {
    if fits(&body) {
        return body;
    }
    for step in &mut body.steps {
        step.detail = None;
    }
    body.steps.push(trimmed_step());
    if fits(&body) {
        return body;
    }
    for step in &mut body.steps {
        if step.failure.is_some() {
            step.failure = Some("withheld: the report was over the size limit".to_owned());
        }
    }
    if fits(&body) {
        return body;
    }
    body.steps = vec![trimmed_step()];
    body
}

/// The engine's report as it goes to the controller, under the controller's
/// number.
pub(super) fn reported(deploy_id: DeployId, report: &DeployReport) -> DeployReportBody {
    fit_to_the_wire(DeployReportBody {
        deploy_id,
        outcome: reported_outcome(&report.outcome),
        steps: report
            .steps
            .iter()
            .map(|step| ReportedStep {
                name: bounded(&step.name),
                millis: step.millis,
                failure: match &step.result {
                    StepResult::Ok => None,
                    StepResult::Failed { reason } => Some(bounded(reason)),
                },
                detail: step.detail.as_ref().map(reported_detail),
            })
            .collect(),
    })
}

/// The engine's reports the deployment has, as they read, passing over and
/// journalling any that can't be read.
fn engine_reports(state: &DeploymentState) -> Result<Vec<(String, DeployReport)>, StateError> {
    #[derive(Serialize)]
    struct Unreadable {
        event: &'static str,
        error: String,
    }
    let mut reports = Vec::new();
    for name in state.report_names()? {
        match state.report(&name) {
            Ok(report) => reports.push((name, report)),
            Err(error) => journal::emit(
                Priority::Warning,
                &Unreadable {
                    event: "deploy_report_unreadable",
                    error: error.to_string(),
                },
            ),
        }
    }
    Ok(reports)
}

/// The engine's report that ends `claim`: one written since the claim was made.
/// There can be several, when a rollback failed and a `recover` succeeded later:
/// with the marker gone, one that isn't a failed rollback ends it, and otherwise
/// the times between these reports are all there is to go by.
fn latest_report(
    state: &DeploymentState,
    claim: &ControllerClaim,
) -> Result<Option<DeployReport>, StateError> {
    Ok(engine_reports(state)?
        .into_iter()
        .filter(|(name, report)| {
            !claim.reports_before.contains(name)
                && report.tag == claim.tag
                && report.digest == claim.digest
        })
        .map(|(_, report)| report)
        .max_by_key(|report| {
            (
                !matches!(report.outcome, Outcome::RollbackFailed { .. }),
                report.started_at,
            )
        }))
}

/// Whether this release has already failed on this host, by the engine's own
/// reports, which a controller has no say in. It stays failed: a newer release is
/// another matter.
pub(super) fn failed_before(
    state: &DeploymentState,
    tag: &landfall_core::ids::ReleaseTag,
    digest: &landfall_core::ids::ImageDigest,
) -> Result<bool, StateError> {
    Ok(engine_reports(state)?.iter().any(|(_, report)| {
        report.tag == *tag
            && report.digest == *digest
            && matches!(
                report.outcome,
                Outcome::RolledBack { .. }
                    | Outcome::FailedNoPrevious { .. }
                    | Outcome::RollbackFailed { .. }
            )
    }))
}

/// Deals with what a crash or a `recover` left of a deploy. With its marker
/// still there it goes on waiting for `recover`; holding the lock keeps a
/// running `recover` out of the way.
pub(super) fn settle_claim(state_dir: &Path, id: &DeploymentId) -> Result<(), StateError> {
    #[derive(Serialize)]
    struct Settled<'a> {
        event: &'static str,
        deployment: &'a DeploymentId,
        deploy_id: DeployId,
        found: &'static str,
    }
    let root = StateDir::open(state_dir)?;
    let state = root.deployment(id)?;
    let Some(claim) = state.claim()? else {
        return Ok(());
    };
    let _lock = match state.lock() {
        Ok(lock) => lock,
        Err(StateError::Busy(_)) => return Ok(()),
        Err(error) => return Err(error),
    };
    if state.in_progress()?.is_some() {
        return Ok(());
    }
    let body = if let Some(report) = latest_report(&state, &claim)? {
        Some(reported(claim.deploy_id, &report))
    } else {
        // No report, yet the record names the release: the engine got that far
        // and no further.
        state
            .deployed()?
            .filter(|deployed| deployed.tag == claim.tag && deployed.digest == claim.digest)
            .map(|_| DeployReportBody {
                deploy_id: claim.deploy_id,
                outcome: ReportedOutcome::Deployed {},
                steps: Vec::new(),
            })
    };
    let found = if body.is_some() {
        "report queued"
    } else {
        "never started; the controller delivers it again"
    };
    if let Some(body) = &body {
        root.finished_put(body)?;
        root.outbox_put(body)?;
    }
    journal::emit(
        Priority::Warning,
        &Settled {
            event: "deploy_claim_settled",
            deployment: id,
            deploy_id: claim.deploy_id,
            found,
        },
    );
    state.clear_claim()
}

/// How sending one report ended.
enum Delivery {
    /// Acknowledged, or refused for good; it has left the outbox.
    Gone,
    /// Not delivered; it stays in the outbox.
    Kept(String),
}

/// Sends one report. An acknowledged one is removed. So is one the API refuses
/// for good, loudly: repeating it can't help, and the ledger and the engine's own
/// copy stay. Anything else keeps it, whatever the status.
async fn send_report<C: Controller>(
    controller: &C,
    state_dir: &Path,
    report: &DeployReportBody,
) -> Delivery {
    #[derive(Serialize)]
    struct ReportEvent {
        event: &'static str,
        deploy_id: DeployId,
        error: Option<String>,
    }
    let event = |event, error| ReportEvent {
        event,
        deploy_id: report.deploy_id,
        error,
    };
    // Whatever is in the outbox, nothing over the limit goes out: the controller's
    // answer to that can arrive as a connection reset, which looks retryable and
    // would never end.
    let result = controller.report(&fit_to_the_wire(report.clone())).await;
    match &result {
        Ok(()) => journal::emit(Priority::Info, &event("report_delivered", None)),
        Err(error) if error.is_rejection() => journal::emit(
            Priority::Error,
            &event("report_rejected", Some(error.to_string())),
        ),
        Err(error) => {
            journal::emit(
                Priority::Warning,
                &event("report_kept", Some(error.to_string())),
            );
            return Delivery::Kept(error.to_string());
        }
    }
    let (dir, id) = (state_dir.to_owned(), report.deploy_id);
    let removed = on_thread("remove report", move || {
        StateDir::open(&dir)?.outbox_remove(id)
    })
    .await;
    if let Err(error) = removed {
        // It is sent again, and reports are idempotent by deploy id.
        journal::emit(Priority::Error, &event("report_not_removed", Some(error)));
    }
    Delivery::Gone
}

/// Sends what is in the outbox, oldest first, stopping at one that can't be
/// delivered now.
pub(super) async fn flush<C: Controller>(
    controller: &C,
    state_dir: &Path,
) -> Result<(), StepOutcome> {
    let dir = state_dir.to_owned();
    let pending = on_thread("read outbox", move || StateDir::open(&dir)?.outbox())
        .await
        .map_err(|error| StepOutcome::Failed { error })?;
    for report in &pending {
        if let Delivery::Kept(error) = send_report(controller, state_dir, report).await {
            return Err(StepOutcome::Unavailable { error });
        }
    }
    Ok(())
}

/// Records a finished report in the ledger and the outbox, releases the claim and
/// sends it.
pub(super) async fn finish<C: Controller>(
    controller: &C,
    state_dir: &Path,
    body: DeployReportBody,
    claimed: Option<&DeploymentId>,
) -> StepOutcome {
    #[derive(Serialize)]
    struct NotKept {
        event: &'static str,
        deploy_id: DeployId,
        error: String,
    }
    let (dir, copy, id) = (state_dir.to_owned(), body.clone(), claimed.cloned());
    let kept = on_thread("keep report", move || {
        let root = StateDir::open(&dir)?;
        root.finished_put(&copy)?;
        root.outbox_put(&copy)?;
        if let Some(id) = id {
            root.deployment(&id)?.clear_claim()?;
        }
        Ok(())
    })
    .await;
    if let Err(error) = kept {
        // A claim that stayed brings it back after this. A refusal has none, and
        // is asked for again by the controller if this send fails too.
        journal::emit(
            Priority::Critical,
            &NotKept {
                event: "report_not_kept",
                deploy_id: body.deploy_id,
                error,
            },
        );
    }
    let delivered = matches!(
        send_report(controller, state_dir, &body).await,
        Delivery::Gone
    );
    StepOutcome::Finished {
        deploy_id: body.deploy_id,
        outcome: body.outcome,
        delivered,
    }
}
