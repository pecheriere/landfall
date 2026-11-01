//! Bounding a deploy report before anything of it is stored.
//!
//! A report is never refused for its size, because a refused report would be
//! retried forever. Everything an agent sent is kept quoted and truncated with
//! [`shown`], and the number of steps and checks is capped, with the count of
//! what was dropped kept in its place.

use landfall_core::protocol::{
    DeployId, DeployReportBody, ReportedDetail, ReportedOutcome, ReportedStep,
};
use landfall_core::text::shown;
use serde_json::{Value, json};

/// The most steps stored for one deploy. A real deploy, rollback included, has
/// far fewer. The bound keeps the audit row under
/// [`MAX_DETAIL_BYTES`](crate::audit::MAX_DETAIL_BYTES) with hostile text in every
/// field: [`shown`] keeps 64 characters, each of which escapes to at most
/// `\\u{10ffff}` in the JSON of its quoted form, 11 bytes, so about 711 bytes a
/// field; a step has two text fields and some 60 bytes of its own, and 32 steps
/// are then at most 48 KiB.
pub const MAX_STORED_STEPS: usize = 32;

/// The most post-deploy checks stored for one deploy, across its steps.
pub const MAX_STORED_CHECKS: usize = 128;

/// One step, ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedStep {
    /// What was done, quoted and truncated.
    pub name: String,
    /// How long it took, clamped to what `SQLite` can hold.
    pub millis: i64,
    /// Why it failed, quoted and truncated.
    pub failure: Option<String>,
    /// More about the step, as JSON with its text quoted and truncated.
    pub detail: Option<String>,
}

/// A deploy report, ready to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BoundedReport {
    /// The deploy.
    pub deploy_id: DeployId,
    /// The outcome's stable name.
    pub outcome: &'static str,
    /// Whether the host refused the deploy.
    pub refused: bool,
    /// Why, quoted and truncated.
    pub reason: Option<String>,
    /// Why the rollback failed, quoted and truncated.
    pub rollback_reason: Option<String>,
    /// The first [`MAX_STORED_STEPS`] steps.
    pub steps: Vec<BoundedStep>,
    /// How many steps were left out.
    pub steps_dropped: usize,
    /// How many checks were left out.
    pub checks_dropped: usize,
}

/// A `millis` as `SQLite` can hold it. A value past the range is nonsense from a
/// hostile or broken agent, but it is no reason to lose the report.
fn clamped(millis: u64) -> i64 {
    i64::try_from(millis).unwrap_or(i64::MAX)
}

/// What to store for a step's detail, taking its checks from `checks_left`.
fn bounded_detail(
    detail: Option<&ReportedDetail>,
    checks_left: &mut usize,
    checks_dropped: &mut usize,
) -> Option<String> {
    let value = match detail? {
        ReportedDetail::Checks { checks } => {
            let kept = checks.len().min(*checks_left);
            *checks_left -= kept;
            *checks_dropped += checks.len() - kept;
            let checks: Vec<Value> = checks
                .iter()
                .take(kept)
                .map(|c| {
                    json!({
                        "check": shown(&c.check),
                        "attempts": c.attempts,
                        "millis": c.millis,
                    })
                })
                .collect();
            json!({ "kind": "checks", "checks": checks })
        }
        ReportedDetail::Backup {
            files,
            directories,
            symlinks,
            bytes,
        } => json!({
            "kind": "backup",
            "files": files,
            "directories": directories,
            "symlinks": symlinks,
            "bytes": bytes,
        }),
        // A kind added to the protocol later: nothing is known about how to
        // bound it, so it is not stored.
        _ => return None,
    };
    Some(value.to_string())
}

fn bounded_step(
    step: &ReportedStep,
    checks_left: &mut usize,
    checks_dropped: &mut usize,
) -> BoundedStep {
    BoundedStep {
        name: shown(&step.name),
        millis: clamped(step.millis),
        failure: step.failure.as_deref().map(shown),
        detail: bounded_detail(step.detail.as_ref(), checks_left, checks_dropped),
    }
}

impl BoundedReport {
    /// Quotes, truncates and caps `report`.
    #[must_use]
    pub fn new(report: &DeployReportBody) -> Self {
        let (outcome, reason, rollback_reason) = match &report.outcome {
            ReportedOutcome::Deployed {} => ("deployed", None, None),
            ReportedOutcome::RolledBack { reason } => ("rolled_back", Some(reason), None),
            ReportedOutcome::NothingChanged { reason } => ("nothing_changed", Some(reason), None),
            ReportedOutcome::FailedNoPrevious { reason } => {
                ("failed_no_previous", Some(reason), None)
            }
            ReportedOutcome::RollbackFailed {
                reason,
                rollback_reason,
            } => ("rollback_failed", Some(reason), Some(rollback_reason)),
            ReportedOutcome::Refused { reason } => ("refused", Some(reason), None),
            // An outcome added to the protocol later: the deploy did end, so
            // the report is kept without what is not understood.
            _ => ("unknown", None, None),
        };
        let mut checks_left = MAX_STORED_CHECKS;
        let mut checks_dropped = 0;
        let steps = report
            .steps
            .iter()
            .take(MAX_STORED_STEPS)
            .map(|step| bounded_step(step, &mut checks_left, &mut checks_dropped))
            .collect();
        Self {
            deploy_id: report.deploy_id,
            outcome,
            refused: matches!(report.outcome, ReportedOutcome::Refused { .. }),
            reason: reason.map(|text| shown(text)),
            rollback_reason: rollback_reason.map(|text| shown(text)),
            steps,
            steps_dropped: report.steps.len().saturating_sub(MAX_STORED_STEPS),
            checks_dropped,
        }
    }

    /// The audit row's detail: the outcome and every stored step by name, with
    /// failures. Check details stay in `deploy_steps`, so the row stays bounded.
    #[must_use]
    pub fn audit_detail(&self, tag: &str) -> Value {
        let steps: Vec<Value> = self
            .steps
            .iter()
            .map(|s| json!({ "name": s.name, "millis": s.millis, "failure": s.failure }))
            .collect();
        json!({
            "deploy_id": self.deploy_id,
            "tag": tag,
            "outcome": self.outcome,
            "reason": self.reason,
            "rollback_reason": self.rollback_reason,
            "steps": steps,
            "steps_dropped": self.steps_dropped,
            "checks_dropped": self.checks_dropped,
        })
    }
}

#[cfg(test)]
mod tests {
    use landfall_core::protocol::ReportedCheck;

    use super::*;
    use crate::audit::MAX_DETAIL_BYTES;

    /// Every character escapes as long as a character can in a quoted form.
    fn hostile(count: usize) -> String {
        "\u{10ffff}".repeat(count)
    }

    fn step(name: &str, failure: Option<&str>, detail: Option<ReportedDetail>) -> ReportedStep {
        ReportedStep {
            name: name.to_owned(),
            millis: 1,
            failure: failure.map(str::to_owned),
            detail,
        }
    }

    fn report(outcome: ReportedOutcome, steps: Vec<ReportedStep>) -> DeployReportBody {
        DeployReportBody {
            deploy_id: DeployId(7),
            outcome,
            steps,
        }
    }

    fn checks(count: usize) -> ReportedDetail {
        ReportedDetail::Checks {
            checks: vec![
                ReportedCheck {
                    check: "c".to_owned(),
                    attempts: 1,
                    millis: 1,
                };
                count
            ],
        }
    }

    #[test]
    fn the_worst_report_fits_the_audit_limit() {
        let text = hostile(1000);
        let steps = vec![step(&text, Some(&text), None); MAX_STORED_STEPS + 100];
        let bounded = BoundedReport::new(&report(
            ReportedOutcome::RollbackFailed {
                reason: text.clone(),
                rollback_reason: text.clone(),
            },
            steps,
        ));
        assert_eq!(bounded.steps.len(), MAX_STORED_STEPS);
        assert_eq!(bounded.steps_dropped, 100);
        let detail = bounded.audit_detail(&"t".repeat(128)).to_string();
        assert!(detail.len() < MAX_DETAIL_BYTES, "{}", detail.len());
        // It is the size the comment on MAX_STORED_STEPS says it is, so that
        // reasoning stays honest if `shown` changes.
        assert!(detail.len() < 48 * 1024, "{}", detail.len());
    }

    #[test]
    fn agent_text_is_quoted_and_truncated() {
        let bounded = BoundedReport::new(&report(
            ReportedOutcome::Refused {
                reason: format!("a\nb\u{1b}[31m{}", "x".repeat(100)),
            },
            vec![step("na\nme", Some("fa\u{1b}il"), None)],
        ));
        let reason = bounded.reason.unwrap();
        assert!(reason.starts_with("\"a\\nb\\u{1b}[31m"), "{reason}");
        assert!(reason.ends_with("\"..."), "{reason}");
        assert_eq!(bounded.steps[0].name, "\"na\\nme\"");
        assert_eq!(bounded.steps[0].failure.as_deref(), Some("\"fa\\u{1b}il\""));
        assert!(bounded.refused);
    }

    #[test]
    fn checks_are_capped_across_the_report() {
        let steps = vec![step("checks", None, Some(checks(64))); 3];
        let bounded = BoundedReport::new(&report(ReportedOutcome::Deployed {}, steps));
        assert_eq!(bounded.checks_dropped, 64);
        let stored: Vec<usize> = bounded
            .steps
            .iter()
            .map(|s| {
                let detail: Value = serde_json::from_str(s.detail.as_deref().unwrap()).unwrap();
                detail["checks"].as_array().unwrap().len()
            })
            .collect();
        assert_eq!(stored, [64, 64, 0]);
    }

    #[test]
    fn millis_past_the_range_are_clamped() {
        let mut long = step("s", None, None);
        long.millis = u64::MAX;
        let bounded = BoundedReport::new(&report(ReportedOutcome::Deployed {}, vec![long]));
        assert_eq!(bounded.steps[0].millis, i64::MAX);
    }
}
