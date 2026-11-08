//! Where a release stands, and why: one pure function over what is known of it, with a fixed
//! precedence. The first status that applies wins, in this order:
//!
//! 1. `running`: its host runs this tag at this digest.
//! 2. `deploying`: a deploy of it is queued or claimed.
//! 3. `awaiting_approval`: a request for it waits for an approver.
//! 4. `refused`: verification or the rule refused it.
//! 5. `held`: a hold on it, or on the whole deployment.
//! 6. `superseded`: a higher version runs. A rollback to it is the next thing to do when
//!    asking is how it would deploy.
//! 7. `failed`: its last finished deploy rolled back, or failed with nothing to go back to,
//!    or failed and so did going back. It isn't tried again by itself.
//! 8. `host_refused`: its last finished deploy was refused by its host.
//! 9. `deferred`: its host said not now.
//! 10. `promotion_pending`: it waits to be healthy for long enough where it is promoted from.
//! 11. `needs_request`: it deploys only when someone asks.
//! 12. `waiting`: it deploys by itself, and nothing known stands in the way.
//!
//! Each status comes with its reasons, in order, and one next action. Reasons and actions are
//! the controller's own words, with the stored text they quote: a hold's or a host's reason,
//! or a decision's where it is what decided, each quoted when it was recorded. A deployment
//! is named only as the reader may see it.

use std::borrow::Cow;

use landfall_api::ReleaseStatus;
use landfall_api::{Decision as ApiDecision, DeploymentRef, NextAction, NextKind, Outcome};
use landfall_core::ids::{ImageDigest, ReleaseTag};
use landfall_core::rule::{Decision, reason as rule_reason};
use semver::Version;

use crate::store::views::RunningRow;
use crate::store::{Hold, ReleaseDecision};

/// What a release's status is decided from.
#[derive(Debug, Clone)]
pub(crate) struct StoryInputs<'a> {
    /// The release's tag.
    pub(crate) tag: &'a ReleaseTag,
    /// Its digest, if it verified.
    pub(crate) digest: Option<&'a ImageDigest>,
    /// The decision the status goes by: see [`decided`].
    pub(crate) decision: ApiDecision,
    /// Why it was decided so: see [`decided`].
    pub(crate) decision_reason: &'a str,
    /// What its deployment's host last said, if that host is the deployment's now.
    pub(crate) running: Option<&'a RunningRow>,
    /// Whether a deploy of it is queued or claimed.
    pub(crate) active_deploy: bool,
    /// Whether a request for it waits for an approver.
    pub(crate) open_request: bool,
    /// The hold on it, or else the one on the whole deployment.
    pub(crate) hold: Option<&'a Hold>,
    /// How its last finished deploy at this digest went, with what its host said, quoted.
    pub(crate) last_outcome: Option<(Outcome, &'a str)>,
    /// The deployment its promotion waits for, as this principal may name it.
    pub(crate) promotion_waits_for: Option<DeploymentRef>,
    /// Whether it is a lower version than the one running.
    pub(crate) lower_than_running: bool,
}

/// A release's status, why, and what to do next.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct StatusExplained {
    /// Where it stands.
    pub(crate) status: ReleaseStatus,
    /// Why, in order.
    pub(crate) reasons: Vec<String>,
    /// What to do next.
    pub(crate) next: Option<NextAction>,
}

/// The decision the watcher recorded, as the API names it.
#[must_use]
pub(crate) fn recorded(decision: ReleaseDecision) -> ApiDecision {
    match decision {
        ReleaseDecision::Auto => ApiDecision::Auto,
        ReleaseDecision::NeedsApproval => ApiDecision::NeedsApproval,
        ReleaseDecision::Manual => ApiDecision::Manual,
        ReleaseDecision::Refused => ApiDecision::Refused,
        ReleaseDecision::Deferred => ApiDecision::Deferred,
    }
}

/// What the rule said of a release, and of what versions: `candidate` over `running`, or
/// over nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct RuleSaid<'v> {
    /// What [`decide`](landfall_core::rule::decide) said.
    pub(crate) decision: Decision,
    /// The running version, if anything runs.
    pub(crate) running: Option<&'v Version>,
    /// The release's version.
    pub(crate) candidate: &'v Version,
}

/// The decision a status goes by, and the reason that decided it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Decided<'a> {
    /// The decision.
    pub(crate) decision: ApiDecision,
    /// Why: the rule's words, or a stored reason where that is what decided.
    pub(crate) reason: Cow<'a, str>,
}

/// The decision a status goes by, and why: a refusal by verification, with its stored
/// reason; then what the rule says with what runs now (`rule`, `None` when either version
/// can't be read), in the rule's words. What the watcher recorded of the release's deploys
/// is told by the status from the deploys themselves, as asking leaves a retry to an
/// approver: so a release the watcher refused for what became of it, and that the rule
/// wouldn't refuse, now deploys only when someone asks, for the stored reason, one of the
/// watcher's fixed texts. Without the rule's word, what the watcher recorded, in words of its
/// own. Any other stored reason is never shown: it may say what has changed since, and the
/// one promotion left names the deployment promoted from, which a reader may not view.
#[must_use]
pub(crate) fn decided<'a>(
    stored: ReleaseDecision,
    stored_reason: &'a str,
    origin_refused: bool,
    rule: Option<RuleSaid<'_>>,
) -> Decided<'a> {
    let stored_says = |decision| Decided {
        decision,
        reason: Cow::Borrowed(stored_reason),
    };
    let rule_says = |decision, reason: &'static str| Decided {
        decision,
        reason: Cow::Borrowed(reason),
    };
    if origin_refused {
        return stored_says(ApiDecision::Refused);
    }
    // A refusal the rule didn't make, nor verification, is the watcher's, for the release's
    // past deploys.
    let by_history = stored == ReleaseDecision::Refused;
    // The rule's word decides, but where the watcher refused for history what the rule
    // would deploy by itself.
    if let Some(said) = rule.filter(|said| !(by_history && said.decision == Decision::Auto)) {
        let decision = match said.decision {
            Decision::Auto => ApiDecision::Auto,
            Decision::NeedsApproval => ApiDecision::NeedsApproval,
            Decision::Manual => ApiDecision::Manual,
            Decision::Refused(_) => ApiDecision::Refused,
        };
        return rule_says(
            decision,
            rule_reason(said.decision, said.running, said.candidate),
        );
    }
    match stored {
        _ if by_history => stored_says(ApiDecision::Manual),
        ReleaseDecision::Auto => rule_says(ApiDecision::Auto, "it deploys by itself"),
        ReleaseDecision::NeedsApproval => {
            rule_says(ApiDecision::NeedsApproval, "it needs an approver")
        }
        ReleaseDecision::Manual | ReleaseDecision::Refused => {
            rule_says(ApiDecision::Manual, "it deploys only when someone asks")
        }
        ReleaseDecision::Deferred => rule_says(ApiDecision::Deferred, "its host said not now"),
    }
}

fn next(kind: NextKind, detail: impl Into<String>) -> NextAction {
    NextAction {
        kind,
        detail: detail.into(),
    }
}

fn explained(status: ReleaseStatus, reasons: Vec<String>, next: NextAction) -> StatusExplained {
    StatusExplained {
        status,
        reasons,
        next: Some(next),
    }
}

/// `what`, and the stored words after it when there are any.
pub(super) fn with_reason(what: &str, reason: &str) -> String {
    if reason.is_empty() {
        what.to_owned()
    } else {
        format!("{what}: {reason}")
    }
}

/// What a failed deploy did, and what to do about it.
fn failure(outcome: Outcome, tag: &ReleaseTag) -> Option<(&'static str, NextAction)> {
    match outcome {
        Outcome::RolledBack => Some((
            "its last deploy failed, and its host went back to what ran before",
            next(
                NextKind::Request,
                format!("once the cause is fixed, ask for {tag} again with `landfall request`"),
            ),
        )),
        Outcome::FailedNoPrevious => Some((
            "its last deploy failed, with nothing on its host to go back to",
            next(
                NextKind::Recover,
                "nothing may be running: look at its host, then ask again with `landfall request`",
            ),
        )),
        Outcome::RollbackFailed => Some((
            "its last deploy failed, and so did going back to what ran before",
            next(
                NextKind::Recover,
                "its host may be left half-way: look at it before asking for anything",
            ),
        )),
        _ => None,
    }
}

/// Where the release `inputs` describes stands, why, and what to do next: the first status
/// that applies, in the module's order.
#[must_use]
pub(crate) fn status(inputs: &StoryInputs<'_>) -> StatusExplained {
    under_way(inputs)
        .or_else(|| stopped(inputs))
        .or_else(|| after_its_deploys(inputs))
        .unwrap_or_else(|| ahead(inputs))
}

/// `running`, `deploying` and `awaiting_approval`: what is already happening to it.
fn under_way(inputs: &StoryInputs<'_>) -> Option<StatusExplained> {
    let runs_it = inputs.running.is_some_and(|row| {
        inputs.digest.is_some()
            && row.running.tag.as_ref() == Some(inputs.tag)
            && row.running.digest.as_ref() == inputs.digest
    });
    if runs_it {
        return Some(explained(
            ReleaseStatus::Running,
            vec!["its host runs it".to_owned()],
            next(NextKind::None, "nothing: it runs"),
        ));
    }
    if inputs.active_deploy {
        return Some(explained(
            ReleaseStatus::Deploying,
            vec!["a deploy of it is queued or running on its host".to_owned()],
            next(
                NextKind::Wait,
                "wait for its host to say how the deploy went",
            ),
        ));
    }
    inputs.open_request.then(|| {
        explained(
            ReleaseStatus::AwaitingApproval,
            vec!["a request for it waits for an approver".to_owned()],
            next(
                NextKind::Approve,
                "an approver signs it with a passkey on the controller's approval page; \
                 agents can't approve",
            ),
        )
    })
}

/// `refused`, `held` and `superseded`: what stands in its way before its past deploys count.
fn stopped(inputs: &StoryInputs<'_>) -> Option<StatusExplained> {
    if inputs.decision == ApiDecision::Refused {
        return Some(explained(
            ReleaseStatus::Refused,
            vec![with_reason("refused", inputs.decision_reason)],
            next(
                NextKind::None,
                "nothing: a refused release is never deployed",
            ),
        ));
    }
    if let Some(hold) = inputs.hold {
        return Some(explained(
            ReleaseStatus::Held,
            vec![
                with_reason("held", hold.reason()),
                "the controller tries it again by itself".to_owned(),
            ],
            next(NextKind::Wait, "wait for the controller to try it again"),
        ));
    }
    if !inputs.lower_than_running {
        return None;
    }
    let running = inputs
        .running
        .and_then(|row| row.running.tag.as_ref())
        .map_or_else(
            || "a higher version runs".to_owned(),
            |running| format!("a higher version, {running}, runs"),
        );
    let then = if matches!(
        inputs.decision,
        ApiDecision::NeedsApproval | ApiDecision::Manual
    ) {
        next(
            NextKind::Rollback,
            format!(
                "to go back to {}, ask for a rollback with `landfall rollback`",
                inputs.tag
            ),
        )
    } else {
        next(NextKind::None, "nothing: a higher version runs")
    };
    Some(explained(ReleaseStatus::Superseded, vec![running], then))
}

/// `failed`, `host_refused` and `deferred`: what its last deploy says.
fn after_its_deploys(inputs: &StoryInputs<'_>) -> Option<StatusExplained> {
    if let Some((outcome, reason)) = inputs.last_outcome {
        if let Some((what, then)) = failure(outcome, inputs.tag) {
            return Some(explained(
                ReleaseStatus::Failed,
                vec![
                    with_reason(what, reason),
                    "it isn't tried again by itself".to_owned(),
                ],
                then,
            ));
        }
        if outcome == Outcome::Refused {
            return Some(explained(
                ReleaseStatus::HostRefused,
                vec![with_reason("its host refused it", reason)],
                next(
                    NextKind::FixHost,
                    "see why its host refused it, and fix the host or its configuration",
                ),
            ));
        }
    }
    let deferred_by_host = inputs
        .last_outcome
        .filter(|(outcome, _)| *outcome == Outcome::Deferred);
    (inputs.decision == ApiDecision::Deferred || deferred_by_host.is_some()).then(|| {
        let reason = deferred_by_host.map_or("", |(_, reason)| reason);
        explained(
            ReleaseStatus::Deferred,
            vec![with_reason("its host said not now", reason)],
            next(
                NextKind::Wait,
                "wait: the controller asks its host again after a while",
            ),
        )
    })
}

/// `promotion_pending`, `needs_request` and `waiting`: what is left for it.
fn ahead(inputs: &StoryInputs<'_>) -> StatusExplained {
    let tag = inputs.tag;
    if let Some(source) = &inputs.promotion_waits_for {
        return explained(
            ReleaseStatus::PromotionPending,
            vec![format!(
                "it waits to be reported healthy for long enough on {source}, which it is \
                 promoted from (enforced by the controller only)"
            )],
            next(
                NextKind::Wait,
                format!("wait for it to stay healthy on {source}"),
            ),
        );
    }
    match inputs.decision {
        ApiDecision::NeedsApproval => explained(
            ReleaseStatus::NeedsRequest,
            vec![inputs.decision_reason.to_owned()],
            next(
                NextKind::Request,
                format!(
                    "ask for a deploy of {tag} with `landfall request`; an approver then signs it"
                ),
            ),
        ),
        ApiDecision::Manual => explained(
            ReleaseStatus::NeedsRequest,
            vec![inputs.decision_reason.to_owned()],
            next(
                NextKind::Request,
                format!("ask for a deploy of {tag} with `landfall request`"),
            ),
        ),
        _ => explained(
            ReleaseStatus::Waiting,
            vec!["it deploys by itself once its host can take it".to_owned()],
            next(NextKind::Wait, "wait: nothing known stands in the way"),
        ),
    }
}
