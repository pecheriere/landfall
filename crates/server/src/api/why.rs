//! Why a deploy ended as it did, or where it stands if it hasn't: one pure function over the
//! deploy and the steps its host reported.
//!
//! The events come in time order: who asked and who signed, if it came from a request, then
//! the queue, its host taking it, each step, and the outcome. The summary is one sentence an
//! agent can act on, naming the tag and the host, and `next` the one thing to do. The host is
//! named only to a reader who may see it, as `getHost` shows it, and is otherwise "a host you
//! can't view". The host's
//! words are shown as they were stored, quoted when they were recorded; only the deploy's own
//! deployment is concerned, which whoever reads this may view.

use landfall_api::{DeployState, NextAction, NextKind, Outcome, Why, WhyEvent, WhyKind};
use landfall_core::ids::HostId;

use super::story::with_reason;
use crate::store::history::{DeployRow, StepRow};

fn event(at: Option<i64>, what: WhyKind, text: String) -> WhyEvent {
    WhyEvent { at, what, text }
}

fn next(kind: NextKind, detail: String) -> NextAction {
    NextAction { kind, detail }
}

/// What a host the reader can't see is called: they are never told its name.
pub(crate) const UNSEEN_HOST: &str = "a host you can't view";

/// What happened to `deploy`, its steps being `steps`, why, and what to do next. `host` is
/// the deploy's host as the reader may see it: `None` names it [`UNSEEN_HOST`].
#[must_use]
pub(crate) fn explain(deploy: &DeployRow, steps: &[StepRow], host: Option<&HostId>) -> Why {
    let host = host.map_or_else(|| UNSEEN_HOST.to_owned(), ToString::to_string);
    let host = host.as_str();
    let mut events = asked(deploy, host);
    events.extend(steps.iter().map(step_event));
    let reason = deploy.reason.as_deref().unwrap_or("");
    if let Some(outcome) = deploy.outcome {
        let (what, text) = ended(deploy, host, outcome, reason);
        events.push(event(deploy.finished_at, what, text));
    }
    let failed_at = steps
        .iter()
        .find(|step| step.failure.is_some())
        .map_or_else(String::new, |step| format!(" at step {}", step.name));
    let (summary, next) = said(deploy, host, reason, &failed_at);
    Why {
        deploy: deploy.id,
        outcome: deploy.outcome,
        summary,
        events,
        next,
    }
}

/// Who asked for it and who signed it, if anyone did, then its queue and its host taking it.
fn asked(deploy: &DeployRow, host: &str) -> Vec<WhyEvent> {
    let mut events = Vec::new();
    if let Some(by) = &deploy.requested_by {
        let number = deploy
            .request_id
            .map_or_else(String::new, |id| format!(" in request {id}"));
        events.push(event(
            deploy.requested_at,
            WhyKind::Requested,
            format!("{by} asked for {}{number}", deploy.tag),
        ));
    }
    if let Some(by) = &deploy.approved_by {
        events.push(event(
            Some(deploy.created_at),
            WhyKind::Approved,
            format!("{by} signed the request with a passkey"),
        ));
    }
    let queued = if deploy.request_id.is_some() {
        format!("the controller queued it for {host}")
    } else {
        format!("the controller queued it for {host} by itself, as the deployment's rule allows")
    };
    events.push(event(Some(deploy.created_at), WhyKind::Queued, queued));
    if let Some(at) = deploy.claimed_at {
        events.push(event(Some(at), WhyKind::Claimed, format!("{host} took it")));
    }
    events
}

fn step_event(step: &StepRow) -> WhyEvent {
    let (name, millis) = (&step.name, step.millis);
    match &step.failure {
        None => event(None, WhyKind::Step, format!("{name} took {millis} ms")),
        Some(failure) => event(
            None,
            WhyKind::StepFailed,
            format!("{name} failed after {millis} ms: {failure}"),
        ),
    }
}

/// The last event: how it ended, in the host's words.
fn ended(deploy: &DeployRow, host: &str, outcome: Outcome, reason: &str) -> (WhyKind, String) {
    match outcome {
        Outcome::Deployed => (WhyKind::Finished, format!("it runs on {host}")),
        Outcome::RolledBack => (
            WhyKind::RolledBack,
            with_reason(
                &format!("it failed, and {host} went back to what ran before"),
                reason,
            ),
        ),
        Outcome::NothingChanged => (
            WhyKind::Finished,
            with_reason(
                &format!("it stopped before anything changed on {host}"),
                reason,
            ),
        ),
        Outcome::FailedNoPrevious => (
            WhyKind::Finished,
            with_reason(
                &format!("it failed, with nothing on {host} to go back to"),
                reason,
            ),
        ),
        Outcome::RollbackFailed => {
            let back = deploy.rollback_reason.as_deref().unwrap_or("");
            (
                WhyKind::RollbackFailed,
                format!(
                    "{}; {}",
                    with_reason("it failed", reason),
                    with_reason(
                        &format!("going back to what ran before on {host} failed too"),
                        back
                    ),
                ),
            )
        }
        Outcome::Refused => (
            WhyKind::HostRefused,
            with_reason(&format!("{host} refused it"), reason),
        ),
        Outcome::Deferred => (
            WhyKind::Deferred,
            with_reason(&format!("{host} said not now"), reason),
        ),
        Outcome::Unknown => (WhyKind::Finished, format!("{host} said how it went")),
    }
}

/// The summary and the next action: by the outcome once it finished, and by its state until
/// then.
fn said(
    deploy: &DeployRow,
    host: &str,
    reason: &str,
    failed_at: &str,
) -> (String, Option<NextAction>) {
    let tag = &deploy.tag;
    let not_retried = "it won't be retried automatically";
    match (deploy.state, deploy.outcome) {
        (DeployState::Queued, _) => (
            format!("{tag} is queued for {host}, which hasn't taken it yet"),
            Some(next(NextKind::Wait, format!("wait for {host} to take it"))),
        ),
        (DeployState::Claimed, _) => (
            format!("{host} is deploying {tag}"),
            Some(next(
                NextKind::Wait,
                format!("wait for {host} to say how it went"),
            )),
        ),
        (_, Some(Outcome::Deployed)) => (
            format!("{tag} deployed on {host} and runs there"),
            Some(next(NextKind::None, "nothing: it runs".to_owned())),
        ),
        (_, Some(Outcome::RolledBack)) => (
            format!(
                "{tag} failed on {host}{failed_at} and rolled back to the previous version; \
                 {not_retried}"
            ),
            Some(ask_again(deploy)),
        ),
        (_, Some(Outcome::FailedNoPrevious)) => (
            format!(
                "{tag} failed on {host}{failed_at} with no previous version to go back to, so \
                 nothing of it may be running there; {not_retried}"
            ),
            Some(ask_again(deploy)),
        ),
        (_, Some(Outcome::RollbackFailed)) => (
            format!(
                "{tag} failed on {host}{failed_at}, and so did rolling back to the previous \
                 version, so the host may be left half-way; {not_retried}"
            ),
            Some(next(
                NextKind::Recover,
                format!(
                    "run `landfall-agent recover` on {host}, then look at what runs there before \
                     asking for anything"
                ),
            )),
        ),
        (_, Some(Outcome::Refused)) => (
            with_reason(&format!("{host} refused {tag}"), reason),
            Some(next(
                NextKind::FixHost,
                format!(
                    "{}. A host refusing what the controller sent it is an alert: the host's \
                     configuration and the controller's disagree. Fix the host or its \
                     configuration before asking again",
                    with_reason(&format!("{host} refused it"), reason)
                ),
            )),
        ),
        (_, Some(Outcome::Deferred)) => (
            format!("{host} said not now to {tag}; the controller asks it again after a while"),
            Some(next(
                NextKind::Wait,
                format!("wait: the controller asks {host} again after a while"),
            )),
        ),
        (_, Some(Outcome::NothingChanged)) => (
            format!(
                "{tag} stopped on {host}{failed_at} before anything changed, so what ran before \
                 still runs"
            ),
            Some(next(
                NextKind::Wait,
                with_reason(
                    "wait for the controller to try it again, and if it keeps stopping, see why",
                    reason,
                ),
            )),
        ),
        (_, Some(Outcome::Unknown) | None) => (
            format!("{tag} on {host} is in a state this controller can't explain"),
            None,
        ),
    }
}

/// After a failed deploy: ask again, for a newer release or this one.
fn ask_again(deploy: &DeployRow) -> NextAction {
    next(
        NextKind::Request,
        format!(
            "once the cause is fixed, ask for a newer release, or for {} again, with `landfall \
             request`; a retry is deployed only once an approver signs it",
            deploy.tag
        ),
    )
}
