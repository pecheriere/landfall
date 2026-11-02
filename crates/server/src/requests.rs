//! Asking for a deploy and approving one: `POST /api/v1/deployments/{id}/requests`,
//! `GET /api/v1/approvals`, `POST /api/v1/approvals/{id}` and `POST
//! /api/v1/approvals/{id}/cancel`.
//!
//! The controller carries an approval and can't make one. What it does here is keep the
//! gate: who may ask, who may sign, and that what reaches a host was signed, by that
//! person, for exactly what the controller means to run. The host checks all of it again.
//!
//! A request is its own row and not a deploy: `store/requests.rs` and the migration say why
//! and what its states are. The intent is the controller's, from its own records: a fresh
//! random nonce, `expected_running` from the host's last report, and the commit and digest
//! the watcher verified. A client names a tag and nothing else. A deployment has one host
//! by the configuration, so a request and its running digest are for that host.
//!
//! What a request takes:
//!
//! - a record of the release from the watcher, for this configuration, that verified and
//!   hasn't been refused or put on hold since. A tag the controller doesn't know, or
//!   several runs for one tag, which the watcher records as a refusal, are all refused
//!   alike. Only the watcher goes to the network: it enumerates a non-automatic release's
//!   runs once, so a second run that came since is left for the host to refuse.
//! - what the rule says, with what runs now. `Refused` stays refused. A downgrade, the
//!   manual rollback, takes the `rollback` grant; all else takes `request`. Whatever the
//!   watcher recorded of it from its history doesn't count, since retrying a release that
//!   failed is what an approval is for.
//! - promotion, as the watcher goes by it, but for a rollback, which must not have to wait.
//!   Promotion is the controller's alone to enforce, so it is looked at when asking and
//!   again when approving, each time in the transaction.
//! - no other request open, no deploy active, and a host that can take it. A rollback by
//!   someone with the `rollback` grant takes an open request's place, cancelling it in the
//!   same transaction: nobody's forgotten or stolen request gets to stand in its way.
//!
//! Each refusal someone can be held to has an audit row, in the transaction of whatever
//! else it changed. Handlers take a [`Principal`] first and read a body only after it may
//! ask, so nobody else gets a body read.

mod approving;
mod asking;
mod cancelling;

use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header;
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_core::config::{Config, Deployment, Permission};
use landfall_core::ids::{DeploymentId, HostId, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::text::shown;
use serde::Serialize;
use serde_json::json;
use sqlx::{Sqlite, Transaction};

use crate::agent_api::{ApiProblem, ApiState, deadline, json as json_answer, read_body};
use crate::audit::{AuditEvent, EventKind};
use crate::auth::{HumanProblem, Principal, can, sees};
use crate::store::{RequestSnapshot, RequestState, StoreError, StoredRequest, WatchedRunning};

const BAD_BODY: &str = "the body is not a valid request";
const UNREADABLE_BODY: &str = "the body could not be read within its limits";

/// A request, as a principal may see it, with what a passkey signs.
#[derive(Debug, Serialize)]
struct RequestView<'a> {
    id: i64,
    host: &'a HostId,
    intent: &'a DeployIntent,
    challenge: String,
    state: &'static str,
    requested_by: &'a PrincipalId,
    created_at: i64,
    expires_at: i64,
    can_approve: bool,
}

fn view(request: &StoredRequest, can_approve: bool) -> RequestView<'_> {
    RequestView {
        id: request.id,
        host: &request.host,
        intent: &request.intent,
        challenge: URL_SAFE_NO_PAD.encode(request.intent.challenge()),
        state: "awaiting_approval",
        requested_by: &request.requested_by,
        created_at: request.created_at,
        expires_at: request.expires_at,
        can_approve,
    }
}

fn no_store() -> [(header::HeaderName, &'static str); 1] {
    [(header::CACHE_CONTROL, "no-store")]
}

/// What was refused and why. The reason is the controller's own text, or quoted.
#[derive(Debug)]
struct Refused {
    problem: HumanProblem,
    reason: String,
}

/// Why a step in a transaction went no further.
#[derive(Debug)]
enum Stop {
    /// A refusal to answer and to record, with what the transaction did so far.
    Refused(Refused),
    /// A failure, which rolls the transaction back.
    Store(StoreError),
}

impl From<StoreError> for Stop {
    fn from(error: StoreError) -> Self {
        Self::Store(error)
    }
}

fn refused(problem: HumanProblem, reason: &str) -> Stop {
    Stop::Refused(Refused {
        problem,
        reason: reason.to_owned(),
    })
}

/// What a refusal's audit row says the refusal was of.
#[derive(Debug, Clone, Copy)]
struct Subject<'a> {
    kind: EventKind,
    deployment: Option<&'a Deployment>,
    /// What the client named, quoted, when it may not be real.
    about: Option<&'a str>,
    /// The request refused, if it came to one.
    request: Option<i64>,
    tag: Option<&'a ReleaseTag>,
}

fn refusal_event(principal: &Principal, subject: Subject<'_>, refusal: &Refused) -> AuditEvent {
    AuditEvent {
        kind: subject.kind,
        deployment: subject.deployment.map(|d| d.id().clone()),
        host: subject.deployment.map(|d| d.host().clone()),
        detail: json!({
            "by": principal.audited(),
            "about": subject.about.map(shown),
            "request": subject.request,
            "tag": subject.tag,
            "problem": refusal.problem.code(),
            "reason": refusal.reason,
        }),
    }
}

/// Records a refusal on its own and gives the answer to it. If that can't be recorded, the
/// answer says so instead, and what was asked is still refused.
async fn refuse_alone(
    state: &ApiState,
    principal: &Principal,
    subject: Subject<'_>,
    problem: HumanProblem,
    reason: &str,
) -> HumanProblem {
    let refusal = Refused {
        problem,
        reason: reason.to_owned(),
    };
    match state
        .store()
        .record(&refusal_event(principal, subject, &refusal))
        .await
    {
        Ok(()) => problem,
        Err(error) => error.into(),
    }
}

/// Ends a transaction that refused: what it changed, with the refusal's row, or nothing.
async fn refuse_in(
    state: &ApiState,
    mut tx: Transaction<'_, Sqlite>,
    principal: &Principal,
    subject: Subject<'_>,
    refusal: &Refused,
) -> Result<(), StoreError> {
    state
        .store()
        .append(&mut tx, &refusal_event(principal, subject, refusal))
        .await?;
    tx.commit().await?;
    Ok(())
}

/// Reads and parses a body within `limit`. `Err` is the problem and why.
async fn parsed_body<T: serde::de::DeserializeOwned>(
    state: &ApiState,
    body: Body,
    limit: usize,
) -> Result<T, (HumanProblem, &'static str)> {
    let bytes = read_body(body, limit, state.limits().body_timeout)
        .await
        .map_err(|problem| (HumanProblem::from(problem), UNREADABLE_BODY))?;
    serde_json::from_slice(&bytes)
        .map_err(|_| (HumanProblem::from(ApiProblem::BadRequest), BAD_BODY))
}

/// Refuses unless the host reported this deployment and can take a deploy now.
fn ready_host(snapshot: &RequestSnapshot) -> Result<&WatchedRunning, Stop> {
    let not_ready = |reason| refused(HumanProblem::HostNotReady, reason);
    let Some(running) = &snapshot.running else {
        return Err(not_ready("its host has not reported this deployment"));
    };
    if running.drift {
        return Err(not_ready(
            "the running state differs from what the agent deployed",
        ));
    }
    if snapshot.config_drifted {
        return Err(not_ready(
            "its host's configuration differs from the controller's",
        ));
    }
    if running.busy || running.phase != "idle" {
        return Err(not_ready(
            "its host has a deploy in progress, or one waiting for recovery",
        ));
    }
    Ok(running)
}

/// A 403 for someone who may know this deployment exists, and for anyone else the same 404
/// as for one that doesn't.
fn visibility(
    config: &Config,
    principal: &Principal,
    deployment: Option<&DeploymentId>,
) -> HumanProblem {
    if deployment.is_some_and(|d| sees(config, principal, d)) {
        HumanProblem::Forbidden
    } else {
        HumanProblem::NotFound
    }
}

/// A request number as a path has it: plain digits with no leading zero, so that one
/// request has one path.
fn request_number(raw: &str) -> Option<i64> {
    let canonical = !raw.starts_with('0') && raw.bytes().all(|b| b.is_ascii_digit());
    canonical.then(|| raw.parse().ok()).flatten()
}

/// The request a path names, as it is now.
async fn named_request(state: &ApiState, raw: &str) -> Result<Option<StoredRequest>, StoreError> {
    match request_number(raw) {
        Some(id) => state.store().request(id).await,
        None => Ok(None),
    }
}

/// Why this state can't be approved or cancelled, if it can't.
fn closed(state: RequestState) -> Option<(HumanProblem, &'static str)> {
    match state {
        RequestState::AwaitingApproval => None,
        RequestState::Approved => Some((
            HumanProblem::RequestClosed,
            "the request was already approved",
        )),
        RequestState::Stale => Some((
            HumanProblem::RequestStale,
            "what is running changed since the request was made",
        )),
        RequestState::Expired => Some((
            HumanProblem::RequestExpired,
            "no approver signed the request in time",
        )),
        RequestState::Cancelled => {
            Some((HumanProblem::RequestCancelled, "the request was cancelled"))
        }
    }
}

/// `GET /api/v1/approvals`: what this principal may see that waits for an approver, each
/// saying whether they could sign it. Changes nothing. A request past its time is left out
/// here, whether or not the next tick of the watcher has ended it yet.
async fn list(
    State(state): State<ApiState>,
    principal: Principal,
) -> Result<Response, HumanProblem> {
    let config = state.config();
    let open = state.store().open_requests(state.store().now()?).await?;
    let views: Vec<RequestView<'_>> = open
        .iter()
        .filter_map(|request| {
            let id = &request.intent.deployment;
            let approves = can(config, &principal, id, Permission::Approve);
            (approves || can(config, &principal, id, Permission::View))
                .then(|| view(request, approves))
        })
        .collect();
    Ok(json_answer(&json!({ "approvals": views }), &no_store()))
}

async fn not_found() -> HumanProblem {
    HumanProblem::NotFound
}

async fn method_not_allowed() -> HumanProblem {
    HumanProblem::MethodNotAllowed
}

/// The API's routes, with every answer `application/problem+json` that isn't a success.
pub(crate) fn router(state: ApiState) -> Router {
    let limit = state.limits().request_timeout;
    Router::new()
        .route(
            "/api/v1/deployments/{name}/{stage}/requests",
            post(asking::ask),
        )
        .route("/api/v1/approvals", get(list))
        .route("/api/v1/approvals/{id}", post(approving::approve))
        .route("/api/v1/approvals/{id}/cancel", post(cancelling::cancel))
        .route("/api/v1", any(not_found))
        .route("/api/v1/", any(not_found))
        .route("/api/v1/{*rest}", any(not_found))
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn_with_state(limit, deadline))
}

#[cfg(test)]
mod tests;
