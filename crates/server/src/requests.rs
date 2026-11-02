//! Asking for a deploy and approving one: `POST /api/v1/deployments/{id}/requests`,
//! `GET /api/v1/approvals` and `POST /api/v1/approvals/{id}`.
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
//!   Promotion is the controller's alone to enforce. It is read just before the
//!   transaction, as a store on one connection could not read it during one.
//! - no other request open, no deploy active, and a host that can take it.
//!
//! Each refusal someone can be held to has an audit row, in the transaction of whatever
//! else it changed. Handlers take a [`Principal`] first and read a body only after it may
//! ask, so nobody else gets a body read.

use axum::Router;
use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::{StatusCode, header};
use axum::middleware;
use axum::response::Response;
use axum::routing::{any, get, post};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{
    Assertion, CoseKey, Expect, MAX_AUTHENTICATOR_DATA_BYTES, MAX_CLIENT_DATA_BYTES,
    MAX_SIGNATURE_BYTES, verify,
};
use landfall_core::config::{Config, Deployment, MAX_CREDENTIAL_ID_LEN, Permission};
use landfall_core::ids::{DeploymentId, HostId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{Approval, AssertionText};
use landfall_core::rule::{Decision, decide};
use landfall_core::text::{quoted, shown};
use semver::Version;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sqlx::{Sqlite, Transaction};

use crate::agent_api::{ApiProblem, ApiState, deadline, json as json_answer, read_body};
use crate::audit::{AuditEvent, EventKind};
use crate::auth::{HumanProblem, Principal, can, sees};
use crate::report::REFUSAL_SHOWN_CHARS;
use crate::store::{
    NewRequest, RequestSnapshot, RequestState, StoreError, StoredRequest, WatchedRunning,
};
use crate::watcher::promotion_waits_for;

/// A request is one tag, at most 128 bytes.
const MAX_REQUEST_BODY_BYTES: usize = 1024;

/// An assertion at the limits of every field, in base64url and JSON, leaves room in this.
const MAX_APPROVAL_BODY_BYTES: usize = 32 * 1024;

const _: () = assert!(
    (MAX_CREDENTIAL_ID_LEN
        + MAX_AUTHENTICATOR_DATA_BYTES
        + MAX_CLIENT_DATA_BYTES
        + MAX_SIGNATURE_BYTES)
        .div_ceil(3)
        * 4
        + 1024
        <= MAX_APPROVAL_BODY_BYTES
);

const NO_GRANT_TO_ASK: &str = "no grant lets this principal ask for this deployment";
const NO_GRANT_TO_APPROVE: &str =
    "no grant lets this principal approve here, and a token never can";
const BAD_BODY: &str = "the body is not a valid request";
const UNREADABLE_BODY: &str = "the body could not be read within its limits";

/// `POST .../requests`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AskBody {
    tag: ReleaseTag,
}

/// `POST /approvals/{id}`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApproveBody {
    assertion: AssertionText,
}

/// A request, as a principal may see it, with what a passkey signs.
#[derive(Debug, Serialize)]
struct RequestView<'a> {
    id: i64,
    host: &'a HostId,
    intent: &'a DeployIntent,
    challenge: String,
    state: &'static str,
    requested_by: &'a landfall_core::ids::PrincipalId,
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

/// Whether promotion holds this release back: not for a downgrade, the manual rollback.
async fn promotion_holds(
    state: &ApiState,
    d: &Deployment,
    tag: &ReleaseTag,
    version: &Version,
) -> Result<bool, StoreError> {
    let store = state.store();
    let running = store.watch_view(d.id(), d.host()).await?.running;
    let running_version = running
        .and_then(|running| running.tag)
        .and_then(|running| d.origin().tags().parse_tag(&running).ok());
    if running_version.is_some_and(|running| *version < running) {
        return Ok(false);
    }
    let Some(digest) = store
        .release(d.id(), tag)
        .await?
        .and_then(|release| release.digest)
    else {
        return Ok(false);
    };
    Ok(
        promotion_waits_for(store, state.config(), d.id(), tag, &digest)
            .await?
            .is_some(),
    )
}

/// Everything about a request but its nonce, judged in `tx`: the intent to record.
async fn judge_request(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    principal: &Principal,
    (d, tag, version): (&Deployment, &ReleaseTag, &Version),
    nonce: [u8; 32],
) -> Result<DeployIntent, Stop> {
    let snapshot = state
        .store()
        .request_snapshot(tx, (d.id(), d.host(), tag))
        .await?;
    if snapshot.open_request {
        return Err(refused(
            HumanProblem::RequestOpen,
            "the deployment already has a request waiting for an approver",
        ));
    }
    if snapshot.active_deploy {
        return Err(refused(
            HumanProblem::DeploymentBusy,
            "the deployment has a deploy queued or running",
        ));
    }
    let running = ready_host(&snapshot)?;
    let held = state.store().release_held(tx, d.id(), tag).await?;
    let settled = snapshot
        .release
        .as_ref()
        .filter(|release| !held && release.verified_under(state.config().hash()))
        .and_then(|release| release.settled());
    let Some((commit, digest)) = settled else {
        return Err(refused(
            HumanProblem::ReleaseNotVerified,
            "no verified record of this release for this configuration",
        ));
    };
    let running_version = match &running.tag {
        None => None,
        Some(running) => match d.origin().tags().parse_tag(running) {
            Ok(version) => Some(version),
            Err(_) => {
                return Err(refused(
                    HumanProblem::HostNotReady,
                    "the running tag does not match the deployment's tag pattern",
                ));
            }
        },
    };
    match decide(d.rule(), running_version.as_ref(), version) {
        Decision::Refused(_) => {
            return Err(refused(
                HumanProblem::ReleaseRefused,
                "the rule refuses this release",
            ));
        }
        Decision::Auto | Decision::NeedsApproval | Decision::Manual => {}
    }
    let downgrade = running_version
        .as_ref()
        .is_some_and(|running| version < running);
    let needs = if downgrade {
        Permission::Rollback
    } else {
        Permission::Request
    };
    if !can(state.config(), principal, d.id(), needs) {
        return Err(refused(
            HumanProblem::Forbidden,
            "no grant lets this principal ask for this: a lower version takes rollback, and \
             any other takes request",
        ));
    }
    Ok(DeployIntent {
        deployment: d.id().clone(),
        tag: tag.clone(),
        commit: commit.clone(),
        digest: digest.clone(),
        expected_running: running.digest.clone(),
        nonce,
    })
}

/// `POST /api/v1/deployments/{name}/{stage}/requests`.
async fn ask(
    State(state): State<ApiState>,
    principal: Principal,
    path: Result<Path<(String, String)>, PathRejection>,
    body: Body,
) -> Result<Response, HumanProblem> {
    let config = state.config();
    let raw = path.map_or_else(|_| String::new(), |Path((a, b))| format!("{a}/{b}"));
    let deployment = raw
        .parse::<DeploymentId>()
        .ok()
        .and_then(|id| config.deployment(&id));
    let subject = Subject {
        kind: EventKind::RequestRefused,
        deployment,
        about: Some(&raw),
        request: None,
        tag: None,
    };
    let may_ask = |d: &&Deployment| {
        can(config, &principal, d.id(), Permission::Request)
            || can(config, &principal, d.id(), Permission::Rollback)
    };
    let Some(d) = deployment.filter(may_ask) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            visibility(config, &principal, deployment.map(Deployment::id)),
            NO_GRANT_TO_ASK,
        )
        .await);
    };
    let asked: AskBody = match parsed_body(&state, body, MAX_REQUEST_BODY_BYTES).await {
        Ok(asked) => asked,
        Err((problem, why)) => {
            return Err(refuse_alone(&state, &principal, subject, problem, why).await);
        }
    };
    let tag = &asked.tag;
    let subject = Subject {
        tag: Some(tag),
        ..subject
    };
    let Ok(version) = d.origin().tags().parse_tag(tag) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            HumanProblem::ReleaseNotVerified,
            "the tag is not one of this deployment's releases",
        )
        .await);
    };
    if promotion_holds(&state, d, tag, &version).await? {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            HumanProblem::PromotionPending,
            "not yet reported healthy for long enough where it is promoted from",
        )
        .await);
    }
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(StoreError::Random)?;
    let store = state.store();
    let now = store.now()?;
    let mut tx = store.begin().await?;
    store.expire_requests(&mut tx, now).await?;
    match judge_request(&state, &mut tx, &principal, (d, tag, &version), nonce).await {
        Ok(intent) => {
            let request = NewRequest {
                host: d.host(),
                intent,
                requested_by: principal.id(),
                audited_by: principal.audited(),
            };
            let stored = store.insert_request(&mut tx, &request).await?;
            tx.commit().await.map_err(StoreError::from)?;
            let can_approve = can(config, &principal, d.id(), Permission::Approve);
            let mut answer = json_answer(&view(&stored, can_approve), &no_store());
            *answer.status_mut() = StatusCode::CREATED;
            Ok(answer)
        }
        Err(Stop::Refused(refusal)) => {
            refuse_in(&state, tx, &principal, subject, &refusal).await?;
            Err(refusal.problem)
        }
        Err(Stop::Store(error)) => Err(error.into()),
    }
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

/// `GET /api/v1/approvals`: what this principal may see that waits for an approver, each
/// saying whether they could sign it. Changes nothing. A request past its time is left out
/// here, and ended by the next write that comes to it.
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

/// Refuses an assertion that isn't this approver's over this intent's challenge, by what
/// the host will check. The key is the configuration's: the one the host goes by.
fn check_assertion(
    config: &Config,
    principal: &Principal,
    intent: &DeployIntent,
    text: &AssertionText,
) -> Result<(), Refused> {
    let refuse = |why: String| Refused {
        problem: HumanProblem::AssertionRefused,
        reason: quoted(&why, REFUSAL_SHOWN_CHARS),
    };
    let Some(settings) = config.approval() else {
        return Err(Refused {
            problem: HumanProblem::ApprovalsNotConfigured,
            reason: "the configuration has no [approval] settings".to_owned(),
        });
    };
    let Some(approver) = config.approver(principal.id()) else {
        return Err(refuse(
            "this principal has no key in [approvers]".to_owned(),
        ));
    };
    let key = CoseKey::parse(approver.public_key()).map_err(|error| refuse(error.to_string()))?;
    let assertion = Assertion::try_from(text).map_err(|error| refuse(error.to_string()))?;
    verify(
        &assertion,
        &Expect {
            key: &key,
            credential_id: approver.credential_id(),
            rp_id: settings.rp_id(),
            origin: settings.origin(),
            challenge: &intent.challenge(),
        },
    )
    .map_err(|error| refuse(error.to_string()))
}

/// Why this state can't be approved, if it can't.
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
    }
}

/// Ends `request` as stale for `reason`, and says so to who tried it.
async fn gone_stale(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    request: &StoredRequest,
    reason: &str,
) -> Result<(), Stop> {
    state.store().stale_request(tx, request, reason).await?;
    Err(refused(HumanProblem::RequestStale, reason))
}

/// All that could stop `request` from being approved, looked at in `tx`, whose lock is
/// held from before the look until the commit: a host's report comes either before it,
/// which this sees, or after it, and is about a deploy the host will judge for itself.
async fn judge_approval(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    d: &Deployment,
    request: &StoredRequest,
) -> Result<(), Stop> {
    let store = state.store();
    store.expire_requests(tx, store.now()?).await?;
    if let Some((problem, why)) = closed(store.request_state(tx, request.id).await?) {
        return Err(refused(problem, why));
    }
    let intent = &request.intent;
    if request.host != *d.host() {
        return gone_stale(
            state,
            tx,
            request,
            "the deployment is on another host now, by the configuration",
        )
        .await;
    }
    let snapshot = store
        .request_snapshot(tx, (d.id(), d.host(), &intent.tag))
        .await?;
    let same_release = snapshot
        .release
        .as_ref()
        .and_then(|release| release.settled())
        .is_some_and(|(commit, digest)| *commit == intent.commit && *digest == intent.digest);
    if !same_release {
        return gone_stale(
            state,
            tx,
            request,
            "the release's verified record changed after the request was made",
        )
        .await;
    }
    if let Some(running) = &snapshot.running
        && running.digest != intent.expected_running
    {
        return gone_stale(
            state,
            tx,
            request,
            "the running digest moved after the request was made",
        )
        .await;
    }
    if snapshot.active_deploy {
        return Err(refused(
            HumanProblem::DeploymentBusy,
            "the deployment has a deploy queued or running",
        ));
    }
    ready_host(&snapshot)?;
    Ok(())
}

/// `POST /api/v1/approvals/{id}`.
async fn approve(
    State(state): State<ApiState>,
    principal: Principal,
    path: Result<Path<String>, PathRejection>,
    body: Body,
) -> Result<Response, HumanProblem> {
    let config = state.config();
    let store = state.store();
    let raw = path.map_or_else(|_| String::new(), |Path(raw)| raw);
    let stored = match raw.parse::<i64>() {
        Ok(id) if id > 0 => store.request(id).await?,
        _ => None,
    };
    let deployment = stored
        .as_ref()
        .and_then(|request| config.deployment(&request.intent.deployment));
    let subject = Subject {
        kind: EventKind::ApprovalRefused,
        deployment,
        about: stored.is_none().then_some(raw.as_str()),
        request: stored.as_ref().map(|request| request.id),
        tag: stored.as_ref().map(|request| &request.intent.tag),
    };
    let allowed = deployment.filter(|d| can(config, &principal, d.id(), Permission::Approve));
    let (Some(request), Some(d)) = (&stored, allowed) else {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            visibility(config, &principal, deployment.map(Deployment::id)),
            NO_GRANT_TO_APPROVE,
        )
        .await);
    };
    // A clear answer for what's over, whatever came with the asking. The transaction below
    // looks again, and is what counts.
    if let Some((problem, why)) = closed(request.state) {
        return Err(refuse_alone(&state, &principal, subject, problem, why).await);
    }
    let sent: ApproveBody = match parsed_body(&state, body, MAX_APPROVAL_BODY_BYTES).await {
        Ok(sent) => sent,
        Err((problem, why)) => {
            return Err(refuse_alone(&state, &principal, subject, problem, why).await);
        }
    };
    if let Err(refusal) = check_assertion(config, &principal, &request.intent, &sent.assertion) {
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            refusal.problem,
            &refusal.reason,
        )
        .await);
    }
    let approval = Approval {
        intent: request.intent.clone(),
        assertion: sent.assertion,
    };
    let mut tx = store.begin().await?;
    match approve_in(&state, &mut tx, &principal, d, request, &approval).await {
        Ok(deploy_id) => {
            tx.commit().await.map_err(StoreError::from)?;
            store.wake_agents();
            Ok(json_answer(
                &json!({ "request": request.id, "deploy_id": deploy_id }),
                &no_store(),
            ))
        }
        Err(Stop::Refused(refusal)) => {
            refuse_in(&state, tx, &principal, subject, &refusal).await?;
            Err(refusal.problem)
        }
        Err(Stop::Store(error)) => Err(error.into()),
    }
}

/// The judgement and the conditional update that follows from it.
async fn approve_in(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    principal: &Principal,
    d: &Deployment,
    request: &StoredRequest,
    approval: &Approval,
) -> Result<landfall_core::protocol::DeployId, Stop> {
    judge_approval(state, tx, d, request).await?;
    let queued = state
        .store()
        .approve_request(tx, request, principal.id(), approval)
        .await?;
    queued.ok_or_else(|| {
        refused(
            HumanProblem::RequestClosed,
            "the request was already approved",
        )
    })
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
        .route("/api/v1/deployments/{name}/{stage}/requests", post(ask))
        .route("/api/v1/approvals", get(list))
        .route("/api/v1/approvals/{id}", post(approve))
        .route("/api/v1", any(not_found))
        .route("/api/v1/", any(not_found))
        .route("/api/v1/{*rest}", any(not_found))
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state)
        .layer(middleware::from_fn_with_state(limit, deadline))
}

#[cfg(test)]
mod tests;
