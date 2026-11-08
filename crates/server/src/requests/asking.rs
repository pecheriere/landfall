//! `POST /api/v1/deployments/{name}/{stage}/requests`.

use axum::body::Body;
use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::http::StatusCode;
use landfall_api::{NewRequest, Problem, RequestView};
use landfall_core::config::{Deployment, Permission};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::rule::{Decision, decide};
use semver::Version;
use sqlx::{Sqlite, Transaction};

use super::{
    Stop, Subject, parsed_body, ready_host, refuse_alone, refuse_in, refused, view, visibility,
};
use crate::agent_api::ApiState;
use crate::api::{
    ApiJson, ApiQuery, BadRequest, BodyTooLarge, Busy, DeploymentPath, Forbidden, Internal,
    NoQuery, NotFound, RateLimited, SlowRequest, Unauthenticated,
};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal, can};
use crate::store::{NewRequest as StoredNewRequest, StoreError};

/// A request is one tag, at most 128 bytes.
const MAX_REQUEST_BODY_BYTES: usize = 1024;

const NO_GRANT_TO_ASK: &str = "no grant lets this principal ask for this deployment";

/// Everything about a request but its nonce, judged in `tx`: the intent to record, and
/// whether it is a rollback. A rollback by someone who may do one cancels the open request it
/// finds, once nothing else stands in its way.
async fn judge_request(
    state: &ApiState,
    tx: &mut Transaction<'_, Sqlite>,
    principal: &Principal,
    (d, tag, version): (&Deployment, &ReleaseTag, &Version),
    nonce: [u8; 32],
) -> Result<(DeployIntent, bool), Stop> {
    let store = state.store();
    let snapshot = store.request_snapshot(tx, (d.id(), d.host(), tag)).await?;
    let running_tag = snapshot.running.as_ref().and_then(|r| r.tag.as_ref());
    let readable = running_tag.map(|running| d.origin().tags().parse_tag(running).ok());
    let downgrade = readable
        .as_ref()
        .and_then(Option::as_ref)
        .is_some_and(|running| version < running);
    let may_roll_back = downgrade && can(state.config(), principal, d.id(), Permission::Rollback);
    if snapshot.open_request && !may_roll_back {
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
    let held = store.release_held(tx, d.id(), tag).await?;
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
    if readable.as_ref().is_some_and(Option::is_none) {
        return Err(refused(
            HumanProblem::HostNotReady,
            "the running tag does not match the deployment's tag pattern",
        ));
    }
    match decide(d.rule(), readable.flatten().as_ref(), version) {
        Decision::Refused(_) => {
            return Err(refused(
                HumanProblem::ReleaseRefused,
                "the rule refuses this release",
            ));
        }
        Decision::Auto | Decision::NeedsApproval | Decision::Manual => {}
    }
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
    if !downgrade
        && store
            .promotion_waits_for_on(tx, state.config(), d.id(), (tag, digest))
            .await?
            .is_some()
    {
        return Err(refused(
            HumanProblem::PromotionPending,
            "not yet reported healthy for long enough where it is promoted from",
        ));
    }
    if snapshot.open_request {
        let reason = format!(
            "superseded by a rollback to {tag}, asked for by {}",
            principal.id()
        );
        store
            .cancel_open_request(tx, (d.id(), None), &principal.audited(), &reason)
            .await?;
    }
    let intent = DeployIntent {
        deployment: d.id().clone(),
        tag: tag.clone(),
        commit: commit.clone(),
        digest: digest.clone(),
        expected_running: running.digest.clone(),
        nonce,
    };
    Ok((intent, downgrade))
}

/// The handler.
#[utoipa::path(
    post,
    path = "/api/v1/deployments/{name}/{stage}/requests",
    operation_id = "requestDeploy",
    tag = "requests",
    summary = "Ask for a deploy",
    description = "Asks for a verified release to be deployed, once an approver signs it. The \
                   controller makes the intent from its own records; the client names a tag and \
                   nothing else.",
    params(DeploymentPath, NoQuery),
    request_body = NewRequest,
    security(("token" = ["request", "rollback"]), ("session" = ["request", "rollback"])),
    extensions((
        "x-landfall-grant" = json!({
            "request": "a tag above what runs, or the first deploy",
            "rollback": "a tag below what runs",
        })
    )),
    responses(
        (
            status = 201,
            description = "The request, waiting for an approver. A rollback by someone with \
                           the `rollback` grant cancels the request it finds open.",
            body = RequestView,
        ),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 408, response = SlowRequest),
        (
            status = 409,
            description = "Nothing can be asked for now: `request_open`, `deployment_busy`, \
                           `host_not_ready`, `release_not_verified`, `release_refused` or \
                           `promotion_pending`.",
            body = Problem,
            content_type = "application/problem+json",
        ),
        (status = 413, response = BodyTooLarge),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
pub(super) async fn ask(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
    path: Result<Path<DeploymentPath>, PathRejection>,
    body: Body,
) -> Result<(StatusCode, ApiJson<RequestView>), HumanProblem> {
    let config = state.config();
    let raw = path.map_or_else(|_| String::new(), |Path(path)| path.raw());
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
    let asked: NewRequest = match parsed_body(&state, body, MAX_REQUEST_BODY_BYTES).await {
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
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce).map_err(StoreError::Random)?;
    let store = state.store();
    let now = store.now()?;
    let mut tx = store.begin().await?;
    store.expire_requests(&mut tx, now).await?;
    match judge_request(&state, &mut tx, &principal, (d, tag, &version), nonce).await {
        Ok((intent, is_rollback)) => {
            let request = StoredNewRequest {
                host: d.host(),
                intent,
                requested_by: principal.id(),
                audited_by: principal.audited(),
                is_rollback,
            };
            let stored = store.insert_request(&mut tx, &request).await?;
            tx.commit().await.map_err(StoreError::from)?;
            let can_approve = can(config, &principal, d.id(), Permission::Approve);
            // Whoever asked may cancel it.
            Ok((
                StatusCode::CREATED,
                ApiJson(view(&stored, can_approve, true)),
            ))
        }
        Err(Stop::Refused(refusal)) => {
            refuse_in(&state, tx, &principal, subject, &refusal).await?;
            Err(refusal.problem)
        }
        Err(Stop::Store(error)) => Err(error.into()),
    }
}
