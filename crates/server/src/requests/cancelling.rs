//! `POST /api/v1/approvals/{id}/cancel`: for who asked, and for who could approve it or roll
//! back past it, since without this a request nobody will sign keeps the deployment's next
//! one out until it expires. It takes no body and no assertion: all it can do is stop
//! something from running, and a new request is a click away.

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{Cancelled, Problem, RequestState as RequestStateView};
use landfall_core::config::Permission;

use super::{Refused, Subject, closed, named_request, refuse_alone, refuse_in, visibility};
use crate::agent_api::ApiState;
use crate::api::{
    ApiJson, ApiQuery, BadRequest, Busy, Forbidden, IdPath, InternalOrUnreadable, NoQuery,
    NotFound, RateLimited, SlowRequest, Unauthenticated,
};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal, can};
use crate::store::{StoreError, StoredRequest};

const NO_GRANT_TO_CANCEL: &str =
    "this principal did not ask for this request, and no grant lets it approve or roll back here";

/// Whether `principal` may cancel `request`.
pub(super) fn may_cancel(state: &ApiState, principal: &Principal, request: &StoredRequest) -> bool {
    let id = &request.intent.deployment;
    request.requested_by == *principal.id()
        || can(state.config(), principal, id, Permission::Approve)
        || can(state.config(), principal, id, Permission::Rollback)
}

/// The handler.
#[utoipa::path(
    post,
    path = "/api/v1/approvals/{id}/cancel",
    operation_id = "cancelRequest",
    tag = "requests",
    summary = "Cancel a request",
    description = "For who asked, and for who could approve it or roll back past it. It takes no \
                   body: all it can do is stop something from running.",
    params(IdPath, NoQuery),
    security(
        ("token" = ["requester", "rollback"]),
        ("session" = ["requester", "approve", "rollback"]),
    ),
    responses(
        (status = 200, description = "The request was cancelled.", body = Cancelled),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = Forbidden),
        (status = 404, response = NotFound),
        (status = 408, response = SlowRequest),
        (
            status = 409,
            description = "The request is no longer open: `request_closed`, `request_stale`, \
                           `request_expired` or `request_cancelled`.",
            body = Problem,
            content_type = "application/problem+json",
        ),
        (status = 429, response = RateLimited),
        (status = 500, response = InternalOrUnreadable),
        (status = 503, response = Busy),
    ),
)]
pub(super) async fn cancel(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
    path: Result<Path<IdPath>, PathRejection>,
) -> Result<ApiJson<Cancelled>, HumanProblem> {
    let config = state.config();
    let store = state.store();
    let path = path.map_or_else(|_| IdPath { id: String::new() }, |Path(path)| path);
    let raw = path.id.as_str();
    let stored = named_request(&state, &principal, &path, EventKind::CancelRefused).await?;
    let deployment = stored
        .as_ref()
        .and_then(|request| config.deployment(&request.intent.deployment));
    let subject = Subject {
        kind: EventKind::CancelRefused,
        deployment,
        about: stored.is_none().then_some(raw),
        request: stored.as_ref().map(|request| request.id),
        tag: stored.as_ref().map(|request| &request.intent.tag),
    };
    let Some(request) = stored
        .as_ref()
        .filter(|request| may_cancel(&state, &principal, request))
    else {
        let id = deployment.map(landfall_core::config::Deployment::id);
        return Err(refuse_alone(
            &state,
            &principal,
            subject,
            visibility(config, &principal, id),
            NO_GRANT_TO_CANCEL,
        )
        .await);
    };
    let mut tx = store.begin().await?;
    store.expire_requests(&mut tx, store.now()?).await?;
    let state_now = store.request_state(&mut tx, request.id).await?;
    if let Some((problem, why)) = closed(state_now) {
        let refusal = Refused {
            problem,
            reason: why.to_owned(),
        };
        refuse_in(&state, tx, &principal, subject, &refusal).await?;
        return Err(problem);
    }
    let reason = format!("cancelled by {}", principal.id());
    let ended = store
        .cancel_open_request(
            &mut tx,
            (&request.intent.deployment, Some(request.id)),
            &principal.audited(),
            &reason,
        )
        .await?;
    if !ended {
        return Err(StoreError::Corrupt("a request that was open, and could not be ended").into());
    }
    tx.commit().await.map_err(StoreError::from)?;
    Ok(ApiJson(Cancelled {
        request: request.id,
        state: RequestStateView::Cancelled,
    }))
}
