//! `POST /api/v1/approvals/{id}/cancel`: for who asked, and for who could approve it or roll
//! back past it, since without this a request nobody will sign keeps the deployment's next
//! one out until it expires. It takes no body and no assertion: all it can do is stop
//! something from running, and a new request is a click away.

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use axum::response::Response;
use landfall_core::config::Permission;
use serde_json::json;

use super::{
    Refused, Subject, closed, named_request, no_store, refuse_alone, refuse_in, visibility,
};
use crate::agent_api::{ApiState, json as json_answer};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal, can};
use crate::store::{StoreError, StoredRequest};

const NO_GRANT_TO_CANCEL: &str =
    "this principal did not ask for this request, and no grant lets it approve or roll back here";

/// Whether `principal` may cancel `request`.
fn may_cancel(state: &ApiState, principal: &Principal, request: &StoredRequest) -> bool {
    let id = &request.intent.deployment;
    request.requested_by == *principal.id()
        || can(state.config(), principal, id, Permission::Approve)
        || can(state.config(), principal, id, Permission::Rollback)
}

/// The handler.
pub(super) async fn cancel(
    State(state): State<ApiState>,
    principal: Principal,
    path: Result<Path<String>, PathRejection>,
) -> Result<Response, HumanProblem> {
    let config = state.config();
    let store = state.store();
    let raw = path.map_or_else(|_| String::new(), |Path(raw)| raw);
    let stored = named_request(&state, &raw).await?;
    let deployment = stored
        .as_ref()
        .and_then(|request| config.deployment(&request.intent.deployment));
    let subject = Subject {
        kind: EventKind::CancelRefused,
        deployment,
        about: stored.is_none().then_some(raw.as_str()),
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
    Ok(json_answer(
        &json!({ "request": request.id, "state": "cancelled" }),
        &no_store(),
    ))
}
