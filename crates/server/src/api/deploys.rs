//! A deployment's deploys, one deploy, and why it ended as it did:
//! `GET /api/v1/deployments/{name}/{stage}/deploys`, `GET /api/v1/deploys/{id}` and
//! `GET /api/v1/deploys/{id}/why`.
//!
//! Seeing a deploy takes `view` on its deployment, by the visibility rule: no grant there is
//! the same `404` as a number no deploy has, and some other grant is `403`. A deploy of a
//! deployment the configuration no longer has is `404` to everyone. A list is newest first, a
//! page at a time on the index of a deployment's deploys, with the steps of the whole page
//! read at once. These change nothing.

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{DeployView, Page, StepView, Why};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::ApiJson;
use super::openapi::{
    BadRequest, Busy, Internal, NotFound, RateLimited, ReadForbidden, SlowRequest, Unauthenticated,
};
use super::query::{
    ApiQuery, Cursor, CursorList, DeploymentPath, IdPath, Limit, NoQuery, id_number,
};
use super::visible::{viewable, viewable_by_id};
use super::why::explain;
use crate::agent_api::{ApiProblem, ApiState};
use crate::auth::{HumanProblem, Principal};
use crate::store::history::{DeployRow, StepRow};

/// What `listDeploys` reads from its query string.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct DeploysQuery {
    /// How many deploys a page holds: from 1 to 100, 50 if left out.
    #[param(value_type = Option<u8>, minimum = 1, maximum = 100, default = 50)]
    limit: Option<Limit>,
    /// The last page's `next_cursor`, to get the page after it.
    cursor: Option<String>,
}

fn step_view(step: StepRow) -> StepView {
    StepView {
        position: step.position,
        name: step.name,
        millis: step.millis,
        failure: step.failure,
        detail: step.detail,
    }
}

fn view(row: DeployRow, steps: Vec<StepRow>) -> DeployView {
    DeployView {
        id: row.id,
        deployment: row.deployment,
        host: row.host,
        tag: row.tag,
        digest: row.digest,
        commit: row.commit,
        state: row.state,
        outcome: row.outcome,
        reason: row.reason,
        rollback_reason: row.rollback_reason,
        request: row.request_id,
        approved_by: row.approved_by,
        created_at: row.created_at,
        claimed_at: row.claimed_at,
        finished_at: row.finished_at,
        steps: steps.into_iter().map(step_view).collect(),
    }
}

/// The deploy a path names, with its steps, if this principal may view its deployment.
async fn named_deploy(
    state: &ApiState,
    principal: &Principal,
    path: Result<Path<IdPath>, PathRejection>,
) -> Result<(DeployRow, Vec<StepRow>), HumanProblem> {
    let id = path
        .ok()
        .and_then(|Path(path)| path.number())
        .ok_or(HumanProblem::NotFound)?;
    let store = state.store();
    let row = store.deploy(id).await?.ok_or(HumanProblem::NotFound)?;
    viewable_by_id(state.config(), principal, Some(&row.deployment))?;
    let steps = store.deploy_steps(id).await?;
    Ok((row, steps))
}

/// `GET /api/v1/deployments/{name}/{stage}/deploys`: a deployment's deploys, newest first, a
/// page at a time.
#[utoipa::path(
    get,
    path = "/api/v1/deployments/{name}/{stage}/deploys",
    operation_id = "listDeploys",
    tag = "deploys",
    summary = "A deployment's deploys",
    description = "The deploys of a deployment, newest first, a page at a time, each with the \
                   steps its host reported.",
    params(DeploymentPath, DeploysQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "A page of the deploys.", body = Page<DeployView>),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = ReadForbidden),
        (status = 404, response = NotFound),
        (status = 408, response = SlowRequest),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
async fn list(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(query): ApiQuery<DeploysQuery>,
    path: Result<Path<DeploymentPath>, PathRejection>,
) -> Result<ApiJson<Page<DeployView>>, HumanProblem> {
    let deployment = viewable(
        state.config(),
        &principal,
        path.ok().map(|Path(path)| path.raw()),
    )?;
    let before = match query.cursor.as_deref() {
        None => None,
        Some(raw) => {
            let cursor = Cursor::decode(raw, CursorList::Deploys)?;
            Some(id_number(cursor.after()).ok_or(ApiProblem::BadRequest)?)
        }
    };
    let limit = Limit::or_default(query.limit);
    // One more than the page, to know whether there is a next one.
    let wanted = u32::try_from(limit).unwrap_or(u32::MAX).saturating_add(1);
    let store = state.store();
    let mut rows = store
        .deploys_of_deployment(deployment.id(), before, wanted)
        .await?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = more
        .then(|| rows.last())
        .flatten()
        .map(|last| Cursor::new(CursorList::Deploys, last.id.to_string()).encode());
    let ids: Vec<i64> = rows.iter().map(|row| row.id).collect();
    let mut steps = store.steps_of(&ids).await?;
    let items = rows
        .into_iter()
        .map(|row| {
            let of_it = steps.remove(&row.id).unwrap_or_default();
            view(row, of_it)
        })
        .collect();
    Ok(ApiJson(Page { items, next_cursor }))
}

/// `GET /api/v1/deploys/{id}`: one deploy, with the steps its host reported.
#[utoipa::path(
    get,
    path = "/api/v1/deploys/{id}",
    operation_id = "getDeploy",
    tag = "deploys",
    summary = "One deploy",
    description = "One deploy, with the steps its host reported. A deploy of a deployment the \
                   principal can't view, or the configuration no longer has, is `404`, as a \
                   number no deploy has.",
    params(IdPath, NoQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "The deploy.", body = DeployView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = ReadForbidden),
        (status = 404, response = NotFound),
        (status = 408, response = SlowRequest),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
async fn get(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
    path: Result<Path<IdPath>, PathRejection>,
) -> Result<ApiJson<DeployView>, HumanProblem> {
    let (row, steps) = named_deploy(&state, &principal, path).await?;
    Ok(ApiJson(view(row, steps)))
}

/// `GET /api/v1/deploys/{id}/why`: why a deploy ended as it did.
#[utoipa::path(
    get,
    path = "/api/v1/deploys/{id}/why",
    operation_id = "whyDeploy",
    tag = "deploys",
    summary = "Why a deploy ended as it did",
    description = "What happened to a deploy, in time order, one sentence to act on, and the \
                   one thing to do next. Seen as `getDeploy` is.",
    params(IdPath, NoQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "Why it ended as it did.", body = Why),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = ReadForbidden),
        (status = 404, response = NotFound),
        (status = 408, response = SlowRequest),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
async fn why(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
    path: Result<Path<IdPath>, PathRejection>,
) -> Result<ApiJson<Why>, HumanProblem> {
    let (row, steps) = named_deploy(&state, &principal, path).await?;
    Ok(ApiJson(explain(&row, &steps)))
}

/// The API's operations on deploys.
pub(super) fn routes() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(get))
        .routes(routes!(why))
}
