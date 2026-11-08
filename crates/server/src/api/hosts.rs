//! The hosts, seen through the deployments on them: `GET /api/v1/hosts` and
//! `GET /api/v1/hosts/{host}`.
//!
//! The configuration says which deployment runs on which host, and a host is shown to a
//! principal who may view a deployment on it, with those deployments and no others. With some
//! other grant on a deployment there and no `view`, a host is `403`; with none, the same `404`
//! as a host no deployment names. When it enrolled and whether its configuration drifted come
//! from the store, and when it last reported is the newest report among the deployments shown.
//! These change nothing.

use std::collections::{BTreeMap, HashMap};

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{DeploymentSummary, HostView, HostsView};
use landfall_core::config::Deployment;
use landfall_core::ids::HostId;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::ApiJson;
use super::deployments::{Facts, open_requests, summary};
use super::openapi::{
    BadOrigin, BadRequest, Busy, Internal, NotFound, RateLimited, ReadForbidden, SlowRequest,
    Unauthenticated,
};
use super::query::{ApiQuery, HostPath, NoQuery};
use super::visible::{viewable_deployments, viewable_on_host};
use crate::agent_api::ApiState;
use crate::auth::{HumanProblem, Principal};
use crate::store::views::HostRow;

/// The views of `hosts`, each with the deployments given for it, read in one go: their reports,
/// open requests and latest releases once for all of them, and the hosts once.
async fn host_views(
    state: &ApiState,
    principal: &Principal,
    hosts: &BTreeMap<&HostId, Vec<&Deployment>>,
) -> Result<Vec<HostView>, HumanProblem> {
    let config = state.config();
    let deployments: Vec<&Deployment> = hosts.values().flatten().copied().collect();
    let open = open_requests(state).await?;
    let facts = Facts::of(state, principal, &deployments, open).await?;
    let ids: Vec<&HostId> = hosts.keys().copied().collect();
    let enrolled: HashMap<HostId, HostRow> = state.store().hosts(&ids).await?;
    Ok(hosts
        .iter()
        .map(|(id, deployments)| {
            let summaries: Vec<DeploymentSummary> = deployments
                .iter()
                .map(|d| summary(config, principal, d, &facts))
                .collect();
            let last_report = summaries
                .iter()
                .filter_map(|s| s.running.as_ref()?.last_report)
                .max();
            let row = enrolled.get(*id);
            HostView {
                id: (*id).clone(),
                enrolled_at: row.map(|row| row.enrolled_at),
                config_drift: row.is_some_and(|row| row.config_drift),
                last_report,
                deployments: summaries,
            }
        })
        .collect())
}

/// `deployments` by host, each host's in order of id.
fn by_host<'a>(
    deployments: impl Iterator<Item = &'a Deployment>,
) -> BTreeMap<&'a HostId, Vec<&'a Deployment>> {
    let mut hosts: BTreeMap<&HostId, Vec<&Deployment>> = BTreeMap::new();
    for deployment in deployments {
        hosts.entry(deployment.host()).or_default().push(deployment);
    }
    for deployments in hosts.values_mut() {
        deployments.sort_by(|a, b| a.id().cmp(b.id()));
    }
    hosts
}

/// `GET /api/v1/hosts`: the hosts this principal may see, by id.
#[utoipa::path(
    get,
    path = "/api/v1/hosts",
    operation_id = "listHosts",
    tag = "hosts",
    summary = "The hosts",
    description = "The hosts the configuration puts a deployment on that this principal may \
                   view, by id, each with those deployments and no others. Not paged: the \
                   configuration bounds it.",
    params(NoQuery),
    security(("token" = []), ("session" = [])),
    responses(
        (status = 200, description = "The hosts this principal may see.", body = HostsView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = BadOrigin),
        (status = 408, response = SlowRequest),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
async fn list(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
) -> Result<ApiJson<HostsView>, HumanProblem> {
    let hosts = by_host(viewable_deployments(state.config(), &principal));
    let hosts = host_views(&state, &principal, &hosts).await?;
    Ok(ApiJson(HostsView { hosts }))
}

/// `GET /api/v1/hosts/{host}`: one host, with the deployments on it this principal may view.
#[utoipa::path(
    get,
    path = "/api/v1/hosts/{host}",
    operation_id = "getHost",
    tag = "hosts",
    summary = "One host",
    description = "One host, with the deployments on it this principal may view and no others. \
                   A host with no deployment they hold a grant on is `404`, as one no \
                   deployment names; with some other grant there and no `view`, `403`.",
    params(HostPath, NoQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "The host.", body = HostView),
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
    path: Result<Path<HostPath>, PathRejection>,
) -> Result<ApiJson<HostView>, HumanProblem> {
    let shown = viewable_on_host(
        state.config(),
        &principal,
        path.ok().map(|Path(path)| path.host),
    )?;
    let hosts = by_host(shown.into_iter());
    host_views(&state, &principal, &hosts)
        .await?
        .pop()
        .map(ApiJson)
        .ok_or(HumanProblem::NotFound)
}

/// The API's operations on hosts.
pub(super) fn routes() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(get))
}
