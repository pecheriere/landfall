//! Who is asking, and the deployments they may see: `GET /api/v1/me`,
//! `GET /api/v1/deployments` and `GET /api/v1/deployments/{name}/{stage}`.
//!
//! Deployments come from the configuration, and what their hosts last said from the store.
//! A report from a host the configuration no longer pairs with a deployment is ignored, as
//! the watcher ignores it. Seeing a deployment takes `view`, and a deployment a principal
//! can't view is never named, not even as another's promotion. These change nothing.

use std::collections::HashMap;

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{
    DeploymentRef, DeploymentSummary, DeploymentView, GrantView, HoldView, MeView, Page,
    Permission as Granted, PromotionView, ReleaseBrief, RuleView, RunningView, Via,
};
use landfall_core::config::{Config, Deployment, Permission};
use landfall_core::ids::{DeploymentId, HostId, RepoName};
use serde::Deserialize;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::ApiJson;
use super::openapi::{
    BadOrigin, BadRequest, Busy, Internal, NotFound, RateLimited, ReadForbidden, SlowRequest,
    Unauthenticated,
};
use super::query::{ApiQuery, Cursor, CursorList, DeploymentPath, Limit, NoQuery};
use super::releases;
use super::visible::{shown_deployment, viewable, viewable_deployments};
use crate::agent_api::ApiState;
use crate::auth::{HumanProblem, Principal, can, sees};
use crate::store::StoredRequest;
use crate::store::views::RunningRow;

/// The most holds a deployment's view lists: the newest, with a count of all.
const HOLDS_SHOWN: u32 = 50;

/// Every permission, in the order a grant lists them.
const PERMISSIONS: [(Permission, Granted); 4] = [
    (Permission::View, Granted::View),
    (Permission::Request, Granted::Request),
    (Permission::Approve, Granted::Approve),
    (Permission::Rollback, Granted::Rollback),
];

/// `GET /api/v1/me`: who this principal is, what each grant lets this credential do, and where
/// an approver signs.
#[utoipa::path(
    get,
    path = "/api/v1/me",
    operation_id = "whoAmI",
    tag = "principals",
    summary = "Who is asking",
    description = "The principal, how they proved it, what they may do to each deployment they \
                   hold a grant on by this credential, and where an approver signs a request. A \
                   token never lists `approve`.",
    params(NoQuery),
    security(("token" = []), ("session" = [])),
    responses(
        (status = 200, description = "Who is asking.", body = MeView),
        (status = 400, response = BadRequest),
        (status = 401, response = Unauthenticated),
        (status = 403, response = BadOrigin),
        (status = 408, response = SlowRequest),
        (status = 429, response = RateLimited),
        (status = 500, response = Internal),
        (status = 503, response = Busy),
    ),
)]
async fn me(
    State(state): State<ApiState>,
    principal: Principal,
    ApiQuery(NoQuery {}): ApiQuery<NoQuery>,
) -> ApiJson<MeView> {
    let config = state.config();
    let mut deployments: Vec<&DeploymentId> = config
        .deployments()
        .iter()
        .map(Deployment::id)
        .filter(|id| sees(config, &principal, id))
        .collect();
    deployments.sort();
    let grants = deployments
        .into_iter()
        .map(|id| GrantView {
            deployment: id.clone(),
            can: PERMISSIONS
                .iter()
                .filter(|(permission, _)| can(config, &principal, id, *permission))
                .map(|(_, granted)| *granted)
                .collect(),
        })
        .collect();
    ApiJson(MeView {
        principal: principal.id().clone(),
        via: if principal.is_human() {
            Via::Session
        } else {
            Via::Token
        },
        grants,
        approve_url: config
            .approval()
            .map(|approval| format!("{}/approvals", approval.origin())),
    })
}

/// What `listDeployments` reads from its query string.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct DeploymentsQuery {
    /// Only the deployments on this host.
    #[param(value_type = Option<String>, example = "home-1")]
    host: Option<HostId>,
    /// Only the deployments of this repository.
    #[param(value_type = Option<String>, example = "example/app")]
    repo: Option<RepoName>,
    /// Only those whose `needs_you` is this.
    needs_you: Option<bool>,
    /// How many deployments a page holds: from 1 to 100, 50 if left out.
    #[param(value_type = Option<u8>, minimum = 1, maximum = 100, default = 50)]
    limit: Option<Limit>,
    /// The last page's `next_cursor`, to get the page after it.
    cursor: Option<String>,
}

/// What `deployment`'s host, as the configuration has it now, last said about it, among
/// `running`.
pub(super) fn host_said<'a>(
    running: &'a HashMap<DeploymentId, RunningRow>,
    deployment: &Deployment,
) -> Option<&'a RunningRow> {
    running
        .get(deployment.id())
        .filter(|row| row.host == *deployment.host())
}

/// What every deployment's summary is read from, read once for a whole answer.
pub(super) struct Facts {
    running: HashMap<DeploymentId, RunningRow>,
    open: Vec<StoredRequest>,
    /// Each deployment's newest release and where it stands, if it has one.
    latest: HashMap<DeploymentId, ReleaseBrief>,
}

impl Facts {
    /// What the hosts last said about `deployments`, the open requests, `open`, and each
    /// one's newest release.
    pub(super) async fn of(
        state: &ApiState,
        principal: &Principal,
        deployments: &[&Deployment],
        open: Vec<StoredRequest>,
    ) -> Result<Self, HumanProblem> {
        let ids: Vec<&DeploymentId> = deployments.iter().map(|d| d.id()).collect();
        let running = state.store().running_states(&ids).await?;
        let latest = releases::latest_of(state, principal, deployments, &running, &open).await?;
        Ok(Self {
            running,
            open,
            latest,
        })
    }

    /// What `deployment`'s host, as the configuration has it now, last said about it.
    fn running(&self, deployment: &Deployment) -> Option<RunningView> {
        let row = host_said(&self.running, deployment)?;
        Some(RunningView {
            tag: row.running.tag.clone(),
            digest: row.running.digest.clone(),
            phase: row.running.phase.clone(),
            busy: row.running.busy,
            drift: row.running.drift,
            config_drift: row.config_drift,
            healthy_secs: row.healthy_secs,
            last_report: row.last_report,
        })
    }
}

/// Every request waiting for an approver now: one at most for each deployment.
pub(super) async fn open_requests(state: &ApiState) -> Result<Vec<StoredRequest>, HumanProblem> {
    let store = state.store();
    Ok(store.open_requests(store.now()?).await?)
}

/// `deployment`'s open request, if it has one, and whether this principal could sign it.
fn waiting(
    config: &Config,
    principal: &Principal,
    deployment: &Deployment,
    open: &[StoredRequest],
) -> (Option<i64>, bool) {
    let request = open
        .iter()
        .find(|request| request.intent.deployment == *deployment.id());
    let needs_you =
        request.is_some() && can(config, principal, deployment.id(), Permission::Approve);
    (request.map(|request| request.id), needs_you)
}

pub(super) fn summary(
    config: &Config,
    principal: &Principal,
    deployment: &Deployment,
    facts: &Facts,
) -> DeploymentSummary {
    let (open_request, needs_you) = waiting(config, principal, deployment, &facts.open);
    DeploymentSummary {
        id: deployment.id().clone(),
        repo: deployment.repo().name().clone(),
        host: deployment.host().clone(),
        running: facts.running(deployment),
        latest: facts.latest.get(deployment.id()).cloned(),
        open_request,
        needs_you,
    }
}

/// `GET /api/v1/deployments`: the deployments this principal may view, in order of id, a page
/// at a time.
#[utoipa::path(
    get,
    path = "/api/v1/deployments",
    operation_id = "listDeployments",
    tag = "deployments",
    summary = "The deployments",
    description = "The deployments this principal may view, by id, a page at a time. Those they \
                   may not view are left out before the page is cut. `needs_you` is whether \
                   one has a request this principal could sign, which a token never can.",
    params(DeploymentsQuery),
    security(("token" = []), ("session" = [])),
    responses(
        (
            status = 200,
            description = "A page of the deployments this principal may view.",
            body = Page<DeploymentSummary>,
        ),
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
    ApiQuery(query): ApiQuery<DeploymentsQuery>,
) -> Result<ApiJson<Page<DeploymentSummary>>, HumanProblem> {
    let config = state.config();
    let after = query
        .cursor
        .as_deref()
        .map(|raw| Cursor::decode(raw, CursorList::Deployments))
        .transpose()?;
    let limit = Limit::or_default(query.limit);
    let open = open_requests(&state).await?;
    let mut shown: Vec<&Deployment> = viewable_deployments(config, &principal)
        .filter(|d| query.host.as_ref().is_none_or(|host| d.host() == host))
        .filter(|d| {
            query
                .repo
                .as_ref()
                .is_none_or(|repo| d.repo().name() == repo)
        })
        .filter(|d| {
            after
                .as_ref()
                .is_none_or(|after| d.id().as_ref() > after.after())
        })
        .filter(|d| {
            query
                .needs_you
                .is_none_or(|wanted| waiting(config, &principal, d, &open).1 == wanted)
        })
        .collect();
    shown.sort_by(|a, b| a.id().cmp(b.id()));
    let more = shown.len() > limit;
    shown.truncate(limit);
    let next_cursor = more
        .then(|| shown.last())
        .flatten()
        .map(|last| Cursor::new(CursorList::Deployments, last.id().as_ref()).encode());
    let facts = Facts::of(&state, &principal, &shown, open).await?;
    let items = shown
        .iter()
        .map(|d| summary(config, &principal, d, &facts))
        .collect();
    Ok(ApiJson(Page { items, next_cursor }))
}

fn rule_view(deployment: &Deployment) -> RuleView {
    let rule = deployment.rule();
    RuleView {
        auto: rule.auto().map(|level| level.to_string()),
        approve: rule.approve().map(|level| level.to_string()),
        approvers: rule.approvers().to_vec(),
        prereleases: rule.prereleases(),
    }
}

/// The deployments whose releases come on to `target`: each one this principal may view, by
/// id, then at most one marker for all those they may not, so that neither their names nor
/// how many there are is told. The marker carries the longest wait among those it stands for.
fn promoted_from(
    config: &Config,
    principal: &Principal,
    target: &DeploymentId,
) -> Vec<PromotionView> {
    let mut seen: Vec<(DeploymentId, u64)> = Vec::new();
    let mut unseen: Option<u64> = None;
    for source in config.deployments() {
        let Some(promotion) = source.promote_to().filter(|p| p.deployment() == target) else {
            continue;
        };
        let wait = promotion.healthy_for_secs();
        match shown_deployment(config, principal, source.id()) {
            DeploymentRef::Seen(id) => seen.push((id, wait)),
            DeploymentRef::Unseen => {
                unseen = Some(unseen.map_or(wait, |longest| longest.max(wait)));
            }
        }
    }
    seen.sort_by(|a, b| a.0.cmp(&b.0));
    seen.into_iter()
        .map(|(id, healthy_for_secs)| PromotionView {
            deployment: DeploymentRef::Seen(id),
            healthy_for_secs,
        })
        .chain(unseen.map(|healthy_for_secs| PromotionView {
            deployment: DeploymentRef::Unseen,
            healthy_for_secs,
        }))
        .collect()
}

/// `GET /api/v1/deployments/{name}/{stage}`: one deployment, with its rule, its promotions,
/// its holds and what its host last said.
#[utoipa::path(
    get,
    path = "/api/v1/deployments/{name}/{stage}",
    operation_id = "getDeployment",
    tag = "deployments",
    summary = "One deployment",
    description = "One deployment: what a list shows of it, its rule, where its releases go on \
                   to and come from, and the newest 50 of its holds with a count of all. A \
                   deployment this principal can't view is never named in a promotion.",
    params(DeploymentPath, NoQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "The deployment.", body = DeploymentView),
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
    path: Result<Path<DeploymentPath>, PathRejection>,
) -> Result<ApiJson<DeploymentView>, HumanProblem> {
    let config = state.config();
    let deployment = viewable(config, &principal, path.ok().map(|Path(path)| path.raw()))?;
    let open = open_requests(&state).await?;
    let facts = Facts::of(&state, &principal, &[deployment], open).await?;
    let (holds, holds_total) = state
        .store()
        .holds_of_deployment(deployment.id(), HOLDS_SHOWN)
        .await?;
    let promotion = |target: &DeploymentId, healthy_for_secs| PromotionView {
        deployment: shown_deployment(config, &principal, target),
        healthy_for_secs,
    };
    Ok(ApiJson(DeploymentView {
        summary: summary(config, &principal, deployment, &facts),
        rule: rule_view(deployment),
        promote_to: deployment
            .promote_to()
            .map(|p| promotion(p.deployment(), p.healthy_for_secs())),
        promoted_from: promoted_from(config, &principal, deployment.id()),
        holds: holds
            .into_iter()
            .map(|(tag, hold)| HoldView {
                tag,
                reason: hold.reason().to_owned(),
                since: hold.since,
                last_try: hold.last_try,
            })
            .collect(),
        holds_total,
    }))
}

/// The API's operations on who is asking and on deployments.
pub(super) fn routes() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(me))
        .routes(routes!(list))
        .routes(routes!(get))
}
