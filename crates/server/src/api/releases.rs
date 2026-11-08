//! A deployment's releases and the story of one: `GET /api/v1/deployments/{name}/{stage}/releases`
//! and `GET /api/v1/deployments/{name}/{stage}/releases/{tag}`.
//!
//! A release is one the watcher recorded. Where each stands is [`story::status`]'s to say,
//! from what is known of it now. A list is in the order of semantic versions, highest first,
//! by the deployment's tag pattern, and tags the pattern doesn't read come last, in string
//! order. No index holds that order, so each page sorts the deployment's releases in memory:
//! at most [`MAX_LISTED_TAGS`](landfall_origin::fetch::MAX_LISTED_TAGS), the watcher's own
//! bound on its tags. Seeing them takes `view`. These change nothing.

use std::cmp::Reverse;
use std::collections::HashMap;

use axum::extract::rejection::PathRejection;
use axum::extract::{Path, State};
use landfall_api::{
    CommitSource, CommitView, CommitsState, CommitsView, DeployBrief, OriginView, Page,
    ReleaseBrief, ReleaseStory, ReleaseView, RequestBrief, RequestState as RequestStateView,
};
use landfall_core::config::{Config, Deployment};
use landfall_core::ids::{DeploymentId, ReleaseTag, TagPattern};
use landfall_core::rule::decide;
use landfall_origin::fetch::compare_url;
use semver::Version;
use serde::Deserialize;
use serde_json::Value;
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use super::ApiJson;
use super::deployments::{host_said, open_requests};
use super::openapi::{
    BadRequest, Busy, Internal, NotFound, RateLimited, ReadForbidden, SlowRequest, Unauthenticated,
};
use super::query::{ApiQuery, Cursor, CursorList, DeploymentPath, Limit, NoQuery, TagPath};
use super::story::{RuleSaid, StatusExplained, StoryInputs, decided, recorded, status};
use super::visible::{shown_deployment, viewable};
use crate::agent_api::{ApiProblem, ApiState};
use crate::auth::{HumanProblem, Principal};
use crate::store::history::{DeployRow, LastFinished, ReleaseRow, RequestRow, outcome};
use crate::store::views::RunningRow;
use crate::store::{Hold, RangeState, RequestState, Store, StoreError, StoredRequest};
use crate::watcher::commits::SettledByVersion;

/// The most requests, and the most deploys, a story shows: the newest.
const STORY_ROWS: u32 = 20;

/// Where a release falls in a list: by version, highest first, then the tags the pattern
/// doesn't read, in string order.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord)]
enum Order {
    Version(Reverse<Version>, String),
    Unreadable(String),
}

impl Order {
    fn of(pattern: &TagPattern, tag: &ReleaseTag) -> Self {
        match pattern.parse_tag(tag) {
            Ok(version) => Self::Version(Reverse(version), tag.to_string()),
            Err(_) => Self::Unreadable(tag.to_string()),
        }
    }
}

/// What runs on a deployment, by version.
enum RunningVersion {
    Nothing,
    Readable(Version),
    /// A tag runs that the deployment's pattern doesn't read.
    Unreadable,
}

/// What every release's status on one deployment is decided from, read once for an answer.
struct Standing<'a> {
    config: &'a Config,
    principal: &'a Principal,
    deployment: &'a Deployment,
    running: Option<RunningRow>,
    running_version: RunningVersion,
    active: Option<ReleaseTag>,
    open: Option<ReleaseTag>,
    holds: HashMap<String, Hold>,
    whole: Option<Hold>,
    /// Whether any deployment promotes to this one.
    promoted_to: bool,
}

impl<'a> Standing<'a> {
    /// What `deployment`'s host said, `running`, its open request's tag, `open`, its holds,
    /// by tag and on the whole deployment, and its deploy in progress, `active`.
    fn new(
        state: &'a ApiState,
        principal: &'a Principal,
        deployment: &'a Deployment,
        (running, open): (Option<RunningRow>, Option<ReleaseTag>),
        (holds, whole): (HashMap<String, Hold>, Option<Hold>),
        active: Option<ReleaseTag>,
    ) -> Self {
        let config = state.config();
        let running_version = match running.as_ref().and_then(|row| row.running.tag.as_ref()) {
            None => RunningVersion::Nothing,
            Some(tag) => deployment
                .origin()
                .tags()
                .parse_tag(tag)
                .map_or(RunningVersion::Unreadable, RunningVersion::Readable),
        };
        let promoted_to = config.deployments().iter().any(|source| {
            source
                .promote_to()
                .is_some_and(|p| p.deployment() == deployment.id())
        });
        Self {
            config,
            principal,
            deployment,
            running,
            running_version,
            active,
            open,
            holds,
            whole,
            promoted_to,
        }
    }

    /// The same, reading what its host said and its open request too.
    async fn of(
        state: &'a ApiState,
        principal: &'a Principal,
        deployment: &'a Deployment,
    ) -> Result<Self, HumanProblem> {
        let store = state.store();
        let running = store.running_states(&[deployment.id()]).await?;
        let running = host_said(&running, deployment).cloned();
        let open = open_tag(&open_requests(state).await?, deployment);
        let holds = store.holds_of(deployment.id()).await?;
        let active = store.active_deploy_tag(deployment.id()).await?;
        Ok(Self::new(
            state,
            principal,
            deployment,
            (running, open),
            holds,
            active,
        ))
    }

    /// Where `row` stands, why, and what to do next, given `last`, the last finished deploy
    /// of each release by tag and digest.
    async fn explain(
        &self,
        store: &Store,
        row: &ReleaseRow,
        last: &HashMap<(String, String), LastFinished>,
    ) -> Result<StatusExplained, StoreError> {
        let release = &row.release;
        let version = self.deployment.origin().tags().parse_tag(&row.tag).ok();
        let rule = self.deployment.rule();
        let running = match &self.running_version {
            RunningVersion::Nothing => Some(None),
            RunningVersion::Readable(running) => Some(Some(running)),
            RunningVersion::Unreadable => None,
        };
        let rule_says = version
            .as_ref()
            .zip(running)
            .map(|(candidate, running)| RuleSaid {
                decision: decide(rule, running, candidate),
                running,
                candidate,
            });
        let lower_than_running = rule_says
            .is_some_and(|said| said.running.is_some_and(|running| said.candidate < running));
        let decided = decided(
            release.decision,
            release.reason(),
            release.origin_refused,
            rule_says,
        );
        let last = release
            .digest
            .as_ref()
            .and_then(|digest| last.get(&(row.tag.to_string(), digest.to_string())));
        let last_outcome = last
            .map(|last| {
                outcome(&last.outcome)
                    .map(|outcome| (outcome, last.reason.as_deref().unwrap_or("")))
            })
            .transpose()?;
        // As asking goes by it: a rollback doesn't wait for promotion.
        let promotion_waits_for = match release.settled() {
            Some((_, digest)) if self.promoted_to && !lower_than_running => store
                .promotion_waits_for(self.config, self.deployment.id(), (&row.tag, digest))
                .await?
                .map(|source| shown_deployment(self.config, self.principal, source)),
            _ => None,
        };
        let inputs = StoryInputs {
            tag: &row.tag,
            digest: release.digest.as_ref(),
            decision: decided.decision,
            decision_reason: &decided.reason,
            running: self.running.as_ref(),
            active_deploy: self.active.as_ref() == Some(&row.tag),
            open_request: self.open.as_ref() == Some(&row.tag),
            hold: self.holds.get(row.tag.as_ref()).or(self.whole.as_ref()),
            last_outcome,
            promotion_waits_for,
            lower_than_running,
        };
        Ok(status(&inputs))
    }

    /// `rows`, each with where it stands.
    async fn views(
        &self,
        store: &Store,
        rows: &[&ReleaseRow],
    ) -> Result<Vec<ReleaseView>, StoreError> {
        let tags: Vec<&ReleaseTag> = rows.iter().map(|row| &row.tag).collect();
        let last = store.last_finished(self.deployment.id(), &tags).await?;
        let mut views = Vec::with_capacity(rows.len());
        for row in rows {
            let explained = self.explain(store, row, &last).await?;
            views.push(view(row, &explained));
        }
        Ok(views)
    }
}

/// The tag `deployment`'s open request asks for, if it has one.
pub(super) fn open_tag(open: &[StoredRequest], deployment: &Deployment) -> Option<ReleaseTag> {
    open.iter()
        .find(|request| request.intent.deployment == *deployment.id())
        .map(|request| request.intent.tag.clone())
}

fn view(row: &ReleaseRow, explained: &StatusExplained) -> ReleaseView {
    ReleaseView {
        tag: row.tag.clone(),
        status: explained.status,
        decision: recorded(row.release.decision),
        first_seen_at: row.first_seen_at,
        seen_at: row.seen_at,
    }
}

/// Each of `deployments`' newest release, the first a list of its releases shows, and where
/// it stands: for their summaries. `running` and `open` are what their hosts said and the
/// open requests. A fixed number of statements on indexes, whatever their histories hold,
/// but for promotion, looked up for a deployment something promotes to.
pub(super) async fn latest_of(
    state: &ApiState,
    principal: &Principal,
    deployments: &[&Deployment],
    running: &HashMap<DeploymentId, RunningRow>,
    open: &[StoredRequest],
) -> Result<HashMap<DeploymentId, ReleaseBrief>, StoreError> {
    let store = state.store();
    let wanted: Vec<(&DeploymentId, &str)> = deployments
        .iter()
        .map(|d| (d.id(), d.origin().tags().prefix()))
        .collect();
    let mut facts = store.latest_facts(&wanted).await?;
    let mut latest = HashMap::new();
    let none = HashMap::new();
    for d in deployments {
        let Some(row) = facts.rows.get(d.id()) else {
            continue;
        };
        let standing = Standing::new(
            state,
            principal,
            d,
            (host_said(running, d).cloned(), open_tag(open, d)),
            facts.holds.remove(d.id()).unwrap_or_default(),
            facts.active.remove(d.id()),
        );
        let last = facts.last.get(d.id()).unwrap_or(&none);
        let explained = standing.explain(store, row, last).await?;
        latest.insert(
            d.id().clone(),
            ReleaseBrief {
                tag: row.tag.clone(),
                status: explained.status,
            },
        );
    }
    Ok(latest)
}

/// What `listReleases` reads from its query string.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct ReleasesQuery {
    /// How many releases a page holds: from 1 to 100, 50 if left out.
    #[param(value_type = Option<u8>, minimum = 1, maximum = 100, default = 50)]
    limit: Option<Limit>,
    /// The last page's `next_cursor`, to get the page after it.
    cursor: Option<String>,
}

/// `GET /api/v1/deployments/{name}/{stage}/releases`: the releases the controller recorded,
/// highest version first, a page at a time.
#[utoipa::path(
    get,
    path = "/api/v1/deployments/{name}/{stage}/releases",
    operation_id = "listReleases",
    tag = "releases",
    summary = "A deployment's releases",
    description = "The releases the controller recorded for a deployment, each with where it \
                   stands, a page at a time: highest semantic version first by the \
                   deployment's tag pattern, then the tags it doesn't read, in string order. \
                   At most the 5,000 first recorded most recently are listed.",
    params(DeploymentPath, ReleasesQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "A page of the releases.", body = Page<ReleaseView>),
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
    ApiQuery(query): ApiQuery<ReleasesQuery>,
    path: Result<Path<DeploymentPath>, PathRejection>,
) -> Result<ApiJson<Page<ReleaseView>>, HumanProblem> {
    let config = state.config();
    let deployment = viewable(config, &principal, path.ok().map(|Path(path)| path.raw()))?;
    let pattern = deployment.origin().tags();
    let after = match query.cursor.as_deref() {
        None => None,
        Some(raw) => {
            let cursor = Cursor::decode(raw, CursorList::Releases)?;
            let tag: ReleaseTag = cursor.after().parse().map_err(|_| ApiProblem::BadRequest)?;
            Some(Order::of(pattern, &tag))
        }
    };
    let limit = Limit::or_default(query.limit);
    let store = state.store();
    let rows = store.release_rows(deployment.id()).await?;
    let mut ordered: Vec<(Order, &ReleaseRow)> = rows
        .iter()
        .map(|row| (Order::of(pattern, &row.tag), row))
        .filter(|(order, _)| after.as_ref().is_none_or(|after| order > after))
        .collect();
    ordered.sort_by(|a, b| a.0.cmp(&b.0));
    let more = ordered.len() > limit;
    ordered.truncate(limit);
    let page: Vec<&ReleaseRow> = ordered.into_iter().map(|(_, row)| row).collect();
    let next_cursor = more
        .then(|| page.last())
        .flatten()
        .map(|last| Cursor::new(CursorList::Releases, last.tag.as_ref()).encode());
    let standing = Standing::of(&state, &principal, deployment).await?;
    let items = standing.views(store, &page).await?;
    Ok(ApiJson(Page { items, next_cursor }))
}

/// The commits `row` brings over the settled release below it among `rows`, and what the
/// story says of them beyond its status.
async fn commits_of(
    store: &Store,
    config: &Config,
    deployment: &Deployment,
    row: &ReleaseRow,
    rows: &[ReleaseRow],
) -> Result<(CommitsView, Vec<String>), StoreError> {
    let hash = config.hash();
    let settled_head = |row: &ReleaseRow| {
        row.release
            .verified_under(hash)
            .then(|| row.release.settled())
            .flatten()
            .map(|(commit, _)| commit.clone())
    };
    let view = |state, base: Option<&ReleaseTag>, compare: Option<String>| CommitsView {
        source: CommitSource::Github,
        verified: false,
        state,
        base: base.cloned(),
        total: None,
        compare_url: compare,
        commits: Vec::new(),
    };
    let pattern = deployment.origin().tags();
    let (Some(head), Ok(version)) = (settled_head(row), pattern.parse_tag(&row.tag)) else {
        return Ok((view(CommitsState::NotRecorded, None, None), Vec::new()));
    };
    let settled = SettledByVersion::new(
        pattern,
        rows.iter()
            .filter_map(|row| Some((row.tag.clone(), settled_head(row)?, ()))),
    );
    let Some((base, base_commit)) = settled.base_of(&version) else {
        return Ok((view(CommitsState::First, None, None), Vec::new()));
    };
    let repo = deployment.repo().name();
    let compare = compare_url(repo, base_commit, &head);
    let Some(range) = store.commit_range(repo, base_commit, &head).await? else {
        let fetched = store
            .commits_began()
            .await?
            .is_some_and(|since| row.first_seen_at >= since);
        let state = if fetched {
            CommitsState::NotYet
        } else {
            CommitsState::NotRecorded
        };
        return Ok((view(state, Some(base), Some(compare)), Vec::new()));
    };
    let mut reasons = Vec::new();
    let state = match range.state {
        RangeState::Listed => CommitsState::Listed,
        RangeState::Unavailable => CommitsState::Unavailable,
        RangeState::BaseNotFound => {
            reasons.push(format!(
                "its commits aren't listed: the commit of {base}, the release below it, isn't \
                 an ancestor of this one's, so the history was rewritten between them"
            ));
            CommitsState::BaseNotFound
        }
        RangeState::TooLarge => {
            reasons.push(format!(
                "its commits since {base} are too many for GitHub to list: read them at \
                 {compare}"
            ));
            CommitsState::TooLarge
        }
    };
    let mut commits = view(state, Some(base), Some(compare));
    if state == CommitsState::Listed {
        let listed = range.commits.len();
        if let Some(total) = range
            .total
            .filter(|total| usize::try_from(*total).ok() != Some(listed))
        {
            reasons.push(format!(
                "the commits listed since {base} are the newest {listed} of {total}"
            ));
        }
        commits.total = range.total;
        commits.commits = range
            .commits
            .into_iter()
            .map(|commit| CommitView {
                sha: commit.sha,
                summary: commit.summary,
                author: commit.author,
            })
            .collect();
    }
    Ok((commits, reasons))
}

/// Where `row` came from, from its `origin` column, if it verified and hasn't been refused
/// since.
fn origin_of(row: &ReleaseRow, origin: Option<Value>) -> Result<Option<OriginView>, StoreError> {
    if row.release.settled().is_none() {
        return Ok(None);
    }
    origin
        .map(|origin| serde_json::from_value(origin).map_err(|_| StoreError::Corrupt("origin")))
        .transpose()
}

fn request_brief(row: RequestRow) -> RequestBrief {
    RequestBrief {
        id: row.id,
        state: match row.state {
            RequestState::AwaitingApproval => RequestStateView::AwaitingApproval,
            RequestState::Approved => RequestStateView::Approved,
            RequestState::Stale => RequestStateView::Stale,
            RequestState::Expired => RequestStateView::Expired,
            RequestState::Cancelled => RequestStateView::Cancelled,
        },
        requested_by: row.requested_by,
        approved_by: row.approved_by,
        created_at: row.created_at,
        closed_reason: row.closed_reason,
    }
}

fn deploy_brief(row: &DeployRow) -> DeployBrief {
    DeployBrief {
        id: row.id,
        state: row.state,
        outcome: row.outcome,
        created_at: row.created_at,
        finished_at: row.finished_at,
    }
}

/// `GET /api/v1/deployments/{name}/{stage}/releases/{tag}`: one release, why it stands
/// where it does, where it came from, its commits, and its requests and deploys.
#[utoipa::path(
    get,
    path = "/api/v1/deployments/{name}/{stage}/releases/{tag}",
    operation_id = "getRelease",
    tag = "releases",
    summary = "One release, and its story",
    description = "One release the controller recorded: where it stands and why, what to do \
                   next, where it came from, the commits it brings over the verified release \
                   below it as GitHub lists them, and its newest 20 requests and deploys. A \
                   tag the controller hasn't recorded is `404`.",
    params(TagPath, NoQuery),
    security(("token" = ["view"]), ("session" = ["view"])),
    responses(
        (status = 200, description = "The release's story.", body = ReleaseStory),
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
    path: Result<Path<TagPath>, PathRejection>,
) -> Result<ApiJson<ReleaseStory>, HumanProblem> {
    let config = state.config();
    let path = path.ok().map(|Path(path)| path);
    let deployment = viewable(
        config,
        &principal,
        path.as_ref().map(TagPath::raw_deployment),
    )?;
    let tag = path
        .and_then(|path| path.tag.parse::<ReleaseTag>().ok())
        .ok_or(HumanProblem::NotFound)?;
    let store = state.store();
    let (row, origin) = store
        .release_row(deployment.id(), &tag)
        .await?
        .ok_or(HumanProblem::NotFound)?;
    let standing = Standing::of(&state, &principal, deployment).await?;
    let last = store.last_finished(deployment.id(), &[&row.tag]).await?;
    let explained = standing.explain(store, &row, &last).await?;
    let rows = store.release_rows(deployment.id()).await?;
    let (commits, more) = commits_of(store, config, deployment, &row, &rows).await?;
    let requests = store
        .requests_of_release(deployment.id(), &tag, STORY_ROWS)
        .await?;
    let deploys = store
        .deploys_of_release(deployment.id(), &tag, STORY_ROWS)
        .await?;
    let release = view(&row, &explained);
    let mut reasons = explained.reasons;
    reasons.extend(more);
    Ok(ApiJson(ReleaseStory {
        release,
        reasons,
        next: explained.next,
        origin: origin_of(&row, origin)?,
        commits,
        requests: requests.into_iter().map(request_brief).collect(),
        deploys: deploys.iter().map(deploy_brief).collect(),
    }))
}

/// The API's operations on releases.
pub(super) fn routes() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new()
        .routes(routes!(list))
        .routes(routes!(get))
}
