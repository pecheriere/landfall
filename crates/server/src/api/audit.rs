//! The audit log, as far as a principal may see it: `GET /api/v1/audit`.
//!
//! A row about a deployment is seen with `view` on it. A row about a host alone is seen only
//! if its kind is one of [`HOST_ROW_KINDS`], and only with `view` on a deployment the
//! configuration puts on that host. A row about neither (tokens, passkeys, sign-ins,
//! throttling) never comes through the API. All of that is in the query: one branch for each
//! deployment and host the principal may see, each read from its index, so that a page is
//! never short of what they may see and a cursor can't reach past it. A filter only narrows
//! that scope, so one naming what the principal can't see gives an empty page, and says
//! nothing. This changes nothing.
//!
//! [`HOST_ROW_KINDS`]: crate::store::views::HOST_ROW_KINDS

use std::collections::BTreeSet;

use axum::extract::State;
use landfall_api::{AuditEntry, Page, RawJson};
use landfall_core::config::Deployment;
use landfall_core::ids::{DeploymentId, HostId};
use landfall_core::text::{quoted, shown};
use serde::Deserialize;
use serde_json::{Value, json};
use utoipa::IntoParams;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

use self::detail::Reader;
use super::ApiJson;
use super::openapi::{
    BadOrigin, BadRequest, Busy, Internal, RateLimited, SlowRequest, Unauthenticated,
};
use super::query::{ApiQuery, Cursor, CursorList, Limit, id_number};
use super::visible::viewable_deployments;
use crate::agent_api::{ApiProblem, ApiState};
use crate::audit::EventKind;
use crate::auth::{HumanProblem, Principal};
use crate::store::views::{AuditBranches, AuditScope};
use crate::store::{AuditRow, StoreError};

mod detail;

/// How much of a detail that isn't a JSON object an entry quotes, in characters.
const UNREADABLE_CHARS: usize = 256;

/// What `listAudit` reads from its query string.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct AuditQuery {
    /// Only the rows about this deployment.
    #[param(value_type = Option<String>, example = "app/prod")]
    deployment: Option<DeploymentId>,
    /// Only the rows about this host alone, and those about the deployments the configuration
    /// puts on it.
    #[param(value_type = Option<String>, example = "home-1")]
    host: Option<HostId>,
    /// Only the rows of this kind: a name the log uses, such as `deploy_queued`. Any other is
    /// refused.
    #[param(example = "deploy_queued")]
    kind: Option<String>,
    /// How many rows a page holds: from 1 to 100, 50 if left out.
    #[param(value_type = Option<u8>, minimum = 1, maximum = 100, default = 50)]
    limit: Option<Limit>,
    /// The last page's `next_cursor`, to get the page after it.
    cursor: Option<String>,
}

/// A row as `reader` may see it: its detail as its kind shows it, and its host only if they
/// may see that host. A detail that isn't a JSON object, which only someone editing the
/// database writes, is shown quoted, as unreadable, rather than failing the page, and so is a
/// kind this version doesn't know.
fn entry(reader: &Reader<'_>, row: AuditRow) -> Result<AuditEntry, StoreError> {
    let kind = row.kind.parse::<EventKind>().ok();
    let detail = match serde_json::from_str::<Value>(&row.detail) {
        Ok(Value::Object(stored)) => reader.detail(kind, &stored),
        _ => json!({ "unreadable": quoted(&row.detail, UNREADABLE_CHARS) }),
    };
    Ok(AuditEntry {
        seq: row.seq,
        ts: row.ts,
        kind: kind.map_or_else(|| shown(&row.kind), |kind| kind.as_str().to_owned()),
        // Each row was selected by a configured deployment's id, or a host's.
        deployment: row.deployment.and_then(|id| id.parse().ok()),
        host: reader.host(row.host.as_deref()),
        detail: RawJson::from_value(&detail)?,
    })
}

/// `GET /api/v1/audit`: the audit log as far as this principal may see it, newest first, a page
/// at a time.
#[utoipa::path(
    get,
    path = "/api/v1/audit",
    operation_id = "listAudit",
    tag = "audit",
    summary = "The audit log",
    description = "The rows of the audit log this principal may see, newest first, a page at a \
                   time: those about a deployment they may view, and a host's `host_enrolled` \
                   and `config_drift` rows where they may view a deployment on it. Rows about \
                   tokens, passkeys, sign-ins and throttling are never listed. A `deployment` \
                   or `host` filter on what they can't see gives an empty page. Sequence \
                   numbers are the whole log's, so gaps are rows this principal can't see. A \
                   page over more than 400 deployments and hosts' kinds at once is refused \
                   with `bad_request`, asking for a filter.",
    params(AuditQuery),
    security(("token" = []), ("session" = [])),
    responses(
        (
            status = 200,
            description = "A page of the rows this principal may see.",
            body = Page<AuditEntry>,
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
    ApiQuery(query): ApiQuery<AuditQuery>,
) -> Result<ApiJson<Page<AuditEntry>>, HumanProblem> {
    let kind = query
        .kind
        .as_deref()
        .map(|name| name.parse().map(EventKind::as_str))
        .transpose()
        .map_err(|_| ApiProblem::BadRequest)?;
    let before = match query.cursor.as_deref() {
        None => None,
        Some(raw) => {
            let cursor = Cursor::decode(raw, CursorList::Audit)?;
            Some(id_number(cursor.after()).ok_or(ApiProblem::BadRequest)?)
        }
    };
    let limit = Limit::or_default(query.limit);
    let shown: Vec<&Deployment> = viewable_deployments(state.config(), &principal)
        .filter(|d| query.deployment.as_ref().is_none_or(|id| d.id() == id))
        .filter(|d| query.host.as_ref().is_none_or(|host| d.host() == host))
        .collect();
    let deployments: Vec<&DeploymentId> = shown.iter().map(|d| d.id()).collect();
    // A row about a host alone is about no deployment, so a deployment filter leaves it out.
    let hosts: Vec<&HostId> = if query.deployment.is_some() {
        Vec::new()
    } else {
        let hosts: BTreeSet<&HostId> = shown.iter().map(|d| d.host()).collect();
        hosts.into_iter().collect()
    };
    let scope = AuditScope {
        deployments: &deployments,
        hosts: &hosts,
    };
    let branches = AuditBranches::new(&scope, kind).ok_or(HumanProblem::AuditTooWide)?;
    // One more than the page, to know whether there is a next one.
    let wanted = u32::try_from(limit).unwrap_or(u32::MAX).saturating_add(1);
    let mut rows = state.store().audit_page(&branches, before, wanted).await?;
    let more = rows.len() > limit;
    rows.truncate(limit);
    let next_cursor = more
        .then(|| rows.last())
        .flatten()
        .map(|last| Cursor::new(CursorList::Audit, last.seq.to_string()).encode());
    let reader = Reader::new(state.config(), &principal);
    Ok(ApiJson(Page {
        items: rows
            .into_iter()
            .map(|row| entry(&reader, row))
            .collect::<Result<_, _>>()?,
        next_cursor,
    }))
}

/// The API's operations on the audit log.
pub(super) fn routes() -> OpenApiRouter<ApiState> {
    OpenApiRouter::new().routes(routes!(list))
}
