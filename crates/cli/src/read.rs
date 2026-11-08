//! The commands that read the controller's state: `status`, `history`, `release`,
//! `releases`, `why`, `hosts`, `audit` and `approvals`.
//!
//! Each makes at most three calls, but for `status` with no deployment, which pages through
//! the deployments within a cap. With `--json`, each prints the controller's answer as it was
//! received, escaped; `status` prints the items of every page it read. Otherwise each prints a
//! view of it for a person, every string the controller sent escaped, by `render`.

use std::collections::HashSet;
use std::io::Write;

use clap::{Args, Subcommand};
use landfall_api::{ApprovalsView, DeploymentSummary, MeView, Page};
use landfall_core::ids::{DeploymentId, HostId, ReleaseTag, RepoName};
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use crate::api_client::{ApiClient, ApiError, deployment_path, segment};
use crate::cli::{API_EXIT_STATUS, ApiArgs, CliError};
use crate::display::write_json;

mod render;
#[cfg(test)]
pub(crate) mod tests;

/// The most deployments `status` lists.
const MAX_ITEMS: usize = 1000;

/// The most pages `status` reads.
const MAX_PAGES: usize = 20;

/// What `status` asks for in a page: the most the API gives.
const PAGE_LIMIT: &str = "100";

/// How `status` pages, shown in its `--help`.
const STATUS_PAGING: &str = "\
Without a deployment, status reads the deployments a page of 100 at a time, and stops at
1,000 deployments or 20 pages, or when the controller sends a cursor twice, with a line
saying which.";

/// The controller's API, as the read commands use it: [`ApiClient`], or a fake in tests.
///
/// It is used generically, never as `&dyn Api`: a method returning `impl Future` isn't
/// dyn-compatible.
pub trait Api {
    /// `GET path?query`, and the body of its answer, as [`ApiClient::get`].
    fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> impl Future<Output = Result<Value, ApiError>> + Send;
}

impl Api for ApiClient {
    fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> impl Future<Output = Result<Value, ApiError>> + Send {
        ApiClient::get(self, path, query)
    }
}

/// A command that reads the controller's state.
#[derive(Debug, Subcommand)]
pub enum ReadCommand {
    /// Where each deployment stands, or one in full: its rule, promotion, holds, what runs
    /// and its newest release.
    #[command(after_help = format!("{STATUS_PAGING}\n\n{API_EXIT_STATUS}"))]
    Status(StatusArgs),
    /// A deployment's deploys, newest first.
    #[command(after_help = API_EXIT_STATUS)]
    History(ListArgs),
    /// The story of one release: where it stands and why, what to do next, where it came
    /// from, the commits it brings, and what was asked and deployed of it.
    #[command(after_help = API_EXIT_STATUS)]
    Release(ReleaseArgs),
    /// A deployment's releases, newest first.
    #[command(after_help = API_EXIT_STATUS)]
    Releases(ListArgs),
    /// Why a deploy ended as it did, or where it stands, and what to do next.
    #[command(after_help = API_EXIT_STATUS)]
    Why(WhyArgs),
    /// The hosts and the deployments on each that this token may view, or one host.
    #[command(after_help = API_EXIT_STATUS)]
    Hosts(HostsArgs),
    /// The audit log, as far as this token may see it, newest first.
    #[command(after_help = API_EXIT_STATUS)]
    Audit(AuditArgs),
    /// The requests waiting for an approver, and where an approver signs them.
    #[command(after_help = API_EXIT_STATUS)]
    Approvals(ApprovalsArgs),
}

/// `landfall status`.
#[derive(Debug, Args)]
pub struct StatusArgs {
    /// One deployment, `<name>/<stage>`, in full.
    #[arg(value_name = "DEPLOYMENT", conflicts_with_all = ["host", "repo", "needs_you"])]
    deployment: Option<DeploymentId>,
    /// Only the deployments on this host.
    #[arg(long, value_name = "ID")]
    host: Option<HostId>,
    /// Only the deployments of this repository, `<owner>/<repo>`.
    #[arg(long, value_name = "NAME")]
    repo: Option<RepoName>,
    /// Only the deployments with a request this principal could sign.
    #[arg(long)]
    needs_you: bool,
    #[command(flatten)]
    api: ApiArgs,
}

/// A deployment's list: `landfall history` and `landfall releases`.
#[derive(Debug, Args)]
pub struct ListArgs {
    /// The deployment, `<name>/<stage>`.
    #[arg(value_name = "DEPLOYMENT")]
    deployment: DeploymentId,
    /// How many to list, from 1 to 100; the controller's default, 50, if left out.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=100))]
    limit: Option<u8>,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall release`.
#[derive(Debug, Args)]
pub struct ReleaseArgs {
    /// The deployment, `<name>/<stage>`.
    #[arg(value_name = "DEPLOYMENT")]
    deployment: DeploymentId,
    /// The release's tag.
    #[arg(value_name = "TAG")]
    tag: ReleaseTag,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall why`.
#[derive(Debug, Args)]
pub struct WhyArgs {
    /// The deploy's number.
    #[arg(value_name = "DEPLOY_ID", value_parser = clap::value_parser!(u64).range(1..))]
    deploy: u64,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall hosts`.
#[derive(Debug, Args)]
pub struct HostsArgs {
    /// One host, by id.
    #[arg(value_name = "HOST")]
    host: Option<HostId>,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall audit`.
#[derive(Debug, Args)]
pub struct AuditArgs {
    /// Only the rows about this deployment.
    #[arg(long, value_name = "ID")]
    deployment: Option<DeploymentId>,
    /// Only the rows about this host.
    #[arg(long, value_name = "ID")]
    host: Option<HostId>,
    /// Only the rows of this kind, such as `deploy_queued`.
    #[arg(long, value_name = "KIND")]
    kind: Option<String>,
    /// How many rows to list, from 1 to 100; the controller's default, 50, if left out.
    #[arg(long, value_name = "N", value_parser = clap::value_parser!(u8).range(1..=100))]
    limit: Option<u8>,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall approvals`.
#[derive(Debug, Args)]
pub struct ApprovalsArgs {
    #[command(flatten)]
    api: ApiArgs,
}

impl ReadCommand {
    /// Where the controller is, and how to print its answer.
    #[must_use]
    pub fn api(&self) -> &ApiArgs {
        match self {
            Self::Status(args) => &args.api,
            Self::History(args) | Self::Releases(args) => &args.api,
            Self::Release(args) => &args.api,
            Self::Why(args) => &args.api,
            Self::Hosts(args) => &args.api,
            Self::Audit(args) => &args.api,
            Self::Approvals(args) => &args.api,
        }
    }
}

/// Runs `command` against `client`, printing to `out`: the answer as received with `json`,
/// else a view of it for a person.
///
/// # Errors
///
/// [`CliError::Api`] if a call fails, [`CliError::Output`] if `out` does.
pub async fn run_with<A: Api>(
    command: &ReadCommand,
    client: &A,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    match command {
        ReadCommand::Status(args) => match &args.deployment {
            Some(deployment) => {
                let value = client.get(&deployment_path(deployment), &[]).await?;
                show(out, json, &value, render::deployment)
            }
            None => status_list(args, client, out, json).await,
        },
        ReadCommand::History(args) => {
            let path = format!("{}/deploys", deployment_path(&args.deployment));
            let value = client.get(&path, &pairs(&limit(args.limit))).await?;
            show(out, json, &value, render::deploys)
        }
        ReadCommand::Releases(args) => {
            let path = format!("{}/releases", deployment_path(&args.deployment));
            let value = client.get(&path, &pairs(&limit(args.limit))).await?;
            show(out, json, &value, render::releases)
        }
        ReadCommand::Release(args) => {
            let path = format!(
                "{}/releases/{}",
                deployment_path(&args.deployment),
                segment(args.tag.as_ref())
            );
            let value = client.get(&path, &[]).await?;
            show(out, json, &value, render::story)
        }
        ReadCommand::Why(args) => {
            let value = client
                .get(&format!("/api/v1/deploys/{}/why", args.deploy), &[])
                .await?;
            show(out, json, &value, render::why)
        }
        ReadCommand::Hosts(args) => {
            if let Some(host) = &args.host {
                let path = format!("/api/v1/hosts/{}", segment(host.as_ref()));
                let value = client.get(&path, &[]).await?;
                show(out, json, &value, render::host)
            } else {
                let value = client.get("/api/v1/hosts", &[]).await?;
                show(out, json, &value, render::hosts)
            }
        }
        ReadCommand::Audit(args) => {
            let mut query: Vec<(&str, String)> = Vec::new();
            if let Some(deployment) = &args.deployment {
                query.push(("deployment", deployment.to_string()));
            }
            if let Some(host) = &args.host {
                query.push(("host", host.to_string()));
            }
            if let Some(kind) = &args.kind {
                query.push(("kind", kind.clone()));
            }
            query.extend(limit(args.limit));
            let value = client.get("/api/v1/audit", &pairs(&query)).await?;
            show(out, json, &value, render::audit)
        }
        ReadCommand::Approvals(_) => approvals(client, out, json).await,
    }
}

/// `limit=N` when one is given.
fn limit(limit: Option<u8>) -> Vec<(&'static str, String)> {
    limit
        .map(|n| ("limit", n.to_string()))
        .into_iter()
        .collect()
}

fn pairs<'a>(query: &'a [(&'a str, String)]) -> Vec<(&'a str, &'a str)> {
    query
        .iter()
        .map(|(name, value)| (*name, value.as_str()))
        .collect()
}

/// Prints `value` as received with `json`, else through `view` once read as `T`.
fn show<T: DeserializeOwned>(
    out: &mut dyn Write,
    json: bool,
    value: &Value,
    view: fn(&T, &mut dyn Write) -> std::io::Result<()>,
) -> Result<(), CliError> {
    if json {
        return write_json(out, value).map_err(CliError::Output);
    }
    let typed: T = ApiClient::typed(value)?;
    view(&typed, out).map_err(CliError::Output)
}

/// Why `status` stopped paging before the last page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stopped {
    /// It holds [`MAX_ITEMS`].
    Items,
    /// It read [`MAX_PAGES`].
    Pages,
    /// The controller sent a cursor it had already sent.
    RepeatedCursor,
}

/// `listDeployments`, page by page, within the caps.
async fn status_list<A: Api>(
    args: &StatusArgs,
    client: &A,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    let mut filters: Vec<(&str, String)> = Vec::new();
    if let Some(host) = &args.host {
        filters.push(("host", host.to_string()));
    }
    if let Some(repo) = &args.repo {
        filters.push(("repo", repo.to_string()));
    }
    if args.needs_you {
        filters.push(("needs_you", "true".to_owned()));
    }
    filters.push(("limit", PAGE_LIMIT.to_owned()));

    let mut items: Vec<Value> = Vec::new();
    let mut seen = HashSet::new();
    let mut cursor: Option<String> = None;
    let mut pages = 0;
    let stopped = loop {
        let mut query = pairs(&filters);
        if let Some(cursor) = &cursor {
            query.push(("cursor", cursor));
        }
        let value = client.get("/api/v1/deployments", &query).await?;
        pages += 1;
        let page: Page<Value> = ApiClient::typed(&value)?;
        let room = MAX_ITEMS - items.len();
        items.extend(page.items.into_iter().take(room));
        let Some(next) = page.next_cursor else {
            break None;
        };
        if items.len() >= MAX_ITEMS {
            break Some(Stopped::Items);
        }
        if pages >= MAX_PAGES {
            break Some(Stopped::Pages);
        }
        if !seen.insert(next.clone()) {
            break Some(Stopped::RepeatedCursor);
        }
        cursor = Some(next);
    };

    if json {
        let mut body = json!({ "items": items });
        if let Some(stopped) = stopped {
            body["stopped"] = Value::String(render::stopped_text(stopped).to_owned());
        }
        return write_json(out, &body).map_err(CliError::Output);
    }
    let summaries: Vec<DeploymentSummary> = ApiClient::typed(&Value::Array(items))?;
    render::deployments(&summaries, out).map_err(CliError::Output)?;
    if let Some(stopped) = stopped {
        writeln!(out, "{}", render::stopped_text(stopped)).map_err(CliError::Output)?;
    }
    Ok(())
}

/// `listApprovals`, and, when a request is open and a person reads it, `whoAmI` for where an
/// approver signs.
async fn approvals<A: Api>(client: &A, out: &mut dyn Write, json: bool) -> Result<(), CliError> {
    let value = client.get("/api/v1/approvals", &[]).await?;
    if json {
        return write_json(out, &value).map_err(CliError::Output);
    }
    let approvals: ApprovalsView = ApiClient::typed(&value)?;
    let approve_url = if approvals.approvals.is_empty() {
        None
    } else {
        let me: MeView = ApiClient::typed(&client.get("/api/v1/me", &[]).await?)?;
        me.approve_url
    };
    render::approvals(&approvals, approve_url.as_deref(), out).map_err(CliError::Output)
}
