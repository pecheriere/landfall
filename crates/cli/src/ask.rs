//! The commands that ask the controller for something: `request deploy`, `rollback` and
//! `cancel`.
//!
//! A request waits for an approver, who signs it with a passkey on the controller's own page:
//! the CLI says where, and an agent can't approve. `rollback` says that it means a rollback,
//! so the controller refuses it as `not_a_rollback` rather than take a higher tag under the
//! `rollback` grant's name. With `--json`, each prints the controller's answer as it was
//! received, escaped; otherwise a view of it for a person, every string the controller sent
//! escaped.

use std::io::Write;

use clap::{Args, Subcommand};
use landfall_api::{ApprovalsView, NewRequest, ProblemCode, RequestState};
use landfall_core::ids::{DeploymentId, ReleaseTag};

use crate::api_client::{Api, ApiClient, ApiError, NO_BODY, deployment_path};
use crate::cli::{API_EXIT_STATUS, ApiArgs, CliError};
use crate::read::{render, show};

#[cfg(test)]
pub(crate) mod tests;

/// What `request deploy` and `rollback` say of approving, in their `--help`.
const APPROVING: &str = "\
The request waits for an approver, who signs it with a passkey on the
controller's page; this prints where. Agents can't approve.";

/// What `rollback` means, in its `--help`.
const ROLLING_BACK: &str = "\
The tag must be lower than what runs: otherwise, or when nothing runs or what
runs isn't a version, the controller refuses it as not_a_rollback. A request
for a lower tag by someone who may roll back takes the place of an open one.";

/// A command that asks the controller for something.
#[derive(Debug, Subcommand)]
pub enum AskCommand {
    /// Ask for something, which an approver then signs.
    #[command(subcommand)]
    Request(RequestCommand),
    /// Ask to go back to a release lower than what runs, once an approver signs it.
    #[command(after_help = format!("{ROLLING_BACK}\n\n{APPROVING}\n\n{API_EXIT_STATUS}"))]
    Rollback(TargetArgs),
    /// Cancel a request nobody has signed yet: whoever asked may, and so may who could
    /// approve it or roll back past it.
    #[command(after_help = API_EXIT_STATUS)]
    Cancel(CancelArgs),
}

/// What `landfall request` asks for.
#[derive(Debug, Subcommand)]
pub enum RequestCommand {
    /// Ask for a verified release of a deployment to be deployed, once an approver signs it.
    #[command(after_help = format!("{APPROVING}\n\n{API_EXIT_STATUS}"))]
    Deploy(TargetArgs),
}

/// A release of a deployment: `landfall request deploy` and `landfall rollback`.
#[derive(Debug, Args)]
pub struct TargetArgs {
    /// The deployment, `<name>/<stage>`.
    #[arg(value_name = "DEPLOYMENT")]
    deployment: DeploymentId,
    /// The release's tag.
    #[arg(value_name = "TAG")]
    tag: ReleaseTag,
    #[command(flatten)]
    api: ApiArgs,
}

/// `landfall cancel`.
#[derive(Debug, Args)]
pub struct CancelArgs {
    /// The request's number.
    #[arg(value_name = "REQUEST_ID", value_parser = clap::value_parser!(i64).range(1..))]
    request: i64,
    #[command(flatten)]
    api: ApiArgs,
}

impl AskCommand {
    /// Where the controller is, and how to print its answer.
    #[must_use]
    pub fn api(&self) -> &ApiArgs {
        match self {
            Self::Request(RequestCommand::Deploy(args)) | Self::Rollback(args) => &args.api,
            Self::Cancel(args) => &args.api,
        }
    }
}

/// Runs `command` against `client`, printing to `out`: the answer as received with `json`,
/// else a view of it for a person.
///
/// # Errors
///
/// [`CliError::Api`] if the controller refuses or can't be asked,
/// [`CliError::RequestOpen`] when a request it names already waits on the deployment,
/// [`CliError::RollbackNotUnderstood`] when it takes `rollback` for a bad request, and
/// [`CliError::Output`] if `out` fails.
pub async fn run_with<A: Api>(
    command: &AskCommand,
    client: &A,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    match command {
        AskCommand::Request(RequestCommand::Deploy(args)) => {
            ask(args, false, client, out, json).await
        }
        AskCommand::Rollback(args) => ask(args, true, client, out, json).await,
        AskCommand::Cancel(args) => {
            let path = format!("/api/v1/approvals/{}/cancel", args.request);
            let text = client.post(&path, NO_BODY).await?;
            show(out, json, &text, render::cancelled)
        }
    }
}

/// `requestDeploy` for `args`, meant as a rollback or not.
async fn ask<A: Api>(
    args: &TargetArgs,
    rollback: bool,
    client: &A,
    out: &mut dyn Write,
    json: bool,
) -> Result<(), CliError> {
    let body = NewRequest {
        tag: args.tag.clone(),
        rollback,
    };
    let path = format!("{}/requests", deployment_path(&args.deployment));
    match client.post(&path, Some(&body)).await {
        Ok(text) => show(out, json, &text, render::request),
        Err(
            refusal @ ApiError::Refused {
                code: ProblemCode::BadRequest,
                ..
            },
        ) if rollback => Err(CliError::RollbackNotUnderstood(refusal)),
        Err(
            refusal @ ApiError::Refused {
                code: ProblemCode::RequestOpen,
                ..
            },
        ) => Err(open_request(client, &args.deployment, refusal).await),
        Err(error) => Err(error.into()),
    }
}

/// `refusal`, a `request_open`, naming the request that waits on `deployment` when this
/// principal may see it. The refusal is what the command ends with either way, so a list that
/// can't be read or doesn't hold it leaves it as it is.
async fn open_request<A: Api>(
    client: &A,
    deployment: &DeploymentId,
    refusal: ApiError,
) -> CliError {
    let open = client
        .get("/api/v1/approvals", &[])
        .await
        .and_then(|text| ApiClient::typed::<ApprovalsView>(&text))
        .ok()
        .and_then(|approvals| {
            approvals
                .approvals
                .into_iter()
                .find(|request| {
                    request.intent.deployment == *deployment
                        && request.state == RequestState::AwaitingApproval
                })
                .map(|request| request.id)
        });
    match open {
        Some(request) => CliError::RequestOpen {
            request,
            deployment: deployment.clone(),
            source: refusal,
        },
        None => refusal.into(),
    }
}
