//! `token create`, `token revoke` and `passkey-invite`: run against the database, like
//! `enrol-code`, while `serve` runs or not.

use std::io::Write;
use std::path::{Path, PathBuf};

use clap::{Args, Subcommand};
use landfall_core::ids::PrincipalId;
use serde_json::json;

use super::{CliError, EXIT_OK, load_config, opened};
use crate::auth::named_in_config;
use crate::store::Store;

/// Where a passkey invite's page is. The code goes after `#`: a browser doesn't send that
/// part, so it reaches no access log.
const REGISTRATION_PATH: &str = "/passkeys/register";

#[derive(Debug, Subcommand)]
pub(super) enum TokenCommand {
    /// Make an API token for a principal the configuration names, and print it once as
    /// JSON, with the id that revokes it. Only its hash is kept: nothing can show it again.
    Create(TokenCreateArgs),
    /// Revoke an API token by its id, from its next use on.
    Revoke(TokenRevokeArgs),
}

#[derive(Debug, Args)]
pub(super) struct TokenCreateArgs {
    /// Who it acts for. Its grants are this principal's, without `approve`, which a token
    /// never has.
    #[arg(long, value_name = "NAME")]
    principal: PrincipalId,
    /// The fleet configuration file, which must name the principal.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The database file `serve` uses, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
}

#[derive(Debug, Args)]
pub(super) struct TokenRevokeArgs {
    /// The id `token create` printed, also in the audit log's `token_created` rows.
    #[arg(long, value_name = "ID")]
    id: i64,
    /// The database file `serve` uses, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
}

#[derive(Debug, Args)]
pub(super) struct PasskeyInviteArgs {
    /// Who will register a passkey. They need not be in the configuration yet: this is how
    /// they get the key to add to it.
    #[arg(long, value_name = "NAME")]
    principal: PrincipalId,
    /// The fleet configuration file, for the controller's origin.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The database file `serve` uses, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
}

/// The database `serve` uses, if it has the tables these commands use: only `serve`
/// migrates, so a database from before an upgrade gets told so rather than a raw error.
async fn upgraded(db: &Path) -> Result<Store, CliError> {
    let store = opened(db).await?;
    let current = store.schema_is_current().await;
    if !current? {
        store.close().await;
        return Err(CliError::OutOfDate {
            path: db.to_owned(),
        });
    }
    Ok(store)
}

pub(super) async fn token(command: TokenCommand, out: &mut impl Write) -> Result<u8, CliError> {
    match command {
        TokenCommand::Create(args) => create(args, out).await,
        TokenCommand::Revoke(args) => revoke(args, out).await,
    }
}

async fn create(args: TokenCreateArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let config = load_config(&args.config)?;
    if !named_in_config(&config, &args.principal) {
        return Err(CliError::UnknownPrincipal(args.principal));
    }
    let store = upgraded(&args.db).await?;
    let made = store.create_token(&args.principal).await;
    store.close().await;
    let (id, token) = made?;
    let line = json!({ "id": id, "principal": args.principal, "token": token.reveal() });
    writeln!(out, "{line}").map_err(CliError::Output)?;
    Ok(EXIT_OK)
}

async fn revoke(args: TokenRevokeArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = upgraded(&args.db).await?;
    let revoked = store.revoke_token(args.id).await;
    store.close().await;
    let line = json!({ "id": args.id, "already_revoked": !revoked? });
    writeln!(out, "{line}").map_err(CliError::Output)?;
    Ok(EXIT_OK)
}

pub(super) async fn passkey_invite(
    args: PasskeyInviteArgs,
    out: &mut impl Write,
) -> Result<u8, CliError> {
    let config = load_config(&args.config)?;
    let Some(settings) = config.approval() else {
        return Err(CliError::NoApprovalSettings);
    };
    let store = upgraded(&args.db).await?;
    let issued = store.issue_passkey_invite(&args.principal).await;
    store.close().await;
    let code = issued?.reveal();
    writeln!(out, "{}{REGISTRATION_PATH}#{code}", settings.origin()).map_err(CliError::Output)?;
    Ok(EXIT_OK)
}
