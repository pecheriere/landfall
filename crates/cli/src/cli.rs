//! The command line: what it takes, and what comes of it.

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand};
use thiserror::Error;

use crate::api_client::{ApiClient, ApiError};
use crate::display::safe;
use crate::read::{self, ReadCommand};
use crate::settings::{self, Env, ProcessEnv, SettingsError, SystemFiles};
use crate::{host, verify, whoami};

#[cfg(test)]
mod tests;

/// The command line.
#[derive(Debug, Parser)]
#[command(name = "landfall", version, about)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

/// The exit statuses of `landfall verify`, shown in its `--help`.
const VERIFY_EXIT_STATUS: &str = "\
Exit status:
  0  the release is verified
  1  the release is refused: a verification check failed
  2  the release could not be verified: configuration, usage, network,
     rate limit or trust root error

Environment:
  GITHUB_TOKEN  sent to the GitHub API (never to the registry) when set and
                non-empty, for its higher rate limit";

/// The exit statuses of the commands that call the controller's API, and where they find
/// it, shown in their `--help`.
pub(crate) const API_EXIT_STATUS: &str = "\
Exit status:
  0  done
  1  the controller refused: its problem code says why
  2  could not ask: configuration, credentials (401), network, rate limit
     (429) or server error

Environment:
  LANDFALL_CONTROLLER  the controller, when --controller isn't given
  LANDFALL_TOKEN       the API token. Or a file holding it, named by
                       --token-file, LANDFALL_TOKEN_FILE or token_file in the
                       configuration file, readable by its owner only. With
                       none, no token is sent, for a proxy that adds one.
  XDG_CONFIG_HOME      the configuration file is
                       $XDG_CONFIG_HOME/landfall/cli.toml, or
                       ~/.config/landfall/cli.toml, unless --cli-config names
                       another: controller, token_file and
                       allow_insecure_controller";

/// Where the controller is, and how to print what it says: each API command takes these, so
/// that they never clash with `host install`'s own `--controller`.
#[derive(Debug, Clone, Default, Args)]
pub struct ApiArgs {
    /// The controller's URL, `https://`. Else `LANDFALL_CONTROLLER`, else `controller` in the
    /// configuration file.
    #[arg(long, value_name = "URL")]
    pub controller: Option<String>,
    /// Allow an `http://` controller on a loopback address, `localhost` or a `*.ts.net` name. The
    /// token then goes in clear.
    #[arg(long)]
    pub allow_insecure_controller: bool,
    /// A file holding the API token, readable by its owner only.
    #[arg(long, value_name = "FILE")]
    pub token_file: Option<PathBuf>,
    /// The configuration file, instead of the default one, which then must exist.
    #[arg(long, value_name = "FILE")]
    pub cli_config: Option<PathBuf>,
    /// Print the controller's answer as JSON, as received.
    #[arg(long)]
    pub json: bool,
}

/// A command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify a release of a deployment as a host would before deploying it:
    /// tag signature, image index, build-provenance attestation and
    /// platform. Prints where it came from as JSON.
    #[command(after_help = VERIFY_EXIT_STATUS)]
    Verify(verify::VerifyArgs),
    /// Who the controller takes this token for, and what it may do to each deployment.
    #[command(after_help = API_EXIT_STATUS)]
    Whoami(ApiArgs),
    /// A command that reads the controller's state.
    #[command(flatten)]
    Read(ReadCommand),
    /// Install an agent on a host, over SSH.
    Host {
        /// What to do.
        #[command(subcommand)]
        command: host::HostCommand,
    },
}

/// Why the command failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum CliError {
    /// The async runtime could not start.
    #[error("cannot start the async runtime")]
    Runtime(#[source] std::io::Error),
    /// `landfall verify` refused the release or could not verify it.
    #[error(transparent)]
    Verify(#[from] verify::VerifyError),
    /// A `landfall host` command refused or couldn't go on.
    #[error(transparent)]
    Host(#[from] host::HostError),
    /// The API command's settings are missing or refused.
    #[error(transparent)]
    Settings(#[from] SettingsError),
    /// A call to the controller's API failed.
    #[error(transparent)]
    Api(#[from] ApiError),
    /// The result could not be written to stdout.
    #[error("cannot write the result")]
    Output(#[source] std::io::Error),
}

impl CliError {
    pub(crate) fn exit_code(&self) -> u8 {
        match self {
            Self::Verify(error) => error.exit_code(),
            Self::Host(error) => error.exit_code(),
            Self::Api(error) => error.exit_code(),
            Self::Runtime(_) | Self::Output(_) | Self::Settings(_) => verify::EXIT_UNVERIFIED,
        }
    }
}

/// Runs a command with this process's environment, stdout and stderr, and gives the process's
/// exit status.
#[must_use]
pub fn run(cli: Cli) -> u8 {
    run_with(
        cli,
        &ProcessEnv,
        &mut std::io::stdout().lock(),
        &mut std::io::stderr().lock(),
    )
}

/// Runs a command, writing what it prints to `out` and a failure to `err`, escaped, and gives
/// the exit status: 0, or what the failure was. API commands read their settings from `env`,
/// and token files from the real file system.
#[must_use]
pub fn run_with(cli: Cli, env: &dyn Env, out: &mut dyn Write, err: &mut dyn Write) -> u8 {
    let result = run_command(cli, env, out).and_then(|()| out.flush().map_err(CliError::Output));
    match result {
        Ok(()) => 0,
        Err(error) => {
            // A failure's text holds what the controller said: escape it all. Nothing more
            // can be reported if `err` itself fails.
            let _ = writeln!(err, "landfall: {}", safe(&Chain(&error).to_string()));
            error.exit_code()
        }
    }
}

fn run_command(cli: Cli, env: &dyn Env, out: &mut dyn Write) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    match cli.command {
        Command::Verify(args) => {
            let origin = runtime.block_on(verify::run(args))?;
            serde_json::to_writer_pretty(&mut *out, &origin)
                .map_err(|e| CliError::Output(e.into()))?;
            writeln!(out).map_err(CliError::Output)?;
        }
        Command::Whoami(args) => {
            whoami::run(&runtime, &client(&args, env)?, args.json, out)?;
        }
        Command::Read(command) => {
            let args = command.api();
            let client = client(args, env)?;
            runtime.block_on(read::run_with(&command, &client, out, args.json))?;
        }
        Command::Host { command } => {
            host::run(command, &runtime, out)?;
        }
    }
    Ok(())
}

/// A client for the controller `args` and `env` name, with the token they give.
fn client(args: &ApiArgs, env: &dyn Env) -> Result<ApiClient, CliError> {
    let settings = settings::resolve(args, env, &SystemFiles)?;
    Ok(ApiClient::new(&settings)?)
}

/// Displays an error and its sources as `error: source: source`.
struct Chain<'a>(&'a (dyn Error + 'static));

impl fmt::Display for Chain<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)?;
        let mut source = self.0.source();
        while let Some(error) = source {
            write!(f, ": {error}")?;
            source = error.source();
        }
        Ok(())
    }
}
