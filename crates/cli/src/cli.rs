//! The command line: what it takes, and what comes of it.

use std::error::Error;
use std::fmt;
use std::io::Write;

use clap::{Parser, Subcommand};
use thiserror::Error;

use crate::verify;

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

/// A command.
#[derive(Debug, Subcommand)]
pub enum Command {
    /// Verify a release of a deployment as a host would before deploying it:
    /// tag signature, image index, build-provenance attestation and
    /// platform. Prints where it came from as JSON.
    #[command(after_help = VERIFY_EXIT_STATUS)]
    Verify(verify::VerifyArgs),
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
    /// The result could not be written to stdout.
    #[error("cannot write the result")]
    Output(#[source] std::io::Error),
}

impl CliError {
    fn exit_code(&self) -> u8 {
        match self {
            Self::Verify(error) => error.exit_code(),
            Self::Runtime(_) | Self::Output(_) => verify::EXIT_UNVERIFIED,
        }
    }
}

/// Runs a command, reports a failure on stderr, and gives the process's exit status: 0, or
/// what the failure was.
#[must_use]
pub fn run(cli: Cli) -> u8 {
    match run_command(cli) {
        Ok(()) => 0,
        Err(error) => {
            // Nothing more can be reported if stderr itself fails.
            let _ = writeln!(std::io::stderr().lock(), "landfall: {}", Chain(&error));
            error.exit_code()
        }
    }
}

fn run_command(cli: Cli) -> Result<(), CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)?;
    match cli.command {
        Command::Verify(args) => {
            let origin = runtime.block_on(verify::run(args))?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &origin)
                .map_err(|e| CliError::Output(e.into()))?;
            writeln!(stdout).map_err(CliError::Output)?;
            stdout.flush().map_err(CliError::Output)?;
        }
    }
    Ok(())
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
