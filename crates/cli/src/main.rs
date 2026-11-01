//! `landfall`: Command-line client for the landfall API.

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use thiserror::Error;

mod verify;

#[derive(Parser)]
#[command(name = "landfall", version, about)]
struct Cli {
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

#[derive(Subcommand)]
enum Command {
    /// Verify a release of a deployment as a host would before deploying it:
    /// tag signature, image index, build-provenance attestation and
    /// platform. Prints where it came from as JSON.
    #[command(after_help = VERIFY_EXIT_STATUS)]
    Verify(verify::VerifyArgs),
}

/// Why the command failed.
#[derive(Debug, Error)]
enum CliError {
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

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Nothing more can be reported if stderr itself fails.
            let _ = writeln!(std::io::stderr().lock(), "landfall: {}", Chain(&error));
            ExitCode::from(error.exit_code())
        }
    }
}

fn run(cli: Cli) -> Result<(), CliError> {
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

#[cfg(test)]
mod tests {
    use clap::{CommandFactory, Parser};
    use thiserror::Error;

    use super::{Chain, Cli};

    #[test]
    fn command_line_is_well_formed() {
        Cli::command().debug_assert();
    }

    #[test]
    fn verify_help_documents_exit_status_and_token() {
        let mut command = Cli::command();
        let help = command
            .find_subcommand_mut("verify")
            .unwrap()
            .render_long_help()
            .to_string();
        for line in [
            "0  the release is verified",
            "1  the release is refused",
            "2  the release could not be verified",
            "GITHUB_TOKEN",
        ] {
            assert!(help.contains(line), "{line:?} missing from:\n{help}");
        }
    }

    #[test]
    fn usage_errors_exit_2() {
        let error = Cli::try_parse_from(["landfall", "verify"]).err().unwrap();
        assert_eq!(error.exit_code(), 2);
    }

    #[derive(Debug, Error)]
    #[error("outer")]
    struct Outer(#[source] Inner);

    #[derive(Debug, Error)]
    #[error("inner")]
    struct Inner;

    #[test]
    fn error_chain_names_every_cause() {
        assert_eq!(Chain(&Outer(Inner)).to_string(), "outer: inner");
    }
}
