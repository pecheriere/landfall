//! `landfall`: Command-line client for the landfall API.

use std::error::Error;
use std::fmt;
use std::io::Write;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod verify;

#[derive(Parser)]
#[command(name = "landfall", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Verify a release of a deployment as a host would before deploying it:
    /// tag signature, image index, build-provenance attestation and
    /// platform. Prints where it came from as JSON.
    Verify(verify::VerifyArgs),
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // Nothing more can be reported if stderr itself fails.
            let _ = writeln!(
                std::io::stderr().lock(),
                "landfall: {}",
                Chain(error.as_ref())
            );
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<(), Box<dyn Error>> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    match cli.command {
        Command::Verify(args) => {
            let origin = runtime.block_on(verify::run(args))?;
            let mut stdout = std::io::stdout().lock();
            serde_json::to_writer_pretty(&mut stdout, &origin)?;
            writeln!(stdout)?;
            stdout.flush()?;
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
    use clap::CommandFactory;
    use thiserror::Error;

    use super::{Chain, Cli};

    #[test]
    fn command_line_is_well_formed() {
        Cli::command().debug_assert();
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
