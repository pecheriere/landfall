//! `landfall-agent`: Runs on each host: verifies and deploys releases, checks health, rolls back.

use std::process::ExitCode;

use clap::Parser;
use landfall_agent::cli::{self, Cli};

fn main() -> ExitCode {
    ExitCode::from(cli::run(Cli::parse()))
}
