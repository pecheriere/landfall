//! `landfall`: Command-line client for the landfall API.

use std::process::ExitCode;

use clap::Parser;
use landfall_cli::cli::{self, Cli};

fn main() -> ExitCode {
    ExitCode::from(cli::run(Cli::parse()))
}
