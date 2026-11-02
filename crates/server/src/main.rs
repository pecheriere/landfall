//! `landfall-server`: Watches releases, verifies their origin and coordinates deploys.

use std::process::ExitCode;

use clap::Parser;
use landfall_server::cli::{self, Cli};

fn main() -> ExitCode {
    ExitCode::from(cli::run(Cli::parse()))
}
