//! `landfall-agent`: Runs on each host: verifies and deploys releases, checks health, rolls back.

use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
