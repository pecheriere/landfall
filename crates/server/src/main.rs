//! `landfall-server`: Watches releases, verifies their origin and coordinates deploys.

use clap::Parser;

#[derive(Parser)]
#[command(version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
