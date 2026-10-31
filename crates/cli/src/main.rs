//! `landfall`: Command-line client for the landfall API.

use clap::Parser;

#[derive(Parser)]
#[command(name = "landfall", version, about)]
struct Cli {}

fn main() {
    Cli::parse();
}
