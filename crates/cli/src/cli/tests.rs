//! The command line's shape, and how a failure reads.

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
