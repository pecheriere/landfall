//! The command line's shape, and how a failure reads.

use clap::{CommandFactory, Parser};
use thiserror::Error;

use super::{Chain, Cli, run};

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

fn host_install_help() -> String {
    let mut command = Cli::command();
    command
        .find_subcommand_mut("host")
        .unwrap()
        .find_subcommand_mut("install")
        .unwrap()
        .render_long_help()
        .to_string()
}

#[test]
fn help_documents_the_exit_statuses() {
    let help = host_install_help();
    for line in [
        "0  the agent is installed",
        "1  refused or stopped",
        "2  could not try",
        "GITHUB_TOKEN",
    ] {
        assert!(help.contains(line), "{line:?} missing from:\n{help}");
    }
}

/// Every flag the task names, in its own spelling, and no flag for what a test sets.
#[test]
fn host_install_takes_what_it_should() {
    let cli = Cli::try_parse_from([
        "landfall",
        "host",
        "install",
        "user@host.example",
        "--host",
        "home-1",
        "--config",
        "fleet.toml",
        "--controller",
        "https://controller.example",
        "--allow-insecure-controller",
        "--code-file",
        "code",
        "--tag",
        "v1.2.3",
        "--dry-run",
        "--yes",
        "--replace-config",
        "--replace-unit",
        "--ssh-config",
        "ssh_config",
        "--cache-dir",
        "cache",
    ]);
    assert!(cli.is_ok(), "{:?}", cli.err());
    assert!(!host_install_help().contains("--timing"));
    assert!(!host_install_help().contains("stable"));

    for missing in ["--host", "--config", "--controller"] {
        let mut args = vec![
            "landfall",
            "host",
            "install",
            "user@host.example",
            "--host",
            "home-1",
            "--config",
            "fleet.toml",
            "--controller",
            "https://controller.example",
        ];
        let at = args.iter().position(|arg| arg == &missing).unwrap();
        args.drain(at..at + 2);
        let error = Cli::try_parse_from(args).err().unwrap();
        assert_eq!(error.exit_code(), 2, "{missing}");
    }
}

/// All the way through `run`, stopped by a destination before anything could connect.
#[test]
fn a_host_command_reaches_its_error_and_exit_status() {
    let cli = Cli::try_parse_from([
        "landfall",
        "host",
        "install",
        "a;b",
        "--host",
        "home-1",
        "--config",
        "fleet.toml",
        "--controller",
        "https://controller.example",
    ])
    .unwrap();
    assert_eq!(run(cli), 2);
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
