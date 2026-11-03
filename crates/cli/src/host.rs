//! `landfall host`: what puts an agent on a host, over the operator's own SSH.
//!
//! [`facts`] reads what a read-only probe of the target printed, [`mod@unit`] renders the systemd
//! units, and [`plan`] the one script that runs as root: all pure. What the target prints is
//! hostile, and what is rendered runs as root, so [`shell`] is the only way a value reaches a
//! script. [`ssh`] is how anything reaches the target, and [`install`] puts them together.

use std::fmt::Write as _;
use std::io::{self, BufRead as _, IsTerminal as _, Write};
use std::path::PathBuf;

use clap::Subcommand;
use landfall_core::config::ConfigError;
use landfall_core::controller_url::UrlError;
use landfall_core::ids::HostId;
use landfall_core::text::quoted;
use landfall_origin::trust::Refresh;
use thiserror::Error;
use tokio::runtime::Runtime;

use crate::agent_release::{AgentReleaseError, GitHubReleases};
use crate::verify::{EXIT_REFUSED, EXIT_UNVERIFIED};

pub mod facts;
pub mod install;
pub mod plan;
pub mod shell;
pub mod ssh;
pub mod unit;

#[cfg(test)]
mod tests;

/// The exit statuses of `landfall host install`, shown in its `--help`.
const INSTALL_EXIT_STATUS: &str = "\
Exit status:
  0  the agent is installed, or --dry-run showed what would run
  1  refused or stopped: the release failed verification, the target isn't fit
     for an agent, sudo can't be used, you declined, or the script stopped
  2  could not try or finish: configuration, usage, network, SSH connection or
     host key, a connection lost during the script, a failed upload such as a
     full disk, or the release could not be fetched

Environment:
  GITHUB_TOKEN  never sent to the target, and removed from what ssh is given";

/// How many bytes name the upload directory.
const UPLOAD_NAME_BYTES: usize = 16;

/// The name of a `/tmp` directory's prefix that the root script's cleanup knows.
const UPLOAD_PREFIX: &str = "/tmp/landfall-install.";

/// A command under `landfall host`.
#[derive(Debug, Subcommand)]
#[non_exhaustive]
pub enum HostCommand {
    /// Put a verified agent on a host over SSH, with its configuration and units, enrol it if
    /// given a code, and start it. It shows what will run as root first.
    #[command(after_help = INSTALL_EXIT_STATUS)]
    Install(install::InstallArgs),
}

/// Why a `landfall host` command failed.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HostError {
    /// The release was refused, couldn't be fetched, or this build can't verify any.
    #[error(transparent)]
    Release(AgentReleaseError),
    /// The configuration file could not be read.
    #[error("cannot read configuration {}", .path.display())]
    ReadConfig {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: io::Error,
    },
    /// The configuration file is invalid.
    #[error("configuration {} is invalid", .path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: Box<ConfigError>,
    },
    /// The agent couldn't start with this configuration.
    #[error("configuration {} has no deployment on host {host}, and an agent can't start without one", .path.display())]
    NoDeployment {
        /// The host.
        host: HostId,
        /// The file.
        path: PathBuf,
    },
    /// A compose directory a unit can't name.
    #[error(transparent)]
    UnsafePath(#[from] unit::UnitError),
    /// The controller's URL isn't one an agent would take.
    #[error(transparent)]
    Controller(#[from] UrlError),
    /// The enrolment code's file could not be read. Nothing of its content is in this.
    #[error("cannot read the enrolment code in {}", .path.display())]
    CodeFile {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: io::Error,
    },
    /// The enrolment code's file is a link, or not a file at all.
    #[error("the enrolment code's file {} must be a regular file itself, not a link", .0.display())]
    CodeNotRegular(PathBuf),
    /// The enrolment code's file doesn't hold a code. Nothing of its content is in this.
    #[error("{} doesn't hold an enrolment code", .0.display())]
    CodeInvalid(PathBuf),
    /// SSH couldn't do what was asked.
    #[error(transparent)]
    Ssh(#[from] ssh::SshError),
    /// What came back isn't what a probe prints. What it said is hostile, so it's quoted.
    #[error(
        "the target didn't answer the probe as it should: status {status}, and it said {}",
        quoted(.said, 400)
    )]
    Probe {
        /// What's wrong with its output.
        #[source]
        source: facts::FactsError,
        /// The remote command's status.
        status: i32,
        /// Its stderr.
        said: String,
    },
    /// The target can't take an agent.
    #[error("{}", refusals(.0))]
    Refused(Vec<facts::Refusal>),
    /// No terminal to ask on, and not told to go ahead.
    #[error("there is no terminal to ask on: read what --dry-run shows, and pass --yes")]
    NoTerminal,
    /// `sudo` would ask, with nobody to answer.
    #[error(
        "sudo on the target wants a password and there is no terminal to ask on, so nothing was sent: run this from a terminal, or give this login passwordless sudo"
    )]
    NoSudo,
    /// The operator said no.
    #[error("declined: nothing was sent")]
    Declined,
    /// The upload to the target failed. What it said is hostile, so it's quoted.
    #[error("cannot send {what} to the target: status {status}, and it said {}", quoted(.said, 400))]
    Upload {
        /// What was being sent.
        what: &'static str,
        /// The remote command's status.
        status: i32,
        /// Its stderr.
        said: String,
    },
    /// The script ended with something other than success.
    #[error("the script on the target stopped with status {0}: what it said is above")]
    ScriptFailed(i32),
    /// The system had no randomness to give.
    #[error("cannot draw a name for the upload")]
    Random(getrandom::Error),
    /// What's shown could not be written.
    #[error("cannot write to stdout")]
    Output(#[source] io::Error),
}

impl HostError {
    /// The process's exit status: 1 for a refusal or a script that stopped, and 2 for what stopped
    /// it being tried.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Release(error) if error.is_refusal() => EXIT_REFUSED,
            Self::Probe { .. }
            | Self::Refused(_)
            | Self::NoTerminal
            | Self::NoSudo
            | Self::Declined
            | Self::ScriptFailed(_) => EXIT_REFUSED,
            _ => EXIT_UNVERIFIED,
        }
    }
}

fn refusals(refusals: &[facts::Refusal]) -> String {
    refusals.iter().fold(
        "the target can't take an agent:".to_owned(),
        |mut text, refusal| {
            // Writing to a `String` can't fail.
            let _ = write!(text, "\n  {refusal}");
            text
        },
    )
}

/// A name for the upload directory that nobody can guess, drawn before the script is shown so
/// that what is shown is what runs: `/tmp/landfall-install.<32 hex digits>`.
///
/// # Errors
///
/// [`HostError::Random`] if the system has no randomness to give.
pub fn upload_dir() -> Result<String, HostError> {
    let mut bytes = [0; UPLOAD_NAME_BYTES];
    getrandom::fill(&mut bytes).map_err(HostError::Random)?;
    Ok(bytes
        .iter()
        .fold(UPLOAD_PREFIX.to_owned(), |mut name, byte| {
            // Writing to a `String` can't fail.
            let _ = write!(name, "{byte:02x}");
            name
        }))
}

/// Whether an answer to `[y/N]` is yes: anything else leaves it at no.
fn is_yes(answer: &str) -> bool {
    matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
}

/// A person at this process's terminal.
struct TerminalConfirm;

impl install::Confirm for TerminalConfirm {
    fn is_terminal(&self) -> bool {
        io::stdin().is_terminal() && io::stdout().is_terminal()
    }

    fn ask(&mut self, script_sha256: &str) -> io::Result<bool> {
        let mut stderr = io::stderr().lock();
        write!(
            stderr,
            "landfall: run the script with SHA-256 {script_sha256} as root? [y/N] "
        )?;
        stderr.flush()?;
        let mut answer = String::new();
        io::stdin().lock().read_line(&mut answer)?;
        Ok(is_yes(&answer))
    }
}

fn source_for(args: &install::InstallArgs) -> GitHubReleases {
    GitHubReleases::new(args.cache_dir.clone(), Refresh::Online)
}

fn remote_for(args: &install::InstallArgs) -> Result<ssh::OpenSsh, HostError> {
    let dest = ssh::Destination::parse(&args.dest)?;
    Ok(ssh::OpenSsh::new(dest, args.ssh_config.clone())?)
}

/// The process's result: a person saying no isn't success for whatever runs this.
fn finished(outcome: install::Outcome) -> Result<(), HostError> {
    match outcome {
        install::Outcome::Declined => Err(HostError::Declined),
        install::Outcome::Installed | install::Outcome::DryRun => Ok(()),
    }
}

/// Runs a `landfall host` command for real, against the project's releases and the system's `ssh`.
///
/// # Errors
///
/// A [`HostError`], [`HostError::Declined`] when the operator said no.
pub fn run(command: HostCommand, runtime: &Runtime, out: &mut dyn Write) -> Result<(), HostError> {
    match command {
        HostCommand::Install(args) => {
            let source = source_for(&args);
            let remote = remote_for(&args)?;
            finished(install::run_with(
                &args,
                &source,
                &remote,
                runtime,
                out,
                &mut TerminalConfirm,
            )?)
        }
    }
}
