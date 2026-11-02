//! Why a Docker call failed.

use std::io;
use std::time::Duration;

/// A failure running Docker.
#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    /// The binary could not be started.
    #[error("{command}: cannot start: {source}")]
    Spawn {
        /// The command.
        command: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// Reading the command's output failed.
    #[error("{command}: reading output: {source}")]
    Io {
        /// The command.
        command: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The command ran past its timeout and was killed.
    #[error("{command}: timed out after {after:?}")]
    Timeout {
        /// The command.
        command: &'static str,
        /// The timeout that applied.
        after: Duration,
    },
    /// The command wrote more than the cap and was killed.
    #[error("{command}: output exceeds {cap} bytes")]
    TooMuchOutput {
        /// The command.
        command: &'static str,
        /// The cap.
        cap: usize,
    },
    /// The command failed; the last part of its stderr is quoted.
    #[error("{command}: {status}; stderr ends with {stderr:?}")]
    Failed {
        /// The command.
        command: &'static str,
        /// The exit status.
        status: String,
        /// The truncated, lossily decoded tail of stderr.
        stderr: String,
    },
    /// The command failed and, because its output can echo secrets or
    /// container logs, only its exit status is reported, with the command to
    /// run by hand to see why.
    #[error("{command}: {status} (output withheld; to see why, run by hand: {argv})")]
    FailedQuietly {
        /// The command.
        command: &'static str,
        /// The exit status.
        status: String,
        /// The command line, which holds nothing from the configuration but
        /// names validated before they got here.
        argv: String,
    },
    /// The command was killed after an error or timeout, but did not exit
    /// within a few seconds (a process stuck in the kernel). It may still be
    /// running.
    #[error("{command}: did not exit after being killed")]
    Unkillable {
        /// The command.
        command: &'static str,
    },
    /// The command succeeded but its output was not what was asked for.
    /// The output is not quoted: it may hold secrets.
    #[error("{command}: unexpected output ({reason})")]
    BadOutput {
        /// The command.
        command: &'static str,
        /// What was wrong, in words that quote nothing.
        reason: &'static str,
    },
    /// The compose project has no such service.
    #[error("compose project has no service {service:?}")]
    NoSuchService {
        /// The service.
        service: String,
    },
    /// The service has more than one running container: it is scaled, or a
    /// second project runs it from the same directory.
    #[error("{command}: more than one running container")]
    SeveralContainers {
        /// The command.
        command: &'static str,
    },
    /// An argument was refused before anything ran.
    #[error("{command}: refused argument: {reason}")]
    BadArgument {
        /// The command.
        command: &'static str,
        /// Why.
        reason: &'static str,
    },
}
