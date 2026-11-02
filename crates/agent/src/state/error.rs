//! Why a state operation failed.

use std::io;
use std::path::{Path, PathBuf};

use landfall_core::ids::DeploymentId;

/// A failure reading or writing the agent's state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A filesystem operation failed.
    #[error("state: {op} {path}: {source}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The state path is not a directory (a symlink is not followed).
    #[error("state: {0} is not a directory")]
    NotADirectory(PathBuf),
    /// The directory belongs to another user.
    #[error("state: {path} is owned by uid {owner}, not by the agent's uid {agent}")]
    WrongOwner {
        /// The directory.
        path: PathBuf,
        /// Its owner.
        owner: u32,
        /// The agent's user.
        agent: u32,
    },
    /// The directory is writable by its group or by everyone.
    #[error("state: {path} has mode {mode:o}; it must not be group- or world-writable")]
    Writable {
        /// The directory.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Another process holds the deployment's lock.
    #[error("deployment {0} is busy: another agent process holds its lock")]
    Busy(DeploymentId),
    /// Another `run` or `enrol` is working in this state directory.
    #[error("state: another landfall-agent run or enrol holds {0}")]
    DaemonBusy(PathBuf),
    /// Something holds the lock on the nonce log, so it can't be asked now. Nothing is wrong
    /// with the log as far as this knows, and nothing was read or written.
    #[error("state: something holds the lock on the nonce log {0}")]
    NonceLogBusy(PathBuf),
    /// A state file exists but cannot be read as what it should hold. It is
    /// never treated as empty: that could deploy over an unknown state.
    #[error("state: {path} is corrupt: {source}")]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// Why it did not parse.
        source: serde_json::Error,
    },
    /// A state value could not be serialised.
    #[error("state: cannot serialise {path}: {source}")]
    Serialise {
        /// The file that was to be written.
        path: PathBuf,
        /// Why it did not serialise.
        source: serde_json::Error,
    },
    /// A report id is not a plain file name.
    #[error("state: report id {0:?} must be 1 to 128 of [A-Za-z0-9_-]")]
    InvalidReportId(String),
    /// The log of used approval nonces can't be trusted, so no approval can be either.
    #[error("state: the nonce log {path} can't be used: {reason}")]
    NonceLog {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
}

pub(super) fn io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> StateError {
    let path = path.to_owned();
    move |source| StateError::Io { op, path, source }
}
