//! The error type, and the helpers that build it from a failed call.

use std::ffi::{CStr, OsStr};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

use rustix::fs::Mode;
use rustix::io::Errno;

use super::MAX_ERROR_PATH;

/// A failure of a filesystem operation.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SafeFsError {
    /// A relative path is not acceptable.
    #[error("invalid relative path {path:?}: {reason}")]
    InvalidPath {
        /// The path as given.
        path: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// A path that has to be absolute is not.
    #[error("{} is not an absolute path", quoted(path))]
    NotAbsolute {
        /// The path.
        path: PathBuf,
    },
    /// The path does not exist.
    #[error("{} does not exist", quoted(path))]
    Missing {
        /// The path.
        path: PathBuf,
    },
    /// A component that has to be a real directory is not, which includes a
    /// symlink to one.
    #[error("{} is not a real directory", quoted(path))]
    NotADirectory {
        /// The path.
        path: PathBuf,
    },
    /// A file to be read is a symlink.
    #[error("{} is a symlink; it is not followed", quoted(path))]
    SymlinkRefused {
        /// The path.
        path: PathBuf,
    },
    /// A file to be read is not a regular file.
    #[error("{} is not a regular file", quoted(path))]
    NotRegularFile {
        /// The path.
        path: PathBuf,
    },
    /// A tree holds a device, socket or FIFO.
    #[error("{} is a {kind}; special files are refused", quoted(path))]
    SpecialFile {
        /// The path.
        path: PathBuf,
        /// What kind of file it is.
        kind: &'static str,
    },
    /// A file is larger than the caller allows.
    #[error("{} is larger than {cap} bytes", quoted(path))]
    TooLarge {
        /// The path.
        path: PathBuf,
        /// The limit.
        cap: usize,
    },
    /// A tree goes deeper than [`MAX_DEPTH`](super::MAX_DEPTH).
    #[error("{} is more than {limit} levels deep", quoted(path))]
    TooDeep {
        /// The path.
        path: PathBuf,
        /// The limit.
        limit: usize,
    },
    /// A directory holds more than [`MAX_DIR_ENTRIES`](super::MAX_DIR_ENTRIES) entries.
    #[error("{} holds more than {limit} entries", quoted(path))]
    TooManyEntries {
        /// The directory.
        path: PathBuf,
        /// The limit.
        limit: usize,
    },
    /// A removal found a directory it could not get any emptier: a pass over
    /// it removed nothing and it still holds entries, or the directory an
    /// entry had to move to is gone.
    #[error("{} cannot be removed: no progress is possible", quoted(path))]
    RemovalStalled {
        /// The directory or entry.
        path: PathBuf,
    },
    /// An entry the agent had just created is no longer what it created.
    #[error("{} was replaced while it was being created", quoted(path))]
    Replaced {
        /// The path.
        path: PathBuf,
    },
    /// Something is already where a new entry has to go.
    #[error("{} already exists", quoted(path))]
    AlreadyExists {
        /// The path.
        path: PathBuf,
    },
    /// One path of a list contains another.
    #[error("paths overlap: {} contains {}", quoted(outer), quoted(inner))]
    OverlappingPaths {
        /// The shorter path.
        outer: PathBuf,
        /// The path below it.
        inner: PathBuf,
    },
    /// A mode to write holds more than permission bits.
    #[error("mode {mode:o} holds more than the permission bits")]
    InvalidMode {
        /// The mode as given.
        mode: u32,
    },
    /// The kernel did not keep the mode that was set, as it does when
    /// set-gid is set without the capability to do so.
    #[error("{}: mode {wanted:?} was not preserved, it is {got:?}", quoted(path))]
    ModeNotPreserved {
        /// The path.
        path: PathBuf,
        /// The mode that was set.
        wanted: Mode,
        /// The mode it has now.
        got: Mode,
    },
    /// A system call failed.
    #[error("{op} {}: {source}", quoted(path))]
    Io {
        /// What was being done.
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// An operation failed, and so did removing what it had left behind.
    #[error("{original}; cleaning up also failed: {cleanup}")]
    CleanupFailed {
        /// The failure that started it.
        #[source]
        original: Box<SafeFsError>,
        /// The failure to clean up.
        cleanup: Box<SafeFsError>,
    },
}

/// A path as it goes into an error: quoted, with control characters escaped,
/// and cut to its tail, since a hostile tree picks the names.
#[expect(
    clippy::unnecessary_debug_formatting,
    reason = "the escaping is the point: `Display` would pass a newline in a hostile name through"
)]
fn quoted(path: &Path) -> String {
    let text = format!("{path:?}");
    match text.char_indices().rev().nth(MAX_ERROR_PATH) {
        Some((start, _)) => format!("...{}", &text[start..]),
        None => text,
    }
}

pub(super) fn io_err(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
    let path = path.to_owned();
    move |errno| SafeFsError::Io {
        op,
        path,
        source: errno.into(),
    }
}

pub(super) fn file_io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> SafeFsError {
    let path = path.to_owned();
    move |source| SafeFsError::Io { op, path, source }
}

/// The error for a directory that could not be opened on a walk.
pub(super) fn walk_err(path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
    let path = path.to_owned();
    move |errno| match errno {
        Errno::NOENT => SafeFsError::Missing { path },
        Errno::NOTDIR | Errno::LOOP => SafeFsError::NotADirectory { path },
        other => SafeFsError::Io {
            op: "open directory",
            path,
            source: other.into(),
        },
    }
}

pub(super) fn with_cleanup(original: SafeFsError, cleanup: Result<(), SafeFsError>) -> SafeFsError {
    match cleanup {
        Ok(()) => original,
        Err(cleanup) => SafeFsError::CleanupFailed {
            original: Box::new(original),
            cleanup: Box::new(cleanup),
        },
    }
}

/// The error for an entry already seen, where its disappearing is `Missing`.
pub(super) fn entry_err(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
    let path = path.to_owned();
    move |errno| match errno {
        Errno::NOENT => SafeFsError::Missing { path },
        other => SafeFsError::Io {
            op,
            path,
            source: other.into(),
        },
    }
}

pub(super) fn name_path(name: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(name.to_bytes()))
}
