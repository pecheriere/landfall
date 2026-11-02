//! Paths relative to a root, and walking to a directory by descriptor.

use std::ffi::{CStr, CString};
use std::fmt;
use std::iter;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Component, Path, PathBuf};

use rustix::fs::{CWD, Mode, openat};

use super::error::{file_io_err, name_path, walk_err};
use super::{MAX_DEPTH, OPEN_DIR, SafeFsError};

/// A validated path relative to a [`Root`]: at most [`MAX_DEPTH`] components,
/// none of them empty, `.` or `..`, and no leading `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPath {
    text: String,
    pub(super) parents: Vec<CString>,
    pub(super) name: CString,
}

impl RelPath {
    /// Validates a relative path.
    ///
    /// # Errors
    ///
    /// [`SafeFsError::InvalidPath`] when it could leave the root or is not a
    /// plain sequence of names.
    pub fn new(path: &str) -> Result<Self, SafeFsError> {
        let invalid = |reason| SafeFsError::InvalidPath {
            path: path.to_owned(),
            reason,
        };
        if path.starts_with('/') {
            return Err(invalid("it must not start with /"));
        }
        let mut parts = Vec::new();
        for part in path.split('/') {
            match part {
                "" => return Err(invalid("it has an empty component")),
                "." | ".." => return Err(invalid("it has a . or .. component")),
                _ => parts.push(CString::new(part).map_err(|_| invalid("it holds a NUL byte"))?),
            }
        }
        if parts.len() > MAX_DEPTH {
            return Err(invalid("it has too many components"));
        }
        let name = parts.pop().ok_or_else(|| invalid("it is empty"))?;
        Ok(Self {
            text: path.to_owned(),
            parents: parts,
            name,
        })
    }

    /// The path as a [`Path`], for messages and joining onto a trusted base.
    #[must_use]
    pub fn as_path(&self) -> &Path {
        Path::new(&self.text)
    }

    /// How deep the entry is below the root: 1 for a plain name.
    pub(super) fn depth(&self) -> usize {
        self.parents.len() + 1
    }

    pub(super) fn components(&self) -> impl Iterator<Item = &CString> {
        self.parents.iter().chain(iter::once(&self.name))
    }
}

impl fmt::Display for RelPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

/// An open directory that walks start from. The path it was opened from is
/// trusted (it comes from resolved configuration or the agent's own state);
/// everything below it is not.
#[derive(Debug)]
pub struct Root {
    pub(super) fd: OwnedFd,
    pub(super) path: PathBuf,
}

impl Root {
    /// Opens an absolute path that has to be a directory. The last component
    /// must not be a symlink.
    ///
    /// # Errors
    ///
    /// [`SafeFsError::NotAbsolute`], [`SafeFsError::Missing`],
    /// [`SafeFsError::NotADirectory`], or [`SafeFsError::Io`].
    pub fn open(path: &Path) -> Result<Self, SafeFsError> {
        require_absolute(path)?;
        let fd = openat(CWD, path, OPEN_DIR, Mode::empty()).map_err(walk_err(path))?;
        Ok(Self {
            fd,
            path: path.to_owned(),
        })
    }

    /// The path this root was opened from.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Opens the directory holding `name`, one component at a time.
    pub(super) fn open_parent(&self, name: &RelPath) -> Result<OwnedFd, SafeFsError> {
        walk(self.fd.as_fd(), &self.path, &name.parents)
    }
}

/// Opens `parts` below `start`, refusing anything but real directories.
pub(super) fn walk(
    start: BorrowedFd<'_>,
    label: &Path,
    parts: &[CString],
) -> Result<OwnedFd, SafeFsError> {
    let mut path = label.to_owned();
    let mut current = start
        .try_clone_to_owned()
        .map_err(file_io_err("duplicate descriptor of", label))?;
    for part in parts {
        path.push(name_path(part));
        current = open_dir(current.as_fd(), part).map_err(walk_err(&path))?;
    }
    Ok(current)
}

pub(super) fn open_dir(parent: BorrowedFd<'_>, name: &CStr) -> rustix::io::Result<OwnedFd> {
    openat(parent, name, OPEN_DIR, Mode::empty())
}

pub(super) fn require_absolute(path: &Path) -> Result<(), SafeFsError> {
    if path.is_absolute() && !path.components().any(|c| c == Component::ParentDir) {
        Ok(())
    } else {
        Err(SafeFsError::NotAbsolute {
            path: path.to_owned(),
        })
    }
}
