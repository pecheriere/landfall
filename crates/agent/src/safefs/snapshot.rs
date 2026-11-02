//! Taking a snapshot of paths and restoring it.

use std::ffi::CString;
use std::os::fd::AsFd;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use rustix::fs::{AtFlags, CWD, Mode, fsync, mkdirat, openat, renameat, statat};
use rustix::io::Errno;
use serde::{Deserialize, Serialize};

use super::copy::copy_paths;
use super::error::{io_err, name_path, walk_err, with_cleanup};
use super::paths::{open_dir, require_absolute};
use super::removal::{Removal, remove_entry};
use super::{MAX_DIR_ENTRIES, OPEN_DIR, PARTIAL_SUFFIX, RelPath, Root, SafeFsError};

/// What a snapshot copied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SnapshotStats {
    /// Regular files copied.
    pub files: u64,
    /// Directories copied, including the parents of the requested paths.
    pub directories: u64,
    /// Symlinks copied.
    pub symlinks: u64,
    /// Bytes of file content copied.
    pub bytes: u64,
}

/// Copies `paths` from `source` into a new directory `dest`, by way of
/// `<dest>.partial`, which is renamed only when everything is copied and
/// synced, and removed on failure. A partial copy never looks complete.
/// Mode, owner and times are preserved; `dest` itself is private to the agent.
///
/// `dest` lives in the agent's own state directory, which is trusted, and its
/// parent has to exist.
///
/// # Errors
///
/// [`SafeFsError::Missing`] for a missing path,
/// [`SafeFsError::SpecialFile`] for a device, socket or FIFO,
/// [`SafeFsError::NotADirectory`] when a parent of a path is not a real
/// directory, [`SafeFsError::TooDeep`] past [`MAX_DEPTH`](super::MAX_DEPTH),
/// [`SafeFsError::TooManyEntries`] past [`MAX_DIR_ENTRIES`] in a directory,
/// [`SafeFsError::SymlinkRefused`] when an entry becomes a symlink as it is
/// opened, [`SafeFsError::Replaced`] when a new symlink is swapped for
/// something else, [`SafeFsError::OverlappingPaths`] when one path contains
/// another, [`SafeFsError::AlreadyExists`] when `dest` exists,
/// [`SafeFsError::RemovalStalled`] when a leftover `.partial` cannot be
/// removed, and [`SafeFsError::Io`].
pub fn snapshot(
    source: &Root,
    paths: &[RelPath],
    dest: &Path,
) -> Result<SnapshotStats, SafeFsError> {
    snapshot_limited(source, paths, dest, MAX_DIR_ENTRIES)
}

/// [`snapshot`] with the limit on directory size as an argument, so that a
/// test need not create a million files.
pub(super) fn snapshot_limited(
    source: &Root,
    paths: &[RelPath],
    dest: &Path,
    max_entries: usize,
) -> Result<SnapshotStats, SafeFsError> {
    check_overlap(paths)?;
    require_absolute(dest)?;
    let (Some(parent_path), Some(file_name)) = (dest.parent(), dest.file_name()) else {
        return Err(SafeFsError::NotAbsolute {
            path: dest.to_owned(),
        });
    };
    let parent =
        openat(CWD, parent_path, OPEN_DIR, Mode::empty()).map_err(walk_err(parent_path))?;
    let dest_name = CString::new(file_name.as_bytes()).map_err(|_| SafeFsError::InvalidPath {
        path: dest.display().to_string(),
        reason: "it holds a NUL byte",
    })?;
    let partial_name = {
        let bytes = [dest_name.as_bytes(), PARTIAL_SUFFIX].concat();
        CString::new(bytes).map_err(|_| SafeFsError::InvalidPath {
            path: dest.display().to_string(),
            reason: "it holds a NUL byte",
        })?
    };
    let partial_path = parent_path.join(name_path(&partial_name));

    match statat(&parent, &dest_name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => {
            return Err(SafeFsError::AlreadyExists {
                path: dest.to_owned(),
            });
        }
        Err(Errno::NOENT) => {}
        Err(errno) => return Err(io_err("inspect", dest)(errno)),
    }
    remove_entry(parent.as_fd(), &partial_name, &partial_path)?;
    mkdirat(&parent, &partial_name, Mode::RWXU).map_err(io_err("create", &partial_path))?;

    let copied = open_dir(parent.as_fd(), &partial_name)
        .map_err(walk_err(&partial_path))
        .and_then(|partial| {
            let stats = copy_paths(
                source,
                partial.as_fd(),
                &partial_path,
                paths,
                Removal::None,
                max_entries,
            )?;
            renameat(&parent, &partial_name, &parent, &dest_name)
                .map_err(io_err("rename to", dest))?;
            Ok(stats)
        });
    let stats = copied.map_err(|err| {
        let cleanup = remove_entry(parent.as_fd(), &partial_name, &partial_path);
        with_cleanup(err, cleanup)
    })?;
    fsync(&parent).map_err(io_err("sync", parent_path))?;
    Ok(stats)
}

/// Puts `paths` back in `target` from a snapshot: what is there now is
/// removed, descending by descriptor and never following, and the snapshot's
/// copy is created in its place. A parent of a path that is missing, or that
/// a container swapped for something else, is recreated from the snapshot;
/// a parent that is a real directory keeps its owner and mode.
///
/// Nothing is removed unless the snapshot holds every path. What is removed
/// can be of any depth and size, so a tree a container planted cannot stop a
/// rollback; see the module documentation.
///
/// # Errors
///
/// [`SafeFsError::Missing`] when the snapshot lacks a path,
/// [`SafeFsError::OverlappingPaths`] when one path contains another,
/// [`SafeFsError::Replaced`] when a new symlink is swapped for something else,
/// [`SafeFsError::RemovalStalled`] when what is there cannot be removed,
/// [`SafeFsError::TooDeep`] and [`SafeFsError::TooManyEntries`] for a snapshot
/// past the limits, which [`snapshot`] does not make, and [`SafeFsError::Io`].
/// A failure part-way leaves the paths already restored in place and the rest
/// removed or as they were.
pub fn restore(snapshot: &Path, target: &Root, paths: &[RelPath]) -> Result<(), SafeFsError> {
    check_overlap(paths)?;
    let snapshot = Root::open(snapshot)?;
    for path in paths {
        let parent = snapshot.open_parent(path)?;
        let label = snapshot.path.join(path.as_path());
        statat(&parent, &path.name, AtFlags::SYMLINK_NOFOLLOW).map_err(|errno| match errno {
            Errno::NOENT => SafeFsError::Missing {
                path: label.clone(),
            },
            other => io_err("inspect", &label)(other),
        })?;
    }
    copy_paths(
        &snapshot,
        target.fd.as_fd(),
        &target.path,
        paths,
        Removal::First,
        MAX_DIR_ENTRIES,
    )?;
    Ok(())
}

/// Refuses a list where one path contains another: copying the inner one
/// again would collide, and restoring it could put back a stale copy.
fn check_overlap(paths: &[RelPath]) -> Result<(), SafeFsError> {
    for (index, first) in paths.iter().enumerate() {
        for second in &paths[index + 1..] {
            if first
                .components()
                .zip(second.components())
                .all(|(a, b)| a == b)
            {
                let (outer, inner) = if first.depth() <= second.depth() {
                    (first, second)
                } else {
                    (second, first)
                };
                return Err(SafeFsError::OverlappingPaths {
                    outer: outer.as_path().to_owned(),
                    inner: inner.as_path().to_owned(),
                });
            }
        }
    }
    Ok(())
}
