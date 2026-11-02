//! Removing a tree without following what a container planted in it.

use std::ffi::{CStr, CString};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{AtFlags, Dir, FileType, Mode, fsync, mkdirat, renameat, statat, unlinkat};
use rustix::io::Errno;

use super::error::{io_err, name_path};
use super::files::remove_file;
use super::paths::open_dir;
#[cfg(test)]
use super::seam;
use super::{
    DEEP_PREFIX, MAX_DEPTH, MAX_DIR_ENTRIES, PARTIAL_SUFFIX, RACE_ATTEMPTS, REMOVAL_BATCH, Root,
    SafeFsError,
};

/// Removes the oldest backups beyond `keep`, by directory name (a sortable
/// id derived from RFC 3339), and every `.partial` leftover. Entries that are
/// not directories are not backups and stay. An absent `backups` directory is
/// nothing to do.
///
/// A `.partial` is taken for a leftover, not a snapshot in progress. So call it
/// under the deployment's lock, and not at all while a snapshot that outran its
/// deadline may still be running under that same lock: the thread cannot be
/// cancelled.
///
/// # Errors
///
/// [`SafeFsError::TooManyEntries`] when `backups` holds more than
/// [`MAX_DIR_ENTRIES`] entries, [`SafeFsError::RemovalStalled`] when an entry
/// cannot be removed, and [`SafeFsError::Io`], from reading `backups` or
/// removing an entry.
pub fn prune(backups: &Path, keep: usize, spare: Option<&str>) -> Result<(), SafeFsError> {
    let root = match Root::open(backups) {
        Ok(root) => root,
        Err(SafeFsError::Missing { .. }) => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut complete = Vec::new();
    for name in read_all_names(root.fd.as_fd(), backups, MAX_DIR_ENTRIES)? {
        let path = backups.join(name_path(&name));
        if name.as_bytes().ends_with(PARTIAL_SUFFIX) {
            remove_entry(root.fd.as_fd(), &name, &path)?;
            continue;
        }
        let seen =
            statat(&root.fd, &name, AtFlags::SYMLINK_NOFOLLOW).map_err(io_err("inspect", &path))?;
        if FileType::from_raw_mode(seen.st_mode) == FileType::Directory {
            complete.push(name);
        }
    }
    complete.sort_unstable_by(|a, b| b.cmp(a));
    for name in complete.iter().skip(keep) {
        if spare.is_some_and(|spare| spare.as_bytes() == name.as_bytes()) {
            continue;
        }
        let path = backups.join(name_path(name));
        remove_entry(root.fd.as_fd(), name, &path)?;
    }
    fsync(&root.fd).map_err(io_err("sync", backups))
}

/// Reads up to `stop_after` of a directory's entry names, closing its stream
/// before returning so that a walk only ever holds its chain of parents. Each
/// call reads from the start, on a stream of its own.
fn read_names(
    dir: BorrowedFd<'_>,
    path: &Path,
    stop_after: usize,
) -> Result<Vec<CString>, SafeFsError> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir).map_err(io_err("list", path))? {
        let entry = entry.map_err(io_err("list", path))?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            names.push(name.to_owned());
            if names.len() >= stop_after {
                break;
            }
        }
    }
    Ok(names)
}

/// Reads all of a directory's entry names, refusing more than `limit`.
pub(super) fn read_all_names(
    dir: BorrowedFd<'_>,
    path: &Path,
    limit: usize,
) -> Result<Vec<CString>, SafeFsError> {
    let names = read_names(dir, path, limit.saturating_add(1))?;
    if names.len() > limit {
        return Err(SafeFsError::TooManyEntries {
            path: path.to_owned(),
            limit,
        });
    }
    Ok(names)
}

/// Removes whatever `name` is, without following it, at any depth and size.
/// An absent entry is fine.
///
/// A directory swapped for a symlink mid-walk fails the open, and the symlink
/// is what gets removed. One swapped the other way fails the `unlinkat`.
pub(super) fn remove_entry(
    parent: BorrowedFd<'_>,
    name: &CStr,
    path: &Path,
) -> Result<(), SafeFsError> {
    if let Found::Dir(dir) = open_or_unlink(parent, name, path)? {
        let mut deep_moved = 0;
        empty_dir(dir.as_fd(), dir.as_fd(), path, 1, &mut deep_moved)?;
        drop(dir);
        remove_dir(parent, name, path)?;
    }
    Ok(())
}

/// What a removal found at a name.
enum Found {
    /// A real directory, still to be emptied and removed.
    Dir(OwnedFd),
    /// Anything else, which is now removed.
    Removed,
    /// Nothing: something else removed it first.
    Absent,
}

/// Opens `name` if it is a real directory, and removes it if it is not.
fn open_or_unlink(parent: BorrowedFd<'_>, name: &CStr, path: &Path) -> Result<Found, SafeFsError> {
    match open_dir(parent, name) {
        Ok(dir) => Ok(Found::Dir(dir)),
        Err(Errno::NOENT) => Ok(Found::Absent),
        Err(Errno::NOTDIR | Errno::LOOP) => match unlinkat(parent, name, AtFlags::empty()) {
            Ok(()) => Ok(Found::Removed),
            Err(Errno::NOENT) => Ok(Found::Absent),
            Err(errno) => Err(io_err("remove", path)(errno)),
        },
        Err(errno) => Err(io_err("open directory", path)(errno)),
    }
}

/// Says whether this call is what removed it.
fn remove_dir(parent: BorrowedFd<'_>, name: &CStr, path: &Path) -> Result<bool, SafeFsError> {
    match unlinkat(parent, name, AtFlags::REMOVEDIR) {
        Ok(()) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(errno) => Err(io_err("remove directory", path)(errno)),
    }
}

/// Removes everything in `dir`, a batch of names at a time. `top` is the
/// directory the removal started in and `depth` how far below it `dir` is.
///
/// A directory at [`MAX_DEPTH`] is moved into `top` instead of descended into.
/// That leaves its parents empty, and `top`, which reads its names again until
/// there are none, finds it there, now near the top of the walk. So nothing
/// has to be remembered, whatever the number of such directories, and a crash
/// leaves them inside what was being removed.
///
/// So that this always ends, a pass that removed nothing has to be followed by
/// an empty directory. One such pass is not an error in itself: all the names
/// it read can have been removed by something else first.
pub(super) fn empty_dir(
    top: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    path: &Path,
    depth: usize,
    deep_moved: &mut u64,
) -> Result<(), SafeFsError> {
    let mut removed_any = true;
    loop {
        let batch = read_names(dir, path, REMOVAL_BATCH)?;
        if batch.is_empty() {
            return Ok(());
        }
        if !removed_any {
            return Err(SafeFsError::RemovalStalled {
                path: path.to_owned(),
            });
        }
        removed_any = false;
        for child in &batch {
            let child_path = path.join(name_path(child));
            #[cfg(test)]
            seam::run(seam::Point::RemovalOpen, child);
            removed_any |= match open_or_unlink(dir, child, &child_path)? {
                Found::Removed => true,
                Found::Absent => false,
                Found::Dir(child_dir) if depth >= MAX_DEPTH => {
                    drop(child_dir);
                    move_to_top(top, dir, child, &child_path, deep_moved)?
                }
                Found::Dir(child_dir) => {
                    empty_dir(top, child_dir.as_fd(), &child_path, depth + 1, deep_moved)?;
                    drop(child_dir);
                    remove_dir(dir, child, &child_path)?
                }
            };
        }
    }
}

/// Moves `name` into `top` under a name not in use, and says whether this call
/// is what moved it. A taken name can have been planted, so the next one is
/// tried; an empty directory or a stray file being replaced by this is fine,
/// as all of `top` is being removed.
///
/// `ENOENT` has two meanings here: `name` is gone, which is what was wanted,
/// or `top` is gone, and then `name` can never move.
pub(super) fn move_to_top(
    top: BorrowedFd<'_>,
    dir: BorrowedFd<'_>,
    name: &CStr,
    path: &Path,
    deep_moved: &mut u64,
) -> Result<bool, SafeFsError> {
    #[cfg(test)]
    seam::run(seam::Point::MoveUp, name);
    loop {
        let fresh = format!("{DEEP_PREFIX}{deep_moved}");
        *deep_moved = deep_moved.saturating_add(1);
        match renameat(dir, name, top, fresh.as_str()) {
            Ok(()) => return Ok(true),
            Err(Errno::NOENT) => {
                return match statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
                    Ok(_) => Err(SafeFsError::RemovalStalled {
                        path: path.to_owned(),
                    }),
                    Err(Errno::NOENT) => Ok(false),
                    Err(errno) => Err(io_err("inspect", path)(errno)),
                };
            }
            Err(Errno::NOTEMPTY | Errno::EXIST | Errno::NOTDIR | Errno::ISDIR) => {}
            Err(errno) => return Err(io_err("move up", path)(errno)),
        }
    }
}

/// Opens `name` below `parent` as a real directory, creating it, and replacing
/// a symlink or other non-directory there, as needed. Says whether it was
/// created here, so the caller knows its metadata is still to be set.
pub(super) fn ensure_real_dir(
    parent: BorrowedFd<'_>,
    name: &CStr,
    path: &Path,
) -> Result<(OwnedFd, bool), SafeFsError> {
    let mut created = false;
    for _ in 0..RACE_ATTEMPTS {
        match open_dir(parent, name) {
            Ok(dir) => return Ok((dir, created)),
            Err(Errno::NOTDIR | Errno::LOOP) => remove_file(parent, name, path)?,
            Err(Errno::NOENT) => {}
            Err(errno) => return Err(io_err("open directory", path)(errno)),
        }
        match mkdirat(parent, name, Mode::RWXU) {
            Ok(()) => created = true,
            Err(Errno::EXIST) => {}
            Err(errno) => return Err(io_err("create", path)(errno)),
        }
    }
    Err(SafeFsError::NotADirectory {
        path: path.to_owned(),
    })
}

/// Whether what a destination already holds is removed before copying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Removal {
    None,
    First,
}
