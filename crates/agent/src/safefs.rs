//! Every filesystem operation in a directory a container can write to.
//!
//! The agent is root-equivalent, and a hostile container can plant symlinks,
//! FIFOs or devices, or swap a path for one of them at any moment. So nothing
//! here checks a path and then opens it. Each component is opened relative to
//! its parent's file descriptor with `O_NOFOLLOW`, and what to do is decided
//! from the descriptor (`fstat`), so a swap makes an open fail rather than
//! lead outside the tree. An earlier `lstat` only keeps a walk from opening a
//! device or socket, since opening one can have side effects: without a race a
//! device is never opened. In the window between the `lstat` and the open one
//! may be opened, `O_RDONLY|O_NONBLOCK|O_NOCTTY`, and is then refused by
//! `fstat` before any read.
//!
//! Symlinks are copied as symlinks and never followed. Devices, sockets and
//! FIFOs are refused, naming the path.
//!
//! A copy is not a perfect image. Extended attributes, ACLs and file
//! capabilities are not preserved. A sparse file is written out in full and a
//! hard link becomes a separate file, so a backup can use more disk than its
//! source; running out of space is an error that ends in cleanup.
//!
//! New entries stay private to the agent (`0600`, `0700`) while they fill up.
//! Their metadata is applied afterwards on the descriptor, in this order:
//! owner, then mode, then times. `chown` clears set-uid and set-gid, so those
//! bits are only ever set after it has succeeded, and a failed `chown` is an
//! error that leaves them unset. The kernel can also drop set-gid without an
//! error, so the mode is read back and a difference is an error too.
//!
//! A symlink has no descriptor to read through, but on Linux an `O_PATH` one
//! can carry its owner and times. That needs Linux 5.8 for `utimensat` with
//! `AT_EMPTY_PATH`; on an older kernel copying a symlink fails, so a backup
//! fails before a deploy rather than a rollback failing after one. Linux is
//! the agent's production target. Elsewhere those two calls go by name, where
//! a writer swapping the name at that instant could give the swapped-in entry
//! the owner and times.
//!
//! The limits a hostile tree could otherwise exploit differ by direction,
//! since refusing is safe for a backup and not for a rollback:
//!
//! - A copy stops with a typed error past [`MAX_DEPTH`] levels or past
//!   [`MAX_DIR_ENTRIES`] entries in one directory. Its memory is bounded by
//!   those two numbers.
//! - A removal is not stopped by depth or size. It reads names in batches of
//!   at most 4096, and at [`MAX_DEPTH`] levels it moves the directory there up
//!   to the top of the removal, to be taken apart from there, so a chain gets
//!   shorter on each pass. Its stack, descriptors and memory stay bounded by
//!   those two numbers. It always ends, unless something adds to the tree
//!   faster than it removes, which is why a service is stopped first: a pass
//!   over a directory either removes something, or finds it empty next time,
//!   or ends in [`SafeFsError::RemovalStalled`].
//!
//! Either way only a chain of parent directories stays open, and data moves
//! through one fixed buffer, never allocated from a size the container
//! controls.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, OsStr};
use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::iter;
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf};

use rustix::fs::{
    AtFlags, CWD, Dir, FileType, Gid, Mode, OFlags, RawMode, Stat, Timespec, Timestamps, Uid,
    chownat, fchmod, fchown, fstat, fsync, futimens, mkdirat, openat, readlinkat, renameat, statat,
    symlinkat, unlinkat, utimensat,
};
use rustix::io::Errno;
use serde::Serialize;

/// How deep a walk goes below where it started, so that a deep tree can neither
/// overflow the stack nor use up file descriptors. Past this a copy stops with
/// [`SafeFsError::TooDeep`], and a removal moves the directory up and goes on.
pub const MAX_DEPTH: usize = 256;

/// How many entries one directory may hold in a copy. Past this a walk stops
/// with [`SafeFsError::TooManyEntries`], since its names are held in memory.
pub const MAX_DIR_ENTRIES: usize = 1_000_000;

/// How many names a removal reads from a directory before removing them.
const REMOVAL_BATCH: usize = 4096;
/// What a directory too deep to descend into is renamed to, plus a number.
const DEEP_PREFIX: &str = ".landfall-deep-";

const COPY_BUFFER: usize = 64 * 1024;
const PARTIAL_SUFFIX: &[u8] = b".partial";
const TEMP_SUFFIX: &[u8] = b".landfall-tmp";
const MAX_ERROR_PATH: usize = 512;
/// How often a walk retries when a racing container keeps changing an entry.
const RACE_ATTEMPTS: usize = 3;

const OPEN_DIR: OFlags = OFlags::RDONLY
    .union(OFlags::DIRECTORY)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::CLOEXEC);
const OPEN_ANY: OFlags = OFlags::RDONLY
    .union(OFlags::NOFOLLOW)
    .union(OFlags::NONBLOCK)
    .union(OFlags::NOCTTY)
    .union(OFlags::CLOEXEC);
const CREATE_FILE: OFlags = OFlags::WRONLY
    .union(OFlags::CREATE)
    .union(OFlags::EXCL)
    .union(OFlags::NOFOLLOW)
    .union(OFlags::CLOEXEC);

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
    /// A tree goes deeper than [`MAX_DEPTH`].
    #[error("{} is more than {limit} levels deep", quoted(path))]
    TooDeep {
        /// The path.
        path: PathBuf,
        /// The limit.
        limit: usize,
    },
    /// A directory holds more than [`MAX_DIR_ENTRIES`] entries.
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

fn io_err(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
    let path = path.to_owned();
    move |errno| SafeFsError::Io {
        op,
        path,
        source: errno.into(),
    }
}

fn file_io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> SafeFsError {
    let path = path.to_owned();
    move |source| SafeFsError::Io { op, path, source }
}

/// The error for a directory that could not be opened on a walk.
fn walk_err(path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
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

fn with_cleanup(original: SafeFsError, cleanup: Result<(), SafeFsError>) -> SafeFsError {
    match cleanup {
        Ok(()) => original,
        Err(cleanup) => SafeFsError::CleanupFailed {
            original: Box::new(original),
            cleanup: Box::new(cleanup),
        },
    }
}

/// The error for an entry already seen, where its disappearing is `Missing`.
fn entry_err(op: &'static str, path: &Path) -> impl FnOnce(Errno) -> SafeFsError {
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

fn name_path(name: &CStr) -> &Path {
    Path::new(OsStr::from_bytes(name.to_bytes()))
}

/// A validated path relative to a [`Root`]: at most [`MAX_DEPTH`] components,
/// none of them empty, `.` or `..`, and no leading `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelPath {
    text: String,
    parents: Vec<CString>,
    name: CString,
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
    fn depth(&self) -> usize {
        self.parents.len() + 1
    }

    fn components(&self) -> impl Iterator<Item = &CString> {
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
    fd: OwnedFd,
    path: PathBuf,
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
    fn open_parent(&self, name: &RelPath) -> Result<OwnedFd, SafeFsError> {
        walk(self.fd.as_fd(), &self.path, &name.parents)
    }
}

/// Opens `parts` below `start`, refusing anything but real directories.
fn walk(start: BorrowedFd<'_>, label: &Path, parts: &[CString]) -> Result<OwnedFd, SafeFsError> {
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

fn open_dir(parent: BorrowedFd<'_>, name: &CStr) -> rustix::io::Result<OwnedFd> {
    openat(parent, name, OPEN_DIR, Mode::empty())
}

fn require_absolute(path: &Path) -> Result<(), SafeFsError> {
    if path.is_absolute() && !path.components().any(|c| c == Component::ParentDir) {
        Ok(())
    } else {
        Err(SafeFsError::NotAbsolute {
            path: path.to_owned(),
        })
    }
}

/// What a snapshot copied.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
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

/// The name of the temporary file [`write_atomic`] uses beside `name`. It is
/// fixed, not random, so a crash leaves one leftover to clear, not many.
fn temp_name(name: &CStr) -> Result<CString, SafeFsError> {
    let bytes = [b".", name.to_bytes(), TEMP_SUFFIX].concat();
    CString::new(bytes).map_err(|_| SafeFsError::InvalidPath {
        path: String::from_utf8_lossy(name.to_bytes()).into_owned(),
        reason: "it holds a NUL byte",
    })
}

/// Creates the temporary file. A leftover regular file is what a crash leaves
/// and is replaced; anything else there was planted, and is refused.
fn create_temp(parent: BorrowedFd<'_>, name: &CStr, path: &Path) -> Result<OwnedFd, SafeFsError> {
    for _ in 0..RACE_ATTEMPTS {
        match openat(parent, name, CREATE_FILE, Mode::RUSR | Mode::WUSR) {
            Ok(fd) => return Ok(fd),
            Err(Errno::EXIST) => {}
            Err(errno) => return Err(io_err("create", path)(errno)),
        }
        let seen = match statat(parent, name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(seen) => seen,
            Err(Errno::NOENT) => continue,
            Err(errno) => return Err(io_err("inspect", path)(errno)),
        };
        if FileType::from_raw_mode(seen.st_mode) != FileType::RegularFile {
            break;
        }
        // Removing never follows or writes through what is being removed.
        remove_file(parent, name, path)?;
    }
    Err(SafeFsError::AlreadyExists {
        path: path.to_owned(),
    })
}

/// `unlinkat`, where something already gone is what was wanted.
fn remove_file(parent: BorrowedFd<'_>, name: &CStr, path: &Path) -> Result<(), SafeFsError> {
    match unlinkat(parent, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(errno) => Err(io_err("remove", path)(errno)),
    }
}

/// Atomically replaces `name` with `bytes`: a new temporary file beside it,
/// `fsync`, `renameat`, and an `fsync` of the directory. A crash leaves the
/// old content or the new. A symlink at `name` is replaced, not followed.
///
/// This assumes no hostile writer in the parent directory beyond what could
/// edit `compose.yaml` anyway: one there could still replace the file or
/// remove it after the rename. What it cannot do is redirect the write.
///
/// # Errors
///
/// [`SafeFsError::InvalidMode`] when `mode` holds more than permission bits,
/// [`SafeFsError::AlreadyExists`] when something other than a regular file is
/// at the temporary name, and otherwise as [`Root::open`].
pub fn write_atomic(
    root: &Root,
    name: &RelPath,
    bytes: &[u8],
    mode: u32,
) -> Result<(), SafeFsError> {
    if mode & !0o777 != 0 {
        return Err(SafeFsError::InvalidMode { mode });
    }
    let parent = root.open_parent(name)?;
    let path = root.path.join(name.as_path());
    let temp = temp_name(&name.name)?;
    let temp_path = path.with_file_name(name_path(&temp));
    let file = File::from(create_temp(parent.as_fd(), &temp, &temp_path)?);

    let replace = |mut file: File| {
        file.write_all(bytes).map_err(file_io_err("write", &path))?;
        fchmod(&file, Mode::from_raw_mode(fit::<u32, RawMode>(mode)))
            .map_err(io_err("set mode of", &path))?;
        fsync(&file).map_err(io_err("sync", &path))?;
        drop(file);
        renameat(&parent, &temp, &parent, &name.name).map_err(io_err("rename to", &path))?;
        fsync(&parent).map_err(io_err("sync directory of", &path))
    };
    replace(file).map_err(|err| with_cleanup(err, remove_file(parent.as_fd(), &temp, &temp_path)))
}

/// Reads a regular file, up to `cap` bytes. `None` when it, or a directory
/// above it, does not exist.
///
/// # Errors
///
/// [`SafeFsError::SymlinkRefused`] for a symlink,
/// [`SafeFsError::NotRegularFile`] for anything else that is not a regular
/// file, [`SafeFsError::NotADirectory`] when a parent is not a real directory
/// and [`SafeFsError::TooLarge`] past the cap.
pub fn read_file(root: &Root, name: &RelPath, cap: usize) -> Result<Option<Vec<u8>>, SafeFsError> {
    let path = root.path.join(name.as_path());
    let parent = match root.open_parent(name) {
        Ok(parent) => parent,
        Err(SafeFsError::Missing { .. }) => return Ok(None),
        Err(err) => return Err(err),
    };
    let seen = match statat(&parent, &name.name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(seen) => seen,
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(io_err("inspect", &path)(errno)),
    };
    match FileType::from_raw_mode(seen.st_mode) {
        FileType::RegularFile => {}
        FileType::Symlink => return Err(SafeFsError::SymlinkRefused { path }),
        _ => return Err(SafeFsError::NotRegularFile { path }),
    }
    #[cfg(test)]
    seam::run(seam::Point::LstatToOpen, &name.name);
    let fd = match openat(&parent, &name.name, OPEN_ANY, Mode::empty()) {
        Ok(fd) => fd,
        Err(Errno::NOENT) => return Ok(None),
        Err(Errno::LOOP) => return Err(SafeFsError::SymlinkRefused { path }),
        Err(errno) => return Err(io_err("open", &path)(errno)),
    };
    let opened = fstat(&fd).map_err(io_err("inspect", &path))?;
    if FileType::from_raw_mode(opened.st_mode) != FileType::RegularFile {
        return Err(SafeFsError::NotRegularFile { path });
    }

    // `Take` reports no size to `read_to_end`, so nothing is allocated from
    // the size of the file, only from what is read.
    let limit = u64::try_from(cap).unwrap_or(u64::MAX).saturating_add(1);
    let mut content = Vec::new();
    File::from(fd)
        .take(limit)
        .read_to_end(&mut content)
        .map_err(file_io_err("read", &path))?;
    if content.len() > cap {
        return Err(SafeFsError::TooLarge { path, cap });
    }
    Ok(Some(content))
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
/// directory, [`SafeFsError::TooDeep`] past [`MAX_DEPTH`],
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
fn snapshot_limited(
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

/// Removes the oldest backups beyond `keep`, by directory name (a sortable
/// id derived from RFC 3339), and every `.partial` leftover. Entries that are
/// not directories are not backups and stay. An absent `backups` directory is
/// nothing to do.
///
/// Call it under the deployment's lock: a `.partial` is assumed to be a
/// leftover, not a snapshot in progress.
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
fn read_all_names(
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
fn remove_entry(parent: BorrowedFd<'_>, name: &CStr, path: &Path) -> Result<(), SafeFsError> {
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
fn empty_dir(
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
fn move_to_top(
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
fn ensure_real_dir(
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
enum Removal {
    None,
    First,
}

/// Copies each path, with its parents, from `source` to below `dst`. Shared
/// by snapshot (into a fresh directory) and restore (into a hostile one).
fn copy_paths(
    source: &Root,
    dst: BorrowedFd<'_>,
    dst_label: &Path,
    paths: &[RelPath],
    removal: Removal,
    max_entries: usize,
) -> Result<SnapshotStats, SafeFsError> {
    let mut copier = Copier {
        src_label: &source.path,
        dst_label,
        buf: vec![0; COPY_BUFFER],
        stats: SnapshotStats::default(),
        max_entries,
    };
    // Parents created here get their metadata last: creating an entry would
    // change a directory's time, and a restrictive mode could block the next.
    let mut created: BTreeMap<&[CString], Stat> = BTreeMap::new();
    for path in paths {
        let (src_parent, dst_parent) =
            copier.descend(source.fd.as_fd(), dst, path, &mut created)?;
        if removal == Removal::First {
            let label = dst_label.join(path.as_path());
            remove_entry(dst_parent.as_fd(), &path.name, &label)?;
        }
        copier.copy_entry(
            src_parent.as_fd(),
            dst_parent.as_fd(),
            &path.name,
            path.as_path(),
            path.depth(),
        )?;
        fsync(&dst_parent).map_err(io_err("sync directory of", &dst_label.join(path.as_path())))?;
    }
    // Deepest first, as a parent's mode can block the way to its children.
    for (parents, stat) in created.iter().rev() {
        let fd = walk(dst, dst_label, parents)?;
        let label = parents
            .iter()
            .fold(dst_label.to_owned(), |mut label, part| {
                label.push(name_path(part));
                label
            });
        apply_metadata(fd.as_fd(), stat, &label)?;
        fsync(&fd).map_err(io_err("sync", &label))?;
    }
    fsync(dst).map_err(io_err("sync", dst_label))?;
    Ok(copier.stats)
}

/// One copy run: the labels errors are named with, the one buffer data moves
/// through, what has been copied so far and how large a directory may be.
struct Copier<'a> {
    src_label: &'a Path,
    dst_label: &'a Path,
    buf: Vec<u8>,
    stats: SnapshotStats,
    max_entries: usize,
}

impl<'a> Copier<'a> {
    /// Walks to the parents of `path` on both sides. The source side must be
    /// real directories; the destination's are made so.
    fn descend(
        &mut self,
        src_root: BorrowedFd<'_>,
        dst_root: BorrowedFd<'_>,
        path: &'a RelPath,
        created: &mut BTreeMap<&'a [CString], Stat>,
    ) -> Result<(OwnedFd, OwnedFd), SafeFsError> {
        let mut src = src_root
            .try_clone_to_owned()
            .map_err(file_io_err("duplicate descriptor of", self.src_label))?;
        let mut dst = dst_root
            .try_clone_to_owned()
            .map_err(file_io_err("duplicate descriptor of", self.dst_label))?;
        let mut rel = PathBuf::new();
        for (index, part) in path.parents.iter().enumerate() {
            rel.push(name_path(part));
            let src_path = self.src_label.join(&rel);
            src = open_dir(src.as_fd(), part).map_err(walk_err(&src_path))?;
            let stat = fstat(&src).map_err(io_err("inspect", &src_path))?;
            let (next, made) = ensure_real_dir(dst.as_fd(), part, &self.dst_label.join(&rel))?;
            dst = next;
            if made {
                self.stats.directories += 1;
                created.insert(&path.parents[..=index], stat);
            }
        }
        Ok((src, dst))
    }

    /// Copies whatever `name` is. `rel` is its path below the root, `depth`
    /// its level, 1 being directly below the root.
    fn copy_entry(
        &mut self,
        src_parent: BorrowedFd<'_>,
        dst_parent: BorrowedFd<'_>,
        name: &CStr,
        rel: &Path,
        depth: usize,
    ) -> Result<(), SafeFsError> {
        let src_path = self.src_label.join(rel);
        if depth > MAX_DEPTH {
            return Err(SafeFsError::TooDeep {
                path: src_path,
                limit: MAX_DEPTH,
            });
        }
        let seen = statat(src_parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(entry_err("inspect", &src_path))?;
        match FileType::from_raw_mode(seen.st_mode) {
            FileType::Symlink => {
                return self.copy_symlink(src_parent, dst_parent, name, rel, &seen);
            }
            FileType::RegularFile | FileType::Directory => {}
            other => return Err(special_file(src_path, other)),
        }
        // The `lstat` above only chose the route. From here the descriptor
        // decides: `O_NOFOLLOW` fails on a symlink swapped in, `O_NONBLOCK`
        // keeps a FIFO swapped in from blocking the open.
        #[cfg(test)]
        seam::run(seam::Point::LstatToOpen, name);
        let fd = match openat(src_parent, name, OPEN_ANY, Mode::empty()) {
            Ok(fd) => fd,
            Err(Errno::LOOP) => return Err(SafeFsError::SymlinkRefused { path: src_path }),
            Err(errno) => return Err(entry_err("open", &src_path)(errno)),
        };
        let opened = fstat(&fd).map_err(io_err("inspect", &src_path))?;
        match FileType::from_raw_mode(opened.st_mode) {
            FileType::RegularFile => self.copy_file(fd, dst_parent, name, rel, &opened),
            FileType::Directory => self.copy_dir(&fd, dst_parent, name, rel, depth, &opened),
            other => Err(special_file(src_path, other)),
        }
    }

    fn copy_file(
        &mut self,
        src: OwnedFd,
        dst_parent: BorrowedFd<'_>,
        name: &CStr,
        rel: &Path,
        stat: &Stat,
    ) -> Result<(), SafeFsError> {
        let (src_path, dst_path) = (self.src_label.join(rel), self.dst_label.join(rel));
        let created = openat(dst_parent, name, CREATE_FILE, Mode::RUSR | Mode::WUSR)
            .map_err(io_err("create", &dst_path))?;
        let mut reader = File::from(src);
        let mut writer = File::from(created);
        loop {
            let count = match reader.read(&mut self.buf) {
                Ok(0) => break,
                Ok(count) => count,
                Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
                Err(err) => return Err(file_io_err("read", &src_path)(err)),
            };
            let chunk = self.buf.get(..count).unwrap_or_default();
            writer
                .write_all(chunk)
                .map_err(file_io_err("write", &dst_path))?;
            self.stats.bytes = self.stats.bytes.saturating_add(fit(count));
        }
        apply_metadata(writer.as_fd(), stat, &dst_path)?;
        fsync(&writer).map_err(io_err("sync", &dst_path))?;
        self.stats.files += 1;
        Ok(())
    }

    fn copy_dir(
        &mut self,
        src: &OwnedFd,
        dst_parent: BorrowedFd<'_>,
        name: &CStr,
        rel: &Path,
        depth: usize,
        stat: &Stat,
    ) -> Result<(), SafeFsError> {
        let (src_path, dst_path) = (self.src_label.join(rel), self.dst_label.join(rel));
        mkdirat(dst_parent, name, Mode::RWXU).map_err(io_err("create", &dst_path))?;
        let dst = open_dir(dst_parent, name).map_err(walk_err(&dst_path))?;
        for child in read_all_names(src.as_fd(), &src_path, self.max_entries)? {
            let child_rel = rel.join(name_path(&child));
            self.copy_entry(src.as_fd(), dst.as_fd(), &child, &child_rel, depth + 1)?;
        }
        apply_metadata(dst.as_fd(), stat, &dst_path)?;
        fsync(&dst).map_err(io_err("sync", &dst_path))?;
        self.stats.directories += 1;
        Ok(())
    }

    /// `readlinkat` fails if the entry is no longer a symlink, so what is read
    /// is a link target, never a file's content.
    fn copy_symlink(
        &mut self,
        src_parent: BorrowedFd<'_>,
        dst_parent: BorrowedFd<'_>,
        name: &CStr,
        rel: &Path,
        stat: &Stat,
    ) -> Result<(), SafeFsError> {
        let (src_path, dst_path) = (self.src_label.join(rel), self.dst_label.join(rel));
        let target =
            readlinkat(src_parent, name, Vec::new()).map_err(entry_err("read", &src_path))?;
        symlinkat(target.as_c_str(), dst_parent, name).map_err(io_err("create", &dst_path))?;
        #[cfg(test)]
        seam::run(seam::Point::SymlinkCreated, name);
        apply_symlink_metadata(dst_parent, name, target.as_c_str(), stat, &dst_path)?;
        self.stats.symlinks += 1;
        Ok(())
    }
}

fn special_file(path: PathBuf, kind: FileType) -> SafeFsError {
    let kind = match kind {
        FileType::Fifo => "FIFO",
        FileType::Socket => "socket",
        FileType::CharacterDevice => "character device",
        FileType::BlockDevice => "block device",
        _ => "file of an unknown kind",
    };
    SafeFsError::SpecialFile { path, kind }
}

/// Sets owner, mode and times on an open file or directory, in that order;
/// see the module documentation. The owner changes only if it differs, so
/// the agent needs no capability for what it already owns.
fn apply_metadata(fd: BorrowedFd<'_>, from: &Stat, path: &Path) -> Result<(), SafeFsError> {
    let current = fstat(fd).map_err(io_err("inspect", path))?;
    if current.st_uid != from.st_uid || current.st_gid != from.st_gid {
        fchown(
            fd,
            Some(Uid::from_raw(from.st_uid)),
            Some(Gid::from_raw(from.st_gid)),
        )
        .map_err(io_err("set owner of", path))?;
    }
    let wanted = Mode::from_raw_mode(from.st_mode);
    fchmod(fd, wanted).map_err(io_err("set mode of", path))?;
    let got = Mode::from_raw_mode(fstat(fd).map_err(io_err("inspect", path))?.st_mode);
    if got != wanted {
        return Err(SafeFsError::ModeNotPreserved {
            path: path.to_owned(),
            wanted,
            got,
        });
    }
    futimens(fd, &timestamps(from)).map_err(io_err("set times of", path))
}

/// Sets owner and times on a symlink just created, on a descriptor of it, so
/// that an entry swapped in at that name receives neither.
#[cfg(target_os = "linux")]
fn apply_symlink_metadata(
    parent: BorrowedFd<'_>,
    name: &CStr,
    target: &CStr,
    from: &Stat,
    path: &Path,
) -> Result<(), SafeFsError> {
    let flags = OFlags::PATH | OFlags::NOFOLLOW | OFlags::CLOEXEC;
    let link = openat(parent, name, flags, Mode::empty()).map_err(io_err("open", path))?;
    let current = fstat(&link).map_err(io_err("inspect", path))?;
    check_new_symlink(link.as_fd(), c"", target, &current, path)?;
    let flags = AtFlags::EMPTY_PATH | AtFlags::SYMLINK_NOFOLLOW;
    set_symlink_metadata(link.as_fd(), c"", flags, &current, from, path)
}

/// Sets owner and times on a symlink just created, by name. A writer swapping
/// the name right now would give the entry swapped in the owner and times. The
/// agent's production target is Linux, which closes this window.
#[cfg(not(target_os = "linux"))]
fn apply_symlink_metadata(
    parent: BorrowedFd<'_>,
    name: &CStr,
    target: &CStr,
    from: &Stat,
    path: &Path,
) -> Result<(), SafeFsError> {
    let flags = AtFlags::SYMLINK_NOFOLLOW;
    let current = statat(parent, name, flags).map_err(io_err("inspect", path))?;
    check_new_symlink(parent, name, target, &current, path)?;
    set_symlink_metadata(parent, name, flags, &current, from, path)
}

/// Confirms that an entry is the symlink just created, not one swapped in: it
/// has the target just written, and no other name that would also be changed.
fn check_new_symlink(
    dir: BorrowedFd<'_>,
    name: &CStr,
    target: &CStr,
    current: &Stat,
    path: &Path,
) -> Result<(), SafeFsError> {
    let replaced = || SafeFsError::Replaced {
        path: path.to_owned(),
    };
    if FileType::from_raw_mode(current.st_mode) != FileType::Symlink || current.st_nlink != 1 {
        return Err(replaced());
    }
    let written = readlinkat(dir, name, Vec::new()).map_err(io_err("read", path))?;
    if written.as_c_str() != target {
        return Err(replaced());
    }
    Ok(())
}

fn set_symlink_metadata(
    dir: BorrowedFd<'_>,
    name: &CStr,
    flags: AtFlags,
    current: &Stat,
    from: &Stat,
    path: &Path,
) -> Result<(), SafeFsError> {
    if current.st_uid != from.st_uid || current.st_gid != from.st_gid {
        chownat(
            dir,
            name,
            Some(Uid::from_raw(from.st_uid)),
            Some(Gid::from_raw(from.st_gid)),
            flags,
        )
        .map_err(io_err("set owner of", path))?;
    }
    utimensat(dir, name, &timestamps(from), flags).map_err(io_err("set times of", path))
}

fn timestamps(stat: &Stat) -> Timestamps {
    Timestamps {
        last_access: Timespec {
            tv_sec: fit(stat.st_atime),
            tv_nsec: fit(stat.st_atime_nsec),
        },
        last_modification: Timespec {
            tv_sec: fit(stat.st_mtime),
            tv_nsec: fit(stat.st_mtime_nsec),
        },
    }
}

/// Converts between integer types whose widths differ by target (`Stat`'s
/// fields, `RawMode`) and always hold the value at hand: times and masked
/// modes, or a `usize` count into a `u64`. Generic so that no target sees a
/// conversion from a type to itself.
fn fit<T, U: TryFrom<T> + Default>(value: T) -> U {
    U::try_from(value).unwrap_or_default()
}

/// Lets a test act at a point where a racing container could, so that what a
/// race would do happens every time. Compiled out of production.
#[cfg(test)]
mod seam {
    use std::cell::RefCell;
    use std::ffi::CStr;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub(super) enum Point {
        /// A source entry has been seen with `lstat` and is about to be opened.
        LstatToOpen,
        /// A symlink has been created and its metadata is about to be set.
        SymlinkCreated,
        /// A removal has read a name and is about to open it.
        RemovalOpen,
        /// A removal is about to move a directory up.
        MoveUp,
    }

    type Hook = Box<dyn FnMut(Point, &CStr)>;

    thread_local! {
        // Per thread, as each test runs on its own and others run alongside.
        static HOOK: RefCell<Option<Hook>> = const { RefCell::new(None) };
    }

    pub(super) fn set(hook: impl FnMut(Point, &CStr) + 'static) {
        HOOK.set(Some(Box::new(hook)));
    }

    pub(super) fn run(point: Point, name: &CStr) {
        HOOK.with_borrow_mut(|hook| {
            if let Some(hook) = hook {
                hook(point, name);
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use std::fs::{self, File, Permissions};
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime};

    use rustix::fs::{
        AtFlags, CWD, Mode, OFlags, Timespec, Timestamps, mkdirat, openat, utimensat,
    };

    use super::{
        MAX_DEPTH, REMOVAL_BATCH, RelPath, Root, SafeFsError, empty_dir, move_to_top, prune,
        read_file, remove_entry, restore, seam, snapshot, snapshot_limited, temp_name,
        write_atomic,
    };

    const SECRET: &[u8] = b"sentinel content, must not be copied";
    const SENTINEL_MTIME: i64 = 1_500_000_000;

    fn rel(path: &str) -> RelPath {
        RelPath::new(path).unwrap()
    }

    fn root(path: &Path) -> Root {
        Root::open(path).unwrap()
    }

    fn write(path: &Path, content: &[u8], mode: u32) {
        fs::write(path, content).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    fn mkdir(path: &Path, mode: u32) {
        fs::create_dir(path).unwrap();
        fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
    }

    fn set_mtime(path: &Path, secs: u64) {
        let time = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
        File::open(path).unwrap().set_modified(time).unwrap();
    }

    fn mkfifo(path: &Path) {
        let status = Command::new("mkfifo").arg(path).status().unwrap();
        assert!(status.success());
    }

    fn mode(path: &Path) -> u32 {
        fs::symlink_metadata(path).unwrap().mode() & 0o7777
    }

    fn mtime(path: &Path) -> i64 {
        fs::symlink_metadata(path).unwrap().mtime()
    }

    /// A directory holding one file: what a hostile link would point at.
    fn sentinel(base: &Path) -> PathBuf {
        let dir = base.join("sentinel");
        mkdir(&dir, 0o755);
        write(&dir.join("keep"), SECRET, 0o644);
        let secs = u64::try_from(SENTINEL_MTIME).unwrap();
        set_mtime(&dir.join("keep"), secs);
        set_mtime(&dir, secs);
        dir
    }

    /// Owner is compared with the sentinel's parent, which nothing under test
    /// is pointed at, because a new entry's group depends on the platform.
    fn assert_sentinel_untouched(dir: &Path) {
        let parent = fs::symlink_metadata(dir.parent().unwrap()).unwrap();
        for entry in [dir.to_owned(), dir.join("keep")] {
            let seen = fs::symlink_metadata(&entry).unwrap();
            assert_eq!(seen.uid(), parent.uid(), "{entry:?}");
            assert_eq!(seen.gid(), parent.gid(), "{entry:?}");
            assert_eq!(seen.mtime(), SENTINEL_MTIME, "{entry:?}");
        }
        assert_eq!(mode(dir), 0o755);
        assert_eq!(fs::read(dir.join("keep")).unwrap(), SECRET);
        assert_eq!(mode(&dir.join("keep")), 0o644);
        assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
    }

    fn assert_no_secret_in(dir: &Path) {
        for entry in fs::read_dir(dir).unwrap() {
            let entry = entry.unwrap();
            let kind = entry.file_type().unwrap();
            if kind.is_dir() {
                assert_no_secret_in(&entry.path());
            } else if kind.is_file() {
                assert_ne!(fs::read(entry.path()).unwrap(), SECRET, "{entry:?}");
            }
        }
    }

    #[test]
    fn snapshot_and_restore_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        let data = compose.join("data");
        mkdir(&data, 0o750);
        let sub = data.join("sub");
        mkdir(&sub, 0o750);
        mkdir(&data.join("empty"), 0o750);
        write(&sub.join("a.txt"), b"first", 0o640);
        write(&data.join("b.bin"), &vec![0_u8; 200_000], 0o750);
        mkdir(&compose.join("conf"), 0o710);
        write(&compose.join("conf/app.ini"), b"second", 0o640);
        set_mtime(&sub.join("a.txt"), 1_600_000_000);
        set_mtime(&sub, 1_600_000_100);
        set_mtime(&data, 1_600_000_200);
        set_mtime(&compose.join("conf"), 1_600_000_300);

        let dest = tmp.path().join("2026-11-01T10-00-00Z");
        let paths = [rel("data"), rel("conf/app.ini")];
        let stats = snapshot(&root(&compose), &paths, &dest).unwrap();
        assert_eq!(stats.files, 3);
        assert_eq!(stats.directories, 4);
        assert_eq!(stats.bytes, 200_011);
        assert!(!tmp.path().join("2026-11-01T10-00-00Z.partial").exists());
        assert_eq!(fs::read(dest.join("data/sub/a.txt")).unwrap(), b"first");
        assert_eq!(mode(&dest.join("data")), 0o750);
        assert_eq!(mtime(&dest.join("data")), 1_600_000_200);
        assert_eq!(mode(&dest.join("conf")), 0o710);
        assert_eq!(mtime(&dest.join("conf")), 1_600_000_300);

        fs::remove_dir_all(&data).unwrap();
        fs::remove_dir_all(compose.join("conf")).unwrap();
        restore(&dest, &root(&compose), &paths).unwrap();

        assert_eq!(fs::read(sub.join("a.txt")).unwrap(), b"first");
        assert_eq!(mode(&sub.join("a.txt")), 0o640);
        assert_eq!(mtime(&sub.join("a.txt")), 1_600_000_000);
        assert_eq!(mode(&sub), 0o750);
        assert_eq!(mtime(&sub), 1_600_000_100);
        assert_eq!(mode(&data), 0o750);
        assert_eq!(mtime(&data), 1_600_000_200);
        assert_eq!(fs::read(data.join("b.bin")).unwrap().len(), 200_000);
        assert_eq!(mode(&data.join("b.bin")), 0o750);
        assert!(data.join("empty").is_dir());
        assert_eq!(fs::read_dir(data.join("empty")).unwrap().count(), 0);
        assert_eq!(fs::read(compose.join("conf/app.ini")).unwrap(), b"second");
        assert_eq!(mode(&compose.join("conf")), 0o710);
        assert_eq!(mtime(&compose.join("conf")), 1_600_000_300);
    }

    #[test]
    fn set_id_bits_survive_the_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        write(&compose.join("tool"), b"x", 0o4755);
        mkdir(&compose.join("shared"), 0o2750);

        let dest = tmp.path().join("snap");
        let paths = [rel("tool"), rel("shared")];
        snapshot(&root(&compose), &paths, &dest).unwrap();
        assert_eq!(mode(&dest.join("tool")), 0o4755);
        assert_eq!(mode(&dest.join("shared")), 0o2750);

        fs::remove_file(compose.join("tool")).unwrap();
        restore(&dest, &root(&compose), &paths).unwrap();
        assert_eq!(mode(&compose.join("tool")), 0o4755);
        assert_eq!(mode(&compose.join("shared")), 0o2750);
    }

    #[test]
    fn snapshot_copies_symlinks_as_symlinks() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        symlink(outside.join("keep"), data.join("link")).unwrap();
        symlink(&outside, data.join("dirlink")).unwrap();

        let dest = tmp.path().join("snap");
        let stats = snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

        assert_eq!(stats.symlinks, 2);
        assert_eq!(stats.files, 0);
        assert_eq!(
            fs::read_link(dest.join("data/link")).unwrap(),
            outside.join("keep")
        );
        assert_eq!(fs::read_link(dest.join("data/dirlink")).unwrap(), outside);
        assert_no_secret_in(&dest);

        fs::remove_dir_all(&data).unwrap();
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();
        assert_eq!(
            fs::read_link(data.join("link")).unwrap(),
            outside.join("keep")
        );
        assert_sentinel_untouched(&outside);
    }

    #[test]
    fn special_file_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        write(&data.join("before"), b"copied first", 0o644);
        mkfifo(&data.join("pipe"));

        let dest = tmp.path().join("snap");
        let err = snapshot(&root(&compose), &[rel("data")], &dest).unwrap_err();

        assert!(matches!(err, SafeFsError::SpecialFile { .. }), "{err}");
        assert!(err.to_string().contains("data/pipe"), "{err}");
        assert!(!dest.exists());
        assert!(!tmp.path().join("snap.partial").exists());
    }

    #[test]
    fn stale_partial_is_replaced_and_existing_dest_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        write(&compose.join("file"), b"new", 0o644);
        let dest = tmp.path().join("snap");
        fs::create_dir(tmp.path().join("snap.partial")).unwrap();
        write(&tmp.path().join("snap.partial/stale"), b"old", 0o644);

        snapshot(&root(&compose), &[rel("file")], &dest).unwrap();
        assert!(!dest.join("stale").exists());

        let err = snapshot(&root(&compose), &[rel("file")], &dest).unwrap_err();
        assert!(matches!(err, SafeFsError::AlreadyExists { .. }), "{err}");
        assert_eq!(fs::read(dest.join("file")).unwrap(), b"new");
    }

    #[test]
    fn missing_path_is_missing() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        let dest = tmp.path().join("snap");

        for path in ["absent", "absent/below"] {
            let err = snapshot(&root(&compose), &[rel(path)], &dest).unwrap_err();
            assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
            assert!(err.to_string().contains("absent"), "{err}");
            assert!(!dest.exists());
            assert!(!tmp.path().join("snap.partial").exists());
        }
    }

    #[test]
    fn parent_symlink_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        symlink(&outside, compose.join("data")).unwrap();

        let dest = tmp.path().join("snap");
        let err = snapshot(&root(&compose), &[rel("data/keep")], &dest).unwrap_err();

        assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
        assert!(!dest.exists());
    }

    #[test]
    fn overlapping_paths_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        fs::create_dir_all(compose.join("data/x")).unwrap();
        let dest = tmp.path().join("snap");

        for paths in [[rel("data"), rel("data/x")], [rel("data/x"), rel("data")]] {
            let err = snapshot(&root(&compose), &paths, &dest).unwrap_err();
            assert!(matches!(err, SafeFsError::OverlappingPaths { .. }), "{err}");
        }
    }

    #[test]
    fn restore_removes_what_the_container_added() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        write(&data.join("kept"), b"original", 0o644);
        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

        write(&data.join("kept"), b"tampered", 0o644);
        fs::create_dir_all(data.join("added/deep")).unwrap();
        write(&data.join("added/deep/file"), b"x", 0o444);
        mkfifo(&data.join("added/pipe"));
        symlink("/", data.join("added/link")).unwrap();

        restore(&dest, &root(&compose), &[rel("data")]).unwrap();

        assert_eq!(fs::read(data.join("kept")).unwrap(), b"original");
        assert!(!data.join("added").exists());
    }

    #[test]
    fn symlink_swapped_during_restore_stays_inside() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(data.join("sub")).unwrap();
        write(&data.join("keep"), b"from the snapshot", 0o600);
        write(&data.join("sub/file"), b"nested", 0o600);
        fs::set_permissions(&data, Permissions::from_mode(0o700)).unwrap();

        // The whole path is swapped for a link, then a parent of the path.
        for paths in [vec![rel("data")], vec![rel("data/keep"), rel("data/sub")]] {
            let dest = tmp.path().join(format!("snap-{}", paths.len()));
            snapshot(&root(&compose), &paths, &dest).unwrap();

            fs::remove_dir_all(&data).unwrap();
            symlink(&outside, &data).unwrap();

            restore(&dest, &root(&compose), &paths).unwrap();

            assert_sentinel_untouched(&outside);
            assert!(fs::symlink_metadata(&data).unwrap().is_dir());
            assert_eq!(mode(&data), 0o700);
            assert_eq!(fs::read(data.join("keep")).unwrap(), b"from the snapshot");
            assert_eq!(fs::read(data.join("sub/file")).unwrap(), b"nested");
        }
    }

    #[test]
    fn links_planted_below_the_path_are_removed_not_followed() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(data.join("sub")).unwrap();
        write(&data.join("sub/file"), b"nested", 0o600);
        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

        fs::remove_dir_all(data.join("sub")).unwrap();
        symlink(&outside, data.join("sub")).unwrap();
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();

        assert_sentinel_untouched(&outside);
        assert!(fs::symlink_metadata(data.join("sub")).unwrap().is_dir());
        assert_eq!(fs::read(data.join("sub/file")).unwrap(), b"nested");
    }

    #[test]
    fn a_fifo_in_place_of_the_path_does_not_block_restore() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        write(&compose.join("file"), b"original", 0o644);
        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("file")], &dest).unwrap();

        fs::remove_file(compose.join("file")).unwrap();
        mkfifo(&compose.join("file"));
        restore(&dest, &root(&compose), &[rel("file")]).unwrap();

        // Checked first: reading a FIFO left in place would hang the test.
        assert!(
            fs::symlink_metadata(compose.join("file"))
                .unwrap()
                .is_file()
        );
        assert_eq!(fs::read(compose.join("file")).unwrap(), b"original");
    }

    #[test]
    fn incomplete_snapshot_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        write(&compose.join("one"), b"live", 0o644);
        write(&compose.join("two"), b"live", 0o644);
        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("one")], &dest).unwrap();

        let err = restore(&dest, &root(&compose), &[rel("one"), rel("two")]).unwrap_err();

        assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
        assert!(err.to_string().contains("two"), "{err}");
        assert_eq!(fs::read(compose.join("two")).unwrap(), b"live");
    }

    /// A container keeps swapping a directory for a link to the sentinel
    /// while snapshots and restores run. Either may fail; neither may touch
    /// or copy the sentinel.
    #[test]
    fn racing_swaps_never_reach_the_sentinel() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(data.join("sub")).unwrap();
        write(&data.join("sub/file"), b"nested", 0o600);
        let clean = tmp.path().join("clean");
        snapshot(&root(&compose), &[rel("data")], &clean).unwrap();

        let stop = Arc::new(AtomicBool::new(false));
        let swapper = std::thread::spawn({
            let stop = Arc::clone(&stop);
            let data = data.clone();
            let outside = outside.clone();
            move || {
                let (sub, held) = (data.join("sub"), data.join("held"));
                while !stop.load(Ordering::Relaxed) {
                    // Failures are expected: restore removes these under us.
                    let _ = fs::rename(&sub, &held);
                    let _ = symlink(&outside, &sub);
                    std::thread::yield_now();
                    let _ = fs::remove_file(&sub);
                    let _ = fs::rename(&held, &sub);
                }
            }
        });

        let compose_root = root(&compose);
        for round in 0..100 {
            let dest = tmp.path().join(format!("race-{round}"));
            if snapshot(&compose_root, &[rel("data")], &dest).is_ok() {
                assert_no_secret_in(&dest);
            }
            // Restore fails when it collides with the swapper; that is fine.
            let _ = restore(&clean, &compose_root, &[rel("data")]);
        }
        stop.store(true, Ordering::Relaxed);
        swapper.join().unwrap();

        assert_sentinel_untouched(&outside);
    }

    /// A source tree with one file, and a snapshot's destination, where
    /// `swap` replaces that file between `lstat` and open.
    fn snapshot_with_swap_in_open_window(
        tmp: &Path,
        swap: impl Fn(&Path) + 'static,
    ) -> Result<PathBuf, SafeFsError> {
        let compose = tmp.join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        let file = data.join("file");
        write(&file, b"ordinary", 0o644);

        seam::set(move |point, name| {
            if point == seam::Point::LstatToOpen && name == c"file" {
                swap(&file);
            }
        });
        let dest = tmp.join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).map(|_| dest)
    }

    #[test]
    fn swap_to_symlink_in_open_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let keep = outside.join("keep");

        let result = snapshot_with_swap_in_open_window(tmp.path(), move |file| {
            fs::remove_file(file).unwrap();
            symlink(&keep, file).unwrap();
        });

        let err = result.unwrap_err();
        assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
        assert!(err.to_string().contains("data/file"), "{err}");
        assert!(!tmp.path().join("snap").exists());
        assert!(!tmp.path().join("snap.partial").exists());
        assert_sentinel_untouched(&outside);
    }

    #[test]
    fn swap_to_fifo_in_open_window_is_refused() {
        let tmp = tempfile::tempdir().unwrap();

        let result = snapshot_with_swap_in_open_window(tmp.path(), |file| {
            fs::remove_file(file).unwrap();
            mkfifo(file);
        });

        let err = result.unwrap_err();
        assert!(matches!(err, SafeFsError::SpecialFile { .. }), "{err}");
        assert!(err.to_string().contains("data/file"), "{err}");
        assert!(!tmp.path().join("snap").exists());
        assert!(!tmp.path().join("snap.partial").exists());
    }

    #[test]
    fn entry_vanishing_in_open_window_is_missing() {
        let tmp = tempfile::tempdir().unwrap();

        let result = snapshot_with_swap_in_open_window(tmp.path(), |file| {
            fs::remove_file(file).unwrap();
        });

        let err = result.unwrap_err();
        assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
        assert!(err.to_string().contains("data/file"), "{err}");
        assert!(!tmp.path().join("snap.partial").exists());
    }

    /// Makes `levels` nested directories, one at a time by descriptor, since
    /// a path to the bottom of a long chain is too long to be used whole.
    fn plant_chain(base: &Path, levels: usize) {
        let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
        let mut current = openat(CWD, base, flags, Mode::empty()).unwrap();
        for _ in 0..levels {
            mkdirat(&current, c"d", Mode::RWXU).unwrap();
            current = openat(&current, c"d", flags, Mode::empty()).unwrap();
        }
    }

    /// A snapshot of `data` with one file, then `plant` changing `data`.
    fn restore_after(plant: impl FnOnce(&Path)) {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        write(&data.join("kept"), b"original", 0o644);
        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

        plant(&data);
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();

        assert_eq!(fs::read(data.join("kept")).unwrap(), b"original");
        assert_eq!(fs::read_dir(&data).unwrap().count(), 1);
    }

    #[test]
    fn restore_succeeds_over_a_tree_deeper_than_the_limit() {
        restore_after(|data| plant_chain(data, MAX_DEPTH + 5));
    }

    #[test]
    fn restore_succeeds_over_a_chain_needing_several_passes() {
        restore_after(|data| plant_chain(data, MAX_DEPTH * 3 + 7));
    }

    #[test]
    fn restore_clears_deep_directories_side_by_side() {
        restore_after(|data| {
            for name in ["one", "two"] {
                let branch = data.join(name);
                mkdir(&branch, 0o755);
                plant_chain(&branch, MAX_DEPTH + 5);
            }
        });
    }

    /// The names a deep directory would move to are taken, by a file and by a
    /// directory with something in it: it takes the next, and they stay for
    /// the removal to reach in its own time.
    #[test]
    fn a_deep_directory_moves_past_planted_names() {
        let tmp = tempfile::tempdir().unwrap();
        let top = tmp.path().join("top");
        mkdir(&top, 0o755);
        write(&top.join(".landfall-deep-0"), b"planted", 0o644);
        fs::create_dir_all(top.join(".landfall-deep-1/full")).unwrap();
        fs::create_dir_all(top.join("below/deep/inside")).unwrap();
        let (top_root, below_root) = (root(&top), root(&top.join("below")));

        let mut moved = 0;
        move_to_top(
            top_root.fd.as_fd(),
            below_root.fd.as_fd(),
            c"deep",
            &top.join("below/deep"),
            &mut moved,
        )
        .unwrap();

        assert_eq!(moved, 3);
        assert!(top.join(".landfall-deep-2/inside").is_dir());
        assert!(!top.join("below/deep").exists());
        assert_eq!(fs::read(top.join(".landfall-deep-0")).unwrap(), b"planted");
        assert!(top.join(".landfall-deep-1/full").is_dir());
    }

    /// A directory at the depth limit, in a directory `top` of its own, with
    /// that directory opened and `top` already removed if `remove_top`.
    fn deep_child(tmp: &Path, remove_top: bool) -> (Root, Root, PathBuf) {
        let top = tmp.join("top");
        mkdir(&top, 0o755);
        let dir = tmp.join("dir");
        fs::create_dir_all(dir.join("deep/inside")).unwrap();
        let (top_root, dir_root) = (root(&top), root(&dir));
        if remove_top {
            fs::remove_dir(&top).unwrap();
        }
        (top_root, dir_root, dir)
    }

    #[test]
    fn removal_errors_when_the_top_directory_is_gone() {
        let tmp = tempfile::tempdir().unwrap();
        let (top, dir, dir_path) = deep_child(tmp.path(), true);
        let (top, dir) = (top.fd.as_fd(), dir.fd.as_fd());
        let deep = dir_path.join("deep");

        let err = move_to_top(top, dir, c"deep", &deep, &mut 0).unwrap_err();
        assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");

        let err = empty_dir(top, dir, &dir_path, MAX_DEPTH, &mut 0).unwrap_err();
        assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");
        assert!(err.to_string().contains("deep"), "{err}");
        assert!(deep.join("inside").is_dir());
    }

    #[test]
    fn deep_directory_vanishing_before_its_move_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let (top, dir, dir_path) = deep_child(tmp.path(), false);
        let deep = dir_path.join("deep");
        let gone = deep.clone();
        seam::set(move |point, name| {
            if point == seam::Point::MoveUp && name == c"deep" {
                fs::remove_dir_all(&gone).unwrap();
            }
        });

        let (top_fd, dir_fd) = (top.fd.as_fd(), dir.fd.as_fd());
        let moved = move_to_top(top_fd, dir_fd, c"deep", &deep, &mut 0).unwrap();
        assert!(!moved);

        fs::create_dir_all(&deep).unwrap();
        empty_dir(top_fd, dir_fd, &dir_path, MAX_DEPTH, &mut 0).unwrap();
        assert_eq!(fs::read_dir(&dir_path).unwrap().count(), 0);
        assert_eq!(fs::read_dir(top.path()).unwrap().count(), 0);
    }

    #[test]
    fn entry_vanishing_during_removal_is_not_an_error() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dir");
        mkdir(&dir, 0o755);
        write(&dir.join("file"), b"x", 0o644);
        let file = dir.join("file");
        seam::set(move |point, _| {
            if point == seam::Point::RemovalOpen {
                fs::remove_file(&file).unwrap();
            }
        });

        remove_entry(root(tmp.path()).fd.as_fd(), c"dir", &dir).unwrap();
        assert!(!dir.exists());
    }

    /// Every name listed is gone when it is opened, yet the directory never
    /// empties. This would spin forever if a pass removing nothing were
    /// accepted, so the hook gives up by panicking.
    #[test]
    fn removal_errors_when_a_pass_removes_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dir");
        mkdir(&dir, 0o755);
        write(&dir.join("0"), b"x", 0o644);
        let listed = dir.clone();
        let mut renames = 0;
        seam::set(move |point, name| {
            if point == seam::Point::RemovalOpen {
                renames += 1;
                assert!(renames < 100, "the removal does not stop");
                let from = listed.join(name.to_str().unwrap());
                fs::rename(from, listed.join(renames.to_string())).unwrap();
            }
        });

        let err = remove_entry(root(tmp.path()).fd.as_fd(), c"dir", &dir).unwrap_err();

        assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");
        assert!(err.to_string().contains("dir"), "{err}");
    }

    #[test]
    fn restore_clears_a_directory_larger_than_a_batch() {
        restore_after(|data| {
            let added = data.join("added");
            mkdir(&added, 0o755);
            for index in 0..=REMOVAL_BATCH {
                File::create(added.join(index.to_string())).unwrap();
            }
        });
    }

    #[test]
    fn directory_over_the_entry_limit_is_refused_naming_it() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        for index in 0..4 {
            File::create(data.join(index.to_string())).unwrap();
        }
        let compose_root = root(&compose);
        let dest = tmp.path().join("snap");

        let err = snapshot_limited(&compose_root, &[rel("data")], &dest, 3).unwrap_err();
        assert!(matches!(err, SafeFsError::TooManyEntries { .. }), "{err}");
        assert!(err.to_string().contains("data"), "{err}");
        assert!(!dest.exists());
        assert!(!tmp.path().join("snap.partial").exists());

        snapshot_limited(&compose_root, &[rel("data")], &dest, 4).unwrap();
        assert_eq!(fs::read_dir(dest.join("data")).unwrap().count(), 4);
    }

    #[test]
    fn symlink_times_survive_the_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        symlink("elsewhere", data.join("link")).unwrap();
        let time = Timespec {
            tv_sec: 1_600_000_000,
            tv_nsec: 0,
        };
        let times = Timestamps {
            last_access: time,
            last_modification: time,
        };
        let flags = AtFlags::SYMLINK_NOFOLLOW;
        utimensat(CWD, data.join("link"), &times, flags).unwrap();

        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
        assert_eq!(mtime(&dest.join("data/link")), 1_600_000_000);

        fs::remove_file(data.join("link")).unwrap();
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();
        assert_eq!(mtime(&data.join("link")), 1_600_000_000);
    }

    /// A snapshot of one symlink, where `swap` replaces the new copy of it
    /// before its metadata is set.
    fn snapshot_with_new_symlink_swapped(
        tmp: &Path,
        swap: impl Fn(&Path) + 'static,
    ) -> Result<(), SafeFsError> {
        let compose = tmp.join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        symlink("elsewhere", data.join("link")).unwrap();

        let created = tmp.join("snap.partial/data/link");
        seam::set(move |point, name| {
            if point == seam::Point::SymlinkCreated && name == c"link" {
                fs::remove_file(&created).unwrap();
                swap(&created);
            }
        });
        let dest = tmp.join("snap");
        let result = snapshot(&root(&compose), &[rel("data")], &dest).map(|_| ());
        assert_eq!(result.is_err(), !dest.exists());
        result
    }

    /// An entry swapped in for a new symlink, here a hard link to an outside
    /// file, must not receive the symlink's owner and times.
    #[test]
    fn symlink_replaced_before_its_metadata_is_set_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let keep = outside.join("keep");

        let err = snapshot_with_new_symlink_swapped(tmp.path(), move |created| {
            fs::hard_link(&keep, created).unwrap();
        })
        .unwrap_err();

        assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
        assert_sentinel_untouched(&outside);
    }

    #[test]
    fn symlink_replaced_by_another_symlink_is_refused() {
        let tmp = tempfile::tempdir().unwrap();

        let err = snapshot_with_new_symlink_swapped(tmp.path(), |created| {
            symlink("planted", created).unwrap();
        })
        .unwrap_err();

        assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
    }

    /// A hard link to another symlink with the same target looks like the new
    /// one in every way but its link count. Only Linux: there, `link` makes a
    /// hard link to the symlink itself.
    #[cfg(target_os = "linux")]
    #[test]
    fn symlink_replaced_by_a_hard_link_to_a_symlink_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let other = tmp.path().join("other");
        symlink("elsewhere", &other).unwrap();

        let err = snapshot_with_new_symlink_swapped(tmp.path(), move |created| {
            fs::hard_link(&other, created).unwrap();
        })
        .unwrap_err();

        assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
    }

    #[cfg(target_os = "linux")]
    const FOREIGN_UID: u32 = 1234;
    #[cfg(target_os = "linux")]
    const FOREIGN_GID: u32 = 2345;

    /// Whether this test can run: it needs root. Where root is required, as
    /// it is in CI, not having it is a failure.
    #[cfg(target_os = "linux")]
    #[expect(
        clippy::print_stderr,
        reason = "a test skipped for lack of privileges has to say so; libtest has no runtime skip"
    )]
    fn can_chown(test: &str) -> bool {
        let root = rustix::process::geteuid().is_root();
        if !root {
            assert!(
                std::env::var_os("LANDFALL_TEST_REQUIRE_ROOT").is_none(),
                "{test} must run as root here"
            );
            eprintln!("{test}: skipped, it needs root to give a file another owner");
        }
        root
    }

    #[cfg(target_os = "linux")]
    fn owner(path: &Path) -> (u32, u32) {
        let seen = fs::symlink_metadata(path).unwrap();
        (seen.uid(), seen.gid())
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_owner_survives_the_round_trip() {
        use std::os::unix::fs::{chown, lchown};

        if !can_chown("foreign_owner_survives_the_round_trip") {
            return;
        }
        let foreign = (FOREIGN_UID, FOREIGN_GID);
        let ids = (Some(FOREIGN_UID), Some(FOREIGN_GID));
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        let (file, tool, link) = (data.join("file"), data.join("tool"), data.join("link"));
        write(&file, b"x", 0o640);
        write(&tool, b"x", 0o644);
        symlink("elsewhere", &link).unwrap();
        chown(&file, ids.0, ids.1).unwrap();
        chown(&tool, ids.0, ids.1).unwrap();
        lchown(&link, ids.0, ids.1).unwrap();
        chown(&data, ids.0, ids.1).unwrap();
        // After the `chown`, which would clear it.
        fs::set_permissions(&tool, Permissions::from_mode(0o4755)).unwrap();

        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
        for name in ["data", "data/file", "data/tool", "data/link"] {
            assert_eq!(owner(&dest.join(name)), foreign, "{name}");
        }
        assert_eq!(mode(&dest.join("data/tool")), 0o4755);

        fs::remove_dir_all(&data).unwrap();
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();
        for path in [&data, &file, &tool, &link] {
            assert_eq!(owner(path), foreign, "{path:?}");
        }
        assert_eq!(mode(&tool), 0o4755);
        assert_eq!(fs::read_link(&link).unwrap(), Path::new("elsewhere"));
    }

    /// With a foreign owner to hand on, a swapped-in entry receiving it would
    /// show: this is what makes the owner check of the sentinel able to fail.
    #[cfg(target_os = "linux")]
    #[test]
    fn foreign_owner_does_not_reach_an_entry_swapped_in() {
        use std::os::unix::fs::lchown;

        if !can_chown("foreign_owner_does_not_reach_an_entry_swapped_in") {
            return;
        }
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        let link = data.join("link");
        symlink("elsewhere", &link).unwrap();
        lchown(&link, Some(FOREIGN_UID), Some(FOREIGN_GID)).unwrap();

        let created = tmp.path().join("snap.partial/data/link");
        let keep = outside.join("keep");
        seam::set(move |point, name| {
            if point == seam::Point::SymlinkCreated && name == c"link" {
                fs::remove_file(&created).unwrap();
                fs::hard_link(&keep, &created).unwrap();
            }
        });
        let result = snapshot(&root(&compose), &[rel("data")], &tmp.path().join("snap"));

        assert_sentinel_untouched(&outside);
        let err = result.unwrap_err();
        assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
    }

    /// Only Linux: other filesystems, like APFS, refuse such a name.
    #[cfg(target_os = "linux")]
    #[test]
    fn non_utf8_names_round_trip() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;

        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        let name = OsStr::from_bytes(b"caf\xe9");
        write(&data.join(name), b"content", 0o644);

        let dest = tmp.path().join("snap");
        snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
        assert_eq!(fs::read(dest.join("data").join(name)).unwrap(), b"content");

        fs::remove_file(data.join(name)).unwrap();
        restore(&dest, &root(&compose), &[rel("data")]).unwrap();
        assert_eq!(fs::read(data.join(name)).unwrap(), b"content");
    }

    #[test]
    fn tree_deeper_than_the_limit_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let mut deep = compose.clone();
        for _ in 0..=MAX_DEPTH {
            deep.push("d");
        }
        fs::create_dir_all(&deep).unwrap();

        let dest = tmp.path().join("snap");
        let err = snapshot(&root(&compose), &[rel("d")], &dest).unwrap_err();
        assert!(matches!(err, SafeFsError::TooDeep { .. }), "{err}");
        assert!(!dest.exists());
        assert!(!tmp.path().join("snap.partial").exists());
    }

    #[test]
    fn error_text_quotes_and_truncates_hostile_names() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        let data = compose.join("data");
        fs::create_dir_all(&data).unwrap();
        mkfifo(&data.join("evil\nline"));

        let dest = tmp.path().join("snap");
        let err = snapshot(&root(&compose), &[rel("data")], &dest).unwrap_err();
        let text = err.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.contains(r"evil\nline"), "{text}");

        let long = SafeFsError::Missing {
            path: PathBuf::from("x/".repeat(5_000)),
        };
        assert!(long.to_string().len() < 1_000);
    }

    #[test]
    fn root_escape_paths_are_rejected() {
        for bad in [
            "", "..", ".", "/etc", "a//b", "a/", "../a", "a/..", "a/../b", "./a", "a/./b", "a\0b",
        ] {
            assert!(
                matches!(RelPath::new(bad), Err(SafeFsError::InvalidPath { .. })),
                "{bad:?}"
            );
        }
        let too_deep = vec!["d"; MAX_DEPTH + 1].join("/");
        assert!(RelPath::new(&too_deep).is_err());
        assert!(RelPath::new("a/b.c/..d").is_ok());
    }

    #[test]
    fn root_must_be_an_absolute_real_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("dir");
        mkdir(&dir, 0o755);
        symlink(&dir, tmp.path().join("link")).unwrap();

        assert!(matches!(
            Root::open(Path::new("relative")),
            Err(SafeFsError::NotAbsolute { .. })
        ));
        assert!(matches!(
            Root::open(&tmp.path().join("link")),
            Err(SafeFsError::NotADirectory { .. })
        ));
        assert!(matches!(
            Root::open(&tmp.path().join("absent")),
            Err(SafeFsError::Missing { .. })
        ));
    }

    #[test]
    fn write_atomic_replaces_but_refuses_symlink_temp() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        let compose_root = root(&compose);
        let target = compose.join("override.yaml");
        let name = rel("override.yaml");

        write_atomic(&compose_root, &name, b"one", 0o640).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"one");
        assert_eq!(mode(&target), 0o640);
        write_atomic(&compose_root, &name, b"two", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"two");
        assert_eq!(mode(&target), 0o600);
        assert_eq!(fs::read_dir(&compose).unwrap().count(), 1);

        let leftover = compose.join(temp_name(c"override.yaml").unwrap().to_str().unwrap());
        symlink(outside.join("keep"), &leftover).unwrap();
        let err = write_atomic(&compose_root, &name, b"three", 0o644).unwrap_err();
        assert!(matches!(err, SafeFsError::AlreadyExists { .. }), "{err}");
        assert_sentinel_untouched(&outside);
        assert_eq!(fs::read(&target).unwrap(), b"two");
        fs::remove_file(&leftover).unwrap();

        // What a crash leaves behind does not block the next write.
        write(&leftover, b"partial", 0o600);
        write_atomic(&compose_root, &name, b"four", 0o644).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"four");
        assert!(!leftover.exists());
    }

    #[test]
    fn write_atomic_replaces_a_symlink_without_following_it() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        symlink(outside.join("keep"), compose.join("override.yaml")).unwrap();

        write_atomic(&root(&compose), &rel("override.yaml"), b"new", 0o644).unwrap();

        assert_sentinel_untouched(&outside);
        assert!(
            fs::symlink_metadata(compose.join("override.yaml"))
                .unwrap()
                .is_file()
        );
    }

    #[test]
    fn write_atomic_refuses_a_symlinked_parent_and_set_id_modes() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        symlink(&outside, compose.join("data")).unwrap();
        let compose_root = root(&compose);

        let err = write_atomic(&compose_root, &rel("data/new"), b"x", 0o644).unwrap_err();
        assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
        assert_sentinel_untouched(&outside);

        let err = write_atomic(&compose_root, &rel("file"), b"x", 0o4755).unwrap_err();
        assert!(matches!(err, SafeFsError::InvalidMode { .. }), "{err}");
        assert!(!compose.join("file").exists());
    }

    #[test]
    fn read_file_refuses_symlink() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        symlink(outside.join("keep"), compose.join("link")).unwrap();
        symlink(&outside, compose.join("dirlink")).unwrap();
        let compose_root = root(&compose);

        let err = read_file(&compose_root, &rel("link"), 1024).unwrap_err();
        assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
        let err = read_file(&compose_root, &rel("dirlink/keep"), 1024).unwrap_err();
        assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
    }

    #[test]
    fn read_file_returns_content_none_when_absent_and_enforces_the_cap() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        write(&compose.join("file"), b"12345", 0o644);
        let compose_root = root(&compose);

        let content = read_file(&compose_root, &rel("file"), 5).unwrap();
        assert_eq!(content.as_deref(), Some(&b"12345"[..]));
        assert_eq!(read_file(&compose_root, &rel("absent"), 5).unwrap(), None);
        assert_eq!(read_file(&compose_root, &rel("no/such"), 5).unwrap(), None);
        let err = read_file(&compose_root, &rel("file"), 4).unwrap_err();
        assert!(matches!(err, SafeFsError::TooLarge { .. }), "{err}");
    }

    /// Reads a file that `swap` replaces between `lstat` and open.
    fn read_with_swap_in_open_window(
        tmp: &Path,
        swap: impl Fn(&Path) + 'static,
    ) -> Result<Option<Vec<u8>>, SafeFsError> {
        let compose = tmp.join("compose");
        mkdir(&compose, 0o755);
        let file = compose.join("file");
        write(&file, b"ordinary", 0o644);
        seam::set(move |point, name| {
            if point == seam::Point::LstatToOpen && name == c"file" {
                fs::remove_file(&file).unwrap();
                swap(&file);
            }
        });
        read_file(&root(&compose), &rel("file"), 1024)
    }

    #[test]
    fn read_file_refuses_a_fifo_swapped_in_the_open_window() {
        let tmp = tempfile::tempdir().unwrap();
        let err = read_with_swap_in_open_window(tmp.path(), mkfifo).unwrap_err();
        assert!(matches!(err, SafeFsError::NotRegularFile { .. }), "{err}");
    }

    #[test]
    fn read_file_refuses_a_symlink_swapped_in_the_open_window() {
        let tmp = tempfile::tempdir().unwrap();
        let outside = sentinel(tmp.path());
        let keep = outside.join("keep");
        let err = read_with_swap_in_open_window(tmp.path(), move |file| {
            symlink(&keep, file).unwrap();
        })
        .unwrap_err();
        assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
    }

    #[test]
    fn read_file_of_an_entry_vanishing_in_the_open_window_is_none() {
        let tmp = tempfile::tempdir().unwrap();
        let content = read_with_swap_in_open_window(tmp.path(), |_| {}).unwrap();
        assert_eq!(content, None);
    }

    #[test]
    fn read_file_refuses_fifo_and_directory_without_blocking() {
        let tmp = tempfile::tempdir().unwrap();
        let compose = tmp.path().join("compose");
        mkdir(&compose, 0o755);
        mkfifo(&compose.join("pipe"));
        mkdir(&compose.join("dir"), 0o755);
        let compose_root = root(&compose);

        for name in ["pipe", "dir"] {
            let err = read_file(&compose_root, &rel(name), 1024).unwrap_err();
            assert!(matches!(err, SafeFsError::NotRegularFile { .. }), "{err}");
        }
    }

    #[test]
    fn prune_keeps_newest() {
        let tmp = tempfile::tempdir().unwrap();
        let backups = tmp.path().join("backups");
        mkdir(&backups, 0o700);
        for name in [
            "2026-11-01T10-00-00Z",
            "2026-11-03T10-00-00Z",
            "2026-11-02T10-00-00Z",
            "2026-10-31T10-00-00Z",
            "2026-11-04T10-00-00Z.partial",
        ] {
            fs::create_dir_all(backups.join(name).join("data/sub")).unwrap();
        }
        let outside = sentinel(tmp.path());
        symlink(&outside, backups.join("2026-10-31T10-00-00Z/data/link")).unwrap();

        prune(&backups, 2, None).unwrap();

        let mut left: Vec<_> = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["2026-11-02T10-00-00Z", "2026-11-03T10-00-00Z"]);
        assert_sentinel_untouched(&outside);

        prune(&backups, 0, None).unwrap();
        assert_eq!(fs::read_dir(&backups).unwrap().count(), 0);
    }

    #[test]
    fn prune_spares_the_backup_it_is_told_to() {
        let tmp = tempfile::tempdir().unwrap();
        let backups = tmp.path().join("backups");
        mkdir(&backups, 0o700);
        for name in [
            "2026-11-01T00-00-00Z",
            "2026-11-02T00-00-00Z",
            "2026-11-03T00-00-00Z",
        ] {
            fs::create_dir(backups.join(name)).unwrap();
        }

        prune(&backups, 1, Some("2026-11-01T00-00-00Z")).unwrap();

        let mut left: Vec<_> = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["2026-11-01T00-00-00Z", "2026-11-03T00-00-00Z"]);
    }

    #[test]
    fn prune_of_an_absent_directory_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        prune(&tmp.path().join("absent"), 3, None).unwrap();
    }
}
