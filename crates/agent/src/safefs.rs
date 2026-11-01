//! Every filesystem operation in a directory a container can write to.
//!
//! The agent is root-equivalent, and a hostile container can plant symlinks,
//! FIFOs or devices, or swap a path for one of them at any moment. So nothing
//! here checks a path and then opens it. Each component is opened relative to
//! its parent's file descriptor with `O_NOFOLLOW`, and what to do is decided
//! from the descriptor (`fstat`), so a swap makes an open fail rather than
//! lead outside the tree. An earlier `lstat` only avoids opening a device or
//! socket at all, since opening one can have side effects.
//!
//! Symlinks are copied as symlinks and never followed. Devices, sockets and
//! FIFOs are refused, naming the path. Hard links become separate files.
//!
//! New entries stay private to the agent (`0600`, `0700`) while they fill up.
//! Their metadata is applied afterwards on the descriptor, in this order:
//! owner, then mode, then times. `chown` clears set-uid and set-gid, so those
//! bits are only ever set after it has succeeded, and a failed `chown` is an
//! error that leaves them unset. The kernel can also drop set-gid without an
//! error, so the mode is read back and a difference is an error too.
//!
//! The limits a hostile tree could otherwise exploit: recursion stops at
//! [`MAX_DEPTH`] with a typed error, only the chain of parent directories
//! stays open, and data moves through one fixed buffer, never allocated from
//! a size the container controls.

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

/// How deep a tree may go below its root. Past this a walk stops with
/// [`SafeFsError::TooDeep`], so a deep tree can neither overflow the stack
/// nor use up file descriptors.
pub const MAX_DEPTH: usize = 256;

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
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
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
/// [`SafeFsError::OverlappingPaths`] when one path contains another,
/// [`SafeFsError::AlreadyExists`] when `dest` exists, and [`SafeFsError::Io`].
pub fn snapshot(
    source: &Root,
    paths: &[RelPath],
    dest: &Path,
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
    remove_entry(parent.as_fd(), &partial_name, &partial_path, 0)?;
    mkdirat(&parent, &partial_name, Mode::RWXU).map_err(io_err("create", &partial_path))?;

    let copied = open_dir(parent.as_fd(), &partial_name)
        .map_err(walk_err(&partial_path))
        .and_then(|partial| {
            let stats = copy_paths(source, partial.as_fd(), &partial_path, paths, Removal::None)?;
            renameat(&parent, &partial_name, &parent, &dest_name)
                .map_err(io_err("rename to", dest))?;
            Ok(stats)
        });
    let stats = copied.map_err(|err| {
        let cleanup = remove_entry(parent.as_fd(), &partial_name, &partial_path, 0);
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
/// Nothing is removed unless the snapshot holds every path.
///
/// # Errors
///
/// [`SafeFsError::Missing`] when the snapshot lacks a path,
/// [`SafeFsError::TooDeep`] when what is to be removed goes past
/// [`MAX_DEPTH`], [`SafeFsError::OverlappingPaths`] when one path contains
/// another, and [`SafeFsError::Io`]. A failure part-way leaves the paths
/// already restored in place and the rest removed or as they were.
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
/// [`SafeFsError::TooDeep`] and [`SafeFsError::Io`], from reading `backups`
/// or removing an entry.
pub fn prune(backups: &Path, keep: usize) -> Result<(), SafeFsError> {
    let root = match Root::open(backups) {
        Ok(root) => root,
        Err(SafeFsError::Missing { .. }) => return Ok(()),
        Err(err) => return Err(err),
    };
    let mut complete = Vec::new();
    for name in read_names(root.fd.as_fd(), backups)? {
        let path = backups.join(name_path(&name));
        if name.as_bytes().ends_with(PARTIAL_SUFFIX) {
            remove_entry(root.fd.as_fd(), &name, &path, 0)?;
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
        let path = backups.join(name_path(name));
        remove_entry(root.fd.as_fd(), name, &path, 0)?;
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

/// Reads a directory's entry names, closing its stream before returning so
/// that a walk only ever holds its chain of parents. Reading first also keeps
/// a removal from changing the directory under its own stream.
fn read_names(dir: BorrowedFd<'_>, path: &Path) -> Result<Vec<CString>, SafeFsError> {
    let mut names = Vec::new();
    for entry in Dir::read_from(dir).map_err(io_err("list", path))? {
        let entry = entry.map_err(io_err("list", path))?;
        let name = entry.file_name();
        if name != c"." && name != c".." {
            names.push(name.to_owned());
        }
    }
    Ok(names)
}

/// Removes whatever `name` is, without following it. An absent entry is fine.
/// `depth` counts from where the removal started.
///
/// A directory swapped for a symlink mid-walk fails the open, and the symlink
/// is what gets removed. One swapped the other way fails the `unlinkat`.
fn remove_entry(
    parent: BorrowedFd<'_>,
    name: &CStr,
    path: &Path,
    depth: usize,
) -> Result<(), SafeFsError> {
    match open_dir(parent, name) {
        Ok(dir) => {
            if depth > MAX_DEPTH {
                return Err(SafeFsError::TooDeep {
                    path: path.to_owned(),
                    limit: MAX_DEPTH,
                });
            }
            for child in read_names(dir.as_fd(), path)? {
                let child_path = path.join(name_path(&child));
                remove_entry(dir.as_fd(), &child, &child_path, depth + 1)?;
            }
            drop(dir);
            match unlinkat(parent, name, AtFlags::REMOVEDIR) {
                Ok(()) | Err(Errno::NOENT) => Ok(()),
                Err(errno) => Err(io_err("remove directory", path)(errno)),
            }
        }
        Err(Errno::NOENT) => Ok(()),
        Err(Errno::NOTDIR | Errno::LOOP) => remove_file(parent, name, path),
        Err(errno) => Err(io_err("open directory", path)(errno)),
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
) -> Result<SnapshotStats, SafeFsError> {
    let mut copier = Copier {
        src_label: &source.path,
        dst_label,
        buf: vec![0; COPY_BUFFER],
        stats: SnapshotStats::default(),
    };
    // Parents created here get their metadata last: creating an entry would
    // change a directory's time, and a restrictive mode could block the next.
    let mut created: BTreeMap<&[CString], Stat> = BTreeMap::new();
    for path in paths {
        let (src_parent, dst_parent) =
            copier.descend(source.fd.as_fd(), dst, path, &mut created)?;
        if removal == Removal::First {
            let label = dst_label.join(path.as_path());
            remove_entry(dst_parent.as_fd(), &path.name, &label, path.depth())?;
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
/// through, and what has been copied so far.
struct Copier<'a> {
    src_label: &'a Path,
    dst_label: &'a Path,
    buf: Vec<u8>,
    stats: SnapshotStats,
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
        let seen =
            statat(src_parent, name, AtFlags::SYMLINK_NOFOLLOW).map_err(|errno| match errno {
                Errno::NOENT => SafeFsError::Missing {
                    path: src_path.clone(),
                },
                other => io_err("inspect", &src_path)(other),
            })?;
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
        let fd =
            openat(src_parent, name, OPEN_ANY, Mode::empty()).map_err(io_err("open", &src_path))?;
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
        for child in read_names(src.as_fd(), &src_path)? {
            let child_rel = rel.join(name_path(&child));
            self.copy_entry(src.as_fd(), dst.as_fd(), &child, &child_rel, depth + 1)?;
        }
        apply_metadata(dst.as_fd(), stat, &dst_path)?;
        fsync(&dst).map_err(io_err("sync", &dst_path))?;
        self.stats.directories += 1;
        Ok(())
    }

    /// A symlink has no descriptor to work on, so everything here goes by
    /// name relative to the parent, with `SYMLINK_NOFOLLOW`. `readlinkat`
    /// fails if the entry is no longer a symlink.
    fn copy_symlink(
        &mut self,
        src_parent: BorrowedFd<'_>,
        dst_parent: BorrowedFd<'_>,
        name: &CStr,
        rel: &Path,
        stat: &Stat,
    ) -> Result<(), SafeFsError> {
        let (src_path, dst_path) = (self.src_label.join(rel), self.dst_label.join(rel));
        let target = readlinkat(src_parent, name, Vec::new()).map_err(io_err("read", &src_path))?;
        symlinkat(target.as_c_str(), dst_parent, name).map_err(io_err("create", &dst_path))?;
        let created = statat(dst_parent, name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(io_err("inspect", &dst_path))?;
        if created.st_uid != stat.st_uid || created.st_gid != stat.st_gid {
            chownat(
                dst_parent,
                name,
                Some(Uid::from_raw(stat.st_uid)),
                Some(Gid::from_raw(stat.st_gid)),
                AtFlags::SYMLINK_NOFOLLOW,
            )
            .map_err(io_err("set owner of", &dst_path))?;
        }
        utimensat(
            dst_parent,
            name,
            &timestamps(stat),
            AtFlags::SYMLINK_NOFOLLOW,
        )
        .map_err(io_err("set times of", &dst_path))?;
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

#[cfg(test)]
mod tests {
    use std::fs::{self, File, Permissions};
    use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};
    use std::path::{Path, PathBuf};
    use std::process::Command;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::time::{Duration, SystemTime};

    use super::{
        MAX_DEPTH, RelPath, Root, SafeFsError, prune, read_file, restore, snapshot, temp_name,
        write_atomic,
    };

    const SECRET: &[u8] = b"sentinel content, must not be copied";

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
        dir
    }

    fn assert_sentinel_untouched(dir: &Path) {
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

        prune(&backups, 2).unwrap();

        let mut left: Vec<_> = fs::read_dir(&backups)
            .unwrap()
            .map(|entry| entry.unwrap().file_name().into_string().unwrap())
            .collect();
        left.sort();
        assert_eq!(left, ["2026-11-02T10-00-00Z", "2026-11-03T10-00-00Z"]);
        assert_sentinel_untouched(&outside);

        prune(&backups, 0).unwrap();
        assert_eq!(fs::read_dir(&backups).unwrap().count(), 0);
    }

    #[test]
    fn prune_of_an_absent_directory_does_nothing() {
        let tmp = tempfile::tempdir().unwrap();
        prune(&tmp.path().join("absent"), 3).unwrap();
    }
}
