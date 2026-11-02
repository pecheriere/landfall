//! Copying a tree, entry by entry, with its metadata.

use std::collections::BTreeMap;
use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::{Path, PathBuf};

use rustix::fs::{
    AtFlags, FileType, Gid, Mode, Stat, Timespec, Timestamps, Uid, chownat, fchmod, fchown, fstat,
    fsync, futimens, mkdirat, openat, readlinkat, statat, symlinkat, utimensat,
};
use rustix::io::Errno;

use super::error::{entry_err, file_io_err, io_err, name_path, walk_err};
use super::paths::{open_dir, walk};
use super::removal::{Removal, ensure_real_dir, read_all_names, remove_entry};
#[cfg(test)]
use super::seam;
use super::{
    COPY_BUFFER, CREATE_FILE, MAX_DEPTH, OPEN_ANY, RelPath, Root, SafeFsError, SnapshotStats,
};

/// Copies each path, with its parents, from `source` to below `dst`. Shared
/// by snapshot (into a fresh directory) and restore (into a hostile one).
pub(super) fn copy_paths(
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
pub(super) fn fit<T, U: TryFrom<T> + Default>(value: T) -> U {
    U::try_from(value).unwrap_or_default()
}
