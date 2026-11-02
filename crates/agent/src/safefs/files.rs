//! Reading and atomically writing one file.

use std::ffi::{CStr, CString};
use std::fs::File;
use std::io::{Read, Write};
use std::os::fd::{AsFd, BorrowedFd, OwnedFd};
use std::path::Path;

use rustix::fs::{
    AtFlags, FileType, Mode, RawMode, fchmod, fstat, fsync, openat, renameat, statat, unlinkat,
};
use rustix::io::Errno;

use super::copy::fit;
use super::error::{file_io_err, io_err, name_path, with_cleanup};
#[cfg(test)]
use super::seam;
use super::{CREATE_FILE, OPEN_ANY, RACE_ATTEMPTS, RelPath, Root, SafeFsError, TEMP_SUFFIX};

/// The name of the temporary file [`write_atomic`] uses beside `name`. It is
/// fixed, not random, so a crash leaves one leftover to clear, not many.
pub(super) fn temp_name(name: &CStr) -> Result<CString, SafeFsError> {
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
pub(super) fn remove_file(
    parent: BorrowedFd<'_>,
    name: &CStr,
    path: &Path,
) -> Result<(), SafeFsError> {
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
