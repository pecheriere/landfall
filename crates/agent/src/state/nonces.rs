//! The nonces of the approvals this host has run: what makes an approval work once.
//!
//! One file for the whole state directory, so a nonce is spent on this host, whatever
//! deployment it was for. One line per nonce, 64 lowercase hex digits and a newline,
//! appended and `fsync`ed before a deploy starts, so a crash can't reuse one. Only
//! an approval that verified is written here, so what grows this takes a person with a
//! passkey, and a compromised controller can neither fill it nor burn a real approval.
//!
//! Nothing here reads as empty when it can't be trusted: a log that is torn, malformed,
//! past its bound, or not a private regular file is an error, and is left as it is
//! for the operator. A crash in the middle of an append leaves a torn last line. The
//! deploy it was for never started, since a deploy waits for the `fsync`, so the partial
//! line can safely be removed by hand, which `docs/operations.md` says how to do. Doing it
//! here would make a log damaged some other way look like one that crashed.
//!
//! Each call reads the file again rather than keeping it in memory, and takes the
//! file's own lock for that, so two processes can't both spend one nonce. It reads one
//! line at a time, so the size of the log takes no memory.

use std::fs::File;
use std::io::{BufReader, Read as _, Write as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::deployment::sync_dir;
use super::error::io_err;
use super::{NONCE_LOG, StateDir, StateError};

/// The bytes of one line.
const LINE_BYTES: usize = 65;

/// The longest the log may be: a million approvals, or 27 a day for a hundred years. Past
/// this it refuses, and an approval is what it refuses.
pub const MAX_NONCE_LOG_BYTES: u64 = 65_000_000;

/// What [`StateDir::spend_nonce`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[must_use]
pub enum NonceSpend {
    /// It wasn't in the log, and now it is, on disk.
    Recorded,
    /// It was in the log already. Nothing was written.
    AlreadyUsed,
}

fn unusable(path: &Path, reason: impl Into<String>) -> StateError {
    StateError::NonceLog {
        path: path.to_owned(),
        reason: reason.into(),
    }
}

/// Opens the log without following a symlink, and checks that it is a regular file
/// only the agent's user can change. `None` if it isn't there.
fn open(path: &Path, flags: OFlags) -> Result<Option<File>, StateError> {
    // Not blocking: on a FIFO in the log's place, a plain open would wait for a writer.
    let flags = flags | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK;
    let file = match rustix::fs::open(path, flags, Mode::RUSR | Mode::WUSR) {
        Ok(fd) => File::from(fd),
        Err(Errno::NOENT) => return Ok(None),
        Err(errno) => return Err(io_err("open", path)(errno.into())),
    };
    let meta = file.metadata().map_err(io_err("inspect", path))?;
    if !meta.is_file() {
        return Err(unusable(path, "it isn't a regular file"));
    }
    let agent = rustix::process::geteuid().as_raw();
    if meta.uid() != agent {
        return Err(StateError::WrongOwner {
            path: path.to_owned(),
            owner: meta.uid(),
            agent,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(StateError::Writable {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(Some(file))
}

/// Reads the whole log from its start, refusing it if any of it isn't what the log
/// holds, and says whether `nonce` is in it.
fn scan(file: &File, path: &Path, nonce: &[u8; 32]) -> Result<bool, StateError> {
    let len = file.metadata().map_err(io_err("inspect", path))?.len();
    if len > MAX_NONCE_LOG_BYTES {
        return Err(unusable(
            path,
            format!("it is {len} bytes, past its bound of {MAX_NONCE_LOG_BYTES}"),
        ));
    }
    if len % LINE_BYTES as u64 != 0 {
        return Err(unusable(
            path,
            format!("it is {len} bytes, which isn't whole lines: its last line is torn"),
        ));
    }
    let wanted = hex::encode(nonce);
    let mut found = false;
    let mut reader = BufReader::new(file);
    let mut line = [0_u8; LINE_BYTES];
    for number in 1..=len / LINE_BYTES as u64 {
        reader.read_exact(&mut line).map_err(io_err("read", path))?;
        let (digits, end) = line.split_at(LINE_BYTES - 1);
        let is_hex = digits
            .iter()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
        if !is_hex || end != b"\n" {
            return Err(unusable(path, format!("line {number} isn't a nonce")));
        }
        found |= digits == wanted.as_bytes();
    }
    Ok(found)
}

impl StateDir {
    /// Where the log is.
    #[must_use]
    pub fn nonce_log_path(&self) -> PathBuf {
        self.path().join(NONCE_LOG)
    }

    /// Whether `nonce` has been spent. No log means none has.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the log can't be read or can't be trusted.
    pub fn nonce_used(&self, nonce: &[u8; 32]) -> Result<bool, StateError> {
        let path = self.nonce_log_path();
        let Some(file) = open(&path, OFlags::RDONLY)? else {
            return Ok(false);
        };
        file.lock_shared().map_err(io_err("lock", &path))?;
        scan(&file, &path, nonce)
    }

    /// Reads the log and says if it can be trusted.
    ///
    /// # Errors
    ///
    /// [`StateError`] if it can't.
    pub fn check_nonce_log(&self) -> Result<(), StateError> {
        self.nonce_used(&[0; 32]).map(|_| ())
    }

    /// Spends `nonce`: refuses it if it was spent, and otherwise appends it, and it is
    /// on disk, directory entry included, when this returns. The check and the append
    /// are one step under the file's lock.
    ///
    /// After an error, the nonce may or may not be on disk, and the line may be torn.
    /// Nothing may run on it.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the log can't be read, can't be trusted or can't be written.
    pub fn spend_nonce(&self, nonce: &[u8; 32]) -> Result<NonceSpend, StateError> {
        let path = self.nonce_log_path();
        let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE;
        let Some(mut file) = open(&path, flags)? else {
            return Err(unusable(&path, "it isn't there after creating it"));
        };
        file.lock().map_err(io_err("lock", &path))?;
        if scan(&file, &path, nonce)? {
            return Ok(NonceSpend::AlreadyUsed);
        }
        let line = format!("{}\n", hex::encode(nonce));
        file.write_all(line.as_bytes())
            .map_err(io_err("write", &path))?;
        file.sync_all().map_err(io_err("sync", &path))?;
        sync_dir(self.path())?;
        Ok(NonceSpend::Recorded)
    }
}
