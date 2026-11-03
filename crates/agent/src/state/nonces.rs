//! The nonces of the approvals this host has run: what makes an approval work once.
//!
//! One file for the whole state directory, so a nonce is spent on this host, whatever
//! deployment it was for. One line per nonce, 64 lowercase hex digits and a newline,
//! appended and `fsync`ed before a deploy starts, so a crash can't reuse one. Only
//! an approval that verified is written here, so what grows this takes a person with a
//! passkey, and a compromised controller can neither fill it nor burn a real approval.
//!
//! Nothing here reads as empty when it can't be trusted: a log that is torn, malformed,
//! full, or not a private regular file is an error, and is left as it is
//! for the operator. A crash in the middle of an append leaves a torn last line. The
//! deploy it was for never started, since a deploy waits for the `fsync`, so the partial
//! line can safely be removed by hand, which `docs/operations.md` says how to do. Doing it
//! here would make a log damaged some other way look like one that crashed.
//!
//! Each call reads the file again rather than keeping it in memory, and takes the
//! file's own lock for that, so two processes can't both spend one nonce. It reads one
//! line at a time, so the size of the log takes no memory.
//!
//! Neither call blocks on that lock. Nothing but the daemon uses it, so only something run by
//! hand can hold it, for as long as it likes, and a thread blocked there would hold on to the
//! deployment's lock when it is spending. So a call tries for [`LOCK_PATIENCE`], and then says
//! [`StateError::NonceLogBusy`], and the work waits for the next poll with nothing spent. The
//! patience is for the daemon's own threads, which have the log for as long as a spend takes. A
//! child forked in another thread shares this descriptor until it execs, so the lock is let go by
//! [`HeldLog`] and not by closing the file, which would wait for that child.

use std::fs::{File, TryLockError};
use std::io::{BufReader, Read as _, Write};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use rustix::fs::{Mode, OFlags};
use rustix::io::Errno;

use super::deployment::sync_dir;
use super::error::io_err;
use super::{NONCE_LOG, StateDir, StateError};

/// The bytes of one line.
const LINE_BYTES: usize = 65;

/// The longest the log gets: a million approvals, or 27 a day for a hundred years. At this
/// length it refuses, and an approval is what it refuses, so no line goes past it.
pub const MAX_NONCE_LOG_BYTES: u64 = 65_000_000;

/// How long a call goes on trying for the log's lock. It is the longest a spending thread can be
/// kept from answering by a lock it can't have.
const LOCK_PATIENCE: Duration = Duration::from_secs(1);
/// How long between tries.
const LOCK_RETRY: Duration = Duration::from_millis(5);

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

/// The log, with a lock on it that's let go when this is dropped.
#[derive(Debug)]
pub(super) struct HeldLog(File);

impl Drop for HeldLog {
    /// If this fails, closing the file is still what frees it.
    fn drop(&mut self) {
        drop(self.0.unlock());
    }
}

/// Tries for a lock on the log, for [`LOCK_PATIENCE`] at most.
pub(super) fn locked(
    file: File,
    attempt: impl Fn(&File) -> Result<(), TryLockError>,
    path: &Path,
) -> Result<HeldLog, StateError> {
    let started = Instant::now();
    loop {
        match attempt(&file) {
            Ok(()) => return Ok(HeldLog(file)),
            Err(TryLockError::Error(error)) => return Err(io_err("lock", path)(error)),
            Err(TryLockError::WouldBlock) if started.elapsed() >= LOCK_PATIENCE => {
                return Err(StateError::NonceLogBusy(path.to_owned()));
            }
            Err(TryLockError::WouldBlock) => std::thread::sleep(LOCK_RETRY),
        }
    }
}

/// Reads the whole log from its start, refusing it if any of it isn't what the log
/// holds, and hands `each` the digits of every line.
fn read_lines(file: &File, path: &Path, mut each: impl FnMut(&[u8])) -> Result<(), StateError> {
    let len = file.metadata().map_err(io_err("inspect", path))?.len();
    if len >= MAX_NONCE_LOG_BYTES {
        return Err(unusable(
            path,
            format!("it is {len} bytes, and it is full at {MAX_NONCE_LOG_BYTES}"),
        ));
    }
    if len % LINE_BYTES as u64 != 0 {
        return Err(unusable(
            path,
            format!("it is {len} bytes, which isn't whole lines: its last line is torn"),
        ));
    }
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
        each(digits);
    }
    Ok(())
}

/// Reads the whole log as [`read_lines`] does, and says whether `nonce` is in it.
fn scan(file: &File, path: &Path, nonce: &[u8; 32]) -> Result<bool, StateError> {
    let wanted = hex::encode(nonce);
    let mut found = false;
    read_lines(file, path, |digits| found |= digits == wanted.as_bytes())?;
    Ok(found)
}

/// The log, with a lock on it to read. `None` if it isn't there.
fn open_to_read(path: &Path) -> Result<Option<HeldLog>, StateError> {
    let Some(file) = open(path, OFlags::RDONLY)? else {
        return Ok(None);
    };
    locked(file, File::try_lock_shared, path).map(Some)
}

/// Writes `line` through `out`, which ends up in `file`. Called under the file's lock. A
/// write that fails, on a full disk say, can leave part of the line, which would refuse
/// every approval until someone repaired it by hand, so the file goes back to the length
/// it had. Nothing else writes to it meanwhile. If that fails too, the partial line stays,
/// and the log refuses, as for a crash.
pub(super) fn append_line(
    file: &File,
    out: &mut impl Write,
    line: &[u8],
    path: &Path,
) -> Result<(), StateError> {
    let prior = file.metadata().map_err(io_err("inspect", path))?.len();
    let Err(failed) = out.write_all(line) else {
        return Ok(());
    };
    match file.set_len(prior) {
        Ok(()) => Err(io_err("write", path)(failed)),
        Err(truncate) => Err(unusable(
            path,
            format!(
                "writing to it failed: {failed}, and so did taking back what was written: {truncate}"
            ),
        )),
    }
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
    /// [`StateError`] if the log can't be read or can't be trusted, and
    /// [`StateError::NonceLogBusy`] if something holds its lock to write.
    pub fn nonce_used(&self, nonce: &[u8; 32]) -> Result<bool, StateError> {
        let path = self.nonce_log_path();
        let Some(log) = open_to_read(&path)? else {
            return Ok(false);
        };
        scan(&log.0, &path, nonce)
    }

    /// Reads the log and says if it can be trusted. No log can be.
    ///
    /// # Errors
    ///
    /// [`StateError`] if it can't, and [`StateError::NonceLogBusy`] if something holds its lock
    /// to write.
    pub fn check_nonce_log(&self) -> Result<(), StateError> {
        let path = self.nonce_log_path();
        match open_to_read(&path)? {
            Some(log) => read_lines(&log.0, &path, |_| {}),
            None => Ok(()),
        }
    }

    /// Spends `nonce`: refuses it if it was spent, and otherwise appends it, and it is
    /// on disk, directory entry included, when this returns. The check and the append
    /// are one step under the file's lock.
    ///
    /// After an error, the nonce may or may not be on disk. Nothing may run on it.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the log can't be read, can't be trusted or can't be written, and
    /// [`StateError::NonceLogBusy`] if something holds its lock, with nothing written.
    pub fn spend_nonce(&self, nonce: &[u8; 32]) -> Result<NonceSpend, StateError> {
        let path = self.nonce_log_path();
        let flags = OFlags::RDWR | OFlags::APPEND | OFlags::CREATE;
        let Some(file) = open(&path, flags)? else {
            return Err(unusable(&path, "it isn't there after creating it"));
        };
        let log = locked(file, File::try_lock, &path)?;
        let file = &log.0;
        if scan(file, &path, nonce)? {
            return Ok(NonceSpend::AlreadyUsed);
        }
        let line = format!("{}\n", hex::encode(nonce));
        let mut out = file;
        append_line(file, &mut out, line.as_bytes(), &path)?;
        file.sync_all().map_err(io_err("sync", &path))?;
        sync_dir(self.path())?;
        Ok(NonceSpend::Recorded)
    }
}
