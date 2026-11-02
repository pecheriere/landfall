//! Running a command in a process group of its own, with a timeout and capped output.

use std::future::Future;
use std::io;
use std::ops::{Deref, DerefMut};
use std::process::ExitStatus;
use std::time::Duration;

use rustix::process::{Pid, Signal, kill_process_group};
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

use super::{DockerError, KILL_WAIT, READ_CHUNK};

/// The command line of `cmd` as an operator can type it, for an error that
/// withholds the output. It is printed, so it holds nothing that comes from
/// the stack's configuration: an argument with characters no flag or validated
/// name has, and the project name, which compose interpolates, are shown as
/// placeholders.
pub(super) fn shown_argv(cmd: &Command) -> String {
    let mut shown = String::from("docker");
    let mut after_project = false;
    for arg in cmd.as_std().get_args() {
        let plain = arg.to_str().filter(|arg| {
            !arg.is_empty()
                && arg
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b':'))
        });
        shown.push(' ');
        match plain {
            _ if after_project => shown.push_str("<project>"),
            Some(arg) => shown.push_str(arg),
            None => shown.push_str("<value>"),
        }
        after_project = arg == "-p";
    }
    shown
}

/// A running command. Dropping it before it has been reaped, which is what
/// dropping a call's future does, kills its whole process group: `kill_on_drop`
/// only reaches the direct child.
pub(super) struct GroupChild(Child);

impl GroupChild {
    fn group(&self) -> Option<Pid> {
        // `id` is `None` once the child has been reaped. Until then its pid,
        // which is also the group's id, cannot have been reused.
        self.0
            .id()
            .and_then(|pid| i32::try_from(pid).ok())
            .and_then(Pid::from_raw)
    }

    fn kill_group(&self) {
        if let Some(group) = self.group() {
            // The group may be gone already.
            let _ = kill_process_group(group, Signal::KILL);
        }
    }
}

impl Drop for GroupChild {
    fn drop(&mut self) {
        self.kill_group();
    }
}

impl Deref for GroupChild {
    type Target = Child;

    fn deref(&self) -> &Child {
        &self.0
    }
}

impl DerefMut for GroupChild {
    fn deref_mut(&mut self) -> &mut Child {
        &mut self.0
    }
}

/// Kills the child's whole process group and waits, for a few seconds, for
/// the child to be gone.
pub(super) async fn kill_group(
    label: &'static str,
    child: &mut GroupChild,
) -> Result<(), DockerError> {
    child.kill_group();
    // Covers a child that was not (or no longer) the leader of a group.
    let _ = child.start_kill();
    await_killed(label, child.wait(), KILL_WAIT).await
}

/// Waits for a killed command to be gone. A process stuck in the kernel does
/// not go, however it is killed, and the caller must not wait for it forever.
pub(super) async fn await_killed<T>(
    label: &'static str,
    exit: impl Future<Output = T>,
    limit: Duration,
) -> Result<(), DockerError> {
    match tokio::time::timeout(limit, exit).await {
        Ok(_) => Ok(()),
        Err(_) => Err(DockerError::Unkillable { command: label }),
    }
}

pub(super) fn spawn(label: &'static str, cmd: &mut Command) -> Result<GroupChild, DockerError> {
    cmd.spawn()
        .map(GroupChild)
        .map_err(|source| DockerError::Spawn {
            command: label,
            source,
        })
}

/// Refuses a name or reference that a client could read as a flag.
pub(super) fn not_a_flag(label: &'static str, value: &str) -> Result<(), DockerError> {
    if value.is_empty() || value.starts_with('-') {
        Err(DockerError::BadArgument {
            command: label,
            reason: "empty or starting with '-'",
        })
    } else {
        Ok(())
    }
}

pub(super) struct Captured {
    pub(super) status: ExitStatus,
    pub(super) stdout: Vec<u8>,
    pub(super) stderr_tail: Vec<u8>,
}

pub(super) enum ReadError {
    TooMuch,
    Io(io::Error),
}

/// Reads `reader` to its end, refusing more than `cap` bytes.
pub(super) async fn read_capped<R: AsyncRead + Unpin>(
    reader: Option<R>,
    cap: usize,
) -> Result<Vec<u8>, ReadError> {
    let Some(mut reader) = reader else {
        return Ok(Vec::new());
    };
    let mut out = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let n = reader.read(&mut chunk).await.map_err(ReadError::Io)?;
        if n == 0 {
            return Ok(out);
        }
        if out.len() + n > cap {
            return Err(ReadError::TooMuch);
        }
        out.extend_from_slice(&chunk[..n]);
    }
}

/// Reads `reader` to its end, keeping only the last `keep` bytes.
pub(super) async fn read_tail<R: AsyncRead + Unpin>(
    reader: Option<R>,
    keep: usize,
) -> Result<Vec<u8>, ReadError> {
    let Some(mut reader) = reader else {
        return Ok(Vec::new());
    };
    let mut tail: Vec<u8> = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let n = reader.read(&mut chunk).await.map_err(ReadError::Io)?;
        if n == 0 {
            return Ok(tail);
        }
        tail.extend_from_slice(&chunk[..n]);
        if tail.len() > keep {
            tail.drain(..tail.len() - keep);
        }
    }
}
