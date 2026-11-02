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

use rustix::fs::OFlags;

mod copy;
mod error;
mod files;
mod paths;
mod removal;
#[cfg(test)]
mod seam;
mod snapshot;
#[cfg(test)]
mod tests;

pub use error::SafeFsError;
pub use files::{read_file, write_atomic};
pub use paths::{RelPath, Root};
pub use removal::prune;
pub use snapshot::{SnapshotStats, restore, snapshot};

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
