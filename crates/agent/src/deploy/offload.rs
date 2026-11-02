//! Blocking work run on a thread of its own, up to a deadline.

use std::sync::Arc;
use std::time::Duration;

use super::FileFailure;
#[cfg(test)]
use super::faults;
use crate::state::DeployLock;

/// Why blocking work given to [`on_thread_within`] has no result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Unfinished {
    /// The thread doing it panicked.
    Panicked,
    /// It ran past its deadline and may still be running.
    Deadline,
}

impl Unfinished {
    pub(super) fn failure(self, op: &'static str, after: Duration) -> FileFailure {
        match self {
            Self::Panicked => FileFailure::Panicked { op },
            Self::Deadline => FileFailure::Deadline { op, after },
        }
    }
}

/// Runs blocking work on a thread, waiting for it up to `deadline`. A thread
/// cannot be cancelled, so past the deadline the work may still be running.
pub(crate) async fn on_thread_within<T: Send + 'static>(
    deadline: Duration,
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, Unfinished> {
    match tokio::time::timeout(deadline, tokio::task::spawn_blocking(work)).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(_)) => Err(Unfinished::Panicked),
        Err(_) => Err(Unfinished::Deadline),
    }
}

/// Runs blocking file work on a thread of its own, up to `deadline`. Work past
/// the deadline is reported as a failure, and the thread keeps its share of the
/// deployment's lock until it ends, so no other process starts on the same
/// files in the meantime.
pub(super) async fn off_thread<T, E>(
    lock: &Arc<DeployLock>,
    op: &'static str,
    deadline: Duration,
    work: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> Result<T, FileFailure>
where
    T: Send + 'static,
    E: Into<FileFailure> + Send + 'static,
{
    #[cfg(test)]
    let (work, deadline) = faults::inject(op, deadline, work);
    let held = Arc::clone(lock);
    on_thread_within(deadline, move || {
        let _held = held;
        work()
    })
    .await
    .map_err(|unfinished| unfinished.failure(op, deadline))?
    .map_err(Into::into)
}
