//! Test support: file work of the engine that fails on request. A thread that
//! dies part-way cannot be arranged any other way, and permissions don't stop
//! the root user the Linux run has.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::mpsc::Receiver;
use std::time::Duration;

use super::FileFailure;
use crate::state::StateError;

/// What one run of a file operation does.
pub(super) enum Fault {
    /// It works.
    Pass,
    /// It fails without doing anything.
    Fail,
    /// It does its work and reports a failure, as `write_atomic` does when
    /// the rename worked and the `fsync` after it did not.
    FailAfter,
    /// It is past its deadline at once, and does its work when released.
    Late(Receiver<()>),
}

type Plan = Mutex<HashMap<&'static str, VecDeque<Fault>>>;

tokio::task_local! {
    static PLAN: Plan;
}

/// Runs `work` with these faults. Each list is for the runs of the named
/// operation in order; runs past its end work.
pub(super) async fn with_faults<T>(
    plan: impl IntoIterator<Item = (&'static str, Vec<Fault>)>,
    work: impl Future<Output = T>,
) -> T {
    let plan = plan
        .into_iter()
        .map(|(op, faults)| (op, VecDeque::from(faults)))
        .collect();
    PLAN.scope(Mutex::new(plan), work).await
}

/// The error of file work under [`inject`].
pub(super) enum Injected<E> {
    /// The work's own.
    Real(E),
    /// The fault's.
    Fault,
}

impl<E: Into<FileFailure>> From<Injected<E>> for FileFailure {
    fn from(error: Injected<E>) -> Self {
        match error {
            Injected::Real(error) => error.into(),
            Injected::Fault => FileFailure::State(StateError::Io {
                op: "inject",
                path: PathBuf::from("injected"),
                source: io::Error::other("injected fault"),
            }),
        }
    }
}

/// `work` with the next fault of `op`, and the deadline that goes with it.
pub(super) fn inject<T, E>(
    op: &'static str,
    deadline: Duration,
    work: impl FnOnce() -> Result<T, E> + Send + 'static,
) -> (
    impl FnOnce() -> Result<T, Injected<E>> + Send + 'static,
    Duration,
)
where
    E: Into<FileFailure> + Send + 'static,
{
    let fault = PLAN
        .try_with(|plan| {
            plan.lock()
                .unwrap()
                .get_mut(op)
                .and_then(VecDeque::pop_front)
        })
        .ok()
        .flatten()
        .unwrap_or(Fault::Pass);
    let deadline = if matches!(fault, Fault::Late(_)) {
        Duration::ZERO
    } else {
        deadline
    };
    let work = move || match fault {
        Fault::Pass => work().map_err(Injected::Real),
        Fault::Fail => Err(Injected::Fault),
        Fault::FailAfter => work()
            .map_err(Injected::Real)
            .and_then(|_| Err(Injected::Fault)),
        Fault::Late(release) => {
            let _ = release.recv();
            work().map_err(Injected::Real)
        }
    };
    (work, deadline)
}
