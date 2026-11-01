//! Test support: a scriptable [`Docker`] that records every call.
//!
//! Each method has a script of replies. Replies are consumed in order and the
//! last one repeats, so `[starting, starting, healthy]` means "healthy from
//! the third call on". A method without a script answers with a plain default
//! (documented on its setter); for the methods whose answer a test must
//! decide (`inspect`, `exec`, `compose_service`) the default is an error, so
//! an unscripted call fails loudly instead of passing by accident.

use std::collections::{BTreeMap, VecDeque};
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, PoisonError};

use jiff::Timestamp;

use crate::docker::{ContainerId, ContainerInfo, Docker, DockerError, ServiceConfig};

/// A scripted reply: a value, or the reason of a [`DockerError::BadOutput`].
pub type Reply<T> = Result<T, &'static str>;

/// One call the fake received, with its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Call {
    /// `pull(image)`.
    Pull(String),
    /// `compose_service(dir, service)`.
    ComposeService {
        /// Compose directory.
        dir: PathBuf,
        /// Service name.
        service: String,
    },
    /// `compose_up(dir, service)`.
    ComposeUp {
        /// Compose directory.
        dir: PathBuf,
        /// Service name.
        service: String,
    },
    /// `compose_stop(dir, service)`.
    ComposeStop {
        /// Compose directory.
        dir: PathBuf,
        /// Service name.
        service: String,
    },
    /// `container(dir, service)`.
    Container {
        /// Compose directory.
        dir: PathBuf,
        /// Service name.
        service: String,
    },
    /// `inspect(id)`.
    Inspect(ContainerId),
    /// `exec(id, argv)`.
    Exec {
        /// Container.
        id: ContainerId,
        /// Command.
        argv: Vec<String>,
    },
    /// `logs_contain(id, since, needle)`.
    LogsContain {
        /// Container.
        id: ContainerId,
        /// Start of the window.
        since: Timestamp,
        /// The substring asked for.
        needle: String,
    },
}

#[derive(Debug)]
struct Script<T>(VecDeque<Reply<T>>);

impl<T: Clone> Script<T> {
    fn empty() -> Self {
        Self(VecDeque::new())
    }

    /// The next reply; the last one repeats. `None` when nothing is scripted.
    fn next(&mut self) -> Option<Reply<T>> {
        if self.0.len() > 1 {
            self.0.pop_front()
        } else {
            self.0.front().cloned()
        }
    }
}

#[derive(Debug)]
struct Inner {
    calls: Vec<Call>,
    pull: Script<()>,
    compose_service: Script<ServiceConfig>,
    compose_up: Script<()>,
    compose_stop: Script<()>,
    container: Script<Option<ContainerId>>,
    inspect: Script<ContainerInfo>,
    exec: Script<bool>,
    logs_contain: Script<bool>,
}

/// A [`Docker`] that answers from scripts and logs what it was asked.
#[derive(Debug)]
pub struct FakeDocker {
    inner: Mutex<Inner>,
}

impl Default for FakeDocker {
    fn default() -> Self {
        Self::new()
    }
}

fn fail(command: &'static str, reason: &'static str) -> DockerError {
    DockerError::BadOutput { command, reason }
}

/// A container id for tests.
///
/// # Panics
///
/// Never: the literal is a valid id.
#[must_use]
pub fn container_id() -> ContainerId {
    "0123456789ab"
        .parse()
        .expect("a valid container id literal")
}

/// A running container that has just started, attached to `networks`.
#[must_use]
pub fn running(health: Option<&str>, networks: &[(&str, Option<IpAddr>)]) -> ContainerInfo {
    ContainerInfo {
        image: "ghcr.io/example/app@sha256:00".to_owned(),
        status: "running".to_owned(),
        health: health.map(str::to_owned),
        started_at: Timestamp::now(),
        networks: networks
            .iter()
            .map(|(name, ip)| ((*name).to_owned(), *ip))
            .collect::<BTreeMap<_, _>>(),
    }
}

macro_rules! script_setter {
    ($(#[$doc:meta])* $name:ident, $field:ident, $ty:ty) => {
        $(#[$doc])*
        pub fn $name(&self, replies: impl IntoIterator<Item = Reply<$ty>>) {
            self.lock().$field = Script(replies.into_iter().collect());
        }
    };
}

impl FakeDocker {
    /// A fake with nothing scripted.
    #[must_use]
    pub fn new() -> Self {
        Self {
            inner: Mutex::new(Inner {
                calls: Vec::new(),
                pull: Script::empty(),
                compose_service: Script::empty(),
                compose_up: Script::empty(),
                compose_stop: Script::empty(),
                container: Script::empty(),
                inspect: Script::empty(),
                exec: Script::empty(),
                logs_contain: Script::empty(),
            }),
        }
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Every call received so far, in order.
    #[must_use]
    pub fn calls(&self) -> Vec<Call> {
        self.lock().calls.clone()
    }

    /// How many calls satisfy `pred`.
    pub fn count(&self, pred: impl Fn(&Call) -> bool) -> usize {
        self.lock().calls.iter().filter(|c| pred(c)).count()
    }

    script_setter!(
        /// Replies of `pull`. Default: success.
        script_pull, pull, ()
    );
    script_setter!(
        /// Replies of `compose_service`. Default: an error.
        script_compose_service, compose_service, ServiceConfig
    );
    script_setter!(
        /// Replies of `compose_up`. Default: success.
        script_compose_up, compose_up, ()
    );
    script_setter!(
        /// Replies of `compose_stop`. Default: success.
        script_compose_stop, compose_stop, ()
    );
    script_setter!(
        /// Replies of `container`. Default: the id from [`container_id`].
        script_container, container, Option<ContainerId>
    );
    script_setter!(
        /// Replies of `inspect`. Default: an error.
        script_inspect, inspect, ContainerInfo
    );
    script_setter!(
        /// Replies of `exec`. Default: an error.
        script_exec, exec, bool
    );
    script_setter!(
        /// Replies of `logs_contain`. Default: no match.
        script_logs_contain, logs_contain, bool
    );
}

fn lift<T>(command: &'static str, reply: Reply<T>) -> Result<T, DockerError> {
    reply.map_err(|reason| fail(command, reason))
}

impl Docker for FakeDocker {
    async fn pull(&self, image: &str) -> Result<(), DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::Pull(image.to_owned()));
        lift("pull", inner.pull.next().unwrap_or(Ok(())))
    }

    async fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::ComposeService {
            dir: dir.to_owned(),
            service: service.to_owned(),
        });
        lift(
            "compose config",
            inner
                .compose_service
                .next()
                .unwrap_or(Err("unscripted compose_service")),
        )
    }

    async fn compose_up(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::ComposeUp {
            dir: dir.to_owned(),
            service: service.to_owned(),
        });
        lift("compose up", inner.compose_up.next().unwrap_or(Ok(())))
    }

    async fn compose_stop(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::ComposeStop {
            dir: dir.to_owned(),
            service: service.to_owned(),
        });
        lift("compose stop", inner.compose_stop.next().unwrap_or(Ok(())))
    }

    async fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Option<ContainerId>, DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::Container {
            dir: dir.to_owned(),
            service: service.to_owned(),
        });
        lift(
            "compose ps",
            inner
                .container
                .next()
                .unwrap_or_else(|| Ok(Some(container_id()))),
        )
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerInfo, DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::Inspect(id.clone()));
        lift(
            "inspect",
            inner.inspect.next().unwrap_or(Err("unscripted inspect")),
        )
    }

    async fn exec(&self, id: &ContainerId, argv: &[String]) -> Result<bool, DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::Exec {
            id: id.clone(),
            argv: argv.to_vec(),
        });
        lift("exec", inner.exec.next().unwrap_or(Err("unscripted exec")))
    }

    async fn logs_contain(
        &self,
        id: &ContainerId,
        since: Timestamp,
        needle: &str,
    ) -> Result<bool, DockerError> {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let mut inner = self.lock();
        inner.calls.push(Call::LogsContain {
            id: id.clone(),
            since,
            needle: needle.to_owned(),
        });
        lift("logs", inner.logs_contain.next().unwrap_or(Ok(false)))
    }
}
