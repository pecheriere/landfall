//! Test support: a scriptable [`Docker`] that records every call.
//!
//! Each method has a script of replies. Replies are consumed in order and the
//! last one repeats, so `[starting, starting, healthy]` means "healthy from
//! the third call on". A method without a script answers with a plain default
//! (documented on its setter); for the methods whose answer a test must
//! decide (`inspect`, `exec`, `compose_service`) the default is an error, so
//! an unscripted call fails loudly instead of passing by accident.
//!
//! Also here: [`ComposeProject`], for the tests that run against a real Docker
//! daemon.

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{SystemTime, UNIX_EPOCH};

use jiff::Timestamp;

use crate::docker::{ContainerId, ContainerInfo, Docker, DockerCli, DockerError, ServiceConfig};

/// The image of tests against a real Docker daemon: busybox 1.37, by the
/// digest of its multi-platform index.
pub const TEST_IMAGE: &str =
    "busybox@sha256:a7dbc319b1438115a207e11930dc4bb3e643dcb3ec0bdd694bb36cd8fad289ec";

/// A compose project on a real Docker daemon with a unique name, removed on
/// drop with its network and containers (one-offs included).
#[derive(Debug)]
pub struct ComposeProject {
    /// The project's name.
    pub name: String,
    dir: tempfile::TempDir,
}

impl ComposeProject {
    /// Pulls [`TEST_IMAGE`] and writes a project with the YAML of `services`
    /// (indented by two spaces). Services may join the network `net`, which
    /// Docker knows as `<name>-net`.
    ///
    /// # Panics
    ///
    /// When any of that fails: this is test setup.
    pub async fn new(cli: &DockerCli, services: &str) -> Self {
        // Tests start together and a clock may tick in microseconds: only the
        // counter tells them apart. The time tells this run from an earlier
        // one that had the same process id and left something behind.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("landfall-test-{}-{nanos}-{serial}", std::process::id());
        cli.pull(TEST_IMAGE).await.unwrap();
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("compose.yaml"),
            format!("name: {name}\nservices:\n{services}networks:\n  net:\n    name: {name}-net\n"),
        )
        .unwrap();
        Self { name, dir }
    }

    /// The compose directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        self.dir.path()
    }

    /// The ids of the project's containers, one-offs included.
    ///
    /// # Panics
    ///
    /// When the Docker client cannot be run.
    #[must_use]
    pub fn all_containers(&self) -> Vec<String> {
        let out = Command::new("docker")
            .args(["ps", "-a", "-q", "--no-trunc", "--filter"])
            .arg(format!("label=com.docker.compose.project={}", self.name))
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Drop for ComposeProject {
    fn drop(&mut self) {
        let _ = Command::new("docker")
            .args(["compose", "-p", &self.name, "down"])
            .args(["--volumes", "--remove-orphans", "--timeout", "1"])
            // By name and from elsewhere: a test may leave a project behind
            // that compose refuses to load.
            .current_dir(self.dir.path().parent().unwrap_or(Path::new("/")))
            .output();
    }
}

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
    /// `compose_service_checked(dir, service)`.
    ComposeServiceChecked {
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
    /// `logs_contain(id, since, until, needle)`.
    LogsContain {
        /// Container.
        id: ContainerId,
        /// Start of the window.
        since: Timestamp,
        /// End of the window.
        until: Timestamp,
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

/// Runs for every call, as it is recorded.
type OnCall = Arc<dyn Fn(&Call) + Send + Sync>;
/// Says which calls never return.
type HangWhen = Arc<dyn Fn(&Call) -> bool + Send + Sync>;

struct Inner {
    calls: Vec<Call>,
    on_call: Option<OnCall>,
    hang_when: Option<HangWhen>,
    pull: Script<()>,
    compose_service: Script<ServiceConfig>,
    compose_up: Script<()>,
    compose_stop: Script<()>,
    container: Script<Option<ContainerId>>,
    inspect: Script<ContainerInfo>,
    inspect_after_up: BTreeMap<usize, Script<ContainerInfo>>,
    exec: Script<bool>,
    logs_contain: Script<bool>,
}

/// A [`Docker`] that answers from scripts and logs what it was asked.
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
                on_call: None,
                hang_when: None,
                pull: Script::empty(),
                compose_service: Script::empty(),
                compose_up: Script::empty(),
                compose_stop: Script::empty(),
                container: Script::empty(),
                inspect: Script::empty(),
                inspect_after_up: BTreeMap::new(),
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

    /// Runs `hook` for every call, after it is logged and before it is
    /// answered, so a test can change the world in the middle of a call. The
    /// fake is not locked meanwhile: the hook may use it.
    pub fn on_call(&self, hook: impl Fn(&Call) + Send + Sync + 'static) {
        self.lock().on_call = Some(Arc::new(hook));
    }

    /// Makes the calls `pred` picks never return (a daemon that hangs). They
    /// are still logged.
    pub fn hang_when(&self, pred: impl Fn(&Call) -> bool + Send + Sync + 'static) {
        self.lock().hang_when = Some(Arc::new(pred));
    }

    /// Replies of `inspect` once `compose_up` has been called exactly `ups`
    /// times, so a script follows the deploy rather than the number of
    /// inspects. Takes precedence over [`script_inspect`](Self::script_inspect).
    pub fn script_inspect_after_up(
        &self,
        ups: usize,
        replies: impl IntoIterator<Item = Reply<ContainerInfo>>,
    ) {
        self.lock()
            .inspect_after_up
            .insert(ups, Script(replies.into_iter().collect()));
    }

    /// What every call does first: logs itself and runs the hook.
    async fn record(&self, call: Call) {
        // Like real I/O, a call is a point where other tasks can run.
        tokio::task::yield_now().await;
        let (on_call, hang_when) = {
            let mut inner = self.lock();
            inner.calls.push(call.clone());
            (inner.on_call.clone(), inner.hang_when.clone())
        };
        if let Some(hook) = on_call {
            hook(&call);
        }
        if hang_when.is_some_and(|pred| pred(&call)) {
            std::future::pending::<()>().await;
        }
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
        self.record(Call::Pull(image.to_owned())).await;
        lift("pull", self.lock().pull.next().unwrap_or(Ok(())))
    }

    async fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        self.record(Call::ComposeService {
            dir: dir.to_owned(),
            service: service.to_owned(),
        })
        .await;
        lift(
            "compose config",
            self.lock()
                .compose_service
                .next()
                .unwrap_or(Err("unscripted compose_service")),
        )
    }

    /// Answers from the same script as `compose_service`.
    async fn compose_service_checked(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        self.record(Call::ComposeServiceChecked {
            dir: dir.to_owned(),
            service: service.to_owned(),
        })
        .await;
        lift(
            "compose config",
            self.lock()
                .compose_service
                .next()
                .unwrap_or(Err("unscripted compose_service")),
        )
    }

    async fn compose_up(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        self.record(Call::ComposeUp {
            dir: dir.to_owned(),
            service: service.to_owned(),
        })
        .await;
        lift(
            "compose up",
            self.lock().compose_up.next().unwrap_or(Ok(())),
        )
    }

    async fn compose_stop(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        self.record(Call::ComposeStop {
            dir: dir.to_owned(),
            service: service.to_owned(),
        })
        .await;
        lift(
            "compose stop",
            self.lock().compose_stop.next().unwrap_or(Ok(())),
        )
    }

    async fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Option<ContainerId>, DockerError> {
        self.record(Call::Container {
            dir: dir.to_owned(),
            service: service.to_owned(),
        })
        .await;
        lift(
            "compose ps",
            self.lock()
                .container
                .next()
                .unwrap_or_else(|| Ok(Some(container_id()))),
        )
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerInfo, DockerError> {
        self.record(Call::Inspect(id.clone())).await;
        let mut inner = self.lock();
        let ups = inner
            .calls
            .iter()
            .filter(|c| matches!(c, Call::ComposeUp { .. }))
            .count();
        let reply = match inner.inspect_after_up.get_mut(&ups) {
            Some(script) => script.next(),
            None => inner.inspect.next(),
        };
        lift("inspect", reply.unwrap_or(Err("unscripted inspect")))
    }

    async fn exec(&self, id: &ContainerId, argv: &[String]) -> Result<bool, DockerError> {
        self.record(Call::Exec {
            id: id.clone(),
            argv: argv.to_vec(),
        })
        .await;
        lift(
            "exec",
            self.lock().exec.next().unwrap_or(Err("unscripted exec")),
        )
    }

    async fn logs_contain(
        &self,
        id: &ContainerId,
        since: Timestamp,
        until: Timestamp,
        needle: &str,
    ) -> Result<bool, DockerError> {
        self.record(Call::LogsContain {
            id: id.clone(),
            since,
            until,
            needle: needle.to_owned(),
        })
        .await;
        lift("logs", self.lock().logs_contain.next().unwrap_or(Ok(false)))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::AtomicUsize;

    use super::{Arc, Call, Docker, FakeDocker, Ordering, Path, container_id, running};

    #[tokio::test]
    async fn on_call_runs_during_the_call_and_may_use_the_fake() {
        let docker = Arc::new(FakeDocker::new());
        let seen = Arc::new(AtomicUsize::new(0));
        let (fake, count) = (Arc::downgrade(&docker), Arc::clone(&seen));
        docker.on_call(move |call| {
            if matches!(call, Call::ComposeUp { .. }) {
                let fake = fake.upgrade().unwrap();
                count.store(fake.calls().len(), Ordering::SeqCst);
            }
        });
        docker
            .compose_up(Path::new("/srv/compose/app"), "app")
            .await
            .unwrap();
        assert_eq!(seen.load(Ordering::SeqCst), 1, "logged before the hook ran");
    }

    #[tokio::test]
    async fn inspect_replies_follow_the_number_of_compose_ups() {
        let docker = FakeDocker::new();
        let (old, new) = (
            running(Some("healthy"), &[]),
            running(Some("starting"), &[]),
        );
        docker.script_inspect_after_up(0, [Ok(old.clone())]);
        docker.script_inspect_after_up(1, [Ok(new.clone())]);
        let id = container_id();
        for _ in 0..3 {
            assert_eq!(docker.inspect(&id).await.unwrap(), old);
        }
        docker
            .compose_up(Path::new("/srv/compose/app"), "app")
            .await
            .unwrap();
        assert_eq!(docker.inspect(&id).await.unwrap(), new);
        docker
            .compose_up(Path::new("/srv/compose/app"), "app")
            .await
            .unwrap();
        assert!(
            docker.inspect(&id).await.is_err(),
            "nothing scripted for two ups, and no plain inspect script to fall back on"
        );
    }
}
