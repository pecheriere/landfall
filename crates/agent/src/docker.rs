//! The Docker driver: the only code in the agent that runs the Docker CLI.
//!
//! Commands are argument vectors, never a shell. Their environment loses
//! `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME` and `COMPOSE_PROFILES`, so the
//! stack's `.env` decides, and `PWD`, or compose would label a container with
//! the agent's symlink to the directory. Every call has a timeout and every captured
//! output a cap. Each runs in its own process group, which a timeout, or
//! dropping the call, kills whole: `docker compose` is a plugin run by the `docker` client, and a
//! call given up on must not keep working under the rollback that follows it.
//!
//! Two kinds of output are secret-bearing and treated as such. The JSON of
//! `docker compose config` holds interpolated secrets: only the service's
//! image and whether it has a `build` section are read from it, and neither
//! it, nor its stderr, nor a parser's message about it reaches an error. The
//! same holds for every other `docker compose` subcommand, which loads the
//! same `.env` and compose files and prints their parse errors, values
//! included: they report their exit status only.
//! `docker inspect` is asked for a fixed set of fields through `--format`,
//! so a container's environment is never read.

use std::future::Future;
use std::path::Path;
use std::time::Duration;

use jiff::Timestamp;

mod cli;
mod error;
mod parse;
mod process;
mod scan;
#[cfg(test)]
mod tests;
mod types;

pub use cli::DockerCli;
pub use error::DockerError;
pub use types::{ContainerId, ContainerIdError, ContainerInfo, ServiceConfig, ServiceContainer};

/// Captured output is refused beyond this many bytes.
const OUTPUT_CAP: usize = 16 * 1024 * 1024;

/// The part of a failing command's stderr that an error quotes.
const STDERR_TAIL: usize = 4096;

/// The longest line `logs_contain` holds; longer lines are scanned in chunks.
const LINE_LIMIT: usize = 1024 * 1024;

const READ_CHUNK: usize = 64 * 1024;

/// How long a killed process group is waited for before giving up on it.
const KILL_WAIT: Duration = Duration::from_secs(5);

/// Environment variables that would make a compose command read something
/// other than the stack's own files, or, for `PWD`, label a container with
/// another spelling of its directory: Go takes the path from it when it leads
/// to the working directory, a symlink included. And the agent's token for GitHub,
/// which goes to GitHub only: compose would hand it to any stack that names it in
/// its file.
const SCRUBBED_ENV: [&str; 5] = [
    "COMPOSE_FILE",
    "COMPOSE_PROJECT_NAME",
    "COMPOSE_PROFILES",
    "GITHUB_TOKEN",
    "PWD",
];

/// The Go template `docker inspect` is given: the fields the agent needs and
/// nothing else (no `.Config.Env`). `.State.Health` is absent without a
/// healthcheck, hence the `if`. Networks come as `[name, ip]` pairs ending in
/// `null`, which keeps the template free of separator logic. Each network
/// gives `[name, IPv4, global IPv6]`; either address is empty when the
/// container has none.
const INSPECT_FORMAT: &str = concat!(
    "{\"image\":{{json .Config.Image}},",
    "\"status\":{{json .State.Status}},",
    "\"health\":{{if .State.Health}}{{json .State.Health.Status}}{{else}}null{{end}},",
    "\"started_at\":{{json .State.StartedAt}},",
    "\"networks\":[{{range $name, $net := .NetworkSettings.Networks}}",
    "[{{json $name}},{{json $net.IPAddress}},{{json $net.GlobalIPv6Address}}],{{end}}null]}"
);

/// The Go template of `docker ps` that reads a container's id, state, compose
/// project and working directory, and nothing else, as a JSON array on one
/// line: a label it doesn't have is empty.
const SERVICE_CONTAINER_FORMAT: &str = concat!(
    "[{{json .ID}},{{json .State}},",
    "{{json (.Label \"com.docker.compose.project\")}},",
    "{{json (.Label \"com.docker.compose.project.working_dir\")}}]"
);

/// The Docker operations the agent needs. Implemented by [`DockerCli`]; a
/// fake stands in for it in tests of the deploy sequence.
pub trait Docker: Send + Sync {
    /// Pulls `image`.
    fn pull(&self, image: &str) -> impl Future<Output = Result<(), DockerError>> + Send;

    /// Reads `service` from the resolved compose project in `dir`.
    ///
    /// # Errors
    ///
    /// [`DockerError::NoSuchService`] when the project has no such service.
    fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<ServiceConfig, DockerError>> + Send;

    /// [`compose_service`](Self::compose_service) with the whole project held
    /// to what `up` requires: a network, volume, secret or `depends_on` target
    /// that is not defined is an error here, and so is a service without an
    /// image, so this is for a project that should be ready to start.
    ///
    /// # Errors
    ///
    /// [`DockerError::NoSuchService`] when the project has no such service.
    fn compose_service_checked(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<ServiceConfig, DockerError>> + Send;

    /// `docker compose up -d --no-deps <service>`.
    fn compose_up(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<(), DockerError>> + Send;

    /// `docker compose stop <service>`.
    fn compose_stop(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<(), DockerError>> + Send;

    /// The service's running container in the compose project of `dir`, found
    /// by the project's name, whichever directory it was started from; none if
    /// it isn't running, which includes a stopped one and one never created.
    /// It loads the project, so it needs the stack's files.
    ///
    /// # Errors
    ///
    /// [`DockerError::SeveralContainers`] for a scaled service.
    fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<Option<ContainerId>, DockerError>> + Send;

    /// [`container`](Self::container) by the working directory the container
    /// is labelled with, without loading the project. This is for reporting
    /// on a stack that may not be readable: a container started from elsewhere
    /// (a compose file in another directory, a path through a symlink) is not
    /// found, and a second project in `dir` counts.
    ///
    /// # Errors
    ///
    /// [`DockerError::SeveralContainers`] when `dir` has more than one.
    fn container_at(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<Option<ContainerId>, DockerError>> + Send;

    /// The fields of [`ContainerInfo`] for `id`.
    fn inspect(
        &self,
        id: &ContainerId,
    ) -> impl Future<Output = Result<ContainerInfo, DockerError>> + Send;

    /// Every container of a service called `service` on this host, in any state
    /// and any project, one-offs left out, each said to be in the compose
    /// project of `dir` or not. It loads the project for its name, so it needs
    /// the stack's files. For telling what stands in the way of a deploy;
    /// [`container`](Self::container) is the service's running one.
    fn service_containers(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<Vec<ServiceContainer>, DockerError>> + Send;

    /// Runs `argv` in the container; whether it exited with status 0. Its
    /// output is discarded. On a timeout only the `docker exec` client is
    /// killed: the process it started keeps running in the container.
    fn exec(
        &self,
        id: &ContainerId,
        argv: &[String],
    ) -> impl Future<Output = Result<bool, DockerError>> + Send;

    /// Whether any line the container logged (on stdout or stderr) between
    /// `since` and `until`, both rounded outwards to the second, contains
    /// `needle`.
    fn logs_contain(
        &self,
        id: &ContainerId,
        since: Timestamp,
        until: Timestamp,
        needle: &str,
    ) -> impl Future<Output = Result<bool, DockerError>> + Send;
}
