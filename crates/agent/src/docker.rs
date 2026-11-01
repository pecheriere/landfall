//! The Docker driver: the only code in the agent that runs the Docker CLI.
//!
//! Commands are argument vectors, never a shell. Their environment loses
//! `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME` and `COMPOSE_PROFILES`, so the
//! stack's `.env` decides. Every call has a timeout and every captured
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

use std::collections::BTreeMap;
use std::fmt;
use std::future::Future;
use std::io;
use std::net::IpAddr;
use std::ops::{Deref, DerefMut};
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::str::FromStr;
use std::time::Duration;

use jiff::Timestamp;
use landfall_core::config::LOG_PATTERN_LIMIT;
use rustix::process::{Pid, Signal, kill_process_group};
use serde::Deserialize;
use serde::de::IgnoredAny;
use tokio::io::{AsyncRead, AsyncReadExt};
use tokio::process::{Child, Command};

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
/// other than the stack's own files.
const SCRUBBED_ENV: [&str; 3] = ["COMPOSE_FILE", "COMPOSE_PROJECT_NAME", "COMPOSE_PROFILES"];

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

/// A failure running Docker.
#[derive(Debug, thiserror::Error)]
pub enum DockerError {
    /// The binary could not be started.
    #[error("{command}: cannot start: {source}")]
    Spawn {
        /// The command.
        command: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// Reading the command's output failed.
    #[error("{command}: reading output: {source}")]
    Io {
        /// The command.
        command: &'static str,
        /// The underlying error.
        source: io::Error,
    },
    /// The command ran past its timeout and was killed.
    #[error("{command}: timed out after {after:?}")]
    Timeout {
        /// The command.
        command: &'static str,
        /// The timeout that applied.
        after: Duration,
    },
    /// The command wrote more than the cap and was killed.
    #[error("{command}: output exceeds {cap} bytes")]
    TooMuchOutput {
        /// The command.
        command: &'static str,
        /// The cap.
        cap: usize,
    },
    /// The command failed; the last part of its stderr is quoted.
    #[error("{command}: {status}; stderr ends with {stderr:?}")]
    Failed {
        /// The command.
        command: &'static str,
        /// The exit status.
        status: String,
        /// The truncated, lossily decoded tail of stderr.
        stderr: String,
    },
    /// The command failed and, because its output can echo secrets or
    /// container logs, only its exit status is reported, with the command to
    /// run by hand to see why.
    #[error("{command}: {status} (output withheld; to see why, run by hand: {argv})")]
    FailedQuietly {
        /// The command.
        command: &'static str,
        /// The exit status.
        status: String,
        /// The command line, which holds nothing from the configuration but
        /// names validated before they got here.
        argv: String,
    },
    /// The command was killed after an error or timeout, but did not exit
    /// within a few seconds (a process stuck in the kernel). It may still be
    /// running.
    #[error("{command}: did not exit after being killed")]
    Unkillable {
        /// The command.
        command: &'static str,
    },
    /// The command succeeded but its output was not what was asked for.
    /// The output is not quoted: it may hold secrets.
    #[error("{command}: unexpected output ({reason})")]
    BadOutput {
        /// The command.
        command: &'static str,
        /// What was wrong, in words that quote nothing.
        reason: &'static str,
    },
    /// The compose project has no such service.
    #[error("compose project has no service {service:?}")]
    NoSuchService {
        /// The service.
        service: String,
    },
    /// An argument was refused before anything ran.
    #[error("{command}: refused argument: {reason}")]
    BadArgument {
        /// The command.
        command: &'static str,
        /// Why.
        reason: &'static str,
    },
}

/// A container id: 12 to 64 lowercase hexadecimal digits.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ContainerId(String);

/// The text is not a container id.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("not a container id: expected 12 to 64 lowercase hex digits")]
pub struct ContainerIdError;

impl FromStr for ContainerId {
    type Err = ContainerIdError;

    fn from_str(s: &str) -> Result<Self, ContainerIdError> {
        let ok = (12..=64).contains(&s.len())
            && s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        if ok {
            Ok(Self(s.to_owned()))
        } else {
            Err(ContainerIdError)
        }
    }
}

impl fmt::Display for ContainerId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for ContainerId {
    fn as_ref(&self) -> &str {
        &self.0
    }
}

/// What the agent reads of a service in the resolved compose project.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceConfig {
    /// The image the project resolves to, if the service has one.
    pub image: Option<String>,
    /// Whether the service has a `build` section (refused by the agent).
    pub has_build: bool,
}

/// What the agent reads of a container; its environment is not among it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerInfo {
    /// `.Config.Image`: the image reference the container was created with.
    pub image: String,
    /// `.State.Status`: `running`, `exited`, ...
    pub status: String,
    /// `.State.Health.Status`, absent without a healthcheck.
    pub health: Option<String>,
    /// When the container last started.
    pub started_at: Timestamp,
    /// Attached networks and the container's IP on each, if it has one.
    pub networks: BTreeMap<String, Option<IpAddr>>,
}

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

    /// The service's container, running or not; none if it has never been
    /// created. More than one (a scaled service) is an error.
    fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> impl Future<Output = Result<Option<ContainerId>, DockerError>> + Send;

    /// The fields of [`ContainerInfo`] for `id`.
    fn inspect(
        &self,
        id: &ContainerId,
    ) -> impl Future<Output = Result<ContainerInfo, DockerError>> + Send;

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

/// [`Docker`] on the `docker` command-line client.
#[derive(Debug, Clone)]
pub struct DockerCli {
    binary: PathBuf,
    /// Timeout of quick calls (config, ps, inspect, exec). Default 60 s.
    pub timeout: Duration,
    /// Timeout of calls that move data (pull, up, stop). Default 600 s.
    pub long_timeout: Duration,
}

impl Default for DockerCli {
    fn default() -> Self {
        Self::with_binary("docker")
    }
}

impl DockerCli {
    /// The client found as `docker` on the agent's `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The client at `binary`, which is a path or a name looked up on
    /// `PATH`. Tests point this at a stub script.
    #[must_use]
    pub fn with_binary(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            timeout: Duration::from_secs(60),
            long_timeout: Duration::from_secs(600),
        }
    }

    fn command(&self, dir: Option<&Path>) -> Command {
        let mut cmd = Command::new(&self.binary);
        for var in SCRUBBED_ENV {
            cmd.env_remove(var);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if let Some(dir) = dir {
            cmd.current_dir(dir);
        }
        cmd
    }

    fn compose(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = self.command(Some(dir));
        cmd.arg("compose").args(args);
        cmd
    }

    /// Runs `cmd` to completion within `limit`, with output capped, killing
    /// it on any error.
    async fn capture(
        label: &'static str,
        mut cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let mut child = spawn(label, &mut cmd)?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let work = async {
            let (out, err) = tokio::try_join!(
                read_capped(stdout, OUTPUT_CAP),
                read_tail(stderr, STDERR_TAIL)
            )?;
            let status = child.wait().await.map_err(ReadError::Io)?;
            Ok::<_, ReadError>(Captured {
                status,
                stdout: out,
                stderr_tail: err,
            })
        };
        let result = tokio::time::timeout(limit, work).await;
        let error = match result {
            Ok(Ok(captured)) => return Ok(captured),
            Ok(Err(ReadError::TooMuch)) => DockerError::TooMuchOutput {
                command: label,
                cap: OUTPUT_CAP,
            },
            Ok(Err(ReadError::Io(source))) => DockerError::Io {
                command: label,
                source,
            },
            Err(_) => DockerError::Timeout {
                command: label,
                after: limit,
            },
        };
        kill_group(label, &mut child).await?;
        Err(error)
    }

    /// [`capture`](Self::capture) for a `docker compose` subcommand: it loads
    /// the stack's `.env` and compose files and prints their parse errors,
    /// quoting values, so a failure reports its exit status only.
    async fn run_compose(
        label: &'static str,
        cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let argv = format!("{} in the compose directory", shown_argv(&cmd));
        let captured = Self::capture(label, cmd, limit).await?;
        if captured.status.success() {
            Ok(captured)
        } else {
            Err(DockerError::FailedQuietly {
                command: label,
                status: captured.status.to_string(),
                argv,
            })
        }
    }

    /// The compose project's name in `dir`. Commands given it don't load the
    /// project: compose refuses one where the service has no image, which is
    /// the state before a first deploy and the one a failed first deploy goes
    /// back to, possibly with its container still running.
    async fn project_name(&self, label: &'static str, dir: &Path) -> Result<String, DockerError> {
        let config = self.compose(dir, &["config", "--no-consistency", "--format", "json"]);
        let captured = Self::run_compose(label, config, self.timeout).await?;
        let project = parse_project_name(&captured.stdout)?;
        not_a_flag(label, &project)?;
        Ok(project)
    }

    /// [`capture`](Self::capture), failing on a non-zero exit with the
    /// quoted tail of stderr.
    async fn run(
        label: &'static str,
        cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let captured = Self::capture(label, cmd, limit).await?;
        if captured.status.success() {
            Ok(captured)
        } else {
            Err(DockerError::Failed {
                command: label,
                status: captured.status.to_string(),
                stderr: String::from_utf8_lossy(&captured.stderr_tail).into_owned(),
            })
        }
    }
}

/// The command line of `cmd` as an operator can type it, for an error that
/// withholds the output. It is printed, so it holds nothing that comes from
/// the stack's configuration: an argument with characters no flag or validated
/// name has, and the project name, which compose interpolates, are shown as
/// placeholders.
fn shown_argv(cmd: &Command) -> String {
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
struct GroupChild(Child);

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
async fn kill_group(label: &'static str, child: &mut GroupChild) -> Result<(), DockerError> {
    child.kill_group();
    // Covers a child that was not (or no longer) the leader of a group.
    let _ = child.start_kill();
    await_killed(label, child.wait(), KILL_WAIT).await
}

/// Waits for a killed command to be gone. A process stuck in the kernel does
/// not go, however it is killed, and the caller must not wait for it forever.
async fn await_killed<T>(
    label: &'static str,
    exit: impl Future<Output = T>,
    limit: Duration,
) -> Result<(), DockerError> {
    match tokio::time::timeout(limit, exit).await {
        Ok(_) => Ok(()),
        Err(_) => Err(DockerError::Unkillable { command: label }),
    }
}

fn spawn(label: &'static str, cmd: &mut Command) -> Result<GroupChild, DockerError> {
    cmd.spawn()
        .map(GroupChild)
        .map_err(|source| DockerError::Spawn {
            command: label,
            source,
        })
}

/// Refuses a name or reference that a client could read as a flag.
fn not_a_flag(label: &'static str, value: &str) -> Result<(), DockerError> {
    if value.is_empty() || value.starts_with('-') {
        Err(DockerError::BadArgument {
            command: label,
            reason: "empty or starting with '-'",
        })
    } else {
        Ok(())
    }
}

struct Captured {
    status: ExitStatus,
    stdout: Vec<u8>,
    stderr_tail: Vec<u8>,
}

enum ReadError {
    TooMuch,
    Io(io::Error),
}

/// Reads `reader` to its end, refusing more than `cap` bytes.
async fn read_capped<R: AsyncRead + Unpin>(
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
async fn read_tail<R: AsyncRead + Unpin>(
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

/// The only parts of `docker compose config --format json` that are read.
/// Every other field, secrets included, is skipped without being kept.
#[derive(Deserialize)]
struct ConfigDoc {
    #[serde(default)]
    services: BTreeMap<String, ServiceDoc>,
}

#[derive(Deserialize)]
struct ServiceDoc {
    image: Option<String>,
    build: Option<IgnoredAny>,
}

/// Reads `service` out of `docker compose config --format json`. Errors say
/// nothing about the input, which holds secrets.
fn parse_config(raw: &[u8], service: &str) -> Result<ServiceConfig, DockerError> {
    let doc: ConfigDoc = serde_json::from_slice(raw).map_err(|_| DockerError::BadOutput {
        command: "docker compose config",
        reason: "not the expected JSON",
    })?;
    let svc = doc
        .services
        .get(service)
        .ok_or_else(|| DockerError::NoSuchService {
            service: service.to_owned(),
        })?;
    Ok(ServiceConfig {
        image: svc.image.clone(),
        has_build: svc.build.is_some(),
    })
}

/// The project's name out of `docker compose config --format json`. As in
/// [`parse_config`], errors say nothing about the input.
fn parse_project_name(raw: &[u8]) -> Result<String, DockerError> {
    #[derive(Deserialize)]
    struct NameDoc {
        name: Option<String>,
    }
    const LABEL: &str = "docker compose config";
    let doc: NameDoc = serde_json::from_slice(raw).map_err(|_| DockerError::BadOutput {
        command: LABEL,
        reason: "not the expected JSON",
    })?;
    doc.name
        .filter(|name| !name.is_empty())
        .ok_or(DockerError::BadOutput {
            command: LABEL,
            reason: "the project has no name",
        })
}

/// `docker inspect --format INSPECT_FORMAT`, as emitted.
#[derive(Deserialize)]
struct InspectDoc {
    image: String,
    status: String,
    health: Option<String>,
    started_at: String,
    networks: Vec<Option<(String, String, String)>>,
}

fn bad_inspect(reason: &'static str) -> DockerError {
    DockerError::BadOutput {
        command: "docker inspect",
        reason,
    }
}

fn parse_inspect(raw: &[u8]) -> Result<ContainerInfo, DockerError> {
    let doc: InspectDoc =
        serde_json::from_slice(raw).map_err(|_| bad_inspect("not the expected JSON"))?;
    let started_at = doc
        .started_at
        .parse::<Timestamp>()
        .map_err(|_| bad_inspect("unreadable start time"))?;
    let mut networks = BTreeMap::new();
    for (name, v4, v6) in doc.networks.into_iter().flatten() {
        // Docker keeps the IPv4 and the global IPv6 address apart: IPv4
        // wins when both are there.
        let address = if v4.is_empty() { v6 } else { v4 };
        let ip = if address.is_empty() {
            None
        } else {
            Some(
                address
                    .parse::<IpAddr>()
                    .map_err(|_| bad_inspect("unreadable network address"))?,
            )
        };
        networks.insert(name, ip);
    }
    Ok(ContainerInfo {
        image: doc.image,
        status: doc.status,
        health: doc.health,
        started_at,
        networks,
    })
}

fn parse_container(raw: &[u8]) -> Result<Option<ContainerId>, DockerError> {
    let text = std::str::from_utf8(raw).map_err(|_| DockerError::BadOutput {
        command: "docker compose ps",
        reason: "not UTF-8",
    })?;
    let mut ids = text.lines().map(str::trim).filter(|l| !l.is_empty());
    let Some(first) = ids.next() else {
        return Ok(None);
    };
    if ids.next().is_some() {
        return Err(DockerError::BadOutput {
            command: "docker compose ps",
            reason: "more than one container",
        });
    }
    first
        .parse()
        .map(Some)
        .map_err(|_: ContainerIdError| DockerError::BadOutput {
            command: "docker compose ps",
            reason: "not a container id",
        })
}

/// Looks for a needle in a stream, line by line, holding at most
/// [`LINE_LIMIT`] bytes. A line longer than that is scanned as it fills,
/// keeping the last `needle.len() - 1` bytes, so a match across the
/// boundary is found. A needle never matches across a newline.
struct LineScanner<'a> {
    needle: &'a [u8],
    line: Vec<u8>,
}

impl<'a> LineScanner<'a> {
    fn new(needle: &'a [u8]) -> Self {
        Self {
            needle,
            line: Vec::new(),
        }
    }

    fn matches(&self) -> bool {
        memchr::memmem::find(&self.line, self.needle).is_some()
    }

    /// Feeds more of the stream; whether the needle has been found.
    fn feed(&mut self, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            let end = memchr::memchr(b'\n', data);
            let (segment, rest) = match end {
                Some(i) => (&data[..i], &data[i + 1..]),
                None => (data, &[][..]),
            };
            if self.push(segment) || self.matches() {
                return true;
            }
            if end.is_some() {
                self.line.clear();
            }
            data = rest;
        }
        false
    }

    fn push(&mut self, mut segment: &[u8]) -> bool {
        while !segment.is_empty() {
            let take = (LINE_LIMIT - self.line.len()).min(segment.len());
            self.line.extend_from_slice(&segment[..take]);
            segment = &segment[take..];
            if self.line.len() >= LINE_LIMIT {
                if self.matches() {
                    return true;
                }
                let keep = self.needle.len() - 1;
                self.line.drain(..self.line.len() - keep);
            }
        }
        false
    }

    /// The stream ended: the unterminated last line counts.
    fn finish(&self) -> bool {
        self.matches()
    }
}

/// Scans a stream for the needle until it ends or matches.
async fn scan<R: AsyncRead + Unpin>(reader: Option<R>, needle: &[u8]) -> Result<bool, io::Error> {
    let Some(mut reader) = reader else {
        return Ok(false);
    };
    let mut scanner = LineScanner::new(needle);
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(scanner.finish());
        }
        if scanner.feed(&chunk[..n]) {
            return Ok(true);
        }
    }
}

impl Docker for DockerCli {
    async fn pull(&self, image: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker pull";
        not_a_flag(LABEL, image)?;
        let mut cmd = self.command(None);
        cmd.args(["pull", "--", image]);
        Self::run(LABEL, cmd, self.long_timeout).await.map(drop)
    }

    async fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        const LABEL: &str = "docker compose config";
        // Without `--no-consistency`, compose refuses a service that has no
        // image yet, which is what a first deploy starts from (design 7.1).
        let cmd = self.compose(dir, &["config", "--no-consistency", "--format", "json"]);
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_config(&captured.stdout, service)
    }

    async fn compose_service_checked(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        const LABEL: &str = "docker compose config";
        let cmd = self.compose(dir, &["config", "--format", "json"]);
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_config(&captured.stdout, service)
    }

    async fn compose_up(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker compose up";
        not_a_flag(LABEL, service)?;
        let cmd = self.compose(dir, &["up", "-d", "--no-deps", "--", service]);
        Self::run_compose(LABEL, cmd, self.long_timeout)
            .await
            .map(drop)
    }

    async fn compose_stop(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker compose stop";
        not_a_flag(LABEL, service)?;
        let project = self.project_name(LABEL, dir).await?;
        let cmd = self.compose(dir, &["-p", &project, "stop", "--", service]);
        Self::run_compose(LABEL, cmd, self.long_timeout)
            .await
            .map(drop)
    }

    async fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Option<ContainerId>, DockerError> {
        const LABEL: &str = "docker compose ps";
        not_a_flag(LABEL, service)?;
        let project = self.project_name(LABEL, dir).await?;
        // Without `--all`: that also lists the one-off containers of
        // `compose run`, and a service is only ever up as a long-running one.
        let cmd = self.compose(dir, &["-p", &project, "ps", "--quiet", "--", service]);
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_container(&captured.stdout)
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerInfo, DockerError> {
        const LABEL: &str = "docker inspect";
        let mut cmd = self.command(None);
        cmd.args(["inspect", "--type", "container", "--format", INSPECT_FORMAT])
            .arg("--")
            .arg(id.as_ref());
        let captured = Self::run(LABEL, cmd, self.timeout).await?;
        parse_inspect(&captured.stdout)
    }

    async fn exec(&self, id: &ContainerId, argv: &[String]) -> Result<bool, DockerError> {
        const LABEL: &str = "docker exec";
        if argv.is_empty() {
            return Err(DockerError::BadArgument {
                command: LABEL,
                reason: "empty command",
            });
        }
        // After the container id Docker reads no more flags of its own, so
        // an argument starting with '-' belongs to the command.
        let mut cmd = self.command(None);
        cmd.args(["exec", "--", id.as_ref()])
            .args(argv)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn(LABEL, &mut cmd)?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) => Ok(status.success()),
            Ok(Err(source)) => {
                kill_group(LABEL, &mut child).await?;
                Err(DockerError::Io {
                    command: LABEL,
                    source,
                })
            }
            Err(_) => {
                kill_group(LABEL, &mut child).await?;
                Err(DockerError::Timeout {
                    command: LABEL,
                    after: self.timeout,
                })
            }
        }
    }

    async fn logs_contain(
        &self,
        id: &ContainerId,
        since: Timestamp,
        until: Timestamp,
        needle: &str,
    ) -> Result<bool, DockerError> {
        const LABEL: &str = "docker logs";
        if needle.is_empty() || needle.len() > LOG_PATTERN_LIMIT || needle.contains('\n') {
            return Err(DockerError::BadArgument {
                command: LABEL,
                reason: "needle must be 1 to 4096 bytes on a single line",
            });
        }
        let out_of_range = |_| DockerError::BadArgument {
            command: LABEL,
            reason: "time out of range",
        };
        let since = Timestamp::from_second(since.as_second()).map_err(out_of_range)?;
        // Rounded up: a line in the last fraction of the window counts.
        let until_second = until.as_second() + i64::from(until.subsec_nanosecond() > 0);
        let until = Timestamp::from_second(until_second).map_err(out_of_range)?;
        let mut cmd = self.command(None);
        cmd.args([
            "logs",
            "--since",
            &since.to_string(),
            "--until",
            &until.to_string(),
            "--",
        ])
        .arg(id.as_ref());
        let argv = shown_argv(&cmd);
        let mut child = spawn(LABEL, &mut cmd)?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let needle = needle.as_bytes();
        let work = async {
            // The container's stdout and stderr are both its log: the first
            // match in either wins, and a stream that ends only hands over
            // to the other.
            let out = scan(stdout, needle);
            let err = scan(stderr, needle);
            tokio::pin!(out, err);
            let (mut out_done, mut err_done) = (false, false);
            while !(out_done && err_done) {
                tokio::select! {
                    r = &mut out, if !out_done => {
                        if r? { return Ok::<_, io::Error>(true); }
                        out_done = true;
                    }
                    r = &mut err, if !err_done => {
                        if r? { return Ok(true); }
                        err_done = true;
                    }
                }
            }
            Ok(false)
        };
        let result = tokio::time::timeout(self.timeout, work).await;
        let error = match result {
            Ok(Ok(true)) => {
                kill_group(LABEL, &mut child).await?;
                return Ok(true);
            }
            Ok(Ok(false)) => {
                let status = tokio::time::timeout(self.timeout, child.wait()).await;
                return match status {
                    Ok(Ok(status)) if status.success() => Ok(false),
                    Ok(Ok(status)) => Err(DockerError::FailedQuietly {
                        command: LABEL,
                        status: status.to_string(),
                        argv,
                    }),
                    Ok(Err(source)) => Err(DockerError::Io {
                        command: LABEL,
                        source,
                    }),
                    Err(_) => {
                        kill_group(LABEL, &mut child).await?;
                        Err(DockerError::Timeout {
                            command: LABEL,
                            after: self.timeout,
                        })
                    }
                };
            }
            Ok(Err(source)) => DockerError::Io {
                command: LABEL,
                source,
            },
            Err(_) => DockerError::Timeout {
                command: LABEL,
                after: self.timeout,
            },
        };
        kill_group(LABEL, &mut child).await?;
        Err(error)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::Write as _;
    use std::os::unix::fs::OpenOptionsExt;
    use std::sync::{Mutex, MutexGuard, PoisonError};

    use super::*;

    /// Running a freshly written script races with forks in other threads
    /// (`ETXTBSY`), so the tests that run stubs take turns.
    static STUBS: Mutex<()> = Mutex::new(());

    /// A fake `docker` in a temp directory; the guard keeps tests that run
    /// stubs from overlapping.
    struct Stub {
        dir: tempfile::TempDir,
        _turn: MutexGuard<'static, ()>,
    }

    impl Stub {
        fn new(body: &str) -> Self {
            let turn = STUBS.lock().unwrap_or_else(PoisonError::into_inner);
            let dir = tempfile::tempdir().unwrap();
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o755)
                .open(dir.path().join("docker"))
                .unwrap();
            writeln!(file, "#!/bin/sh\n{body}").unwrap();
            file.sync_all().unwrap();
            drop(file);
            Self { dir, _turn: turn }
        }

        fn cli(&self) -> DockerCli {
            DockerCli::with_binary(self.dir.path().join("docker"))
        }

        fn path(&self, name: &str) -> PathBuf {
            self.dir.path().join(name)
        }
    }

    fn id() -> ContainerId {
        "0123456789ab".parse().unwrap()
    }

    #[test]
    fn compose_config_finds_image_and_build() {
        let raw = br#"{"name":"stack","services":{
            "app":{"image":"ghcr.io/example/app@sha256:00","environment":{"TOKEN":"s3cret"}},
            "worker":{"build":{"context":"."},"command":["run"]},
            "db":{"image":"postgres:17","ports":[{"target":5432}]}},
            "networks":{"default":{"name":"stack_default"}}}"#;
        let app = parse_config(raw, "app").unwrap();
        assert_eq!(app.image.as_deref(), Some("ghcr.io/example/app@sha256:00"));
        assert!(!app.has_build);
        let worker = parse_config(raw, "worker").unwrap();
        assert_eq!(worker.image, None);
        assert!(worker.has_build);
        assert!(matches!(
            parse_config(raw, "nope"),
            Err(DockerError::NoSuchService { service }) if service == "nope"
        ));
        assert!(matches!(
            parse_config(br#"{"name":"stack"}"#, "app"),
            Err(DockerError::NoSuchService { .. })
        ));
    }

    #[test]
    fn compose_config_error_never_contains_the_output() {
        // `image` has the wrong type, so serde would quote the offending
        // value; the secret sits in the value and in the key.
        let raw = br#"{"services":{"app":{"image":"hunter2","environment":{"SECRET=hunter2":1}},
            "other":{"image":{"SECRET":"hunter2"}}}}"#;
        let err = parse_config(raw, "app").unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
        let truncated = br#"{"services":{"app":{"image":"x","environment":{"SECRET":"hunter2"#;
        let err = parse_config(truncated, "app").unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
        let err = parse_config(b"SECRET=hunter2", "app").unwrap_err();
        assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
    }

    #[test]
    fn inspect_output_parses() {
        let raw = br#"{"image":"ghcr.io/example/app@sha256:00","status":"running","health":null,"started_at":"2026-11-01T10:00:00.123456789Z","networks":[["app_default","172.18.0.2",""],["host-only","",""],["v6","","fd00::2"],["dual","172.19.0.3","fd00::3"],null]}
"#;
        let info = parse_inspect(raw).unwrap();
        assert_eq!(info.image, "ghcr.io/example/app@sha256:00");
        assert_eq!(info.status, "running");
        assert_eq!(info.health, None);
        assert_eq!(
            info.started_at,
            "2026-11-01T10:00:00.123456789Z".parse().unwrap()
        );
        assert_eq!(info.networks.len(), 4);
        assert_eq!(
            info.networks["app_default"],
            Some("172.18.0.2".parse().unwrap())
        );
        assert_eq!(info.networks["host-only"], None);
        assert_eq!(info.networks["v6"], Some("fd00::2".parse().unwrap()));
        assert_eq!(info.networks["dual"], Some("172.19.0.3".parse().unwrap()));

        let healthy = br#"{"image":"i","status":"running","health":"healthy","started_at":"2026-11-01T10:00:00Z","networks":[null]}"#;
        let info = parse_inspect(healthy).unwrap();
        assert_eq!(info.health.as_deref(), Some("healthy"));
        assert!(info.networks.is_empty());
    }

    #[test]
    fn inspect_refuses_what_it_cannot_read() {
        for raw in [
            &br#"{"image":"i"}"#[..],
            br#"{"image":"i","status":"s","health":null,"started_at":"yesterday","networks":[null]}"#,
            br#"{"image":"i","status":"s","health":null,"started_at":"2026-11-01T10:00:00Z","networks":[["n","999.1.1.1",""],null]}"#,
            b"not json",
        ] {
            assert!(matches!(
                parse_inspect(raw),
                Err(DockerError::BadOutput { .. })
            ));
        }
    }

    #[test]
    fn commands_lose_the_compose_selection_variables() {
        let cli = DockerCli::with_binary("docker");
        let cmd = cli.command(None);
        let envs: Vec<_> = cmd.as_std().get_envs().collect();
        for var in SCRUBBED_ENV {
            assert!(
                envs.iter().any(|(k, v)| *k == var && v.is_none()),
                "{var} is not removed"
            );
        }
    }

    #[test]
    fn inspect_template_reads_no_environment() {
        assert!(!INSPECT_FORMAT.contains("Env"));
        assert!(INSPECT_FORMAT.contains("{{if .State.Health}}"));
    }

    #[test]
    fn container_id_rejects_non_hex() {
        for bad in [
            "",
            "0123456789a",
            "0123456789AB",
            "0123456789ag",
            "--all0123456",
            "0123456789ab\n",
            &"a".repeat(65),
        ] {
            assert!(bad.parse::<ContainerId>().is_err(), "{bad:?}");
        }
        assert!("0123456789ab".parse::<ContainerId>().is_ok());
        assert!("a".repeat(64).parse::<ContainerId>().is_ok());
    }

    #[test]
    fn container_output_is_zero_or_one_id() {
        assert_eq!(parse_container(b"").unwrap(), None);
        assert_eq!(parse_container(b"\n").unwrap(), None);
        assert_eq!(parse_container(b"0123456789ab\n").unwrap(), Some(id()));
        assert!(parse_container(b"0123456789ab\n0123456789ac\n").is_err());
        assert!(parse_container(b"not-an-id\n").is_err());
    }

    #[test]
    fn scanner_finds_a_needle_across_chunks_and_not_across_lines() {
        let mut s = LineScanner::new(b"fatal error");
        assert!(!s.feed(b"all fine\nfat"));
        assert!(s.feed(b"al error here\n"));

        let mut s = LineScanner::new(b"ab");
        assert!(!s.feed(b"xa\nbx\n"));
        assert!(!s.finish());

        let mut s = LineScanner::new(b"tail");
        assert!(!s.feed(b"no newline at the end, just the tai"));
        assert!(!s.finish());
        assert!(s.feed(b"l"));
    }

    #[test]
    fn scanner_scans_a_long_line_in_bounded_chunks() {
        let needle = b"NEEDLE";
        let mut s = LineScanner::new(needle);
        // A match straddling the 1 MiB boundary.
        let mut line = vec![b'x'; LINE_LIMIT - 3];
        line.extend_from_slice(needle);
        line.extend_from_slice(b"yyy");
        assert!(s.feed(&line));
        assert!(s.line.len() <= LINE_LIMIT);

        // Several limits of filler never grow the buffer.
        let mut s = LineScanner::new(needle);
        let filler = vec![b'x'; READ_CHUNK];
        for _ in 0..(3 * LINE_LIMIT / READ_CHUNK) {
            assert!(!s.feed(&filler));
            assert!(s.line.len() <= LINE_LIMIT);
        }
        assert!(s.feed(b"NEEDLE"));
    }

    #[tokio::test]
    async fn timeout_kills_the_child() {
        let stub = Stub::new("echo $$ > \"$(dirname \"$0\")/pid\"\nexec sleep 30");
        let mut cli = stub.cli();
        cli.timeout = Duration::from_millis(500);
        let started = std::time::Instant::now();
        let err = cli
            .compose_service(stub.dir.path(), "app")
            .await
            .unwrap_err();
        assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
        let pid: i32 = fs::read_to_string(stub.path("pid"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        assert!(
            rustix::process::test_kill_process(pid).is_err(),
            "the child is still running"
        );
    }

    /// Whether `pid` still exists, polling briefly for a reaper to finish.
    async fn gone(pid: i32) -> bool {
        let pid = rustix::process::Pid::from_raw(pid).unwrap();
        for _ in 0..40 {
            if rustix::process::test_kill_process(pid).is_err() {
                return true;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        false
    }

    #[tokio::test]
    async fn timeout_kills_the_whole_process_group() {
        // The stub stands for `docker`, the sleeper for the compose plugin.
        let stub = Stub::new("sleep 30 &\necho $! > \"$(dirname \"$0\")/grandchild\"\nwait");
        let mut cli = stub.cli();
        cli.long_timeout = Duration::from_millis(500);
        let err = cli.compose_up(stub.dir.path(), "app").await.unwrap_err();
        assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
        let pid: i32 = fs::read_to_string(stub.path("grandchild"))
            .unwrap()
            .trim()
            .parse()
            .unwrap();
        assert!(gone(pid).await, "the grandchild is still running");
    }

    #[tokio::test]
    async fn dropping_a_call_kills_the_whole_process_group() {
        let stub = Stub::new(
            "sleep 30 &\necho $! > \"$(dirname \"$0\")/grandchild.tmp\"\nmv \"$(dirname \"$0\")/grandchild.tmp\" \"$(dirname \"$0\")/grandchild\"\nwait",
        );
        let cli = stub.cli();
        let mut call = Box::pin(cli.compose_up(stub.dir.path(), "app"));
        let pid = loop {
            tokio::select! {
                result = &mut call => panic!("the call ended: {result:?}"),
                () = tokio::time::sleep(Duration::from_millis(20)) => {
                    if let Ok(text) = fs::read_to_string(stub.path("grandchild")) {
                        break text.trim().parse::<i32>().unwrap();
                    }
                }
            }
        };
        drop(call);
        assert!(gone(pid).await, "the grandchild is still running");
    }

    #[tokio::test(start_paused = true)]
    async fn a_command_that_outlives_its_kill_is_reported() {
        let err = await_killed("docker pull", std::future::pending::<()>(), KILL_WAIT)
            .await
            .unwrap_err();
        assert!(
            matches!(
                err,
                DockerError::Unkillable {
                    command: "docker pull"
                }
            ),
            "{err}"
        );
    }

    #[tokio::test]
    async fn a_withheld_failure_names_the_command_to_rerun() {
        let stub = Stub::new("echo 'SECRET=hunter2' >&2\nexit 1");
        let err = stub
            .cli()
            .compose_up(stub.dir.path(), "app")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("docker compose up -d --no-deps -- app in the compose directory"),
            "{text}"
        );
        assert!(!text.contains("hunter2"), "{text}");

        let err = stub
            .cli()
            .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "x")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains(
                "docker logs --since 1970-01-01T00:00:00Z --until 1970-01-01T00:00:00Z -- 0123456789ab"
            ),
            "{text}"
        );
    }

    #[tokio::test]
    async fn a_withheld_failure_leaves_out_the_project_name_and_odd_arguments() {
        let stub = Stub::new(
            "case \"$2\" in config) echo '{\"name\":\"s3cretproject\",\"services\":{}}';; *) exit 1;; esac",
        );
        let err = stub
            .cli()
            .compose_stop(stub.dir.path(), "app")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(
            text.contains("docker compose -p <project> stop -- app"),
            "{text}"
        );
        assert!(!text.contains("s3cretproject"), "{text}");

        let err = stub
            .cli()
            .compose_up(stub.dir.path(), "a$(b) c")
            .await
            .unwrap_err();
        let text = err.to_string();
        assert!(text.contains("-- <value> in the"), "{text}");
        assert!(!text.contains("$(b)"), "{text}");
    }

    #[tokio::test]
    async fn oversized_output_is_refused() {
        let stub = Stub::new("head -c 17000000 /dev/zero");
        let err = stub.cli().pull("example").await.unwrap_err();
        assert!(matches!(err, DockerError::TooMuchOutput { .. }), "{err}");
    }

    #[tokio::test]
    async fn config_failure_reports_only_the_status() {
        let stub = Stub::new("echo 'SECRET=hunter2 is invalid' >&2\nexit 3");
        let err = stub
            .cli()
            .compose_service(stub.dir.path(), "app")
            .await
            .unwrap_err();
        let text = format!("{err} {err:?}");
        assert!(matches!(err, DockerError::FailedQuietly { .. }), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains('3'), "{text}");
    }

    #[tokio::test]
    async fn compose_siblings_never_quote_stderr() {
        let stub = Stub::new(
            "echo 'failed to read .env: line 3: unterminated quoted value \"hunter2' >&2\nexit 1",
        );
        let cli = stub.cli();
        let dir = stub.dir.path();
        let errors = [
            cli.compose_up(dir, "app").await.unwrap_err(),
            cli.compose_stop(dir, "app").await.unwrap_err(),
            cli.container(dir, "app").await.unwrap_err(),
        ];
        for err in errors {
            let text = format!("{err} {err:?}");
            assert!(matches!(err, DockerError::FailedQuietly { .. }), "{text}");
            assert!(!text.contains("hunter2"), "{text}");
            assert!(text.contains("docker compose"), "{text}");
        }
    }

    #[tokio::test]
    async fn container_lookup_leaves_out_one_off_containers() {
        let stub = Stub::new(
            "case \"$2\" in config) echo '{\"name\":\"stack\"}';; *) echo \"$@\" > \"$(dirname \"$0\")/seen\"; echo 0123456789ab;; esac",
        );
        let found = stub.cli().container(stub.dir.path(), "app").await.unwrap();
        assert_eq!(found, Some(id()));
        let seen = fs::read_to_string(stub.path("seen")).unwrap();
        assert_eq!(seen.trim(), "compose -p stack ps --quiet -- app");
    }

    #[tokio::test]
    async fn logs_use_the_short_timeout() {
        let stub = Stub::new("exec sleep 30");
        let mut cli = stub.cli();
        cli.timeout = Duration::from_millis(300);
        let started = std::time::Instant::now();
        let err = cli
            .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "never")
            .await
            .unwrap_err();
        assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn exec_output_is_discarded_not_buffered() {
        let stub = Stub::new("head -c 40000000 /dev/zero\nexit 0");
        assert!(stub.cli().exec(&id(), &["true".into()]).await.unwrap());
    }

    #[tokio::test]
    async fn exec_times_out() {
        let stub = Stub::new("exec sleep 30");
        let mut cli = stub.cli();
        cli.timeout = Duration::from_millis(300);
        let err = cli.exec(&id(), &["true".into()]).await.unwrap_err();
        assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
    }

    #[tokio::test]
    async fn other_failures_quote_the_end_of_stderr() {
        let stub = Stub::new(
            "head -c 10000 /dev/zero | tr '\\0' 'a' >&2\necho 'pull access denied' >&2\nexit 1",
        );
        let err = stub.cli().pull("example").await.unwrap_err();
        let DockerError::Failed { stderr, .. } = &err else {
            panic!("{err}");
        };
        assert!(stderr.len() <= STDERR_TAIL, "{}", stderr.len());
        assert!(stderr.ends_with("pull access denied\n"));
    }

    #[tokio::test]
    async fn compose_calls_run_in_the_directory_with_plain_argv() {
        let stub = Stub::new(
            "{ pwd -P; for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"",
        );
        let work = tempfile::tempdir().unwrap();
        stub.cli().compose_up(work.path(), "app").await.unwrap();
        let seen = fs::read_to_string(stub.path("seen")).unwrap();
        let mut lines = seen.lines();
        assert_eq!(
            lines.next().unwrap(),
            work.path().canonicalize().unwrap().to_str().unwrap()
        );
        let args: Vec<&str> = lines.collect();
        assert_eq!(
            args,
            [
                "arg:compose",
                "arg:up",
                "arg:-d",
                "arg:--no-deps",
                "arg:--",
                "arg:app"
            ]
        );
    }

    #[tokio::test]
    async fn names_that_look_like_flags_are_refused_before_running() {
        let cli = DockerCli::with_binary("/nonexistent/docker");
        let dir = Path::new("/");
        assert!(matches!(
            cli.compose_up(dir, "--help").await,
            Err(DockerError::BadArgument { .. })
        ));
        assert!(matches!(
            cli.compose_stop(dir, "-x").await,
            Err(DockerError::BadArgument { .. })
        ));
        assert!(matches!(
            cli.pull("--all-tags").await,
            Err(DockerError::BadArgument { .. })
        ));
        assert!(matches!(
            cli.exec(&id(), &[]).await,
            Err(DockerError::BadArgument { .. })
        ));
        let since = Timestamp::UNIX_EPOCH;
        let long = "x".repeat(LOG_PATTERN_LIMIT + 1);
        for needle in ["", "a\nb", long.as_str()] {
            assert!(matches!(
                cli.logs_contain(&id(), since, since, needle).await,
                Err(DockerError::BadArgument { .. })
            ));
        }
    }

    #[tokio::test]
    async fn exec_passes_dashed_arguments_to_the_command() {
        let stub = Stub::new(
            "{ for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"\nexit 1",
        );
        let ok = stub
            .cli()
            .exec(&id(), &["ls".into(), "-la".into()])
            .await
            .unwrap();
        assert!(!ok);
        let seen = fs::read_to_string(stub.path("seen")).unwrap();
        assert_eq!(
            seen.lines().collect::<Vec<_>>(),
            [
                "arg:exec",
                "arg:--",
                "arg:0123456789ab",
                "arg:ls",
                "arg:-la"
            ]
        );
    }

    #[tokio::test]
    async fn logs_on_either_stream_are_scanned() {
        let since: Timestamp = "2026-11-01T10:00:00.9Z".parse().unwrap();
        let until: Timestamp = "2026-11-01T10:00:30.1Z".parse().unwrap();
        let on_stderr = Stub::new(
            "echo \"$@\" > \"$(dirname \"$0\")/seen\"\necho out line\necho 'panic: boom' >&2",
        );
        let cli = on_stderr.cli();
        assert!(
            cli.logs_contain(&id(), since, until, "panic:")
                .await
                .unwrap()
        );
        assert!(
            !cli.logs_contain(&id(), since, until, "absent")
                .await
                .unwrap()
        );
        let seen = fs::read_to_string(on_stderr.path("seen")).unwrap();
        assert_eq!(
            seen.trim(),
            "logs --since 2026-11-01T10:00:00Z --until 2026-11-01T10:00:31Z -- 0123456789ab"
        );

        drop(on_stderr);
        let on_stdout = Stub::new("echo 'listening on :8080'");
        assert!(
            on_stdout
                .cli()
                .logs_contain(&id(), since, until, "listening")
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn a_log_match_stops_and_kills_the_reader() {
        let stub = Stub::new("echo 'ready'\nexec sleep 30");
        let started = std::time::Instant::now();
        assert!(
            stub.cli()
                .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "ready")
                .await
                .unwrap()
        );
        assert!(started.elapsed() < Duration::from_secs(10));
    }

    #[tokio::test]
    async fn a_failing_logs_command_reports_only_its_status() {
        let stub = Stub::new("echo 'Error: No such container: SECRET=hunter2' >&2\nexit 1");
        let err = stub
            .cli()
            .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "x")
            .await
            .unwrap_err();
        assert!(matches!(err, DockerError::FailedQuietly { .. }), "{err}");
        assert!(!format!("{err} {err:?}").contains("hunter2"));
    }

    /// Tests against a real Docker daemon: `cargo test -p landfall-agent
    /// -- --ignored docker`.
    mod real {
        use std::process::Command as StdCommand;

        use super::*;
        use crate::testing::{ComposeProject, TEST_IMAGE};

        /// Two long-running services on the project's network, one with a
        /// healthcheck.
        async fn project(cli: &DockerCli) -> ComposeProject {
            let services = format!(
                "  plain:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n    networks: [net]\n  healthy:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n    networks: [net]\n    healthcheck:\n      test: [CMD, 'true']\n      interval: 1s\n"
            );
            ComposeProject::new(cli, &services).await
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_inspect_reads_what_the_template_asks_for() {
            let cli = DockerCli::new();
            let project = project(&cli).await;
            let before = Timestamp::now();
            cli.compose_up(project.path(), "plain").await.unwrap();
            cli.compose_up(project.path(), "healthy").await.unwrap();

            let svc = cli.compose_service(project.path(), "plain").await.unwrap();
            assert_eq!(svc.image.as_deref(), Some(TEST_IMAGE));
            assert!(!svc.has_build);

            let plain = cli
                .container(project.path(), "plain")
                .await
                .unwrap()
                .unwrap();
            let info = cli.inspect(&plain).await.unwrap();
            // Started by digest: the container keeps the digest reference.
            assert_eq!(info.image, TEST_IMAGE);
            assert_eq!(info.status, "running");
            assert_eq!(info.health, None);
            assert!(
                info.started_at
                    >= before
                        .checked_sub(jiff::SignedDuration::from_secs(5))
                        .unwrap()
            );
            assert!(info.started_at <= Timestamp::now());
            let net = format!("{}-net", project.name);
            assert_eq!(info.networks.len(), 1, "{:?}", info.networks);
            assert!(
                matches!(info.networks[&net], Some(IpAddr::V4(_))),
                "{:?}",
                info.networks
            );

            let healthy = cli
                .container(project.path(), "healthy")
                .await
                .unwrap()
                .unwrap();
            let mut health = None;
            for _ in 0..30 {
                health = cli.inspect(&healthy).await.unwrap().health;
                if health.as_deref() == Some("healthy") {
                    break;
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
            assert_eq!(health.as_deref(), Some("healthy"));

            assert!(cli.exec(&plain, &["true".into()]).await.unwrap());
            assert!(!cli.exec(&plain, &["false".into()]).await.unwrap());
            assert!(
                !cli.logs_contain(&plain, before, Timestamp::now(), "never-logged")
                    .await
                    .unwrap()
            );

            cli.compose_stop(project.path(), "plain").await.unwrap();
            assert_eq!(cli.container(project.path(), "plain").await.unwrap(), None);
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_config_ps_and_stop_work_on_a_service_without_an_image() {
            let cli = DockerCli::new();
            let project = project(&cli).await;
            cli.compose_up(project.path(), "plain").await.unwrap();
            let id = cli
                .container(project.path(), "plain")
                .await
                .unwrap()
                .unwrap();
            // The override of a failed first deploy has been taken back out.
            fs::write(
                project.path().join("compose.yaml"),
                format!(
                    "name: {}\nservices:\n  plain:\n    command: [sleep, '300']\n    stop_grace_period: 1s\n",
                    project.name
                ),
            )
            .unwrap();

            let svc = cli.compose_service(project.path(), "plain").await.unwrap();
            assert_eq!(svc.image, None);
            assert!(!svc.has_build);
            assert_eq!(
                cli.container(project.path(), "plain")
                    .await
                    .unwrap()
                    .as_ref(),
                Some(&id)
            );

            cli.compose_stop(project.path(), "plain").await.unwrap();
            assert_eq!(cli.inspect(&id).await.unwrap().status, "exited");
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_ps_ignores_one_off_containers() {
            let cli = DockerCli::new();
            let project = project(&cli).await;
            assert_eq!(cli.container(project.path(), "plain").await.unwrap(), None);
            cli.compose_up(project.path(), "plain").await.unwrap();
            let service = cli
                .container(project.path(), "plain")
                .await
                .unwrap()
                .unwrap();

            let run = StdCommand::new("docker")
                .args(["compose", "run", "-d", "--no-deps", "plain", "sleep", "300"])
                .current_dir(project.path())
                .output()
                .unwrap();
            assert!(run.status.success());
            assert_eq!(project.all_containers().len(), 2);

            assert_eq!(
                cli.container(project.path(), "plain").await.unwrap(),
                Some(service)
            );
        }
    }
}
