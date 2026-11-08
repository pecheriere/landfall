//! That a stderr that takes nothing, as a stalled journald or log driver leaves it, can't stop the
//! controller answering or stopping. Its stderr here is a pipe nobody reads, filled to the brim
//! once it has said where it listens, and it is then sent more refusals than it has threads, each
//! of which it logs.
//!
//! The controller is this test binary run again as `cli::run_watching_within`, as in
//! `serve_upkeep`: `main` but for the watcher's source.

#![cfg(test)]

use std::io::{BufRead as _, BufReader, PipeReader, PipeWriter, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use clap::Parser as _;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::RunCandidate;
use landfall_origin::fetch::ListedTag;
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use landfall_server::agent_api::Limits;
use landfall_server::cli::{self, Cli};
use serde_json::json;

const CHILD_ARGS: &str = "LANDFALL_STUCK_STDERR_CHILD";
/// A stuck wait ends here, saying what it was waiting for. Long, so that a slow machine can't fail
/// these, and only a hung test ever waits it out.
const PATIENCE: Duration = Duration::from_mins(5);
/// What the guide gives a service manager to wait for it: `TimeoutStopSec=30`.
const STOP_TIMEOUT: Duration = Duration::from_secs(30);
/// How long an answer may take: far longer than any takes, and short of nextest's limit, so that a
/// request left hanging fails saying so.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// More refusals than any machine running this has threads, and more than the capped log's 60 a
/// minute, so that every line it allows is written.
const REFUSALS: usize = 100;

/// A source with nothing to say.
struct NoReleases;

impl landfall_server::watcher::ReleaseSource for NoReleases {
    fn prepare(&self) -> impl Future<Output = Result<(), String>> + Send {
        std::future::ready(Ok(()))
    }

    fn tags(
        &self,
        _: &DeploymentId,
    ) -> impl Future<Output = Result<Vec<ListedTag>, ReleaseError>> + Send {
        std::future::ready(Ok(Vec::new()))
    }

    async fn verify(
        &self,
        _: &DeploymentId,
        _: &ReleaseTag,
    ) -> Result<ReleaseOrigin, ReleaseError> {
        std::future::pending().await
    }

    async fn attested_digests(
        &self,
        _: &DeploymentId,
        _: &ReleaseTag,
        _: &CommitSha,
        _: &ImageDigest,
    ) -> Result<Vec<RunCandidate>, ReleaseError> {
        std::future::pending().await
    }
}

/// Not a test: the controller, as this file's test runs it. It does nothing without its variable.
#[test]
#[ignore = "not a test: the test here runs this as a process"]
fn child_process() {
    if let Ok(args) = std::env::var(CHILD_ARGS) {
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let cli = Cli::parse_from(std::iter::once("landfall-server".to_owned()).chain(args));
        let (limits, drain) = (Limits::default(), Duration::from_secs(5));
        let every = Duration::from_hours(1);
        let code = cli::run_watching_within(cli, Arc::new(NoReleases), every, limits, drain);
        std::process::exit(code.into());
    }
}

struct Controller {
    child: Child,
    address: SocketAddr,
    /// Held, and never read from again once it has said where it listens: dropping it would make
    /// each write fail at once rather than wait.
    unread: BufReader<PipeReader>,
}

impl Controller {
    /// Starts it with its stderr a pipe, and gives it with the pipe's other writing end.
    fn start(dir: &Path) -> (Self, PipeWriter) {
        let config = dir.join("fleet.toml");
        std::fs::write(&config, "").unwrap();
        let args = json!([
            "serve",
            "--config",
            config,
            "--db",
            dir.join("c.db"),
            "--listen",
            "127.0.0.1:0"
        ]);
        let (reader, writer) = std::io::pipe().unwrap();
        let ours = writer.try_clone().unwrap();
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_process", "--ignored", "--nocapture"])
            .env(CHILD_ARGS, args.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(writer)
            .spawn()
            .unwrap();
        let mut controller = Self {
            child,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            unread: BufReader::new(reader),
        };
        let mut line = String::new();
        let started = Instant::now();
        loop {
            line.clear();
            let read = controller.unread.read_line(&mut line).unwrap();
            assert!(read > 0, "it ended without saying where it listens");
            if let Some(address) = line
                .trim_end()
                .strip_prefix("landfall-server: listening on ")
            {
                controller.address = address.parse().unwrap();
                break;
            }
            assert!(started.elapsed() < PATIENCE, "the controller did not start");
        }
        (controller, ours)
    }

    /// SIGTERM.
    fn stop(&self) {
        let stopped = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(stopped.success());
    }

    /// Waits up to `limit` for it to end.
    fn exit_status_within(&mut self, limit: Duration) -> Option<ExitStatus> {
        let started = Instant::now();
        while started.elapsed() < limit {
            if let Some(status) = self.child.try_wait().unwrap() {
                return Some(status);
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        None
    }

    /// A GET, with no credentials. Gives the answer's status, or fails if none comes in time.
    fn get(&self, path: &str) -> u16 {
        let mut stream = TcpStream::connect(self.address).unwrap();
        stream.set_read_timeout(Some(ANSWER_TIMEOUT)).unwrap();
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: landfall.example\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
        let mut answer = String::new();
        stream
            .read_to_string(&mut answer)
            .unwrap_or_else(|error| panic!("no answer to {path}: {error}"));
        answer.split_whitespace().nth(1).unwrap().parse().unwrap()
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// Writes into the pipe until it takes no more, a byte at a time so that it is full to the last
/// byte, and leaves a thread blocked on the next. Returns once nothing has gone in for a while.
fn fill(mut pipe: PipeWriter) {
    let written = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&written);
    std::thread::spawn(move || {
        while pipe.write_all(b".").is_ok() {
            counted.fetch_add(1, Ordering::Relaxed);
        }
    });
    let started = Instant::now();
    let mut seen = usize::MAX;
    loop {
        std::thread::sleep(Duration::from_millis(300));
        let now = written.load(Ordering::Relaxed);
        if now == seen {
            return;
        }
        seen = now;
        assert!(started.elapsed() < PATIENCE, "the pipe never filled");
    }
}

#[test]
fn a_stderr_that_takes_nothing_neither_stops_answers_nor_holds_up_stopping() {
    let dir = tempfile::tempdir().unwrap();
    let (mut controller, pipe) = Controller::start(dir.path());
    fill(pipe);

    for _ in 0..REFUSALS {
        let status = controller.get("/api/v1/approvals");
        assert!(matches!(status, 401 | 429), "{status}");
    }
    assert_eq!(controller.get("/healthz"), 200);

    controller.stop();
    let status = controller
        .exit_status_within(STOP_TIMEOUT)
        .expect("it did not stop in the time a service manager gives it");
    assert!(status.success(), "{status}");
}
