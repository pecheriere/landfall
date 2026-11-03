//! That `serve` itself writes down counted failures: each interval, and when it stops. Failures
//! go in the audit log by this and nothing else, so a test of the task alone wouldn't show it.
//!
//! The controller is this test binary run again as `cli::run_watching_within`, as in the agent's
//! end-to-end tests: `main` but for the watcher's source, and for the clocks a request runs
//! against, as these tests hold one open for as long as a loaded machine makes them. One test runs
//! the real `cli::run`, for the real ones.

#![cfg(test)]

use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::{SocketAddr, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::{Arc, mpsc};
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser as _;
use landfall_approval::{Assertion, Ceremony, SoftwareAuthenticator};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::RunCandidate;
use landfall_origin::fetch::ListedTag;
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use landfall_server::agent_api::Limits;
use landfall_server::cli::{self, Cli};
use landfall_server::serve::ServeOptions;
use landfall_server::watcher::ReleaseSource;
use serde_json::{Value, json};
use sqlx::SqlitePool;

const CHILD_ARGS: &str = "LANDFALL_UPKEEP_CHILD";
const CHILD_INTERVAL_MS: &str = "LANDFALL_UPKEEP_INTERVAL_MS";
const CHILD_IS_REAL: &str = "LANDFALL_UPKEEP_REAL";
/// A stuck wait ends here, saying what it was waiting for. On a starved machine, starting or
/// stopping a process has been seen to take over a minute. It's long so that a slow machine can't
/// fail these, and only a hung test ever waits it out.
const PATIENCE: Duration = Duration::from_mins(5);
/// What a request's clocks are set to here, as nothing in these tests is about running them out.
const NO_HURRY: Duration = Duration::from_mins(10);
const RP_ID: &str = "landfall.example";
const ORIGIN: &str = "https://landfall.example";

/// A source with nothing to say.
struct NoReleases;

impl ReleaseSource for NoReleases {
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

/// Not a test: the controller, as this file's tests run it. It does nothing without its variable.
#[test]
#[ignore = "not a test: the tests here run this as a process"]
fn child_process() {
    if let Ok(args) = std::env::var(CHILD_ARGS) {
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let every: u64 = std::env::var(CHILD_INTERVAL_MS).unwrap().parse().unwrap();
        let cli = Cli::parse_from(std::iter::once("landfall-server".to_owned()).chain(args));
        let code = if std::env::var_os(CHILD_IS_REAL).is_some() {
            cli::run(cli)
        } else {
            let limits = Limits {
                body_timeout: NO_HURRY,
                request_timeout: NO_HURRY,
                ..Limits::default()
            };
            let every = Duration::from_millis(every);
            cli::run_watching_within(cli, Arc::new(NoReleases), every, limits, NO_HURRY)
        };
        std::process::exit(code.into());
    }
}

struct Controller {
    child: Child,
    address: SocketAddr,
    db: PathBuf,
}

impl Controller {
    fn start(dir: &Path, key: &SoftwareAuthenticator, every_ms: u64) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command.env(CHILD_INTERVAL_MS, every_ms.to_string());
        Self::start_as(command, dir, key)
    }

    /// The real `serve`, which is what's documented, and which has nothing to watch here.
    fn start_real(dir: &Path, key: &SoftwareAuthenticator) -> Self {
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .env(CHILD_IS_REAL, "1")
            .env(CHILD_INTERVAL_MS, "0")
            .env_remove("GITHUB_TOKEN");
        Self::start_as(command, dir, key)
    }

    fn start_as(mut command: Command, dir: &Path, key: &SoftwareAuthenticator) -> Self {
        let config = dir.join("fleet.toml");
        let text = format!(
            "[approval]\nrp_id = \"{RP_ID}\"\norigin = \"{ORIGIN}\"\n\n[approvers]\n\
             alice = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
            URL_SAFE_NO_PAD.encode(key.credential_id()),
            URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
        );
        std::fs::write(&config, text).unwrap();
        // Port 0, and it says which it got: no other process can take a port from under it.
        let args = json!([
            "serve",
            "--config",
            config,
            "--db",
            dir.join("c.db"),
            "--listen",
            "127.0.0.1:0"
        ]);
        let mut child = command
            .args(["--exact", "child_process", "--ignored", "--nocapture"])
            .env(CHILD_ARGS, args.to_string())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let said = BufReader::new(child.stderr.take().unwrap());
        // Made before the wait, so that a panic in it still kills the child. The address comes
        // once it is listening and hears signals.
        let mut controller = Self {
            child,
            address: SocketAddr::from(([127, 0, 0, 1], 0)),
            db: dir.join("c.db"),
        };
        let (found, listening) = mpsc::channel();
        // Keeps reading to the end, so that the child's writes to stderr never block.
        std::thread::spawn(move || {
            for line in said.lines().map_while(Result::ok) {
                drop(writeln!(std::io::stderr(), "{line}"));
                if let Some(address) = line.strip_prefix("landfall-server: listening on ") {
                    let _ = found.send(address.parse::<SocketAddr>().unwrap());
                }
            }
        });
        controller.address = listening
            .recv_timeout(PATIENCE)
            .expect("the controller did not start");
        controller
    }

    /// SIGTERM.
    fn stop(&self) {
        let stopped = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .unwrap();
        assert!(stopped.success());
    }

    /// Waits for it to end, or fails saying so, rather than holding up the whole run.
    fn exit_status(&mut self) -> ExitStatus {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(started.elapsed() < PATIENCE, "it did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// A POST from the configured origin. Gives the status and the body.
    fn post(&self, path: &str, body: &Value) -> (u16, Value) {
        let body = body.to_string();
        let mut stream = TcpStream::connect(self.address).unwrap();
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: {RP_ID}\r\nOrigin: {ORIGIN}\r\nConnection: close\r\n\
             Content-Length: {}\r\n\r\n{body}",
            body.len(),
        )
        .unwrap();
        let mut answer = String::new();
        stream.read_to_string(&mut answer).unwrap();
        let status = answer.split_whitespace().nth(1).unwrap().parse().unwrap();
        let (_, payload) = answer.split_once("\r\n\r\n").unwrap();
        (status, serde_json::from_str(payload).unwrap())
    }

    /// One signature that doesn't verify, on `key`'s credential.
    fn fail_a_sign_in(&self, key: &SoftwareAuthenticator) {
        let body = self.forged_finish(key);
        let (status, answer) = self.post("/sign-in/finish", &body);
        assert_eq!(status, 403, "{answer}");
    }

    /// The body of a finish, for a new challenge, with a signature that doesn't verify.
    fn forged_finish(&self, key: &SoftwareAuthenticator) -> Value {
        let (status, begun) = self.post("/sign-in/begin", &json!({}));
        assert_eq!(status, 200, "{begun}");
        let text = begun["publicKey"]["challenge"].as_str().unwrap();
        let challenge = URL_SAFE_NO_PAD.decode(text).unwrap();
        let mut forged = Ceremony::new(RP_ID, ORIGIN, &challenge);
        forged.credential_id = Some(key.credential_id().to_vec());
        let assertion = SoftwareAuthenticator::es256()
            .unwrap()
            .assertion(&forged)
            .unwrap();
        finish_body(text, &assertion)
    }
}

/// The body of a finish.
fn finish_body(challenge: &str, assertion: &Assertion) -> Value {
    let encode = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
    json!({
        "challenge": challenge,
        "assertion": {
            "credential_id": encode(&assertion.credential_id),
            "authenticator_data": encode(&assertion.authenticator_data),
            "client_data_json": encode(&assertion.client_data_json),
            "signature": encode(&assertion.signature),
        },
    })
}

impl Drop for Controller {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// The details of every audit row of this kind.
async fn rows(db: &Path, kind: &str) -> Vec<Value> {
    let pool = SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_events WHERE kind = ? ORDER BY seq")
            .bind(kind)
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    details
        .iter()
        .map(|detail| serde_json::from_str(detail).unwrap())
        .collect()
}

/// The `attempts` of every `sign_in_refused` row.
async fn attempts(db: &Path) -> Vec<i64> {
    rows(db, "sign_in_refused")
        .await
        .iter()
        .map(|detail| detail["attempts"].as_i64().unwrap())
        .collect()
}

/// A request the server has begun on, in the middle of reading its body. `Expect: 100-continue`
/// makes the server say so at the moment its handler first asks for the body.
fn a_request_under_way(controller: &Controller, body: &str) -> TcpStream {
    let mut stream = TcpStream::connect(controller.address).unwrap();
    stream.set_read_timeout(Some(PATIENCE)).unwrap();
    write!(
        stream,
        "POST /sign-in/finish HTTP/1.1\r\nHost: {RP_ID}\r\nOrigin: {ORIGIN}\r\n\
         Connection: close\r\nExpect: 100-continue\r\nContent-Length: {}\r\n\r\n",
        body.len(),
    )
    .unwrap();
    stream.flush().unwrap();
    let mut said = Vec::new();
    let mut byte = [0];
    while !said.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        said.push(byte[0]);
    }
    assert!(said.starts_with(b"HTTP/1.1 100"), "{said:?}");
    stream
}

/// Stops it, and waits until the upkeep task has had its last look, which is what it does with the
/// failure counted here. From then on, only what `serve` does after draining can write anything.
async fn stop_and_see_the_tasks_last_look(controller: &Controller, key: &SoftwareAuthenticator) {
    controller.fail_a_sign_in(key);
    controller.stop();
    let db = controller.db.clone();
    let started = Instant::now();
    while attempts(&db).await.is_empty() {
        assert!(started.elapsed() < PATIENCE, "the task never wrote it");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Sends the rest of a request under way, and gives the answer.
fn finish(mut stream: TcpStream, body: &str) -> String {
    stream.write_all(body.as_bytes()).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    answer
}

/// The body of a finish that `key` really signed, for a new challenge.
fn signed_finish(controller: &Controller, key: &SoftwareAuthenticator) -> Value {
    let (status, begun) = controller.post("/sign-in/begin", &json!({}));
    assert_eq!(status, 200, "{begun}");
    let text = begun["publicKey"]["challenge"].as_str().unwrap();
    let challenge = URL_SAFE_NO_PAD.decode(text).unwrap();
    let assertion = key
        .assertion(&Ceremony::new(RP_ID, ORIGIN, &challenge))
        .unwrap();
    finish_body(text, &assertion)
}

#[tokio::test]
async fn serve_writes_failures_down_each_interval() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let controller = Controller::start(dir.path(), &key, 50);
    controller.fail_a_sign_in(&key);
    let started = Instant::now();
    while attempts(&dir.path().join("c.db")).await.is_empty() {
        assert!(started.elapsed() < PATIENCE, "nothing was written");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    drop(controller);
}

#[tokio::test]
async fn serve_writes_failures_down_when_it_stops() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let mut controller = Controller::start(dir.path(), &key, 3_600_000);
    controller.fail_a_sign_in(&key);
    controller.fail_a_sign_in(&key);
    assert_eq!(attempts(&dir.path().join("c.db")).await, [] as [i64; 0]);

    controller.stop();
    let status = controller.exit_status();
    assert!(status.success(), "{status}");
    assert_eq!(attempts(&dir.path().join("c.db")).await, [2]);
}

/// A request still running as stopping begins finishes in the drain, after the upkeep task has
/// had its last look. What it counts mustn't be lost, as it could be a barred key's.
#[tokio::test]
async fn serve_writes_down_a_failure_counted_in_the_drain() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let mut controller = Controller::start(dir.path(), &key, 3_600_000);
    let body = controller.forged_finish(&key).to_string();
    let stream = a_request_under_way(&controller, &body);
    stop_and_see_the_tasks_last_look(&controller, &key).await;

    let answer = finish(stream, &body);
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

    let status = controller.exit_status();
    assert!(status.success(), "{status}");
    // The one the task saw, and the one it couldn't have.
    assert_eq!(attempts(&dir.path().join("c.db")).await, [1, 1]);
}

/// The same for a call over its budget. A sign-in is the one that gets that far with its body read:
/// it spends only after the signature is checked.
#[tokio::test]
async fn serve_writes_down_a_call_dropped_in_the_drain() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let mut controller = Controller::start(dir.path(), &key, 3_600_000);
    for _ in 0..10 {
        let body = signed_finish(&controller, &key);
        let (status, answer) = controller.post("/sign-in/finish", &body);
        assert_eq!(status, 200, "{answer}");
    }
    let body = signed_finish(&controller, &key).to_string();
    let stream = a_request_under_way(&controller, &body);
    stop_and_see_the_tasks_last_look(&controller, &key).await;
    assert_eq!(rows(&controller.db, "access_throttled").await.len(), 0);

    let answer = finish(stream, &body);
    assert!(answer.starts_with("HTTP/1.1 429"), "{answer}");

    let status = controller.exit_status();
    assert!(status.success(), "{status}");
    let throttled = rows(&controller.db, "access_throttled").await;
    assert_eq!(throttled.len(), 1, "{throttled:?}");
    assert_eq!(throttled[0]["dropped"], 1);
    assert_eq!(throttled[0]["by"]["via"], "sign_in");
}

/// A drain it's given is the one it keeps: a request is answered past the one it would have had.
#[tokio::test]
async fn serve_gives_a_request_the_drain_it_is_told() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let mut controller = Controller::start(dir.path(), &key, 3_600_000);
    let body = controller.forged_finish(&key).to_string();
    let stream = a_request_under_way(&controller, &body);

    controller.stop();
    std::thread::sleep(ServeOptions::default().drain_timeout + Duration::from_secs(1));

    let answer = finish(stream, &body);
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");
    assert!(controller.exit_status().success());
}

/// The five seconds `docs/operations.md` gives requests in flight, in the real `serve`, which is
/// nothing else in these tests. A request whose body doesn't come is also out by its own clock, at
/// which it's answered, so on a machine so loaded that it got most of the way there before the
/// signal, that's the sooner it can stop.
#[tokio::test]
async fn the_real_serve_gives_a_request_five_seconds_and_stops() {
    let dir = tempfile::tempdir().unwrap();
    let key = SoftwareAuthenticator::es256().unwrap();
    let mut controller = Controller::start_real(dir.path(), &key);
    let body = controller.forged_finish(&key).to_string();
    let began = Instant::now();
    let mut stream = a_request_under_way(&controller, &body);

    controller.stop();
    let stopping = Instant::now();
    let status = controller.exit_status();
    let took = stopping.elapsed();

    assert!(status.success(), "{status}");
    let drain = Duration::from_secs(5);
    let body_runs_out = Limits::default()
        .body_timeout
        .saturating_sub(stopping.duration_since(began));
    assert!(took >= drain.min(body_runs_out), "only {took:?}");
    // With time to spare, the drain was the first to end, and that gets no answer. A longer drain
    // would have let the body's clock answer.
    if body_runs_out > drain + Duration::from_secs(4) {
        let mut answer = String::new();
        drop(stream.read_to_string(&mut answer));
        assert_eq!(answer, "", "after {took:?}");
    }
}
