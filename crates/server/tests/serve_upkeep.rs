//! That `serve` itself writes down counted failures: each interval, and when it stops. Failures
//! go in the audit log by this and nothing else, so a test of the task alone wouldn't show it.
//!
//! The controller is this test binary run again as `cli::run_watching`, as in the agent's
//! end-to-end tests: `main` but for the watcher's source.

#![cfg(test)]

use std::io::{Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser as _;
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::RunCandidate;
use landfall_origin::fetch::ListedTag;
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use landfall_server::cli::{self, Cli};
use landfall_server::watcher::ReleaseSource;
use serde_json::{Value, json};
use sqlx::SqlitePool;

const CHILD_ARGS: &str = "LANDFALL_UPKEEP_CHILD";
const CHILD_INTERVAL_MS: &str = "LANDFALL_UPKEEP_INTERVAL_MS";
/// Shorter than nextest's limit, so that a failure says what it was waiting for.
const PATIENCE: Duration = Duration::from_secs(20);
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
        let code = cli::run_watching(cli, Arc::new(NoReleases), Duration::from_millis(every));
        std::process::exit(code.into());
    }
}

struct Controller {
    child: Child,
    address: SocketAddr,
}

impl Controller {
    fn start(dir: &Path, key: &SoftwareAuthenticator, every_ms: u64) -> Self {
        let config = dir.join("fleet.toml");
        let text = format!(
            "[approval]\nrp_id = \"{RP_ID}\"\norigin = \"{ORIGIN}\"\n\n[approvers]\n\
             alice = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
            URL_SAFE_NO_PAD.encode(key.credential_id()),
            URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
        );
        std::fs::write(&config, text).unwrap();
        let port = TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let address = SocketAddr::from(([127, 0, 0, 1], port));
        let args = json!([
            "serve",
            "--config",
            config,
            "--db",
            dir.join("c.db"),
            "--listen",
            address
        ]);
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_process", "--ignored", "--nocapture"])
            .env(CHILD_ARGS, args.to_string())
            .env(CHILD_INTERVAL_MS, every_ms.to_string())
            .spawn()
            .unwrap();
        // Made before the wait, so that a panic in it still kills the child.
        let controller = Self { child, address };
        let started = Instant::now();
        while TcpStream::connect(address).is_err() {
            assert!(started.elapsed() < PATIENCE, "the controller did not start");
            std::thread::sleep(Duration::from_millis(20));
        }
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
        let encode = |bytes: &[u8]| URL_SAFE_NO_PAD.encode(bytes);
        json!({
            "challenge": text,
            "assertion": {
                "credential_id": encode(&assertion.credential_id),
                "authenticator_data": encode(&assertion.authenticator_data),
                "client_data_json": encode(&assertion.client_data_json),
                "signature": encode(&assertion.signature),
            },
        })
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        drop(self.child.kill());
        drop(self.child.wait());
    }
}

/// The `attempts` of every `sign_in_refused` row.
async fn attempts(db: &Path) -> Vec<i64> {
    let pool = SqlitePool::connect(&format!("sqlite://{}", db.display()))
        .await
        .unwrap();
    let details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_events WHERE kind = 'sign_in_refused'")
            .fetch_all(&pool)
            .await
            .unwrap();
    pool.close().await;
    details
        .iter()
        .map(|detail| {
            let detail: Value = serde_json::from_str(detail).unwrap();
            detail["attempts"].as_i64().unwrap()
        })
        .collect()
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
    let status = controller.child.wait().unwrap();
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
    let (first, rest) = body.split_at(body.len() / 2);

    let mut stream = TcpStream::connect(controller.address).unwrap();
    write!(
        stream,
        "POST /sign-in/finish HTTP/1.1\r\nHost: {RP_ID}\r\nOrigin: {ORIGIN}\r\n\
         Connection: close\r\nContent-Length: {}\r\n\r\n{first}",
        body.len(),
    )
    .unwrap();
    stream.flush().unwrap();
    // Long enough for the request to be under way and, once stopped, for the task to finish.
    tokio::time::sleep(Duration::from_millis(200)).await;
    controller.stop();
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(attempts(&dir.path().join("c.db")).await, [] as [i64; 0]);

    stream.write_all(rest.as_bytes()).unwrap();
    let mut answer = String::new();
    stream.read_to_string(&mut answer).unwrap();
    assert!(answer.starts_with("HTTP/1.1 403"), "{answer}");

    let status = controller.child.wait().unwrap();
    assert!(status.success(), "{status}");
    assert_eq!(attempts(&dir.path().join("c.db")).await, [1]);
}
