//! The pages in a real browser, under their real headers: `ceremonies.mjs` drives Chromium and
//! its virtual authenticator through registration, sign-in, cancelling, approving and sign-out.
//! It is the one way to see that the pages work under their policy.
//!
//! It needs Node, `openssl` and Playwright, so it is `#[ignore]`d and CI doesn't run it:
//!
//! ```sh
//! npm ci --prefix crates/server/tests/browser --ignore-scripts
//! npx --prefix crates/server/tests/browser playwright install chromium
//! cargo test -p landfall-server --test browser --locked -- --ignored browser_ceremonies --nocapture
//! ```
//!
//! Set `LANDFALL_BROWSER_CHANNEL=chrome` to use an installed Chrome instead of downloading a
//! browser. A virtual authenticator isn't a real passkey: `docs/operations.md` lists what this
//! can't answer.
//!
//! The controller is this test binary run again as `cli::run_watching`, which is the whole of
//! what `main` does but for the watcher's source: no test repository signs real releases, and
//! the real source would hold every deployment with no network. `passkey-invite` is the real
//! binary. What the watcher would have recorded is written by the store's own functions.

#![cfg(test)]

use std::io::{BufRead as _, BufReader, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser as _;
use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};
use landfall_core::release::RunCandidate;
use landfall_origin::fetch::{ComparePage, CompareStatus, ListedTag};
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use landfall_server::cli::{self, Cli};
use landfall_server::store::{ReleaseDecision, Seen, Store};
use landfall_server::watcher::ReleaseSource;
use serde_json::json;
use sqlx::SqlitePool;

const CHILD_ARGS: &str = "LANDFALL_BROWSER_CHILD";
const PATIENCE: Duration = Duration::from_secs(30);

/// A source with nothing new to say.
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

    fn compare_page(
        &self,
        _: &DeploymentId,
        _: &CommitSha,
        _: &CommitSha,
        _: u32,
    ) -> impl Future<Output = Result<ComparePage, ReleaseError>> + Send {
        std::future::ready(Ok(ComparePage::Listed {
            status: CompareStatus::Ahead,
            total: 0,
            commits: Vec::new(),
            rate_remaining: Some(5000),
        }))
    }

    fn has_github_token(&self) -> bool {
        false
    }
}

/// Not a test: the controller, as [`Controller::start`] runs it. It does nothing without its
/// variable, so that `--ignored` finds nothing wrong with it.
#[test]
#[ignore = "not a test: the browser test runs this as a process"]
fn child_process() {
    if let Ok(args) = std::env::var(CHILD_ARGS) {
        let args: Vec<String> = serde_json::from_str(&args).unwrap();
        let cli = Cli::parse_from(std::iter::once("landfall-server".to_owned()).chain(args));
        let code = cli::run_watching(cli, Arc::new(NoReleases), Duration::from_hours(1));
        std::process::exit(code.into());
    }
}

/// A controller running over `files`, killed when it goes out of scope.
struct Controller(Child);

impl Controller {
    fn start(files: &Files) -> Self {
        let args = json!([
            "serve",
            "--config",
            files.config,
            "--db",
            files.db,
            "--listen",
            files.backend,
        ]);
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "child_process", "--ignored", "--nocapture"])
            .env(CHILD_ARGS, args.to_string())
            .spawn()
            .unwrap();
        // Made before the wait, so that a panic in it still kills the child.
        let controller = Self(child);
        let started = Instant::now();
        while TcpStream::connect(files.backend).is_err() {
            assert!(started.elapsed() < PATIENCE, "the controller did not start");
            std::thread::sleep(Duration::from_millis(50));
        }
        controller
    }
}

impl Drop for Controller {
    fn drop(&mut self) {
        drop(self.0.kill());
        drop(self.0.wait());
    }
}

struct Files {
    _dir: tempfile::TempDir,
    config: PathBuf,
    db: PathBuf,
    backend: SocketAddr,
    proxy_port: u16,
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn approval_section(proxy_port: u16) -> String {
    format!("[approval]\nrp_id = \"localhost\"\norigin = \"https://localhost:{proxy_port}\"\n")
}

/// With the approver's line the page gave, and a deployment they may ask for and approve.
fn full_config(proxy_port: u16, approver_line: &str) -> String {
    format!(
        r#"{}
[approvers]
{approver_line}

[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1, owner_id = 2 }}
host = "host-a"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = ["alice"] }}
checks = ["container-healthy"]

[[grant]]
principal = "alice"
deployments = ["app/prod"]
can = ["view", "request", "approve"]
"#,
        approval_section(proxy_port),
    )
}

/// What a host and the watcher would have said: `v1.0.0` runs, and `v1.1.0` is verified.
async fn seed(db: &Path, config: &str) {
    let config = landfall_approval::parse_config(config.as_bytes()).unwrap();
    let store = Store::open(db).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    let deployment: DeploymentId = "app/prod".parse().unwrap();
    let state = RunningState {
        deployment: deployment.clone(),
        deployed: Some(DeployedRelease {
            tag: "v1.0.0".parse().unwrap(),
            digest: format!("sha256:{}", "0".repeat(64)).parse().unwrap(),
        }),
        drift: false,
        phase: Phase::Idle,
        busy: false,
    };
    store
        .record_host_state(&host, None, &[&state])
        .await
        .unwrap();
    let commit = "1".repeat(40).parse().unwrap();
    let digest = format!("sha256:{}", "1".repeat(64)).parse().unwrap();
    let seen = Seen {
        tag_object: "object",
        config_hash: config.hash(),
        commit: Some(&commit),
        digest: Some(&digest),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    store
        .record_release(
            (&deployment, &host, &"v1.1.0".parse().unwrap()),
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver",
            Some(&seen),
        )
        .await
        .unwrap();
    store.close().await;
}

fn invite_link(files: &Files) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_landfall-server"))
        .arg("passkey-invite")
        .args(["--principal", "alice"])
        .arg("--config")
        .arg(&files.config)
        .arg("--db")
        .arg(&files.db)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap().trim().to_owned()
}

#[test]
#[ignore = "needs Node, openssl and Playwright: see this file's documentation"]
fn browser_ceremonies_work_under_the_policy() {
    let script_dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/browser");
    assert!(
        script_dir.join("node_modules/playwright").exists(),
        "run npm ci in {}: see this file's documentation",
        script_dir.display()
    );
    let dir = tempfile::tempdir().unwrap();
    let files = Files {
        config: dir.path().join("fleet.toml"),
        db: dir.path().join("controller.db"),
        backend: SocketAddr::from(([127, 0, 0, 1], free_port())),
        proxy_port: free_port(),
        _dir: dir,
    };
    std::fs::write(&files.config, approval_section(files.proxy_port)).unwrap();

    let mut controller = Controller::start(&files);
    let mut node = Command::new("node")
        .arg("ceremonies.mjs")
        .current_dir(&script_dir)
        .env("LANDFALL_INVITE_LINK", invite_link(&files))
        .env("LANDFALL_BACKEND_PORT", files.backend.port().to_string())
        .env("LANDFALL_PROXY_PORT", files.proxy_port.to_string())
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .unwrap();
    let mut told = node.stdin.take().unwrap();
    let mut said = BufReader::new(node.stdout.take().unwrap()).lines();

    let line = said
        .next()
        .expect("the browser run ended before registering")
        .unwrap();
    let approver_line = line.strip_prefix("REGISTERED ").unwrap();

    // The operator reviews it and copies it in, and the controller loads it.
    drop(controller);
    let config = full_config(files.proxy_port, approver_line);
    std::fs::write(&files.config, &config).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(seed(&files.db, &config));
    controller = Controller::start(&files);
    told.write_all(b"READY\n").unwrap();

    let done = said.next().expect("the browser run ended before finishing");
    assert_eq!(done.unwrap(), "DONE");
    assert!(node.wait().unwrap().success());
    drop(controller);

    // The approval reached the queue, with what a host will check.
    runtime.block_on(async {
        let pool = SqlitePool::connect(&format!("sqlite://{}", files.db.display()))
            .await
            .unwrap();
        let approvals: Vec<String> =
            sqlx::query_scalar("SELECT approval FROM deploys WHERE approval IS NOT NULL")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(approvals.len(), 1);
        let kinds: Vec<String> = sqlx::query_scalar("SELECT kind FROM audit_events ORDER BY seq")
            .fetch_all(&pool)
            .await
            .unwrap();
        for kind in [
            "passkey_invite_issued",
            "passkey_registered",
            "signed_in",
            "deploy_requested",
            "request_cancelled",
            "request_approved",
            "signed_out",
        ] {
            assert!(kinds.iter().any(|seen| seen == kind), "{kind}: {kinds:?}");
        }
        pool.close().await;
    });
}
