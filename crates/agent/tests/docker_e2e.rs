//! The deploy engine and the binary against a real Docker daemon. All of it
//! is `#[ignore]`d, and runs with
//! `cargo test -p landfall-agent --all-features --locked -- --ignored docker`.
//!
//! The images are public and multi-platform, on the registry the agent deploys
//! from, each pinned by the digest of its index: tags 1.36 and 1.28 of
//! `ghcr.io/containerd/busybox`, a copy of busybox, whose `sh`, `sleep` and
//! `httpd` serve as the service.
//!
//! Which tests need what:
//!
//! - `docker_foreign_owner_*` needs root, as the agent's capabilities would
//!   give it, and Linux, whose bind mounts keep the owner a container sets. It
//!   skips otherwise, unless `LANDFALL_TEST_REQUIRE_ROOT` is set, as it is in
//!   CI, which makes that a failure. The others run as any user who can reach
//!   Docker: their containers run as that user, so the data stays readable.
//! - `docker_http_*` needs Linux: the host must reach a Docker bridge network,
//!   which a Mac's Docker cannot give it.

#![cfg(test)]

use std::fs;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Command as StdCommand, Output};
use std::time::Duration;

use jiff::Timestamp;
use landfall_agent::checks::CheckOptions;
use landfall_agent::compose::{self, OVERRIDE_FILE, PLACEHOLDER};
use landfall_agent::deploy::{self, DeployPlan, DeployReport, EngineOptions, Outcome, StepResult};
use landfall_agent::docker::{ContainerId, Docker, DockerCli};
use landfall_agent::safefs::{self, RelPath, Root};
use landfall_agent::state::{DeploymentState, InProgress, Phase, RecordedBackup, StateDir};
use landfall_core::config::{Config, Deployment, parse};
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::release::ReleaseOrigin;
use serde_json::Value;

#[path = "support/compose_project.rs"]
mod compose_project;

use compose_project::ComposeProject;

const REPO: &str = "containerd/busybox";
/// Tag 1.36: what a healthy version runs.
const DIGEST_A: &str = "sha256:7b3ccabffc97de872a30dfd234fd972a66d247c8cfc69b0550f276481852627c";
/// Tag 1.28: the version a deploy tries next.
const DIGEST_B: &str = "sha256:141c253bc4c3fd0a201d32dc1f493bcf3fff003b6df416dea4f41046e0f37d47";
const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DEPLOYMENT: &str = "app/prod";
/// A rollback runs the deployment's checks on the previous version too, so a
/// check that fails on every version, like [`FAILS`], makes the rollback fail.
/// This one fails on all but one.
fn passes_only_on(version: &str) -> String {
    format!(
        "checks = [{{ command = [\"sh\", \"-c\", \"busybox | head -n 1 | grep -q {version}\"] }}]\n"
    )
}

const BACKUP: &str = "backup = { paths = [\"data\"], stop = true }\n";
const PASSES: &str = "checks = [{ command = [\"true\"] }]\n";
const FAILS: &str = "checks = [{ command = [\"false\"] }]\n";

fn image(digest: &str) -> String {
    format!("ghcr.io/{REPO}@{digest}")
}

/// The service's command: what it does as version B, then its long sleep.
/// `$$` is a `$` that compose does not interpolate.
fn script_with(as_b: &str) -> String {
    format!(
        "v=$$(busybox | head -n 1 | cut -d \" \" -f 2)\n        touch \"/data/started-$$v\"\n        case \"$$v\" in v1.28*) {as_b} ;; esac\n        exec sleep 300"
    )
}

/// Who the service's container runs as.
#[derive(Clone, Copy, PartialEq)]
enum RunAs {
    /// The test's own user, so the data stays the test's to read.
    Agent,
    /// The image's default, root, which can give files to anyone.
    #[cfg(target_os = "linux")]
    Root,
}

/// A compose project using the override, with a `data` directory, a state
/// directory, and a base file that gives the service no image.
struct Stack {
    project: ComposeProject,
    dir: PathBuf,
    state_root: tempfile::TempDir,
    state: DeploymentState,
    docker: DockerCli,
}

impl Stack {
    fn new(run_as: RunAs, script: &str) -> Self {
        let user = if run_as == RunAs::Agent {
            let (uid, gid) = (
                rustix::process::geteuid().as_raw(),
                rustix::process::getegid().as_raw(),
            );
            format!("    user: \"{uid}:{gid}\"\n")
        } else {
            String::new()
        };
        let project = ComposeProject::create(&format!(
            "  app:\n{user}    command:\n      - sh\n      - -c\n      - |\n        {script}\n    stop_grace_period: 1s\n    volumes:\n      - ./data:/data\n    networks: [net]\n"
        ));
        let dir = project.path().canonicalize().unwrap();
        fs::write(
            dir.join(".env"),
            format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
        )
        .unwrap();
        fs::create_dir(dir.join("data")).unwrap();
        let state_root = tempfile::tempdir().unwrap();
        let state = StateDir::open(state_root.path())
            .unwrap()
            .deployment(&DEPLOYMENT.parse().unwrap())
            .unwrap();
        Self {
            project,
            dir,
            state_root,
            state,
            docker: DockerCli::new(),
        }
    }

    fn data(&self, name: &str) -> PathBuf {
        self.dir.join("data").join(name)
    }

    fn fleet(&self, rest: &str) -> String {
        format!(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"{DEPLOYMENT}\"\nrepo = {{ name = \"{REPO}\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = {dir:?}, service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{rest}\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"{DEPLOYMENT}\"]\ncan = [\"approve\"]\n",
            dir = self.dir.to_str().unwrap(),
        )
    }

    fn config(&self, rest: &str) -> Config {
        parse(self.fleet(rest).as_bytes()).unwrap()
    }

    fn deployment(&self, rest: &str) -> Deployment {
        self.config(rest).deployments()[0].clone()
    }

    async fn deploy(&self, rest: &str, tag: &str, digest: &str) -> DeployReport {
        let deployment = self.deployment(rest);
        let plan = plan(&deployment, tag, digest);
        deploy::run(
            &self.docker,
            &self.state,
            &deployment,
            &self.dir,
            &plan,
            &options(),
        )
        .await
        .unwrap()
    }

    /// [`Self::deploy`], and whether `data/<name>` appeared while it ran.
    async fn deploy_watching(
        &self,
        rest: &str,
        tag: &str,
        digest: &str,
        name: &str,
    ) -> (DeployReport, bool) {
        let deploy = self.deploy(rest, tag, digest);
        tokio::pin!(deploy);
        let mut seen = false;
        loop {
            tokio::select! {
                report = &mut deploy => return (report, seen),
                () = tokio::time::sleep(Duration::from_millis(50)) => {
                    seen = seen || fs::symlink_metadata(self.data(name)).is_ok();
                }
            }
        }
    }

    async fn container(&self) -> ContainerId {
        self.docker
            .container(&self.dir, "app")
            .await
            .unwrap()
            .expect("the service has a running container")
    }

    async fn running_image(&self) -> String {
        let info = self.docker.inspect(&self.container().await).await.unwrap();
        assert_eq!(info.status, "running");
        info.image
    }

    /// Runs `script` in the service's container, as the service's user.
    async fn in_container(&self, script: &str) {
        let argv = ["sh".to_owned(), "-c".to_owned(), script.to_owned()];
        let id = self.container().await;
        assert!(self.docker.exec(&id, &argv).await.unwrap(), "{script}");
    }

    /// The newest backup: their names sort by time.
    fn newest_backup(&self) -> PathBuf {
        fs::read_dir(self.state.backups_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .max()
            .unwrap()
    }

    /// Runs the real binary with `args` and the state directory.
    async fn binary(&self, args: &[&str]) -> Output {
        tokio::process::Command::new(env!("CARGO_BIN_EXE_landfall-agent"))
            .args(args)
            .arg("--state-dir")
            .arg(self.state_root.path())
            .output()
            .await
            .unwrap()
    }

    fn config_file(&self, rest: &str) -> PathBuf {
        let path = self.state_root.path().join("fleet.toml");
        fs::write(&path, self.fleet(rest)).unwrap();
        path
    }

    async fn status(&self, rest: &str) -> Value {
        let config = self.config_file(rest);
        let out = self
            .binary(&[
                "status",
                "--config",
                config.to_str().unwrap(),
                "--host",
                "home-1",
            ])
            .await;
        assert_eq!(out.status.code(), Some(0), "{out:?}");
        let text = String::from_utf8(out.stdout).unwrap();
        assert_eq!(text.lines().count(), 1, "{text}");
        serde_json::from_str(&text).unwrap()
    }
}

fn plan(deployment: &Deployment, tag: &str, digest: &str) -> DeployPlan {
    DeployPlan::from_verified(
        deployment,
        &tag.parse().unwrap(),
        tag.trim_start_matches('v').parse().unwrap(),
        &origin(digest),
    )
}

/// A verified origin for `digest`. These tests start from what verification
/// hands over; `verify_release` has its own.
fn origin(digest: &str) -> ReleaseOrigin {
    ReleaseOrigin {
        commit: COMMIT.parse().unwrap(),
        tag: None,
        attestation: VerifiedAttestation {
            digest: digest.parse().unwrap(),
            san: String::new(),
            commit: COMMIT.parse().unwrap(),
            git_ref: String::new(),
            repo_id: 1,
            owner_id: 2,
            run_url: String::new(),
            rekor_log_index: 0,
            integrated_time: 0,
        },
        platforms: Vec::new(),
    }
}

/// Short enough that a check that can't pass ends the test quickly, long enough
/// for a loaded CI machine to run one that can.
fn options() -> EngineOptions {
    EngineOptions {
        checks: CheckOptions {
            interval: Duration::from_millis(200),
            deadline: Duration::from_secs(12),
            http_timeout: Duration::from_secs(2),
            settle: Duration::from_millis(500),
        },
        ..EngineOptions::default()
    }
}

fn failed_step(report: &DeployReport, name: &str) -> bool {
    report
        .steps
        .iter()
        .any(|step| step.name == name && matches!(step.result, StepResult::Failed { .. }))
}

fn assert_rolled_back(report: &DeployReport) {
    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
}

/// What a read of `/etc` would notice changing.
fn etc_fingerprint() -> Vec<(String, u64, i64, u32, u32)> {
    let mut seen: Vec<_> = fs::read_dir("/etc")
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            let meta = entry.metadata().unwrap();
            let name = entry.file_name().to_string_lossy().into_owned();
            // A directory's times move on their own, on a live host.
            let len = if meta.is_file() { meta.len() } else { 0 };
            let mtime = if meta.is_file() { meta.mtime() } else { 0 };
            (name, len, mtime, meta.mode(), meta.uid())
        })
        .collect();
    seen.sort();
    seen
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_deploy_then_failed_check_rolls_back() {
    let stack = Stack::new(RunAs::Agent, &script_with("echo overwritten > /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    stack
        .in_container("echo before > /data/db && chmod 640 /data/db")
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    // Named by its version: the container of B, which started and wrote.
    let (report, b_ran) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, "started-v1.28.4")
        .await;

    assert_rolled_back(&report);
    assert!(failed_step(&report, "checks"), "{report:?}");
    assert!(b_ran, "version B never ran, so the restore proves nothing");
    assert_eq!(stack.running_image().await, image(DIGEST_A));
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(
        fs::metadata(stack.data("db")).unwrap().permissions().mode() & 0o7777,
        0o640,
        "mode only: owners are in docker_foreign_owner_survives_backup_and_restore"
    );
    assert!(
        fs::symlink_metadata(stack.data("started-v1.28.4")).is_err(),
        "what version B added is gone"
    );

    assert_eq!(stack.state.in_progress().unwrap(), None);
    let recorded = stack.state.deployed().unwrap().unwrap();
    assert_eq!(recorded.digest.as_ref(), DIGEST_A);
    assert_eq!(recorded.tag.as_ref(), "v1.0.0");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_symlink_in_backup_is_not_followed() {
    // Version B also replaces a file with a link out of the tree, which the
    // restore has to take away rather than write through.
    let stack = Stack::new(
        RunAs::Agent,
        &script_with("rm -f /data/db && ln -s /etc/hostname /data/db"),
    );
    let etc = etc_fingerprint();
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack
        .in_container("echo before > /data/db && ln -s /etc /data/link")
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let (report, b_ran) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, "started-v1.28.4")
        .await;

    assert_rolled_back(&report);
    assert!(b_ran, "version B never ran, so the restore proves nothing");

    let link = fs::symlink_metadata(stack.data("link")).unwrap();
    assert!(link.file_type().is_symlink());
    assert_eq!(
        fs::read_link(stack.data("link")).unwrap(),
        Path::new("/etc")
    );

    let db = fs::symlink_metadata(stack.data("db")).unwrap();
    assert!(db.file_type().is_file(), "{db:?}");
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");

    // The snapshot holds the link, not what it points at.
    let copied = stack.newest_backup().join("data/link");
    assert!(
        fs::symlink_metadata(&copied)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    assert_eq!(etc_fingerprint(), etc, "/etc changed");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_first_deploy_failure_with_no_base_image() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));

    let report = stack.deploy(FAILS, "v1.0.0", DIGEST_A).await;

    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        stack.docker.container(&stack.dir, "app").await.unwrap(),
        None,
        "the service is stopped"
    );
    let containers = stack.project.all_containers();
    assert_eq!(containers.len(), 1, "{containers:?}");
    let id: ContainerId = containers[0].parse().unwrap();
    assert_eq!(stack.docker.inspect(&id).await.unwrap().status, "exited");
    assert_eq!(
        fs::read_to_string(stack.dir.join(OVERRIDE_FILE)).unwrap(),
        PLACEHOLDER
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(stack.state.deployed().unwrap(), None);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_first_deploy_needs_its_backup_paths_to_exist() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    fs::remove_dir(stack.dir.join("data")).unwrap();

    let report = stack
        .deploy(&format!("{PASSES}{BACKUP}"), "v1.0.0", DIGEST_A)
        .await;

    assert!(
        matches!(&report.outcome, Outcome::FailedNoPrevious { reason } if reason.starts_with("backup:")),
        "{:?}",
        report.outcome
    );
    assert_eq!(stack.project.all_containers(), Vec::<String>::new());
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_leftover_one_off_does_not_disturb_deploy_or_rollback() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let run = StdCommand::new("docker")
        .args(["compose", "run", "-d", "--no-deps", "app", "sleep", "300"])
        .current_dir(&stack.dir)
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    assert_eq!(stack.project.all_containers().len(), 2);

    // A deploy goes through with it there.
    let second = stack.deploy(&good, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    // So does a rollback.
    let bad = format!("{}{BACKUP}", passes_only_on("v1.28"));
    let third = stack.deploy(&bad, "v3.0.0", DIGEST_A).await;
    assert_rolled_back(&third);
    assert_eq!(stack.running_image().await, image(DIGEST_B));
    assert_eq!(stack.project.all_containers().len(), 2);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_recover_rolls_back_an_interrupted_deploy() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack.in_container("echo before > /data/db").await;

    // An agent that died with version B up: it had stopped the service, taken
    // a backup, written the override and started B, which wrote to the data.
    stack.docker.compose_stop(&stack.dir, "app").await.unwrap();
    let previous = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let backup = "2026-11-01T10-00-00-000000000Z";
    safefs::snapshot(
        &Root::open(&stack.dir).unwrap(),
        &[RelPath::new("data").unwrap()],
        &stack.state.backups_dir().join(backup),
    )
    .unwrap();
    stack.state.set_previous_override(&previous).unwrap();
    stack
        .state
        .set_previous_deployed(stack.state.deployed().unwrap().as_ref())
        .unwrap();
    stack
        .state
        .set_in_progress(&InProgress {
            deploy_id: "interrupted".to_owned(),
            phase: Phase::Deploying,
            tag: "v2.0.0".parse().unwrap(),
            digest: DIGEST_B.parse().unwrap(),
            previous_can_start: true,
            backup: Some(RecordedBackup {
                id: backup.to_owned(),
                paths: vec!["data".to_owned()],
            }),
            started_at: Timestamp::now(),
        })
        .unwrap();
    let deployment = stack.deployment(&rest);
    let next = plan(&deployment, "v2.0.0", DIGEST_B);
    fs::write(
        stack.dir.join(OVERRIDE_FILE),
        compose::render_override(
            "app",
            next.image(),
            next.deployment(),
            next.tag(),
            next.commit(),
        ),
    )
    .unwrap();
    stack.docker.pull(next.image()).await.unwrap();
    stack.docker.compose_up(&stack.dir, "app").await.unwrap();
    assert_eq!(stack.running_image().await, image(DIGEST_B));
    fs::write(stack.data("db"), "half migrated\n").unwrap();

    let status = stack.status(&rest).await;
    assert_eq!(status["in_progress"], true);

    // Through the binary, with the engine's real timing.
    let config = stack.config_file(&rest);
    let args = [
        "recover",
        "--config",
        config.to_str().unwrap(),
        "--deployment",
        DEPLOYMENT,
    ];
    let out = stack.binary(&args).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["outcome"]["kind"], "rolled_back", "{report}");

    assert_eq!(stack.running_image().await, image(DIGEST_A));
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap(), previous);

    let again = stack.binary(&args).await;
    assert_eq!(again.status.code(), Some(2), "nothing left to recover");
    assert_eq!(again.stdout, b"");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_reports_drift() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = PASSES;
    let first = stack.deploy(rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let status = stack.status(rest).await;
    assert_eq!(status["deployment"], DEPLOYMENT);
    assert_eq!(status["dir"], stack.dir.to_str().unwrap());
    assert_eq!(status["deployed"]["digest"], DIGEST_A);
    assert_eq!(status["in_progress"], false);
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
    assert_eq!(status["drift"], false);

    // The override moves on and the container doesn't.
    let deployment = stack.deployment(rest);
    let next = plan(&deployment, "v2.0.0", DIGEST_B);
    fs::write(
        stack.dir.join(OVERRIDE_FILE),
        compose::render_override(
            "app",
            next.image(),
            next.deployment(),
            next.tag(),
            next.commit(),
        ),
    )
    .unwrap();
    let status = stack.status(rest).await;
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
    assert_eq!(status["drift"], true);
}

/// Whether this test can run: it needs root to see another user's files
/// through a backup. Where root is required, not having it is a failure.
#[cfg(target_os = "linux")]
#[expect(
    clippy::print_stderr,
    reason = "a test skipped for lack of privileges has to say so; libtest has no runtime skip"
)]
fn has_root(test: &str) -> bool {
    if rustix::process::geteuid().is_root() {
        return true;
    }
    assert!(
        std::env::var_os("LANDFALL_TEST_REQUIRE_ROOT").is_none(),
        "{test} must run as root here"
    );
    eprintln!("{test}: skipped, it needs root to see another user's files");
    false
}

#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_foreign_owner_survives_backup_and_restore() {
    if !has_root("docker_foreign_owner_survives_backup_and_restore") {
        return;
    }
    let stack = Stack::new(RunAs::Root, &script_with("chown 3000:3000 /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack
        .in_container(
            "echo before > /data/db && chown 1000:1001 /data/db && chmod 640 /data/db \
             && ln -s /etc /data/link && chown -h 1002:1003 /data/link \
             && mkdir /data/sub && chown 1004:1005 /data/sub && chmod 2750 /data/sub",
        )
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let (report, b_ran) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, "started-v1.28.4")
        .await;

    assert_rolled_back(&report);
    assert!(b_ran, "version B never ran, so the restore proves nothing");
    for base in [stack.dir.join("data"), stack.newest_backup().join("data")] {
        for (name, uid, gid, mode) in [
            ("db", 1000, 1001, Some(0o640)),
            ("link", 1002, 1003, None),
            ("sub", 1004, 1005, Some(0o2750)),
        ] {
            let meta = fs::symlink_metadata(base.join(name)).unwrap();
            assert_eq!((meta.uid(), meta.gid()), (uid, gid), "{base:?}/{name}");
            if let Some(mode) = mode {
                assert_eq!(meta.mode() & 0o7777, mode, "{base:?}/{name}");
            }
        }
    }
    assert_eq!(
        fs::read_link(stack.data("link")).unwrap(),
        Path::new("/etc")
    );
}

/// The host reaches the container's address on a bridge network, which a Mac's
/// Docker does not offer. Only version A serves the path.
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_http_check_reaches_the_container_and_a_failed_one_rolls_back() {
    const SERVE: &str = "mkdir -p /tmp/www\n        case \"$$(busybox | head -n 1)\" in *v1.36*) echo ok > /tmp/www/health ;; esac\n        exec httpd -f -p 8080 -h /tmp/www";
    let stack = Stack::new(RunAs::Agent, SERVE);
    let check = format!(
        "checks = [{{ http = \"/health\", network = \"{}-net\", port = 8080, expect = 200 }}]\n",
        stack.project.name
    );

    let first = stack.deploy(&check, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    let second = stack.deploy(&check, "v2.0.0", DIGEST_B).await;
    assert_rolled_back(&second);
    assert!(failed_step(&second, "checks"), "{second:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));
}
