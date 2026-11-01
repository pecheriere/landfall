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
use landfall_agent::deploy::{
    self, DeployError, DeployPlan, DeployReport, EngineOptions, Outcome, StepDetail, StepResult,
};
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
    options: EngineOptions,
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
            options: options(),
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
        self.attempt(rest, tag, digest).await.unwrap()
    }

    async fn attempt(
        &self,
        rest: &str,
        tag: &str,
        digest: &str,
    ) -> Result<DeployReport, DeployError> {
        let deployment = self.deployment(rest);
        let plan = plan(&deployment, tag, digest);
        deploy::run(
            &self.docker,
            &self.state,
            &deployment,
            &self.dir,
            &plan,
            &self.options,
        )
        .await
    }

    /// Runs `docker compose` in the compose directory, as an operator would.
    fn compose_by_hand(&self, args: &[&str]) {
        let out = StdCommand::new("docker")
            .arg("compose")
            .args(args)
            .current_dir(&self.dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    }

    /// The service's container and its start, to tell later that neither moved.
    async fn running_since(&self) -> (ContainerId, Timestamp) {
        let id = self.container().await;
        let info = self.docker.inspect(&id).await.unwrap();
        assert_eq!(info.status, "running");
        (id, info.started_at)
    }

    /// Replaces `from` in the base compose file.
    fn edit_compose(&self, from: &str, to: &str) {
        let file = self.dir.join("compose.yaml");
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.contains(from), "{text}");
        fs::write(&file, text.replace(from, to)).unwrap();
    }

    /// A link to the compose directory, outside it.
    fn symlink_to_dir(&self) -> PathBuf {
        let link = self.state_root.path().join("link-to-compose");
        std::os::unix::fs::symlink(&self.dir, &link).unwrap();
        link
    }

    /// [`Self::deploy`], and whether `seen` was ever true while it ran.
    async fn deploy_watching(
        &self,
        rest: &str,
        tag: &str,
        digest: &str,
        seen: impl Fn() -> bool,
    ) -> (DeployReport, bool) {
        let deploy = self.deploy(rest, tag, digest);
        tokio::pin!(deploy);
        let mut was_seen = false;
        loop {
            tokio::select! {
                report = &mut deploy => return (report, was_seen),
                () = tokio::time::sleep(Duration::from_millis(50)) => {
                    was_seen = was_seen || seen();
                }
            }
        }
    }

    /// Whether version B has started: the file it adds is there.
    fn b_started(&self) -> impl Fn() -> bool + use<> {
        let file = self.data("started-v1.28.4");
        move || fs::symlink_metadata(&file).is_ok()
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
        self.binary_command(args).output().await.unwrap()
    }

    fn binary_command(&self, args: &[&str]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_landfall-agent"));
        command
            .args(args)
            .arg("--state-dir")
            .arg(self.state_root.path());
        command
    }

    fn config_file(&self, rest: &str) -> PathBuf {
        let path = self.state_root.path().join("fleet.toml");
        fs::write(&path, self.fleet(rest)).unwrap();
        path
    }

    /// The real `status`: its exit status and its lines.
    async fn status_lines(&self, rest: &str) -> (Option<i32>, Vec<Value>) {
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
        let text = String::from_utf8(out.stdout).unwrap();
        let lines = text
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        (out.status.code(), lines)
    }

    /// The real `status` of the only deployment, which must be readable.
    async fn status(&self, rest: &str) -> Value {
        let (code, mut lines) = self.status_lines(rest).await;
        assert_eq!(code, Some(0), "{lines:?}");
        assert_eq!(lines.len(), 1, "{lines:?}");
        lines.remove(0)
    }

    fn write_override_for(&self, rest: &str, digest: &str) {
        let deployment = self.deployment(rest);
        let next = plan(&deployment, "v2.0.0", digest);
        fs::write(
            self.dir.join(OVERRIDE_FILE),
            compose::render_override(
                "app",
                next.image(),
                next.deployment(),
                next.tag(),
                next.commit(),
            ),
        )
        .unwrap();
    }
}

/// A compose project started by hand under another name, removed on drop.
struct OtherProject(String);

impl Drop for OtherProject {
    fn drop(&mut self) {
        let _ = StdCommand::new("docker")
            .args(["compose", "-p", &self.0, "down"])
            .args(["--volumes", "--remove-orphans", "--timeout", "1"])
            .current_dir("/")
            .output();
    }
}

/// The working directory compose labelled a container with.
fn labelled_working_dir(id: &ContainerId) -> String {
    let out = StdCommand::new("docker")
        .args(["inspect", "--type", "container", "--format"])
        .arg("{{index .Config.Labels \"com.docker.compose.project.working_dir\"}}")
        .arg(id.as_ref())
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    String::from_utf8(out.stdout).unwrap().trim().to_owned()
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

/// What a write, `chmod` or `chown` through a link to `/etc` would change: `/etc`
/// itself and what is directly in it.
fn etc_fingerprint() -> Vec<(String, u64, i64, u32, u32, u32)> {
    let print = |name: String, meta: &fs::Metadata| {
        // Beyond a regular file's, the times of what is in `/etc` move on their
        // own on a live host.
        let (len, mtime) = if meta.is_file() {
            (meta.len(), meta.mtime())
        } else {
            (0, 0)
        };
        (name, len, mtime, meta.mode(), meta.uid(), meta.gid())
    };
    let mut seen: Vec<_> = fs::read_dir("/etc")
        .unwrap()
        .map(|entry| {
            let entry = entry.unwrap();
            print(
                entry.file_name().to_string_lossy().into_owned(),
                &entry.metadata().unwrap(),
            )
        })
        .collect();
    seen.sort();
    let etc = fs::metadata("/etc").unwrap();
    let mut itself = print("/etc".to_owned(), &etc);
    itself.2 = etc.mtime();
    seen.insert(0, itself);
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
    let db = stack.data("db");
    let (report, overwritten) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, || {
            fs::read_to_string(&db).is_ok_and(|text| text == "overwritten\n")
        })
        .await;

    assert_rolled_back(&report);
    assert!(failed_step(&report, "checks"), "{report:?}");
    let detail = |name: &str| {
        report
            .steps
            .iter()
            .find(|step| step.name == name)
            .and_then(|step| step.detail.as_ref())
    };
    assert!(
        matches!(detail("backup"), Some(StepDetail::Backup { stats }) if stats.files >= 1),
        "{report:?}"
    );
    assert!(
        matches!(detail("checks"), Some(StepDetail::Checks { checks }) if checks[0].attempts >= 1),
        "{report:?}"
    );
    assert!(
        overwritten,
        "version B never overwrote the file, so the restore proves nothing"
    );
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
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, stack.b_started())
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
    stack.write_override_for(&rest, DIGEST_B);
    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    stack.docker.compose_up(&stack.dir, "app").await.unwrap();
    assert_eq!(stack.running_image().await, image(DIGEST_B));
    fs::write(stack.data("db"), "half migrated\n").unwrap();

    let status = stack.status(&rest).await;
    assert_eq!(status["in_progress"], true);
    assert_eq!(status["phase"], "deploying");

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
    assert_eq!(status["phase"], Value::Null);
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
    assert_eq!(status["running_image_matches"], true);
    assert_eq!(status["drift"], false);

    // The override moves on and the container doesn't.
    stack.write_override_for(rest, DIGEST_B);
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);

    // The override is gone, with a deploy on record.
    fs::remove_file(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "missing");
    assert_eq!(status["drift"], true);

    // A hand-edited override isn't the agent's to go by.
    fs::write(
        stack.dir.join(OVERRIDE_FILE),
        format!("services:\n  app:\n    image: {}\n", image(DIGEST_A)),
    )
    .unwrap();
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "unrecognised");
    assert_eq!(status["drift"], true);
}

/// The project no longer uses the override: `.env` is emptied and the base file
/// names an image, which is what `docker compose` then resolves to and runs.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_drift_goes_by_the_override_not_by_what_env_resolves_to() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    fs::write(stack.dir.join(".env"), "").unwrap();
    let base = fs::read_to_string(stack.dir.join("compose.yaml")).unwrap();
    fs::write(
        stack.dir.join("compose.yaml"),
        base.replace(
            "  app:\n",
            &format!("  app:\n    image: {}\n", image(DIGEST_B)),
        ),
    )
    .unwrap();
    let up = StdCommand::new("docker")
        .args(["compose", "up", "-d", "--no-deps", "app"])
        .current_dir(&stack.dir)
        .output()
        .unwrap();
    assert!(up.status.success(), "{up:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    let status = stack.status(PASSES).await;
    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);
}

/// `image: ${IMG}` puts whatever `.env` says into the container's image, so an
/// image other than the pinned one can hold a secret. Here that value is the
/// other version's reference, which nothing else in the row has a reason to name.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_status_never_prints_an_image_it_did_not_pin() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    fs::write(stack.dir.join(".env"), format!("IMG={}\n", image(DIGEST_B))).unwrap();
    stack.edit_compose("  app:\n", "  app:\n    image: ${IMG}\n");
    stack.compose_by_hand(&["up", "-d", "--no-deps", "app"]);
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    let status = stack.status(PASSES).await;

    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);
    assert!(!status.to_string().contains(DIGEST_B), "{status}");
}

/// Before a first deploy: no override, and a stack the agent's user can't read.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_needs_neither_an_override_nor_compose() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    fs::set_permissions(stack.dir.join(".env"), fs::Permissions::from_mode(0o000)).unwrap();
    fs::remove_file(stack.dir.join("compose.yaml")).unwrap();

    let status = stack.status(PASSES).await;

    assert_eq!(status["override_file"], "missing");
    assert_eq!(status["deployed"], Value::Null);
    assert_eq!(status["in_progress"], false);
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["drift"], false);
    assert_eq!(status["error"], Value::Null);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_reports_every_deployment_and_exits_2_if_one_is_bad() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let gone = stack.dir.join("gone");
    let rest = format!(
        "{PASSES}[[deployment]]\nid = \"app/gone\"\nrepo = {{ name = \"{REPO}\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{PASSES}",
        gone.to_str().unwrap()
    );

    let (code, lines) = stack.status_lines(&rest).await;

    assert_eq!(code, Some(2), "{lines:?}");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["deployment"], DEPLOYMENT);
    assert_eq!(lines[0]["drift"], false);
    assert_eq!(lines[0]["error"], Value::Null);
    assert_eq!(lines[1]["deployment"], "app/gone");
    assert_eq!(lines[1]["drift"], Value::Null);
    assert!(lines[1]["error"].is_string(), "{lines:?}");
}

/// A deadline that lets a check that can't pass fail quickly, for tests that go
/// through several of them.
fn quick_to_fail() -> EngineOptions {
    let mut options = options();
    options.checks.deadline = Duration::from_secs(3);
    options
}

/// The rollback gets the previous version running, on its restored data, and
/// its checks fail because a dependency is down. It keeps serving for as long as
/// that takes to fix, and `recover` must not take what it wrote since.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_recover_after_failed_rollback_keeps_later_writes() {
    let mut stack = Stack::new(RunAs::Agent, &script_with("echo overwritten > /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack.in_container("echo before > /data/db").await;

    stack.options = quick_to_fail();
    let needs_dependency =
        format!("checks = [{{ command = [\"test\", \"-f\", \"/data/dependency-up\"] }}]\n{BACKUP}");
    let report = stack.deploy(&needs_dependency, "v2.0.0", DIGEST_B).await;

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("check_previous")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        stack.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    // Hours later: it has gone on writing, and the dependency is fixed.
    stack
        .in_container("echo written since > /data/db && echo fixed > /data/dependency-up")
        .await;
    let before = stack.running_since().await;
    stack.options = options();
    let deployment = stack.deployment(&needs_dependency);
    let report = deploy::recover(
        &stack.docker,
        &stack.state,
        &deployment,
        &stack.dir,
        &stack.options,
    )
    .await
    .unwrap();

    assert_rolled_back(&report);
    assert_eq!(
        fs::read_to_string(stack.data("db")).unwrap(),
        "written since\n",
        "what the previous version wrote is still there"
    );
    assert_eq!(
        stack.running_since().await,
        before,
        "the service was neither stopped nor restarted"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(
        stack.state.deployed().unwrap().unwrap().digest.as_ref(),
        DIGEST_A
    );
}

/// A failed deploy takes a backup too: without pruning, six of them left seven
/// copies of the data, and each could have filled the disk.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_failed_deploys_keep_only_the_newest_backups() {
    const KEPT: usize = 3;
    let mut stack = Stack::new(RunAs::Agent, &script_with(":"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.options = quick_to_fail();
    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let backups = stack.state.backups_dir();
    let count = |dir: &Path| fs::read_dir(dir).map_or(0, Iterator::count);
    for attempt in 0..3 {
        let (report, over) = stack
            .deploy_watching(&bad, "v2.0.0", DIGEST_B, || count(&backups) > KEPT)
            .await;
        assert_rolled_back(&report);
        assert!(!over, "attempt {attempt}: more than {KEPT} at some point");
        assert_eq!(count(&backups), KEPT.min(attempt + 2), "attempt {attempt}");
    }

    // More than the number kept turned up by the time a rollback ends: an agent
    // whose prune failed ahead of its backup leaves that.
    let seeded = std::cell::Cell::new(false);
    let stale = backups.join("2000-01-01T00-00-00-000000000Z");
    let b_started = stack.b_started();
    let (report, _) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, || {
            if !seeded.get() && b_started() {
                fs::create_dir(&stale).unwrap();
                seeded.set(true);
            }
            false
        })
        .await;
    assert_rolled_back(&report);
    assert!(seeded.get());
    assert!(fs::symlink_metadata(&stale).is_err(), "it was pruned");
    assert_eq!(count(&backups), KEPT);
}

/// The backup a marker names is what a rollback or `recover` would restore, so
/// it stays even when others sort ahead of it, as a clock that went back leaves.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_prune_spares_the_backup_a_live_marker_names() {
    const AHEAD: [&str; 3] = [
        "2999-01-01T00-00-00-000000000Z",
        "2999-01-02T00-00-00-000000000Z",
        "2999-01-03T00-00-00-000000000Z",
    ];
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let earlier = stack.newest_backup();

    // Seeded once the backup of this deploy is taken, with the marker naming
    // it, so only the prune at the end of the deploy can see them.
    let backups = stack.state.backups_dir();
    let seeded = std::cell::Cell::new(false);
    let b_started = stack.b_started();
    let (second, _) = stack
        .deploy_watching(&rest, "v2.0.0", DIGEST_B, || {
            if !seeded.get() && b_started() {
                for name in AHEAD {
                    fs::create_dir(backups.join(name)).unwrap();
                }
                seeded.set(true);
            }
            false
        })
        .await;

    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
    assert!(seeded.get());
    let left: Vec<PathBuf> = fs::read_dir(&backups)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| !AHEAD.iter().any(|name| path.ends_with(name)))
        .collect();
    assert_eq!(left.len(), 1, "the marker's backup, and only it: {left:?}");
    assert_ne!(left[0], earlier, "the older one was pruned, not this one");
}

/// A rollback's `up` fails. Whatever is running stays running, in the critical
/// state with deploys blocked; the agent does not stop it to tidy up.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_failed_rollback_up_leaves_what_runs_running() {
    let mut stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = passes_only_on("v1.36");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    // With version B up, the project comes to name an external network that
    // isn't there. That passes `config`, and `stop` would still work, so nothing
    // but the agent's choice keeps the service running: only `up` fails.
    stack.options = quick_to_fail();
    let compose_file = stack.dir.join("compose.yaml");
    let intact = fs::read_to_string(&compose_file).unwrap();
    let name = stack.project.name.clone();
    let broken = std::cell::Cell::new(false);
    let b_started = stack.b_started();
    let (report, _) = stack
        .deploy_watching(&rest, "v2.0.0", DIGEST_B, || {
            if !broken.get() && b_started() {
                stack.edit_compose(
                    &format!("name: {name}-net\n"),
                    &format!("name: {name}-missing\n    external: true\n"),
                );
                broken.set(true);
            }
            false
        })
        .await;

    assert!(broken.get());
    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("start_previous")),
        "{:?}",
        report.outcome
    );
    assert!(report.steps.iter().all(|step| step.name != "stop_service"));
    let containers = stack.project.all_containers();
    assert_eq!(containers.len(), 1, "{containers:?}");
    let id: ContainerId = containers[0].parse().unwrap();
    let info = stack.docker.inspect(&id).await.unwrap();
    assert_eq!(info.status, "running", "the agent stopped it");
    assert_eq!(info.image, image(DIGEST_B));

    let refused = stack.attempt(&rest, "v3.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(refused, DeployError::Interrupted { .. }),
        "{refused}"
    );
    let status = stack.status(&rest).await;
    assert_eq!(status["in_progress"], true);
    assert_eq!(status["phase"], "rolling_back");
    assert_eq!(status["running_image_matches"], false);

    // The operator fixes it, and `recover` brings the previous version back.
    fs::write(&compose_file, intact).unwrap();
    stack.options = options();
    let deployment = stack.deployment(&rest);
    let recovered = deploy::recover(
        &stack.docker,
        &stack.state,
        &deployment,
        &stack.dir,
        &stack.options,
    )
    .await
    .unwrap();
    assert_rolled_back(&recovered);
    assert_eq!(stack.running_image().await, image(DIGEST_A));
}

/// A scaled service used to pass the preflight, get stopped and end in a false
/// critical: its checks could not tell one container.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_scaled_service_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;
    let override_before = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let plain = fs::read_to_string(stack.dir.join("compose.yaml")).unwrap();

    for asked in ["    scale: 2\n", "    deploy:\n      replicas: 2\n"] {
        stack.edit_compose("  app:\n", &format!("  app:\n{asked}"));
        let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
        assert!(
            matches!(err, DeployError::Scaled { replicas: 2, .. }),
            "{asked}: {err}"
        );
        assert_eq!(stack.running_since().await, before, "{asked}");
        assert_eq!(stack.state.in_progress().unwrap(), None, "{asked}");
        fs::write(stack.dir.join("compose.yaml"), &plain).unwrap();
    }
    // None at all used to pass too, and end in a false critical.
    for asked in ["    scale: 0\n", "    deploy:\n      replicas: 0\n"] {
        stack.edit_compose("  app:\n", &format!("  app:\n{asked}"));
        let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
        assert!(
            matches!(err, DeployError::Scaled { replicas: 0, .. }),
            "{asked}: {err}"
        );
        assert_eq!(stack.running_since().await, before, "{asked}");
        assert_eq!(stack.state.in_progress().unwrap(), None, "{asked}");
        fs::write(stack.dir.join("compose.yaml"), &plain).unwrap();
    }
    assert_eq!(
        fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap(),
        override_before
    );

    // Scaled by hand, which the files don't show.
    stack.compose_by_hand(&["up", "-d", "--no-deps", "--scale", "app=2", "app"]);
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(
        stack.project.all_containers().len(),
        2,
        "neither was stopped or removed"
    );

    // What the error says to do works.
    stack.compose_by_hand(&["up", "-d", "--no-deps", "--scale", "app=1", "app"]);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// A second project in the directory has its own container, and shares the
/// directory's data with a backup and a restore.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_second_project_in_the_directory_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;

    let other = OtherProject(format!("{}-other", stack.project.name));
    stack.compose_by_hand(&["-p", &other.0, "up", "-d", "--no-deps", "app"]);

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.running_since().await, before);
    assert_eq!(stack.state.in_progress().unwrap(), None);

    // `status` can't tell them apart without loading the project, and says so.
    let (code, lines) = stack.status_lines(&rest).await;
    assert_eq!(code, Some(2), "{lines:?}");
    assert!(
        lines[0]["error"]
            .as_str()
            .unwrap()
            .contains("more than one running container"),
        "{lines:?}"
    );

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// `name:` edited while the container runs: the project no longer has it, and a
/// restore would have run under it while it wrote.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_container_left_behind_by_a_renamed_project_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let (id, started_at) = stack.running_since().await;
    let name = stack.project.name.clone();
    // Nothing should run under the new name; if a deploy starts it, it goes too.
    let _renamed = OtherProject(format!("{name}-renamed"));

    stack.edit_compose(
        &format!("name: {name}\n"),
        &format!("name: {name}-renamed\n"),
    );
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    let info = stack.docker.inspect(&id).await.unwrap();
    assert_eq!(
        (info.status.as_str(), info.started_at),
        ("running", started_at)
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    stack.edit_compose(
        &format!("name: {name}-renamed\n"),
        &format!("name: {name}\n"),
    );
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// Another project runs alone from the directory, with the deployment's own
/// stopped: the lookup by the project's name finds nothing.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_lone_container_of_another_project_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.compose_by_hand(&["stop", "app"]);
    let other = OtherProject(format!("{}-other", stack.project.name));
    stack.compose_by_hand(&["-p", &other.0, "up", "-d", "--no-deps", "app"]);
    let lone = stack
        .docker
        .container_at(&stack.dir, "app")
        .await
        .unwrap()
        .expect("the other project's container runs from this directory");
    let started_at = stack.docker.inspect(&lone).await.unwrap().started_at;

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    let info = stack.docker.inspect(&lone).await.unwrap();
    assert_eq!(
        (info.status.as_str(), info.started_at),
        ("running", started_at)
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// Two directories with one project's name. Deploying the second used to stop
/// and replace the first's service, end `Deployed`, and leave the first's
/// `status` clean.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_project_name_shared_with_another_directory_is_refused_before_stop() {
    let first_stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = first_stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = first_stack.running_since().await;

    let second_stack = Stack::new(RunAs::Agent, &script_with(":"));
    second_stack.edit_compose(
        &format!("name: {}\n", second_stack.project.name),
        &format!("name: {}\n", first_stack.project.name),
    );
    let err = second_stack
        .attempt(&rest, "v2.0.0", DIGEST_B)
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    let text = err.to_string();
    assert!(
        text.contains("`name:`") && text.contains("`COMPOSE_PROJECT_NAME`"),
        "{text}"
    );
    assert!(
        text.contains(&format!("\"{}\"", first_stack.dir.display())),
        "the other directory is named, quoted: {text}"
    );
    assert_eq!(first_stack.running_since().await, before);
    assert_eq!(second_stack.state.in_progress().unwrap(), None);
    let status = first_stack.status(&rest).await;
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
}

/// The other directory's service is stopped. `up` under the shared name would
/// recreate its container all the same, so it is no less in the way.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_stopped_service_of_another_directory_is_refused_before_stop() {
    let first_stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = first_stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    first_stack.compose_by_hand(&["stop", "app"]);
    let before = first_stack.project.all_containers();
    assert_eq!(before.len(), 1);

    let second_stack = Stack::new(RunAs::Agent, &script_with(":"));
    second_stack.edit_compose(
        &format!("name: {}\n", second_stack.project.name),
        &format!("name: {}\n", first_stack.project.name),
    );
    let err = second_stack
        .attempt(&rest, "v2.0.0", DIGEST_B)
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    assert_eq!(
        first_stack.project.all_containers(),
        before,
        "the stopped container was not replaced"
    );
    assert_eq!(second_stack.state.in_progress().unwrap(), None);
}

/// A second project started through a symlink is labelled with the link, which
/// the lookup by the directory's path doesn't match.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_second_project_started_through_a_symlink_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;

    let other = OtherProject(format!("{}-other", stack.project.name));
    let link = stack.symlink_to_dir();
    let out = StdCommand::new("docker")
        .args(["compose", "-p", &other.0, "up", "-d", "--no-deps", "app"])
        .current_dir(&link)
        .env("PWD", &link)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stack.docker.container_at(&stack.dir, "app").await.unwrap(),
        Some(before.0.clone()),
        "only the deployment's own is found by the real path, or this proves nothing"
    );

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.running_since().await, before);

    // With its own stopped, it is the only one running from the directory.
    stack.compose_by_hand(&["stop", "app"]);
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// A service started by hand through a symlink is labelled with the symlink's
/// path. That used to turn a healthy service into a permanent critical.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_service_started_through_a_symlink_is_found() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let link = stack.symlink_to_dir();
    let out = StdCommand::new("docker")
        .args([
            "compose",
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "app",
        ])
        .current_dir(&link)
        .env("PWD", &link)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let id = stack.container().await;
    assert_eq!(
        Path::new(&labelled_working_dir(&id)),
        link,
        "the container is not labelled with the link, so this proves nothing"
    );
    assert_eq!(
        stack.docker.container_at(&stack.dir, "app").await.unwrap(),
        None,
        "`status` goes by the directory, as the operations guide says"
    );

    // A release that fails its check on the version running goes back to it.
    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let second = stack.deploy(&bad, "v2.0.0", DIGEST_B).await;
    assert_rolled_back(&second);
    assert_eq!(stack.running_image().await, image(DIGEST_A));
    let third = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(third.outcome, Outcome::Deployed, "{third:?}");
}

/// The base file lives elsewhere, so that is the working directory compose
/// labels the container with. The container can't be told from another stack's,
/// so the compose file has to live in the compose directory.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_compose_file_in_another_directory_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let elsewhere = stack.dir.join("elsewhere");
    fs::create_dir_all(elsewhere.join("data")).unwrap();
    fs::rename(
        stack.dir.join("compose.yaml"),
        elsewhere.join("compose.yaml"),
    )
    .unwrap();
    fs::write(
        stack.dir.join(".env"),
        format!("COMPOSE_FILE=elsewhere/compose.yaml:{OVERRIDE_FILE}\n"),
    )
    .unwrap();

    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let id = stack.container().await;
    assert_eq!(
        Path::new(&labelled_working_dir(&id)),
        elsewhere,
        "the working directory is the agent's, so this proves nothing"
    );
    let before = stack.running_since().await;

    let err = stack.attempt(PASSES, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    assert!(err.to_string().contains("compose directory"), "{err}");
    assert_eq!(stack.running_since().await, before);
    assert_eq!(stack.state.in_progress().unwrap(), None);
}

/// An agent started with `PWD` on a symlink to the directory must not hand it to
/// compose, whose label would then keep `status` from finding the service.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_pwd_on_a_symlink_does_not_reach_the_label() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    // An agent that died with version B up, and no backup to restore.
    let previous = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
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
            backup: None,
            started_at: Timestamp::now(),
        })
        .unwrap();
    stack.write_override_for(PASSES, DIGEST_B);
    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    stack.docker.compose_up(&stack.dir, "app").await.unwrap();

    let link = stack.symlink_to_dir();
    let config = stack.config_file(PASSES);
    let out = stack
        .binary_command(&[
            "recover",
            "--config",
            config.to_str().unwrap(),
            "--deployment",
            DEPLOYMENT,
        ])
        .env("PWD", &link)
        .output()
        .await
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let id = stack.container().await;
    assert_eq!(Path::new(&labelled_working_dir(&id)), stack.dir);
    let status = stack.status(PASSES).await;
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
}

/// `config` leaves out a service behind a profile that isn't active.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_service_behind_an_inactive_profile_is_refused() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    stack.edit_compose("  app:\n", "  app:\n    profiles: [off]\n");

    let err = stack.attempt(PASSES, "v1.0.0", DIGEST_A).await.unwrap_err();

    assert!(matches!(err, DeployError::NoSuchService { .. }), "{err}");
    assert_eq!(stack.project.all_containers(), Vec::<String>::new());
    assert_eq!(stack.state.in_progress().unwrap(), None);
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
    let etc = etc_fingerprint();
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
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, stack.b_started())
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
    assert_eq!(etc_fingerprint(), etc, "/etc changed");
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
