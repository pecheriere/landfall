//! The compose project, the service and the helpers the scenarios share.

use std::fs;
use std::os::unix::fs::MetadataExt as _;
use std::path::PathBuf;
use std::process::{Command as StdCommand, Output};
use std::time::Duration;

use jiff::Timestamp;
use landfall_agent::checks::CheckOptions;
use landfall_agent::compose::{self, OVERRIDE_FILE};
use landfall_agent::deploy::{
    self, DeployError, DeployPlan, DeployReport, EngineOptions, Outcome, StepResult,
};
use landfall_agent::docker::{ContainerId, Docker, DockerCli};
use landfall_agent::state::{DeploymentState, StateDir};
use landfall_approval::parse_config;
use landfall_core::config::{Config, Deployment};
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::release::ReleaseOrigin;
use serde_json::Value;

use crate::compose_project::ComposeProject;

pub(super) const REPO: &str = "containerd/busybox";

/// Tag 1.36: what a healthy version runs.
pub(super) const DIGEST_A: &str =
    "sha256:7b3ccabffc97de872a30dfd234fd972a66d247c8cfc69b0550f276481852627c";

/// Tag 1.28: the version a deploy tries next.
pub(super) const DIGEST_B: &str =
    "sha256:141c253bc4c3fd0a201d32dc1f493bcf3fff003b6df416dea4f41046e0f37d47";

const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

pub(super) const DEPLOYMENT: &str = "app/prod";

/// A rollback runs the deployment's checks on the previous version too, so a
/// check that fails on every version, like [`FAILS`], makes the rollback fail.
/// This one fails on all but one.
pub(super) fn passes_only_on(version: &str) -> String {
    format!(
        "checks = [{{ command = [\"sh\", \"-c\", \"busybox | head -n 1 | grep -q {version}\"] }}]\n"
    )
}

pub(super) const BACKUP: &str = "backup = { paths = [\"data\"], stop = true }\n";

pub(super) const PASSES: &str = "checks = [{ command = [\"true\"] }]\n";

pub(super) const FAILS: &str = "checks = [{ command = [\"false\"] }]\n";

pub(super) fn image(digest: &str) -> String {
    format!("ghcr.io/{REPO}@{digest}")
}

/// The service's command: what it does as version B, then its long sleep.
/// `$$` is a `$` that compose does not interpolate.
pub(super) fn script_with(as_b: &str) -> String {
    format!(
        "v=$$(busybox | head -n 1 | cut -d \" \" -f 2)\n        touch \"/data/started-$$v\"\n        case \"$$v\" in v1.28*) {as_b} ;; esac\n        exec sleep 300"
    )
}

/// Who the service's container runs as.
#[derive(Clone, Copy, PartialEq)]
pub(super) enum RunAs {
    /// The test's own user, so the data stays the test's to read.
    Agent,
    /// The image's default, root, which can give files to anyone.
    #[cfg(target_os = "linux")]
    Root,
}

/// A compose project using the override, with a `data` directory, a state
/// directory, and a base file that gives the service no image.
pub(super) struct Stack {
    pub(super) project: ComposeProject,
    pub(super) dir: PathBuf,
    state_root: tempfile::TempDir,
    pub(super) state: DeploymentState,
    pub(super) docker: DockerCli,
    pub(super) options: EngineOptions,
}

impl Stack {
    pub(super) fn new(run_as: RunAs, script: &str) -> Self {
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

    pub(super) fn data(&self, name: &str) -> PathBuf {
        self.dir.join("data").join(name)
    }

    fn fleet(&self, rest: &str) -> String {
        format!(
            "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approval]\nrp_id = \"landfall.example\"\norigin = \"https://landfall.example\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea\" }}\n\
             [[deployment]]\nid = \"{DEPLOYMENT}\"\nrepo = {{ name = \"{REPO}\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = {dir:?}, service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{rest}\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"{DEPLOYMENT}\"]\ncan = [\"approve\"]\n",
            dir = self.dir.to_str().unwrap(),
        )
    }

    fn config(&self, rest: &str) -> Config {
        parse_config(self.fleet(rest).as_bytes()).unwrap()
    }

    pub(super) fn deployment(&self, rest: &str) -> Deployment {
        self.config(rest).deployments()[0].clone()
    }

    pub(super) async fn deploy(&self, rest: &str, tag: &str, digest: &str) -> DeployReport {
        self.attempt(rest, tag, digest).await.unwrap()
    }

    pub(super) async fn attempt(
        &self,
        rest: &str,
        tag: &str,
        digest: &str,
    ) -> Result<DeployReport, DeployError> {
        let deployment = self.deployment(rest);
        let plan = plan(&deployment, tag, digest);
        // Boxed: in a workspace build, feature unification (tokio's
        // `rt-multi-thread` through the server crate) takes the engine's future
        // over clippy's size limit in every caller here.
        Box::pin(deploy::run(
            &self.docker,
            &self.state,
            &deployment,
            &self.dir,
            &plan,
            &self.options,
        ))
        .await
    }

    /// Runs `docker compose` in the compose directory, as an operator would.
    pub(super) fn compose_by_hand(&self, args: &[&str]) {
        let out = StdCommand::new("docker")
            .arg("compose")
            .args(args)
            .current_dir(&self.dir)
            .output()
            .unwrap();
        assert!(out.status.success(), "{args:?}: {out:?}");
    }

    /// The service's container and its start, to tell later that neither moved.
    pub(super) async fn running_since(&self) -> (ContainerId, Timestamp) {
        let id = self.container().await;
        let info = self.docker.inspect(&id).await.unwrap();
        assert_eq!(info.status, "running");
        (id, info.started_at)
    }

    /// Replaces `from` in the base compose file.
    pub(super) fn edit_compose(&self, from: &str, to: &str) {
        let file = self.dir.join("compose.yaml");
        let text = fs::read_to_string(&file).unwrap();
        assert!(text.contains(from), "{text}");
        fs::write(&file, text.replace(from, to)).unwrap();
    }

    /// A link to the compose directory, outside it.
    pub(super) fn symlink_to_dir(&self) -> PathBuf {
        let link = self.state_root.path().join("link-to-compose");
        std::os::unix::fs::symlink(&self.dir, &link).unwrap();
        link
    }

    /// [`Self::deploy`], and whether `seen` was ever true while it ran.
    pub(super) async fn deploy_watching(
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
    pub(super) fn b_started(&self) -> impl Fn() -> bool + use<> {
        let file = self.data("started-v1.28.4");
        move || fs::symlink_metadata(&file).is_ok()
    }

    pub(super) async fn container(&self) -> ContainerId {
        self.docker
            .container(&self.dir, "app")
            .await
            .unwrap()
            .expect("the service has a running container")
    }

    pub(super) async fn running_image(&self) -> String {
        let info = self.docker.inspect(&self.container().await).await.unwrap();
        assert_eq!(info.status, "running");
        info.image
    }

    /// Runs `script` in the service's container, as the service's user.
    pub(super) async fn in_container(&self, script: &str) {
        let argv = ["sh".to_owned(), "-c".to_owned(), script.to_owned()];
        let id = self.container().await;
        assert!(self.docker.exec(&id, &argv).await.unwrap(), "{script}");
    }

    /// The newest backup: their names sort by time.
    pub(super) fn newest_backup(&self) -> PathBuf {
        fs::read_dir(self.state.backups_dir())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .max()
            .unwrap()
    }

    /// Runs the real binary with `args` and the state directory.
    pub(super) async fn binary(&self, args: &[&str]) -> Output {
        self.binary_command(args).output().await.unwrap()
    }

    pub(super) fn binary_command(&self, args: &[&str]) -> tokio::process::Command {
        let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_landfall-agent"));
        command
            .args(args)
            .arg("--state-dir")
            .arg(self.state_root.path());
        command
    }

    pub(super) fn config_file(&self, rest: &str) -> PathBuf {
        let path = self.state_root.path().join("fleet.toml");
        fs::write(&path, self.fleet(rest)).unwrap();
        path
    }

    /// The real `status`: its exit status and its lines.
    pub(super) async fn status_lines(&self, rest: &str) -> (Option<i32>, Vec<Value>) {
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
    pub(super) async fn status(&self, rest: &str) -> Value {
        let (code, mut lines) = self.status_lines(rest).await;
        assert_eq!(code, Some(0), "{lines:?}");
        assert_eq!(lines.len(), 1, "{lines:?}");
        lines.remove(0)
    }

    pub(super) fn write_override_for(&self, rest: &str, digest: &str) {
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
pub(super) struct OtherProject(pub(super) String);

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
pub(super) fn labelled_working_dir(id: &ContainerId) -> String {
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
pub(super) fn options() -> EngineOptions {
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

pub(super) fn failed_step(report: &DeployReport, name: &str) -> bool {
    report
        .steps
        .iter()
        .any(|step| step.name == name && matches!(step.result, StepResult::Failed { .. }))
}

pub(super) fn assert_rolled_back(report: &DeployReport) {
    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
}

/// What a write, `chmod` or `chown` through a link to `/etc` would change: `/etc`
/// itself and what is directly in it.
pub(super) fn etc_fingerprint() -> Vec<(String, u64, i64, u32, u32, u32)> {
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
