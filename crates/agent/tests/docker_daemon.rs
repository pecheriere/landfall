//! One poll of the daemon against a real Docker daemon, with a fake controller
//! and a fake verifier: no test repository signs real releases. `#[ignore]`d, as
//! in `docker_e2e/main.rs`, which has the images and what each test needs. This one
//! runs as any user who can reach Docker.

#![cfg(test)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use std::time::Duration;

use landfall_agent::checks::CheckOptions;
use landfall_agent::client::{Controller, ControllerError};
use landfall_agent::compose::{OVERRIDE_FILE, resolve_dirs};
use landfall_agent::daemon::{DaemonOptions, Shutdown, StepOutcome, Verifier, VerifyFailure, step};
use landfall_agent::deploy::{self, DeployPlan, EngineOptions, Outcome};
use landfall_agent::docker::{Docker, DockerCli};
use landfall_agent::state::{DeploymentState, StateDir};
use landfall_core::config::{Config, parse};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::protocol::{
    DeployId, DeployReportBody, DeployWork, Phase, ReportedOutcome, WorkRequest, WorkResponse,
};
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::release::ReleaseOrigin;

#[path = "support/compose_project.rs"]
mod compose_project;

use compose_project::ComposeProject;

const REPO: &str = "containerd/busybox";
/// Tag 1.36: what runs before the poll.
const DIGEST_A: &str = "sha256:7b3ccabffc97de872a30dfd234fd972a66d247c8cfc69b0550f276481852627c";
/// Tag 1.28: the release the controller asks for.
const DIGEST_B: &str = "sha256:141c253bc4c3fd0a201d32dc1f493bcf3fff003b6df416dea4f41046e0f37d47";
const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const DEPLOYMENT: &str = "app/prod";

fn image(digest: &str) -> String {
    format!("ghcr.io/{REPO}@{digest}")
}

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

#[derive(Default)]
struct FakeController {
    work: Mutex<Vec<DeployWork>>,
    requests: Mutex<Vec<WorkRequest>>,
    reports: Mutex<Vec<DeployReportBody>>,
}

impl Controller for FakeController {
    fn work(
        &self,
        request: &WorkRequest,
    ) -> impl Future<Output = Result<WorkResponse, ControllerError>> + Send {
        self.requests.lock().unwrap().push(request.clone());
        std::future::ready(Ok(WorkResponse {
            work: self.work.lock().unwrap().pop(),
            held_back: Vec::new(),
        }))
    }

    fn report(
        &self,
        report: &DeployReportBody,
    ) -> impl Future<Output = Result<(), ControllerError>> + Send {
        self.reports.lock().unwrap().push(report.clone());
        std::future::ready(Ok(()))
    }
}

/// Verifies every release to the digest the test says it is.
struct FakeVerifier(String);

impl Verifier for FakeVerifier {
    fn verify(
        &self,
        _: &Config,
        _: &DeploymentId,
        _: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, VerifyFailure>> + Send {
        std::future::ready(Ok(origin(&self.0)))
    }
}

struct Stack {
    /// Removes the project when the test ends, however it ends.
    project: ComposeProject,
    dir: PathBuf,
    state_root: tempfile::TempDir,
    state: DeploymentState,
    config: Config,
    docker: DockerCli,
    options: DaemonOptions,
}

fn stack() -> Stack {
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let project = ComposeProject::create(&format!(
        "  app:\n    user: \"{uid}:{gid}\"\n    command: [\"sleep\", \"300\"]\n    stop_grace_period: 1s\n    networks: [net]\n"
    ));
    let dir = project.path().canonicalize().unwrap();
    fs::write(
        dir.join(".env"),
        format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
    )
    .unwrap();
    let state_root = tempfile::tempdir().unwrap();
    let id: DeploymentId = DEPLOYMENT.parse().unwrap();
    let state = StateDir::open(state_root.path())
        .unwrap()
        .deployment(&id)
        .unwrap();
    let text = format!(
        "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
         [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
         [[deployment]]\nid = \"{DEPLOYMENT}\"\nrepo = {{ name = \"{REPO}\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ auto = \"patch\", approvers = [\"operator\"] }}\nchecks = [{{ command = [\"true\"] }}]\n\
         [[grant]]\nprincipal = \"operator\"\ndeployments = [\"{DEPLOYMENT}\"]\ncan = [\"approve\"]\n",
        dir.to_str().unwrap()
    );
    let config = parse(text.as_bytes()).unwrap();
    let dirs: BTreeMap<_, _> = resolve_dirs(&config, &"home-1".parse().unwrap()).unwrap();
    let (trigger, shutdown) = Shutdown::channel();
    drop(trigger);
    let mut options = DaemonOptions::new(dirs, [1; 32], shutdown);
    options.engine = EngineOptions {
        checks: CheckOptions {
            interval: Duration::from_millis(200),
            deadline: Duration::from_secs(12),
            http_timeout: Duration::from_secs(2),
            settle: Duration::from_millis(500),
        },
        ..EngineOptions::default()
    };
    Stack {
        project,
        dir,
        state_root,
        state,
        config,
        docker: DockerCli::new(),
        options,
    }
}

async fn running_image(stack: &Stack) -> String {
    let id = stack
        .docker
        .container_at(&stack.dir, "app")
        .await
        .unwrap()
        .expect("the service runs");
    stack.docker.inspect(&id).await.unwrap().image
}

async fn poll(stack: &Stack, controller: &FakeController, verified: &str) -> StepOutcome {
    Box::pin(step(
        &stack.docker,
        controller,
        &FakeVerifier(verified.to_owned()),
        &stack.config,
        stack.state_root.path(),
        &stack.options,
    ))
    .await
}

fn work(deploy_id: u64, tag: &str) -> DeployWork {
    DeployWork {
        deploy_id: DeployId(deploy_id),
        deployment: DEPLOYMENT.parse().unwrap(),
        tag: tag.parse().unwrap(),
        digest: DIGEST_B.parse().unwrap(),
        commit: COMMIT.parse().unwrap(),
    }
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn docker_daemon_step_deploys_what_the_rule_allows_and_refuses_the_rest() {
    let stack = stack();

    // A running version on record, as a first deploy by an operator leaves it.
    let deployment = stack.config.deployments()[0].clone();
    let first = DeployPlan::from_verified(
        &deployment,
        &"v1.2.3".parse().unwrap(),
        semver::Version::new(1, 2, 3),
        &origin(DIGEST_A),
    );
    let report = Box::pin(deploy::run(
        &stack.docker,
        &stack.state,
        &deployment,
        &stack.dir,
        &first,
        &stack.options.engine,
    ))
    .await
    .unwrap();
    assert_eq!(report.outcome, Outcome::Deployed, "{report:?}");
    assert_eq!(running_image(&stack).await, image(DIGEST_A));

    // A minor under a patch rule: nothing moves.
    let controller = FakeController::default();
    controller.work.lock().unwrap().push(work(41, "v1.3.0"));
    let outcome = poll(&stack, &controller, DIGEST_B).await;
    assert!(
        matches!(
            &outcome,
            StepOutcome::Finished {
                deploy_id: DeployId(41),
                outcome: ReportedOutcome::Refused { .. },
                delivered: true,
            }
        ),
        "{outcome:?}"
    );
    assert_eq!(running_image(&stack).await, image(DIGEST_A));

    // The next patch: deployed on the real daemon and reported under the
    // controller's number.
    controller.work.lock().unwrap().push(work(42, "v1.2.4"));
    let outcome = poll(&stack, &controller, DIGEST_B).await;
    assert_eq!(
        outcome,
        StepOutcome::Finished {
            deploy_id: DeployId(42),
            outcome: ReportedOutcome::Deployed {},
            delivered: true,
        }
    );
    assert_eq!(running_image(&stack).await, image(DIGEST_B));
    assert_eq!(
        stack.state.deployed().unwrap().unwrap().tag.as_ref(),
        "v1.2.4"
    );
    let reports = controller.reports.lock().unwrap().clone();
    assert_eq!(reports.len(), 2);
    assert_eq!(reports[1].deploy_id, DeployId(42));
    assert!(reports[1].steps.iter().any(|s| s.name == "up"));

    // And the controller is told how things stand, with no drift on the real
    // container.
    assert_eq!(
        poll(&stack, &controller, DIGEST_B).await,
        StepOutcome::NoWork
    );
    let last = controller.requests.lock().unwrap().last().unwrap().running[0].clone();
    assert_eq!(last.deployed.unwrap().tag.as_ref(), "v1.2.4");
    assert_eq!(last.phase, Phase::Idle);
    assert!(!last.busy);
    assert!(!last.drift);
    assert_eq!(
        stack.project.all_containers().len(),
        1,
        "the release replaced the old container"
    );
}
