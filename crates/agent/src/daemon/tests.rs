//! The daemon against a fake controller, a fake verifier and a fake Docker. A
//! compromised controller is the case these are mostly about: see [`refusals`].

use std::collections::{BTreeMap, VecDeque};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use jiff::Timestamp;
use landfall_core::config::{Config, parse};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::protocol::{
    DeployId, DeployReportBody, DeployWork, ReportedOutcome, WorkRequest, WorkResponse,
};
use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::release::ReleaseOrigin;
use reqwest::StatusCode;

use super::{DaemonOptions, Shutdown, ShutdownTrigger, StepOutcome, Verifier, VerifyFailure, step};
use crate::checks::CheckOptions;
use crate::client::{Controller, ControllerError};
use crate::compose::{self, OVERRIDE_FILE};
use crate::deploy::EngineOptions;
use crate::docker::{ContainerInfo, ServiceConfig};
use crate::journal::{Priority, capture};
use crate::state::{ControllerClaim, Deployed, DeploymentState, InProgress, StateDir};
use crate::testing::{Call, FakeDocker, running};

mod after_a_deploy;
mod failure_evidence;
mod lifecycle;
mod refusals;
mod reports;

const ID: &str = "app/prod";
const OLD_DIGEST: &str = "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const OLD: &str =
    "ghcr.io/example/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const NEW_DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEW: &str =
    "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const PATCH_RULE: &str = "auto = \"patch\", approve = \"minor\"";

fn id() -> DeploymentId {
    ID.parse().unwrap()
}

fn deployment_text(id: &str, dir: &Path, rule: &str) -> String {
    format!(
        "[[deployment]]\nid = \"{id}\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ {rule}, approvers = [\"operator\"] }}\nchecks = [\"container-healthy\"]\n",
        dir.to_str().unwrap()
    )
}

fn fleet(deployments: &str, ids: &str) -> String {
    format!(
        "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
         [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
         {deployments}\
         [[grant]]\nprincipal = \"operator\"\ndeployments = [{ids}]\ncan = [\"approve\"]\n"
    )
}

fn container(image: &str, healthy: bool) -> ContainerInfo {
    let mut info = running(healthy.then_some("healthy"), &[]);
    image.clone_into(&mut info.image);
    info
}

fn image(image: &str) -> ServiceConfig {
    ServiceConfig {
        image: Some(image.to_owned()),
        has_build: false,
        replicas: 1,
    }
}

fn work(deploy_id: u64, tag: &str) -> DeployWork {
    DeployWork {
        deploy_id: DeployId(deploy_id),
        deployment: id(),
        tag: tag.parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        commit: COMMIT.parse().unwrap(),
    }
}

fn origin(digest: &str, commit: &str) -> ReleaseOrigin {
    ReleaseOrigin {
        commit: commit.parse().unwrap(),
        tag: None,
        attestation: VerifiedAttestation {
            digest: digest.parse().unwrap(),
            san: String::new(),
            commit: commit.parse().unwrap(),
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

/// What the fake controller does with a `work` call.
enum Answer {
    Work(WorkResponse),
    Hang,
}

fn answer(item: Option<DeployWork>) -> Answer {
    Answer::Work(WorkResponse {
        work: item,
        held_back: Vec::new(),
    })
}

#[derive(Default)]
struct FakeController {
    answers: Mutex<VecDeque<Answer>>,
    requests: Mutex<Vec<WorkRequest>>,
    reports: Mutex<Vec<DeployReportBody>>,
    /// Every request fails as an outage does.
    down: Mutex<bool>,
    /// A report gets this status, with nothing to say it's the API's.
    report_status: Mutex<Option<StatusCode>>,
    /// A report gets the API's refusal for good.
    report_rejected: Mutex<bool>,
    report_attempts: Mutex<usize>,
}

impl FakeController {
    fn with(answers: impl IntoIterator<Item = Answer>) -> Self {
        let fake = Self::default();
        fake.answers.lock().unwrap().extend(answers);
        fake
    }

    fn set_down(&self, down: bool) {
        *self.down.lock().unwrap() = down;
    }

    fn reports(&self) -> Vec<DeployReportBody> {
        self.reports.lock().unwrap().clone()
    }

    fn requests(&self) -> Vec<WorkRequest> {
        self.requests.lock().unwrap().clone()
    }

    fn outage(&self) -> Result<(), ControllerError> {
        if *self.down.lock().unwrap() {
            Err(ControllerError::Transport("connection refused".to_owned()))
        } else {
            Ok(())
        }
    }
}

impl Controller for FakeController {
    async fn work(&self, request: &WorkRequest) -> Result<WorkResponse, ControllerError> {
        self.requests.lock().unwrap().push(request.clone());
        self.outage()?;
        let next = self.answers.lock().unwrap().pop_front();
        match next {
            Some(Answer::Work(response)) => Ok(response),
            Some(Answer::Hang) => std::future::pending().await,
            None => Ok(WorkResponse {
                work: None,
                held_back: Vec::new(),
            }),
        }
    }

    fn report(
        &self,
        report: &DeployReportBody,
    ) -> impl Future<Output = Result<(), ControllerError>> + Send {
        *self.report_attempts.lock().unwrap() += 1;
        let refused = *self.report_status.lock().unwrap();
        let rejected = *self.report_rejected.lock().unwrap();
        let result = self.outage().and_then(|()| {
            if rejected {
                return Err(ControllerError::Rejected {
                    status: StatusCode::NOT_FOUND,
                    code: "unknown_deploy",
                    title: "\"no\"".to_owned(),
                });
            }
            if let Some(status) = refused {
                return Err(ControllerError::Status {
                    status,
                    detail: "\"no\"".to_owned(),
                });
            }
            self.reports.lock().unwrap().push(report.clone());
            Ok(())
        });
        std::future::ready(result)
    }
}

struct FakeVerifier {
    result: Result<ReleaseOrigin, VerifyFailure>,
    calls: Mutex<usize>,
    /// Asks for a stop while it verifies.
    stop: Mutex<Option<ShutdownTrigger>>,
}

impl FakeVerifier {
    fn answering(result: Result<ReleaseOrigin, VerifyFailure>) -> Self {
        Self {
            result,
            calls: Mutex::new(0),
            stop: Mutex::new(None),
        }
    }

    /// Verifies every release to the new digest and the commit.
    fn passes() -> Self {
        Self::answering(Ok(origin(NEW_DIGEST, COMMIT)))
    }

    fn calls(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl Verifier for FakeVerifier {
    fn verify(
        &self,
        _: &Config,
        _: &DeploymentId,
        _: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, VerifyFailure>> + Send {
        *self.calls.lock().unwrap() += 1;
        if let Some(trigger) = &*self.stop.lock().unwrap() {
            trigger.stop();
        }
        std::future::ready(self.result.clone())
    }
}

fn engine_options() -> EngineOptions {
    EngineOptions {
        checks: CheckOptions {
            interval: Duration::from_millis(1),
            deadline: Duration::from_millis(500),
            http_timeout: Duration::from_millis(100),
            settle: Duration::from_millis(1),
        },
        ..EngineOptions::default()
    }
}

struct Fixture {
    _tmp: tempfile::TempDir,
    compose: PathBuf,
    state_dir: PathBuf,
    config: Config,
    docker: FakeDocker,
    options: DaemonOptions,
}

/// `app/prod` under `rule`, on record and running at v1.2.3 with nothing
/// drifted, with a project that goes to the new image.
fn fixture(rule: &str) -> Fixture {
    let f = bare_fixture(rule);
    state_of(&f)
        .set_deployed(&deployed_at("v1.2.3", 1, 2, 3))
        .unwrap();
    f
}

/// [`fixture`] with no record of a deploy.
fn bare_fixture(rule: &str) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let compose = root.join("compose");
    fs::create_dir(&compose).unwrap();
    let state_dir = root.join("state");
    fs::create_dir(&state_dir).unwrap();
    let text = fleet(&deployment_text(ID, &compose, rule), &format!("\"{ID}\""));
    let config = parse(text.as_bytes()).unwrap();
    fs::write(
        compose.join(OVERRIDE_FILE),
        compose::render_override(
            "app",
            OLD,
            &id(),
            &"v1.2.3".parse().unwrap(),
            &COMMIT.parse().unwrap(),
        ),
    )
    .unwrap();
    let docker = FakeDocker::new();
    docker.script_inspect_after_up(0, [Ok(container(OLD, true))]);
    docker.script_inspect_after_up(1, [Ok(container(NEW, true))]);
    docker.script_compose_service([Ok(image(OLD)), Ok(image(NEW)), Ok(image(OLD))]);
    let mut options = options_for(BTreeMap::from([(id(), compose.clone())]));
    options.heartbeat = Duration::from_secs(3600);
    Fixture {
        _tmp: tmp,
        compose,
        state_dir,
        config,
        docker,
        options,
    }
}

/// Fast options that nothing stops, unless a test puts its own [`Shutdown`] in.
fn options_for(dirs: BTreeMap<DeploymentId, PathBuf>) -> DaemonOptions {
    let (trigger, shutdown) = Shutdown::channel();
    drop(trigger);
    let mut options = DaemonOptions::new(dirs, [9; 32], shutdown);
    options.engine = engine_options();
    options
}

fn deployed_at(tag: &str, major: u64, minor: u64, patch: u64) -> Deployed {
    Deployed {
        deploy_id: "2026-10-01T10-00-00-000000000Z".to_owned(),
        tag: tag.parse().unwrap(),
        version: semver::Version::new(major, minor, patch),
        digest: OLD_DIGEST.parse().unwrap(),
        commit: COMMIT.parse().unwrap(),
        deployed_at: Timestamp::UNIX_EPOCH,
    }
}

fn state_of(f: &Fixture) -> DeploymentState {
    StateDir::open(&f.state_dir)
        .unwrap()
        .deployment(&id())
        .unwrap()
}

fn outbox(f: &Fixture) -> Vec<DeployReportBody> {
    StateDir::open(&f.state_dir).unwrap().outbox().unwrap()
}

fn marker(phase: crate::state::Phase) -> InProgress {
    InProgress {
        deploy_id: "2026-11-01T10-00-00-000000000Z".to_owned(),
        phase,
        tag: "v1.2.4".parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        previous_can_start: true,
        backup: None,
        started_at: Timestamp::now(),
    }
}

fn claim(deploy_id: u64) -> ControllerClaim {
    ControllerClaim {
        deploy_id: DeployId(deploy_id),
        tag: "v1.2.4".parse().unwrap(),
        digest: NEW_DIGEST.parse().unwrap(),
        reports_before: Vec::new(),
    }
}

async fn poll(f: &Fixture, controller: &FakeController, verifier: &FakeVerifier) -> StepOutcome {
    Box::pin(step(
        &f.docker,
        controller,
        verifier,
        &f.config,
        &f.state_dir,
        &f.options,
    ))
    .await
}

/// The calls that change what runs. Reading what runs is fine for a refusal.
fn touched(docker: &FakeDocker) -> Vec<Call> {
    docker
        .calls()
        .into_iter()
        .filter(|call| {
            matches!(
                call,
                Call::Pull(_)
                    | Call::ComposeUp { .. }
                    | Call::ComposeStop { .. }
                    | Call::ComposeService { .. }
                    | Call::ComposeServiceChecked { .. }
            )
        })
        .collect()
}

/// Runs a work item that must be refused, checks that nothing ran and returns
/// why it was refused and at what priority the journal said so.
async fn assert_refused(
    f: &Fixture,
    verifier: &FakeVerifier,
    item: DeployWork,
) -> (String, Priority) {
    let controller = FakeController::with([answer(Some(item.clone()))]);
    let seen_before = capture::events("controller_work_refused").len();
    let marker_before = state_of(f).in_progress().unwrap();

    let outcome = poll(f, &controller, verifier).await;

    let reports = controller.reports();
    assert_eq!(reports.len(), 1, "{outcome:?}");
    assert_eq!(reports[0].deploy_id, item.deploy_id);
    assert!(reports[0].steps.is_empty(), "no step ran");
    let ReportedOutcome::Refused { reason } = &reports[0].outcome else {
        panic!("not refused: {:?}", reports[0].outcome);
    };
    assert_eq!(
        outcome,
        StepOutcome::Finished {
            deploy_id: item.deploy_id,
            outcome: reports[0].outcome.clone(),
            delivered: true,
        }
    );
    assert_eq!(touched(&f.docker), [], "{reason}");
    assert_eq!(state_of(f).in_progress().unwrap(), marker_before);
    assert_eq!(state_of(f).claim().unwrap(), None);
    assert_eq!(outbox(f), [], "acknowledged");

    let events = capture::events("controller_work_refused");
    assert_eq!(events.len(), seen_before + 1);
    let (priority, event) = events.last().unwrap();
    assert_eq!(event["reason"], reason.as_str(), "the journal says why too");
    assert_eq!(event["deploy_id"], item.deploy_id.0);
    (reason.clone(), *priority)
}
