//! The engine against a fake Docker and a real state directory.

use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use landfall_core::config::{Deployment, parse};
use serde_json::Value;

use super::{DeployError, DeployPlan, EngineOptions, StepResult, recover, run};
use crate::checks::CheckOptions;
use crate::compose::{self, OVERRIDE_FILE};
use crate::docker::{ContainerInfo, ServiceConfig};
use crate::safefs::{self, RelPath, Root};
use crate::state::{Deployed, DeploymentState, InProgress, Phase, RecordedBackup, StateDir};
use crate::testing::{Call, FakeDocker, running};

mod backups;
mod drift;
mod plan_and_report;
mod recover_phases;
mod recovery;
mod refusals;
mod rollback;
mod sequence;
mod state_writes;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const COMMIT: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

const PINNED: &str =
    "ghcr.io/example/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

const OLD: &str =
    "ghcr.io/example/app@sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

const PREVIOUS: &str = "# the previous override\nservices: {}\n";

const STOP_TRUE: &str = "backup = { paths = [\"data\"], stop = true }\n";

const STOP_FALSE: &str = "backup = { paths = [\"data\"], stop = false }\n";

const DEPLOY_ID: &str = "2026-11-01T10-00-00-000000000Z";

struct Fixture {
    _tmp: tempfile::TempDir,
    dir: PathBuf,
    state: DeploymentState,
    docker: FakeDocker,
    deployment: Deployment,
    plan: DeployPlan,
}

fn deployment(backup: &str) -> Deployment {
    deployment_with_checks(&format!("checks = [\"container-healthy\"]\n{backup}"))
}

/// A deployment with `rest` as the last lines of its table.
fn deployment_with_checks(rest: &str) -> Deployment {
    let text = format!(
        "[signers]\nmaintainer = \"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn\"\n\
             [approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"app/prod\"\nrepo = {{ name = \"example/app\", id = 1, owner_id = 2 }}\n\
             host = \"home-1\"\ncompose = {{ dir = \"/srv/compose/app\", service = \"app\" }}\n\
             origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
             rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{rest}\
             [[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\ncan = [\"approve\"]\n"
    );
    parse(text.as_bytes()).unwrap().deployments()[0].clone()
}

/// A compose directory with a previous override and `data/db` holding
/// "before", and an empty state directory.
fn fixture(backup: &str) -> Fixture {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path().canonicalize().unwrap();
    let dir = root.join("compose");
    fs::create_dir_all(dir.join("data")).unwrap();
    fs::write(dir.join("data/db"), "before").unwrap();
    fs::write(dir.join(OVERRIDE_FILE), PREVIOUS).unwrap();
    let state_root = root.join("state");
    fs::create_dir(&state_root).unwrap();
    let deployment = deployment(backup);
    let state = StateDir::open(&state_root)
        .unwrap()
        .deployment(deployment.id())
        .unwrap();
    let plan = DeployPlan::for_test(&deployment, "v1.2.3", DIGEST, COMMIT);
    Fixture {
        _tmp: tmp,
        dir,
        state,
        docker: FakeDocker::new(),
        deployment,
        plan,
    }
}

fn options() -> EngineOptions {
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

fn image(image: Option<&str>) -> ServiceConfig {
    ServiceConfig {
        image: image.map(str::to_owned),
        has_build: false,
        replicas: 1,
    }
}

/// A running container of `image`; without a healthcheck, the check of
/// these deployments fails for good.
fn container(image: &str, healthy: bool) -> ContainerInfo {
    let mut info = running(healthy.then_some("healthy"), &[]);
    image.clone_into(&mut info.image);
    info
}

/// The project resolves to `previous`, then to the pinned image while the
/// new override is in place, and to `previous` once it is back.
fn resolves(f: &Fixture, previous: Option<&str>) {
    f.docker.script_compose_service([
        Ok(image(previous)),
        Ok(image(Some(PINNED))),
        Ok(image(previous)),
    ]);
}

/// The deploy succeeds: the new image runs and is healthy.
fn healthy_deploy(f: &Fixture) {
    resolves(f, Some(OLD));
    f.docker.script_inspect([Ok(container(PINNED, true))]);
}

/// The new image runs and fails its check for good; once the service is
/// up for the second time, the previous image runs and is healthy.
fn failing_check(f: &Fixture, previous: &str) {
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(previous, true))]);
}

/// The calls that change something, and the configuration reads, in order.
/// Reads of the running state are left out: how many of those a check
/// takes is its own business.
fn changes(f: &Fixture) -> Vec<&'static str> {
    f.docker
        .calls()
        .iter()
        .filter_map(|call| match call {
            Call::Pull(_) => Some("pull"),
            Call::ComposeService { .. } | Call::ComposeServiceChecked { .. } => Some("config"),
            Call::ComposeUp { .. } => Some("up"),
            Call::ComposeStop { .. } => Some("stop"),
            _ => None,
        })
        .collect()
}

fn count_ups(f: &Fixture) -> usize {
    f.docker.count(|c| matches!(c, Call::ComposeUp { .. }))
}

fn count_stops(f: &Fixture) -> usize {
    f.docker.count(|c| matches!(c, Call::ComposeStop { .. }))
}

fn override_text(dir: &std::path::Path) -> String {
    fs::read_to_string(dir.join(OVERRIDE_FILE)).unwrap()
}

fn rendered(f: &Fixture) -> String {
    compose::render_override(
        "app",
        PINNED,
        f.deployment.id(),
        f.plan.tag(),
        f.plan.commit(),
    )
}

fn data(f: &Fixture) -> String {
    fs::read_to_string(f.dir.join("data/db")).unwrap()
}

/// What "the new version" does to the data: rewrites `data/db`, adds a file.
fn migrate(dir: &std::path::Path) {
    fs::write(dir.join("data/db"), "migrated").unwrap();
    fs::write(dir.join("data/extra"), "new").unwrap();
}

/// On every `up` while the new override is in place, the data changes.
fn new_version_migrates(f: &Fixture) {
    let dir = f.dir.clone();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) && override_text(&dir).contains(PINNED) {
            migrate(&dir);
        }
    });
}

async fn deploy(f: &Fixture) -> Result<super::DeployReport, DeployError> {
    run(
        &f.docker,
        &f.state,
        &f.deployment,
        &f.dir,
        &f.plan,
        &options(),
    )
    .await
}

async fn deploy_with(
    f: &Fixture,
    options: &EngineOptions,
) -> Result<super::DeployReport, DeployError> {
    run(&f.docker, &f.state, &f.deployment, &f.dir, &f.plan, options).await
}

async fn recovered(f: &Fixture) -> Result<super::DeployReport, DeployError> {
    recover(&f.docker, &f.state, &f.deployment, &f.dir, &options()).await
}

fn backups(f: &Fixture) -> Vec<String> {
    let mut names: Vec<String> = match fs::read_dir(f.state.backups_dir()) {
        Ok(entries) => entries
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect(),
        Err(_) => Vec::new(),
    };
    names.sort();
    names
}

fn reports(f: &Fixture) -> Vec<Value> {
    let dir = f.state.backups_dir().with_file_name("reports");
    fs::read_dir(dir)
        .unwrap()
        .map(|e| serde_json::from_slice(&fs::read(e.unwrap().path()).unwrap()).unwrap())
        .collect()
}

fn step_names(report: &super::DeployReport) -> Vec<&str> {
    report.steps.iter().map(|s| s.name.as_str()).collect()
}

/// The state an agent leaves behind when it dies after starting the new
/// version: in-progress with a backup, the new override, changed data.
fn interrupted(f: &Fixture) {
    f.state.set_previous_override(PREVIOUS.as_bytes()).unwrap();
    f.state
        .set_previous_deployed(f.state.deployed().unwrap().as_ref())
        .unwrap();
    fs::create_dir_all(f.state.backups_dir()).unwrap();
    let id = "2026-11-01T10-00-00-000000000Z";
    safefs::snapshot(
        &Root::open(&f.dir).unwrap(),
        &[RelPath::new("data").unwrap()],
        &f.state.backups_dir().join(id),
    )
    .unwrap();
    f.state
        .set_in_progress(&InProgress {
            deploy_id: DEPLOY_ID.to_owned(),
            phase: Phase::Deploying,
            tag: f.plan.tag().clone(),
            digest: f.plan.digest().clone(),
            previous_can_start: true,
            backup: Some(RecordedBackup {
                id: id.to_owned(),
                paths: vec!["data".to_owned()],
            }),
            started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
        })
        .unwrap();
    fs::write(f.dir.join(OVERRIDE_FILE), rendered(f)).unwrap();
    fs::write(f.dir.join("data/db"), "half migrated").unwrap();
}

/// The record of an earlier deploy, of an earlier release.
fn earlier_release(f: &Fixture) -> Deployed {
    Deployed {
        deploy_id: "2026-10-01T10-00-00-000000000Z".to_owned(),
        tag: "v1.2.2".parse().unwrap(),
        version: semver::Version::new(1, 2, 2),
        digest: f.plan.digest().clone(),
        commit: f.plan.commit().clone(),
        deployed_at: "2026-10-01T10:01:00Z".parse().unwrap(),
    }
}

/// Runs a deploy up to the `nth` call that `pick` chooses, and kills it
/// there, the way a dying process does: what is on disk stays, the lock
/// goes, and nothing else runs.
async fn crash_at(f: &Fixture, nth: usize, pick: fn(&Call) -> bool) {
    let seen = Arc::new(Mutex::new(0));
    let hit = Arc::new(Mutex::new(false));
    let reached = Arc::clone(&hit);
    f.docker.hang_when(move |call| {
        if !pick(call) {
            return false;
        }
        let mut seen = seen.lock().unwrap();
        *seen += 1;
        if *seen - 1 == nth {
            *reached.lock().unwrap() = true;
            return true;
        }
        false
    });
    let crashed = async {
        while !*hit.lock().unwrap() {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    };
    tokio::select! {
        result = deploy(f) => panic!("the deploy finished: {result:?}"),
        () = crashed => {}
    }
    f.docker.hang_when(|_| false);
}

/// The lock is free again: late file work has ended.
async fn late_work_has_ended(f: &Fixture) {
    for _ in 0..5000 {
        if f.state.lock().is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("the lock was never released");
}

/// The new image passes its checks; the previous one does after an `up`.
fn new_passes_then_previous_passes(f: &Fixture) {
    resolves(f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, true))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
}

fn step_failed(report: &super::DeployReport, name: &str) -> bool {
    report
        .steps
        .iter()
        .any(|s| s.name == name && matches!(s.result, StepResult::Failed { .. }))
}
