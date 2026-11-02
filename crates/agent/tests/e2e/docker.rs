//! The same way a release takes, on a real Docker daemon. The verifier stays fake,
//! as no test repository signs real releases. `#[ignore]`d as in `docker_e2e/main.rs`,
//! which has the images. It runs as any user who can reach Docker.

use std::fs;

use landfall_agent::compose::OVERRIDE_FILE;
use landfall_agent::docker::{Docker as _, DockerCli};
use landfall_core::ids::ImageDigest;

use crate::harness::{Fleet, FleetOptions};

#[path = "../support/compose_project.rs"]
mod compose_project;

pub use compose_project::ComposeProject;

pub const REPO: &str = "containerd/busybox";
/// Tag 1.36: it fails the deployment's check.
pub const FAILS: &str = "sha256:7b3ccabffc97de872a30dfd234fd972a66d247c8cfc69b0550f276481852627c";
/// Tag 1.28: it passes.
pub const PASSES: &str = "sha256:141c253bc4c3fd0a201d32dc1f493bcf3fff003b6df416dea4f41046e0f37d47";
pub const CHECK: &str =
    "checks = [{ command = [\"sh\", \"-c\", \"! busybox | head -n 1 | grep -q v1.36\"] }]";

pub fn digest(text: &str) -> ImageDigest {
    text.parse().unwrap()
}

pub async fn running_image(fleet: &Fleet) -> String {
    let docker = DockerCli::new();
    let id = docker
        .container_at(&fleet.compose, "app")
        .await
        .unwrap()
        .expect("the service runs");
    docker.inspect(&id).await.unwrap().image
}

/// A service that sleeps as this user, in a project the override applies to.
pub fn sleeping_project() -> ComposeProject {
    let (uid, gid) = (
        rustix::process::geteuid().as_raw(),
        rustix::process::getegid().as_raw(),
    );
    let project = ComposeProject::create(&format!(
        "  app:\n    user: \"{uid}:{gid}\"\n    command: [\"sleep\", \"300\"]\n    stop_grace_period: 1s\n    networks: [net]\n"
    ));
    fs::write(
        project.path().join(".env"),
        format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
    )
    .unwrap();
    project
}

#[tokio::test]
#[ignore = "needs Docker"]
async fn docker_controller_and_agent_deploy_roll_back_and_finish_through_a_stop() {
    let project = sleeping_project();
    let fleet = Fleet::with(FleetOptions {
        repo: REPO.to_owned(),
        checks: CHECK.to_owned(),
        compose: Some(project.path().to_owned()),
        ..FleetOptions::default()
    });

    let mut controller = fleet.controller().await;
    fleet.enrol();
    let first = fleet.world.publish_digest("v1.2.3", &digest(PASSES));
    fleet.seed_on(&DockerCli::new(), &first).await;
    let mut agent = fleet.agent_on_docker();
    fleet.wait_running("v1.2.3").await;

    // A release that fails its check on the real container is rolled back on it.
    fleet.world.publish_digest("v1.2.4", &digest(FAILS));
    let failed = fleet.wait_finished("v1.2.4").await;
    assert_eq!(failed.outcome.as_deref(), Some("rolled_back"));
    assert!(running_image(&fleet).await.ends_with(PASSES));
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await.len(), 1, "not queued again");

    // The next one goes, and a stop while it runs waits for it.
    fleet.world.publish_digest("v1.2.5", &digest(PASSES));
    let state = fleet.deployment_state();
    fleet
        .wait_until("the deploy under way", async || {
            state.in_progress().unwrap().is_some()
        })
        .await;
    agent.stop().await;
    let finished = fleet.wait_finished("v1.2.5").await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert!(state.in_progress().unwrap().is_none());
    assert_eq!(project.all_containers().len(), 1);

    let mut agent = fleet.agent_on_docker();
    fleet.wait_running("v1.2.5").await;
    assert_eq!(fleet.audit_verify(None).status, 0);
    agent.stop().await;
    controller.stop().await;
}
