//! Approvals with a real container: what a refusal leaves alone is a process, here.
//! `#[ignore]`d as in `docker_e2e/main.rs`, which has the images.

use landfall_agent::docker::{Docker as _, DockerCli};
use landfall_approval::SoftwareAuthenticator;
use serde_json::json;

use super::forged::forge;
use super::{Desk, nonces_spent, options_for, refusal_reason, tap, wait_askable, wait_deploy};
use crate::docker::{CHECK, FAILS, PASSES, REPO, digest, running_image, sleeping_project};
use crate::harness::{Fleet, FleetOptions};

#[tokio::test]
#[ignore = "needs Docker"]
async fn docker_an_approved_first_deploy_runs_and_a_forged_approval_leaves_the_container_alone() {
    let project = sleeping_project();
    let key = SoftwareAuthenticator::es256().unwrap();
    let fleet = Fleet::with(FleetOptions {
        repo: REPO.to_owned(),
        checks: CHECK.to_owned(),
        compose: Some(project.path().to_owned()),
        ..options_for(&key)
    });
    let mut controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    let mut agent = fleet.agent_on_docker();

    // A first deploy, on an approval, with nothing there before it.
    fleet.world.publish_digest("v1.2.3", &digest(PASSES));
    wait_askable(&fleet, "v1.2.3").await;
    assert_eq!(project.all_containers(), Vec::<String>::new());
    let request = desk.ask("v1.2.3").await;
    let first = desk.approve(&request).await;
    let finished = wait_deploy(&fleet, first).await;
    assert_eq!(
        finished.outcome.as_deref(),
        Some("deployed"),
        "{}",
        fleet.log("agent")
    );
    fleet.wait_running("v1.2.3").await;
    assert!(running_image(&fleet).await.ends_with(PASSES));
    let docker = DockerCli::new();
    let container = docker
        .container_at(&fleet.compose, "app")
        .await
        .unwrap()
        .expect("the service runs");
    let started = docker.inspect(&container).await.unwrap().started_at;
    let spent = nonces_spent(&fleet);
    assert_eq!(spent.len(), 1);

    // A forged approval of the next release, whose image would fail its check if it ran.
    fleet.world.publish_digest("v1.3.0", &digest(FAILS));
    wait_askable(&fleet, "v1.3.0").await;
    let asked = desk.ask("v1.3.0").await;
    let thief = SoftwareAuthenticator::es256().unwrap();
    let approval = json!({ "intent": asked["intent"], "assertion": tap(&thief, &asked) });
    agent.stop().await;
    let forged = forge(&fleet, "v1.3.0", Some((&asked, &approval))).await;
    let mut agent = fleet.agent_on_docker();

    let refused = wait_deploy(&fleet, forged).await;
    assert_eq!(refused.outcome.as_deref(), Some("refused"));
    let reason = refusal_reason(&fleet, forged).await;
    assert!(
        reason.contains("approval refused: no approver in this host's configuration"),
        "{reason}"
    );

    // The same container, never restarted, on the same image.
    let still = docker
        .container_at(&fleet.compose, "app")
        .await
        .unwrap()
        .expect("the service still runs");
    assert_eq!(still, container);
    assert_eq!(docker.inspect(&still).await.unwrap().started_at, started);
    assert!(running_image(&fleet).await.ends_with(PASSES));
    assert_eq!(project.all_containers().len(), 1);
    assert_eq!(nonces_spent(&fleet), spent);
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
