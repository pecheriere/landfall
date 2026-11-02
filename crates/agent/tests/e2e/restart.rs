//! The agent stopped or killed while a deploy is in flight.

use std::time::Duration;

use landfall_agent::deploy::{self, Outcome};
use rustix::process::Signal;

use crate::harness::{Fleet, quick_engine};
use crate::world::{SimDocker, digest_of};

/// SIGTERM finishes the deploy first. What was asked for is done, reported, and not
/// run again by the agent that comes after.
#[tokio::test]
async fn a_stop_during_a_deploy_finishes_and_reports_it_first() {
    let fleet = Fleet::new();
    let mut controller = fleet.controller().await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    fleet.world.hold_up();
    fleet.world.publish("v1.2.4");
    fleet.wait_at_up().await;

    agent.signal(Signal::TERM);
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(agent.running(), "it waits for the deploy");
    assert_eq!(fleet.deploys().await[0].state, "claimed");

    fleet.world.release_up();
    assert_eq!(agent.exit_status().await, 0);
    assert_eq!(
        fleet.journalled("agent_stopping"),
        1,
        "{}",
        fleet.log("agent")
    );
    let finished = fleet.wait_finished("v1.2.4").await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert_eq!(
        fleet.deployment_state().in_progress().unwrap(),
        None,
        "nothing is left unfinished"
    );
    let ups = fleet.world.ups();

    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.4").await;
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(fleet.deploys().await.len(), 1);

    agent.stop().await;
    controller.stop().await;
}

/// SIGKILL leaves the deploy unfinished. The agent that comes after blocks it, is
/// given it again under the same number, waits for `recover`, and reports what that
/// came to under that number.
#[tokio::test]
async fn a_kill_during_a_deploy_waits_for_recover_and_reports_under_the_same_number() {
    let fleet = Fleet::new();
    let mut controller = fleet.controller().await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    fleet.world.hold_up();
    fleet.world.publish("v1.2.4");
    fleet.wait_at_up().await;
    let claimed = fleet.deploys().await;

    agent.kill().await;
    let state = fleet.deployment_state();
    assert!(state.in_progress().unwrap().is_some(), "the marker stays");
    assert!(state.claim().unwrap().is_some(), "the number stays");
    fleet.world.release_up();

    let mut agent = fleet.agent();
    fleet
        .wait_until("the restarted agent waiting for recover", async || {
            fleet.log("agent").contains("landfall-agent recover")
        })
        .await;
    assert_eq!(fleet.deploys().await, claimed, "still claimed, still one");
    assert!(state.in_progress().unwrap().is_some());

    let report = Box::pin(deploy::recover(
        &SimDocker(fleet.world.clone()),
        &state,
        &fleet.config.deployments()[0],
        &fleet.compose,
        &quick_engine(),
    ))
    .await
    .unwrap();
    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{report:?}"
    );

    let finished = fleet.wait_finished("v1.2.4").await;
    assert_eq!(finished.id, claimed[0].id);
    assert_eq!(finished.outcome.as_deref(), Some("rolled_back"));
    assert!(
        fleet
            .world
            .image()
            .unwrap()
            .ends_with(digest_of("v1.2.3").as_ref())
    );
    fleet.wait_running("v1.2.3").await;

    // It failed here, so it is over, and the next one goes.
    fleet.world.publish("v1.2.5");
    let next = fleet.wait_finished("v1.2.5").await;
    assert_eq!(next.outcome.as_deref(), Some("deployed"));
    assert_eq!(fleet.deploys().await.len(), 2);
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
