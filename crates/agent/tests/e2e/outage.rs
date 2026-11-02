//! The controller goes away while a host deploys: the deploy doesn't notice, and
//! the report waits for it.

use crate::harness::{Fleet, Process};
use crate::world::digest_of;

/// A deploy reaches its `up`, `stop` ends the controller, the deploy finishes with
/// nobody to tell, and a controller started afterwards hears of it, once.
async fn deploy_outlives_the_controller(stop: impl AsyncFnOnce(&mut Process)) {
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
    assert_eq!(claimed[0].state, "claimed", "{claimed:?}");

    stop(&mut controller).await;
    fleet.world.release_up();
    fleet
        .wait_until("the report kept", async || {
            fleet.journalled("report_kept") > 0
        })
        .await;
    assert!(
        fleet
            .world
            .image()
            .unwrap()
            .ends_with(digest_of("v1.2.4").as_ref()),
        "the deploy finished without its controller"
    );
    let outbox = fleet.state_dir.join("outbox");
    assert_eq!(std::fs::read_dir(&outbox).unwrap().count(), 1);
    let ups = fleet.world.ups();

    let mut controller = fleet.controller().await;
    let finished = fleet.wait_finished("v1.2.4").await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert_eq!(finished.id, claimed[0].id, "under the number it was given");
    fleet.wait_running("v1.2.4").await;
    fleet
        .wait_until("the outbox emptied", async || {
            std::fs::read_dir(&outbox).unwrap().count() == 0
        })
        .await;

    // Once: one row of the audit log for it, one deploy, and nothing run again.
    fleet.let_the_watcher_look().await;
    let rows = fleet.audit().await;
    let reports = rows.iter().filter(|row| row.kind == "deploy_finished");
    assert_eq!(reports.count(), 1);
    assert_eq!(fleet.deploys().await.len(), 1);
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(fleet.journalled("report_delivered"), 1);
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}

#[tokio::test]
async fn a_report_reaches_a_controller_stopped_during_the_deploy_once_it_is_back() {
    deploy_outlives_the_controller(async |controller| controller.stop().await).await;
}

#[tokio::test]
async fn a_report_reaches_a_controller_killed_during_the_deploy_once_it_is_back() {
    deploy_outlives_the_controller(async |controller| controller.kill().await).await;
}
