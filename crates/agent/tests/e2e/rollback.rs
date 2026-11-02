//! A release that fails on its host stays failed, and the next one is another matter.

use crate::harness::Fleet;
use crate::world::digest_of;

#[tokio::test]
async fn a_rollback_keeps_the_old_version_is_not_queued_again_and_the_next_release_goes() {
    let fleet = Fleet::new();
    let mut controller = fleet.controller().await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    fleet.world.fail_checks_on("v1.2.4");
    fleet.world.publish("v1.2.4");
    let failed = fleet.wait_finished("v1.2.4").await;
    assert_eq!(failed.outcome.as_deref(), Some("rolled_back"));
    assert!(
        fleet
            .world
            .image()
            .unwrap()
            .ends_with(digest_of("v1.2.3").as_ref()),
        "the old version runs again"
    );
    let state = fleet.deployment_state();
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.3");
    assert_eq!(
        fleet.running_tag().await.flatten().as_deref(),
        Some("v1.2.3")
    );
    let remembered = state.failed_releases().unwrap();
    assert_eq!(remembered.len(), 1);
    assert_eq!(remembered[0].tag.as_ref(), "v1.2.4");

    // The controller looks again and again, and leaves it, saying why.
    fleet
        .wait_until("the failed release refused", async || {
            fleet.audit().await.iter().any(|row| {
                row.kind == "rule_decision"
                    && row.detail["tag"] == "v1.2.4"
                    && row.detail["decision"] == "refused"
            })
        })
        .await;
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await.len(), 1, "not queued again");

    // The next newer one is.
    fleet.world.publish("v1.2.5");
    let next = fleet.wait_finished("v1.2.5").await;
    assert_eq!(next.outcome.as_deref(), Some("deployed"));
    fleet.wait_running("v1.2.5").await;
    assert_eq!(fleet.deploys().await.len(), 2);

    // And it is still not queued after the controller starts over.
    controller.stop().await;
    let mut controller = fleet.controller().await;
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await.len(), 2);
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
