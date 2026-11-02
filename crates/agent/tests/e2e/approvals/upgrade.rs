//! A minor release under a rule that takes an approval for one.

use landfall_approval::SoftwareAuthenticator;

use super::{Desk, nonce_approved, nonces_spent, options_for, runs, wait_askable, wait_deploy};
use crate::harness::Fleet;
use crate::world::digest_of;

#[tokio::test]
async fn a_minor_upgrade_waits_for_an_approver_and_a_patch_after_it_does_not() {
    let key = SoftwareAuthenticator::eddsa().unwrap();
    let fleet = Fleet::with(options_for(&key));
    let mut controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    fleet.world.publish("v1.3.0");
    wait_askable(&fleet, "v1.3.0").await;
    let rows = fleet.audit().await;
    assert!(
        rows.iter().any(|row| row.kind == "rule_decision"
            && row.detail["tag"] == "v1.3.0"
            && row.detail["decision"] == "needs_approval"),
        "{rows:#?}"
    );
    let ups = fleet.world.ups();
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await, [], "it waits");
    assert!(runs(&fleet, "v1.2.3"));

    let request = desk.ask("v1.3.0").await;
    assert_eq!(
        request["intent"]["expected_running"].as_str(),
        Some(digest_of("v1.2.3").as_ref()),
        "the intent binds what the host said it runs"
    );
    let deploy_id = desk.approve(&request).await;

    // An approval goes through once, whoever asks.
    let again = desk.try_approve(&request).await;
    assert_eq!((again.status, again.code()), (409, "request_closed"));

    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    fleet.wait_running("v1.3.0").await;
    assert!(runs(&fleet, "v1.3.0"));
    assert_eq!(fleet.world.ups(), ups + 1);
    let spent = nonces_spent(&fleet);
    assert_eq!(spent, [nonce_approved(&fleet, deploy_id).await]);

    // A patch on top is automatic, so it takes nobody and spends nothing.
    fleet.world.publish("v1.3.1");
    let patch = fleet.wait_finished("v1.3.1").await;
    assert_eq!(patch.outcome.as_deref(), Some("deployed"));
    assert!(runs(&fleet, "v1.3.1"));
    assert_eq!(nonces_spent(&fleet), spent);

    let rows = fleet.audit().await;
    assert_eq!(
        rows.iter().filter(|r| r.kind == "request_approved").count(),
        1
    );
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
