//! A person taking a deployment back to a lower version.

use landfall_approval::SoftwareAuthenticator;

use super::{Desk, nonces_spent, options_for, runs, wait_askable, wait_deploy};
use crate::harness::Fleet;

#[tokio::test]
async fn a_manual_rollback_takes_the_rollback_grant_and_an_approval() {
    let key = SoftwareAuthenticator::es256().unwrap();
    let fleet = Fleet::with(options_for(&key));
    let mut controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    fleet.world.publish("v1.3.0");
    wait_askable(&fleet, "v1.3.0").await;
    let upgrade = desk.ask("v1.3.0").await;
    let upgraded = desk.approve(&upgrade).await;
    wait_deploy(&fleet, upgraded).await;
    fleet.wait_running("v1.3.0").await;
    wait_askable(&fleet, "v1.2.3").await;
    let ups = fleet.world.ups();

    // `request` isn't enough to go down.
    let refused = desk.try_ask("v1.2.3").await;
    assert_eq!((refused.status, refused.code()), (403, "forbidden"));

    let request = desk.ask_in_person("v1.2.3").await;
    assert!(runs(&fleet, "v1.3.0"), "asking changes nothing");
    assert_eq!(fleet.world.ups(), ups);

    let deploy_id = desk.approve(&request).await;
    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.tag, "v1.2.3");
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    fleet.wait_running("v1.2.3").await;

    // What the host did: the lower version on record, and no failure of the higher.
    assert!(runs(&fleet, "v1.2.3"));
    assert_eq!(fleet.world.ups(), ups + 1);
    let state = fleet.deployment_state();
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.3");
    assert_eq!(state.failed_releases().unwrap(), []);
    assert_eq!(nonces_spent(&fleet).len(), 2);

    // And it stays there: the way up takes an approval again.
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await.len(), 2);
    assert!(runs(&fleet, "v1.2.3"));

    let rows = fleet.audit().await;
    let refused = rows.iter().find(|r| r.kind == "request_refused").unwrap();
    assert_eq!(refused.detail["problem"], "forbidden");
    assert_eq!(refused.detail["by"]["principal"], "ci");
    let asked = rows
        .iter()
        .find(|r| r.kind == "deploy_requested" && r.detail["tag"] == "v1.2.3")
        .unwrap();
    assert_eq!(asked.detail["by"]["principal"], "operator");
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
