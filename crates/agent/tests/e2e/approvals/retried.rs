//! A release that failed on its host, tried again by a person.

use landfall_approval::SoftwareAuthenticator;

use super::{Desk, nonce_approved, nonces_spent, options_for, runs, wait_askable, wait_deploy};
use crate::harness::Fleet;

#[tokio::test]
async fn a_release_that_rolled_back_runs_again_only_on_an_approval() {
    let key = SoftwareAuthenticator::es256().unwrap();
    let fleet = Fleet::with(options_for(&key));
    let mut controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;

    // A patch, so it is automatic, and it fails its checks.
    fleet.world.fail_checks_on("v1.2.4");
    fleet.world.publish("v1.2.4");
    let failed = fleet.wait_finished("v1.2.4").await;
    assert_eq!(failed.outcome.as_deref(), Some("rolled_back"));
    assert!(runs(&fleet, "v1.2.3"));
    let state = fleet.deployment_state();
    let remembered = state.failed_releases().unwrap();
    assert_eq!(remembered[0].tag.as_ref(), "v1.2.4");

    // Whatever was wrong is put right, and still it doesn't go by itself.
    fleet.world.pass_checks();
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
    assert_eq!(fleet.deploys().await.len(), 1);
    assert!(runs(&fleet, "v1.2.3"));

    wait_askable(&fleet, "v1.2.4").await;
    let request = desk.ask("v1.2.4").await;
    let ups = fleet.world.ups();
    let deploy_id = desk.approve(&request).await;
    assert_ne!(deploy_id, failed.id, "a new number for a new try");

    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    fleet.wait_running("v1.2.4").await;

    // What the host did: it ran, once, on that approval, and it's off the record.
    assert!(runs(&fleet, "v1.2.4"));
    assert_eq!(fleet.world.ups(), ups + 1);
    assert_eq!(state.failed_releases().unwrap(), []);
    assert_eq!(
        nonces_spent(&fleet),
        [nonce_approved(&fleet, deploy_id).await]
    );

    // The audit log has both tries, under their own numbers, in the order they went.
    let rows = fleet.audit().await;
    let outcomes: Vec<(i64, String)> = rows
        .iter()
        .filter(|row| row.kind == "deploy_finished")
        .map(|row| {
            (
                row.detail["deploy_id"].as_i64().unwrap(),
                row.detail["outcome"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    assert_eq!(
        outcomes,
        [
            (failed.id, "rolled_back".to_owned()),
            (deploy_id, "deployed".to_owned()),
        ]
    );
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
