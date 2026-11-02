//! The way in: a passkey registered and copied into the file, a first deploy asked for,
//! approved and run.

use std::fs;

use landfall_approval::SoftwareAuthenticator;

use super::{
    Desk, ORIGIN_URL, RP_ID, copy_into_the_config, nonce_approved, nonces_spent,
    options_with_no_key_yet, register, runs, wait_askable, wait_deploy,
};
use crate::flow::in_order;
use crate::harness::Fleet;

#[tokio::test]
async fn a_first_deploy_is_asked_for_approved_and_run_by_a_registered_passkey() {
    let fleet = Fleet::with(options_with_no_key_yet());

    // The operations guide's first file: a deployment needs an approver, who needs a key.
    let whole_file = fs::read_to_string(&fleet.config_path).unwrap();
    let first_file = format!("[approval]\nrp_id = \"{RP_ID}\"\norigin = \"{ORIGIN_URL}\"\n");
    fs::write(&fleet.config_path, first_file).unwrap();
    let mut controller = fleet.controller().await;

    // The page shows the key, and the file is what makes it count.
    let key = SoftwareAuthenticator::es256().unwrap();
    let shown = register(&fleet, &key).await;
    assert_eq!(
        shown["fingerprint"].as_str().unwrap(),
        key.key().unwrap().fingerprint(),
    );
    fs::write(&fleet.config_path, whole_file).unwrap();
    copy_into_the_config(&fleet, shown["config_line"].as_str().unwrap());
    controller.stop().await;
    let mut controller = fleet.controller().await;

    fleet.enrol();
    let desk = Desk::open(&fleet, key).await;
    let mut agent = fleet.agent();
    fleet.world.publish("v1.2.3");
    wait_askable(&fleet, "v1.2.3").await;

    // Nothing starts by itself: a first deploy is manual.
    assert_eq!(fleet.deploys().await, []);
    assert_eq!(fleet.world.ups(), 0);

    let request = desk.ask("v1.2.3").await;
    assert_eq!(request["state"], "awaiting_approval");
    assert_eq!(
        request["intent"]["expected_running"],
        serde_json::Value::Null
    );
    assert_eq!(fleet.deploys().await, [], "asking queues nothing");

    // A good assertion in a program's hands is still no approval.
    let by_program = desk.try_approve_as_the_program(&request).await;
    assert_eq!(by_program.status, 403, "{by_program:?}");
    assert_eq!(fleet.deploys().await, []);

    let deploy_id = desk.approve(&request).await;
    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert_eq!(finished.tag, "v1.2.3");
    fleet.wait_running("v1.2.3").await;

    // What the host did.
    assert!(runs(&fleet, "v1.2.3"));
    assert_eq!(fleet.world.ups(), 1);
    let deployed = fleet.deployment_state().deployed().unwrap().unwrap();
    assert_eq!(deployed.tag.as_ref(), "v1.2.3");
    assert_eq!(
        nonces_spent(&fleet),
        [nonce_approved(&fleet, deploy_id).await],
        "the nonce the audit log names is the one spent"
    );
    assert_eq!(fleet.journalled("approval_about_to_be_spent"), 1);
    assert_eq!(fleet.journalled("controller_work_refused"), 0);

    // What the audit log says.
    let rows = fleet.audit().await;
    assert!(
        in_order(
            &rows,
            &[
                "passkey_invite_issued",
                "passkey_registered",
                "signed_in",
                "deploy_requested",
                "request_approved",
                "deploy_claimed",
                "deploy_finished",
                "running_changed",
            ],
        ),
        "{rows:#?}"
    );
    let asked = rows.iter().find(|r| r.kind == "deploy_requested").unwrap();
    assert_eq!(asked.detail["by"]["principal"], "ci");
    let approved = rows.iter().find(|r| r.kind == "request_approved").unwrap();
    assert_eq!(approved.detail["approver"], "operator");
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
