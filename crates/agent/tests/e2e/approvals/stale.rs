//! An approval for a host that has since moved: stopped at the controller when the controller
//! knows, and at the host when it doesn't.

use landfall_approval::SoftwareAuthenticator;

use super::{
    Desk, journalled_critical, nonce_approved, nonces_spent, options_for, refusal_reason, runs,
    tap, wait_askable, wait_deploy,
};
use crate::harness::Fleet;
use crate::world::digest_of;

/// The controller hears of the move before anyone signs.
#[tokio::test]
async fn a_request_goes_stale_when_the_host_moves_and_asking_again_makes_a_new_intent() {
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
    let old = desk.ask("v1.3.0").await;

    // An automatic patch moves the host while the request is open.
    fleet.world.publish("v1.2.4");
    fleet.wait_finished("v1.2.4").await;
    fleet.wait_running("v1.2.4").await;
    let ups = fleet.world.ups();

    let late = desk.try_approve(&old).await;
    assert_eq!((late.status, late.code()), (409, "request_stale"));
    assert_eq!(fleet.deploys().await.len(), 1, "nothing queued for it");
    let rows = fleet.audit().await;
    let staled = rows.iter().find(|r| r.kind == "request_stale").unwrap();
    assert_eq!(staled.detail["request"], old["id"]);
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), Vec::<String>::new());

    // Asking again binds what runs now, under a new nonce.
    let new = desk.ask("v1.3.0").await;
    assert_ne!(new["id"], old["id"]);
    assert_ne!(new["intent"]["nonce"], old["intent"]["nonce"]);
    assert_eq!(
        new["intent"]["expected_running"].as_str(),
        Some(digest_of("v1.2.4").as_ref())
    );

    // The tap on the old one is no use on the new one.
    let refused = desk.try_approve_with(&new, &tap(&desk.key, &old)).await;
    assert_eq!((refused.status, refused.code()), (403, "assertion_refused"));

    let deploy_id = desk.approve(&new).await;
    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert!(runs(&fleet, "v1.3.0"));
    assert_eq!(fleet.world.ups(), ups + 1);
    assert_eq!(
        nonces_spent(&fleet),
        [nonce_approved(&fleet, deploy_id).await]
    );
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}

/// The approval is on its way when the host moves, by a deploy the controller hasn't heard of:
/// the controller delivers it, as it can't know better, and the host has the last word.
///
/// This pins issue #30, that a queued approved row can't be cancelled. Fixing that may stop the
/// delivery, and then the refusal row, the reason and its journal line go with it. What must survive
/// the fix is the rest: no `up`, no nonce spent, `v1.2.4` on the record and running, and that asking
/// again runs under a new number.
#[tokio::test]
async fn a_host_that_moved_refuses_the_approval_on_its_own_record_and_stays_as_it_is() {
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
    let request = desk.ask("v1.3.0").await;

    agent.stop().await;
    let deploy_id = desk.approve(&request).await;
    fleet.seed("v1.2.4").await;
    let ups = fleet.world.ups();

    let mut agent = fleet.agent();
    let refused = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(refused.outcome.as_deref(), Some("refused"));

    // The reason says what the host holds against it, so it can be told from any other.
    let (signed, on_record) = (digest_of("v1.2.3"), digest_of("v1.2.4"));
    let reason = format!(
        "approval refused: it is for a host running {signed}, and this host has {on_record} on record"
    );
    assert!(
        refusal_reason(&fleet, deploy_id).await.contains(&reason),
        "{}",
        refusal_reason(&fleet, deploy_id).await
    );
    assert_eq!(journalled_critical(&fleet, deploy_id, &reason), 1);

    // The service wasn't touched, and the approval wasn't spent.
    assert!(runs(&fleet, "v1.2.4"));
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), Vec::<String>::new());
    assert_eq!(fleet.journalled("approval_about_to_be_spent"), 0);
    let state = fleet.deployment_state();
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.4");
    assert_eq!(state.in_progress().unwrap(), None);
    fleet.wait_running("v1.2.4").await;
    assert_eq!(fleet.audit_verify(None).status, 0);

    // A person who still wants it signs what is true now, under a new number.
    wait_askable(&fleet, "v1.3.0").await;
    let again = desk.ask("v1.3.0").await;
    let next = desk.approve(&again).await;
    assert_ne!(next, deploy_id);
    let finished = wait_deploy(&fleet, next).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert!(runs(&fleet, "v1.3.0"));

    agent.stop().await;
    controller.stop().await;
}
