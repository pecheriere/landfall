//! A controller's database restored from a backup while an approval is on its way. The
//! controller then remembers less than the host does, and may deliver again what ran. What
//! keeps the host from running it twice is the host's own record, so these go by the real
//! `backup` and the guide's steps to restore, and then, where it takes that, by the row
//! renumbered, which is what a lying controller would do to get past the ledger of what
//! finished: "a number goes with its release", and that number is the controller's to pick.

use landfall_approval::SoftwareAuthenticator;
use serde_json::Value;
use sqlx::Connection as _;

use super::{
    Desk, backup, journalled_critical, lying_connection, nonce_approved, nonces_spent, options_for,
    refusal_reason, restore, runs, wait_askable, wait_deploy,
};
use crate::harness::{Fleet, Process};
use crate::world::digest_of;

const RENUMBERED: i64 = 1000;

/// A fleet running v1.2.3, with its agent stopped and a request for v1.3.0 open.
struct Scene {
    fleet: Fleet,
    desk: Desk,
    controller: Process,
    request: Value,
}

async fn scene() -> Scene {
    let key = SoftwareAuthenticator::es256().unwrap();
    let fleet = Fleet::with(options_for(&key));
    let controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;
    fleet.world.publish("v1.3.0");
    wait_askable(&fleet, "v1.3.0").await;
    let request = desk.ask("v1.3.0").await;
    agent.stop().await;
    Scene {
        fleet,
        desk,
        controller,
        request,
    }
}

/// The row the backup holds, under a number the host hasn't seen. Only with nothing running.
async fn renumber(fleet: &Fleet, id: i64) {
    let mut connection = lying_connection(fleet).await;
    sqlx::query("UPDATE deploys SET id = ? WHERE id = ?")
        .bind(RENUMBERED)
        .bind(id)
        .execute(&mut connection)
        .await
        .unwrap();
    connection.close().await.unwrap();
}

/// The backup is older than the approval. The approval is gone with what it queued, and the
/// person signs again. The host never heard of any of it.
#[tokio::test]
async fn a_backup_from_before_the_approval_forgets_it_and_nothing_runs() {
    let Scene {
        fleet,
        desk,
        mut controller,
        request,
    } = scene().await;
    let copy = backup(&fleet, "before.db");
    let ups = fleet.world.ups();

    let lost = desk.approve(&request).await;
    let head = fleet.audit_verify(None).printed["head_seq"]
        .as_i64()
        .unwrap();
    controller.stop().await;
    restore(&fleet, &copy);
    let mut controller = fleet.controller().await;
    let mut agent = fleet.agent();
    fleet.let_the_watcher_look().await;

    // Gone from the controller, as far as it can tell, and that shows against a kept head.
    assert_eq!(fleet.deploys().await, []);
    let rows = fleet.audit().await;
    assert!(!rows.iter().any(|row| row.kind == "request_approved"));
    assert_eq!(
        fleet.audit_verify(Some(head)).status,
        1,
        "a head kept since the backup fails, as it should"
    );

    // And nothing ran on it.
    assert!(runs(&fleet, "v1.2.3"));
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), Vec::<String>::new());

    // The request is open again, for the same intent. The numbers start over, and a host that
    // never ran that number runs it.
    let deploy_id = desk.approve(&request).await;
    assert_eq!(deploy_id, lost);
    let finished = wait_deploy(&fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert!(runs(&fleet, "v1.3.0"));
    assert_eq!(fleet.world.ups(), ups + 1);
    assert_eq!(
        nonces_spent(&fleet),
        [nonce_approved(&fleet, deploy_id).await]
    );

    agent.stop().await;
    controller.stop().await;
}

/// The backup is from after the approval and before its delivery, and it is restored after the
/// deploy ran. The controller delivers it again, under its number, in all honesty.
#[tokio::test]
async fn a_backup_holding_the_approval_delivers_it_again_and_it_does_not_run_twice() {
    let Scene {
        fleet,
        desk,
        mut controller,
        request,
    } = scene().await;
    let deploy_id = desk.approve(&request).await;
    let copy = backup(&fleet, "queued.db");

    let mut agent = fleet.agent();
    fleet.wait_running("v1.3.0").await;
    let ups = fleet.world.ups();
    let spent = nonces_spent(&fleet);
    assert_eq!(spent.len(), 1);
    agent.stop().await;
    controller.stop().await;

    restore(&fleet, &copy);
    let mut controller = fleet.controller().await;
    let row = fleet.deploys().await.remove(0);
    assert_eq!((row.id, row.state.as_str()), (deploy_id, "queued"));

    let mut agent = fleet.agent();
    let finished = wait_deploy(&fleet, deploy_id).await;

    // The host's ledger answers with what really happened, and nothing ran.
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert_eq!(fleet.journalled("finished_work_delivered_again"), 1);
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), spent);
    assert!(runs(&fleet, "v1.3.0"));
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}

/// The same approval under a new number, with the host since moved on: the ledger doesn't know
/// that number, and what the approval says should be running stops it.
#[tokio::test]
async fn a_restored_approval_under_a_new_number_is_refused_once_the_host_has_moved_on() {
    let Scene {
        fleet,
        desk,
        mut controller,
        request,
    } = scene().await;
    let deploy_id = desk.approve(&request).await;
    let copy = backup(&fleet, "queued.db");

    let mut agent = fleet.agent();
    fleet.wait_running("v1.3.0").await;
    fleet.world.publish("v1.3.1");
    fleet.wait_finished("v1.3.1").await;
    fleet.wait_running("v1.3.1").await;
    let ups = fleet.world.ups();
    let spent = nonces_spent(&fleet);
    agent.stop().await;
    controller.stop().await;

    restore(&fleet, &copy);
    renumber(&fleet, deploy_id).await;
    let mut controller = fleet.controller().await;
    let mut agent = fleet.agent();
    let refused = wait_deploy(&fleet, RENUMBERED).await;

    assert_eq!(refused.outcome.as_deref(), Some("refused"));
    let (signed, on_record) = (digest_of("v1.2.3"), digest_of("v1.3.1"));
    let why = format!(
        "approval refused: it is for a host running {signed}, and this host has {on_record} on record"
    );
    let reason = refusal_reason(&fleet, RENUMBERED).await;
    assert!(reason.contains(&why), "{reason}");
    assert_eq!(journalled_critical(&fleet, RENUMBERED, &why), 1);

    assert!(
        runs(&fleet, "v1.3.1"),
        "a downgrade is what it would have been"
    );
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), spent);

    agent.stop().await;
    controller.stop().await;
}

/// The hardest case. The host has gone up on this approval and come back down, so the digest it
/// names is running again, its signature is good, and the release is what it says: all that
/// stands in the way is the nonce the host wrote down.
#[tokio::test]
async fn a_restored_approval_is_refused_by_the_nonce_log_when_all_else_about_it_holds() {
    let Scene {
        fleet,
        desk,
        mut controller,
        request,
    } = scene().await;
    let deploy_id = desk.approve(&request).await;
    let copy = backup(&fleet, "queued.db");

    let mut agent = fleet.agent();
    fleet.wait_running("v1.3.0").await;
    wait_askable(&fleet, "v1.2.3").await;
    let down = desk.ask_in_person("v1.2.3").await;
    let rollback = desk.approve(&down).await;
    wait_deploy(&fleet, rollback).await;
    fleet.wait_running("v1.2.3").await;
    let ups = fleet.world.ups();
    let spent = nonces_spent(&fleet);
    assert_eq!(spent.len(), 2);
    let nonce = nonce_approved(&fleet, deploy_id).await;
    agent.stop().await;
    controller.stop().await;

    restore(&fleet, &copy);
    renumber(&fleet, deploy_id).await;
    let mut controller = fleet.controller().await;
    let mut agent = fleet.agent();
    let refused = wait_deploy(&fleet, RENUMBERED).await;

    assert_eq!(refused.outcome.as_deref(), Some("refused"));
    let why = format!(
        "approval refused: app/prod: nonce {nonce} was already spent on this host, and this delivery changed nothing on the service"
    );
    let reason = refusal_reason(&fleet, RENUMBERED).await;
    assert!(reason.contains(&why), "{reason}");
    assert_eq!(journalled_critical(&fleet, RENUMBERED, &why), 1);

    // The service stayed where it was, and the log has what it had.
    assert!(runs(&fleet, "v1.2.3"));
    assert_eq!(fleet.world.ups(), ups);
    assert_eq!(nonces_spent(&fleet), spent);
    let state = fleet.deployment_state();
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.3");
    assert_eq!(state.in_progress().unwrap(), None);

    // The chain of the restored log holds, so it is the host that can say this happened.
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}
