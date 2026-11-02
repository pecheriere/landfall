//! A controller that makes up an approval, by writing to its own database: what someone who
//! holds that machine and has no passkey can do. No test here goes through the approval
//! route, so the audit log has no `request_approved`, and `deploy_refused` is how it shows.
//!
//! A row written behind the controller's back wakes no poll that is waiting, so each forgery
//! is made with the agent stopped, and the next agent finds it. A liar could wake it.

use landfall_approval::SoftwareAuthenticator;
use serde_json::{Value, json};
use sqlx::Connection as _;

use super::{
    Desk, assertion_text, ceremony, journalled_critical, lying_connection, nonce_approved,
    nonces_spent, options_for, refusal_reason, runs, tap, wait_askable, wait_deploy,
};
use crate::harness::{DEPLOYMENT, Fleet, HOST, Process};
use crate::world::digest_of;

/// A fleet running v1.2.3 with v1.3.0 and v1.4.0 published.
struct Scene {
    fleet: Fleet,
    desk: Desk,
    controller: Process,
    agent: Process,
    ups: usize,
}

async fn scene() -> Scene {
    let key = SoftwareAuthenticator::es256().unwrap();
    let fleet = Fleet::with(options_for(&key));
    let controller = fleet.controller().await;
    let desk = Desk::open(&fleet, key).await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;
    fleet.world.publish("v1.3.0");
    fleet.world.publish("v1.4.0");
    wait_askable(&fleet, "v1.3.0").await;
    wait_askable(&fleet, "v1.4.0").await;
    let ups = fleet.world.ups();
    Scene {
        fleet,
        desk,
        controller,
        agent,
        ups,
    }
}

/// The row an honest approval would have made, and the request marked as if someone had
/// signed, with no audit row. Gives the deploy's number.
pub async fn forge(fleet: &Fleet, tag: &str, approval: Option<(&Value, &Value)>) -> i64 {
    let mut connection = lying_connection(fleet).await;
    if let Some((request, _)) = approval {
        sqlx::query(
            "UPDATE deploy_requests SET state = 'approved', approved_by = 'operator', closed_at = 1
             WHERE id = ?",
        )
        .bind(request["id"].as_i64().unwrap())
        .execute(&mut connection)
        .await
        .unwrap();
    }
    let release = fleet
        .world
        .releases()
        .into_iter()
        .find(|release| release.tag.as_ref() == tag)
        .unwrap();
    let id = sqlx::query_scalar(
        "INSERT INTO deploys
           (deployment, host, tag, digest, commit_sha, state, created_at, approval, request_id)
         VALUES (?, ?, ?, ?, ?, 'queued', 1, ?, ?) RETURNING id",
    )
    .bind(DEPLOYMENT)
    .bind(HOST)
    .bind(tag)
    .bind(release.digest.as_ref())
    .bind(release.commit.as_ref())
    .bind(approval.map(|(_, sent)| sent.to_string()))
    .bind(approval.map(|(request, _)| request["id"].as_i64().unwrap()))
    .fetch_one(&mut connection)
    .await
    .unwrap();
    connection.close().await.unwrap();
    id
}

impl Scene {
    /// [`forge`], and an agent that comes to find it.
    async fn deliver(&mut self, tag: &str, approval: Option<(&Value, &Value)>) -> i64 {
        self.agent.stop().await;
        let deploy_id = forge(&self.fleet, tag, approval).await;
        self.agent = self.fleet.agent();
        deploy_id
    }
}

/// What holds for every forgery: it went nowhere, and the record shows what it was.
async fn refused_and_untouched(scene: &Scene, deploy_id: i64, why: &str) {
    let fleet = &scene.fleet;
    let finished = wait_deploy(fleet, deploy_id).await;
    assert_eq!(finished.outcome.as_deref(), Some("refused"));

    // In the audit log as such: the host's reason, and no approval anyone gave.
    let reason = refusal_reason(fleet, deploy_id).await;
    assert!(reason.contains(why), "{reason}");
    let rows = fleet.audit().await;
    assert!(
        !rows.iter().any(|row| row.kind == "request_approved"),
        "{rows:#?}"
    );
    assert_eq!(fleet.audit_verify(None).status, 0, "the chain holds");

    // In the host's own journal, at the priority of a controller lying.
    assert_eq!(journalled_critical(fleet, deploy_id, why), 1);

    // On the host: the service wasn't touched, and nothing was spent.
    assert!(runs(fleet, "v1.2.3"));
    assert_eq!(fleet.world.ups(), scene.ups);
    assert_eq!(nonces_spent(fleet), Vec::<String>::new());
    assert_eq!(fleet.journalled("approval_about_to_be_spent"), 0);
    let state = fleet.deployment_state();
    assert_eq!(state.deployed().unwrap().unwrap().tag.as_ref(), "v1.2.3");
    assert_eq!(state.in_progress().unwrap(), None);
    assert_eq!(state.failed_releases().unwrap(), []);
}

/// Signed by a key the host doesn't hold, in the name of the credential it does.
#[tokio::test]
async fn a_signature_by_another_key_on_the_approvers_credential_is_refused() {
    let mut scene = scene().await;
    let request = scene.desk.ask("v1.3.0").await;

    let thief = SoftwareAuthenticator::es256().unwrap();
    let mut forged = ceremony(request["challenge"].as_str().unwrap());
    forged.credential_id = Some(scene.desk.key.credential_id().to_vec());
    let approval = json!({
        "intent": request["intent"],
        "assertion": assertion_text(&thief.assertion(&forged).unwrap()),
    });
    let deploy_id = scene.deliver("v1.3.0", Some((&request, &approval))).await;

    let why = "approval refused: the signature does not verify";
    refused_and_untouched(&scene, deploy_id, why).await;

    // An operator reading the log sees it for what it is.
    let shown = scene.fleet.server_output(
        [
            "audit",
            "show",
            "--db",
            scene.fleet.db.to_str().unwrap(),
            "--deployment",
            DEPLOYMENT,
            "--limit",
            "1000",
        ]
        .map(str::to_owned)
        .to_vec(),
    );
    assert!(
        shown
            .lines()
            .any(|line| line.contains("\"kind\":\"deploy_refused\"") && line.contains(why)),
        "{shown}"
    );

    // Nothing was burnt, and a real approval still works, under a number of its own.
    wait_askable(&scene.fleet, "v1.3.0").await;
    let honest = scene.desk.ask("v1.3.0").await;
    let next = scene.desk.approve(&honest).await;
    assert_ne!(next, deploy_id);
    let finished = wait_deploy(&scene.fleet, next).await;
    assert_eq!(finished.outcome.as_deref(), Some("deployed"));
    assert!(runs(&scene.fleet, "v1.3.0"));
    assert_eq!(
        nonces_spent(&scene.fleet),
        [nonce_approved(&scene.fleet, next).await]
    );

    scene.agent.stop().await;
    scene.controller.stop().await;
}

/// A credential of the attacker's own, which the controller might have shown at registration.
#[tokio::test]
async fn a_key_the_hosts_file_does_not_hold_is_nobody() {
    let mut scene = scene().await;
    let request = scene.desk.ask("v1.3.0").await;

    let thief = SoftwareAuthenticator::es256().unwrap();
    let approval = json!({ "intent": request["intent"], "assertion": tap(&thief, &request) });
    let deploy_id = scene.deliver("v1.3.0", Some((&request, &approval))).await;

    let why = "approval refused: no approver in this host's configuration has credential";
    refused_and_untouched(&scene, deploy_id, why).await;

    scene.agent.stop().await;
    scene.controller.stop().await;
}

/// The person's real tap on v1.3.0, carried to v1.4.0: the intent is rewritten to say so, and
/// agrees with the work, and the signature is over something else.
#[tokio::test]
async fn a_real_tap_carried_to_another_release_is_refused() {
    let mut scene = scene().await;
    let request = scene.desk.ask("v1.3.0").await;
    let real_tap = tap(&scene.desk.key, &request);

    let moved = scene
        .fleet
        .world
        .releases()
        .into_iter()
        .find(|release| release.tag.as_ref() == "v1.4.0")
        .unwrap();
    let mut intent = request["intent"].clone();
    intent["tag"] = json!(moved.tag);
    intent["commit"] = json!(moved.commit);
    intent["digest"] = json!(moved.digest);
    let approval = json!({ "intent": intent, "assertion": real_tap });
    let deploy_id = scene.deliver("v1.4.0", Some((&request, &approval))).await;

    let why = "approval refused: clientDataJSON challenge";
    refused_and_untouched(&scene, deploy_id, why).await;
    assert_eq!(
        scene
            .fleet
            .deployment_state()
            .deployed()
            .unwrap()
            .unwrap()
            .digest,
        digest_of("v1.2.3")
    );

    scene.agent.stop().await;
    scene.controller.stop().await;
}

/// No approval at all, for what takes one.
#[tokio::test]
async fn a_deploy_with_no_approval_is_refused_by_the_hosts_own_rule() {
    let mut scene = scene().await;

    let deploy_id = scene.deliver("v1.3.0", None).await;

    let why =
        "the rule asks for an approval to go from 1.2.3 to 1.3.0, and no approval came with it";
    refused_and_untouched(&scene, deploy_id, why).await;

    scene.agent.stop().await;
    scene.controller.stop().await;
}
