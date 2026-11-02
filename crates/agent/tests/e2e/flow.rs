//! The whole way a release takes, from its tag to the audit log.

use serde_json::Value;

use crate::harness::{AuditRow, Fleet};
use crate::world::digest_of;

/// Whether `wanted` appear in `rows`, in this order, each as a kind of row.
fn in_order(rows: &[AuditRow], wanted: &[&str]) -> bool {
    let mut kinds = rows.iter().map(|row| row.kind.as_str());
    wanted.iter().all(|want| kinds.any(|kind| kind == *want))
}

fn step_names(row: &AuditRow) -> Vec<&str> {
    row.detail["steps"]
        .as_array()
        .unwrap()
        .iter()
        .map(|step| step["name"].as_str().unwrap())
        .collect()
}

/// An operator can see why nothing moves: on stderr, a line for each decision, and in
/// the log itself, without writing to it.
fn says_why_the_minor_waits(fleet: &Fleet) {
    let log = fleet.log("controller");
    let said = log
        .lines()
        .filter(|line| line.contains("decision: app/prod v1.3.0: manual:"))
        .count();
    assert_eq!(said, 1, "{log}");
    let rows = [
        "audit",
        "show",
        "--db",
        fleet.db.to_str().unwrap(),
        "--deployment",
        "app/prod",
        "--limit",
        "1000",
    ];
    let output = fleet.server_output(rows.map(str::to_owned).to_vec());
    assert!(output.contains("\"kind\":\"rule_decision\""), "{output}");
    assert!(output.contains("v1.3.0"), "{output}");
}

#[tokio::test]
async fn a_new_patch_is_queued_deployed_reported_and_audited() {
    let fleet = Fleet::new();
    let mut controller = fleet.controller().await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;
    assert_eq!(
        fleet.deploys().await,
        [],
        "what runs is not asked for again"
    );

    fleet.world.publish("v1.2.4");
    let deploy = fleet.wait_finished("v1.2.4").await;
    assert_eq!(deploy.outcome.as_deref(), Some("deployed"));
    fleet.wait_running("v1.2.4").await;
    assert!(
        fleet
            .world
            .image()
            .unwrap()
            .ends_with(digest_of("v1.2.4").as_ref()),
        "the digest the controller and the host agreed on runs"
    );

    // A minor under a patch rule waits, with its reason, and nothing is asked of
    // the host.
    fleet.world.publish("v1.3.0");
    fleet
        .wait_until("the minor decided", async || {
            fleet.audit().await.iter().any(|row| {
                row.kind == "rule_decision"
                    && row.detail["tag"] == "v1.3.0"
                    && row.detail["decision"] == "manual"
            })
        })
        .await;
    fleet.let_the_watcher_look().await;
    assert_eq!(fleet.deploys().await.len(), 1);

    says_why_the_minor_waits(&fleet);

    // The chain verifies, and names each step of the way.
    let verified = fleet.audit_verify(None);
    assert_eq!(verified.status, 0, "{:?}", verified.printed);
    assert_eq!(verified.printed["first_bad"], Value::Null);
    let rows = fleet.audit().await;
    assert!(
        in_order(
            &rows,
            &[
                "enrol_code_issued",
                "host_enrolled",
                "running_changed",
                "release_seen",
                "rule_decision",
                "deploy_queued",
                "deploy_claimed",
                "deploy_finished",
                "running_changed",
            ]
        ),
        "{rows:#?}"
    );
    let finished = rows
        .iter()
        .find(|row| row.kind == "deploy_finished")
        .unwrap();
    assert_eq!(finished.detail["tag"], "v1.2.4");
    assert_eq!(finished.detail["outcome"], "deployed");
    // Names an agent sent are stored quoted, like all it says.
    let steps = step_names(finished);
    for step in ["\"pull\"", "\"up\"", "\"checks\"", "\"record_deployed\""] {
        assert!(steps.contains(&step), "{steps:?}");
    }
    let secret_free = serde_json::to_string(&rows.iter().map(|r| &r.detail).collect::<Vec<_>>());
    let key = hex::encode(std::fs::read(fleet.state_dir.join("agent.key")).unwrap());
    assert!(!secret_free.unwrap().contains(&key));

    // The head an operator keeps is still there, and still says the same, after
    // the log has grown; and a row the log has not is said to be missing.
    let kept_seq = verified.printed["head_seq"].as_i64().unwrap();
    let kept_hash = verified.printed["head_hash"].clone();
    fleet.world.publish("v1.2.5");
    fleet.wait_finished("v1.2.5").await;
    let later = fleet.audit_verify(Some(kept_seq));
    assert_eq!(later.status, 0, "{:?}", later.printed);
    assert_eq!(later.printed["at_hash"], kept_hash);
    assert!(later.printed["head_seq"].as_i64().unwrap() > kept_seq);
    let beyond = fleet.audit_verify(Some(kept_seq + 1_000_000));
    assert_eq!(beyond.status, 1, "{:?}", beyond.printed);
    assert_eq!(beyond.printed["at_hash"], Value::Null);

    agent.stop().await;
    controller.stop().await;
}
