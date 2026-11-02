//! A request goes stale when what it was made from moves.

use axum::http::StatusCode;
use landfall_core::protocol::{DeployId, DeployReportBody, ReportedOutcome};
use serde_json::json;

use super::{HOST, Harness, PROD, digest, request_of};
use crate::report::BoundedReport;
use crate::store::{NewDeploy, ReleaseDecision, Seen};

#[tokio::test]
async fn request_goes_stale_when_the_running_digest_moves() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // What was reported is what the request expects: nothing happens.
    h.reports(Some(("v1.0.0", '0'))).await;
    assert_eq!(h.request_state(id).await, "awaiting_approval");

    h.reports(Some(("v1.0.1", '2'))).await;
    assert_eq!(h.request_state(id).await, "stale");
    // The same report's transaction wrote the row: nothing later to wait for.
    let stale = h.audited("request_stale").await;
    assert_eq!(stale.len(), 1);
    assert_eq!(stale[0]["request"], id);

    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "request_stale");
    assert_eq!(h.count_deploys().await, 0);
    // No longer on anyone's list.
    let list = h.list(&h.session("alice").await).await.json();
    assert_eq!(list["approvals"], json!([]));

    // Asking again is a new intent from what runs now.
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(asked.status, StatusCode::CREATED, "{asked:?}");
    let (again, fresh) = request_of(&asked.json());
    assert_ne!(again, id);
    assert_ne!(fresh.nonce, intent.nonce);
    assert_eq!(fresh.expected_running, Some(digest('2')));
}

#[tokio::test]
async fn a_report_that_comes_after_its_time_finds_it_expired_and_not_stale() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    h.clock.advance(3 * 24 * 60 * 60);
    h.reports(Some(("v1.0.1", '2'))).await;
    assert_eq!(h.request_state(id).await, "expired");
    assert_eq!(h.audited("request_expired").await.len(), 1);
    assert_eq!(h.audited("request_stale").await.len(), 0);
}

#[tokio::test]
async fn a_new_tag_on_the_same_digest_is_not_a_move() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    h.reports(Some(("v1.0.0-again", '0'))).await;
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}

#[tokio::test]
async fn a_first_deploys_request_goes_stale_when_something_comes_to_run() {
    let h = Harness::new().await;
    h.reports(None).await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let asked = h.ask(&h.token("alice").await, "v1.1.0").await;
    let (id, _) = request_of(&asked.json());
    h.reports(Some(("v1.0.0", '0'))).await;
    assert_eq!(h.request_state(id).await, "stale");
}

#[tokio::test]
async fn a_finished_deploy_stales_it_before_the_next_poll() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    h.verified(PROD, HOST, "v1.0.1", '2').await;
    let host = HOST.parse().unwrap();
    let mut tx = h.store.begin().await.unwrap();
    let deploy = h
        .store
        .queue_deploy(
            &mut tx,
            &NewDeploy {
                deployment: PROD.parse().unwrap(),
                host: HOST.parse().unwrap(),
                tag: "v1.0.1".parse().unwrap(),
                digest: digest('2'),
                commit: "2".repeat(40).parse().unwrap(),
            },
        )
        .await
        .unwrap();
    tx.commit().await.unwrap();
    assert!(h.store.next_work(&host).await.unwrap().work.is_some());
    h.store
        .finish_deploy(
            &host,
            &BoundedReport::new(&DeployReportBody {
                deploy_id: DeployId(deploy.0),
                deployment: PROD.parse().unwrap(),
                tag: "v1.0.1".parse().unwrap(),
                digest: digest('2'),
                outcome: ReportedOutcome::Deployed {},
                steps: Vec::new(),
            }),
        )
        .await
        .unwrap();
    assert_eq!(h.request_state(id).await, "stale");
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "request_stale");
}

#[tokio::test]
async fn approval_itself_catches_a_digest_that_moved_with_nothing_having_said_so() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // Not a path the code takes, which is the point: the look in the approval's own
    // transaction doesn't rest on the other having run.
    sqlx::query("UPDATE running_states SET digest = ? WHERE deployment = ?")
        .bind(digest('9').as_ref())
        .bind(PROD)
        .execute(h.store.pool())
        .await
        .unwrap();
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "request_stale");
    assert_eq!(h.request_state(id).await, "stale");
}

#[tokio::test]
async fn approving_a_request_for_another_host_is_refused() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // The deployment has moved to another host since, by the configuration.
    sqlx::query("UPDATE deploy_requests SET host = 'host-b' WHERE id = ?")
        .bind(id)
        .execute(h.store.pool())
        .await
        .unwrap();
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "request_stale");
    assert_eq!(h.request_state(id).await, "stale");
    assert_eq!(h.count_deploys().await, 0);
}

#[tokio::test]
async fn a_release_whose_record_changed_can_not_be_approved() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // The watcher looked again: the tag names another commit and image now.
    let commit = "7".repeat(40).parse().unwrap();
    let moved = digest('7');
    let seen = Seen {
        tag_object: "another",
        config_hash: h.config.hash(),
        commit: Some(&commit),
        digest: Some(&moved),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (&PROD.parse().unwrap(), &HOST.parse().unwrap(), &intent.tag),
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver",
            Some(&seen),
        )
        .await
        .unwrap();
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "request_stale");
}

#[tokio::test]
async fn a_hold_placed_after_the_request_keeps_it_from_being_approved_for_now() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let deployment = PROD.parse().unwrap();
    let host = HOST.parse().unwrap();
    h.store
        .set_hold(
            (&deployment, &host),
            Some(&intent.tag),
            "two runs for this tag",
            false,
        )
        .await
        .unwrap();
    let alice = h.session("alice").await;
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "release_not_verified");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);

    h.store
        .clear_hold(&deployment, Some(&intent.tag))
        .await
        .unwrap();
    let answer = h.approve(id, &alice, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn a_record_from_another_configuration_keeps_it_from_being_approved_for_now() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let commit = "1".repeat(40).parse().unwrap();
    let same = digest('1');
    let seen = Seen {
        tag_object: "object",
        config_hash: "another",
        commit: Some(&commit),
        digest: Some(&same),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (&PROD.parse().unwrap(), &HOST.parse().unwrap(), &intent.tag),
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver",
            Some(&seen),
        )
        .await
        .unwrap();
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.code(), "release_not_verified");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);
}

#[tokio::test]
async fn the_watchers_record_of_a_waiting_release_does_not_conflict_with_a_request() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // The watcher says what it says each tick. It is about the release, not this request.
    h.store
        .record_release(
            (&PROD.parse().unwrap(), &HOST.parse().unwrap(), &intent.tag),
            ReleaseDecision::Manual,
            "beyond the rule's levels: it needs an operator",
            None,
        )
        .await
        .unwrap();
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    let answer = h
        .approve(id, &h.session("alice").await, &h.keys.alice, &intent)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}
