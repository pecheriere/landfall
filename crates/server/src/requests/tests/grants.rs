//! `can`, and the gates that go by it.

use axum::http::StatusCode;
use landfall_core::config::Permission;
use landfall_core::ids::DeploymentId;
use serde_json::json;

use super::{APPROVALS, Harness, Keys, OTHER, PROD, config_text, principal};
use crate::auth::{Via, can};

fn prod() -> DeploymentId {
    PROD.parse().unwrap()
}

#[tokio::test]
async fn can_denies_by_default_and_follows_the_grants() {
    let h = Harness::new().await;
    let can = |name, via, on: &DeploymentId, what| can(&h.config, &principal(name, via), on, what);
    let other: DeploymentId = OTHER.parse().unwrap();
    let token = Via::Token(1);

    assert!(can("alice", token, &prod(), Permission::View));
    assert!(can("alice", token, &prod(), Permission::Request));
    assert!(!can("alice", token, &prod(), Permission::Rollback));
    assert!(!can("alice", token, &other, Permission::View));
    assert!(can("carol", token, &prod(), Permission::Request));
    assert!(!can("carol", token, &prod(), Permission::View));
    assert!(can("erin", token, &prod(), Permission::Rollback));
    assert!(!can("nobody", token, &prod(), Permission::View));
    assert!(!can(
        "alice",
        token,
        &"no/such".parse().unwrap(),
        Permission::View
    ));
}

#[tokio::test]
async fn approve_is_for_a_session_of_an_approver_with_the_grant() {
    let h = Harness::new().await;
    let can = |name, via| {
        can(
            &h.config,
            &principal(name, via),
            &prod(),
            Permission::Approve,
        )
    };
    assert!(can("alice", Via::Session));
    assert!(can("bob", Via::Session));
    // A token, even of someone a session of whom may.
    assert!(!can("alice", Via::Token(1)));
    assert!(!can("bob", Via::Token(1)));
    // On the rule, with no grant here.
    assert!(!can("zoe", Via::Session));
    // No grant, and not an approver.
    assert!(!can("carol", Via::Session));
}

#[tokio::test]
async fn a_grant_of_approve_outside_the_rule_does_not_load() {
    let keys = Keys::new();
    let text = config_text(
        &keys,
        "[[grant]]\nprincipal = \"alice\"\ndeployments = [\"other/prod\"]\ncan = [\"approve\"]\n",
    );
    let error = landfall_approval::parse_config(text.as_bytes()).unwrap_err();
    assert!(error.to_string().contains("rule.approvers"), "{error}");
}

#[tokio::test]
async fn token_cannot_approve_whatever_the_config_says() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // alice and bob hold the grant and the key, and the config can't say more than that.
    for name in ["alice", "bob"] {
        let caller = h.token(name).await;
        let key = if name == "alice" {
            &h.keys.alice
        } else {
            &h.keys.bob
        };
        let answer = h.approve(id, &caller, key, &intent).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
        assert_eq!(answer.code(), "forbidden");
    }
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    assert_eq!(h.count_deploys().await, 0);
}

#[tokio::test]
async fn request_needs_the_grant() {
    let h = Harness::new().await;
    h.ready().await;
    // Some grant here, so they know it exists: forbidden.
    for (name, session) in [("dave", false), ("bob", true)] {
        let caller = if session {
            h.session(name).await
        } else {
            h.token(name).await
        };
        let answer = h.ask(&caller, "v1.1.0").await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{name}");
        assert_eq!(answer.code(), "forbidden", "{name}");
    }
    // No grant here: as if it didn't exist.
    for (caller, name) in [
        (h.token("otto").await, "token"),
        (h.session("otto").await, "session"),
    ] {
        let answer = h.ask(&caller, "v1.1.0").await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{name}");
        assert_eq!(answer.code(), "not_found", "{name}");
    }
    assert_eq!(h.audited("deploy_requested").await.len(), 0);
}

#[tokio::test]
async fn a_deployment_without_a_grant_and_one_that_does_not_exist_read_the_same() {
    let h = Harness::new().await;
    h.ready().await;
    let otto = h.token("otto").await;
    let tag = json!({ "tag": "v1.1.0" });
    let hidden = h
        .post("/api/v1/deployments/app/prod/requests", &otto, &tag)
        .await;
    let absent = h
        .post("/api/v1/deployments/no/such/requests", &otto, &tag)
        .await;
    let invalid = h
        .post("/api/v1/deployments/NO%0A/such/requests", &otto, &tag)
        .await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.status, hidden.status);
    assert_eq!(absent.body, hidden.body);
    assert_eq!(invalid.status, hidden.status, "{invalid:?}");
}

#[tokio::test]
async fn an_approval_without_a_grant_and_one_that_does_not_exist_read_the_same() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let otto = h.session("otto").await;
    let hidden = h.approve(id, &otto, &h.keys.zoe, &intent).await;
    let absent = h.approve(id + 1, &otto, &h.keys.zoe, &intent).await;
    assert_eq!(hidden.status, StatusCode::NOT_FOUND);
    assert_eq!(absent.status, hidden.status);
    assert_eq!(absent.body, hidden.body);
    // Not even numbers that can't be.
    for path in [
        "0",
        "-1",
        "99999999999999999999",
        "x",
        "%FF",
        "+1",
        "01",
        "00",
    ] {
        let answer = h
            .post(&format!("{APPROVALS}/{path}"), &otto, &json!({}))
            .await;
        assert_eq!(answer.status, hidden.status, "{path}");
        assert_eq!(answer.body, hidden.body, "{path}");
    }
}

#[tokio::test]
async fn approve_needs_the_grant_and_a_listed_approver() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    // zoe is on the rule and has the key, with no grant on this deployment.
    let zoe = h.session("zoe").await;
    let answer = h.approve(id, &zoe, &h.keys.zoe, &intent).await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND, "{answer:?}");
    // dave sees it and has neither.
    let dave = h.session("dave").await;
    let answer = h.approve(id, &dave, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "forbidden");
    assert_eq!(h.request_state(id).await, "awaiting_approval");

    let bob = h.session("bob").await;
    let answer = h.approve(id, &bob, &h.keys.bob, &intent).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[tokio::test]
async fn requester_without_approve_cannot_approve() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.session("carol").await;
    let answer = h.ask(&carol, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (id, intent) = super::request_of(&answer.json());
    // Even with someone's real passkey in hand.
    let answer = h.approve(id, &carol, &h.keys.alice, &intent).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "forbidden");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
}

#[tokio::test]
async fn the_list_shows_what_a_principal_may_see_and_who_may_sign() {
    let h = Harness::new().await;
    let (id, _) = h.opened().await;
    let ids = |value: &serde_json::Value| -> Vec<(i64, bool, bool)> {
        value["approvals"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| {
                (
                    a["id"].as_i64().unwrap(),
                    a["can_approve"].as_bool().unwrap(),
                    a["can_cancel"].as_bool().unwrap(),
                )
            })
            .collect()
    };
    let list = async |caller| ids(&h.list(&caller).await.json());
    assert_eq!(list(h.session("alice").await).await, [(id, true, true)]);
    assert_eq!(list(h.session("bob").await).await, [(id, true, true)]);
    // A token can't sign, and the one who asked can still cancel, by either credential.
    assert_eq!(list(h.token("alice").await).await, [(id, false, true)]);
    // Who may only look can do neither.
    assert_eq!(list(h.token("dave").await).await, [(id, false, false)]);
    // Neither sees nor signs.
    assert_eq!(list(h.token("carol").await).await, []);
    assert_eq!(list(h.session("otto").await).await, []);
    assert_eq!(list(h.session("zoe").await).await, []);
}
