//! The wire types against the JSON they stand for.

use landfall_core::intent::DeployIntent;
use serde_json::json;

use crate::{
    CommitSource, CommitsState, CommitsView, Decision, DeployState, DeploymentRef, IntentView,
    NewApproval, NewRequest, NextKind, Outcome, Permission, Problem, ProblemCode, PromotionView,
    ReleaseStatus, RequestState, Via, WhyKind,
};

fn intent(expected_running: Option<&str>) -> DeployIntent {
    DeployIntent {
        deployment: "app/prod".parse().unwrap(),
        tag: "v1.3.0".parse().unwrap(),
        commit: "a".repeat(40).parse().unwrap(),
        digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
        expected_running: expected_running.map(|digest| digest.parse().unwrap()),
        nonce: [0x0f; 32],
    }
}

#[test]
fn an_intent_view_is_the_json_a_host_checks() {
    let running = format!("sha256:{}", "c".repeat(64));
    for intent in [intent(Some(&running)), intent(None)] {
        let view = serde_json::to_value(IntentView::from(&intent)).unwrap();
        assert_eq!(view, serde_json::to_value(&intent).unwrap());
        let back: DeployIntent = serde_json::from_value(view).unwrap();
        assert_eq!(back, intent);
    }
}

#[test]
fn codes_and_states_from_a_newer_controller_read_as_unknown() {
    let problem: Problem = serde_json::from_value(json!({
        "code": "teleport_refused",
        "title": "a new refusal",
        "status": 409,
        "detail": "a field this client doesn't know",
    }))
    .unwrap();
    assert_eq!(problem.code, ProblemCode::Unknown);
    let state: RequestState = serde_json::from_value(json!("teleporting")).unwrap();
    assert_eq!(state, RequestState::Unknown);
    let via: Via = serde_json::from_value(json!("telepathy")).unwrap();
    assert_eq!(via, Via::Unknown);
    let permission: Permission = serde_json::from_value(json!("teleport")).unwrap();
    assert_eq!(permission, Permission::Unknown);
    let status: ReleaseStatus = serde_json::from_value(json!("teleported")).unwrap();
    assert_eq!(status, ReleaseStatus::Unknown);
}

#[test]
fn unknown_is_never_sent() {
    assert!(serde_json::to_value(ProblemCode::Unknown).is_err());
    assert!(serde_json::to_value(RequestState::Unknown).is_err());
    assert!(serde_json::to_value(Via::Unknown).is_err());
    assert!(serde_json::to_value(Permission::Unknown).is_err());
    assert!(serde_json::to_value(ReleaseStatus::Unknown).is_err());
}

#[test]
fn a_deployment_one_cannot_view_is_never_named() {
    let seen = PromotionView {
        deployment: DeploymentRef::Seen("app/beta".parse().unwrap()),
        healthy_for_secs: 3600,
    };
    let unseen = PromotionView {
        deployment: DeploymentRef::Unseen,
        healthy_for_secs: 3600,
    };
    let seen_json = json!({ "deployment": "app/beta", "healthy_for_secs": 3600 });
    let unseen_json = json!({ "deployment": null, "unseen": true, "healthy_for_secs": 3600 });
    assert_eq!(serde_json::to_value(&seen).unwrap(), seen_json);
    assert_eq!(serde_json::to_value(&unseen).unwrap(), unseen_json);
    assert_eq!(
        serde_json::from_value::<PromotionView>(seen_json).unwrap(),
        seen
    );
    assert_eq!(
        serde_json::from_value::<PromotionView>(unseen_json).unwrap(),
        unseen
    );
    assert_eq!(seen.deployment.to_string(), "app/beta");
    assert_eq!(unseen.deployment.to_string(), "a deployment you can't view");
}

#[test]
fn what_a_client_sends_refuses_fields_the_controller_does_not_know() {
    let request = json!({ "tag": "v1.3.0", "force": true });
    assert!(serde_json::from_value::<NewRequest>(request).is_err());
    let assertion = json!({
        "credential_id": "a",
        "authenticator_data": "b",
        "client_data_json": "c",
        "signature": "d",
    });
    assert!(serde_json::from_value::<NewApproval>(json!({ "assertion": assertion })).is_ok());
    let mut extra = assertion.clone();
    extra["user_handle"] = json!("e");
    assert!(serde_json::from_value::<NewApproval>(json!({ "assertion": extra })).is_err());
    let outer = json!({ "assertion": assertion, "intent": {} });
    assert!(serde_json::from_value::<NewApproval>(outer).is_err());
}

#[test]
fn release_values_from_a_newer_controller_read_as_unknown_and_are_never_sent() {
    fn unknown<T>(value: &str, want: &T)
    where
        T: serde::de::DeserializeOwned + serde::Serialize + PartialEq + std::fmt::Debug,
    {
        let read: T = serde_json::from_value(json!(value)).unwrap();
        assert_eq!(&read, want);
        assert!(serde_json::to_value(&read).is_err(), "{read:?} was sent");
    }
    unknown("teleported", &Decision::Unknown);
    unknown("teleport", &NextKind::Unknown);
    unknown("gitlab", &CommitSource::Unknown);
    unknown("guessed", &CommitsState::Unknown);
    unknown("vanished", &DeployState::Unknown);
    unknown("exploded", &Outcome::Unknown);
    unknown("teleported", &WhyKind::Unknown);
}

#[test]
fn a_story_reads_with_fields_it_does_not_know() {
    let commits = json!({
        "source": "github",
        "verified": false,
        "state": "listed",
        "base": "v1.2.0",
        "total": 250,
        "compare_url": "https://github.com/example/app/compare/a...b",
        "commits": [],
        "signed": "a field from a newer controller",
    });
    let read: CommitsView = serde_json::from_value(commits).unwrap();
    assert_eq!(read.state, CommitsState::Listed);
    assert_eq!(read.total, Some(250));
    assert!(!read.verified);
}
