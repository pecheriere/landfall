//! The wire types against the JSON they stand for.

use landfall_core::intent::DeployIntent;
use serde_json::json;

use crate::{IntentView, NewApproval, NewRequest, Problem, ProblemCode, RequestState};

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
}

#[test]
fn unknown_is_never_sent() {
    assert!(serde_json::to_value(ProblemCode::Unknown).is_err());
    assert!(serde_json::to_value(RequestState::Unknown).is_err());
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
