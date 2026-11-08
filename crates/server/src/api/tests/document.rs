//! The OpenAPI document: generated the same every time, checked in, served as it is, and
//! saying what every operation needs and how each refuses.

use std::collections::BTreeSet;

use axum::body::Body;
use axum::http::{Request, StatusCode, header};
use axum::response::IntoResponse as _;
use serde_json::Value;

use super::App;
use crate::agent_api::ApiProblem;
use crate::api::openapi_document;
use crate::auth::HumanProblem;

const CHECKED_IN: &str = include_str!("../../../../../docs/api/openapi.json");

const DOCUMENT: &str = "/api/v1/openapi.json";

/// Every `/api/v1` operation the plan names: its id, method and path.
const OPERATIONS: &[(&str, &str, &str)] = &[
    ("getOpenApi", "get", "/api/v1/openapi.json"),
    ("listApprovals", "get", "/api/v1/approvals"),
    (
        "requestDeploy",
        "post",
        "/api/v1/deployments/{name}/{stage}/requests",
    ),
    ("approveRequest", "post", "/api/v1/approvals/{id}"),
    ("cancelRequest", "post", "/api/v1/approvals/{id}/cancel"),
    ("whoAmI", "get", "/api/v1/me"),
    ("listDeployments", "get", "/api/v1/deployments"),
    ("getDeployment", "get", "/api/v1/deployments/{name}/{stage}"),
    (
        "listReleases",
        "get",
        "/api/v1/deployments/{name}/{stage}/releases",
    ),
    (
        "getRelease",
        "get",
        "/api/v1/deployments/{name}/{stage}/releases/{tag}",
    ),
    (
        "listDeploys",
        "get",
        "/api/v1/deployments/{name}/{stage}/deploys",
    ),
    ("getDeploy", "get", "/api/v1/deploys/{id}"),
    ("whyDeploy", "get", "/api/v1/deploys/{id}/why"),
    ("listHosts", "get", "/api/v1/hosts"),
    ("getHost", "get", "/api/v1/hosts/{host}"),
    ("listAudit", "get", "/api/v1/audit"),
];

const METHODS: [&str; 8] = [
    "get", "put", "post", "delete", "options", "head", "patch", "trace",
];

fn document() -> Value {
    serde_json::from_str(&openapi_document()).unwrap()
}

/// What `value` is, following a local `$ref` into `document`.
fn resolved<'a>(document: &'a Value, value: &'a Value) -> &'a Value {
    match value["$ref"].as_str() {
        Some(target) => {
            let pointer = target.strip_prefix('#').unwrap();
            document
                .pointer(pointer)
                .unwrap_or_else(|| panic!("{target}"))
        }
        None => value,
    }
}

/// Each operation in `document`: its method, path and body.
fn operations(document: &Value) -> Vec<(&'static str, &str, &Value)> {
    let mut found = Vec::new();
    for (path, item) in document["paths"].as_object().unwrap() {
        for method in METHODS {
            if let Some(operation) = item.get(method) {
                found.push((method, path.as_str(), operation));
            }
        }
    }
    found
}

#[test]
fn openapi_document_is_checked_in() {
    assert!(
        openapi_document() == CHECKED_IN,
        "docs/api/openapi.json is not the generated document; \
         run: cargo run -p landfall-server -- openapi > docs/api/openapi.json"
    );
}

#[test]
fn document_is_generated_the_same_twice() {
    assert_eq!(openapi_document(), openapi_document());
}

#[tokio::test]
async fn served_document_is_the_same_bytes() {
    let answer = App::new().await.get(DOCUMENT, None, None).await;
    assert_eq!(answer.status, StatusCode::OK);
    assert_eq!(answer.headers[header::CONTENT_TYPE], "application/json");
    assert_eq!(answer.headers[header::CACHE_CONTROL], "no-store");
    assert_eq!(answer.body, openapi_document().into_bytes());
}

#[test]
fn document_is_openapi_3_1() {
    let document = document();
    assert_eq!(document["openapi"], "3.1.0");
    assert_eq!(document["info"]["version"], "1");
}

/// Whether `response` is a refusal as `Problem`.
fn is_problem(document: &Value, response: &Value) -> bool {
    let response = resolved(document, response);
    response["content"]["application/problem+json"]["schema"]["$ref"]
        == "#/components/schemas/Problem"
}

#[test]
fn every_operation_has_an_id_security_and_problem_answers() {
    let document = document();
    let found = operations(&document);
    let listed = found
        .iter()
        .any(|(_, _, operation)| operation["operationId"] == "listApprovals");
    assert!(listed, "{document}");
    for (method, path, operation) in found {
        let id = operation["operationId"].as_str().unwrap_or_default();
        assert!(
            OPERATIONS.contains(&(id, method, path)),
            "{method} {path} has operationId {id:?}, which isn't in the table"
        );
        if id == "getOpenApi" {
            continue;
        }
        let security = operation["security"].as_array();
        assert!(
            security.is_some_and(|list| !list.is_empty()),
            "{id} has no security"
        );
        let responses = &operation["responses"];
        let mut wanted = vec!["401", "429"];
        if path.contains('{') {
            wanted.push("404");
        }
        for status in wanted {
            assert!(
                is_problem(&document, &responses[status]),
                "{id} has no {status} answer as Problem"
            );
        }
    }
}

/// Every refusal of the human API, `Shared` ones included. The `match` makes a new variant
/// fail to compile here until it is listed.
fn every_human_problem() -> Vec<HumanProblem> {
    let mut all = vec![
        HumanProblem::Unauthenticated,
        HumanProblem::BadOrigin,
        HumanProblem::Forbidden,
        HumanProblem::NotFound,
        HumanProblem::MethodNotAllowed,
        HumanProblem::RequestOpen,
        HumanProblem::DeploymentBusy,
        HumanProblem::HostNotReady,
        HumanProblem::ReleaseNotVerified,
        HumanProblem::ReleaseRefused,
        HumanProblem::PromotionPending,
        HumanProblem::RequestStale,
        HumanProblem::RequestExpired,
        HumanProblem::RequestClosed,
        HumanProblem::RequestCancelled,
        HumanProblem::RequestUnreadable,
        HumanProblem::AssertionRefused,
        HumanProblem::ApprovalsNotConfigured,
        HumanProblem::OverBudget,
        HumanProblem::ReadsOverBudget,
        HumanProblem::InviteRefused,
        HumanProblem::RegistrationRefused,
        HumanProblem::SignInRefused,
        HumanProblem::CeremoniesBusy,
        HumanProblem::SignInsSpent {
            retry_after_secs: 60,
        },
    ];
    all.extend(every_api_problem().into_iter().map(HumanProblem::Shared));
    for problem in &all {
        match problem {
            HumanProblem::Unauthenticated
            | HumanProblem::BadOrigin
            | HumanProblem::Forbidden
            | HumanProblem::NotFound
            | HumanProblem::MethodNotAllowed
            | HumanProblem::RequestOpen
            | HumanProblem::DeploymentBusy
            | HumanProblem::HostNotReady
            | HumanProblem::ReleaseNotVerified
            | HumanProblem::ReleaseRefused
            | HumanProblem::PromotionPending
            | HumanProblem::RequestStale
            | HumanProblem::RequestExpired
            | HumanProblem::RequestClosed
            | HumanProblem::RequestCancelled
            | HumanProblem::RequestUnreadable
            | HumanProblem::AssertionRefused
            | HumanProblem::ApprovalsNotConfigured
            | HumanProblem::OverBudget
            | HumanProblem::ReadsOverBudget
            | HumanProblem::InviteRefused
            | HumanProblem::RegistrationRefused
            | HumanProblem::SignInRefused
            | HumanProblem::CeremoniesBusy
            | HumanProblem::SignInsSpent { .. }
            | HumanProblem::Shared(_) => {}
        }
    }
    all
}

/// Every refusal of the agent API, which the human API shares.
fn every_api_problem() -> Vec<ApiProblem> {
    let all = vec![
        ApiProblem::Unsigned,
        ApiProblem::BadNonce,
        ApiProblem::BadSignature,
        ApiProblem::InvalidCode,
        ApiProblem::AlreadyEnrolled,
        ApiProblem::KeyInUse,
        ApiProblem::BadRequest,
        ApiProblem::BodyTooLarge,
        ApiProblem::SlowRequest,
        ApiProblem::RateLimited,
        ApiProblem::NoncesExhausted,
        ApiProblem::Busy,
        ApiProblem::UnknownDeploy,
        ApiProblem::NotClaimed,
        ApiProblem::Internal,
    ];
    for problem in &all {
        match problem {
            ApiProblem::Unsigned
            | ApiProblem::BadNonce
            | ApiProblem::BadSignature
            | ApiProblem::InvalidCode
            | ApiProblem::AlreadyEnrolled
            | ApiProblem::KeyInUse
            | ApiProblem::BadRequest
            | ApiProblem::BodyTooLarge
            | ApiProblem::SlowRequest
            | ApiProblem::RateLimited
            | ApiProblem::NoncesExhausted
            | ApiProblem::Busy
            | ApiProblem::UnknownDeploy
            | ApiProblem::NotClaimed
            | ApiProblem::Internal => {}
        }
    }
    all
}

/// The code in the body of `answer`, a refusal.
async fn answered_code(answer: axum::response::Response) -> String {
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap();
    let problem: Value = serde_json::from_slice(&body).unwrap();
    problem["code"].as_str().unwrap().to_owned()
}

#[tokio::test]
async fn every_problem_code_is_in_the_schema() {
    let document = document();
    let code = &document["components"]["schemas"]["Problem"]["properties"]["code"];
    let codes: BTreeSet<&str> = resolved(&document, code)["enum"]
        .as_array()
        .unwrap()
        .iter()
        .map(|code| code.as_str().unwrap())
        .collect();
    assert!(!codes.contains("unknown"), "{codes:?}");
    for problem in every_human_problem() {
        let answered = answered_code(problem.into_response()).await;
        assert!(codes.contains(answered.as_str()), "{problem:?}: {answered}");
        assert_eq!(serde_json::to_value(problem.code()).unwrap(), answered);
    }
    // The agent API's codes are also a contract with the agent, which reads them by core's
    // list.
    for problem in every_api_problem() {
        let answered = answered_code(problem.into_response()).await;
        assert!(
            landfall_core::protocol::ProblemCode::parse(&answered).is_some(),
            "{problem:?}: {answered}"
        );
    }
}

#[tokio::test]
async fn approvals_json_is_unchanged() {
    let app = App::new().await;
    app.open_request().await;
    let token = app.token("operator").await;
    let answer = app.get("/api/v1/approvals", Some(&token), None).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    let keys = |value: &Value| -> BTreeSet<String> {
        value.as_object().unwrap().keys().cloned().collect()
    };
    assert_eq!(keys(&body), BTreeSet::from(["approvals".to_owned()]));
    let approvals = body["approvals"].as_array().unwrap();
    assert_eq!(approvals.len(), 1, "{body}");
    let request = &approvals[0];
    let shipped = [
        "id",
        "host",
        "intent",
        "challenge",
        "state",
        "requested_by",
        "created_at",
        "expires_at",
        "can_approve",
        "can_cancel",
    ];
    assert_eq!(keys(request), shipped.map(str::to_owned).into());
    let intent = [
        "deployment",
        "tag",
        "commit",
        "digest",
        "expected_running",
        "nonce",
    ];
    assert_eq!(keys(&request["intent"]), intent.map(str::to_owned).into());
    assert_eq!(request["state"], "awaiting_approval");
    assert_eq!(request["intent"]["nonce"], "07".repeat(32));
}

#[tokio::test]
async fn api_answers_have_no_cors_headers() {
    let app = App::new().await;
    let token = app.token("operator").await;
    let origin = Some("https://other.example");
    for answer in [
        app.get(DOCUMENT, None, origin).await,
        app.get("/api/v1/approvals", Some(&token), origin).await,
        app.get("/api/v1/approvals", None, origin).await,
        app.get("/api/v1/nothing", Some(&token), origin).await,
    ] {
        let cors: Vec<_> = answer
            .headers
            .keys()
            .filter(|name| name.as_str().starts_with("access-control-"))
            .collect();
        assert!(cors.is_empty(), "{cors:?} in {answer:?}");
    }
}

#[tokio::test]
async fn refusals_are_never_stored() {
    let app = App::new().await;
    let token = app.token("operator").await;
    let delete = Request::delete("/api/v1/approvals")
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .body(Body::empty())
        .unwrap();
    for (answer, status) in [
        (
            app.get("/api/v1/approvals", None, None).await,
            StatusCode::UNAUTHORIZED,
        ),
        (
            app.get("/api/v1/approvals?x=1", Some(&token), None).await,
            StatusCode::BAD_REQUEST,
        ),
        (
            app.get("/api/v1/nothing", Some(&token), None).await,
            StatusCode::NOT_FOUND,
        ),
        (app.send(delete).await, StatusCode::METHOD_NOT_ALLOWED),
    ] {
        assert_eq!(answer.status, status, "{answer:?}");
        assert_eq!(
            answer.headers[header::CACHE_CONTROL],
            "no-store",
            "{answer:?}"
        );
    }
}
