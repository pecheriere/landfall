//! What is signed, and what a refusal is.

use landfall_core::protocol::PROBLEM_CONTENT_TYPE;
use landfall_core::protocol::{Nonce, RequestSignature, verify};
use serde_json::{Value, json};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::{Controller, ControllerError};
use super::{NONCE, client, key, problem, report, request, serve_nonce};

#[tokio::test]
async fn work_is_signed_as_sent_and_the_answer_is_parsed() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    Mock::given(method("POST"))
        .and(path("/agent/v1/work"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"work": null, "held_back": []})),
        )
        .mount(&server)
        .await;

    let response = client(&server).work(&request()).await.unwrap();
    assert_eq!(response.work, None);

    let requests = server.received_requests().await.unwrap();
    let post = requests
        .iter()
        .find(|r| r.method.as_str() == "POST")
        .unwrap();
    let header = |name: &str| post.headers.get(name).unwrap().to_str().unwrap().to_owned();
    assert_eq!(header("landfall-host"), "home-1");
    let nonce: Nonce = header("landfall-nonce").parse().unwrap();
    assert_eq!(nonce, Nonce::from_bytes(NONCE));
    let signature: RequestSignature = header("landfall-signature").parse().unwrap();
    verify(
        &key().verifying_key(),
        &signature,
        &"home-1".parse().unwrap(),
        "POST",
        "/agent/v1/work",
        &nonce,
        &post.body,
    )
    .unwrap();
    let sent: Value = serde_json::from_slice(&post.body).unwrap();
    assert_eq!(sent["config_hash"], "05".repeat(32));
}

#[tokio::test]
async fn each_request_has_its_own_nonce() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    Mock::given(method("POST"))
        .and(path("/agent/v1/report"))
        .respond_with(ResponseTemplate::new(200))
        .mount(&server)
        .await;
    let client = client(&server);
    client.report(&report()).await.unwrap();
    client.report(&report()).await.unwrap();
    let nonces = server
        .received_requests()
        .await
        .unwrap()
        .iter()
        .filter(|r| r.method.as_str() == "GET")
        .count();
    assert_eq!(nonces, 2);
}

#[tokio::test]
async fn a_redirect_is_not_followed() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    Mock::given(method("POST"))
        .and(path("/agent/v1/report"))
        .respond_with(ResponseTemplate::new(307).insert_header("location", "/agent/v1/elsewhere"))
        .mount(&server)
        .await;

    let err = client(&server).report(&report()).await.unwrap_err();

    assert!(matches!(err, ControllerError::Status { .. }), "{err}");
    let requests = server.received_requests().await.unwrap();
    assert!(
        requests
            .iter()
            .all(|r| r.url.path() != "/agent/v1/elsewhere"),
        "the signed request went on to another path"
    );
}

#[tokio::test]
async fn an_oversized_answer_is_refused() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    Mock::given(method("POST"))
        .and(path("/agent/v1/work"))
        .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024 * 1024 + 1)))
        .mount(&server)
        .await;
    let err = client(&server).work(&request()).await.unwrap_err();
    assert!(matches!(err, ControllerError::BadAnswer(_)), "{err}");
}

#[tokio::test]
async fn hostile_error_text_is_quoted_and_truncated() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    let hostile = format!("line\n<2>forged{}", "x".repeat(100_000));
    Mock::given(method("POST"))
        .and(path("/agent/v1/work"))
        .respond_with(ResponseTemplate::new(500).set_body_string(hostile))
        .mount(&server)
        .await;
    let err = client(&server).work(&request()).await.unwrap_err();
    let text = err.to_string();
    assert!(!text.contains('\n'), "{text}");
    assert!(text.len() < 256, "{}", text.len());
}

#[tokio::test]
async fn an_unreadable_work_answer_is_an_error_not_no_work() {
    let server = MockServer::start().await;
    serve_nonce(&server).await;
    Mock::given(method("POST"))
        .and(path("/agent/v1/work"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"held_back": []})))
        .mount(&server)
        .await;
    let err = client(&server).work(&request()).await.unwrap_err();
    assert!(matches!(err, ControllerError::BadAnswer(_)), "{err}");
}

#[tokio::test]
async fn only_the_apis_final_refusal_of_the_post_is_a_rejection() {
    // Stable codes, with a status of the API's own.
    for (template, rejected, why) in [
        (problem(404, "unknown_deploy"), true, "final"),
        (problem(403, "not_claimed"), true, "final"),
        (problem(401, "bad_signature"), true, "final"),
        (problem(400, "bad_nonce"), false, "the code says retry"),
        (problem(429, "rate_limited"), false, "the code says retry"),
        (problem(404, "made_up"), false, "not a code of the API's"),
        (problem(500, "not_claimed"), false, "not a 4xx"),
        (
            ResponseTemplate::new(404).set_body_raw(
                json!({"code": "not_claimed", "title": "no", "status": 403}).to_string(),
                PROBLEM_CONTENT_TYPE,
            ),
            false,
            "the document's status differs",
        ),
        (
            ResponseTemplate::new(404)
                .set_body_json(json!({"code": "not_claimed", "title": "no", "status": 404})),
            false,
            "not the API's content type",
        ),
        (ResponseTemplate::new(404), false, "a bare 404: a proxy's"),
        (ResponseTemplate::new(403), false, "a bare 403: a proxy's"),
        (
            ResponseTemplate::new(403).set_body_raw("<html>", PROBLEM_CONTENT_TYPE),
            false,
            "not a problem document",
        ),
        (ResponseTemplate::new(503), false, "a 5xx"),
    ] {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/report"))
            .respond_with(template)
            .mount(&server)
            .await;
        let err = client(&server).report(&report()).await.unwrap_err();
        assert_eq!(err.is_rejection(), rejected, "{why}: {err}");
    }
}

#[tokio::test]
async fn a_failed_nonce_is_never_a_rejection() {
    for template in [
        ResponseTemplate::new(404),
        ResponseTemplate::new(403),
        problem(404, "not_claimed"),
        problem(403, "bad_signature"),
        problem(400, "bad_request"),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/agent/v1/nonce"))
            .respond_with(template)
            .mount(&server)
            .await;
        let err = client(&server).report(&report()).await.unwrap_err();
        assert!(!err.is_rejection(), "{err}");
        let requests = server.received_requests().await.unwrap();
        assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
    }
}
