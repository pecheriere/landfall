//! What a body or a header can't do: reach a panic, or get an answer that isn't a problem.

use axum::body::Body;
use axum::http::{HeaderValue, Method, Request, StatusCode, header};
use serde_json::json;

use super::{APPROVALS, Caller, Harness, PROD_REQUESTS};

#[tokio::test]
async fn a_long_or_binary_header_is_only_a_bad_credential() {
    let h = Harness::new().await;
    let long = format!("Bearer {}", "a".repeat(64 * 1024));
    let values: Vec<HeaderValue> = vec![
        HeaderValue::from_bytes(&[0xff, 0xfe, 0x80]).unwrap(),
        HeaderValue::from_bytes(b"Bearer \xff\xfe").unwrap(),
        HeaderValue::from_str(&long).unwrap(),
        HeaderValue::from_static("Bearer"),
        HeaderValue::from_static(""),
        HeaderValue::from_static(" "),
        HeaderValue::from_static("Basic lf_"),
        HeaderValue::from_bytes("Bearer lf_é".as_bytes()).unwrap(),
    ];
    for name in [header::AUTHORIZATION, header::COOKIE] {
        for value in &values {
            let request = Request::builder()
                .uri(APPROVALS)
                .header(&name, value.clone())
                .body(Body::empty())
                .unwrap();
            let answer = h.send(request).await;
            assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{value:?}");
            assert_eq!(answer.code(), "unauthenticated", "{value:?}");
        }
    }
    let binary_origin = Request::builder()
        .method(Method::POST)
        .uri(PROD_REQUESTS)
        .header(
            header::COOKIE,
            format!(
                "__Host-landfall-session={}",
                h.store
                    .begin_session_for_test("alice", 60)
                    .await
                    .reveal_for_test()
            ),
        )
        .header(header::ORIGIN, HeaderValue::from_bytes(&[0xff]).unwrap())
        .body(Body::empty())
        .unwrap();
    assert_eq!(h.send(binary_origin).await.code(), "bad_origin");
}

#[tokio::test]
async fn a_body_is_capped_before_it_is_parsed() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    let big = vec![b'x'; 2 * 1024 * 1024];
    let answer = h.call(Method::POST, PROD_REQUESTS, &carol, big).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE, "{answer:?}");
    assert_eq!(answer.code(), "body_too_large");
    // A little over the limit, in a body that would parse.
    let padded = format!(r#"{{"tag":"v1.1.0"{}}}"#, " ".repeat(2048));
    let answer = h
        .call(Method::POST, PROD_REQUESTS, &carol, padded.into_bytes())
        .await;
    assert_eq!(answer.code(), "body_too_large");
}

#[tokio::test]
async fn nobody_gets_a_body_read_without_credentials() {
    let h = Harness::new().await;
    // Over the limit and not read: the answer is about who is asking.
    let big = vec![b'x'; 2 * 1024 * 1024];
    let answer = h
        .call(Method::POST, PROD_REQUESTS, &Caller::Nobody, big)
        .await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{answer:?}");
}

#[tokio::test]
async fn hostile_bodies_are_bad_requests() {
    let h = Harness::new().await;
    h.ready().await;
    let carol = h.token("carol").await;
    let bodies: Vec<Vec<u8>> = vec![
        Vec::new(),
        b"\xff\xfe\x00".to_vec(),
        b"{".to_vec(),
        b"[]".to_vec(),
        b"null".to_vec(),
        br#"{"tag":1}"#.to_vec(),
        br#"{"tag":"v1.1.0","tag":"v1.2.0"}"#.to_vec(),
        br#"{"tag":"\u0000"}"#.to_vec(),
        format!(r#"{{"tag":"{}"}}"#, "v".repeat(500)).into_bytes(),
        "[".repeat(900).into_bytes(),
    ];
    for body in bodies {
        let shown = String::from_utf8_lossy(&body).into_owned();
        let answer = h.call(Method::POST, PROD_REQUESTS, &carol, body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{shown}");
        assert_eq!(answer.code(), "bad_request", "{shown}");
    }
}

#[tokio::test]
async fn every_refusal_is_a_problem_even_with_nothing_routed() {
    let h = Harness::new().await;
    let alice = h.token("alice").await;
    for (method, path, code, status) in [
        (
            Method::GET,
            "/api/v1/nothing",
            "not_found",
            StatusCode::NOT_FOUND,
        ),
        (Method::GET, "/api/v1/", "not_found", StatusCode::NOT_FOUND),
        (
            Method::DELETE,
            APPROVALS,
            "method_not_allowed",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            Method::GET,
            PROD_REQUESTS,
            "method_not_allowed",
            StatusCode::METHOD_NOT_ALLOWED,
        ),
    ] {
        let answer = h.call(method, path, &alice, Vec::new()).await;
        assert_eq!(answer.status, status, "{path}");
        assert_eq!(answer.code(), code, "{path}");
    }
}

#[tokio::test]
async fn no_answer_says_more_than_its_code() {
    let h = Harness::new().await;
    let (id, intent) = h.opened().await;
    let alice = h.session("alice").await;
    let mut body = super::assertion_body(&h.keys.alice, &intent);
    body["assertion"]["credential_id"] = json!("c2VjcmV0");
    let answer = h.post(&format!("{APPROVALS}/{id}"), &alice, &body).await;
    let text = answer.text();
    assert_eq!(answer.code(), "assertion_refused");
    assert!(!text.contains("c2VjcmV0"), "{text}");
    assert!(!text.contains("credential"), "{text}");
}

#[tokio::test]
async fn a_database_that_is_gone_is_a_problem_and_says_nothing_about_it() {
    let h = Harness::new().await;
    let Caller::Token(token) = h.token("alice").await else {
        unreachable!()
    };
    h.store.close().await;
    let answer = h.list(&Caller::Token(token)).await;
    assert!(answer.status.is_server_error(), "{answer:?}");
    let text = answer.text();
    assert!(!text.to_lowercase().contains("sql"), "{text}");
    assert!(!text.contains("database:"), "{text}");
}
