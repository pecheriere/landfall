//! What is served, and the headers on all of it.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::json;

use super::{Answer, Harness};

const REGISTER: &str = include_str!("../static/register.html");
const SIGN_IN: &str = include_str!("../static/sign-in.html");
const APPROVALS: &str = include_str!("../static/approvals.html");
const SCRIPT: &str = include_str!("../static/landfall.js");

const PAGES: [(&str, &str); 3] = [
    ("/passkeys/register", REGISTER),
    ("/sign-in", SIGN_IN),
    ("/approvals", APPROVALS),
];

fn has_the_headers(answer: &Answer) {
    let csp = answer.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap();
    assert!(csp.contains("default-src 'self'"), "{csp}");
    assert!(csp.contains("frame-ancestors 'none'"), "{csp}");
    assert_eq!(answer.headers[header::X_CONTENT_TYPE_OPTIONS], "nosniff");
    assert_eq!(answer.headers[header::REFERRER_POLICY], "no-referrer");
}

#[tokio::test]
async fn csp_has_no_inline_or_external_sources() {
    let h = Harness::new().await;
    let answer = h.get("/sign-in").await;
    let csp = answer.headers[header::CONTENT_SECURITY_POLICY]
        .to_str()
        .unwrap()
        .to_owned();
    let mut directives = Vec::new();
    for directive in csp.split(';') {
        let mut words = directive.split_whitespace();
        let name = words.next().unwrap();
        directives.push(name);
        for source in words {
            assert!(
                source == "'self'" || source == "'none'",
                "{name} allows {source}"
            );
        }
    }
    directives.sort_unstable();
    assert_eq!(
        directives,
        [
            "base-uri",
            "default-src",
            "form-action",
            "frame-ancestors",
            "object-src"
        ]
    );
}

#[tokio::test]
async fn every_answer_has_the_headers() {
    let h = Harness::new().await;
    let session = h.signed_in(&h.alice).await;
    let mut answers = vec![
        h.get("/passkeys/register").await,
        h.get("/sign-in").await,
        h.get("/approvals").await,
        h.get("/static/landfall.js").await,
        h.get("/healthz").await,
        // Not found, in each part of the router.
        h.get("/nothing").await,
        h.get("/static/nothing.js").await,
        h.get("/api/v1/nothing").await,
        h.get("/agent/v1/nonce").await,
        // Refused.
        h.get("/api/v1/approvals").await,
        h.post("/sign-in/finish", None, &json!({})).await,
        h.post("/agent/v1/enrol", None, &json!({})).await,
        h.post("/sign-out", Some(&session), &json!({})).await,
    ];
    answers.push(
        h.send(
            Request::builder()
                .method(Method::DELETE)
                .uri("/sign-in")
                .body(Body::empty())
                .unwrap(),
        )
        .await,
    );
    answers.push(
        h.send(
            Request::builder()
                .method(Method::DELETE)
                .uri("/healthz")
                .body(Body::empty())
                .unwrap(),
        )
        .await,
    );
    for answer in &answers {
        has_the_headers(answer);
    }
    assert_eq!(answers[5].status, StatusCode::NOT_FOUND);
    assert_eq!(answers[6].status, StatusCode::NOT_FOUND);
    assert_eq!(answers[13].status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn each_file_has_its_type_and_only_what_is_listed_is_served() {
    let h = Harness::new().await;
    for (path, text) in PAGES {
        let answer = h.get(path).await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
        assert_eq!(
            answer.headers[header::CONTENT_TYPE],
            "text/html; charset=utf-8"
        );
        assert_eq!(answer.headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(answer.body, text.as_bytes());
    }
    let script = h.get("/static/landfall.js").await;
    assert_eq!(
        script.headers[header::CONTENT_TYPE],
        "text/javascript; charset=utf-8"
    );
    assert_eq!(script.body, SCRIPT.as_bytes());

    for path in [
        "/static/",
        "/static",
        "/static/../static/landfall.js",
        "/static/..%2fweb.rs",
        "/static/%2e%2e/%2e%2e/Cargo.toml",
        "/static/register.html",
        "/passkeys/register/0000",
        "/register.html",
    ] {
        assert_eq!(h.get(path).await.status, StatusCode::NOT_FOUND, "{path}");
    }
}

/// Every word of `html` that opens a tag or names an attribute, in lower case.
fn tags_of(html: &str) -> Vec<String> {
    html.split('<')
        .skip(1)
        .map(|tag| {
            tag.split('>')
                .next()
                .unwrap_or_default()
                .to_ascii_lowercase()
        })
        .collect()
}

#[test]
fn pages_have_no_inline_script_or_style() {
    for (path, html) in PAGES {
        let lower = html.to_ascii_lowercase();
        assert!(!lower.contains("javascript:"), "{path}");
        assert!(!lower.contains("<style"), "{path}");
        assert!(!lower.contains("<form"), "{path}");
        assert!(!lower.contains("<base"), "{path}");
        let scripts: Vec<String> = tags_of(html)
            .into_iter()
            .filter(|tag| tag.starts_with("script"))
            .collect();
        assert_eq!(
            scripts,
            ["script src=\"/static/landfall.js\" defer"],
            "{path}"
        );
        // Nothing between the script's tags.
        assert!(
            lower.contains("<script src=\"/static/landfall.js\" defer></script>"),
            "{path}"
        );
        for tag in tags_of(html) {
            for word in tag.split_whitespace().skip(1) {
                let attribute = word.split('=').next().unwrap_or_default();
                assert!(!attribute.starts_with("on"), "{path}: {tag}");
                assert_ne!(attribute, "style", "{path}: {tag}");
                assert_ne!(
                    attribute, "href",
                    "{path}: no external sheet or link: {tag}"
                );
            }
        }
    }
}

/// The server refuses any other field, so a page that sent one could never sign anyone in.
#[test]
fn the_script_sends_exactly_the_four_assertion_fields() {
    let (_, rest) = SCRIPT.split_once("function assertionText").unwrap();
    let (body, _) = rest.split_once("};").unwrap();
    let fields: Vec<&str> = body
        .lines()
        .filter_map(|line| line.trim().split_once(": "))
        .map(|(name, _)| name)
        .collect();
    assert_eq!(
        fields,
        [
            "credential_id",
            "authenticator_data",
            "client_data_json",
            "signature"
        ]
    );
}

#[test]
fn the_script_only_ever_sets_text() {
    for banned in [
        "innerHTML",
        "outerHTML",
        "insertAdjacentHTML",
        "document.write",
        "eval(",
        "new Function",
        "setAttribute",
        ".style",
    ] {
        assert!(!SCRIPT.contains(banned), "{banned}");
    }
    // It reads the code from the fragment and takes it out of the address bar.
    assert!(SCRIPT.contains("location.hash"));
    assert!(SCRIPT.contains("history.replaceState"));
}

#[tokio::test]
async fn the_pages_name_nothing_about_this_controller() {
    let h = Harness::new().await;
    h.registered("gina").await;
    for (path, _) in PAGES {
        let body = String::from_utf8(h.get(path).await.body).unwrap();
        for secret in ["gina", "alice", "landfall.example"] {
            assert!(!body.contains(secret), "{path}");
        }
    }
}
