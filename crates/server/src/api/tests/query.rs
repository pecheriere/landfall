//! Query strings and ids in paths, as every operation reads them.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE, URL_SAFE_NO_PAD};
use serde::Deserialize;
use utoipa::IntoParams;

use super::grants::{ANYONE, assert_documented, holder_of, operations, served_document, try_case};
use super::{Caller, OUTSIDER, REQUESTER, World, answer, holder};
use crate::agent_api::ApiProblem;
use crate::api::query::{Cursor, CursorList};
use crate::api::{ApiQuery, IdPath};

/// A query with one parameter, to find where the limit falls.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
struct Probe {
    q: Option<String>,
}

async fn probe(ApiQuery(Probe { q }): ApiQuery<Probe>) -> String {
    q.unwrap_or_default().len().to_string()
}

#[tokio::test]
async fn unknown_query_parameter_is_refused() {
    let doc = served_document().await;
    let mut tried = Vec::new();
    for op in operations(&doc) {
        for case in op.cases() {
            let name;
            let caller = if op.public {
                Caller::Nobody
            } else if case.role == ANYONE {
                Caller::Token(OUTSIDER)
            } else {
                name = holder_of(case.role);
                let (scheme, _) = op
                    .schemes
                    .iter()
                    .find(|(_, roles)| roles.iter().any(|role| role == case.role))
                    .unwrap();
                if scheme == "token" {
                    Caller::Token(&name)
                } else {
                    Caller::Session(&name)
                }
            };
            let (answer, changed) = try_case(&op, case, caller, "?unknown=1").await;
            let what = format!("an unknown parameter, on the {} case", case.role);
            assert_eq!(
                answer.status,
                StatusCode::BAD_REQUEST,
                "{}, {what}: {answer:?}",
                op.id
            );
            assert_eq!(answer.code(), "bad_request");
            assert!(!changed, "{}, {what}", op.id);
            assert_documented(&doc, &op.id, &what, &answer);
            tried.push(op.id.clone());
        }
    }
    assert!(tried.contains(&"listApprovals".to_owned()), "{tried:?}");
    assert!(tried.contains(&"requestDeploy".to_owned()), "{tried:?}");
}

#[tokio::test]
async fn query_string_over_2_kib_is_refused() {
    let router = Router::new().route("/probe", get(probe));
    let at_limit = format!("/probe?q={}", "a".repeat(2046));
    let request = Request::get(&at_limit).body(Body::empty()).unwrap();
    let within = answer(&router, request).await;
    assert_eq!(within.status, StatusCode::OK, "{within:?}");
    assert_eq!(within.body, b"2046");
    let over = format!("{at_limit}a");
    let request = Request::get(&over).body(Body::empty()).unwrap();
    let refused = answer(&router, request).await;
    assert_eq!(refused.status, StatusCode::BAD_REQUEST, "{refused:?}");
    assert_eq!(refused.code(), "bad_request");
    assert_eq!(refused.headers[header::CACHE_CONTROL], "no-store");

    // A parameter it doesn't take, however short.
    let request = Request::get("/probe?q=a&r=b").body(Body::empty()).unwrap();
    assert_eq!(
        answer(&router, request).await.status,
        StatusCode::BAD_REQUEST
    );

    // And through the controller's router, after credentials.
    let world = World::seed().await;
    let path = format!("/api/v1/approvals?{}", "a".repeat(2049));
    let answer = world
        .send(Method::GET, &path, Caller::Token(OUTSIDER), None)
        .await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{answer:?}");
    let answer = world.send(Method::GET, &path, Caller::Nobody, None).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{answer:?}");
}

#[tokio::test]
async fn non_canonical_ids_are_refused_as_not_found() {
    let world = World::seed().await;
    let id = world.request.0;
    let approver = holder(&["approve"]);
    let before = world.rows().await;
    let ways = [
        format!("0{id}"),
        format!("+{id}"),
        format!("{id}.0"),
        format!("{id}{}", "0".repeat(29)),
        String::new(),
    ];
    for (suffix, caller, body) in [
        (
            "",
            Caller::Session(&approver),
            Some(world.approval_by(&approver)),
        ),
        ("/cancel", Caller::Token(REQUESTER), None),
    ] {
        let absent = world
            .send(
                Method::POST,
                &format!("/api/v1/approvals/{}{suffix}", id + 1000),
                caller,
                body.clone(),
            )
            .await;
        assert_eq!(absent.status, StatusCode::NOT_FOUND, "{absent:?}");
        for way in &ways {
            let path = format!("/api/v1/approvals/{way}{suffix}");
            let answer = world.send(Method::POST, &path, caller, body.clone()).await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}: {answer:?}");
            assert_eq!(answer.body, absent.body, "{path}");
        }
    }
    assert_eq!(world.rows().await, before);
    // The one way of writing it names the request.
    let path = format!("/api/v1/approvals/{id}/cancel");
    let answer = world
        .send(Method::POST, &path, Caller::Token(REQUESTER), None)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
}

#[test]
fn an_id_is_read_one_way() {
    let number = |raw: &str| IdPath { id: raw.to_owned() }.number();
    assert_eq!(number("1"), Some(1));
    assert_eq!(number("42"), Some(42));
    assert_eq!(number(&i64::MAX.to_string()), Some(i64::MAX));
    for raw in [
        "",
        "0",
        "00",
        "01",
        "+1",
        "-1",
        "1.0",
        " 1",
        "1 ",
        "١",
        "9223372036854775808",
    ] {
        assert_eq!(number(raw), None, "{raw:?}");
    }
}

const LISTS: [CursorList; 4] = [
    CursorList::Releases,
    CursorList::Deploys,
    CursorList::Audit,
    CursorList::Deployments,
];

#[test]
fn cursor_round_trips() {
    let longest = "a".repeat(160);
    for list in LISTS {
        for after in [
            "app/prod",
            "v1.2.0+build.7",
            "42",
            "a.b.c",
            longest.as_str(),
        ] {
            let cursor = Cursor::new(list, after);
            let raw = cursor.encode();
            assert!(
                raw.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
                "{raw}"
            );
            let back = Cursor::decode(&raw, list).unwrap();
            assert_eq!(back, cursor);
            assert_eq!(back.after(), after);
        }
    }
}

#[test]
fn cursor_of_another_list_is_refused() {
    for given in LISTS {
        let raw = Cursor::new(given, "app/prod").encode();
        for expected in LISTS.into_iter().filter(|list| *list != given) {
            assert!(
                matches!(Cursor::decode(&raw, expected), Err(ApiProblem::BadRequest)),
                "{given:?} read as {expected:?}"
            );
        }
    }
}

#[test]
fn malformed_cursor_is_refused() {
    let encoded = |text: &str| URL_SAFE_NO_PAD.encode(text);
    let over = format!("v1.deployments.{}", "a".repeat(161));
    let table: Vec<(&str, String)> = vec![
        ("not base64url", "app/prod".to_owned()),
        ("not base64url", "djEu+GVw/G95bWVudHMu".to_owned()),
        ("padded", URL_SAFE.encode("v1.deployments.app/prod")),
        ("standard alphabet", STANDARD.encode("v1.deployments.a??")),
        (
            "not text",
            URL_SAFE_NO_PAD.encode([b'v', b'1', b'.', 0xff, 0xfe]),
        ),
        ("wrong prefix", encoded("v2.deployments.app/prod")),
        ("wrong prefix", encoded("deployments.app/prod")),
        ("wrong prefix", encoded("V1.deployments.app/prod")),
        ("an unknown list", encoded("v1.hosts.home-1")),
        ("no after", encoded("v1.deployments")),
        ("empty after", encoded("v1.deployments.")),
        ("empty", String::new()),
        ("over 160 bytes", encoded(&over)),
    ];
    for (what, raw) in table {
        assert!(
            matches!(
                Cursor::decode(&raw, CursorList::Deployments),
                Err(ApiProblem::BadRequest)
            ),
            "{what}: {raw:?}"
        );
    }
}
