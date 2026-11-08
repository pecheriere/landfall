//! What reads cost: a bucket of their own for each credential, and a session's read only from
//! the controller's own pages, by `Sec-Fetch-Site`.

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

use super::grants::{
    ANYONE, CASES, assert_documented, documented, holder_of, operations, served_document,
};
use super::{Answer, Caller, ROLES, World, answer, holder};
use crate::agent_api::Limits;
use crate::auth::flush_dropped;

const APPROVALS: &str = "/api/v1/approvals";

/// The title of a read over its budget.
const READS_TITLE: &str = "too many reads by this credential";

/// Who reads, by the principal's name in the [`World`], or by a session's revealed token.
#[derive(Debug, Clone, Copy)]
enum Reader<'a> {
    Token(&'a str),
    Session(&'a str),
    /// A session the test began itself.
    OtherSession(&'a str),
}

/// A `GET` of `path` as `reader`, sending each of `fetch_site` as a `Sec-Fetch-Site` header and
/// no `Origin`, as a browser sends a same-origin `GET`.
async fn read(world: &World, path: &str, reader: Reader<'_>, fetch_site: &[&str]) -> Answer {
    let mut request = Request::builder().method(Method::GET).uri(path);
    request = match reader {
        Reader::Token(name) => {
            let token = world.credentials.tokens[name].reveal();
            request.header(header::AUTHORIZATION, format!("Bearer {token}"))
        }
        Reader::Session(name) => {
            let session = world.credentials.sessions[name].reveal();
            request.header(header::COOKIE, format!("__Host-landfall-session={session}"))
        }
        Reader::OtherSession(session) => {
            request.header(header::COOKIE, format!("__Host-landfall-session={session}"))
        }
    };
    for value in fetch_site {
        request = request.header("sec-fetch-site", *value);
    }
    answer(&world.app, request.body(Body::empty()).unwrap()).await
}

/// The read burst, as the defaults have it.
fn burst() -> usize {
    usize::try_from(Limits::default().read_burst).unwrap()
}

/// Reads `listApprovals` `count` times as `reader`, at one instant, and says how many were
/// answered and how many were over the budget. Anything else fails.
async fn reads(world: &World, reader: Reader<'_>, count: usize) -> (usize, usize) {
    let (mut read_ok, mut over) = (0, 0);
    for _ in 0..count {
        let answer = read(world, APPROVALS, reader, &[]).await;
        match answer.status {
            StatusCode::OK => read_ok += 1,
            StatusCode::TOO_MANY_REQUESTS => over += 1,
            other => panic!("{other}: {answer:?}"),
        }
    }
    (read_ok, over)
}

/// That `answer` is a read refused for its budget, as the document says.
fn assert_over_reads(doc: &Value, operation: &str, answer: &Answer) {
    assert_eq!(answer.status, StatusCode::TOO_MANY_REQUESTS, "{answer:?}");
    assert_eq!(answer.code(), "rate_limited");
    assert_eq!(answer.json()["title"], READS_TITLE);
    let wait = answer.headers[header::RETRY_AFTER].to_str().unwrap();
    assert!(wait.parse::<u32>().unwrap() >= 1, "{wait}");
    assert_documented(doc, operation, "a read over its budget", answer);
}

/// Every audit row of `kind`'s detail, oldest first.
async fn audited(world: &World, kind: &str) -> Vec<Value> {
    let details: Vec<String> =
        sqlx::query_scalar("SELECT detail FROM audit_events WHERE kind = ? ORDER BY seq")
            .bind(kind)
            .fetch_all(world.store.pool())
            .await
            .unwrap();
    details
        .iter()
        .map(|detail| serde_json::from_str(detail).unwrap())
        .collect()
}

async fn audit_rows(world: &World) -> i64 {
    sqlx::query_scalar("SELECT COUNT(*) FROM audit_events")
        .fetch_one(world.store.pool())
        .await
        .unwrap()
}

#[tokio::test]
async fn reads_have_a_burst_of_300_and_ten_more_each_second() {
    let limits = Limits::default();
    assert_eq!((limits.read_burst, limits.read_rate_per_second), (300, 10));
    let world = World::seed().await;
    let reader = Reader::Token("view");
    assert_eq!(reads(&world, reader, burst() + 1).await, (burst(), 1));
    world.clock.advance(1);
    assert_eq!(reads(&world, reader, 11).await, (10, 1));
}

#[tokio::test]
async fn reads_spend_their_own_bucket() {
    let doc = served_document().await;
    let world = World::seed().await;
    let name = holder_of("request");
    let reader = Reader::Token(&name);
    assert_eq!(reads(&world, reader, burst()).await, (burst(), 0));
    let over = read(&world, APPROVALS, reader, &[]).await;
    assert_over_reads(&doc, "listApprovals", &over);

    // The state changes' budget is another, and still whole.
    let ask = CASES
        .iter()
        .find(|case| case.operation == "requestDeploy" && case.role == "request")
        .unwrap();
    let body = ask.body.map(|body| body(&world));
    let asked = world
        .send(
            Method::POST,
            &(ask.path)(&world),
            Caller::Token(&name),
            body,
        )
        .await;
    assert!(asked.status.is_success(), "{asked:?}");
}

#[tokio::test]
async fn a_session_and_tokens_read_apart() {
    let world = World::seed().await;
    let name = holder(&["view"]);
    let other = world
        .store
        .begin_session_for_test(&name, 3600)
        .await
        .reveal();

    assert_eq!(
        reads(&world, Reader::Token(&name), burst() + 1).await,
        (burst(), 1)
    );
    // The principal's sessions have budgets of their own, and so does everyone else.
    assert_eq!(
        reads(&world, Reader::Session(&name), burst() + 1).await,
        (burst(), 1)
    );
    assert_eq!(reads(&world, Reader::OtherSession(&other), 1).await, (1, 0));
    assert_eq!(
        reads(&world, Reader::Token(&holder(&["approve"])), 1).await,
        (1, 0)
    );
}

#[tokio::test]
async fn read_throttles_are_counted_with_reads_true() {
    let world = World::seed().await;
    let name = holder(&["view"]);
    assert_eq!(
        reads(&world, Reader::Token(&name), burst() + 5).await,
        (burst(), 5)
    );
    flush_dropped(&world.state).await;
    let rows = audited(&world, "access_throttled").await;
    assert_eq!(
        rows,
        vec![json!({
            "by": { "principal": name, "via": "token" },
            "dropped": 5,
            "reads": true,
        })]
    );

    // A session's count, by the flush too.
    assert_eq!(
        reads(&world, Reader::Session(&name), burst() + 2).await,
        (burst(), 2)
    );
    flush_dropped(&world.state).await;
    let rows = audited(&world, "access_throttled").await;
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[1],
        json!({
            "by": { "principal": name, "via": "session" },
            "dropped": 2,
            "reads": true,
        })
    );
    assert_eq!(world.store.verify_audit().await.unwrap().first_bad, None);
}

/// A read back within its budget leaves the count for the flush: it writes nothing, so it can't
/// be refused for a write that fails, as it would be with the audit log refusing every row.
#[tokio::test]
async fn a_read_back_within_its_budget_writes_nothing_and_the_flush_writes_the_count() {
    let world = World::seed().await;
    let name = holder(&["view"]);
    assert_eq!(
        reads(&world, Reader::Token(&name), burst() + 3).await,
        (burst(), 3)
    );
    let before = audit_rows(&world).await;
    let refuse_rows = "CREATE TRIGGER no_rows BEFORE INSERT ON audit_events
                       BEGIN SELECT RAISE(ABORT, 'not now'); END";
    sqlx::query(refuse_rows)
        .execute(world.store.pool())
        .await
        .unwrap();
    world.clock.advance(1);
    assert_eq!(reads(&world, Reader::Token(&name), 10).await, (10, 0));
    sqlx::query("DROP TRIGGER no_rows")
        .execute(world.store.pool())
        .await
        .unwrap();
    assert_eq!(audit_rows(&world).await, before);

    flush_dropped(&world.state).await;
    assert_eq!(audit_rows(&world).await, before + 1);
    assert_eq!(
        audited(&world, "access_throttled").await,
        vec![json!({
            "by": { "principal": name, "via": "token" },
            "dropped": 3,
            "reads": true,
        })]
    );
}

#[tokio::test]
async fn a_read_over_budget_writes_nothing() {
    let world = World::seed().await;
    let before = audit_rows(&world).await;
    assert_eq!(
        reads(&world, Reader::Token("view"), burst() + 50).await,
        (burst(), 50)
    );
    assert_eq!(audit_rows(&world).await, before);
    flush_dropped(&world.state).await;
    assert_eq!(audit_rows(&world).await, before + 1);
}

#[tokio::test]
async fn a_cross_site_session_read_is_refused_and_charges_nothing() {
    let doc = served_document().await;
    let world = World::seed().await;
    let name = holder(&["view"]);
    let reader = Reader::Session(&name);
    let before = audit_rows(&world).await;
    let refused: [&[&str]; 4] = [
        &["same-site"],
        &["cross-site"],
        &["Same-Origin"],
        &["same-origin", "same-origin"],
    ];
    for fetch_site in refused {
        for _ in 0..burst() {
            let answer = read(&world, APPROVALS, reader, fetch_site).await;
            assert_eq!(answer.status, StatusCode::FORBIDDEN, "{fetch_site:?}");
            assert_eq!(answer.code(), "bad_origin", "{fetch_site:?}");
            assert_documented(&doc, "listApprovals", "a cross-site read", &answer);
        }
    }
    assert_eq!(audit_rows(&world).await, before);

    // The whole bucket is there for the controller's own pages.
    assert_eq!(reads(&world, reader, burst() + 1).await, (burst(), 1));

    // Counted as a bad `Origin` is: one row for the lot, each watcher interval.
    crate::web::tend(&world.state).await;
    let rows = audited(&world, "access_refused").await;
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(
        rows[0]["by"],
        json!({ "principal": name, "via": "session" })
    );
    assert_eq!(rows[0]["attempts"], burst() * refused.len());
}

#[tokio::test]
async fn same_origin_and_absent_fetch_site_are_read() {
    let world = World::seed().await;
    let name = holder(&["view"]);
    for fetch_site in [&["same-origin"][..], &["none"], &[]] {
        let answer = read(&world, APPROVALS, Reader::Session(&name), fetch_site).await;
        assert_eq!(answer.status, StatusCode::OK, "{fetch_site:?}: {answer:?}");
    }
}

#[tokio::test]
async fn a_token_read_ignores_fetch_site() {
    let world = World::seed().await;
    for fetch_site in ["cross-site", "same-site", "anything"] {
        let answer = read(&world, APPROVALS, Reader::Token("view"), &[fetch_site]).await;
        assert_eq!(answer.status, StatusCode::OK, "{fetch_site}: {answer:?}");
    }
}

/// The holder a check of a read uses for `role`.
fn reader_for(role: &str) -> String {
    if role == ANYONE {
        holder(&ROLES)
    } else {
        holder_of(role)
    }
}

/// Every read the document says can be `429` gives it, by each scheme it lists, with
/// `Retry-After`: a documented refusal that can't happen would mislead a client.
#[tokio::test]
async fn every_read_that_documents_429_gives_it() {
    let doc = served_document().await;
    let mut tried = Vec::new();
    for op in operations(&doc) {
        let documents_429 = documented(&doc, &op.id, StatusCode::TOO_MANY_REQUESTS);
        if op.method != Method::GET || documents_429.is_none() {
            continue;
        }
        let case = op
            .cases()
            .next()
            .unwrap_or_else(|| panic!("{} has no case", op.id));
        for (scheme, _) in &op.schemes {
            let world = World::seed().await;
            let name = reader_for(case.role);
            let caller = match scheme.as_str() {
                "token" => Caller::Token(&name),
                "session" => Caller::Session(&name),
                other => panic!("a scheme the test doesn't know: {other}"),
            };
            let path = (case.path)(&world);
            for _ in 0..burst() {
                let answer = world.send(Method::GET, &path, caller, None).await;
                assert!(answer.status.is_success(), "{}: {answer:?}", op.id);
            }
            let over = world.send(Method::GET, &path, caller, None).await;
            assert_over_reads(&doc, &op.id, &over);
            tried.push(format!("{} by {scheme}", op.id));
        }
    }
    assert!(
        tried.contains(&"listApprovals by token".to_owned())
            && tried.contains(&"listApprovals by session".to_owned()),
        "{tried:?}"
    );
}
