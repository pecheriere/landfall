//! `"rollback": true`: a request that says it is a rollback is one, or is refused before
//! anything else is looked at. And where an approver signs, on every request answered.

use axum::http::StatusCode;
use serde_json::{Value, json};

use super::{Caller, HOST, Harness, ORIGIN, PROD, PROD_REQUESTS, digest, request_of};

/// Asks for `tag` on `app/prod` as `caller`, saying it is a rollback.
async fn roll_back(h: &Harness, caller: &Caller, tag: &str) -> super::Answer {
    h.post(
        PROD_REQUESTS,
        caller,
        &json!({ "tag": tag, "rollback": true }),
    )
    .await
}

/// Every request, by number, with its state.
async fn requests(h: &Harness) -> Vec<(i64, String)> {
    sqlx::query_as("SELECT id, state FROM deploy_requests ORDER BY id")
        .fetch_all(h.store.pool())
        .await
        .unwrap()
}

/// That `answer` is `409 not_a_rollback`, and that its audit row is the last one, a
/// `request_refused` by `by` for `tag`, whose reason holds `reason`.
async fn assert_not_a_rollback(
    h: &Harness,
    answer: &super::Answer,
    by: &str,
    tag: &str,
    reason: &str,
) {
    assert_eq!(answer.status, StatusCode::CONFLICT, "{answer:?}");
    assert_eq!(answer.code(), "not_a_rollback");
    assert!(
        answer.text().contains("not lower than what runs"),
        "{}",
        answer.text()
    );
    assert_eq!(
        h.audit_kinds().await.last().map(String::as_str),
        Some("request_refused")
    );
    let rows = h.audited("request_refused").await;
    let row = rows.last().unwrap();
    assert_eq!(row["by"]["principal"], by);
    assert_eq!(row["tag"], tag);
    assert_eq!(row["problem"], "not_a_rollback");
    assert!(
        row["reason"].as_str().unwrap().contains(reason),
        "{reason}: {row}"
    );
}

#[tokio::test]
async fn rollback_flag_with_a_higher_tag_is_refused_and_audited() {
    let h = Harness::new().await;
    h.ready().await;
    // erin may roll back; frank may also ask for a higher one, and still can't call it a
    // rollback.
    for name in ["erin", "frank"] {
        let caller = h.token(name).await;
        let answer = roll_back(&h, &caller, "v1.1.0").await;
        assert_not_a_rollback(&h, &answer, name, "v1.1.0", "not lower than what runs").await;
    }
    // The tag that runs isn't lower than itself either.
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let erin = h.token("erin").await;
    let answer = roll_back(&h, &erin, "v1.0.0").await;
    assert_not_a_rollback(&h, &answer, "erin", "v1.0.0", "not lower than what runs").await;

    assert_eq!(requests(&h).await, Vec::new());
    assert_eq!(h.audited("deploy_requested").await.len(), 0);
}

#[tokio::test]
async fn rollback_flag_on_a_first_deploy_is_refused() {
    let h = Harness::new().await;
    h.reports(None).await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let frank = h.token("frank").await;
    let answer = roll_back(&h, &frank, "v1.1.0").await;
    assert_not_a_rollback(&h, &answer, "frank", "v1.1.0", "nothing runs").await;

    // Nor before the host said anything at all, which would otherwise be `host_not_ready`.
    let h = Harness::new().await;
    h.verified(PROD, HOST, "v1.1.0", '1').await;
    let answer = roll_back(&h, &h.token("frank").await, "v1.1.0").await;
    assert_not_a_rollback(&h, &answer, "frank", "v1.1.0", "nothing runs").await;
    assert_eq!(requests(&h).await, Vec::new());
}

#[tokio::test]
async fn rollback_flag_with_an_unparseable_running_tag_is_refused() {
    let h = Harness::new().await;
    h.reports(Some(("nightly", '9'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let erin = h.token("erin").await;
    let answer = roll_back(&h, &erin, "v1.0.0").await;
    assert_not_a_rollback(&h, &answer, "erin", "v1.0.0", "not a version").await;
    assert_eq!(requests(&h).await, Vec::new());
}

#[tokio::test]
async fn not_a_rollback_leaves_an_open_request_open() {
    let h = Harness::new().await;
    // `app/prod` runs `v1.1.0`, and carol asked for `v1.2.0`.
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;
    h.verified(PROD, HOST, "v1.3.0", '3').await;
    let answer = h.ask(&h.token("carol").await, "v1.2.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (open, _) = request_of(&answer.json());
    let callers = [
        ("erin", h.token("erin").await),
        ("frank", h.token("frank").await),
    ];
    let before = requests(&h).await;
    let kinds = h.audit_kinds().await;

    // A rollback grant would let a real rollback take its place, and this isn't one.
    for (name, caller) in &callers {
        let answer = roll_back(&h, caller, "v1.3.0").await;
        assert_not_a_rollback(&h, &answer, name, "v1.3.0", "not lower than what runs").await;
    }
    assert_eq!(requests(&h).await, before);
    assert_eq!(h.request_state(open).await, "awaiting_approval");
    // Two refusals, and nothing else.
    let after = h.audit_kinds().await;
    assert_eq!(after[..kinds.len()], kinds[..]);
    assert_eq!(after[kinds.len()..], ["request_refused", "request_refused"]);
    assert_eq!(h.audited("request_cancelled").await.len(), 0);
}

#[tokio::test]
async fn rollback_flag_with_a_lower_tag_needs_the_rollback_grant() {
    let h = Harness::new().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    h.verified(PROD, HOST, "v1.2.0", '2').await;

    // carol may ask, not roll back: the flag grants nothing.
    let carol = h.token("carol").await;
    let answer = roll_back(&h, &carol, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "forbidden");
    assert_eq!(requests(&h).await, Vec::new());

    // erin may, and a rollback takes an open request's place, as without the flag.
    let answer = h.ask(&carol, "v1.2.0").await;
    let (open, _) = request_of(&answer.json());
    let answer = roll_back(&h, &h.token("erin").await, "v1.0.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    let (id, intent) = request_of(&answer.json());
    assert_eq!(intent.tag.as_ref(), "v1.0.0");
    assert_eq!(intent.expected_running, Some(digest('1')));
    assert_eq!(h.request_state(open).await, "cancelled");
    assert_eq!(h.request_state(id).await, "awaiting_approval");
    let is_rollback: bool =
        sqlx::query_scalar("SELECT is_rollback FROM deploy_requests WHERE id = ?")
            .bind(id)
            .fetch_one(h.store.pool())
            .await
            .unwrap();
    assert!(is_rollback);
}

#[tokio::test]
async fn no_flag_keeps_plan_05s_behaviour() {
    // Without the flag, and with it `false`, a lower tag is a rollback by the grant alone, and
    // a higher one a request.
    for flag in [None, Some(false)] {
        let h = Harness::new().await;
        h.reports(Some(("v1.1.0", '1'))).await;
        h.verified(PROD, HOST, "v1.0.0", '0').await;
        h.verified(PROD, HOST, "v1.2.0", '2').await;
        let body = |tag: &str| {
            let mut body = json!({ "tag": tag });
            if let Some(flag) = flag {
                body["rollback"] = json!(flag);
            }
            body
        };
        let carol = h.token("carol").await;
        let answer = h.post(PROD_REQUESTS, &carol, &body("v1.2.0")).await;
        assert_eq!(answer.status, StatusCode::CREATED, "{flag:?}: {answer:?}");
        let (open, _) = request_of(&answer.json());

        let erin = h.token("erin").await;
        let answer = h.post(PROD_REQUESTS, &erin, &body("v1.0.0")).await;
        assert_eq!(answer.status, StatusCode::CREATED, "{flag:?}: {answer:?}");
        assert_eq!(h.request_state(open).await, "cancelled", "{flag:?}");
        assert_eq!(h.audited("request_refused").await.len(), 0, "{flag:?}");
    }
}

#[tokio::test]
async fn unknown_body_field_is_still_refused() {
    let h = Harness::new().await;
    h.reports(Some(("v1.1.0", '1'))).await;
    h.verified(PROD, HOST, "v1.0.0", '0').await;
    let erin = h.token("erin").await;
    for body in [
        json!({ "tag": "v1.0.0", "rollback": true, "force": true }),
        json!({ "tag": "v1.0.0", "rollback": "yes" }),
        json!({ "tag": "v1.0.0", "rollback": 1 }),
        json!({ "tag": "v1.0.0", "rollback": null }),
        json!({ "rollback": true }),
    ] {
        let answer = h.post(PROD_REQUESTS, &erin, &body).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{body}: {answer:?}");
        assert_eq!(answer.code(), "bad_request", "{body}");
    }
    assert_eq!(requests(&h).await, Vec::new());
}

#[tokio::test]
async fn approve_url_follows_the_configured_origin_and_is_null_without_one() {
    let h = Harness::new().await;
    h.ready().await;
    let want = Value::from(format!("{ORIGIN}/approvals"));
    let answer = h.ask(&h.token("alice").await, "v1.1.0").await;
    assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
    assert_eq!(answer.json()["approve_url"], want);
    let answer = h.list(&h.token("dave").await).await;
    assert_eq!(answer.json()["approvals"][0]["approve_url"], want);

    // Another origin is followed. A configuration with a deployment always has `[approval]`,
    // so only one with none has nowhere to sign.
    let other = landfall_approval::parse_config(
        b"[approval]\nrp_id = \"landfall.example.org\"\norigin = \"https://landfall.example.org:8443\"\n",
    )
    .unwrap();
    assert_eq!(
        crate::api::approve_url(&other).as_deref(),
        Some("https://landfall.example.org:8443/approvals")
    );
    let none = landfall_approval::parse_config(b"").unwrap();
    assert_eq!(crate::api::approve_url(&none), None);
}
