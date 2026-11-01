use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use landfall_core::protocol::{EnrolCode, EnrolRequest};
use serde_json::json;
use sqlx::Row as _;

use super::{ENROL, Harness, host, signing_key};

const NOW: i64 = 1_800_000_000;

#[tokio::test]
async fn enrol_with_a_valid_code_records_the_key() {
    let h = Harness::new().await;
    let key = signing_key(1);
    let code = h.code("host-a", false).await;

    let answer = h.enrol_with("host-a", &key, code).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");

    let row = sqlx::query("SELECT public_key, enrolled_at FROM hosts WHERE id = 'host-a'")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(
        row.get::<Vec<u8>, _>("public_key"),
        key.verifying_key().as_bytes()
    );
    assert_eq!(row.get::<i64, _>("enrolled_at"), NOW);
    assert_eq!(
        h.store.host_key(&host("host-a")).await.unwrap(),
        Some(key.verifying_key())
    );
    // The code is gone, and the log has the key and never the code.
    assert_eq!(h.count("enrol_codes").await, 0);
    assert_eq!(h.last_audit_detail().await["replaced_key"], json!(null));
}

#[tokio::test]
async fn code_works_once() {
    let h = Harness::new().await;
    let code = h.code("host-a", false).await;
    let answer = h.enrol_with("host-a", &signing_key(1), code.clone()).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);

    let again = h.enrol_with("host-a", &signing_key(1), code).await;
    assert_eq!(again.status, StatusCode::FORBIDDEN);
    assert_eq!(again.code(), "invalid_code");
}

#[tokio::test]
async fn code_is_bound_to_its_host() {
    let h = Harness::new().await;
    let code = h.code("host-a", false).await;

    let answer = h.enrol_with("host-b", &signing_key(1), code.clone()).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.code(), "invalid_code");
    assert_eq!(h.count("hosts").await, 0);

    // The refusal did not use it up for the host it is for.
    let answer = h.enrol_with("host-a", &signing_key(1), code).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn expired_code_is_refused() {
    let h = Harness::new().await;
    let code = h.code("host-a", false).await;

    h.clock.advance(60 * 60);
    let answer = h.enrol_with("host-a", &signing_key(1), code).await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.code(), "invalid_code");
    assert_eq!(h.count("hosts").await, 0);
}

#[tokio::test]
async fn a_code_is_valid_until_just_before_it_expires() {
    let h = Harness::new().await;
    let code = h.code("host-a", false).await;
    h.clock.advance(60 * 60 - 1);
    let answer = h.enrol_with("host-a", &signing_key(1), code).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn an_unknown_code_is_refused() {
    let h = Harness::new().await;
    let answer = h
        .enrol_with("host-a", &signing_key(1), EnrolCode::from_bytes([7; 32]))
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN);
    assert_eq!(answer.code(), "invalid_code");
}

#[tokio::test]
async fn reenrol_needs_replace() {
    let h = Harness::new().await;
    // A code issued before the host enrolled, still valid afterwards: only
    // reachable if an operator's two runs interleave, and refused all the same.
    let early = h.code("host-a", false).await;
    let first = signing_key(1);
    sqlx::query("INSERT INTO hosts (id, public_key, enrolled_at) VALUES ('host-a', ?, 0)")
        .bind(first.verifying_key().as_bytes().as_slice())
        .execute(h.store.pool())
        .await
        .unwrap();

    let answer = h.enrol_with("host-a", &signing_key(2), early).await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(answer.code(), "already_enrolled");
    assert_eq!(
        h.store.host_key(&host("host-a")).await.unwrap(),
        Some(first.verifying_key()),
    );

    // The operator is stopped too, until they say --replace.
    assert!(
        h.store
            .issue_enrol_code(&host("host-a"), false)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn replace_swaps_the_key_and_records_both() {
    let h = Harness::new().await;
    let old = h.enrolled("host-a", 1).await;
    let new = signing_key(2);
    let code = h.code("host-a", true).await;

    let answer = h.enrol_with("host-a", &new, code).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");
    assert_eq!(
        h.store.host_key(&host("host-a")).await.unwrap(),
        Some(new.verifying_key()),
    );
    let detail = h.last_audit_detail().await;
    assert_eq!(
        detail["replaced_key"],
        hex::encode(old.verifying_key().as_bytes())
    );
    assert_eq!(
        detail["public_key"],
        hex::encode(new.verifying_key().as_bytes())
    );

    // The old key no longer signs for the host.
    let refused = h.work("host-a", &old, Vec::new()).await;
    assert_eq!(refused.status, StatusCode::UNAUTHORIZED);
    assert_eq!(refused.code(), "bad_signature");
}

#[tokio::test]
async fn a_key_enrolled_to_another_host_is_refused() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let code = h.code("host-b", false).await;

    let answer = h.enrol_with("host-b", &key, code.clone()).await;
    assert_eq!(answer.status, StatusCode::CONFLICT);
    assert_eq!(answer.code(), "key_in_use");
    assert_eq!(h.store.host_key(&host("host-b")).await.unwrap(), None);

    // Refused, so the code is still good for a key of its own.
    let answer = h.enrol_with("host-b", &signing_key(2), code).await;
    assert_eq!(answer.status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn replacing_a_key_with_another_hosts_key_is_refused() {
    let h = Harness::new().await;
    let taken = h.enrolled("host-a", 1).await;
    let own = h.enrolled("host-b", 2).await;
    let code = h.code("host-b", true).await;

    let answer = h.enrol_with("host-b", &taken, code).await;
    assert_eq!(answer.code(), "key_in_use");
    assert_eq!(
        h.store.host_key(&host("host-b")).await.unwrap(),
        Some(own.verifying_key())
    );
}

#[tokio::test]
async fn a_weak_key_and_a_malformed_body_are_refused() {
    let h = Harness::new().await;
    let code = h.code("host-a", false).await;
    let mut weak = serde_json::to_value(EnrolRequest {
        code: code.clone(),
        host: host("host-a"),
        public_key: signing_key(1).verifying_key(),
    })
    .unwrap();
    let mut identity = [0_u8; 32];
    identity[0] = 1;
    weak["public_key"] = json!(hex::encode(identity));
    let answer = h.post_json(ENROL, &weak).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST);
    assert_eq!(answer.code(), "bad_request");

    // The answer does not repeat what was sent.
    let hostile = json!({ "code": "<script>", "host": "HOST\n", "public_key": 1 });
    let answer = h.post_json(ENROL, &hostile).await;
    assert_eq!(answer.code(), "bad_request");
    let text = String::from_utf8(answer.body).unwrap();
    assert!(!text.contains("script") && !text.contains("HOST"), "{text}");
}

#[tokio::test]
async fn an_oversized_enrolment_is_refused() {
    let h = Harness::new().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri(ENROL)
        .body(Body::from(vec![b' '; 5 * 1024]))
        .unwrap();
    let answer = h.send(request).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(answer.code(), "body_too_large");
}
