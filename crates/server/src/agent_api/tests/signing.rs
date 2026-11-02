use std::convert::Infallible;
use std::time::{Duration, Instant};

use axum::body::{Body, Bytes};
use axum::http::header::CACHE_CONTROL;
use axum::http::{Method, Request, StatusCode};
use landfall_core::protocol::{
    self, HOST_HEADER, MAX_BODY_BYTES, NONCE_HEADER, Nonce, SIGNATURE_HEADER, SigningKey,
    WorkRequest,
};
use serde_json::json;

use super::{Harness, REPORT, WORK, host, signed_request, signing_key, test_limits};
use crate::agent_api::Limits;
use crate::agent_api::signed::UNKNOWN_HOST_SEED;
use crate::store::NONCE_LIFETIME_SECS;

fn work_body(h: &Harness) -> Vec<u8> {
    serde_json::to_vec(&WorkRequest {
        config_hash: h.config_hash,
        running: Vec::new(),
    })
    .unwrap()
}

#[tokio::test]
async fn nonce_works_once() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let nonce = h.nonce().await;
    let body = work_body(&h);

    let first = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
    assert_eq!(h.send(first).await.status, StatusCode::OK);

    let replay = signed_request("host-a", &key, WORK, WORK, &nonce, body);
    let answer = h.send(replay).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_nonce");
}

#[tokio::test]
async fn a_nonce_is_not_cacheable_and_each_differs() {
    let h = Harness::new().await;
    let answer = h.get_nonce().await;
    assert_eq!(answer.headers[CACHE_CONTROL], "no-store");
    assert_ne!(h.nonce().await, h.nonce().await);
}

#[tokio::test]
async fn expired_nonce_is_refused() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let nonce = h.nonce().await;

    h.clock.advance(NONCE_LIFETIME_SECS);
    let late = signed_request("host-a", &key, WORK, WORK, &nonce, work_body(&h));
    let answer = h.send(late).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_nonce");
}

#[tokio::test]
async fn a_nonce_is_good_until_just_before_it_expires() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let nonce = h.nonce().await;
    h.clock.advance(NONCE_LIFETIME_SECS - 1);
    let request = signed_request("host-a", &key, WORK, WORK, &nonce, work_body(&h));
    assert_eq!(h.send(request).await.status, StatusCode::OK);
}

#[tokio::test]
async fn nonce_table_cannot_grow_without_bound() {
    let h = Harness::with_limits(Limits {
        max_outstanding_nonces: 3,
        ..test_limits()
    })
    .await;
    for _ in 0..3 {
        h.nonce().await;
    }

    let refused = h.get_nonce().await;
    assert_eq!(refused.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(refused.code(), "nonces_exhausted");
    assert!(refused.headers.contains_key("retry-after"));
    assert_eq!(h.count("nonces").await, 3);

    // Expired ones make room.
    h.clock.advance(NONCE_LIFETIME_SECS);
    h.nonce().await;
    assert_eq!(h.count("nonces").await, 1);
}

#[tokio::test]
async fn the_nonce_endpoint_is_rate_limited_per_source() {
    let h = Harness::with_limits(Limits {
        source_rate_per_second: 1,
        source_burst: 2,
        ..test_limits()
    })
    .await;
    let source = "192.0.2.1:1000".parse().unwrap();
    assert_eq!(h.get_nonce_from(source).await.status, StatusCode::OK);
    assert_eq!(h.get_nonce_from(source).await.status, StatusCode::OK);

    let refused = h.get_nonce_from(source).await;
    assert_eq!(refused.status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(refused.code(), "rate_limited");
    assert!(refused.headers.contains_key("retry-after"));
    // A refusal stores nothing.
    assert_eq!(h.count("nonces").await, 2);

    // Another port on the same address is the same source; another address is
    // not, and time restores the first.
    let same = "192.0.2.1:2000".parse().unwrap();
    assert_eq!(
        h.get_nonce_from(same).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    let other = "192.0.2.2:1000".parse().unwrap();
    assert_eq!(h.get_nonce_from(other).await.status, StatusCode::OK);
    h.clock.advance(1);
    assert_eq!(h.get_nonce_from(source).await.status, StatusCode::OK);
}

#[tokio::test]
async fn enrolment_is_rate_limited_per_source() {
    let h = Harness::with_limits(Limits {
        source_rate_per_second: 1,
        source_burst: 1,
        ..test_limits()
    })
    .await;
    let code = h.code("host-a", false).await;
    let first = h.enrol_with("host-a", &signing_key(1), code.clone()).await;
    assert_eq!(first.status, StatusCode::NO_CONTENT, "{first:?}");
    let second = h.enrol_with("host-a", &signing_key(1), code).await;
    assert_eq!(second.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn the_signature_covers_the_query_string() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let body = work_body(&h);
    let with_query = format!("{WORK}?poll=1");

    // A signature over the bare path does not verify with a query added.
    let nonce = h.nonce().await;
    let added = signed_request("host-a", &key, WORK, &with_query, &nonce, body.clone());
    let answer = h.send(added).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_signature");

    // Nor one over the query with it taken away.
    let nonce = h.nonce().await;
    let removed = signed_request("host-a", &key, &with_query, WORK, &nonce, body.clone());
    assert_eq!(h.send(removed).await.code(), "bad_signature");

    // Signed as sent, it verifies: the verifier was given the path with query.
    let nonce = h.nonce().await;
    let exact = signed_request("host-a", &key, &with_query, &with_query, &nonce, body);
    assert_eq!(h.send(exact).await.status, StatusCode::OK);
}

#[tokio::test]
async fn a_signature_cannot_be_moved() {
    let h = Harness::new().await;
    let a = h.enrolled("host-a", 1).await;
    h.enrolled("host-b", 2).await;
    let body = work_body(&h);

    // To another path.
    let nonce = h.nonce().await;
    let moved = signed_request("host-a", &a, REPORT, WORK, &nonce, body.clone());
    assert_eq!(h.send(moved).await.code(), "bad_signature");

    // To another body.
    let nonce = h.nonce().await;
    let mut other_body = signed_request("host-a", &a, WORK, WORK, &nonce, b"{}".to_vec());
    *other_body.body_mut() = Body::from(body.clone());
    assert_eq!(h.send(other_body).await.code(), "bad_signature");

    // To another host, with this host's name in the header.
    let nonce = h.nonce().await;
    let mut as_b = signed_request("host-a", &a, WORK, WORK, &nonce, body.clone());
    as_b.headers_mut()
        .insert(HOST_HEADER, "host-b".parse().unwrap());
    assert_eq!(h.send(as_b).await.code(), "bad_signature");

    // To another method.
    let nonce = h.nonce().await;
    let signature = protocol::sign(&a, &host("host-a"), "GET", WORK, &nonce, &body);
    let request = Request::builder()
        .method(Method::POST)
        .uri(WORK)
        .header(HOST_HEADER, "host-a")
        .header(NONCE_HEADER, nonce.to_string())
        .header(SIGNATURE_HEADER, signature.to_string())
        .body(Body::from(body))
        .unwrap();
    assert_eq!(h.send(request).await.code(), "bad_signature");
}

#[tokio::test]
async fn an_unknown_host_looks_like_a_bad_signature() {
    let h = Harness::new().await;
    let nonce = h.nonce().await;
    let request = signed_request("nobody", &signing_key(1), WORK, WORK, &nonce, work_body(&h));
    let answer = h.send(request).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_signature");
}

#[tokio::test]
async fn the_nonce_is_checked_first_and_a_bad_signature_uses_it_up() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let body = work_body(&h);

    // An unknown nonce is the answer even for a request with a good signature
    // and for a host nobody has heard of.
    let unknown = Nonce::from_bytes([9; 32]);
    let good = signed_request("host-a", &key, WORK, WORK, &unknown, body.clone());
    assert_eq!(h.send(good).await.code(), "bad_nonce");
    let nobody = signed_request("nobody", &key, WORK, WORK, &unknown, body.clone());
    assert_eq!(h.send(nobody).await.code(), "bad_nonce");

    let nonce = h.nonce().await;
    let forged = signed_request("host-a", &signing_key(9), WORK, WORK, &nonce, body.clone());
    assert_eq!(h.send(forged).await.code(), "bad_signature");
    let late = signed_request("host-a", &key, WORK, WORK, &nonce, body);
    assert_eq!(h.send(late).await.code(), "bad_nonce");
}

#[tokio::test]
async fn missing_malformed_and_repeated_headers_are_refused() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let body = work_body(&h);
    let nonce = h.nonce().await;

    for header in [HOST_HEADER, NONCE_HEADER, SIGNATURE_HEADER] {
        let mut missing = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
        missing.headers_mut().remove(header);
        let answer = h.send(missing).await;
        assert_eq!(answer.status, StatusCode::UNAUTHORIZED, "{header}");
        assert_eq!(answer.code(), "unsigned", "{header}");

        let mut malformed = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
        malformed
            .headers_mut()
            .insert(header, "NOT VALID\t".parse().unwrap());
        assert_eq!(h.send(malformed).await.code(), "unsigned", "{header}");

        let mut repeated = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
        let value = repeated.headers()[header].clone();
        repeated.headers_mut().append(header, value);
        assert_eq!(h.send(repeated).await.code(), "unsigned", "{header}");
    }

    // None of that used the nonce up.
    let request = signed_request("host-a", &key, WORK, WORK, &nonce, body);
    assert_eq!(h.send(request).await.status, StatusCode::OK);
}

#[tokio::test]
async fn the_body_is_parsed_only_after_the_signature_and_strictly() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;

    // Garbage with a good signature is a bad request.
    let nonce = h.nonce().await;
    let garbage = signed_request("host-a", &key, WORK, WORK, &nonce, b"{not json".to_vec());
    assert_eq!(h.send(garbage).await.code(), "bad_request");

    // Garbage with a bad signature never got as far as being parsed.
    let nonce = h.nonce().await;
    let forged = signed_request(
        "host-a",
        &signing_key(9),
        WORK,
        WORK,
        &nonce,
        b"{not json".to_vec(),
    );
    assert_eq!(h.send(forged).await.code(), "bad_signature");

    // An unknown field is refused too.
    let extra = json!({
        "config_hash": hex::encode(h.config_hash),
        "running": [],
        "host": "host-b",
    });
    let answer = h.signed_post("host-a", &key, WORK, &extra).await;
    assert_eq!(answer.code(), "bad_request");
}

#[tokio::test]
async fn oversized_body_is_refused() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;

    // Over the limit, whether or not it says so up front.
    let body = vec![b' '; MAX_BODY_BYTES + 1];
    let nonce = h.nonce().await;
    let declared = signed_request("host-a", &key, WORK, WORK, &nonce, body.clone());
    let answer = h.send(declared).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(answer.code(), "body_too_large");

    let nonce = h.nonce().await;
    let mut chunked = signed_request("host-a", &key, WORK, WORK, &nonce, Vec::new());
    let chunks =
        std::iter::repeat_n(Bytes::from(vec![b' '; 64 * 1024]), 17).map(Ok::<_, Infallible>);
    *chunked.body_mut() = Body::from_stream(test_stream::Iter(chunks));
    let answer = h.send(chunked).await;
    assert_eq!(answer.status, StatusCode::PAYLOAD_TOO_LARGE);

    // Exactly at the limit it is read, and then it fails on its signature.
    let nonce = h.nonce().await;
    let mut at_limit = signed_request("host-a", &key, WORK, WORK, &nonce, Vec::new());
    *at_limit.body_mut() = Body::from(vec![b' '; MAX_BODY_BYTES]);
    assert_eq!(h.send(at_limit).await.code(), "bad_signature");
}

#[tokio::test]
async fn an_oversized_body_says_nothing_about_which_hosts_exist() {
    let h = Harness::new().await;
    let key = h.enrolled("host-a", 1).await;
    let body = vec![b' '; MAX_BODY_BYTES + 1];
    let mut answers = Vec::new();
    for name in ["host-a", "nobody"] {
        let nonce = h.nonce().await;
        let request = signed_request(name, &key, WORK, WORK, &nonce, body.clone());
        answers.push(h.send(request).await);
    }
    assert_eq!(answers[0].status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(answers[1].status, answers[0].status);
    assert_eq!(answers[1].body, answers[0].body);
}

/// The key for an unknown host is public, so a good signature by it must count
/// for nothing.
#[tokio::test]
async fn a_signature_by_the_unknown_host_key_is_refused() {
    let h = Harness::new().await;
    let key = SigningKey::from_bytes(&UNKNOWN_HOST_SEED);
    let nonce = h.nonce().await;
    let request = signed_request("nobody", &key, WORK, WORK, &nonce, work_body(&h));
    let answer = h.send(request).await;
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_signature");
}

/// The quickest of a few refusals for a body at the limit.
async fn quickest_refusal(h: &Harness, name: &str, key: &SigningKey) -> Duration {
    let mut quickest = Duration::MAX;
    for _ in 0..5 {
        let nonce = h.nonce().await;
        let mut request = signed_request(name, key, WORK, WORK, &nonce, Vec::new());
        *request.body_mut() = Body::from(vec![b' '; MAX_BODY_BYTES]);
        let started = Instant::now();
        let answer = h.send(request).await;
        quickest = quickest.min(started.elapsed());
        assert_eq!(answer.code(), "bad_signature");
    }
    quickest
}

/// Most of this refusal's time is hashing a large body, so an unknown host skipping
/// the work takes a small fraction of a known host's time. The margin is wide, and
/// the quickest of several ignores a busy machine: the two take about the same.
#[tokio::test]
async fn an_unknown_host_takes_as_long_to_refuse_as_a_known_one() {
    let h = Harness::new().await;
    h.enrolled("host-a", 1).await;
    let wrong = signing_key(9);
    let known = quickest_refusal(&h, "host-a", &wrong).await;
    let unknown = quickest_refusal(&h, "nobody", &wrong).await;
    assert!(unknown * 2 >= known, "{unknown:?} against {known:?}");
}

#[tokio::test]
async fn a_stalled_body_is_cut_off() {
    let h = Harness::with_limits(Limits {
        body_timeout: Duration::from_millis(50),
        ..test_limits()
    })
    .await;
    let key = h.enrolled("host-a", 1).await;
    let nonce = h.nonce().await;
    let mut request = signed_request("host-a", &key, WORK, WORK, &nonce, Vec::new());
    *request.body_mut() = Body::from_stream(test_stream::Pending);

    let answer = tokio::time::timeout(Duration::from_secs(5), h.send(request))
        .await
        .unwrap();
    assert_eq!(answer.status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(answer.code(), "slow_request");
}

#[tokio::test]
async fn every_request_has_a_deadline() {
    // The overall deadline, shorter here than the body's own.
    let h = Harness::with_limits(Limits {
        request_timeout: Duration::from_millis(50),
        ..test_limits()
    })
    .await;
    let key = h.enrolled("host-a", 1).await;
    let nonce = h.nonce().await;
    let mut request = signed_request("host-a", &key, WORK, WORK, &nonce, Vec::new());
    *request.body_mut() = Body::from_stream(test_stream::Pending);

    let answer = tokio::time::timeout(Duration::from_secs(5), h.send(request))
        .await
        .unwrap();
    assert_eq!(answer.status, StatusCode::REQUEST_TIMEOUT);
    assert_eq!(answer.code(), "slow_request");
}

/// Streaming bodies for `Body::from_stream`: one from an iterator, and one
/// that never yields, as a client that stops sending would.
mod test_stream {
    use std::convert::Infallible;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use axum::body::Bytes;
    use futures_core::Stream;

    pub(super) struct Iter<I>(pub(super) I);

    impl<I: Iterator + Unpin> Stream for Iter<I> {
        type Item = I::Item;

        fn poll_next(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<I::Item>> {
            Poll::Ready(self.0.next())
        }
    }

    pub(super) struct Pending;

    impl Stream for Pending {
        type Item = Result<Bytes, Infallible>;

        fn poll_next(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            Poll::Pending
        }
    }
}
