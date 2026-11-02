//! `[server] trusted_proxies`, through the routes that go by the source. The rules themselves are
//! tested with [`client_source`](crate::agent_api), at their own level.

use std::net::SocketAddr;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use landfall_approval::SoftwareAuthenticator;
use serde_json::json;

use super::{Harness, ORIGIN, SIGN_IN_BEGIN, config_text, post_request};
use crate::agent_api::Limits;
use crate::store::Store;

const PROXY: &str = "192.0.2.100";

async fn behind_a_proxy(limits: Limits) -> Harness {
    let alice = SoftwareAuthenticator::es256().unwrap();
    let text = format!(
        "{}\n[server]\ntrusted_proxies = [\"{PROXY}\"]\n",
        config_text(&alice)
    );
    Harness::on(
        Store::open_in_memory().await.unwrap(),
        &text,
        limits,
        alice,
    )
}

fn at(mut request: Request<Body>, peer: &str, forwarded: Option<&str>) -> Request<Body> {
    let peer: SocketAddr = format!("{peer}:1000").parse().unwrap();
    request.extensions_mut().insert(ConnectInfo(peer));
    if let Some(forwarded) = forwarded {
        request
            .headers_mut()
            .insert("x-forwarded-for", forwarded.parse().unwrap());
    }
    request
}

fn begin(peer: &str, forwarded: Option<&str>) -> Request<Body> {
    at(
        post_request(SIGN_IN_BEGIN, Some(ORIGIN), None, &json!({})),
        peer,
        forwarded,
    )
}

fn one_at_a_time() -> Limits {
    Limits {
        ceremony_rate_per_second: 1,
        ceremony_burst: 1,
        source_rate_per_second: 1,
        source_burst: 1,
        ..Limits::default()
    }
}

#[tokio::test]
async fn clients_behind_a_trusted_proxy_have_their_own_allowance() {
    let h = behind_a_proxy(one_at_a_time()).await;
    let client = Some("198.51.100.1");
    assert_eq!(h.send(begin(PROXY, client)).await.status, StatusCode::OK);
    let again = h.send(begin(PROXY, client)).await;
    assert_eq!(again.status, StatusCode::TOO_MANY_REQUESTS);
    // Someone else, through the same proxy.
    let other = h.send(begin(PROXY, Some("198.51.100.2"))).await;
    assert_eq!(other.status, StatusCode::OK);
    // A client can't get round it by adding to the left of what the proxy appended.
    let spoofed = h
        .send(begin(PROXY, Some("203.0.113.9, 198.51.100.1")))
        .await;
    assert_eq!(spoofed.status, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn a_direct_peer_cannot_claim_to_be_anyone() {
    let h = behind_a_proxy(one_at_a_time()).await;
    let direct = "198.51.100.50";
    assert_eq!(
        h.send(begin(direct, Some("203.0.113.1"))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.send(begin(direct, Some("203.0.113.2"))).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

#[tokio::test]
async fn with_no_list_the_header_means_nothing() {
    let h = Harness::with_limits(one_at_a_time()).await;
    assert_eq!(
        h.send(begin(PROXY, Some("203.0.113.1"))).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.send(begin(PROXY, Some("203.0.113.2"))).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
}

/// The agent API's unauthenticated routes go by the same rule, with their own allowance.
#[tokio::test]
async fn the_agent_apis_limit_goes_by_the_same_source() {
    let h = behind_a_proxy(one_at_a_time()).await;
    let nonce = |forwarded| {
        at(
            Request::builder()
                .uri("/agent/v1/nonce")
                .body(Body::empty())
                .unwrap(),
            PROXY,
            Some(forwarded),
        )
    };
    assert_eq!(
        h.send(nonce("198.51.100.1")).await.status,
        StatusCode::OK
    );
    assert_eq!(
        h.send(nonce("198.51.100.1")).await.status,
        StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        h.send(nonce("198.51.100.2")).await.status,
        StatusCode::OK
    );
}

/// What a failure's row names is the client, not the proxy.
#[tokio::test]
async fn a_failures_row_names_the_client() {
    let h = behind_a_proxy(Limits::default()).await;
    let stranger = SoftwareAuthenticator::es256().unwrap();
    let begun = h.send(begin(PROXY, Some("198.51.100.1"))).await;
    let challenge = super::challenge_of(&begun);
    let mut forged = landfall_approval::Ceremony::new(super::RP_ID, ORIGIN, &challenge);
    forged.credential_id = Some(h.alice.credential_id().to_vec());
    let finish = at(
        post_request(
            super::SIGN_IN_FINISH,
            Some(ORIGIN),
            None,
            &super::sign_in_ceremony_body(&stranger, &challenge, &forged),
        ),
        PROXY,
        Some("198.51.100.1"),
    );
    assert_eq!(h.send(finish).await.code(), "sign_in_refused");
    crate::web::tend(&h.state).await;
    let rows = h.audited("sign_in_refused").await;
    assert_eq!(rows[0]["sources"], json!(["198.51.100.1"]));
}
