//! A release's files: listing them, and downloading one within its caps.

use std::time::Duration;

use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::assets::ASSET_TIMEOUT;
use super::super::{
    BINARY_LIMIT, FetchError, MANIFEST_LIMIT, MAX_REDIRECTS, ReleaseAsset, SUMS_LIMIT,
};
use super::redirects::{redirect, serve};
use super::{repo, tag};
use crate::test_support::{fetcher, fetcher_for};

const RELEASE_PATH: &str = "/repos/example/app/releases/tags/v1.2.3";

const ASSET_PATH: &str = "/repos/example/app/releases/assets/7";

fn asset(size: u64) -> ReleaseAsset {
    ReleaseAsset {
        id: 7,
        name: "file".to_owned(),
        size,
    }
}

async fn servers() -> (MockServer, MockServer) {
    (MockServer::start().await, MockServer::start().await)
}

#[tokio::test]
async fn assets_are_listed() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(RELEASE_PATH))
        .and(header("accept", "application/vnd.github+json"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "tag_name": "v1.2.3",
            "draft": false,
            "assets": [
                { "id": 7, "name": "file", "size": 11, "digest": "ignored" },
                { "id": 8, "name": "SHA256SUMS", "size": 90 },
            ],
        })))
        .mount(&github)
        .await;

    let assets = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(
        assets,
        [
            asset(11),
            ReleaseAsset {
                id: 8,
                name: "SHA256SUMS".to_owned(),
                size: 90,
            },
        ]
    );
}

#[tokio::test]
async fn an_answer_about_another_release_is_refused() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(RELEASE_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "tag_name": "v1.2.4", "assets": [] })),
        )
        .mount(&github)
        .await;
    let result = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::Malformed { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn missing_release_is_not_found() {
    let (github, registry) = servers().await;
    let result = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::NotFound { .. })),
        "{result:?}"
    );
}

#[tokio::test]
async fn an_asset_is_downloaded_as_bytes() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(ASSET_PATH))
        .and(header("accept", "application/octet-stream"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"the bytes".to_vec()))
        .mount(&github)
        .await;
    let bytes = fetcher(&github, &registry)
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap();
    assert_eq!(bytes, b"the bytes");
}

#[tokio::test]
async fn oversized_asset_is_refused_before_download() {
    let (github, registry) = servers().await;
    let fetcher = fetcher(&github, &registry);
    for (size, limit) in [
        (11, 10),
        (u64::try_from(BINARY_LIMIT).unwrap() + 1, BINARY_LIMIT),
        (u64::MAX, BINARY_LIMIT),
    ] {
        let result = fetcher.release_asset(&repo(), &asset(size), limit).await;
        assert!(
            matches!(&result, Err(FetchError::TooLarge { limit: l, .. }) if *l == limit),
            "{result:?}"
        );
    }
    assert_eq!(github.received_requests().await.unwrap().len(), 0);
}

#[tokio::test]
async fn asset_longer_than_it_said_is_cut_off() {
    // With its length declared, it is refused on that.
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(ASSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 11]))
        .mount(&github)
        .await;
    let result = fetcher(&github, &registry)
        .release_asset(&repo(), &asset(10), 100)
        .await;
    assert!(
        matches!(result, Err(FetchError::TooLarge { limit: 10, .. })),
        "{result:?}"
    );

    // Without one, as the bytes arrive: a server that never stops is hung up on.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 1024];
        while !request.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buffer).await.unwrap();
            request.extend_from_slice(&buffer[..n]);
        }
        let head = "HTTP/1.1 200 OK\r\ntransfer-encoding: chunked\r\n\r\n";
        socket.write_all(head.as_bytes()).await.unwrap();
        let chunk = vec![b'x'; 1024];
        let frame = [format!("{:x}\r\n", chunk.len()).as_bytes(), &chunk, b"\r\n"].concat();
        while socket.write_all(&frame).await.is_ok() {}
    });
    let base = format!("http://{address}");
    let result = fetcher_for(&base, &base)
        .release_asset(&repo(), &asset(4096), BINARY_LIMIT)
        .await;
    assert!(
        matches!(result, Err(FetchError::TooLarge { limit: 4096, .. })),
        "{result:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn asset_shorter_than_it_said_is_refused() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(ASSET_PATH))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 9]))
        .mount(&github)
        .await;
    let result = fetcher(&github, &registry)
        .release_asset(&repo(), &asset(10), 100)
        .await;
    assert!(
        matches!(result, Err(FetchError::Malformed { .. })),
        "{result:?}"
    );
}

/// A server that sends a head promising more, and then nothing.
async fn stalled_server() -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut buffer = [0_u8; 1024];
        let _ = socket.read(&mut buffer).await;
        let head = "HTTP/1.1 200 OK\r\ncontent-length: 9\r\n\r\nabc";
        socket.write_all(head.as_bytes()).await.unwrap();
        std::future::pending::<()>().await;
    });
    address
}

/// A stalled storage host is given up on by the asset's timeout, whichever it is, and not
/// left to the client's 30 s, which a binary needs more than. The outer limit fails the
/// test well before that.
#[tokio::test]
async fn a_stalled_download_ends_at_the_assets_timeout() {
    let (github, registry) = servers().await;
    let address = stalled_server().await;
    redirect(&github, ASSET_PATH, &format!("http://{address}/stored")).await;
    let fetcher = fetcher(&github, &registry).with_asset_timeout(Duration::from_millis(200));
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        fetcher.release_asset(&repo(), &asset(9), 9),
    )
    .await
    .expect("the asset's timeout applies, and not the client's");
    assert!(
        matches!(result, Err(FetchError::Request { .. })),
        "{result:?}"
    );
}

/// The numbers, spelled out, as nothing else would notice one changing.
#[test]
fn the_limits_are_these() {
    assert_eq!(BINARY_LIMIT, 67_108_864);
    assert_eq!(SUMS_LIMIT, 65_536);
    assert_eq!(MANIFEST_LIMIT, 1_048_576);
    assert_eq!(ASSET_TIMEOUT, Duration::from_mins(10));
    assert_eq!(MAX_REDIRECTS, 3);
    let fetcher = crate::test_support::fetcher_for("http://127.0.0.1:1", "http://127.0.0.1:1");
    assert_eq!(fetcher.asset_timeout, ASSET_TIMEOUT);
}

/// The listing's cap is its own: above a tag object's, as a release lists many files, and
/// no higher than a megabyte.
#[tokio::test]
async fn the_listing_has_its_own_cap() {
    let padded = |total: usize| {
        let head = br#"{ "tag_name": "v1.2.3", "assets": [] }"#;
        let mut body = head.to_vec();
        body.resize(total, b' ');
        body
    };
    let (github, registry) = servers().await;
    serve(&github, RELEASE_PATH, &padded(1_048_576)).await;
    let assets = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(assets, [], "exactly the cap");

    let (github, registry) = servers().await;
    serve(&github, RELEASE_PATH, &padded(1_048_577)).await;
    let result = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await;
    assert!(
        matches!(
            result,
            Err(FetchError::TooLarge {
                limit: 1_048_576,
                ..
            })
        ),
        "{result:?}"
    );
}

#[tokio::test]
async fn a_hostile_tag_name_in_the_answer_is_quoted_and_cut_short() {
    let (github, registry) = servers().await;
    let hostile = format!("v1\n{}", "x".repeat(100_000));
    Mock::given(method("GET"))
        .and(path(RELEASE_PATH))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({ "tag_name": hostile, "assets": [] })),
        )
        .mount(&github)
        .await;
    let error = fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await
        .unwrap_err();
    let text = error.to_string();
    assert!(text.len() < 400, "{} bytes", text.len());
    assert!(!text.contains('\n'), "{text}");
}
