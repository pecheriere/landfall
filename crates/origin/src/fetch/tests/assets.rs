//! A release's files: listing them, and downloading one within its caps.

use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::{BINARY_LIMIT, FetchError, ReleaseAsset};
use super::{GITHUB_TOKEN, repo, tag};
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

/// The error and everything under it, as they would reach a person.
fn chain(error: &dyn std::error::Error) -> String {
    let mut parts = vec![format!("{error} / {error:?}")];
    let mut source = error.source();
    while let Some(next) = source {
        parts.push(format!("{next} / {next:?}"));
        source = next.source();
    }
    parts.join(" / ")
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

#[tokio::test]
async fn token_goes_to_the_api_and_not_the_redirect_target() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(ASSET_PATH))
        .respond_with(ResponseTemplate::new(302).insert_header(
            "location",
            format!("{}/stored?sig=signed-url-secret", storage.uri()).as_str(),
        ))
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path("/stored"))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(b"the bytes".to_vec()))
        .mount(&storage)
        .await;

    let fetcher = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap();
    let bytes = fetcher.release_asset(&repo(), &asset(9), 9).await.unwrap();
    assert_eq!(bytes, b"the bytes", "it was followed");

    let sent = github.received_requests().await.unwrap();
    assert_eq!(
        sent[0].headers.get("authorization").unwrap(),
        format!("Bearer {GITHUB_TOKEN}").as_str(),
    );
    let stored = storage.received_requests().await.unwrap();
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].headers.get("authorization"), None);
}

/// Redirects to a URL whose query is a credential, which go on until the client gives up.
/// That error names the URL it stopped at, so this is the one that would show it. Neither
/// it nor the token reaches the error, in its message or its `Debug`.
#[tokio::test]
async fn neither_the_token_nor_a_signed_url_reaches_an_error() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    let stored = format!("{}/stored?sig=signed-url-secret", storage.uri());
    for (server, at) in [(&github, ASSET_PATH), (&storage, "/stored")] {
        Mock::given(method("GET"))
            .and(path(at))
            .respond_with(ResponseTemplate::new(302).insert_header("location", stored.as_str()))
            .mount(server)
            .await;
    }
    let fetcher = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap();

    let error = fetcher
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Request { .. }), "{error:?}");
    let text = chain(&error);
    assert!(!text.contains(GITHUB_TOKEN), "{text}");
    assert!(!text.contains("signed-url-secret"), "{text}");
    assert!(!format!("{fetcher:?}").contains(GITHUB_TOKEN));
}
