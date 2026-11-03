//! A release's files: listing them, and downloading one within its caps.

use std::time::Duration;

use reqwest::Url;
use reqwest::header::HeaderValue;
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::assets::ASSET_TIMEOUT;
use super::super::http::next_hop;
use super::super::{
    BINARY_LIMIT, FetchError, MANIFEST_LIMIT, MAX_REDIRECTS, ReleaseAsset, SUMS_LIMIT,
};
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
    assert!(matches!(error, FetchError::Redirect { .. }), "{error:?}");
    let text = chain(&error);
    assert!(!text.contains(GITHUB_TOKEN), "{text}");
    assert!(!text.contains("signed-url-secret"), "{text}");
    assert!(!format!("{fetcher:?}").contains(GITHUB_TOKEN));

    // And a host that can't be reached, which a transport error would name.
    let closed = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = closed.local_addr().unwrap();
    drop(closed);
    let (github, registry) = servers().await;
    redirect(
        &github,
        ASSET_PATH,
        &format!("http://{address}/stored?sig=signed-url-secret"),
    )
    .await;
    let error = crate::test_support::fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Request { .. }), "{error:?}");
    let text = chain(&error);
    assert!(!text.contains(GITHUB_TOKEN), "{text}");
    assert!(!text.contains("signed-url-secret"), "{text}");
}

async fn redirect(server: &MockServer, at: &str, to: &str) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to))
        .mount(server)
        .await;
}

async fn serve(server: &MockServer, at: &str, body: &[u8]) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(200).set_body_bytes(body.to_vec()))
        .mount(server)
        .await;
}

/// Asserts a host never saw the token, or a URL it was redirected from.
async fn assert_nothing_of_the_token(server: &MockServer, requests: usize) {
    let seen = server.received_requests().await.unwrap();
    assert_eq!(seen.len(), requests);
    for request in seen {
        assert_eq!(
            request.headers.get("authorization"),
            None,
            "{}",
            request.url
        );
        assert_eq!(request.headers.get("referer"), None, "{}", request.url);
        assert_eq!(
            request.headers.get("x-github-api-version"),
            None,
            "{}",
            request.url
        );
    }
}

/// The chain that once sent it: a client's redirect handling drops a credential for one hop
/// to another host, and puts it back for the next on that host. The storage host redirects
/// to itself, and then to another port, and is never given it.
#[tokio::test]
async fn the_token_never_follows_a_chain_of_redirects() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    redirect(
        &github,
        ASSET_PATH,
        &format!("{}/a?sig=secret-one", storage.uri()),
    )
    .await;
    // Relative, as a `Location` may be.
    redirect(&storage, "/a", "/b?sig=secret-two").await;
    redirect(
        &storage,
        "/b",
        &format!("{}/c?sig=secret-three", elsewhere.uri()),
    )
    .await;
    serve(&elsewhere, "/c", b"the bytes").await;

    let fetcher = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap();
    let bytes = fetcher.release_asset(&repo(), &asset(9), 9).await.unwrap();
    assert_eq!(bytes, b"the bytes");

    let sent = github.received_requests().await.unwrap();
    assert_eq!(sent.len(), 1, "one request to the API");
    assert_eq!(
        sent[0].headers.get("authorization").unwrap(),
        format!("Bearer {GITHUB_TOKEN}").as_str(),
    );
    assert_nothing_of_the_token(&storage, 2).await;
    assert_nothing_of_the_token(&elsewhere, 1).await;
}

/// Every fetch of metadata goes the same way: tag objects and lists of tags and files.
#[tokio::test]
async fn a_chain_from_the_listing_has_no_token_either() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    redirect(&github, RELEASE_PATH, &format!("{}/a", storage.uri())).await;
    redirect(&storage, "/a", "/b").await;
    serve(&storage, "/b", br#"{ "tag_name": "v1.2.3", "assets": [] }"#).await;
    let assets = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .release_assets(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(assets, []);
    assert_nothing_of_the_token(&storage, 2).await;
}

/// A tag object and its ref, behind a chain on another host.
#[tokio::test]
async fn a_chain_from_a_tag_object_has_no_token_either() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    redirect(
        &github,
        "/repos/example/app/git/ref/tags/v1.2.3",
        &format!("{}/a", storage.uri()),
    )
    .await;
    redirect(&storage, "/a", "/b").await;
    let result = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .tag_object(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::NotFound { .. })),
        "{result:?}"
    );
    assert_nothing_of_the_token(&storage, 2).await;
}

/// The registry's pull token, on a blob's way to its storage.
#[tokio::test]
async fn a_chain_from_the_registry_has_no_pull_token() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    redirect(&registry, "/v2/blob", &format!("{}/a", storage.uri())).await;
    redirect(&storage, "/a", "/b").await;
    serve(&storage, "/b", b"the blob").await;
    let token = HeaderValue::from_static("Bearer pull-token");
    let url = Url::parse(&format!("{}/v2/blob", registry.uri())).unwrap();
    let fetched = fetcher(&github, &registry)
        .registry_get(&url, "application/json", Some(&token), 100)
        .await
        .unwrap();
    assert_eq!(fetched.body, b"the blob");
    let sent = registry.received_requests().await.unwrap();
    assert_eq!(
        sent[0].headers.get("authorization").unwrap(),
        "Bearer pull-token"
    );
    assert_nothing_of_the_token(&storage, 2).await;
}

/// A repository that was renamed answers so, within the API: that is the same service.
#[tokio::test]
async fn a_redirect_within_the_api_keeps_the_token_for_metadata() {
    let (github, registry) = servers().await;
    redirect(
        &github,
        RELEASE_PATH,
        "/repositories/1/releases/tags/v1.2.3",
    )
    .await;
    serve(
        &github,
        "/repositories/1/releases/tags/v1.2.3",
        br#"{ "tag_name": "v1.2.3", "assets": [] }"#,
    )
    .await;
    let assets = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .release_assets(&repo(), &tag())
        .await
        .unwrap();
    assert_eq!(assets, []);
    let sent = github.received_requests().await.unwrap();
    assert_eq!(sent.len(), 2);
    for request in sent {
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            format!("Bearer {GITHUB_TOKEN}").as_str()
        );
    }
}

#[tokio::test]
async fn an_asset_redirected_within_the_api_is_refused() {
    let (github, registry) = servers().await;
    redirect(&github, ASSET_PATH, "/elsewhere").await;
    let error = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap()
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Redirect { .. }), "{error:?}");
    assert!(error.is_unavailable());
    assert_eq!(github.received_requests().await.unwrap().len(), 1);
}

/// For any fetch: having left the API's host, it isn't asked again, with or without a token.
#[tokio::test]
async fn a_redirect_back_to_the_api_is_refused() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    for at in [ASSET_PATH, RELEASE_PATH] {
        redirect(&github, at, &format!("{}/a", storage.uri())).await;
    }
    redirect(&storage, "/a", &format!("{}/back", github.uri())).await;
    let fetcher = fetcher(&github, &registry)
        .with_github_token(GITHUB_TOKEN)
        .unwrap();

    let error = fetcher
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Redirect { .. }), "{error:?}");
    let error = fetcher.release_assets(&repo(), &tag()).await.unwrap_err();
    assert!(matches!(error, FetchError::Redirect { .. }), "{error:?}");
    assert_eq!(github.received_requests().await.unwrap().len(), 2);
}

/// Three redirects are followed, which GitHub's storage is well within, and a fourth isn't.
#[tokio::test]
async fn the_hops_are_limited() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    redirect(&github, ASSET_PATH, &format!("{}/1", storage.uri())).await;
    redirect(&storage, "/1", "/2").await;
    redirect(&storage, "/2", "/3").await;
    serve(&storage, "/3", b"the bytes").await;
    redirect(&storage, "/4", "/5").await;
    redirect(&github, RELEASE_PATH, &format!("{}/4", storage.uri())).await;
    redirect(&storage, "/5", "/6").await;
    redirect(&storage, "/6", "/7").await;
    serve(&storage, "/7", b"unreached").await;

    let fetcher = fetcher(&github, &registry);
    let bytes = fetcher.release_asset(&repo(), &asset(9), 9).await.unwrap();
    assert_eq!(bytes, b"the bytes", "three redirects");
    let error = fetcher.release_assets(&repo(), &tag()).await.unwrap_err();
    assert!(
        matches!(error, FetchError::Redirect { reason, .. } if reason.contains("too many")),
        "{error:?}"
    );
    // Within the API's host, the same limit.
    let (github, registry) = servers().await;
    for (from, to) in [
        ("/repos/example/app/releases/tags/v1.2.3", "/1"),
        ("/1", "/2"),
        ("/2", "/3"),
        ("/3", "/4"),
    ] {
        redirect(&github, from, to).await;
    }
    let error = crate::test_support::fetcher(&github, &registry)
        .release_assets(&repo(), &tag())
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Redirect { .. }), "{error:?}");
    assert_eq!(github.received_requests().await.unwrap().len(), 4);
}

/// What may be followed. This is apart from the client's own `https_only`, as tests need
/// plain servers for everything else.
#[test]
fn only_https_is_followed_unless_the_endpoints_are_a_tests() {
    let current = Url::parse("https://api.example/repos/x").unwrap();
    for (location, https_only, expected) in [
        (
            "https://storage.example/a?sig=1",
            true,
            Ok("https://storage.example/a?sig=1"),
        ),
        ("/b", true, Ok("https://api.example/b")),
        ("//other.example/c", true, Ok("https://other.example/c")),
        (
            "http://storage.example/a",
            true,
            Err("its location is not https"),
        ),
        (
            "http://storage.example/a",
            false,
            Ok("http://storage.example/a"),
        ),
        (
            "ftp://storage.example/a",
            true,
            Err("its location is not https"),
        ),
        (
            "ftp://storage.example/a",
            false,
            Err("its location is not https"),
        ),
        (
            "file:///etc/passwd",
            false,
            Err("its location is not https"),
        ),
        (
            "https://u:p@storage.example/a",
            true,
            Err("its location carries credentials"),
        ),
        (
            "https://u@storage.example/a",
            true,
            Err("its location carries credentials"),
        ),
        ("https://[bad/a", true, Err("its location is not a URL")),
    ] {
        let next = next_hop(&current, location, https_only);
        assert_eq!(
            next.as_ref().map(Url::as_str).map_err(|e| *e),
            expected,
            "{location}"
        );
    }
}

#[tokio::test]
async fn a_redirect_with_no_location_is_an_unexpected_status() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(ASSET_PATH))
        .respond_with(ResponseTemplate::new(302))
        .mount(&github)
        .await;
    let error = fetcher(&github, &registry)
        .release_asset(&repo(), &asset(9), 9)
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::Status { status: 302, .. }),
        "{error:?}"
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
