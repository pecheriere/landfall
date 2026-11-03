//! Following redirects: where a credential goes, what is followed, and what a failure names.

use reqwest::Url;
use reqwest::header::HeaderValue;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::http::next_hop;
use super::super::{FetchError, ReleaseAsset};
use super::{GITHUB_TOKEN, repo, tag};
use crate::test_support::fetcher;

const RELEASE_PATH: &str = "/repos/example/app/releases/tags/v1.2.3";

const ASSET_PATH: &str = "/repos/example/app/releases/assets/7";

const EMPTY_RELEASE: &[u8] = br#"{ "tag_name": "v1.2.3", "assets": [] }"#;

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

pub(super) async fn redirect(server: &MockServer, at: &str, to: &str) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(302).insert_header("location", to))
        .mount(server)
        .await;
}

pub(super) async fn serve(server: &MockServer, at: &str, body: &[u8]) {
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
        (
            "https://:p@storage.example/a",
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

/// A redirect with this status, which `redirect` makes a 302.
async fn redirect_by(server: &MockServer, at: &str, status: u16, to: &str) {
    Mock::given(method("GET"))
        .and(path(at))
        .respond_with(ResponseTemplate::new(status).insert_header("location", to))
        .mount(server)
        .await;
}

/// Asserts a failure names the URL asked for and nothing of where it was sent, in its
/// message, its `Debug` or anything under it.
fn assert_names_only_what_was_asked(error: &FetchError, case: &str) {
    let text = chain(error);
    assert!(!text.contains("sig="), "{case}: {text}");
    assert!(!text.contains("signed-url-secret"), "{case}: {text}");
    assert!(!text.contains(GITHUB_TOKEN), "{case}: {text}");
    assert!(text.contains(ASSET_PATH), "{case}: {text}");
}

/// A storage host's query is a credential. Once a redirect has reached it, each way it can
/// fail names the API's URL: an answer it refuses, one too long or too short, and a
/// `Location` of its own that isn't followed.
#[tokio::test]
async fn a_failure_past_a_redirect_names_only_what_was_asked() {
    let answers = [
        ("500", ResponseTemplate::new(500)),
        ("404", ResponseTemplate::new(404)),
        ("403", ResponseTemplate::new(403)),
        (
            "429",
            ResponseTemplate::new(429).insert_header("retry-after", "60"),
        ),
        (
            "too long",
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 10]),
        ),
        (
            "too short",
            ResponseTemplate::new(200).set_body_bytes(vec![b'x'; 8]),
        ),
        (
            "a location that isn't https or http",
            ResponseTemplate::new(302).insert_header("location", "ftp://elsewhere.example/x?sig=2"),
        ),
        (
            "a location that isn't a URL",
            ResponseTemplate::new(302).insert_header("location", "https://[bad?sig=2"),
        ),
        (
            "a location with credentials",
            ResponseTemplate::new(302).insert_header("location", "https://u:p@elsewhere.example/"),
        ),
    ];
    for (case, answer) in answers {
        let (github, registry) = servers().await;
        let storage = MockServer::start().await;
        redirect(
            &github,
            ASSET_PATH,
            &format!("{}/stored?sig=signed-url-secret", storage.uri()),
        )
        .await;
        Mock::given(method("GET"))
            .and(path("/stored"))
            .respond_with(answer)
            .mount(&storage)
            .await;
        let error = fetcher(&github, &registry)
            .with_github_token(GITHUB_TOKEN)
            .unwrap()
            .release_asset(&repo(), &asset(9), 9)
            .await
            .unwrap_err();
        assert_names_only_what_was_asked(&error, case);
    }
}

/// Each of these is followed: 301 is what a renamed repository answers, and 307 what GHCR
/// answers for a blob. From the API, and from the storage host, with no token after the first.
#[tokio::test]
async fn each_redirect_status_is_followed() {
    for status in [301, 302, 303, 307, 308] {
        let (github, registry) = servers().await;
        let storage = MockServer::start().await;
        redirect_by(&github, ASSET_PATH, status, &format!("{}/a", storage.uri())).await;
        redirect_by(&storage, "/a", status, "/b").await;
        serve(&storage, "/b", b"the bytes").await;
        let bytes = fetcher(&github, &registry)
            .with_github_token(GITHUB_TOKEN)
            .unwrap()
            .release_asset(&repo(), &asset(9), 9)
            .await
            .unwrap();
        assert_eq!(bytes, b"the bytes", "{status}");
        assert_nothing_of_the_token(&storage, 2).await;
    }
}

/// A `Location` means nothing on any other status: the answer is taken as it is, and
/// nothing is asked of where it points.
#[tokio::test]
async fn a_location_on_any_other_status_is_not_followed() {
    for status in [200, 201, 204, 300, 304, 305, 306, 400, 403, 404, 500] {
        let (github, registry) = servers().await;
        let storage = MockServer::start().await;
        redirect_by(
            &github,
            RELEASE_PATH,
            status,
            &format!("{}/a", storage.uri()),
        )
        .await;
        serve(&storage, "/a", EMPTY_RELEASE).await;
        let result = fetcher(&github, &registry)
            .release_assets(&repo(), &tag())
            .await;
        assert_eq!(
            storage.received_requests().await.unwrap().len(),
            0,
            "{status}"
        );
        assert!(result.is_err(), "{status}: {result:?}");
    }
}

/// The rename: within the API's host, by 301, for what the token is for.
#[tokio::test]
async fn a_rename_keeps_the_token() {
    let (github, registry) = servers().await;
    redirect_by(
        &github,
        RELEASE_PATH,
        301,
        "/repositories/1/releases/tags/v1.2.3",
    )
    .await;
    serve(
        &github,
        "/repositories/1/releases/tags/v1.2.3",
        EMPTY_RELEASE,
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
            format!("Bearer {GITHUB_TOKEN}").as_str(),
            "{}",
            request.url
        );
        assert_eq!(
            request.headers.get("x-github-api-version").unwrap(),
            "2022-11-28",
            "{}",
            request.url
        );
    }
}

/// A registry's redirect within itself is the same service, by 307 as GHCR answers, and its
/// pull token goes along. On to a blob host, it doesn't.
#[tokio::test]
async fn a_registrys_redirect_within_itself_keeps_its_pull_token() {
    let (github, registry) = servers().await;
    let storage = MockServer::start().await;
    redirect_by(&registry, "/v2/one", 307, "/v2/two").await;
    redirect_by(
        &registry,
        "/v2/two",
        307,
        &format!("{}/blob", storage.uri()),
    )
    .await;
    serve(&storage, "/blob", b"the blob").await;
    let token = HeaderValue::from_static("Bearer pull-token");
    let url = Url::parse(&format!("{}/v2/one", registry.uri())).unwrap();
    let fetched = fetcher(&github, &registry)
        .registry_get(&url, "application/json", Some(&token), 100)
        .await
        .unwrap();
    assert_eq!(fetched.body, b"the blob");
    let sent = registry.received_requests().await.unwrap();
    assert_eq!(sent.len(), 2);
    for request in sent {
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            "Bearer pull-token",
            "{}",
            request.url
        );
    }
    assert_nothing_of_the_token(&storage, 1).await;
    assert_eq!(github.received_requests().await.unwrap().len(), 0);
}
