//! How failures are told apart and reported.

use landfall_core::ids::{ReleaseTag, RepoName};
use wiremock::matchers::method;
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::github::checked_sha1;
use super::super::{Endpoints, FetchError, Fetcher, RateLimitReset, Service};
use super::{BUNDLE, IMAGE, repo, tag};
use crate::test_support::fetcher;

#[tokio::test]
async fn github_rate_limit_names_the_reset_and_suggests_a_token() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("x-ratelimit-reset", "1767225600"),
        )
        .mount(&github)
        .await;

    let error = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await
        .unwrap_err();
    match &error {
        FetchError::RateLimited {
            service,
            status,
            reset,
            ..
        } => {
            assert_eq!(*service, Service::GitHubApi);
            assert_eq!(*status, 403);
            assert_eq!(
                *reset,
                RateLimitReset::At("2026-01-01T00:00:00Z".parse().unwrap())
            );
        }
        other => panic!("{other:?}"),
    }
    assert!(error.is_unavailable());
    let message = error.to_string();
    assert!(
        message.contains("it resets at 2026-01-01T00:00:00Z"),
        "{message}"
    );
    assert!(message.contains("GITHUB_TOKEN"), "{message}");
}

#[tokio::test]
async fn registry_retry_after_is_a_rate_limit() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(429).insert_header("retry-after", "30"))
        .mount(&registry)
        .await;

    let error = fetcher(&github, &registry)
        .resolve_index(IMAGE, &tag())
        .await
        .unwrap_err();
    match &error {
        FetchError::RateLimited {
            service,
            status,
            reset,
            ..
        } => {
            assert_eq!(*service, Service::Registry);
            assert_eq!(*status, 429);
            assert_eq!(*reset, RateLimitReset::After(30));
        }
        other => panic!("{other:?}"),
    }
    let message = error.to_string();
    assert!(message.contains("retry after 30 s"), "{message}");
    assert!(!message.contains("GITHUB_TOKEN"), "{message}");
}

#[tokio::test]
async fn forbidden_without_rate_limit_headers_is_a_status() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "59"))
        .mount(&github)
        .await;

    let result = fetcher(&github, &registry)
        .tag_object(&repo(), &tag())
        .await;
    assert!(
        matches!(result, Err(FetchError::Status { status: 403, .. })),
        "{result:?}"
    );
}

#[test]
fn server_text_in_errors_is_quoted() {
    let error = FetchError::ObjectType {
        tag: tag(),
        found: "tree\u{1b}[2J".to_owned(),
    };
    assert_eq!(
        error.to_string(),
        "tag v1.2.3 points at a \"tree\\u{1b}[2J\" object, not a commit"
    );
    let error = FetchError::ObjectId {
        expected: "a\nb".to_owned(),
        computed: "c".repeat(40),
    };
    assert!(error.to_string().contains("fetched \"a\\nb\""), "{error}");
}

#[test]
fn sha1_collision_is_detected() {
    let prefix = include_bytes!("../../../tests/fixtures/sha1/shattered-1-prefix.bin");
    assert!(checked_sha1(&[prefix]).is_none());
    assert_eq!(
        checked_sha1(&[b"hello ", b"world"]).as_deref(),
        Some("2aae6c35c94fcfb415dbe95f408b9ce91ee846ed")
    );
}

/// The attestation fixture's release, fetched from the real GitHub API
/// and GHCR: the tag object, its commit, the index digest and the bundle.
#[tokio::test]
#[ignore = "network: runs nightly in advisories.yml"]
async fn live_fixture_release() {
    const INDEX_DIGEST: &str = include_str!("../../../tests/fixtures/attestation/index-digest.txt");
    let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    // The nightly job passes its token for the higher API rate limit.
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        fetcher = fetcher.with_github_token(&token).unwrap();
    }
    let repo: RepoName = "dani-garcia/vaultwarden".parse().unwrap();
    let tag: ReleaseTag = "1.37.4".parse().unwrap();

    let raw = fetcher.tag_object(&repo, &tag).await.unwrap();
    assert!(raw.starts_with(b"object 7c188967e7a467b19b2757bc3326f9cf3ccae327\ntype commit\n"));
    let commit = fetcher.tag_commit(&repo, &tag).await.unwrap();
    assert_eq!(commit.as_ref(), "7c188967e7a467b19b2757bc3326f9cf3ccae327");

    let (digest, platforms) = fetcher
        .resolve_index("dani-garcia/vaultwarden", &tag)
        .await
        .unwrap();
    assert_eq!(digest.as_ref(), INDEX_DIGEST.trim());
    assert!(platforms.iter().all(|p| p.os == "linux"), "{platforms:?}");

    let bundle = fetcher
        .bundle("dani-garcia/vaultwarden", &digest)
        .await
        .unwrap();
    let served: serde_json::Value = serde_json::from_slice(&bundle).unwrap();
    let fixture: serde_json::Value = serde_json::from_slice(BUNDLE).unwrap();
    assert_eq!(served, fixture);
}
