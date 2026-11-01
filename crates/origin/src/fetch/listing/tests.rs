//! The lists against a mock GitHub API and registry: pages, caps, and bodies
//! and headers that lie.

use landfall_core::ids::{ImageDigest, RepoName};
use serde_json::{Value, json};
use wiremock::matchers::{method, path, query_param, query_param_is_missing};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::{Endpoints, FetchError, Fetcher, MANIFEST_LIMIT, RateLimitReset};
use super::{MAX_LISTED_TAGS, MAX_PAGES};
use crate::test_support::{REGISTRY_TOKEN, fetcher, mount_token};

const REFS: &str = "/repos/example/app/git/matching-refs/tags";
const TAGS: &str = "/v2/example/app/tags/list";
const IMAGE: &str = "example/app";

/// What a server answers, and whether an error is what that should give.
type HostileCase = (ResponseTemplate, fn(&FetchError) -> bool);

fn repo() -> RepoName {
    "example/app".parse().unwrap()
}

fn object(n: u32) -> String {
    format!("{n:040x}")
}

fn tag_ref(name: &str, n: u32) -> Value {
    json!({
        "ref": format!("refs/tags/{name}"),
        "node_id": "x",
        "url": "https://api.github.com/x",
        "object": { "sha": object(n), "type": "tag", "url": "https://api.github.com/y" },
    })
}

fn digest_hex(c: char) -> String {
    c.to_string().repeat(64)
}

fn digest(c: char) -> ImageDigest {
    format!("sha256:{}", digest_hex(c)).parse().unwrap()
}

fn referrer(c: char) -> String {
    format!("sha256-{}", digest_hex(c))
}

async fn servers() -> (MockServer, MockServer) {
    (MockServer::start().await, MockServer::start().await)
}

/// The registry serves `tags` as one page, with `link` as its `Link` header.
fn tags_page(tags: &[String], link: Option<&str>) -> ResponseTemplate {
    let mut response =
        ResponseTemplate::new(200).set_body_json(json!({ "name": IMAGE, "tags": tags }));
    if let Some(link) = link {
        response = response.insert_header("link", link);
    }
    response
}

async fn registry_requests(server: &MockServer, of: &str) -> Vec<wiremock::Request> {
    server
        .received_requests()
        .await
        .unwrap()
        .into_iter()
        .filter(|r| r.url.path() == of)
        .collect()
}

#[tokio::test]
async fn release_tags_come_from_every_page() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .and(query_param("per_page", "100"))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([tag_ref("v1.0.0", 1), tag_ref("v1.1.0", 2)]))
                .insert_header("link", r#"<https://x.test/next?page=2>; rel="next""#),
        )
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([tag_ref("v2.0.0", 3)])))
        .mount(&github)
        .await;

    let tags = fetcher(&github, &registry)
        .list_release_tags(&repo())
        .await
        .unwrap();
    let names: Vec<(&str, &str)> = tags
        .iter()
        .map(|t| (t.tag.as_ref(), t.object.as_str()))
        .collect();
    assert_eq!(
        names,
        [
            ("v1.0.0", object(1).as_str()),
            ("v1.1.0", object(2).as_str()),
            ("v2.0.0", object(3).as_str()),
        ]
    );
}

#[tokio::test]
async fn a_next_link_is_only_a_signal_and_never_followed() {
    let (github, registry) = servers().await;
    let elsewhere = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .and(query_param("page", "1"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([tag_ref("v1.0.0", 1)]))
                .insert_header(
                    "link",
                    format!(r#"<{}/stolen?page=2>; rel="next""#, elsewhere.uri()),
                ),
        )
        .mount(&github)
        .await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .and(query_param("page", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([])))
        .mount(&github)
        .await;

    let fetcher = fetcher(&github, &registry)
        .with_github_token("a-token")
        .unwrap();
    let tags = fetcher.list_release_tags(&repo()).await.unwrap();
    assert_eq!(tags.len(), 1);
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_list_of_release_tags_that_never_ends_is_refused() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!([tag_ref("v1.0.0", 1)]))
                .insert_header("link", r#"<https://x.test/next>; rel="next""#),
        )
        .mount(&github)
        .await;

    let error = fetcher(&github, &registry)
        .list_release_tags(&repo())
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::ListCap { what: "pages", .. }),
        "{error:?}"
    );
    assert_eq!(
        github.received_requests().await.unwrap().len(),
        MAX_PAGES,
        "it stops at the cap"
    );
    assert!(!error.is_unavailable(), "{error:?}");
}

#[tokio::test]
async fn too_many_release_tags_are_an_error_not_a_shorter_list() {
    let (github, registry) = servers().await;
    let page: Vec<Value> = (0..=MAX_LISTED_TAGS)
        .map(|n| tag_ref(&format!("t{n}"), 1))
        .collect();
    Mock::given(method("GET"))
        .and(path(REFS))
        .respond_with(ResponseTemplate::new(200).set_body_json(page))
        .mount(&github)
        .await;

    let error = fetcher(&github, &registry)
        .list_release_tags(&repo())
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::ListCap { what: "tags", limit, .. } if limit == MAX_LISTED_TAGS),
        "{error:?}"
    );
}

#[tokio::test]
async fn hostile_release_tag_lists_are_refused() {
    let cases: Vec<HostileCase> = vec![
        (
            ResponseTemplate::new(200).set_body_string("not json"),
            |e| matches!(e, FetchError::Json { .. }),
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "not": "a list" })),
            |e| matches!(e, FetchError::Json { .. }),
        ),
        (
            ResponseTemplate::new(200).set_body_json(json!([{
                "ref": "refs/tags/v1.0.0",
                "object": { "sha": "../../etc/passwd", "type": "tag" },
            }])),
            |e| matches!(e, FetchError::Malformed { .. }),
        ),
        (
            ResponseTemplate::new(200).set_body_string("x".repeat(MANIFEST_LIMIT + 1)),
            |e| matches!(e, FetchError::TooLarge { .. }),
        ),
    ];
    for (response, expected) in cases {
        let (github, registry) = servers().await;
        Mock::given(method("GET"))
            .and(path(REFS))
            .respond_with(response)
            .mount(&github)
            .await;
        let error = fetcher(&github, &registry)
            .list_release_tags(&repo())
            .await
            .unwrap_err();
        assert!(expected(&error), "{error:?}");
    }
}

#[tokio::test]
async fn refs_that_are_not_release_tags_are_skipped() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!([
            tag_ref("v1.0.0", 1),
            tag_ref("bad\u{1b}[31mname", 2),
            {
                "ref": "refs/heads/main",
                "object": { "sha": object(3), "type": "commit" },
            },
        ])))
        .mount(&github)
        .await;

    let tags = fetcher(&github, &registry)
        .list_release_tags(&repo())
        .await
        .unwrap();
    assert_eq!(tags.len(), 1);
    assert_eq!(tags[0].tag.as_ref(), "v1.0.0");
}

#[tokio::test]
async fn a_rate_limit_on_the_tag_list_says_when_it_lifts() {
    let (github, registry) = servers().await;
    Mock::given(method("GET"))
        .and(path(REFS))
        .respond_with(
            ResponseTemplate::new(403)
                .insert_header("x-ratelimit-remaining", "0")
                .insert_header("x-ratelimit-reset", "1800000000"),
        )
        .mount(&github)
        .await;

    let error = fetcher(&github, &registry)
        .list_release_tags(&repo())
        .await
        .unwrap_err();
    match error {
        FetchError::RateLimited {
            reset: RateLimitReset::At(at),
            ..
        } => assert_eq!(at.as_second(), 1_800_000_000),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn referrer_tags_are_kept_and_everything_else_is_not() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    let tags = [
        "1.2.3".to_owned(),
        "latest".to_owned(),
        referrer('a'),
        format!("{}.sig", referrer('b')),
        format!("{}.att", referrer('b')),
        format!("sha256-{}", "A".repeat(64)),
        format!("sha256-{}", "a".repeat(63)),
        format!("sha512-{}", "a".repeat(64)),
        referrer('c'),
        referrer('a'),
    ];
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(tags_page(&tags, None))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, [digest('a'), digest('c')]);
}

#[tokio::test]
async fn referrer_tags_come_from_every_page_by_the_registrys_cursor() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param_is_missing("last"))
        .respond_with(tags_page(
            &[referrer('a')],
            Some(r#"</v2/example/app/tags/list?last=cursor-1&n=1000>; rel="next""#),
        ))
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param("last", "cursor-1"))
        .respond_with(tags_page(&[referrer('b')], None))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, [digest('a'), digest('b')]);
}

#[tokio::test]
async fn the_registry_is_asked_with_its_own_token_and_never_the_github_one() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(tags_page(&[referrer('a')], None))
        .mount(&registry)
        .await;

    let fetcher = fetcher(&github, &registry)
        .with_github_token("github-secret")
        .unwrap();
    fetcher.list_referrer_digests(IMAGE).await.unwrap();

    let requests = registry.received_requests().await.unwrap();
    assert!(!requests.is_empty());
    for request in &requests {
        let sent = request
            .headers
            .get("authorization")
            .map(|v| v.to_str().unwrap().to_owned());
        assert_ne!(sent.as_deref(), Some("Bearer github-secret"));
    }
    let listed = registry_requests(&registry, TAGS).await;
    assert_eq!(
        listed[0].headers.get("authorization").unwrap(),
        format!("Bearer {REGISTRY_TOKEN}").as_str()
    );
}

#[tokio::test]
async fn a_next_link_to_another_host_only_gives_its_cursor() {
    let (github, registry) = servers().await;
    let elsewhere = MockServer::start().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param_is_missing("last"))
        .respond_with(tags_page(
            &[referrer('a')],
            Some(&format!(
                r#"<{}/v2/stolen/tags/list?last=next-one>; rel="next""#,
                elsewhere.uri()
            )),
        ))
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param("last", "next-one"))
        .respond_with(tags_page(&[referrer('b')], None))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, [digest('a'), digest('b')]);
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn a_next_link_without_a_cursor_goes_on_from_the_last_tag() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param_is_missing("last"))
        .respond_with(tags_page(
            &["1.0.0".to_owned()],
            Some(r#"</somewhere>; rel="next""#),
        ))
        .mount(&registry)
        .await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .and(query_param("last", "1.0.0"))
        .respond_with(tags_page(&[referrer('b')], None))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, [digest('b')]);
}

#[tokio::test]
async fn a_cursor_that_comes_round_again_is_refused() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(tags_page(
            &[referrer('a')],
            Some(r#"</v2/example/app/tags/list?last=same>; rel="next""#),
        ))
        .mount(&registry)
        .await;

    let error = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Malformed { .. }), "{error:?}");
    // The first page, and the second that gives the same cursor again.
    assert_eq!(registry_requests(&registry, TAGS).await.len(), 2);
}

#[tokio::test]
async fn a_tag_list_that_never_ends_is_refused() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    // Every page has a next, and each is empty of tags that could give the
    // next cursor except through a request's own counter.
    let counter = std::sync::atomic::AtomicUsize::new(0);
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(move |_: &wiremock::Request| {
            let n = counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tags_page(
                &[format!("t{n}")],
                Some(&format!(r#"</x?last=c{n}>; rel="next""#)),
            )
        })
        .mount(&registry)
        .await;

    let error = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::ListCap { what: "pages", .. }),
        "{error:?}"
    );
    assert_eq!(registry_requests(&registry, TAGS).await.len(), MAX_PAGES);
}

#[tokio::test]
async fn too_many_tags_of_any_kind_are_an_error_not_a_shorter_list() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    let tags: Vec<String> = (0..=MAX_LISTED_TAGS).map(|n| format!("t{n}")).collect();
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(tags_page(&tags, None))
        .mount(&registry)
        .await;

    let error = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap_err();
    assert!(
        matches!(error, FetchError::ListCap { what: "tags", limit, .. } if limit == MAX_LISTED_TAGS),
        "{error:?}"
    );
}

#[tokio::test]
async fn the_most_tags_allowed_are_still_read() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    let mut tags: Vec<String> = (1..MAX_LISTED_TAGS).map(|n| format!("t{n}")).collect();
    tags.push(referrer('a'));
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(tags_page(&tags, None))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, [digest('a')]);
}

#[tokio::test]
async fn hostile_tag_lists_are_refused() {
    let cases: Vec<HostileCase> = vec![
        (ResponseTemplate::new(200).set_body_string("{"), |e| {
            matches!(e, FetchError::Json { .. })
        }),
        (
            ResponseTemplate::new(200).set_body_json(json!({ "tags": [1, 2, 3] })),
            |e| matches!(e, FetchError::Json { .. }),
        ),
        (
            ResponseTemplate::new(200).set_body_string("x".repeat(MANIFEST_LIMIT + 1)),
            |e| matches!(e, FetchError::TooLarge { .. }),
        ),
        (ResponseTemplate::new(500), |e| {
            matches!(e, FetchError::Status { status: 500, .. })
        }),
        (ResponseTemplate::new(404), |e| {
            matches!(e, FetchError::NotFound { .. })
        }),
    ];
    for (response, expected) in cases {
        let (github, registry) = servers().await;
        mount_token(&registry).await;
        Mock::given(method("GET"))
            .and(path(TAGS))
            .respond_with(response)
            .mount(&registry)
            .await;
        let error = fetcher(&github, &registry)
            .list_referrer_digests(IMAGE)
            .await
            .unwrap_err();
        assert!(expected(&error), "{error:?}");
    }
}

#[tokio::test]
async fn an_image_with_no_tags_lists_nothing() {
    let (github, registry) = servers().await;
    mount_token(&registry).await;
    Mock::given(method("GET"))
        .and(path(TAGS))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({ "tags": null })))
        .mount(&registry)
        .await;

    let found = fetcher(&github, &registry)
        .list_referrer_digests(IMAGE)
        .await
        .unwrap();
    assert_eq!(found, []);
}

#[tokio::test]
async fn an_invalid_image_name_is_refused_before_any_request() {
    let (github, registry) = servers().await;
    let error = fetcher(&github, &registry)
        .list_referrer_digests("../etc/passwd")
        .await
        .unwrap_err();
    assert!(matches!(error, FetchError::Image(_)), "{error:?}");
    assert!(registry.received_requests().await.unwrap().is_empty());
}

/// The attestation fixture's project on GHCR: its release digest has a referrer
/// tag, however many pages the list takes.
#[tokio::test]
#[ignore = "network: runs nightly in advisories.yml"]
async fn live_referrer_tags_of_a_real_image() {
    let fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    let digests = fetcher
        .list_referrer_digests("dani-garcia/vaultwarden")
        .await
        .unwrap();
    let digest: ImageDigest =
        "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055"
            .parse()
            .unwrap();
    assert!(digests.contains(&digest), "{} digests", digests.len());
}

/// The same project's release tags from the GitHub API.
#[tokio::test]
#[ignore = "network: runs nightly in advisories.yml"]
async fn live_release_tags_of_a_real_repository() {
    let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
    if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
        fetcher = fetcher.with_github_token(&token).unwrap();
    }
    let tags = fetcher
        .list_release_tags(&"dani-garcia/vaultwarden".parse().unwrap())
        .await
        .unwrap();
    assert!(
        tags.iter().any(|t| t.tag.as_ref() == "1.37.4"),
        "{} tags",
        tags.len()
    );
}
