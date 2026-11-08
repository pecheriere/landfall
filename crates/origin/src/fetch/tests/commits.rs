//! GitHub's comparison of two commits, a page at a time, against a mock GitHub.

use landfall_core::ids::CommitSha;
use serde_json::{Value, json};
use wiremock::matchers::{header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::super::{
    COMMIT_SUMMARY_CHARS, COMPARE_PAGE_LIMIT, ComparePage, CompareStatus, FetchError, ListedCommit,
    compare_url,
};
use super::{GITHUB_TOKEN, repo};
use crate::test_support::fetcher;

const BASE: &str = "1111111111111111111111111111111111111111";
const HEAD: &str = "2222222222222222222222222222222222222222";

fn sha(text: &str) -> CommitSha {
    text.parse().unwrap()
}

fn compare_path() -> String {
    format!("/repos/example/app/compare/{BASE}...{HEAD}")
}

/// One commit as GitHub's compare lists it, with the fields this doesn't read.
fn commit_json(sha: &str, message: &str, login: Option<&str>, parents: &[&str]) -> Value {
    let person = |login: &str| {
        json!({
            "login": login,
            "id": 1,
            "node_id": "MDQ6VXNlcjE=",
            "avatar_url": "https://avatars.githubusercontent.com/u/1?v=4",
            "html_url": format!("https://github.com/{login}"),
            "type": "User",
            "site_admin": false
        })
    };
    json!({
        "sha": sha,
        "node_id": "C_kwDOAAAAAdoAKDEx",
        "commit": {
            "author": { "name": "Example Dev", "email": "dev@example.com", "date": "2026-11-01T10:00:00Z" },
            "committer": { "name": "GitHub", "email": "noreply@github.com", "date": "2026-11-01T10:00:00Z" },
            "message": message,
            "tree": { "sha": "3333333333333333333333333333333333333333", "url": "https://api.github.com/repos/example/app/git/trees/3333333333333333333333333333333333333333" },
            "url": format!("https://api.github.com/repos/example/app/git/commits/{sha}"),
            "comment_count": 0,
            "verification": { "verified": false, "reason": "unsigned", "signature": null, "payload": null }
        },
        "url": format!("https://api.github.com/repos/example/app/commits/{sha}"),
        "html_url": format!("https://github.com/example/app/commit/{sha}"),
        "comments_url": format!("https://api.github.com/repos/example/app/commits/{sha}/comments"),
        "author": login.map(person),
        "committer": person("web-flow"),
        "parents": parents.iter().map(|p| json!({
            "sha": p,
            "url": format!("https://api.github.com/repos/example/app/commits/{p}"),
            "html_url": format!("https://github.com/example/app/commit/{p}")
        })).collect::<Vec<_>>()
    })
}

/// A compare body as GitHub serves it, `files` included.
fn compare_body(status: &str, total: u64, commits: &[Value]) -> Value {
    json!({
        "url": format!("https://api.github.com/repos/example/app/compare/{BASE}...{HEAD}"),
        "html_url": format!("https://github.com/example/app/compare/{BASE}...{HEAD}"),
        "permalink_url": format!("https://github.com/example/app/compare/example:{BASE}...example:{HEAD}"),
        "diff_url": format!("https://github.com/example/app/compare/{BASE}...{HEAD}.diff"),
        "patch_url": format!("https://github.com/example/app/compare/{BASE}...{HEAD}.patch"),
        "base_commit": commit_json(BASE, "Release 1.2.0", Some("example-dev"), &[]),
        "merge_base_commit": commit_json(BASE, "Release 1.2.0", Some("example-dev"), &[]),
        "status": status,
        "ahead_by": total,
        "behind_by": 0,
        "total_commits": total,
        "commits": commits,
        "files": [{
            "sha": "4444444444444444444444444444444444444444",
            "filename": "src/main.rs",
            "status": "modified",
            "additions": 1,
            "deletions": 1,
            "changes": 2,
            "blob_url": "https://github.com/example/app/blob/2222222222222222222222222222222222222222/src/main.rs",
            "raw_url": "https://github.com/example/app/raw/2222222222222222222222222222222222222222/src/main.rs",
            "contents_url": "https://api.github.com/repos/example/app/contents/src/main.rs?ref=2222222222222222222222222222222222222222",
            "patch": "@@ -1 +1 @@\n-fn main() {}\n+fn main() { run() }"
        }]
    })
}

async fn mount_page(server: &MockServer, page: u32, response: ResponseTemplate) {
    Mock::given(method("GET"))
        .and(path(compare_path()))
        .and(query_param("per_page", "100"))
        .and(query_param("page", page.to_string()))
        .respond_with(response)
        .mount(server)
        .await;
}

fn ok(body: &Value) -> ResponseTemplate {
    ResponseTemplate::new(200)
        .insert_header("x-ratelimit-remaining", "4321")
        .set_body_json(body)
}

async fn page(server: &MockServer, page: u32) -> Result<ComparePage, FetchError> {
    let registry = MockServer::start().await;
    fetcher(server, &registry)
        .compare_page(&repo(), &sha(BASE), &sha(HEAD), page)
        .await
}

fn listed(page: Result<ComparePage, FetchError>) -> (CompareStatus, u64, Vec<ListedCommit>) {
    match page {
        Ok(ComparePage::Listed {
            status,
            total,
            commits,
            ..
        }) => (status, total, commits),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn compare_page_is_parsed() {
    let github = MockServer::start().await;
    let commit = "5555555555555555555555555555555555555555";
    let body = compare_body(
        "ahead",
        1,
        &[commit_json(
            commit,
            "Fix the parser\n\nIt read one byte too many.",
            Some("example-dev"),
            &[BASE],
        )],
    );
    mount_page(&github, 2, ok(&body)).await;

    let answer = page(&github, 2).await.unwrap();
    assert_eq!(
        answer,
        ComparePage::Listed {
            status: CompareStatus::Ahead,
            total: 1,
            commits: vec![ListedCommit {
                sha: sha(commit),
                summary: "\"Fix the parser\"".to_owned(),
                author: Some("example-dev".to_owned()),
            }],
            rate_remaining: Some(4321),
        }
    );
}

#[tokio::test]
async fn identical_behind_and_diverged_are_read() {
    let github = MockServer::start().await;
    for (n, status) in ["identical", "behind", "diverged"].iter().enumerate() {
        let page_number = u32::try_from(n + 1).unwrap();
        mount_page(&github, page_number, ok(&compare_body(status, 0, &[]))).await;
    }
    let statuses = [
        CompareStatus::Identical,
        CompareStatus::Behind,
        CompareStatus::Diverged,
    ];
    for (n, expected) in statuses.into_iter().enumerate() {
        let (status, total, commits) = listed(page(&github, u32::try_from(n + 1).unwrap()).await);
        assert_eq!((status, total, commits.len()), (expected, 0, 0));
    }
}

#[tokio::test]
async fn files_are_skipped() {
    let github = MockServer::start().await;
    let mut body = compare_body("ahead", 0, &[]);
    // A patch of a few megabytes, in a shape nothing here reads: it is skipped
    // as it parses, and nothing of it is kept.
    body["files"][0]["patch"] = Value::String("+x\n".repeat(1_000_000));
    body["files"][0]["unexpected"] = json!({ "nested": [1, 2, { "deeper": null }] });
    mount_page(&github, 1, ok(&body)).await;

    let (status, total, commits) = listed(page(&github, 1).await);
    assert_eq!((status, total), (CompareStatus::Ahead, 0));
    assert_eq!(commits, []);
}

#[tokio::test]
async fn summary_is_quoted_and_cut() {
    let github = MockServer::start().await;
    let first_line = format!("\u{1b}[31m\u{202e}{}\r", "x".repeat(500));
    let message = format!("{first_line}\nrm -rf / on the second line");
    let commit = "6666666666666666666666666666666666666666";
    let body = compare_body(
        "ahead",
        1,
        &[commit_json(commit, &message, Some("example-dev"), &[BASE])],
    );
    mount_page(&github, 1, ok(&body)).await;

    let (_, _, commits) = listed(page(&github, 1).await);
    let summary = &commits[0].summary;
    let expected: String = first_line
        .trim_end_matches('\r')
        .chars()
        .take(COMMIT_SUMMARY_CHARS)
        .collect();
    assert_eq!(*summary, format!("{expected:?}..."));
    assert!(summary.starts_with("\"\\u{1b}[31m\\u{202e}x"), "{summary}");
    assert!(
        !summary.chars().any(|c| c.is_control() || c == '\u{202e}'),
        "{summary}"
    );
    assert!(!summary.contains("second line"), "{summary}");
}

#[tokio::test]
async fn odd_login_is_dropped() {
    let github = MockServer::start().await;
    let shas: Vec<String> = (0..5).map(|n| format!("{n}").repeat(40)).collect();
    let too_long = "a".repeat(40);
    let logins = [
        Some("evil\u{1b}[2J"),
        Some("has space"),
        Some(too_long.as_str()),
        Some(""),
        None,
    ];
    let commits: Vec<Value> = shas
        .iter()
        .zip(logins)
        .map(|(sha, login)| commit_json(sha, "A change", login, &[BASE]))
        .collect();
    mount_page(&github, 1, ok(&compare_body("ahead", 5, &commits))).await;

    let (_, _, commits) = listed(page(&github, 1).await);
    assert_eq!(commits.len(), 5);
    assert!(commits.iter().all(|c| c.author.is_none()), "{commits:?}");

    // The longest login GitHub allows is kept.
    let github = MockServer::start().await;
    let longest = format!("A-{}", "9".repeat(37));
    let body = compare_body(
        "ahead",
        1,
        &[commit_json(&shas[0], "A change", Some(&longest), &[BASE])],
    );
    mount_page(&github, 1, ok(&body)).await;
    let (_, _, commits) = listed(page(&github, 1).await);
    assert_eq!(commits[0].author.as_deref(), Some(longest.as_str()));
}

/// A comparison across a merged pull request, in GitHub's order (topological, oldest
/// first): the branch's two commits, one on main, and the merge with two parents.
#[tokio::test]
async fn merge_commits_are_parsed_in_order() {
    let github = MockServer::start().await;
    let branch_1 = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1";
    let main_1 = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2";
    let branch_2 = "c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3c3";
    let body = compare_body(
        "ahead",
        4,
        &[
            commit_json(
                branch_1,
                "Add the feature's parser",
                Some("contributor-1"),
                &[BASE],
            ),
            commit_json(main_1, "Bump a dependency", Some("dependabot"), &[BASE]),
            commit_json(
                branch_2,
                "Test the parser\n\nCovers the edge cases.",
                Some("contributor-1"),
                &[branch_1],
            ),
            commit_json(
                HEAD,
                "Merge pull request #12 from example/feature\n\nAdd the feature",
                Some("example-dev"),
                &[main_1, branch_2],
            ),
        ],
    );
    mount_page(&github, 1, ok(&body)).await;

    let (status, total, commits) = listed(page(&github, 1).await);
    assert_eq!((status, total), (CompareStatus::Ahead, 4));
    let read: Vec<(&str, &str, Option<&str>)> = commits
        .iter()
        .map(|c| (c.sha.as_ref(), c.summary.as_str(), c.author.as_deref()))
        .collect();
    assert_eq!(
        read,
        [
            (
                branch_1,
                "\"Add the feature's parser\"",
                Some("contributor-1")
            ),
            (main_1, "\"Bump a dependency\"", Some("dependabot")),
            (branch_2, "\"Test the parser\"", Some("contributor-1")),
            (
                HEAD,
                "\"Merge pull request #12 from example/feature\"",
                Some("example-dev")
            ),
        ]
    );
}

#[tokio::test]
async fn over_the_cap_is_too_large_with_a_link() {
    let github = MockServer::start().await;
    let mut body = compare_body("ahead", 0, &[]).to_string().into_bytes();
    // Pad inside the JSON, so that only the size can refuse it.
    let padding = vec![b' '; 9 * 1024 * 1024];
    body.splice(1..1, padding);
    assert!(body.len() > COMPARE_PAGE_LIMIT);
    mount_page(
        &github,
        1,
        ResponseTemplate::new(200)
            .insert_header("x-ratelimit-remaining", "4000")
            .set_body_raw(body, "application/json"),
    )
    .await;

    let answer = page(&github, 1).await.unwrap();
    assert!(matches!(answer, ComparePage::TooLarge { .. }), "{answer:?}");
    assert_eq!(
        compare_url(&repo(), &sha(BASE), &sha(HEAD)),
        format!("https://github.com/example/app/compare/{BASE}...{HEAD}")
    );
}

#[tokio::test]
async fn a_422_is_too_large() {
    let github = MockServer::start().await;
    mount_page(
        &github,
        1,
        ResponseTemplate::new(422).set_body_json(json!({
            "message": "Server Error: Sorry, this diff is taking too long to generate.",
            "errors": [{ "resource": "Commit", "field": "diff", "code": "not_available" }],
        })),
    )
    .await;

    let answer = page(&github, 1).await.unwrap();
    assert!(matches!(answer, ComparePage::TooLarge { .. }), "{answer:?}");
}

#[tokio::test]
async fn unknown_status_is_an_error() {
    let github = MockServer::start().await;
    mount_page(&github, 1, ok(&compare_body("sideways", 0, &[]))).await;
    let error = page(&github, 1).await.unwrap_err();
    assert!(matches!(error, FetchError::Malformed { .. }), "{error:?}");
    assert!(error.to_string().contains("\"sideways\""), "{error}");
}

#[tokio::test]
async fn a_bad_commit_id_or_too_many_commits_is_an_error() {
    let github = MockServer::start().await;
    let bad = compare_body(
        "ahead",
        1,
        &[commit_json("not-a-sha", "A change", None, &[BASE])],
    );
    mount_page(&github, 1, ok(&bad)).await;
    let error = page(&github, 1).await.unwrap_err();
    assert!(matches!(error, FetchError::Malformed { .. }), "{error:?}");

    let commits: Vec<Value> = (0..101)
        .map(|n| commit_json(&format!("{n:040x}"), "A change", None, &[BASE]))
        .collect();
    mount_page(&github, 2, ok(&compare_body("ahead", 101, &commits))).await;
    let error = page(&github, 2).await.unwrap_err();
    assert!(matches!(error, FetchError::Malformed { .. }), "{error:?}");
}

#[tokio::test]
async fn a_rate_limit_is_an_error_as_elsewhere() {
    let github = MockServer::start().await;
    mount_page(
        &github,
        1,
        ResponseTemplate::new(403).insert_header("x-ratelimit-remaining", "0"),
    )
    .await;
    let error = page(&github, 1).await.unwrap_err();
    assert!(
        matches!(error, FetchError::RateLimited { status: 403, .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn token_goes_with_the_request() {
    let (github, registry) = (MockServer::start().await, MockServer::start().await);
    Mock::given(method("GET"))
        .and(path(compare_path()))
        .and(header("authorization", format!("Bearer {GITHUB_TOKEN}")))
        .and(header("x-github-api-version", "2022-11-28"))
        .respond_with(ok(&compare_body("identical", 0, &[])))
        .expect(1)
        .mount(&github)
        .await;

    let plain = fetcher(&github, &registry);
    assert!(!plain.has_github_token());
    let tokened = plain.with_github_token(GITHUB_TOKEN).unwrap();
    assert!(tokened.has_github_token());
    let (status, _, _) = listed(
        tokened
            .compare_page(&repo(), &sha(BASE), &sha(HEAD), 1)
            .await,
    );
    assert_eq!(status, CompareStatus::Identical);
}
