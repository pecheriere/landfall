//! A deployment's releases and the story of one: `listReleases` and `getRelease`, and the
//! latest release in a deployment's summary.

use axum::http::{Method, StatusCode};
use landfall_core::ids::{CommitSha, DeploymentId, HostId, ReleaseTag, RepoName};
use landfall_origin::fetch::ListedCommit;
use semver::Version;
use serde_json::{Value, json};

use super::deployments::open_request;
use super::{
    Answer, BETA_VIEWER, Caller, FLEET_VIEWER, OUTSIDER, World, holder, verified, world_digest,
};
use crate::api::query::{Cursor, CursorList};
use crate::store::{NewRange, RangeState, ReleaseDecision, Seen};

const NOW: i64 = 1_800_000_000;
const PROD: &str = "/api/v1/deployments/app/prod/releases";

fn sha(fill: char) -> CommitSha {
    fill.to_string().repeat(40).parse().unwrap()
}

fn viewer() -> String {
    holder(&["view"])
}

async fn get(world: &World, path: &str) -> Answer {
    world
        .send(Method::GET, path, Caller::Token(&viewer()), None)
        .await
}

/// The story of `tag` on `app/prod`, as a viewer reads it.
async fn story(world: &World, tag: &str) -> Value {
    let answer = get(world, &format!("{PROD}/{tag}")).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    answer.json()
}

/// `n` commits, newest first, the newest numbered `n`.
fn commits(n: usize) -> Vec<ListedCommit> {
    (1..=n)
        .rev()
        .map(|i| ListedCommit {
            sha: format!("{i:040x}").parse().unwrap(),
            summary: format!("\"change {i}\""),
            author: Some("octocat".to_owned()),
        })
        .collect()
}

/// Stores the range of `example/app` from `base`'s commit to `head`'s, as the watcher does.
async fn range(
    world: &World,
    (base, head): (char, char),
    state: RangeState,
    total: Option<u64>,
    listed: &[ListedCommit],
) {
    let repo: RepoName = "example/app".parse().unwrap();
    let new = NewRange {
        state,
        total,
        commits: listed,
    };
    world
        .store
        .record_commit_range(&repo, &sha(base), &sha(head), &new)
        .await
        .unwrap();
}

/// A deploy of `tag` at `fill`'s digest on `deployment`, finished with `outcome`, as a host's
/// report leaves one.
async fn finished_deploy(
    world: &World,
    deployment: &str,
    (tag, fill): (&str, char),
    outcome: &str,
) {
    sqlx::query(
        "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, outcome, reason,
                              created_at, finished_at)
         VALUES (?, 'home-1', ?, ?, ?, 'finished', ?, '\"check failed\"', ?, ?)",
    )
    .bind(deployment)
    .bind(tag)
    .bind(world_digest(fill).as_ref())
    .bind(sha(fill).as_ref())
    .bind(outcome)
    .bind(NOW - 60)
    .bind(NOW - 30)
    .execute(world.store.pool())
    .await
    .unwrap();
}

/// Records `tag` on `app/prod` as the watcher does when verification refuses it.
async fn refused_by_verification(world: &World, tag: &str) {
    let seen = Seen {
        tag_object: "object",
        config_hash: world.state.config().hash(),
        commit: None,
        digest: None,
        refused: true,
        detail: json!({ "tag": tag, "refused": "\"no attestation\"" }),
        origin: json!({ "tag": tag, "refused": "\"no attestation\"" }),
    };
    world
        .store
        .record_release(
            (
                &"app/prod".parse().unwrap(),
                &"home-1".parse().unwrap(),
                &tag.parse().unwrap(),
            ),
            ReleaseDecision::Refused,
            "no attestation",
            Some(&seen),
        )
        .await
        .unwrap();
}

#[tokio::test]
async fn story_has_origin_commits_requests_and_deploys() {
    let world = World::seed().await;
    range(&world, ('1', '3'), RangeState::Listed, Some(2), &commits(2)).await;
    finished_deploy(&world, "app/prod", ("v1.3.0", '3'), "nothing_changed").await;
    let request = open_request(&world.store, "app/prod", "v1.3.0", '3').await;
    let body = story(&world, "v1.3.0").await;
    let release = &body["release"];
    assert_eq!(release["tag"], "v1.3.0");
    assert_eq!(release["status"], "awaiting_approval");
    assert_eq!(release["decision"], "needs_approval");
    assert_eq!(release["first_seen_at"], NOW);
    assert_eq!(release["seen_at"], NOW);
    assert_eq!(body["next"]["kind"], "approve");
    let origin = &body["origin"];
    assert_eq!(origin["commit"], sha('3').as_ref());
    assert_eq!(origin["digest"], world_digest('3').as_ref());
    assert_eq!(origin["signer"], Value::Null);
    assert_eq!(origin["rekor_log_index"], 42);
    assert!(origin["san"].as_str().unwrap().contains("refs/tags/v1.3.0"));
    let listed = &body["commits"];
    assert_eq!(listed["state"], "listed");
    assert_eq!(listed["base"], "v1.1.0");
    assert_eq!(listed["total"], 2);
    let shas: Vec<&str> = listed["commits"]
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["sha"].as_str().unwrap())
        .collect();
    assert_eq!(shas, [format!("{:040x}", 2), format!("{:040x}", 1)]);
    assert_eq!(listed["commits"][0]["summary"], "\"change 2\"");
    assert_eq!(listed["commits"][0]["author"], "octocat");
    let requests = body["requests"].as_array().unwrap();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0]["id"], request);
    assert_eq!(requests[0]["state"], "awaiting_approval");
    assert_eq!(requests[0]["requested_by"], "viewer");
    assert_eq!(requests[0]["approved_by"], Value::Null);
    let deploys = body["deploys"].as_array().unwrap();
    assert_eq!(deploys.len(), 1);
    assert_eq!(deploys[0]["state"], "finished");
    assert_eq!(deploys[0]["outcome"], "nothing_changed");
    assert_eq!(deploys[0]["finished_at"], NOW - 30);
}

#[tokio::test]
async fn commits_say_github_and_unverified() {
    let world = World::seed().await;
    for tag in ["v1.1.0", "v1.3.0"] {
        let body = story(&world, tag).await;
        assert_eq!(body["commits"]["source"], "github", "{tag}");
        assert_eq!(body["commits"]["verified"], false, "{tag}");
    }
}

#[tokio::test]
async fn first_release_says_first() {
    let world = World::seed().await;
    let commits = &story(&world, "v1.1.0").await["commits"];
    assert_eq!(commits["state"], "first");
    assert_eq!(commits["base"], Value::Null);
    assert_eq!(commits["compare_url"], Value::Null);
    assert_eq!(commits["total"], Value::Null);
    assert_eq!(commits["commits"], json!([]));
}

#[tokio::test]
async fn a_range_not_fetched_is_unknown_not_empty() {
    let world = World::seed().await;
    let compare = format!(
        "https://github.com/example/app/compare/{}...{}",
        sha('1'),
        sha('3')
    );
    // Recorded after commits began to be compared, and not fetched yet.
    let not_yet = &story(&world, "v1.3.0").await["commits"];
    assert_eq!(not_yet["state"], "not_yet");
    assert_eq!(not_yet["base"], "v1.1.0");
    assert_eq!(not_yet["compare_url"], compare.as_str());
    // Recorded before: never fetched.
    sqlx::query("UPDATE releases SET first_seen_at = 0 WHERE tag = 'v1.3.0'")
        .execute(world.store.pool())
        .await
        .unwrap();
    let not_recorded = &story(&world, "v1.3.0").await["commits"];
    assert_eq!(not_recorded["state"], "not_recorded");
    assert_eq!(not_recorded["compare_url"], compare.as_str());
    let mut states = vec![not_yet.clone(), not_recorded.clone()];
    for state in [RangeState::Unavailable, RangeState::TooLarge] {
        range(&world, ('1', '3'), state, None, &[]).await;
        states.push(story(&world, "v1.3.0").await["commits"].clone());
    }
    for unknown in &states {
        assert_eq!(unknown["commits"], json!([]), "{unknown}");
        assert_eq!(unknown["total"], Value::Null, "{unknown}");
    }
    let names: Vec<&str> = states
        .iter()
        .map(|s| s["state"].as_str().unwrap())
        .collect();
    assert_eq!(
        names,
        ["not_yet", "not_recorded", "unavailable", "too_large"]
    );
    // An empty list is a list, and says so.
    range(&world, ('1', '3'), RangeState::Listed, Some(0), &[]).await;
    let empty = &story(&world, "v1.3.0").await["commits"];
    assert_eq!(empty["state"], "listed");
    assert_eq!(empty["total"], 0);
    assert_eq!(empty["commits"], json!([]));
}

#[tokio::test]
async fn base_not_found_adds_a_reason() {
    let world = World::seed().await;
    range(&world, ('1', '3'), RangeState::BaseNotFound, None, &[]).await;
    let body = story(&world, "v1.3.0").await;
    assert_eq!(body["commits"]["state"], "base_not_found");
    assert_eq!(body["commits"]["commits"], json!([]));
    let reasons = body["reasons"].to_string();
    assert!(reasons.contains("v1.1.0"), "{reasons}");
    assert!(reasons.contains("isn't an ancestor"), "{reasons}");
    assert!(reasons.contains("rewritten"), "{reasons}");
}

#[tokio::test]
async fn too_large_has_no_commits_and_links_to_github() {
    let world = World::seed().await;
    range(&world, ('1', '3'), RangeState::TooLarge, None, &[]).await;
    let body = story(&world, "v1.3.0").await;
    let compare = format!(
        "https://github.com/example/app/compare/{}...{}",
        sha('1'),
        sha('3')
    );
    assert_eq!(body["commits"]["state"], "too_large");
    assert_eq!(body["commits"]["commits"], json!([]));
    assert_eq!(body["commits"]["compare_url"], compare.as_str());
    assert!(body["reasons"].to_string().contains(&compare), "{body}");
}

#[tokio::test]
async fn a_cut_list_says_newest_100_of_total() {
    let world = World::seed().await;
    let kept = commits(100);
    range(&world, ('1', '3'), RangeState::Listed, Some(250), &kept).await;
    let body = story(&world, "v1.3.0").await;
    let listed = &body["commits"];
    assert_eq!(listed["state"], "listed");
    assert_eq!(listed["total"], 250);
    assert_eq!(listed["commits"].as_array().unwrap().len(), 100);
    let reasons = body["reasons"].to_string();
    assert!(reasons.contains("the newest 100 of 250"), "{reasons}");
    // A whole list says nothing of the kind.
    range(&world, ('1', '3'), RangeState::Listed, Some(100), &kept).await;
    let whole = story(&world, "v1.3.0").await;
    assert!(!whole["reasons"].to_string().contains("newest"), "{whole}");
}

#[tokio::test]
async fn a_rolled_back_release_says_failed_and_not_retried() {
    let world = World::seed().await;
    finished_deploy(&world, "app/prod", ("v1.3.0", '3'), "rolled_back").await;
    // What the watcher records of it next.
    world
        .store
        .record_release(
            (
                &"app/prod".parse().unwrap(),
                &"home-1".parse().unwrap(),
                &"v1.3.0".parse().unwrap(),
            ),
            ReleaseDecision::Refused,
            "it already rolled back on its host",
            None,
        )
        .await
        .unwrap();
    let body = story(&world, "v1.3.0").await;
    assert_eq!(body["release"]["status"], "failed");
    assert_eq!(body["release"]["decision"], "refused");
    let reasons = body["reasons"].to_string();
    assert!(reasons.contains("check failed"), "{reasons}");
    assert!(reasons.contains("isn't tried again by itself"), "{reasons}");
    assert_eq!(body["next"]["kind"], "request");
}

#[tokio::test]
async fn a_release_that_never_verified_has_no_origin_and_no_commits() {
    let world = World::seed().await;
    refused_by_verification(&world, "v1.4.0").await;
    let body = story(&world, "v1.4.0").await;
    assert_eq!(body["release"]["status"], "refused");
    assert_eq!(body["origin"], Value::Null);
    assert_eq!(body["commits"]["state"], "not_recorded");
    assert_eq!(body["commits"]["commits"], json!([]));
    assert!(
        body["reasons"][0]
            .as_str()
            .unwrap()
            .contains("no attestation")
    );
    // A refused release is never a base: v1.3.0's still starts at v1.1.0.
    assert_eq!(story(&world, "v1.3.0").await["commits"]["base"], "v1.1.0");
}

#[tokio::test]
async fn a_release_promoted_from_elsewhere_waits_for_it() {
    let world = World::seed().await;
    verified(
        &world.store,
        world.state.config(),
        "app/beta",
        "v3.1.0",
        'e',
    )
    .await;
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/beta/releases/v3.1.0",
            Caller::Token(FLEET_VIEWER),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    assert_eq!(body["release"]["status"], "promotion_pending");
    assert!(
        body["reasons"][0].as_str().unwrap().contains("app/canary"),
        "{body}"
    );
    assert_eq!(body["next"]["kind"], "wait");
}

/// The story of `v3.1.0` on `app/beta`, as [`BETA_VIEWER`] reads it: who may view `app/beta`
/// and not `app/canary`, which promotes to it.
async fn beta_story(world: &World) -> Value {
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/beta/releases/v3.1.0",
            Caller::Token(BETA_VIEWER),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    answer.json()
}

#[tokio::test]
async fn an_unseen_promotion_source_is_not_named() {
    let world = World::seed().await;
    verified(
        &world.store,
        world.state.config(),
        "app/beta",
        "v3.1.0",
        'e',
    )
    .await;
    let body = beta_story(&world).await;
    assert_eq!(body["release"]["status"], "promotion_pending");
    let text = body.to_string();
    assert!(text.contains("a deployment you can't view"), "{text}");
    assert!(!text.contains("app/canary"), "{text}");
}

#[tokio::test]
async fn a_stale_promotion_reason_never_names_an_unseen_deployment() {
    let world = World::seed().await;
    verified(
        &world.store,
        world.state.config(),
        "app/beta",
        "v3.1.0",
        'e',
    )
    .await;
    // What the watcher records while promotion holds it back: its reason names the source.
    world
        .store
        .record_release(
            (
                &"app/beta".parse().unwrap(),
                &"home-1".parse().unwrap(),
                &"v3.1.0".parse().unwrap(),
            ),
            ReleaseDecision::Manual,
            "waits for promotion: not yet reported healthy for long enough on app/canary, or \
             it has gone quiet (enforced by the controller only)",
            None,
        )
        .await
        .unwrap();
    // Then `app/canary` had it healthy for long enough, before the watcher looked again.
    sqlx::query(
        "INSERT INTO replaced_releases (deployment, host, tag, digest, healthy_secs)
         VALUES ('app/canary', 'home-1', 'v3.1.0', ?, 7200)",
    )
    .bind(world_digest('e').as_ref())
    .execute(world.store.pool())
    .await
    .unwrap();
    let body = beta_story(&world).await;
    assert_eq!(body["release"]["status"], "needs_request");
    let text = body.to_string();
    assert!(!text.contains("app/canary"), "{text}");
    assert!(text.contains("a first deploy needs an operator"), "{text}");
}

/// The tags of a page of releases, and its cursor.
fn page(answer: &Answer) -> (Vec<String>, Option<String>) {
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    let tags = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["tag"].as_str().unwrap().to_owned())
        .collect();
    (tags, body["next_cursor"].as_str().map(ToOwned::to_owned))
}

/// Every page of `path`'s releases, `limit` at a time, as `reader` reads them.
async fn every_page(world: &World, path: &str, reader: &str, limit: u8) -> Vec<Vec<String>> {
    let mut pages = Vec::new();
    let mut cursor: Option<String> = None;
    loop {
        let query = cursor.map_or(String::new(), |c| format!("&cursor={c}"));
        let answer = world
            .send(
                Method::GET,
                &format!("{path}?limit={limit}{query}"),
                Caller::Token(reader),
                None,
            )
            .await;
        let (tags, next) = page(&answer);
        pages.push(tags);
        match next {
            Some(next) => cursor = Some(next),
            None => return pages,
        }
        assert!(pages.len() <= 60, "the pages never end");
    }
}

fn version(tag: &str) -> Version {
    Version::parse(tag.strip_prefix('v').unwrap()).unwrap()
}

#[tokio::test]
async fn five_thousand_releases_page_in_version_order() {
    let world = World::seed().await;
    let hash = world.state.config().hash().to_owned();
    // `v10.0.9` sorts after `v10.0.10` as a string, and before it as a version.
    let mut tx = world.store.pool().begin().await.unwrap();
    for (i, (major, minor, patch)) in (10..15)
        .flat_map(|a| (0..20).flat_map(move |b| (0..50).map(move |c| (a, b, c))))
        .enumerate()
    {
        sqlx::query(
            "INSERT INTO releases (deployment, tag, commit_sha, digest, decision, reason, seen_at,
                                   tag_object, config_hash, origin_refused, first_seen_at)
             VALUES ('app/other', ?, ?, ?, 'manual', 'beyond the rule''s levels', ?, 'object', ?,
                     0, ?)",
        )
        .bind(format!("v{major}.{minor}.{patch}"))
        .bind(sha('a').as_ref())
        .bind(world_digest('a').as_ref())
        .bind(NOW)
        .bind(&hash)
        .bind(NOW - i64::try_from(i).unwrap())
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
    let pages = every_page(
        &world,
        "/api/v1/deployments/app/other/releases",
        OUTSIDER,
        100,
    )
    .await;
    assert_eq!(pages.len(), 50);
    assert!(pages.iter().all(|page| page.len() == 100));
    assert_eq!(pages[0][0], "v14.19.49");
    assert_eq!(pages[49][99], "v10.0.0");
    for pair in pages.windows(2) {
        let (before, after) = (&pair[0], &pair[1]);
        assert!(
            version(&after[0]) < version(before.last().unwrap()),
            "{} after {}",
            after[0],
            before.last().unwrap()
        );
    }
    let all: Vec<&String> = pages.iter().flatten().collect();
    assert!(all.windows(2).all(|w| version(w[0]) > version(w[1])));
}

#[tokio::test]
async fn unparseable_tags_come_last() {
    let world = World::seed().await;
    for tag in ["vnext", "release-1", "vbeta"] {
        refused_by_verification(&world, tag).await;
    }
    let pages = every_page(&world, PROD, &viewer(), 2).await;
    let all: Vec<String> = pages.into_iter().flatten().collect();
    assert_eq!(all, ["v1.3.0", "v1.1.0", "release-1", "vbeta", "vnext"]);
    let first = get(&world, PROD).await.json();
    let items = first["items"].as_array().unwrap();
    assert_eq!(items[0]["status"], "needs_request");
    assert_eq!(items[1]["status"], "superseded");
    assert_eq!(items[2]["status"], "refused");
}

#[tokio::test]
async fn unrecorded_tag_is_not_found() {
    let world = World::seed().await;
    for tag in ["v9.9.9", "v1.2.0", "bad%20tag", "..", "v1.3.0.lock"] {
        let answer = get(&world, &format!("{PROD}/{tag}")).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{tag}: {answer:?}");
        assert_eq!(answer.code(), "not_found");
    }
    // A cursor that isn't a release tag names nothing to start after.
    let bad = Cursor::new(CursorList::Releases, "a b").encode();
    let answer = get(&world, &format!("{PROD}?cursor={bad}")).await;
    assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{answer:?}");
}

#[tokio::test]
async fn releases_of_a_deployment_one_cannot_view_are_not_told() {
    let world = World::seed().await;
    let path = format!("{PROD}/v1.3.0");
    for target in [PROD, path.as_str()] {
        let outsider = world
            .send(Method::GET, target, Caller::Token(OUTSIDER), None)
            .await;
        assert_eq!(outsider.status, StatusCode::NOT_FOUND, "{target}");
        let requester = world
            .send(
                Method::GET,
                target,
                Caller::Token(&holder(&["request"])),
                None,
            )
            .await;
        assert_eq!(requester.status, StatusCode::FORBIDDEN, "{target}");
        assert_eq!(requester.code(), "forbidden");
    }
}

#[tokio::test]
async fn deployment_summary_shows_the_latest_release_and_its_status() {
    let world = World::seed().await;
    let one = get(&world, "/api/v1/deployments/app/prod").await.json();
    assert_eq!(
        one["summary"]["latest"],
        json!({ "tag": "v1.3.0", "status": "needs_request" })
    );
    let list = get(&world, "/api/v1/deployments").await.json();
    let prod = list["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "app/prod")
        .unwrap();
    assert_eq!(prod["latest"]["tag"], "v1.3.0");
    // Once a deploy of it is queued, it says so.
    let deployment: DeploymentId = "app/prod".parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    let tag: ReleaseTag = "v1.3.0".parse().unwrap();
    sqlx::query(
        "INSERT INTO deploys (deployment, host, tag, digest, commit_sha, state, created_at)
         VALUES (?, ?, ?, ?, ?, 'queued', ?)",
    )
    .bind(deployment.as_ref())
    .bind(host.as_ref())
    .bind(tag.as_ref())
    .bind(world_digest('3').as_ref())
    .bind(sha('3').as_ref())
    .bind(NOW)
    .execute(world.store.pool())
    .await
    .unwrap();
    let one = get(&world, "/api/v1/deployments/app/prod").await.json();
    assert_eq!(one["summary"]["latest"]["status"], "deploying");
    // A deployment with no release has none.
    let other = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/other",
            Caller::Token(OUTSIDER),
            None,
        )
        .await
        .json();
    assert_eq!(other["summary"]["latest"], Value::Null);
}
