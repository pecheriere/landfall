//! The commits between verified releases: which ranges, which commits of them, and
//! GitHub's budget, which verification has first.

use std::sync::Arc;

use landfall_approval::parse_config;
use landfall_core::ids::{CommitSha, RepoName, TagPattern};
use landfall_origin::fetch::{ComparePage, CompareStatus, FetchError, ListedCommit, Service};
use serde_json::json;

use super::super::commits::{GitHubBudget, SettledByVersion, after_tick, pages_for_newest};
use super::promotion::{PROMOTING, STAGING};
use super::{
    CompareAnswer, HOST, Harness, PATCH_RULE, PROD, RateLimitReset, ReleaseError, commit,
    config_text, digest, id, tag,
};
use crate::store::{CommitRange, RangeState, ReleaseDecision, Seen, WantedRange};

pub(super) const T0: i64 = 1_800_000_000;

/// When GitHub's rate-limit window ends, as [`github`] says: ten minutes in.
pub(super) const RESET: i64 = T0 + 600;

pub(super) fn repo() -> RepoName {
    "example/app".parse().unwrap()
}

pub(super) fn sha(n: u64) -> CommitSha {
    format!("{n:040x}").parse().unwrap()
}

/// The `n`th commit of a comparison, counting from 1 in GitHub's order, oldest first.
pub(super) fn nth(n: u64) -> ListedCommit {
    ListedCommit {
        sha: sha(n),
        summary: format!("\"commit {n}\""),
        author: None,
    }
}

/// A harness whose commits began to be compared at its clock's start, whatever the
/// time of the machine running it.
pub(super) async fn harness(config: &str) -> Harness {
    let h = Harness::new(config).await;
    sqlx::query("UPDATE commits_since SET at = ?")
        .bind(T0)
        .execute(h.store.pool())
        .await
        .unwrap();
    h
}

/// Records `tag` of `deployment` as verified, at `head`, under `config_hash`.
pub(super) async fn settle_at(
    h: &Harness,
    deployment: &str,
    release: &str,
    head: &CommitSha,
    hash: &str,
) {
    let seen = Seen {
        tag_object: &head.as_ref()[..40],
        config_hash: hash,
        commit: Some(head),
        digest: Some(&digest(release)),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (&id(deployment), &HOST.parse().unwrap(), &tag(release)),
            ReleaseDecision::Manual,
            "settled in a test",
            Some(&seen),
        )
        .await
        .unwrap();
}

pub(super) async fn settle(h: &Harness, deployment: &str, release: &str) {
    settle_at(h, deployment, release, &commit(release), h.config.hash()).await;
}

/// Records `tag` as refused by verification, with a commit.
async fn refuse(h: &Harness, release: &str) {
    let head = commit(release);
    let seen = Seen {
        tag_object: &head.as_ref()[..40],
        config_hash: h.config.hash(),
        commit: Some(&head),
        digest: None,
        refused: true,
        detail: json!({}),
        origin: json!({}),
    };
    h.store
        .record_release(
            (&id(PROD), &HOST.parse().unwrap(), &tag(release)),
            ReleaseDecision::Refused,
            "tag signature",
            Some(&seen),
        )
        .await
        .unwrap();
}

pub(super) async fn wanted(h: &Harness) -> Vec<WantedRange> {
    h.store
        .ranges_wanted(&h.config, h.config.hash(), h.store.now().unwrap())
        .await
        .unwrap()
}

/// The ranges wanted, as `(base tag's commit, head tag's commit)` named by tag.
async fn wanted_tags(h: &Harness, tags: &[&str]) -> Vec<(String, String)> {
    let name = |sha: &CommitSha| {
        tags.iter()
            .find(|t| commit(t) == *sha)
            .map_or_else(|| sha.to_string(), |t| (*t).to_owned())
    };
    wanted(h)
        .await
        .iter()
        .map(|w| (name(&w.base), name(&w.head)))
        .collect()
}

pub(super) async fn after(h: &Harness) -> usize {
    after_tick(
        &h.store,
        h.fake.as_ref(),
        &h.config,
        &h.state,
        h.store.now().unwrap(),
        &|_| {},
    )
    .await
}

/// [`after`], with the lines it logged.
pub(super) async fn after_logged(h: &Harness) -> (usize, Vec<String>) {
    let lines = std::sync::Mutex::new(Vec::new());
    let stored = after_tick(
        &h.store,
        h.fake.as_ref(),
        &h.config,
        &h.state,
        h.store.now().unwrap(),
        &|line| lines.lock().unwrap().push(line.to_owned()),
    )
    .await;
    (stored, lines.into_inner().unwrap())
}

pub(super) async fn range(h: &Harness, base: &str, head: &str) -> Option<CommitRange> {
    h.store
        .commit_range(&repo(), &commit(base), &commit(head))
        .await
        .unwrap()
}

pub(super) async fn range_count(h: &Harness) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM commit_ranges")
        .fetch_one(h.store.pool())
        .await
        .unwrap()
}

pub(super) fn compares(h: &Harness) -> Vec<u32> {
    h.fake
        .compares
        .lock()
        .unwrap()
        .iter()
        .map(|c| c.2)
        .collect()
}

/// GitHub, comparing any two commits as `total` commits ahead, `rate` requests left.
pub(super) fn github(total: u64, rate: u32) -> CompareAnswer {
    Box::new(move |_, _, page| {
        let first = u64::from(page - 1) * 100 + 1;
        let last = (u64::from(page) * 100).min(total);
        Ok(ComparePage::Listed {
            status: CompareStatus::Ahead,
            total,
            commits: (first..=last).map(nth).collect(),
            rate_remaining: Some(rate),
            rate_reset: Some(RESET),
        })
    })
}

pub(super) fn answer(h: &Harness, answer: CompareAnswer) {
    h.fake.locked().compare = Some(answer);
}

pub(super) fn with_token(h: &Harness) {
    h.fake.locked().github_token = true;
}

fn compare_error(status: u16) -> ReleaseError {
    ReleaseError::Compare(FetchError::Status {
        url: "https://example.test/compare".to_owned(),
        status,
    })
}

#[test]
fn base_is_the_highest_lower_settled_version() {
    let pattern: TagPattern = "v*".parse().unwrap();
    let settled = |tags: &[&str]| {
        SettledByVersion::new(&pattern, tags.iter().map(|t| (tag(t), commit(t), ())))
    };
    let base = |release: &str, tags: &[&str]| {
        let version = pattern.parse_tag(&tag(release)).unwrap();
        settled(tags).base_of(&version).map(|(t, c)| {
            assert_eq!(*c, commit(t.as_ref()));
            t.to_string()
        })
    };
    let all = [
        "v1.3.0",
        "junk",
        "v1.1.9",
        "v2.0.0",
        "v1.2.3",
        "v1.3.0-rc.1",
        "v1.2.0",
    ];
    assert_eq!(base("v1.2.3", &all).as_deref(), Some("v1.2.0"));
    assert_eq!(base("v1.2.0", &all).as_deref(), Some("v1.1.9"));
    assert_eq!(base("v1.3.0", &all).as_deref(), Some("v1.3.0-rc.1"));
    assert_eq!(base("v1.3.0-rc.1", &all).as_deref(), Some("v1.2.3"));
    assert_eq!(base("v2.0.0", &all).as_deref(), Some("v1.3.0"));
    assert_eq!(base("v1.1.9", &all), None);
    // A release not itself settled still finds the one below it.
    assert_eq!(base("v1.2.5", &all).as_deref(), Some("v1.2.3"));
    assert_eq!(base("v1.2.3", &["v1.2.3", "v1.3.0"]), None);
    assert_eq!(base("v1.2.3", &[]), None);

    // In version order, and a tag the pattern doesn't read is never one of them.
    let order: Vec<String> = settled(&all)
        .iter()
        .map(|(_, t, _, ())| t.to_string())
        .collect();
    assert_eq!(
        order,
        [
            "v1.1.9",
            "v1.2.0",
            "v1.2.3",
            "v1.3.0-rc.1",
            "v1.3.0",
            "v2.0.0"
        ]
    );
}

#[test]
fn pages_for_newest_table() {
    for (total, pages) in [
        (0, vec![1]),
        (1, vec![1]),
        (100, vec![1]),
        (101, vec![1, 2]),
        (200, vec![1, 2]),
        (201, vec![2, 3]),
        (250, vec![2, 3]),
        (1_000, vec![9, 10]),
        (u64::MAX, vec![u32::MAX - 1, u32::MAX]),
    ] {
        assert_eq!(pages_for_newest(total), pages, "{total}");
    }
}

#[test]
fn the_budget_is_twelve_with_a_token_and_three_without() {
    assert_eq!(
        format!("{:?}", GitHubBudget::for_tick(true)),
        "GitHubBudget { requests_left: 12, floor: 1000 }"
    );
    assert_eq!(
        format!("{:?}", GitHubBudget::for_tick(false)),
        "GitHubBudget { requests_left: 3, floor: 30 }"
    );
}

#[tokio::test]
async fn a_refused_release_is_neither_compared_nor_a_base() {
    let h = harness(&config_text(PATCH_RULE)).await;
    settle(&h, PROD, "v1.2.0").await;
    refuse(&h, "v1.2.5").await;
    settle(&h, PROD, "v1.3.0").await;

    let tags = ["v1.2.0", "v1.2.5", "v1.3.0"];
    assert_eq!(
        wanted_tags(&h, &tags).await,
        [("v1.2.0".to_owned(), "v1.3.0".to_owned())]
    );

    // A release verified once and refused since is no base either.
    settle(&h, PROD, "v1.1.0").await;
    refuse(&h, "v1.2.0").await;
    let tags = ["v1.1.0", "v1.2.0", "v1.2.5", "v1.3.0"];
    assert_eq!(
        wanted_tags(&h, &tags).await,
        [("v1.1.0".to_owned(), "v1.3.0".to_owned())]
    );
}

#[tokio::test]
async fn a_release_not_settled_under_this_configuration_is_skipped() {
    let h = harness(&config_text(PATCH_RULE)).await;
    settle(&h, PROD, "v1.2.0").await;
    settle_at(
        &h,
        PROD,
        "v1.3.0",
        &commit("v1.3.0"),
        "an older configuration",
    )
    .await;
    assert_eq!(wanted(&h).await, []);

    // Nor is it a base.
    settle_at(
        &h,
        PROD,
        "v1.2.0",
        &commit("v1.2.0"),
        "an older configuration",
    )
    .await;
    settle(&h, PROD, "v1.4.0").await;
    assert_eq!(wanted(&h).await, []);
    after(&h).await;
    assert_eq!(compares(&h), Vec::<u32>::new());
}

#[tokio::test]
async fn a_moved_tag_is_compared_again() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    answer(&h, github(3, 5000));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    assert_eq!(after(&h).await, 1);
    assert_eq!(range(&h, "v1.2.0", "v1.3.0").await.unwrap().total, Some(3));

    let moved = sha(0xbeef);
    settle_at(&h, PROD, "v1.3.0", &moved, h.config.hash()).await;
    let new = wanted(&h).await;
    assert_eq!(new.len(), 1);
    assert_eq!((&new[0].base, &new[0].head), (&commit("v1.2.0"), &moved));
    assert_eq!(after(&h).await, 1);

    // What the release's commits find now is the new range; the old one is left
    // behind under the commit it was for.
    let releases = h.store.releases_of(&id(PROD)).await.unwrap();
    let head = releases["v1.3.0"].commit.clone().unwrap();
    let base = releases["v1.2.0"].commit.clone().unwrap();
    assert_eq!(head, moved);
    let found = h.store.commit_range(&repo(), &base, &head).await.unwrap();
    assert_eq!(found.unwrap().state, RangeState::Listed);
    assert_eq!(range_count(&h).await, 2);
    assert_eq!(wanted(&h).await, []);
}

#[tokio::test]
async fn the_newest_100_come_from_the_last_pages() {
    let h = harness(&config_text(PATCH_RULE)).await;
    answer(&h, github(250, 5000));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;

    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1, 2, 3]);
    let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
    assert_eq!(stored.state, RangeState::Listed);
    assert_eq!(stored.total, Some(250));
    let expected: Vec<ListedCommit> = (151..=250).rev().map(nth).collect();
    assert_eq!(stored.commits, expected);

    // Of 120, the newest 100 of pages 1 and 2, without asking for page 1 twice.
    let h = harness(&config_text(PATCH_RULE)).await;
    answer(&h, github(120, 5000));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    after(&h).await;
    assert_eq!(compares(&h), [1, 2]);
    let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
    let expected: Vec<ListedCommit> = (21..=120).rev().map(nth).collect();
    assert_eq!((stored.total, stored.commits), (Some(120), expected));
}

#[tokio::test]
async fn behind_or_diverged_is_base_not_found() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    answer(
        &h,
        Box::new(|_, head, _| {
            let status = if *head == commit("v1.3.0") {
                CompareStatus::Behind
            } else {
                CompareStatus::Diverged
            };
            Ok(ComparePage::Listed {
                status,
                total: 2,
                commits: vec![nth(1), nth(2)],
                rate_remaining: Some(5000),
                rate_reset: None,
            })
        }),
    );
    for release in ["v1.2.0", "v1.3.0", "v1.4.0"] {
        settle(&h, PROD, release).await;
    }
    assert_eq!(after(&h).await, 2);
    for (base, head) in [("v1.2.0", "v1.3.0"), ("v1.3.0", "v1.4.0")] {
        let stored = range(&h, base, head).await.unwrap();
        assert_eq!(stored.state, RangeState::BaseNotFound, "{head}");
        assert_eq!((stored.total, stored.commits.len()), (None, 0));
    }
    assert_eq!(compares(&h), [1, 1]);
}

#[tokio::test]
async fn too_large_is_recorded_without_a_list() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    answer(&h, Box::new(|_, _, _| Ok(ComparePage::TooLarge)));
    for release in ["v1.2.0", "v1.3.0", "v1.4.0"] {
        settle(&h, PROD, release).await;
    }
    // A too-large answer says nothing of GitHub's limit, so the tick goes on to the next
    // range within its budget.
    assert_eq!(after(&h).await, 2);
    assert_eq!(compares(&h), [1, 1]);
    for (base, head) in [("v1.2.0", "v1.3.0"), ("v1.3.0", "v1.4.0")] {
        let stored = range(&h, base, head).await.unwrap();
        assert_eq!(stored.state, RangeState::TooLarge, "{head}");
        assert_eq!((stored.total, stored.commits.len()), (None, 0));
    }
    assert_eq!(wanted(&h).await, []);
}

#[tokio::test]
async fn a_range_is_never_stored_half_done() {
    let h = harness(&config_text(PATCH_RULE)).await;
    // Page 1 leaves GitHub below the untokened floor of 30.
    answer(&h, github(250, 29));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;

    assert_eq!(after(&h).await, 0);
    assert_eq!(compares(&h), [1]);
    assert_eq!(range_count(&h).await, 0);

    // Once GitHub's window has ended, it is fetched whole.
    answer(&h, github(250, 5000));
    h.clock.advance(RESET - T0);
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1, 1, 2, 3]);
    let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
    assert_eq!(stored.commits.len(), 100);
}

#[tokio::test]
async fn two_deployments_of_one_repo_share_one_range() {
    let h = harness(PROMOTING).await;
    with_token(&h);
    for deployment in [PROD, STAGING] {
        settle(&h, deployment, "v1.2.0").await;
        settle(&h, deployment, "v1.3.0").await;
    }
    assert_eq!(wanted(&h).await.len(), 1);
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1]);
    assert_eq!(range_count(&h).await, 1);
    assert_eq!(wanted(&h).await, []);
}

#[tokio::test]
async fn ranges_go_newest_version_first_across_deployments() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    for release in ["v1.2.0", "v1.3.0", "v1.4.0"] {
        settle(&h, PROD, release).await;
    }
    for release in ["v1.0.0", "v1.3.5"] {
        settle_at(&h, super::OTHER, release, &commit(release), h.config.hash()).await;
    }
    let heads: Vec<CommitSha> = wanted(&h).await.into_iter().map(|w| w.head).collect();
    let expected: Vec<CommitSha> = ["v1.4.0", "v1.3.5", "v1.3.0"]
        .iter()
        .map(|t| commit(t))
        .collect();
    assert_eq!(heads, expected);
}

#[tokio::test]
async fn verification_runs_before_commits() {
    let h = Harness::running("v1.2.0").await;
    sqlx::query("UPDATE commits_since SET at = ?")
        .bind(T0)
        .execute(h.store.pool())
        .await
        .unwrap();
    h.fake.tags(PROD, &["v1.2.0", "v1.2.1", "v1.3.0"]);

    let summary = h.tick().await;
    assert_eq!(summary.verified, 3, "{summary:?}");
    let calls = h.fake.calls.lock().unwrap().clone();
    let first_compare = calls.iter().position(|c| *c == "compare").unwrap();
    assert!(
        calls[first_compare..].iter().all(|c| *c == "compare"),
        "{calls:?}"
    );
    assert_eq!(calls.iter().filter(|c| **c == "verify").count(), 3);
}

#[tokio::test]
async fn compares_stop_when_the_rate_limit_is_low() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    answer(&h, github(5, 999));
    for release in ["v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0"] {
        settle(&h, PROD, release).await;
    }

    // The page that says so is whole, and kept; nothing is asked after it.
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1]);
    assert!(range(&h, "v1.4.0", "v1.5.0").await.is_some());

    // It goes on once GitHub's window has ended.
    answer(&h, github(5, 4000));
    h.clock.advance(RESET - T0);
    assert_eq!(after(&h).await, 2);
    assert_eq!(compares(&h), [1, 1, 1]);
    assert!(range(&h, "v1.2.0", "v1.3.0").await.is_some());
}

#[tokio::test]
async fn a_bare_403_stops_the_tick() {
    let h = harness(&config_text(PATCH_RULE)).await;
    with_token(&h);
    for status in [403, 429] {
        answer(&h, Box::new(move |_, _, _| Err(compare_error(status))));
        for release in ["v1.2.0", "v1.3.0", "v1.4.0"] {
            settle(&h, PROD, release).await;
        }
        h.fake.compares.lock().unwrap().clear();
        assert_eq!(after(&h).await, 0, "{status}");
        assert_eq!(compares(&h), [1], "{status}");
        // Nothing is stored, not even as unavailable: it is asked again once the
        // hour a refusal without a reset waits for has passed.
        assert_eq!(range_count(&h).await, 0, "{status}");
        h.clock.advance(3600);
    }
    answer(&h, github(1, 5000));
    assert_eq!(after(&h).await, 2);
}

#[tokio::test]
async fn untokened_ticks_make_at_most_three_requests() {
    let h = harness(&config_text(PATCH_RULE)).await;
    answer(&h, github(250, 59));
    for release in ["v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0"] {
        settle(&h, PROD, release).await;
    }
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1, 2, 3]);

    // Single pages too: one range, since another could need three.
    let h = harness(&config_text(PATCH_RULE)).await;
    answer(&h, github(1, 59));
    for release in ["v1.2.0", "v1.3.0", "v1.4.0", "v1.5.0"] {
        settle(&h, PROD, release).await;
    }
    for tick in 1..=3 {
        assert_eq!(after(&h).await, 1);
        assert_eq!(compares(&h).len(), tick);
    }
    assert_eq!(after(&h).await, 0);
}

#[tokio::test]
async fn a_rate_limited_answer_stops_the_tick_and_holds_nothing() {
    let h = Harness::running("v1.2.0").await;
    sqlx::query("UPDATE commits_since SET at = ?")
        .bind(T0)
        .execute(h.store.pool())
        .await
        .unwrap();
    h.fake.tags(PROD, &["v1.2.0", "v1.2.1"]);
    h.tick().await;
    let decisions = (
        h.decision(PROD, "v1.2.0").await,
        h.decision(PROD, "v1.2.1").await,
    );
    let audit_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    sqlx::query("DELETE FROM commit_ranges")
        .execute(h.store.pool())
        .await
        .unwrap();

    answer(
        &h,
        Box::new(|_, _, _| {
            Err(ReleaseError::Compare(FetchError::RateLimited {
                service: Service::GitHubApi,
                url: "https://example.test/compare".to_owned(),
                status: 403,
                reset: RateLimitReset::Unknown,
            }))
        }),
    );
    h.clock.advance(300);
    let summary = h.tick().await;
    assert_eq!(summary.backed_off, 0, "{summary:?}");
    assert_eq!(summary.held, 0, "{summary:?}");
    assert_eq!(
        (
            h.decision(PROD, "v1.2.0").await,
            h.decision(PROD, "v1.2.1").await
        ),
        decisions
    );
    assert_eq!(h.hold_reason(PROD, "v1.2.1").await, None);
    assert_eq!(h.hold_reason(PROD, "").await, None);
    assert_eq!(range_count(&h).await, 0);
    let after_rows: i64 = sqlx::query_scalar("SELECT count(*) FROM audit_events")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(after_rows, audit_rows);

    // Nor does it keep the next tick's verifications from GitHub.
    h.fake.tags(PROD, &["v1.2.0", "v1.2.1", "v1.2.2"]);
    h.clock.advance(300);
    let summary = h.tick().await;
    assert_eq!(summary.verified, 1, "{summary:?}");
}

#[tokio::test]
async fn releases_seen_before_the_migration_are_never_fetched() {
    let h = harness(&config_text(PATCH_RULE)).await;
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    // The migration ran after these were first recorded.
    sqlx::query("UPDATE commits_since SET at = ?")
        .bind(T0 + 1)
        .execute(h.store.pool())
        .await
        .unwrap();
    h.clock.advance(60);
    assert_eq!(wanted(&h).await, []);
    assert_eq!(after(&h).await, 0);
    assert_eq!(compares(&h), Vec::<u32>::new());

    // A release recorded since is compared, from an old one.
    settle(&h, PROD, "v1.4.0").await;
    let tags = ["v1.3.0", "v1.4.0"];
    assert_eq!(
        wanted_tags(&h, &tags).await,
        [("v1.3.0".to_owned(), "v1.4.0".to_owned())]
    );
}

#[tokio::test]
async fn a_configuration_change_does_not_make_old_releases_eligible() {
    let h = harness(&config_text(PATCH_RULE)).await;
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    sqlx::query("UPDATE commits_since SET at = ?")
        .bind(T0 + 1)
        .execute(h.store.pool())
        .await
        .unwrap();

    h.clock.advance(3600);
    let changed = Arc::new(
        parse_config(config_text(r#"{ auto = "minor", approvers = ["operator"] }"#).as_bytes())
            .unwrap(),
    );
    assert_ne!(changed.hash(), h.config.hash());
    for release in ["v1.2.0", "v1.3.0"] {
        settle_at(&h, PROD, release, &commit(release), changed.hash()).await;
    }
    let (first_seen, seen): (i64, i64) = sqlx::query_as(
        "SELECT first_seen_at, seen_at FROM releases WHERE deployment = ? AND tag = ?",
    )
    .bind(PROD)
    .bind("v1.3.0")
    .fetch_one(h.store.pool())
    .await
    .unwrap();
    assert_eq!((first_seen, seen), (T0, T0 + 3600));

    let now = h.store.now().unwrap();
    let wanted = h
        .store
        .ranges_wanted(&changed, changed.hash(), now)
        .await
        .unwrap();
    assert_eq!(wanted, []);
    after_tick(&h.store, h.fake.as_ref(), &changed, &h.state, now, &|_| {}).await;
    assert_eq!(compares(&h), Vec::<u32>::new());
}

#[tokio::test]
async fn unavailable_is_retried_after_an_hour() {
    let h = harness(&config_text(PATCH_RULE)).await;
    answer(&h, Box::new(|_, _, _| Err(compare_error(502))));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;

    assert_eq!(after(&h).await, 1);
    let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
    assert_eq!(stored.state, RangeState::Unavailable);
    assert_eq!((stored.total, stored.last_try), (None, T0));
    // Nothing is held or refused for it.
    assert_eq!(h.hold_reason(PROD, "v1.3.0").await, None);
    assert_eq!(h.decision(PROD, "v1.3.0").await.0, "manual");

    answer(&h, github(2, 5000));
    h.clock.advance(3600);
    assert_eq!(after(&h).await, 0);
    assert_eq!(compares(&h), [1]);

    h.clock.advance(1);
    let retry = wanted(&h).await;
    assert!(retry[0].retry, "{retry:?}");
    assert_eq!(after(&h).await, 1);
    let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
    assert_eq!(stored.state, RangeState::Listed);
    assert_eq!(stored.commits, [nth(2), nth(1)]);
}
