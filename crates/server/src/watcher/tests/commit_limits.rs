//! What keeps the commits between releases bounded: a deadline on the tick's commits,
//! no asking while GitHub has the watcher waiting, no short list passed off as whole,
//! and a long history read without re-basing what is already stored.

use std::sync::Arc;
use std::time::{Duration, Instant};

use landfall_origin::fetch::{ComparePage, CompareStatus, FetchError, Service};

use super::commits::{
    RESET, T0, after, after_logged, answer, compares, github, harness, nth, range, range_count,
    settle, sha, wanted, with_token,
};
use super::{
    CompareAnswer, HOST, Harness, OTHER, PATCH_RULE, PROD, RateLimitReset, ReleaseError,
    WatcherState, config_text, id, rate_limited, server_error,
};
use crate::store::RangeState;

#[tokio::test]
async fn a_hanging_compare_does_not_hold_the_tick_past_its_deadline() {
    let mut h = harness(&config_text(PATCH_RULE)).await;
    h.state = Arc::new(WatcherState::with_commits_deadline(Duration::from_millis(
        100,
    )));
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    h.fake.locked().compare_hangs = true;

    let started = Instant::now();
    tokio::time::timeout(Duration::from_secs(10), h.tick())
        .await
        .expect("the tick waited on a compare that never answers");
    assert!(started.elapsed() < Duration::from_secs(5));
    assert_eq!(compares(&h), [1]);
    // Cut short, nothing of it is stored, and the next tick asks again.
    assert_eq!(range_count(&h).await, 0);

    h.fake.locked().compare_hangs = false;
    h.tick().await;
    assert_eq!(compares(&h), [1, 1]);
    assert_eq!(
        range(&h, "v1.2.0", "v1.3.0").await.unwrap().state,
        RangeState::Listed
    );
}

#[tokio::test]
async fn commits_wait_while_github_rate_limits_a_repository() {
    let h = harness(&config_text(PATCH_RULE)).await;
    h.report(PROD, HOST, Some("v1.2.0")).await;
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    h.fake
        .locked()
        .tags_fail
        .insert(PROD.to_owned(), rate_limited(RateLimitReset::After(600)));
    h.fake.tags(OTHER, &[]);

    let summary = h.tick().await;
    assert_eq!(summary.backed_off, 0, "{summary:?}");
    assert_eq!(compares(&h), Vec::<u32>::new());
    h.clock.advance(300);
    h.tick().await;
    assert_eq!(compares(&h), Vec::<u32>::new());

    // Once the limit has lifted, they are asked for.
    h.clock.advance(301);
    h.fake.locked().tags_fail.clear();
    h.tick().await;
    assert_eq!(compares(&h), [1]);
}

#[tokio::test]
async fn an_outage_elsewhere_does_not_stop_commits() {
    let h = harness(&config_text(PATCH_RULE)).await;
    h.report(OTHER, "host-b", None).await;
    settle(&h, PROD, "v1.2.0").await;
    settle(&h, PROD, "v1.3.0").await;
    h.fake
        .locked()
        .tags_fail
        .insert(OTHER.to_owned(), server_error());

    h.tick().await;
    assert_eq!(compares(&h), [1]);
}

#[tokio::test]
async fn a_short_page_is_not_a_list() {
    // Page 1 of 5 holding 3; of 5 holding 6; the last page of 250 short by one.
    let short: [(u64, Vec<u64>); 3] = [
        (5, (1..=3).collect()),
        (5, (1..=6).collect()),
        (250, (1..=249).collect()),
    ];
    for (total, listed) in short {
        let h = harness(&config_text(PATCH_RULE)).await;
        with_token(&h);
        let pages = listed.clone();
        answer(
            &h,
            Box::new(move |_, _, page| {
                let first = u64::from(page - 1) * 100 + 1;
                let last = u64::from(page) * 100;
                Ok(ComparePage::Listed {
                    status: CompareStatus::Ahead,
                    total,
                    commits: pages
                        .iter()
                        .copied()
                        .filter(|n| (first..=last).contains(n) || (total <= 100 && page == 1))
                        .map(nth)
                        .collect(),
                    rate_remaining: Some(5000),
                    rate_reset: None,
                })
            }),
        );
        settle(&h, PROD, "v1.2.0").await;
        settle(&h, PROD, "v1.3.0").await;

        assert_eq!(after(&h).await, 1, "{total}");
        let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
        assert_eq!(stored.state, RangeState::Unavailable, "{total} {listed:?}");
        assert_eq!((stored.total, stored.commits.len()), (None, 0));

        // And tried again after an hour, like any failure.
        answer(&h, github(total, 5000));
        h.clock.advance(3601);
        assert_eq!(after(&h).await, 1);
        let stored = range(&h, "v1.2.0", "v1.3.0").await.unwrap();
        assert_eq!(stored.state, RangeState::Listed, "{total}");
    }
}

/// Settled releases `v1.0.0` to `v1.0.{n - 1}` of `app/prod`, at commits `sha(1)` up, in
/// one transaction: quicker than recording each.
async fn settle_many(h: &Harness, n: u64) {
    let mut tx = h.store.pool().begin().await.unwrap();
    for i in 0..n {
        sqlx::query(
            "INSERT INTO releases (deployment, tag, commit_sha, digest, decision, reason,
                                   seen_at, config_hash, first_seen_at)
             VALUES (?, ?, ?, ?, 'manual', 'settled in a test', ?, ?, ?)",
        )
        .bind(PROD)
        .bind(format!("v1.0.{i}"))
        .bind(sha(i + 1).as_ref())
        .bind(format!("sha256:{}", "a".repeat(64)))
        .bind(T0)
        .bind(h.config.hash())
        .bind(T0)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();
}

#[tokio::test]
async fn heads_with_a_stored_range_are_not_returned() {
    let h = harness(&config_text(PATCH_RULE)).await;
    let n = 3_000;
    settle_many(&h, n).await;
    assert_eq!(h.store.releases_of(&id(PROD)).await.unwrap().len(), 3_000);

    // Every range is stored but two, one of them unavailable a moment ago.
    let mut tx = h.store.pool().begin().await.unwrap();
    for i in 1..n {
        let state = match i {
            500 | 2_999 => continue,
            1_000 => "unavailable",
            7 => "too_large",
            _ => "listed",
        };
        sqlx::query(
            "INSERT INTO commit_ranges (repo, base_commit, head_commit, state, total, last_try)
             VALUES ('example/app', ?, ?, ?, NULL, ?)",
        )
        .bind(sha(i).as_ref())
        .bind(sha(i + 1).as_ref())
        .bind(state)
        .bind(T0)
        .execute(&mut *tx)
        .await
        .unwrap();
    }
    tx.commit().await.unwrap();

    let found: Vec<(String, String)> = wanted(&h)
        .await
        .into_iter()
        .map(|w| (w.tag.to_string(), w.base.to_string()))
        .collect();
    assert_eq!(
        found,
        [
            ("v1.0.2999".to_owned(), sha(2_999).to_string()),
            ("v1.0.500".to_owned(), sha(500).to_string()),
        ]
    );
}

/// Two releases of `app/prod` wanting a range each, `v1.2.0` to `v1.4.0`.
async fn three_releases(h: &Harness) {
    for release in ["v1.2.0", "v1.3.0", "v1.4.0"] {
        settle(h, PROD, release).await;
    }
}

/// GitHub listing one commit with `rate` requests left and the window ending at `reset`.
fn one_commit(rate: u32, reset: Option<i64>) -> CompareAnswer {
    Box::new(move |_, _, _| {
        Ok(ComparePage::Listed {
            status: CompareStatus::Ahead,
            total: 1,
            commits: vec![nth(1)],
            rate_remaining: Some(rate),
            rate_reset: reset,
        })
    })
}

#[tokio::test]
async fn below_the_floor_carries_over_to_the_next_tick() {
    let h = harness(&config_text(PATCH_RULE)).await;
    three_releases(&h).await;
    // Untokened: 29 left is below the floor of 30.
    answer(&h, github(1, 29));
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1]);

    // The next ticks send nothing, though a new tick has a new budget.
    answer(&h, github(1, 5000));
    for _ in 0..(RESET - T0) / 300 - 1 {
        h.clock.advance(300);
        h.tick().await;
    }
    assert_eq!(compares(&h), [1]);
    assert_eq!(range_count(&h).await, 1);

    // From GitHub's reset on, it goes on.
    h.clock.advance(RESET - h.store.now().unwrap());
    h.tick().await;
    assert_eq!(compares(&h), [1, 1]);
    assert_eq!(range_count(&h).await, 2);
}

#[tokio::test]
async fn below_the_floor_without_a_reset_waits_an_hour() {
    let h = harness(&config_text(PATCH_RULE)).await;
    three_releases(&h).await;
    answer(&h, one_commit(29, None));
    assert_eq!(after(&h).await, 1);

    answer(&h, one_commit(5000, None));
    h.clock.advance(3599);
    assert_eq!(after(&h).await, 0);
    assert_eq!(compares(&h), [1]);
    h.clock.advance(1);
    assert_eq!(after(&h).await, 1);
    assert_eq!(compares(&h), [1, 1]);
}

#[tokio::test]
async fn a_reset_far_off_is_believed_for_a_day_at_most() {
    let h = harness(&config_text(PATCH_RULE)).await;
    three_releases(&h).await;
    answer(&h, one_commit(0, Some(i64::MAX)));
    assert_eq!(after(&h).await, 1);

    answer(&h, one_commit(5000, None));
    h.clock.advance(24 * 60 * 60 - 1);
    assert_eq!(after(&h).await, 0);
    h.clock.advance(1);
    assert_eq!(after(&h).await, 1);
}

/// The URL a refusal names: what was asked, which no log line repeats.
const REFUSED_URL: &str = "https://example.test/compare?secret";

fn refusal(status: u16, reset: Option<RateLimitReset>) -> ReleaseError {
    let url = REFUSED_URL.to_owned();
    ReleaseError::Compare(match reset {
        Some(reset) => FetchError::RateLimited {
            service: Service::GitHubApi,
            url,
            status,
            reset,
        },
        None => FetchError::Status { url, status },
    })
}

#[tokio::test]
async fn a_403_or_429_from_compare_backs_off_across_ticks() {
    let cases = [
        (429, Some(RateLimitReset::After(120)), 120),
        (
            403,
            Some(RateLimitReset::At(
                jiff::Timestamp::from_second(T0 + 900).unwrap(),
            )),
            900,
        ),
        (403, None, 3600),
        (429, None, 3600),
        (429, Some(RateLimitReset::Unknown), 3600),
    ];
    for (status, reset, wait) in cases {
        let h = harness(&config_text(PATCH_RULE)).await;
        three_releases(&h).await;
        answer(&h, Box::new(move |_, _, _| Err(refusal(status, reset))));
        let (stored, lines) = after_logged(&h).await;
        assert_eq!(stored, 0, "{status} {reset:?}");
        assert_eq!(compares(&h), [1], "{status} {reset:?}");
        // One line says so, with the repository and when commits go on, and nothing of
        // the request: a refusal that never lifts is seen, an hour at a time.
        assert_eq!(
            lines,
            [format!(
                "watcher: commits: GitHub answered {status} to a compare in example/app: no \
                 commits are fetched until {} (Unix seconds)",
                T0 + wait
            )],
            "{status} {reset:?}"
        );
        assert!(!lines[0].contains("secret"), "{lines:?}");
        // While paused, nothing is asked and nothing more is logged.
        assert_eq!(
            after_logged(&h).await,
            (0, Vec::new()),
            "{status} {reset:?}"
        );

        answer(&h, one_commit(5000, None));
        h.clock.advance(wait - 1);
        h.tick().await;
        assert_eq!(compares(&h), [1], "{status} {reset:?}");
        h.clock.advance(1);
        h.tick().await;
        assert_eq!(compares(&h), [1, 1], "{status} {reset:?}");
    }
}
