//! What keeps the commits between releases bounded: a deadline on the tick's commits,
//! no asking while GitHub has the watcher waiting, no short list passed off as whole,
//! and a long history read without re-basing what is already stored.

use std::sync::Arc;
use std::time::{Duration, Instant};

use landfall_origin::fetch::{ComparePage, CompareStatus};

use super::commits::{
    T0, after, answer, compares, github, harness, nth, range, range_count, settle, sha, wanted,
    with_token,
};
use super::{
    HOST, Harness, OTHER, PATCH_RULE, PROD, RateLimitReset, WatcherState, config_text, id,
    rate_limited, server_error,
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
