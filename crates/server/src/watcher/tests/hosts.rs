//! Whether a host can take a deploy: what it says, and what became of the release
//! on it before.

use super::*;

#[tokio::test]
async fn a_queued_deploy_wakes_a_waiting_agent() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    let waiting = h.store.subscribe_to_work();
    h.tick().await;
    assert!(waiting.has_changed().unwrap());
}

#[tokio::test]
async fn a_host_that_has_not_reported_gets_no_decision_and_a_stated_reason() {
    let h = Harness::new(&config_text(PATCH_RULE)).await;
    h.fake.tags(PROD, &["v1.0.0"]);

    h.tick().await;
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 0);
    let reason = h.hold_reason(PROD, "").await.unwrap();
    assert!(reason.contains("not reported"), "{reason}");
    // Both deployments, once each, over two ticks.
    assert_eq!(h.audit("release_held").await.len(), 2);

    h.report(PROD, HOST, None).await;
    h.tick().await;
    assert_eq!(h.hold_reason(PROD, "").await, None);
    assert_eq!(h.decision(PROD, "v1.0.0").await.0, "manual");
}

#[tokio::test]
async fn a_report_from_a_host_the_deployment_is_not_on_counts_for_nothing() {
    let h = Harness::new(&config_text(PATCH_RULE)).await;
    h.report(PROD, "host-z", Some("v1.2.3")).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    assert_eq!(h.deploys(PROD).await, []);
    assert_eq!(h.fake.verify_count(), 0);
}

#[tokio::test]
async fn no_second_deploy_while_one_is_active() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    assert_eq!(h.tick().await.queued.len(), 1);

    h.fake.tags(PROD, &["v1.2.4", "v1.2.5"]);
    assert_eq!(h.tick().await.queued, []);
    assert_eq!(h.deploys(PROD).await.len(), 1);

    // Claimed, it still blocks.
    let host: landfall_core::ids::HostId = HOST.parse().unwrap();
    h.store.next_work(&host).await.unwrap();
    assert_eq!(h.tick().await.queued, []);
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_release_that_rolled_back_is_not_queued_again_and_a_newer_one_is() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    h.finish(
        HOST,
        ReportedOutcome::RolledBack {
            reason: "checks failed".to_owned(),
        },
    )
    .await;

    assert_eq!(h.tick().await.queued, []);
    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("rolled back"), "{reason}");

    h.fake.tags(PROD, &["v1.2.4", "v1.2.5"]);
    assert_eq!(h.tick().await.queued.len(), 1);
    assert_eq!(h.deploys(PROD).await[1].0, "v1.2.5");
    assert_eq!(h.deploys(PROD).await[1].1, "queued");
}

#[tokio::test]
async fn a_release_its_host_refused_is_not_queued_again() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    h.finish(
        HOST,
        ReportedOutcome::Refused {
            reason: "not in my rule".to_owned(),
        },
    )
    .await;

    assert_eq!(h.tick().await.queued, []);
    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("host refused"), "{reason}");
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn the_refusal_is_for_that_digest_only() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    // The finished deploy names an older digest of the tag.
    sqlx::query("UPDATE deploys SET digest = ?")
        .bind(digest("an older build").as_ref())
        .execute(h.store.pool())
        .await
        .unwrap();
    h.finish(
        HOST,
        ReportedOutcome::RolledBack {
            reason: "checks failed".to_owned(),
        },
    )
    .await;

    assert_eq!(h.tick().await.queued.len(), 1);
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
}

#[tokio::test]
async fn a_deploy_that_never_started_is_tried_a_few_times() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    for _ in 0..NOTHING_CHANGED_TRIES {
        assert_eq!(h.tick().await.queued.len(), 1);
        h.finish(
            HOST,
            ReportedOutcome::NothingChanged {
                reason: "interrupted".to_owned(),
            },
        )
        .await;
    }
    assert_eq!(h.tick().await.queued, []);
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "refused");
}

#[tokio::test]
async fn a_release_already_deployed_is_not_queued_again_before_the_host_says_so() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    h.finish(HOST, ReportedOutcome::Deployed {}).await;

    // The report is in; the host's next poll, saying what runs, is not yet.
    assert_eq!(h.tick().await.queued, []);

    h.report(PROD, HOST, Some("v1.2.4")).await;
    assert_eq!(h.tick().await.queued, []);
    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("already running"), "{reason}");
}

#[tokio::test]
async fn a_host_that_cannot_take_a_deploy_is_not_given_one() {
    /// A name, what the host says, and what is held for it.
    type Setup = (&'static str, fn(&mut RunningState), Option<&'static str>);
    let setups: [Setup; 3] = [
        ("drift", |s| s.drift = true, Some("differs")),
        (
            "busy",
            |s| {
                s.phase = Phase::Deploying;
                s.busy = true;
            },
            None,
        ),
        (
            "interrupted",
            |s| s.phase = Phase::RollingBack,
            Some("recovery"),
        ),
    ];
    for (name, change, held) in setups {
        let h = Harness::running("v1.2.3").await;
        let mut state = Harness::state_of(PROD, Some("v1.2.3"));
        change(&mut state);
        h.report_state(HOST, state).await;
        h.fake.tags(PROD, &["v1.2.4"]);

        assert_eq!(h.tick().await.queued, [], "{name}");
        assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto", "{name}");
        let reason = h.hold_reason(PROD, "").await;
        match held {
            Some(held) => assert!(reason.unwrap().contains(held), "{name}"),
            None => assert_eq!(reason, None, "{name}"),
        }

        // When it clears, the deploy goes, and the hold is gone.
        h.report(PROD, HOST, Some("v1.2.3")).await;
        assert_eq!(h.tick().await.queued.len(), 1, "{name}");
        assert_eq!(h.hold_reason(PROD, "").await, None, "{name}");
    }
}

#[tokio::test]
async fn a_host_with_the_wrong_configuration_is_not_given_a_deploy() {
    let h = Harness::running("v1.2.3").await;
    sqlx::query(
        "INSERT INTO hosts (id, public_key, enrolled_at, drifted_config_hash) VALUES (?, ?, 0, ?)",
    )
    .bind(HOST)
    .bind([1_u8; 32].as_slice())
    .bind([2_u8; 32].as_slice())
    .execute(h.store.pool())
    .await
    .unwrap();
    h.fake.tags(PROD, &["v1.2.4"]);

    assert_eq!(h.tick().await.queued, []);
    let reason = h.hold_reason(PROD, "").await.unwrap();
    assert!(reason.contains("configuration"), "{reason}");
}
