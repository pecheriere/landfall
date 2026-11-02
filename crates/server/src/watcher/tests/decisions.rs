//! What gets decided about a release, why, and how often it is recorded.

use super::*;

#[tokio::test]
async fn new_patch_release_queues_a_deploy() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.3", "v1.2.4"]);

    let summary = h.tick().await;

    assert_eq!(summary.queued.len(), 1, "{summary:?}");
    assert_eq!(
        h.deploys(PROD).await,
        [("v1.2.4".to_owned(), "queued".to_owned())]
    );
    let row = sqlx::query("SELECT digest, commit_sha FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("digest"), digest("v1.2.4").as_ref());
    assert_eq!(
        row.get::<String, _>("commit_sha"),
        commit("v1.2.4").as_ref()
    );
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.audit("deploy_queued").await.len(), 1);
    h.chain_is_intact().await;
}

#[tokio::test]
async fn only_the_highest_eligible_version_is_queued() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4", "v1.2.6", "v1.2.5", "v1.3.0"]);

    h.tick().await;

    assert_eq!(
        h.deploys(PROD).await,
        [("v1.2.6".to_owned(), "queued".to_owned())]
    );
    assert_eq!(h.decision(PROD, "v1.3.0").await.0, "needs_approval");
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
}

#[tokio::test]
async fn minor_under_patch_rule_waits_with_its_reason() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.3.0"]);

    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.3.0").await;
    assert_eq!(decision, "needs_approval");
    assert!(reason.contains("approver"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
    let audited = h.audit("rule_decision").await;
    assert_eq!(audited.len(), 1);
    assert_eq!(audited[0]["decision"], "needs_approval");
    assert_eq!(audited[0]["tag"], "v1.3.0");
    assert_eq!(audited[0]["digest"], digest("v1.3.0").as_ref());
}

#[tokio::test]
async fn first_deploy_is_manual_and_recorded() {
    let h = Harness::new(&config_text(PATCH_RULE)).await;
    h.report(PROD, HOST, None).await;
    h.fake.tags(PROD, &["v1.0.0"]);

    h.tick().await;
    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.0.0").await;
    assert_eq!(decision, "manual");
    assert!(reason.contains("first deploy"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
    assert_eq!(h.audit("rule_decision").await.len(), 1);
}

#[tokio::test]
async fn running_state_comes_from_reports() {
    let h = Harness::new(&config_text(PATCH_RULE)).await;
    h.report(PROD, HOST, None).await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "manual");
    assert_eq!(h.deploys(PROD).await, []);

    // The host now says it runs the version before: the same release is now
    // within the rule, without being verified again.
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await.len(), 1);
    assert_eq!(h.fake.verify_count(), 1);
    assert_eq!(h.audit("rule_decision").await.len(), 2);
}

#[tokio::test]
async fn refused_release_records_the_reason_once() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.4".to_owned(), not_signed());

    h.tick().await;
    h.tick().await;
    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("tag is not signed"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
    assert_eq!(h.fake.verify_count(), 1, "it is not verified again");
    assert_eq!(h.audit("rule_decision").await.len(), 1);
    assert_eq!(h.audit("release_seen").await.len(), 1);
}

#[tokio::test]
async fn a_refusal_is_looked_at_again_when_the_tag_moves() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.4".to_owned(), not_signed());
    h.tick().await;

    // Signed properly now: a new tag object under the same name.
    h.fake.locked().verify_fails.clear();
    h.fake.locked().listed.get_mut(PROD).unwrap()[0].object = "f".repeat(40);
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 2);
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_refusal_is_looked_at_again_when_the_configuration_changes() {
    let mut h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .verify_fails
        .insert("v1.2.4".to_owned(), not_signed());
    h.tick().await;

    h.fake.locked().verify_fails.clear();
    let changed = format!("{}\n# reviewed\n", config_text(PATCH_RULE));
    h.config = Arc::new(config::parse(changed.as_bytes()).unwrap());
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 2);
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
}

#[tokio::test]
async fn hostile_text_in_a_refusal_is_quoted_and_bounded() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    let hostile = format!("evil\n\u{1b}[31m{}", "x".repeat(100_000));
    h.fake.locked().verify_fails.insert(
        "v1.2.4".to_owned(),
        Box::new(move || {
            ReleaseError::Index(FetchError::Malformed {
                url: "https://example.test/x".to_owned(),
                reason: hostile.clone(),
            })
        }),
    );

    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.len() < 2 * MAX_STORED_TEXT_CHARS, "{}", reason.len());
    assert!(!reason.contains('\u{1b}'), "{reason}");
    assert!(!reason.contains('\n'), "{reason}");
    for kind in ["rule_decision", "release_seen"] {
        let detail = h.audit(kind).await.remove(0).to_string();
        assert!(detail.len() < 1024, "{kind}: {}", detail.len());
        assert!(!detail.contains('\u{1b}'), "{kind}: {detail}");
    }
}

#[tokio::test]
async fn several_attested_digests_refuse_the_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .more_candidates
        .insert("v1.2.4".to_owned(), vec![candidate("rerun", RUN_2)]);

    h.tick().await;
    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(
        reason.contains("run 1 attempt 1, run 2 attempt 1"),
        "{reason}"
    );
    assert_eq!(h.deploys(PROD).await, []);
    assert_eq!(h.fake.verify_count(), 1);
    assert_eq!(h.audit("rule_decision").await.len(), 1);
    let row = sqlx::query("SELECT commit_sha, digest FROM releases")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(
        row.get::<String, _>("commit_sha"),
        commit("v1.2.4").as_ref()
    );
    assert_eq!(row.get::<Option<String>, _>("digest"), None);
}

#[tokio::test]
async fn a_second_attempt_of_the_same_run_refuses_the_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.locked().more_candidates.insert(
        "v1.2.4".to_owned(),
        vec![candidate("rerun", RUN_1_ATTEMPT_2)],
    );

    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(
        reason.contains("run 1 attempt 1, run 1 attempt 2"),
        "{reason}"
    );
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn image_variants_from_one_run_pass_and_the_version_tags_digest_is_pinned() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .more_candidates
        .insert("v1.2.4".to_owned(), vec![candidate("alpine", RUN_1)]);

    h.tick().await;

    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    let deployed: String = sqlx::query_scalar("SELECT digest FROM deploys")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    assert_eq!(deployed, digest("v1.2.4").as_ref());
}

#[tokio::test]
async fn a_version_tags_digest_outside_the_attested_ones_refuses_the_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake
        .locked()
        .own_digest_unlisted
        .insert("v1.2.4".to_owned());
    h.fake
        .locked()
        .more_candidates
        .insert("v1.2.4".to_owned(), vec![candidate("alpine", RUN_1)]);

    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("version tag's digest"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn a_run_uri_that_does_not_parse_refuses_the_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.fake.locked().more_candidates.insert(
        "v1.2.4".to_owned(),
        vec![candidate(
            "odd",
            "https://github.com/example/app/actions/runs/1",
        )],
    );

    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("not a run and attempt"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn a_lower_release_can_still_go_when_a_higher_one_was_re_run() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4", "v1.2.5"]);
    h.fake
        .locked()
        .more_candidates
        .insert("v1.2.5".to_owned(), vec![candidate("rerun", RUN_2)]);

    h.tick().await;

    assert_eq!(h.decision(PROD, "v1.2.5").await.0, "refused");
    assert_eq!(
        h.deploys(PROD).await,
        [("v1.2.4".to_owned(), "queued".to_owned())]
    );
}

#[tokio::test]
async fn a_second_run_that_comes_after_verification_stops_the_deploy() {
    let h = Harness::running("v1.2.3").await;
    h.report_busy(PROD, HOST, "v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    assert_eq!(h.decision(PROD, "v1.2.4").await.0, "auto");
    assert_eq!(h.deploys(PROD).await, []);

    // A re-run workflow attests another digest while the host is busy.
    h.fake
        .locked()
        .more_candidates
        .insert("v1.2.4".to_owned(), vec![candidate("rerun", RUN_2)]);
    h.report(PROD, HOST, Some("v1.2.3")).await;
    h.tick().await;

    let (decision, reason) = h.decision(PROD, "v1.2.4").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("workflow runs"), "{reason}");
    assert_eq!(h.deploys(PROD).await, []);
}

#[tokio::test]
async fn unverifiable_candidate_is_ignored() {
    // Candidates that do not verify never come back from the source: what
    // verified is all that counts, here one digest and that of the release itself.
    // `landfall_origin::candidates` has the tests of what comes back.
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;
    assert_eq!(h.fake.enumerations.load(Ordering::SeqCst), 1);
    assert_eq!(h.deploys(PROD).await.len(), 1);
}

#[tokio::test]
async fn a_prerelease_the_rule_does_not_want_costs_no_request() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4-rc.1"]);

    h.tick().await;
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 0);
    let (decision, reason) = h.decision(PROD, "v1.2.4-rc.1").await;
    assert_eq!(decision, "refused");
    assert!(reason.contains("pre-release"), "{reason}");
    assert_eq!(h.audit("rule_decision").await.len(), 1);
}

#[tokio::test]
async fn a_tag_outside_the_pattern_is_not_a_release() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["nightly", "1.2.4", "v1.2.4.5"]);
    h.tick().await;
    assert_eq!(h.fake.verify_count(), 0);
    assert_eq!(h.decided_count().await, 0);
}

#[tokio::test]
async fn a_moved_tag_is_verified_again_and_its_new_look_recorded() {
    let h = Harness::running("v1.2.3").await;
    h.report_busy(PROD, HOST, "v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;

    h.fake.locked().listed.get_mut(PROD).unwrap()[0].object = "f".repeat(40);
    h.tick().await;

    assert_eq!(h.fake.verify_count(), 2);
    let seen = h.audit("release_seen").await;
    assert_eq!(seen.len(), 2);
    assert_eq!(seen[1]["tag_object"], "f".repeat(40));
    // What it decided did not change, so that is still one row.
    assert_eq!(h.audit("rule_decision").await.len(), 1);
}

#[tokio::test]
async fn where_a_release_came_from_is_kept() {
    let h = Harness::running("v1.2.3").await;
    h.fake.tags(PROD, &["v1.2.4"]);
    h.tick().await;

    let stored: String = sqlx::query_scalar("SELECT origin FROM releases")
        .fetch_one(h.store.pool())
        .await
        .unwrap();
    let stored: Value = serde_json::from_str(&stored).unwrap();
    assert_eq!(stored["digest"], digest("v1.2.4").as_ref());
    assert_eq!(stored["rekor_log_index"], 7);
    assert!(
        stored["san"]
            .as_str()
            .unwrap()
            .ends_with("refs/tags/v1.2.4\"")
    );
    let audited = h.audit("release_seen").await;
    assert_eq!(audited[0]["commit"], commit("v1.2.4").as_ref());
}
