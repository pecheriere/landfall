//! The plan, the report, and a deploy that never starts.

use std::fs;

use landfall_origin::attestation::VerifiedAttestation;
use landfall_origin::release::ReleaseOrigin;

use super::super::files::timestamp_id;
use super::super::{DeployError, DeployPlan, Outcome, run};
use super::{
    COMMIT, DIGEST, OLD, PINNED, PREVIOUS, STOP_FALSE, STOP_TRUE, backups, changes, container,
    count_stops, deploy, deploy_once, deployment, failing_check, fixture, healthy_deploy, options,
    override_text, reports, resolves, retrying_while_busy,
};

#[tokio::test]
async fn pull_failure_changes_nothing() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_pull([Err("manifest unknown")]);

    let err = deploy(&f).await.unwrap_err();

    assert!(matches!(err, DeployError::Pull { .. }), "{err}");
    assert_eq!(changes(&f), ["config", "config", "pull"]);
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(
        f.state.previous_override().unwrap().as_deref(),
        Some(PREVIOUS.as_bytes()),
        "the marker promised it; it is what is in place anyway"
    );
    assert_eq!(f.state.deployed().unwrap(), None);
    assert_eq!(backups(&f), Vec::<String>::new());
}

#[tokio::test]
async fn no_backup_declared_never_stops() {
    let f = fixture("");
    healthy_deploy(&f);
    assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
    assert_eq!(count_stops(&f), 0);

    let f = fixture("");
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    let report = deploy(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
    assert_eq!(count_stops(&f), 0, "rollback has nothing to restore either");
}

#[tokio::test]
async fn stop_false_backs_up_without_stopping() {
    let f = fixture(STOP_FALSE);
    healthy_deploy(&f);
    let report = deploy(&f).await.unwrap();
    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(count_stops(&f), 0);
    let kept = backups(&f);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert_eq!(
        fs::read_to_string(f.state.backups_dir().join(&kept[0]).join("data/db")).unwrap(),
        "before"
    );
}

#[tokio::test]
async fn report_is_written_on_every_outcome() {
    let deployed = fixture("");
    healthy_deploy(&deployed);
    let rolled_back = fixture("");
    resolves(&rolled_back, Some(OLD));
    failing_check(&rolled_back, OLD);
    let no_previous = fixture("");
    resolves(&no_previous, None);
    no_previous
        .docker
        .script_inspect([Ok(container(PINNED, false))]);
    let rollback_failed = fixture("");
    resolves(&rollback_failed, Some(OLD));
    rollback_failed.docker.script_compose_up([Err("no")]);

    for (f, kind) in [
        (&deployed, "deployed"),
        (&rolled_back, "rolled_back"),
        (&no_previous, "failed_no_previous"),
        (&rollback_failed, "rollback_failed"),
    ] {
        let report = deploy(f).await.unwrap();
        assert!(report.finished_at >= report.started_at);
        let written = reports(f);
        assert_eq!(written.len(), 1, "{kind}");
        assert_eq!(written[0]["outcome"]["kind"], kind);
        assert_eq!(written[0]["deployment"], "app/prod");
        assert_eq!(written[0]["tag"], "v1.2.3");
        assert_eq!(written[0]["digest"], DIGEST);
        let steps = written[0]["steps"].as_array().unwrap();
        assert_eq!(steps[0]["name"], "preflight", "{kind}");
        assert_eq!(steps[0]["result"]["status"], "ok", "{kind}");
        assert_eq!(steps.len(), report.steps.len(), "{kind}");
    }
}

#[tokio::test]
async fn concurrent_deploy_is_busy() {
    let f = fixture("");
    let held = f.state.lock().unwrap();
    let err = deploy_once(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::Busy(_)), "{err}");
    assert_eq!(f.docker.calls(), []);
    drop(held);

    healthy_deploy(&f);
    // Only one of the two takes the lock, but a lock that seems held for a
    // moment after it was let go would make both busy: wait for it first.
    retrying_while_busy(async || {
        let lock = f
            .state
            .lock()
            .map_err(|_| DeployError::Busy(f.deployment.id().clone()))?;
        drop(lock);
        Ok(())
    })
    .await
    .unwrap();
    let (first, second) = tokio::join!(deploy_once(&f), deploy_once(&f));
    let busy = [&first, &second]
        .iter()
        .filter(|r| matches!(r, Err(DeployError::Busy(_))))
        .count();
    let done = [&first, &second]
        .iter()
        .filter(|r| matches!(r, Ok(report) if report.outcome == Outcome::Deployed))
        .count();
    assert_eq!((busy, done), (1, 1), "{first:?} {second:?}");
}

#[tokio::test]
async fn plan_for_another_deployment_is_refused() {
    let f = fixture("");
    let mut plan = f.plan.clone();
    plan.deployment = "other/prod".parse().unwrap();
    let err = run(
        &f.docker,
        &f.state,
        &f.deployment,
        &f.dir,
        &plan,
        &options(),
    )
    .await
    .unwrap_err();
    assert!(matches!(err, DeployError::PlanMismatch { .. }), "{err}");
    assert_eq!(f.docker.calls(), []);
}

#[test]
fn plan_takes_digest_and_commit_from_the_verified_origin() {
    let d = deployment("");
    let origin = ReleaseOrigin {
        commit: COMMIT.parse().unwrap(),
        tag: None,
        attestation: VerifiedAttestation {
            digest: DIGEST.parse().unwrap(),
            san: String::new(),
            commit: COMMIT.parse().unwrap(),
            git_ref: String::new(),
            repo_id: 1,
            owner_id: 2,
            run_url: String::new(),
            rekor_log_index: 0,
            integrated_time: 0,
        },
        platforms: Vec::new(),
    };
    let plan = DeployPlan::from_verified(
        &d,
        &"v1.2.3".parse().unwrap(),
        semver::Version::new(1, 2, 3),
        &origin,
    );
    assert_eq!(plan.image(), PINNED);
    assert_eq!(plan.digest().as_ref(), DIGEST);
    assert_eq!(plan.commit().as_ref(), COMMIT);
    assert_eq!(plan.deployment(), d.id());
}

#[test]
fn ids_sort_by_time_and_are_plain_names() {
    let times = [
        "2026-01-02T03:04:05Z",
        "2026-01-02T03:04:05.000000001Z",
        "2026-01-02T03:04:05.1Z",
        "2026-01-02T03:04:06Z",
        "2026-10-01T00:00:00Z",
        "2027-01-01T00:00:00Z",
    ];
    let ids: Vec<String> = times
        .iter()
        .map(|t| timestamp_id(t.parse().unwrap()))
        .collect();
    let mut sorted = ids.clone();
    sorted.sort();
    assert_eq!(ids, sorted);
    for id in &ids {
        assert!(
            id.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "{id}"
        );
    }
    assert_eq!(ids[0], "2026-01-02T03-04-05-000000000Z");
}
