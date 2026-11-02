//! Recovery of an interrupted deploy, and crashes at each step.

use std::fs;

use super::super::faults::{Fault, with_faults};
use super::super::{DeployError, Outcome};
use super::{
    DEPLOY_ID, OLD, PINNED, PREVIOUS, STOP_TRUE, changes, container, count_stops, count_ups,
    crash_at, data, deploy, earlier_release, fixture, healthy_deploy, image, interrupted,
    override_text, recovered, rendered, reports, resolves, step_names,
};
use crate::compose::OVERRIDE_FILE;
use crate::journal::Priority;
use crate::state::{Deployed, InProgress, Phase};
use crate::testing::Call;

#[tokio::test]
async fn interrupted_deploy_blocks_until_recovered() {
    let f = fixture(STOP_TRUE);
    interrupted(&f);

    let err = deploy(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::Interrupted { .. }), "{err}");
    assert!(
        err.to_string()
            .contains("landfall-agent recover --deployment app/prod"),
        "{err}"
    );
    assert_eq!(f.docker.calls(), [], "refused before anything ran");
    assert_eq!(data(&f), "half migrated");

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker.script_inspect([Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();
    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("interrupted")),
        "{:?}",
        report.outcome
    );
    assert_eq!(changes(&f), ["stop", "up", "config"]);
    assert_eq!(data(&f), "before");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(reports(&f).len(), 1);

    healthy_deploy(&f);
    assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
}

#[tokio::test]
async fn recover_after_a_failed_rollback_can_succeed() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    f.docker.script_compose_up([Err("daemon gone")]);
    let report = deploy(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));

    f.docker.script_compose_up([Ok(())]);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker.script_inspect([Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn recover_finishes_a_deploy_that_had_already_succeeded() {
    // The agent died after recording the deploy and before clearing the
    // marker: the release passed its checks, so it stays.
    let f = fixture("");
    f.state.set_previous_override(PREVIOUS.as_bytes()).unwrap();
    let started_at = "2026-11-01T10:00:00Z".parse().unwrap();
    f.state
        .set_in_progress(&InProgress {
            deploy_id: DEPLOY_ID.to_owned(),
            phase: Phase::Deploying,
            tag: f.plan.tag().clone(),
            digest: f.plan.digest().clone(),
            previous_can_start: true,
            backup: None,
            started_at,
        })
        .unwrap();
    // The id decides, not the clock, which here went backwards.
    f.state
        .set_deployed(&Deployed {
            deploy_id: DEPLOY_ID.to_owned(),
            tag: f.plan.tag().clone(),
            version: f.plan.version().clone(),
            digest: f.plan.digest().clone(),
            commit: f.plan.commit().clone(),
            deployed_at: "2026-11-01T09:59:00Z".parse().unwrap(),
        })
        .unwrap();
    let new = rendered(&f);
    fs::write(f.dir.join(OVERRIDE_FILE), &new).unwrap();

    let report = recovered(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(f.docker.calls(), []);
    assert_eq!(override_text(&f.dir), new);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn redeploy_of_the_same_digest_interrupted_is_rolled_back() {
    // deployed.json names the same release, from before this deploy, and
    // says it is later: the clock doesn't decide.
    let f = fixture(STOP_TRUE);
    f.state
        .set_deployed(&Deployed {
            tag: f.plan.tag().clone(),
            version: f.plan.version().clone(),
            digest: f.plan.digest().clone(),
            commit: f.plan.commit().clone(),
            deployed_at: "2026-11-01T11:00:00Z".parse().unwrap(),
            ..earlier_release(&f)
        })
        .unwrap();
    interrupted(&f);
    f.docker.script_compose_service([Ok(image(Some(PINNED)))]);
    f.docker.script_inspect([Ok(container(PINNED, true))]);

    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn crash_during_preflight_is_recovered_without_touching_the_service() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));

    crash_at(&f, 0, |c| matches!(c, Call::ComposeServiceChecked { .. })).await;

    assert_eq!(override_text(&f.dir), rendered(&f), "the new one is in");
    let marker = f.state.in_progress().unwrap().unwrap();
    assert_eq!(marker.phase, Phase::Preflight);
    assert_eq!(marker.backup, None);
    assert_eq!(
        f.state.previous_override().unwrap().as_deref(),
        Some(PREVIOUS.as_bytes()),
        "never the new release's override"
    );
    let refused = deploy(&f).await.unwrap_err();
    assert!(
        matches!(refused, DeployError::Interrupted { .. }),
        "{refused}"
    );

    let calls = f.docker.calls().len();
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::NothingChanged { .. }),
        "{:?}",
        report.outcome
    );
    assert_ne!(report.outcome.priority(), Priority::Critical);
    assert_eq!(
        f.docker.calls().len(),
        calls,
        "no stop, up, check or anything else"
    );
    assert_eq!(count_stops(&f), 0);
    assert_eq!(count_ups(&f), 0);
    assert_eq!(
        step_names(&report),
        [
            "read_previous_override",
            "restore_override",
            "clear_in_progress"
        ]
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(reports(&f)[0]["outcome"]["kind"], "nothing_changed");

    // The next deploy still goes back to the right override.
    healthy_deploy(&f);
    assert_eq!(deploy(&f).await.unwrap().outcome, Outcome::Deployed);
    assert_eq!(
        f.state.previous_override().unwrap().as_deref(),
        Some(PREVIOUS.as_bytes())
    );
}

#[tokio::test]
async fn preflight_recover_that_cannot_put_the_override_back_keeps_the_marker() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    crash_at(&f, 0, |c| matches!(c, Call::ComposeServiceChecked { .. })).await;

    let report = with_faults([("write override", vec![Fault::Fail])], recovered(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("restore_override")),
        "{:?}",
        report.outcome
    );
    assert_ne!(f.state.in_progress().unwrap(), None);

    let report = recovered(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn crash_during_the_pull_changes_nothing() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));

    crash_at(&f, 0, |c| matches!(c, Call::Pull(_))).await;

    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Preflight,
        "nothing is touched by a pull"
    );
    let calls = f.docker.calls().len();
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::NothingChanged { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.docker.calls().len(), calls, "no stop, up or check");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn crash_right_after_the_pull_may_have_touched_the_service() {
    // The stop for the backup is the first thing that touches it.
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));

    crash_at(&f, 0, |c| matches!(c, Call::ComposeStop { .. })).await;

    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Deploying,
        "on disk before the stop"
    );
}
