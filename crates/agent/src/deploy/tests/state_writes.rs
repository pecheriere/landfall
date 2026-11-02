//! A state or report write that fails, or outlives its deadline.

use std::fs;

use super::super::faults::{Fault, with_faults};
use super::super::{DeployError, Outcome};
use super::{
    OLD, PINNED, PREVIOUS, STOP_TRUE, changes, container, count_stops, count_ups, data, deploy,
    deployment, earlier_release, failing_check, fixture, healthy_deploy, image, interrupted,
    late_work_has_ended, new_passes_then_previous_passes, new_version_migrates, override_text,
    recovered, rendered, resolves, step_failed,
};
use crate::state::Phase;

#[tokio::test]
async fn failed_record_in_progress_leaves_no_marker_behind() {
    // The rename landed and the directory `fsync` after it failed.
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);

    let err = with_faults([("record in-progress", vec![Fault::FailAfter])], deploy(&f))
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(changes(&f), ["config"], "no new override read, no pull");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_record_in_progress_whose_clear_fails_names_recover() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);

    let err = with_faults(
        [
            ("record in-progress", vec![Fault::FailAfter]),
            ("clear in-progress", vec![Fault::Fail]),
        ],
        deploy(&f),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
    assert!(
        err.to_string().contains("recover --deployment app/prod"),
        "{err}"
    );
    assert_ne!(f.state.in_progress().unwrap(), None);

    let report = recovered(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn record_in_progress_past_its_deadline_blocks_and_recovers() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    let (release, late) = std::sync::mpsc::channel();

    let err = with_faults(
        [("record in-progress", vec![Fault::Late(late)])],
        deploy(&f),
    )
    .await
    .unwrap_err();

    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
    assert!(
        err.to_string().contains("recover --deployment app/prod"),
        "{err}"
    );
    assert_eq!(changes(&f), ["config"], "no new override read, no pull");
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
    assert_ne!(f.state.in_progress().unwrap(), None, "it did land");

    let report = recovered(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_move_to_deploying_is_a_refusal_before_anything_stops() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));

    let err = with_faults([("mark deploying", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(changes(&f), ["config", "config", "pull"], "no stop or up");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn move_to_deploying_past_its_deadline_keeps_the_marker() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    let (release, late) = std::sync::mpsc::channel();

    let err = with_faults([("mark deploying", vec![Fault::Late(late)])], deploy(&f))
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
    assert!(err.to_string().contains("recover"), "{err}");
    assert_eq!(changes(&f), ["config", "config", "pull"], "no stop or up");
    assert_ne!(f.state.in_progress().unwrap(), None);
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Deploying
    );
}

#[tokio::test]
async fn corrupt_deployed_record_is_refused_before_the_override_changes() {
    let f = fixture(STOP_TRUE);
    f.state.set_deployed(&earlier_release(&f)).unwrap();
    let path = f.state.backups_dir().with_file_name("deployed.json");
    fs::write(path, "not json").unwrap();
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);

    let err = deploy(&f).await.unwrap_err();

    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(changes(&f), ["config"]);
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_put_back_keeps_the_marker_and_names_recover() {
    // Both when the preflight passed and when it refused.
    for second_read in [Ok(image(Some(PINNED))), Err("bad project")] {
        let refused = second_read.is_err();
        let f = fixture(STOP_TRUE);
        f.docker
            .script_compose_service([Ok(image(Some(OLD))), second_read]);

        let err = with_faults(
            [("write override", vec![Fault::Pass, Fault::Fail])],
            deploy(&f),
        )
        .await
        .unwrap_err();

        assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("landfall-agent recover --deployment app/prod"),
            "{text}"
        );
        assert!(text.contains("previous override back"), "{text}");
        assert_eq!(text.contains("bad project"), refused, "{text}");
        assert_eq!(changes(&f), ["config", "config"], "no pull, stop or up");
        assert_eq!(override_text(&f.dir), rendered(&f));
        assert_ne!(f.state.in_progress().unwrap(), None);
        assert_eq!(
            f.state.previous_override().unwrap().as_deref(),
            Some(PREVIOUS.as_bytes())
        );
        let blocked = deploy(&f).await.unwrap_err();
        assert!(
            matches!(blocked, DeployError::Interrupted { .. }),
            "{blocked}"
        );

        let report = recovered(&f).await.unwrap();
        assert!(matches!(report.outcome, Outcome::NothingChanged { .. }));
        assert_eq!(count_ups(&f), 0);
        assert_eq!(override_text(&f.dir), PREVIOUS);
    }
}

#[tokio::test]
async fn failed_write_of_the_new_override_is_put_back() {
    // The rename landed and the `fsync` after it failed.
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);

    let err = with_faults([("write override", vec![Fault::FailAfter])], deploy(&f))
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(changes(&f), ["config"], "never read with it, nor pulled");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn new_override_past_its_deadline_blocks_rather_than_racing_it() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    let (release, late) = std::sync::mpsc::channel();

    let err = with_faults([("write override", vec![Fault::Late(late)])], deploy(&f))
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{err}");
    assert!(err.to_string().contains("recover"), "{err}");
    assert_ne!(f.state.in_progress().unwrap(), None);
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
    assert_eq!(override_text(&f.dir), rendered(&f), "it did land");

    recovered(&f).await.unwrap();
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn failed_clear_after_a_refusal_says_so_and_stays_blocked() {
    let f = fixture(STOP_TRUE);
    f.docker
        .script_compose_service([Ok(image(Some(OLD))), Err("bad project")]);

    let err = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap_err();

    let text = err.to_string();
    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{text}");
    assert!(text.contains("bad project"), "{text}");
    assert!(text.contains("marker"), "{text}");
    assert!(text.contains("recover --deployment app/prod"), "{text}");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_ne!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_clear_after_a_failed_pull_says_so_and_stays_blocked() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_pull([Err("manifest unknown")]);

    let err = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap_err();

    let text = err.to_string();
    assert!(matches!(err, DeployError::LeftBlocked { .. }), "{text}");
    assert!(text.contains("manifest unknown"), "{text}");
    assert!(text.contains("recover --deployment app/prod"), "{text}");
    assert_ne!(f.state.in_progress().unwrap(), None);
    assert_eq!(count_stops(&f), 0);

    let report = recovered(&f).await.unwrap();
    assert!(
        matches!(report.outcome, Outcome::NothingChanged { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_stops(&f), 0);
    assert_eq!(count_ups(&f), 0);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_record_rolls_back_and_puts_the_earlier_record_back() {
    let f = fixture("");
    let earlier = earlier_release(&f);
    f.state.set_deployed(&earlier).unwrap();
    new_passes_then_previous_passes(&f);

    let report = with_faults([("record deployed", vec![Fault::FailAfter])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("record_deployed")),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.deployed().unwrap(), Some(earlier));
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn failed_first_record_rolls_back_to_no_record() {
    let f = fixture("");
    new_passes_then_previous_passes(&f);

    let report = with_faults([("record deployed", vec![Fault::FailAfter])], deploy(&f))
        .await
        .unwrap();

    assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
    assert_eq!(f.state.deployed().unwrap(), None);
}

#[tokio::test]
async fn record_left_behind_with_a_failed_rollback_never_recovers_to_deployed() {
    // The worst case: the release's record is on disk and matches, the
    // rollback failed, and it could not even put the earlier record back.
    let f = fixture("");
    let earlier = earlier_release(&f);
    f.state.set_deployed(&earlier).unwrap();
    new_passes_then_previous_passes(&f);

    let report = with_faults(
        [
            ("record deployed", vec![Fault::FailAfter]),
            ("restore deployed", vec![Fault::Fail]),
        ],
        deploy(&f),
    )
    .await
    .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("restore_deployed")),
        "{:?}",
        report.outcome
    );
    let left = f.state.deployed().unwrap().unwrap();
    let marker = f.state.in_progress().unwrap().unwrap();
    assert_eq!(left.deploy_id, marker.deploy_id, "it does match");
    assert_eq!(marker.phase, Phase::RollingBack);

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.deployed().unwrap(), Some(earlier));
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn record_landing_past_its_deadline_is_not_a_finished_deploy() {
    let f = fixture("");
    let earlier = earlier_release(&f);
    f.state.set_deployed(&earlier).unwrap();
    new_passes_then_previous_passes(&f);
    let (release, late) = std::sync::mpsc::channel();

    let report = with_faults([("record deployed", vec![Fault::Late(late)])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("may still land")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 1, "nothing restarted under a late write");
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
    assert_ne!(f.state.deployed().unwrap(), Some(earlier.clone()));

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.deployed().unwrap(), Some(earlier));
}

#[tokio::test]
async fn late_write_of_the_switch_stops_the_rollback() {
    // Preflight's write and put-back work; the third write is the switch.
    let f = fixture("");
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(OLD, true))]);
    let (release, late) = std::sync::mpsc::channel();

    let report = with_faults(
        [(
            "write override",
            vec![Fault::Pass, Fault::Pass, Fault::Late(late)],
        )],
        deploy(&f),
    )
    .await
    .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { reason, rollback_reason }
            if reason.contains("write_override") && rollback_reason.contains("may still land")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 0);
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RollingBack
    );
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
    assert_eq!(override_text(&f.dir), rendered(&f), "it did land");

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    let report = recovered(&f).await.unwrap();
    assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn writes_of_the_rollback_past_their_deadline_fail_it() {
    for (op, runs_before, step) in [
        ("mark rolling back", 0, "mark_rolling_back"),
        ("write override", 3, "restore_override"),
        ("restore deployed", 0, "restore_deployed"),
        ("mark rolled back", 0, "mark_rolled_back"),
    ] {
        let f = fixture("");
        resolves(&f, Some(OLD));
        failing_check(&f, OLD);
        let (release, late) = std::sync::mpsc::channel();
        let mut faults: Vec<Fault> = (0..runs_before).map(|_| Fault::Pass).collect();
        faults.push(Fault::Late(late));

        let report = with_faults([(op, faults)], deploy(&f)).await.unwrap();

        assert!(
            matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
                if rollback_reason.contains(step)
                    && rollback_reason.contains("result is unknown")),
            "{op}: {:?}",
            report.outcome
        );
        assert_ne!(f.state.in_progress().unwrap(), None, "{op}");
        release.send(()).unwrap();
        late_work_has_ended(&f).await;
    }
}

#[tokio::test]
async fn marker_that_cannot_say_rolling_back_undoes_nothing() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);

    let report = with_faults([("mark rolling back", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("mark_rolling_back")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 1);
    assert_eq!(count_stops(&f), 1, "only the backup's");
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Deploying
    );
}

#[tokio::test]
async fn rolled_back_phase_is_only_cleared_and_keeps_later_writes() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    new_version_migrates(&f);

    let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_failed(&report, "clear_in_progress"));
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RolledBack
    );
    let blocked = deploy(&f).await.unwrap_err();
    assert!(
        matches!(blocked, DeployError::Interrupted { .. }),
        "{blocked}"
    );

    // The previous version is healthy and has moved on.
    fs::write(f.dir.join("data/db"), "written since").unwrap();
    let calls = f.docker.calls().len();
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        data(&f),
        "written since",
        "the backup is not restored again"
    );
    assert_eq!(f.docker.calls().len(), calls, "nothing is run");
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn rolled_back_phase_of_a_first_deploy_stays_failed_no_previous() {
    let f = fixture("");
    resolves(&f, None);
    f.docker.script_inspect([Ok(container(PINNED, false))]);

    let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();
    assert!(matches!(report.outcome, Outcome::FailedNoPrevious { .. }));

    let report = recovered(&f).await.unwrap();
    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_clear_after_a_deploy_blocks_until_recover_finishes_it() {
    let f = fixture("");
    healthy_deploy(&f);

    let report = with_faults([("clear in-progress", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert!(step_failed(&report, "clear_in_progress"));
    assert!(report.leaves_deploys_blocked());
    let blocked = deploy(&f).await.unwrap_err();
    assert!(
        matches!(blocked, DeployError::Interrupted { .. }),
        "{blocked}"
    );

    let ups = count_ups(&f);
    let report = recovered(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(count_ups(&f), ups, "the release stays as it is");
    assert_eq!(override_text(&f.dir), rendered(&f));
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn recover_restores_the_paths_the_backup_was_taken_of() {
    for later_config in ["", "backup = { paths = [\"other\"], stop = true }\n"] {
        let mut f = fixture(STOP_TRUE);
        interrupted(&f);
        f.deployment = deployment(later_config);
        f.docker.script_compose_service([Ok(image(Some(OLD)))]);
        f.docker.script_inspect([Ok(container(OLD, true))]);

        let report = recovered(&f).await.unwrap();

        assert!(
            matches!(report.outcome, Outcome::RolledBack { .. }),
            "{later_config}: {:?}",
            report.outcome
        );
        assert_eq!(data(&f), "before", "{later_config}");
    }
}

#[tokio::test]
async fn failed_report_write_changes_no_outcome() {
    let deployed = fixture("");
    healthy_deploy(&deployed);
    let rolled_back = fixture("");
    resolves(&rolled_back, Some(OLD));
    failing_check(&rolled_back, OLD);

    for (f, kind) in [(&deployed, "deployed"), (&rolled_back, "rolled back")] {
        let report = with_faults([("write report", vec![Fault::Fail])], deploy(f))
            .await
            .unwrap();
        let expected = if kind == "deployed" {
            report.outcome == Outcome::Deployed
        } else {
            matches!(report.outcome, Outcome::RolledBack { .. })
        };
        assert!(expected, "{kind}: {:?}", report.outcome);
        assert_eq!(f.state.in_progress().unwrap(), None, "{kind}");
        assert_eq!(
            f.state.deployed().unwrap().is_some(),
            kind == "deployed",
            "{kind}"
        );
    }
}

#[tokio::test]
async fn failed_prune_is_reported_and_changes_no_outcome() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);

    let report = with_faults([("prune backups", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert!(step_failed(&report, "prune_backups"));
    assert!(!report.leaves_deploys_blocked());
    assert_ne!(f.state.deployed().unwrap(), None);
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(override_text(&f.dir), rendered(&f));
}
