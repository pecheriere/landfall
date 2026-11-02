//! Recovery from each phase the marker can name.

use std::fs;

use super::super::Outcome;
use super::super::faults::{Fault, with_faults};
use super::{
    Fixture, OLD, PINNED, PREVIOUS, STOP_TRUE, container, count_stops, count_ups, crash_at, data,
    deploy, earlier_release, failing_check, fixture, image, new_version_migrates, override_text,
    recovered, resolves, step_names,
};
use crate::compose::OVERRIDE_FILE;
use crate::state::Phase;
use crate::testing::Call;

#[tokio::test]
async fn recover_from_a_crash_before_the_backup_restores_nothing() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));

    crash_at(&f, 0, |c| matches!(c, Call::ComposeStop { .. })).await;

    let marker = f.state.in_progress().unwrap().unwrap();
    assert_eq!(marker.phase, Phase::Deploying);
    assert_eq!(marker.backup, None);
    assert_eq!(override_text(&f.dir), PREVIOUS);

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker.script_inspect([Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(!step_names(&report).contains(&"restore_backup"));
    assert_eq!(count_ups(&f), 1, "the service is started again");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(data(&f), "before");
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn recover_from_a_crash_before_the_restore_rolls_back_again() {
    let f = fixture(STOP_TRUE);
    let earlier = earlier_release(&f);
    f.state.set_deployed(&earlier).unwrap();
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    new_version_migrates(&f);

    // The second stop is the rollback's, ahead of the restore.
    crash_at(&f, 1, |c| matches!(c, Call::ComposeStop { .. })).await;

    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RollingBack
    );

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_names(&report).contains(&"restore_backup"));
    assert_eq!(data(&f), "before");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.deployed().unwrap(), Some(earlier));
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn recover_from_a_restore_that_failed_part_way_restores_again() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
    new_version_migrates(&f);

    let report = with_faults([("restore backup", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RollingBack
    );

    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_names(&report).contains(&"restore_backup"));
    assert_eq!(data(&f), "before");
}

#[tokio::test]
async fn recover_after_the_restore_keeps_what_the_previous_version_wrote() {
    let f = fixture(STOP_TRUE);
    let earlier = earlier_release(&f);
    f.state.set_deployed(&earlier).unwrap();
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, false))]);
    new_version_migrates(&f);

    // The previous version is back and fails its checks.
    let report = deploy(&f).await.unwrap();
    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("check_previous")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );
    assert_eq!(data(&f), "before");

    // It runs on for hours, then its dependency is fixed.
    fs::write(f.dir.join("data/db"), "written since").unwrap();
    let stops = count_stops(&f);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker
        .script_inspect_after_up(3, [Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(data(&f), "written since");
    assert_eq!(count_stops(&f), stops, "the service is not stopped");
    assert_eq!(
        step_names(&report),
        [
            "start_previous",
            "verify_previous_image",
            "check_previous",
            "mark_rolled_back",
            "clear_in_progress",
            "prune_backups",
        ]
    );
    assert_eq!(f.state.deployed().unwrap(), Some(earlier));
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn a_crash_right_after_the_restore_does_not_restore_again() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    new_version_migrates(&f);

    // The second `up` is the rollback's: the data is back by then.
    crash_at(&f, 1, |c| matches!(c, Call::ComposeUp { .. })).await;

    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker
        .script_inspect_after_up(3, [Ok(container(OLD, true))]);
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(!step_names(&report).contains(&"restore_backup"));
    assert_eq!(data(&f), "before");
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn restored_phase_of_a_first_deploy_stops_the_service_and_starts_nothing() {
    let f = fixture(STOP_TRUE);
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    resolves(&f, None);
    f.docker.script_inspect([Ok(container(PINNED, false))]);

    let report = with_faults([("mark rolled back", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();
    assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );

    let (ups, stops) = (count_ups(&f), count_stops(&f));
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_names(&report).contains(&"stop_service"));
    assert_eq!(
        (count_ups(&f), count_stops(&f)),
        (ups, stops + 1),
        "what it reports as stopped is stopped, with no previous version to lose writes from"
    );
    assert_eq!(f.state.in_progress().unwrap(), None);
}

/// The new version fails its check, and the previous one passes after an `up`.
fn fails_then_previous_passes(f: &Fixture) {
    resolves(f, Some(OLD));
    failing_check(f, OLD);
    new_version_migrates(f);
}

#[tokio::test]
async fn marker_that_cannot_say_restored_starts_nothing_and_recover_restores_again() {
    let f = fixture(STOP_TRUE);
    fails_then_previous_passes(&f);

    let report = with_faults([("mark restored", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("mark_restored")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 1, "the rollback's `up` did not run");
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RollingBack
    );
    assert_eq!(data(&f), "before");

    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_names(&report).contains(&"restore_backup"));
    assert_eq!(count_ups(&f), 2);
    assert_eq!(data(&f), "before");
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn marker_that_says_restored_though_its_write_failed_is_not_restored_again() {
    let f = fixture(STOP_TRUE);
    fails_then_previous_passes(&f);

    let report = with_faults([("mark restored", vec![Fault::FailAfter])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("mark_restored")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 1, "the rollback's `up` did not run");
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );

    // What the marker promises holds: the restore is not repeated.
    fs::write(f.dir.join("data/db"), "written since").unwrap();
    let report = recovered(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(!step_names(&report).contains(&"restore_backup"));
    assert_eq!(count_ups(&f), 2);
    assert_eq!(data(&f), "written since");
    assert_eq!(f.state.in_progress().unwrap(), None);
}
