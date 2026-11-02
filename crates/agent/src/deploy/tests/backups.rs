//! Backups: deadlines, pruning, and what is kept.

use std::fs;
use std::sync::{Arc, Mutex};

use super::super::faults::{Fault, with_faults};
use super::super::{EngineOptions, Outcome, recover};
use super::{
    DEPLOY_ID, Fixture, OLD, STOP_TRUE, backups, container, deploy, deploy_with, earlier_release,
    failing_check, fixture, healthy_deploy, late_work_has_ended, options, recovered, resolves,
    step_failed, step_names,
};
use crate::state::{Deployed, InProgress, Phase, RecordedBackup};
use crate::testing::Call;

#[tokio::test]
async fn a_backup_past_its_deadline_keeps_the_prune_off_its_partial_copy() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(OLD, true))]);
    // The copy a snapshot is still writing, from when the service stopped.
    let partial = f
        .state
        .backups_dir()
        .join("2000-01-01T00-00-00-000000000Z.partial");
    let (backups_dir, unfinished) = (f.state.backups_dir(), partial.clone());
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeStop { .. }) {
            fs::create_dir_all(&backups_dir).unwrap();
            fs::create_dir(&unfinished).unwrap();
        }
    });
    let (release, released) = std::sync::mpsc::channel();

    let report = with_faults([("backup", vec![Fault::Late(released)])], deploy(&f))
        .await
        .unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert!(step_failed(&report, "backup"));
    assert!(step_failed(&report, "prune_backups"), "the report says so");
    assert_eq!(
        f.state.in_progress().unwrap(),
        None,
        "the skipped prune changes no outcome"
    );
    assert!(partial.exists(), "a snapshot may still be writing it");
    release.send(()).unwrap();
    late_work_has_ended(&f).await;
}

#[tokio::test]
async fn keeping_one_backup_keeps_it_until_the_new_one_exists() {
    let f = fixture(STOP_TRUE);
    let old = old_backups(&f, 3);
    healthy_deploy(&f);
    let at_stop = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&at_stop);
    let backups_dir = f.state.backups_dir();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeStop { .. }) {
            log.lock()
                .unwrap()
                .push(fs::read_dir(&backups_dir).unwrap().count());
        }
    });

    let report = deploy_with(
        &f,
        &EngineOptions {
            backups_kept: 1,
            ..options()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(*at_stop.lock().unwrap(), [1], "the newest stays for now");
    let kept = backups(&f);
    assert_eq!(kept.len(), 1, "{kept:?}");
    assert!(!old.contains(&kept[0]), "{kept:?}");
}

/// `how_many` old backups, which sort before anything the deploy takes.
fn old_backups(f: &Fixture, how_many: usize) -> Vec<String> {
    fs::create_dir_all(f.state.backups_dir()).unwrap();
    (1..=how_many)
        .map(|day| {
            let name = format!("2000-01-{day:02}T00-00-00-000000000Z");
            fs::create_dir(f.state.backups_dir().join(&name)).unwrap();
            name
        })
        .collect()
}

#[tokio::test]
async fn room_is_made_before_the_backup() {
    let f = fixture(STOP_TRUE);
    old_backups(&f, 5);
    healthy_deploy(&f);
    // How many there are when the service stops for the backup.
    let at_stop = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&at_stop);
    let backups_dir = f.state.backups_dir();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeStop { .. }) {
            log.lock()
                .unwrap()
                .push(fs::read_dir(&backups_dir).unwrap().count());
        }
    });

    let report = deploy(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(
        *at_stop.lock().unwrap(),
        [2],
        "one short of the number kept"
    );
}

#[tokio::test]
async fn a_failed_prune_before_the_backup_changes_nothing() {
    let f = fixture(STOP_TRUE);
    old_backups(&f, 5);
    healthy_deploy(&f);

    let report = with_faults([("prune before backup", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert!(step_failed(&report, "prune_before_backup"));
    assert_eq!(backups(&f).len(), 3, "the prune at the end still ran");
}

#[tokio::test]
async fn a_completed_rollback_prunes_once_the_marker_is_gone() {
    let f = fixture(STOP_TRUE);
    old_backups(&f, 5);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);

    // The prune before the backup fails, which leaves this one the work.
    let report = with_faults([("prune before backup", vec![Fault::Fail])], deploy(&f))
        .await
        .unwrap();

    assert!(matches!(report.outcome, Outcome::RolledBack { .. }));
    assert_eq!(backups(&f).len(), 3, "{:?}", backups(&f));
    let names = step_names(&report);
    let clear = names
        .iter()
        .position(|s| *s == "clear_in_progress")
        .unwrap();
    assert_eq!(names[clear + 1], "prune_backups", "{names:?}");
}

#[tokio::test]
async fn a_rollback_whose_marker_stays_does_not_prune_until_recover_clears_it() {
    let f = fixture(STOP_TRUE);
    old_backups(&f, 5);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    let report = with_faults(
        [
            ("prune before backup", vec![Fault::Fail]),
            ("clear in-progress", vec![Fault::Fail]),
        ],
        deploy(&f),
    )
    .await
    .unwrap();
    assert!(!step_names(&report).contains(&"prune_backups"));
    assert_eq!(backups(&f).len(), 6);

    let report = recovered(&f).await.unwrap();

    assert!(step_names(&report).contains(&"prune_backups"));
    assert_eq!(backups(&f).len(), 3);
}

#[tokio::test]
async fn the_backup_a_marker_names_is_never_pruned() {
    // A deploy that finished, with only its clean-up left. Its backup is
    // the oldest here, and a later `recover` may yet be told to use it.
    let f = fixture(STOP_TRUE);
    let old = old_backups(&f, 2);
    fs::create_dir(f.state.backups_dir().join("2030-01-01T00-00-00-000000000Z")).unwrap();
    f.state
        .set_in_progress(&InProgress {
            deploy_id: DEPLOY_ID.to_owned(),
            phase: Phase::Deploying,
            tag: f.plan.tag().clone(),
            digest: f.plan.digest().clone(),
            previous_can_start: true,
            backup: Some(RecordedBackup {
                id: old[0].clone(),
                paths: vec!["data".to_owned()],
            }),
            started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
        })
        .unwrap();
    f.state
        .set_deployed(&Deployed {
            deploy_id: DEPLOY_ID.to_owned(),
            ..earlier_release(&f)
        })
        .unwrap();

    let report = recover(
        &f.docker,
        &f.state,
        &f.deployment,
        &f.dir,
        &EngineOptions {
            backups_kept: 1,
            ..options()
        },
    )
    .await
    .unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(
        backups(&f),
        [old[0].clone(), "2030-01-01T00-00-00-000000000Z".to_owned()],
        "the newest, and the one named"
    );
}
