//! Rollback, and a first deploy that fails.

use std::fs;
use std::sync::Arc;
use std::time::Duration;

use super::super::{DeployError, EngineOptions, Outcome, StepDetail};
use super::{
    OLD, PINNED, STOP_TRUE, changes, container, count_stops, count_ups, data, deploy, deploy_with,
    failing_check, fixture, healthy_deploy, new_version_migrates, options, override_text, resolves,
};
use crate::compose::{OVERRIDE_FILE, PLACEHOLDER};
use crate::journal::Priority;
use crate::state::Phase;
use crate::testing::Call;

#[tokio::test]
async fn rollback_to_the_wrong_image_fails_without_naming_it() {
    let f = fixture("");
    resolves(&f, Some("example/app:token-s3cret"));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container("something/else", true))]);

    let report = deploy(&f).await.unwrap();

    let Outcome::RollbackFailed {
        rollback_reason, ..
    } = &report.outcome
    else {
        panic!("{:?}", report.outcome);
    };
    assert!(
        rollback_reason.contains("verify_previous_image"),
        "{rollback_reason}"
    );
    assert!(!rollback_reason.contains("s3cret"), "{rollback_reason}");
}

#[tokio::test]
async fn failed_rollback_is_critical_and_blocks() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    f.docker.script_compose_up([Err("daemon gone")]);

    let report = deploy(&f).await.unwrap();

    let Outcome::RollbackFailed {
        reason,
        rollback_reason,
    } = &report.outcome
    else {
        panic!("{:?}", report.outcome);
    };
    assert!(reason.contains("daemon gone"), "{reason}");
    assert!(
        rollback_reason.contains("start_previous"),
        "{rollback_reason}"
    );
    assert_eq!(report.outcome.priority(), Priority::Critical);
    assert_ne!(f.state.in_progress().unwrap(), None);

    let refused = deploy(&f).await.unwrap_err();
    assert!(
        matches!(refused, DeployError::Interrupted { .. }),
        "{refused}"
    );
    assert!(refused.to_string().contains("recover"), "{refused}");
}

/// Whatever the failed `up` left is what runs: the agent adds no stop.
#[tokio::test]
async fn a_failed_up_of_the_previous_version_stops_nothing() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    f.docker.script_compose_up([Ok(()), Err("daemon gone")]);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("start_previous")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_stops(&f), 0);
    assert_ne!(f.state.in_progress().unwrap(), None);
    assert!(report.leaves_deploys_blocked());
}

/// With a backup the service was stopped to restore it, before the `up`.
/// That is the one stop on this path, and none follows the failure.
#[tokio::test]
async fn a_failed_up_after_a_restore_adds_no_stop_after_it() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    f.docker.script_compose_up([Ok(()), Err("daemon gone")]);

    let report = deploy(&f).await.unwrap();

    assert!(matches!(report.outcome, Outcome::RollbackFailed { .. }));
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );
    assert_eq!(
        changes(&f).last(),
        Some(&"up"),
        "the failed up is the last thing done to the service"
    );
}

#[tokio::test]
async fn the_report_says_what_the_backup_copied_and_what_each_check_took() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);

    let report = deploy(&f).await.unwrap();

    let detail = |name: &str| {
        report
            .steps
            .iter()
            .find(|step| step.name == name)
            .and_then(|step| step.detail.clone())
    };
    let Some(StepDetail::Backup { stats }) = detail("backup") else {
        panic!("{report:?}");
    };
    assert_eq!((stats.files, stats.bytes), (1, 6));
    let Some(StepDetail::Checks { checks }) = detail("checks") else {
        panic!("{report:?}");
    };
    assert_eq!(checks.len(), 1);
    assert_eq!(checks[0].attempts, 2, "a pass and its confirmation");
    assert!(checks[0].check.starts_with("checks[0]"), "{checks:?}");
    assert_eq!(detail("up"), None);

    let json = serde_json::to_value(&report).unwrap();
    let steps = json["steps"].as_array().unwrap();
    let shown = steps.iter().find(|step| step["name"] == "checks").unwrap();
    assert_eq!(shown["detail"]["kind"], "checks");
    assert_eq!(shown["detail"]["checks"][0]["attempts"], 2);
    let plain = steps.iter().find(|step| step["name"] == "up").unwrap();
    assert!(plain.get("detail").is_none(), "{plain}");
}

#[tokio::test]
async fn a_failed_run_of_the_checks_still_reports_what_they_took() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);

    let report = deploy(&f).await.unwrap();

    for name in ["checks", "check_previous"] {
        let step = report.steps.iter().find(|step| step.name == name).unwrap();
        let Some(StepDetail::Checks { checks }) = &step.detail else {
            panic!("{step:?}");
        };
        assert!(checks[0].attempts >= 1, "{name}: {checks:?}");
    }
}

#[tokio::test]
async fn stop_failure_in_rollback_never_restores_or_starts() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_inspect([Ok(container(PINNED, false))]);
    f.docker.script_compose_stop([Ok(()), Err("will not stop")]);
    new_version_migrates(&f);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("will not stop")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        data(&f),
        "migrated",
        "a running container could outrun a restore"
    );
    assert_eq!(
        count_ups(&f),
        1,
        "nothing was started after the failed stop"
    );
    assert_ne!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn restore_failure_leaves_the_service_stopped() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_inspect([Ok(container(PINNED, false))]);
    // The backup disappears after the new version started.
    let backups_dir = f.state.backups_dir();
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            fs::remove_dir_all(&backups_dir).unwrap();
        }
    });

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("restore_backup")),
        "{:?}",
        report.outcome
    );
    assert_eq!(count_ups(&f), 1, "half-restored data is not started");
    assert_eq!(count_stops(&f), 2);
    assert_eq!(
        f.state.in_progress().unwrap().unwrap().phase,
        Phase::RollingBack,
        "the next recover has to restore again"
    );
}

#[tokio::test]
async fn restore_past_its_deadline_is_a_failed_rollback() {
    let f = fixture(STOP_TRUE);
    for i in 0..300 {
        fs::write(f.dir.join(format!("data/file-{i}")), "x").unwrap();
    }
    resolves(&f, Some(OLD));
    f.docker.script_inspect([Ok(container(PINNED, false))]);

    let report = deploy_with(
        &f,
        &EngineOptions {
            restore_deadline: Duration::ZERO,
            ..options()
        },
    )
    .await
    .unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("restore_backup")
                && rollback_reason.contains("result is unknown")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        count_ups(&f),
        1,
        "nothing starts on top of a running restore"
    );
    assert_ne!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn off_thread_work_keeps_the_lock_past_its_deadline() {
    let f = fixture("");
    let lock = Arc::new(f.state.lock().unwrap());
    let (release, wait) = std::sync::mpsc::channel::<()>();
    let (finished, done) = tokio::sync::oneshot::channel();

    let result = super::super::off_thread(&lock, "slow", Duration::from_millis(5), move || {
        let _ = wait.recv();
        let _ = finished.send(());
        Ok::<(), crate::state::StateError>(())
    })
    .await;

    assert!(
        matches!(
            result,
            Err(super::super::FileFailure::Deadline { op: "slow", .. })
        ),
        "never taken for success: {result:?}"
    );
    drop(lock);
    let busy = f.state.lock().unwrap_err();
    assert!(
        matches!(busy, crate::state::StateError::Busy(_)),
        "a new process must not start while the old work runs: {busy}"
    );
    release.send(()).unwrap();
    done.await.unwrap();
    // The thread lets go of the lock when it ends.
    for _ in 0..1000 {
        if f.state.lock().is_ok() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    panic!("the lock was never released");
}

#[tokio::test]
async fn first_deploy_failure_with_no_base_image_stops_service() {
    let f = fixture("");
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    resolves(&f, None);
    f.docker.script_inspect([Ok(container(PINNED, false))]);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert_ne!(report.outcome.priority(), Priority::Critical);
    assert_eq!(override_text(&f.dir), PLACEHOLDER);
    assert_eq!(count_ups(&f), 1, "there is nothing to start");
    assert_eq!(count_stops(&f), 1);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn first_deploy_failure_with_a_backup_restores_and_stays_stopped() {
    let f = fixture(STOP_TRUE);
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    resolves(&f, None);
    f.docker.script_inspect([Ok(container(PINNED, false))]);
    new_version_migrates(&f);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(data(&f), "before");
    assert_eq!(override_text(&f.dir), PLACEHOLDER);
    assert_eq!(
        changes(&f),
        ["config", "config", "pull", "stop", "up", "stop"],
        "stopped for the backup and the restore, and nothing started after"
    );
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn first_deploy_failure_with_base_image_starts_it() {
    let f = fixture("");
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    resolves(&f, Some("example/app:base"));
    failing_check(&f, "example/app:base");

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(override_text(&f.dir), PLACEHOLDER);
    assert_eq!(count_ups(&f), 2);
    assert_eq!(count_stops(&f), 0);
    assert_eq!(f.state.in_progress().unwrap(), None);
}
