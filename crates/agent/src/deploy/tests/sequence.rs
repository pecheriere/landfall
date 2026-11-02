//! The deploy sequence and the first rollbacks.

use std::fs;
use std::os::unix::net::UnixListener;
use std::sync::{Arc, Mutex};

use jiff::Timestamp;

use super::super::{Outcome, StepResult};
use super::{
    OLD, PINNED, PREVIOUS, STOP_FALSE, STOP_TRUE, backups, changes, container, count_ups, data,
    deploy, deployment_with_checks, failing_check, fixture, healthy_deploy, migrate, override_text,
    rendered, reports, resolves, step_names,
};
use crate::testing::Call;

#[tokio::test]
async fn successful_deploy_runs_steps_in_order() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);
    fs::create_dir_all(f.state.backups_dir()).unwrap();
    for old in 1..=5 {
        fs::create_dir(
            f.state
                .backups_dir()
                .join(format!("2000-01-0{old}T00-00-00-000000000Z")),
        )
        .unwrap();
    }
    // What the override holds at each call that depends on it.
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    let dir = f.dir.clone();
    f.docker.on_call(move |call| {
        if !matches!(
            call,
            Call::Container { .. }
                | Call::ContainerAt { .. }
                | Call::Inspect(_)
                | Call::ServiceContainers { .. }
        ) {
            log.lock().unwrap().push(override_text(&dir));
        }
    });

    let report = deploy(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
    assert_eq!(
        changes(&f),
        ["config", "config", "pull", "stop", "up"],
        "preflight twice, then pull, stop for the backup and up"
    );
    assert_eq!(
        f.docker
            .count(|c| matches!(c, Call::ComposeServiceChecked { .. })),
        1,
        "the read with the new override is held to what `up` requires"
    );
    assert_eq!(
        f.docker.count(|c| *c == Call::Pull(PINNED.to_owned())),
        1,
        "pulled by digest"
    );
    assert_eq!(
        step_names(&report),
        [
            "preflight",
            "record_in_progress",
            "verify_override",
            "pull",
            "mark_deploying",
            "prune_before_backup",
            "stop",
            "backup",
            "record_backup",
            "write_override",
            "up",
            "verify_image",
            "checks",
            "record_deployed",
            "prune_backups",
            "clear_in_progress",
        ]
    );
    assert!(report.steps.iter().all(|s| s.result == StepResult::Ok));
    let new = rendered(&f);
    assert_eq!(
        *seen.lock().unwrap(),
        [PREVIOUS, &new, PREVIOUS, PREVIOUS, &new],
        "config sees the previous then the new override, which is put back until after the backup"
    );
    assert_eq!(override_text(&f.dir), new);
    let deployed = f.state.deployed().unwrap().unwrap();
    assert_eq!(deployed.tag, *f.plan.tag());
    assert_eq!(deployed.digest, *f.plan.digest());
    assert_eq!(deployed.commit, *f.plan.commit());
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(
        f.state.previous_override().unwrap().as_deref(),
        Some(PREVIOUS.as_bytes())
    );
    let kept = backups(&f);
    assert_eq!(kept.len(), 3, "{kept:?}");
    assert!(
        kept[2].starts_with("20") && !kept[2].starts_with("2000"),
        "{kept:?}"
    );
    assert_eq!(
        fs::read_to_string(f.state.backups_dir().join(&kept[2]).join("data/db")).unwrap(),
        "before"
    );
    assert_eq!(reports(&f).len(), 1);
}

#[tokio::test]
async fn failed_check_restores_image_and_data() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    failing_check(&f, OLD);
    // The data at each later call: unchanged until the restore, which
    // happens after the stop and before the second up.
    let at_up_or_stop = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&at_up_or_stop);
    let dir = f.dir.clone();
    f.docker.on_call(move |call| {
        let up = matches!(call, Call::ComposeUp { .. });
        if up && override_text(&dir).contains(PINNED) {
            migrate(&dir);
        }
        if up || matches!(call, Call::ComposeStop { .. }) {
            log.lock()
                .unwrap()
                .push(fs::read_to_string(dir.join("data/db")).unwrap());
        }
    });

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("checks")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        changes(&f),
        [
            "config", "config", "pull", "stop", "up", "stop", "up", "config"
        ]
    );
    assert_eq!(
        *at_up_or_stop.lock().unwrap(),
        ["before", "migrated", "migrated", "before"],
        "stop for backup, up, stop for restore, up"
    );
    assert_eq!(data(&f), "before");
    assert!(!f.dir.join("data/extra").exists(), "the restore removed it");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
    assert_eq!(
        f.state.deployed().unwrap(),
        None,
        "nothing new was recorded"
    );
}

#[tokio::test]
async fn failed_up_rolls_back() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_compose_up([Err("no space"), Ok(())]);
    f.docker.script_inspect([Ok(container(OLD, true))]);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("up") && reason.contains("no space")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        changes(&f),
        [
            "config", "config", "pull", "stop", "up", "stop", "up", "config"
        ]
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn failed_backup_restarts_without_restoring() {
    let f = fixture(STOP_TRUE);
    resolves(&f, Some(OLD));
    f.docker.script_inspect([Ok(container(OLD, true))]);
    // A socket in the tree fails the backup after `db` was copied.
    fs::write(f.dir.join("data/a"), "copied first").unwrap();
    let _socket = UnixListener::bind(f.dir.join("data/zz.sock")).unwrap();

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("backup") && reason.contains("zz.sock")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        changes(&f),
        ["config", "config", "pull", "stop", "up", "config"],
        "one stop for the backup and an up of the previous image; the new override is never written"
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(data(&f), "before");
    assert!(f.dir.join("data/zz.sock").exists(), "nothing was restored");
    assert!(
        !step_names(&report).contains(&"restore_backup"),
        "{:?}",
        step_names(&report)
    );
    assert_eq!(backups(&f), Vec::<String>::new(), "no partial copy stays");
    assert_eq!(f.state.in_progress().unwrap(), None);
}

#[tokio::test]
async fn missing_backup_path_is_a_failed_backup() {
    let f = fixture(STOP_FALSE);
    resolves(&f, Some(OLD));
    f.docker.script_inspect([Ok(container(OLD, true))]);
    fs::remove_dir_all(f.dir.join("data")).unwrap();

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason } if reason.contains("backup")),
        "{:?}",
        report.outcome
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.deployed().unwrap(), None);
}

#[tokio::test]
async fn wrong_running_image_rolls_back() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container("example/other:latest", true))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason }
            if reason.contains("verify_image")
                && reason.contains(PINNED)
                && !reason.contains("example/other")),
        "{:?}",
        report.outcome
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(count_ups(&f), 2);
}

#[tokio::test]
async fn image_swapped_during_the_checks_rolls_back() {
    let f = fixture("");
    resolves(&f, Some(OLD));
    let verified_then_swapped = [
        Ok(container(PINNED, true)),
        Ok(container("example/other:latest", true)),
    ];
    f.docker.script_inspect_after_up(1, verified_then_swapped);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);

    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(&report.outcome, Outcome::RolledBack { reason }
            if reason.contains("checks")
                && reason.contains(PINNED)
                && !reason.contains("example/other")),
        "{:?}",
        report.outcome
    );
    assert_eq!(f.state.deployed().unwrap(), None);
}

#[tokio::test]
async fn previous_image_swapped_during_its_checks_is_a_failed_rollback() {
    let f = fixture("");
    resolves(&f, Some("example/app:token-s3cret"));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, false))]);
    let verified_then_swapped = [
        Ok(container("example/app:token-s3cret", true)),
        Ok(container("something/else", true)),
    ];
    f.docker.script_inspect_after_up(2, verified_then_swapped);

    let report = deploy(&f).await.unwrap();

    let Outcome::RollbackFailed {
        rollback_reason, ..
    } = &report.outcome
    else {
        panic!("{:?}", report.outcome);
    };
    assert!(
        rollback_reason.contains("check_previous"),
        "{rollback_reason}"
    );
    assert!(!rollback_reason.contains("s3cret"), "{rollback_reason}");
}

#[tokio::test]
async fn log_scan_starts_just_before_each_up() {
    let mut f = fixture("");
    f.deployment = deployment_with_checks(
        "checks = [\"container-healthy\", { no_log_match = \"panic\", within_secs = 1 }]\n",
    );
    resolves(&f, Some(OLD));
    f.docker
        .script_inspect_after_up(1, [Ok(container(PINNED, true))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);
    // A match in the new version's logs; none after the rollback.
    f.docker.script_logs_contain([Ok(true), Ok(false)]);
    let ups = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&ups);
    f.docker.on_call(move |call| {
        if matches!(call, Call::ComposeUp { .. }) {
            log.lock().unwrap().push(Timestamp::now());
        }
    });

    let before = Timestamp::now();
    let report = deploy(&f).await.unwrap();

    assert!(
        matches!(report.outcome, Outcome::RolledBack { .. }),
        "{:?}",
        report.outcome
    );
    let scans: Vec<Timestamp> = f
        .docker
        .calls()
        .iter()
        .filter_map(|c| match c {
            Call::LogsContain { since, .. } => Some(*since),
            _ => None,
        })
        .collect();
    let ups = ups.lock().unwrap();
    assert_eq!(ups.len(), 2);
    assert!(
        before <= scans[0] && scans[0] <= ups[0],
        "{scans:?} {ups:?}"
    );
    let last = *scans.last().unwrap();
    assert!(ups[0] <= last && last <= ups[1], "{scans:?} {ups:?}");
}

#[tokio::test]
async fn running_image_is_never_named() {
    // `up` can leave the old container running, whose image comes from
    // interpolated configuration, and a container can claim anything.
    let f = fixture("");
    resolves(&f, Some(OLD));
    let hostile = format!("evil\n<2>token-s3cret{}", "x".repeat(16 * 1024 * 1024));
    f.docker
        .script_inspect_after_up(1, [Ok(container(&hostile, true))]);
    f.docker
        .script_inspect_after_up(2, [Ok(container(OLD, true))]);

    let report = deploy(&f).await.unwrap();

    let Outcome::RolledBack { reason } = &report.outcome else {
        panic!("{:?}", report.outcome);
    };
    assert!(
        reason.contains("the running image isn't the pinned one") && reason.contains(PINNED),
        "{reason}"
    );
    let written = serde_json::to_string(&reports(&f)).unwrap();
    assert!(!written.contains("s3cret"));
    assert!(written.len() < 64 * 1024, "{}", written.len());
}
