//! Failed rollbacks, backups kept and pruned.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use landfall_agent::deploy::{self, DeployError, EngineOptions, Outcome};
use landfall_agent::docker::{ContainerId, Docker};
use landfall_agent::state::Phase;

use super::harness::{
    BACKUP, DIGEST_A, DIGEST_B, PASSES, RunAs, Stack, assert_rolled_back, image, options,
    passes_only_on, retrying_while_busy, script_with,
};

/// A deadline that lets a check that can't pass fail quickly, for tests that go
/// through several of them.
fn quick_to_fail() -> EngineOptions {
    let mut options = options();
    options.checks.deadline = Duration::from_secs(3);
    options
}

/// The rollback gets the previous version running, on its restored data, and
/// its checks fail because a dependency is down. It keeps serving for as long as
/// that takes to fix, and `recover` must not take what it wrote since.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_recover_after_failed_rollback_keeps_later_writes() {
    let mut stack = Stack::new(RunAs::Agent, &script_with("echo overwritten > /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack.in_container("echo before > /data/db").await;

    stack.options = quick_to_fail();
    let needs_dependency =
        format!("checks = [{{ command = [\"test\", \"-f\", \"/data/dependency-up\"] }}]\n{BACKUP}");
    let report = stack.deploy(&needs_dependency, "v2.0.0", DIGEST_B).await;

    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("check_previous")),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        stack.state.in_progress().unwrap().unwrap().phase,
        Phase::Restored
    );
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    // Hours later: it has gone on writing, and the dependency is fixed.
    stack
        .in_container("echo written since > /data/db && echo fixed > /data/dependency-up")
        .await;
    let before = stack.running_since().await;
    stack.options = options();
    let deployment = stack.deployment(&needs_dependency);
    let report = retrying_while_busy(async || {
        Box::pin(deploy::recover(
            &stack.docker,
            &stack.state,
            &deployment,
            &stack.dir,
            &stack.options,
        ))
        .await
    })
    .await
    .unwrap();

    assert_rolled_back(&report);
    assert_eq!(
        fs::read_to_string(stack.data("db")).unwrap(),
        "written since\n",
        "what the previous version wrote is still there"
    );
    assert_eq!(
        stack.running_since().await,
        before,
        "the service was neither stopped nor restarted"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(
        stack.state.deployed().unwrap().unwrap().digest.as_ref(),
        DIGEST_A
    );
}

/// A failed deploy takes a backup too: without pruning, six of them left seven
/// copies of the data, and each could have filled the disk.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_failed_deploys_keep_only_the_newest_backups() {
    const KEPT: usize = 3;
    let mut stack = Stack::new(RunAs::Agent, &script_with(":"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.options = quick_to_fail();
    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let backups = stack.state.backups_dir();
    let count = |dir: &Path| fs::read_dir(dir).map_or(0, Iterator::count);
    for attempt in 0..3 {
        let (report, over) = stack
            .deploy_watching(&bad, "v2.0.0", DIGEST_B, || count(&backups) > KEPT)
            .await;
        assert_rolled_back(&report);
        assert!(!over, "attempt {attempt}: more than {KEPT} at some point");
        assert_eq!(count(&backups), KEPT.min(attempt + 2), "attempt {attempt}");
    }

    // More than the number kept turned up by the time a rollback ends: an agent
    // whose prune failed ahead of its backup leaves that.
    let seeded = std::cell::Cell::new(false);
    let stale = backups.join("2000-01-01T00-00-00-000000000Z");
    let b_started = stack.b_started();
    let (report, _) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, || {
            if !seeded.get() && b_started() {
                fs::create_dir(&stale).unwrap();
                seeded.set(true);
            }
            false
        })
        .await;
    assert_rolled_back(&report);
    assert!(seeded.get());
    assert!(fs::symlink_metadata(&stale).is_err(), "it was pruned");
    assert_eq!(count(&backups), KEPT);
}

/// The backup a marker names is what a rollback or `recover` would restore, so
/// it stays even when others sort ahead of it, as a clock that went back leaves.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_prune_spares_the_backup_an_unfinished_marker_names() {
    const AHEAD: [&str; 3] = [
        "2999-01-01T00-00-00-000000000Z",
        "2999-01-02T00-00-00-000000000Z",
        "2999-01-03T00-00-00-000000000Z",
    ];
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let earlier = stack.newest_backup();

    // Seeded once the backup of this deploy is taken, with the marker naming
    // it, so only the prune at the end of the deploy can see them.
    let backups = stack.state.backups_dir();
    let seeded = std::cell::Cell::new(false);
    let b_started = stack.b_started();
    let (second, _) = stack
        .deploy_watching(&rest, "v2.0.0", DIGEST_B, || {
            if !seeded.get() && b_started() {
                for name in AHEAD {
                    fs::create_dir(backups.join(name)).unwrap();
                }
                seeded.set(true);
            }
            false
        })
        .await;

    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
    assert!(seeded.get());
    let left: Vec<PathBuf> = fs::read_dir(&backups)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| !AHEAD.iter().any(|name| path.ends_with(name)))
        .collect();
    assert_eq!(left.len(), 1, "the marker's backup, and only it: {left:?}");
    assert_ne!(left[0], earlier, "the older one was pruned, not this one");
}

/// A rollback's `up` fails. Whatever is running stays running, in the critical
/// state with deploys blocked; the agent does not stop it to tidy up.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_failed_rollback_up_leaves_what_runs_running() {
    let mut stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = passes_only_on("v1.36");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    // With version B up, the project comes to name an external network that
    // isn't there. That passes `config`, and `stop` would still work, so nothing
    // but the agent's choice keeps the service running: only `up` fails.
    stack.options = quick_to_fail();
    let compose_file = stack.dir.join("compose.yaml");
    let intact = fs::read_to_string(&compose_file).unwrap();
    let name = stack.project.name.clone();
    let broken = std::cell::Cell::new(false);
    let b_started = stack.b_started();
    let (report, _) = stack
        .deploy_watching(&rest, "v2.0.0", DIGEST_B, || {
            if !broken.get() && b_started() {
                stack.edit_compose(
                    &format!("name: {name}-net\n"),
                    &format!("name: {name}-missing\n    external: true\n"),
                );
                broken.set(true);
            }
            false
        })
        .await;

    assert!(broken.get());
    assert!(
        matches!(&report.outcome, Outcome::RollbackFailed { rollback_reason, .. }
            if rollback_reason.contains("start_previous")),
        "{:?}",
        report.outcome
    );
    assert!(report.steps.iter().all(|step| step.name != "stop_service"));
    let containers = stack.project.all_containers();
    assert_eq!(containers.len(), 1, "{containers:?}");
    let id: ContainerId = containers[0].parse().unwrap();
    let info = stack.docker.inspect(&id).await.unwrap();
    assert_eq!(info.status, "running", "the agent stopped it");
    assert_eq!(info.image, image(DIGEST_B));

    let refused = stack.attempt(&rest, "v3.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(refused, DeployError::Interrupted { .. }),
        "{refused}"
    );
    let status = stack.status(&rest).await;
    assert_eq!(status["in_progress"], true);
    assert_eq!(status["phase"], "rolling_back");
    assert_eq!(status["running_image_matches"], false);

    // The operator fixes it, and `recover` brings the previous version back.
    fs::write(&compose_file, intact).unwrap();
    stack.options = options();
    let deployment = stack.deployment(&rest);
    let recovered = retrying_while_busy(async || {
        Box::pin(deploy::recover(
            &stack.docker,
            &stack.state,
            &deployment,
            &stack.dir,
            &stack.options,
        ))
        .await
    })
    .await
    .unwrap();
    assert_rolled_back(&recovered);
    assert_eq!(stack.running_image().await, image(DIGEST_A));
}
