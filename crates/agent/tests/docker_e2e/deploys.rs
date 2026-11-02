//! Deploys, rollbacks of a failed check, and recovery of an interrupted deploy.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::Command as StdCommand;

use jiff::Timestamp;
use landfall_agent::compose::{OVERRIDE_FILE, PLACEHOLDER};
use landfall_agent::deploy::{Outcome, StepDetail};
use landfall_agent::docker::{ContainerId, Docker};
use landfall_agent::safefs::{self, RelPath, Root};
use landfall_agent::state::{InProgress, Phase, RecordedBackup};
use serde_json::Value;

use super::harness::{
    BACKUP, DEPLOYMENT, DIGEST_A, DIGEST_B, FAILS, PASSES, RunAs, Stack, assert_rolled_back,
    etc_fingerprint, failed_step, image, passes_only_on, script_with,
};

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_deploy_then_failed_check_rolls_back() {
    let stack = Stack::new(RunAs::Agent, &script_with("echo overwritten > /data/db"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_A));

    stack
        .in_container("echo before > /data/db && chmod 640 /data/db")
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let db = stack.data("db");
    let (report, overwritten) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, || {
            fs::read_to_string(&db).is_ok_and(|text| text == "overwritten\n")
        })
        .await;

    assert_rolled_back(&report);
    assert!(failed_step(&report, "checks"), "{report:?}");
    let detail = |name: &str| {
        report
            .steps
            .iter()
            .find(|step| step.name == name)
            .and_then(|step| step.detail.as_ref())
    };
    assert!(
        matches!(detail("backup"), Some(StepDetail::Backup { stats }) if stats.files >= 1),
        "{report:?}"
    );
    assert!(
        matches!(detail("checks"), Some(StepDetail::Checks { checks }) if checks[0].attempts >= 1),
        "{report:?}"
    );
    assert!(
        overwritten,
        "version B never overwrote the file, so the restore proves nothing"
    );
    assert_eq!(stack.running_image().await, image(DIGEST_A));
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(
        fs::metadata(stack.data("db")).unwrap().permissions().mode() & 0o7777,
        0o640,
        "mode only: owners are in docker_foreign_owner_survives_backup_and_restore"
    );
    assert!(
        fs::symlink_metadata(stack.data("started-v1.28.4")).is_err(),
        "what version B added is gone"
    );

    assert_eq!(stack.state.in_progress().unwrap(), None);
    let recorded = stack.state.deployed().unwrap().unwrap();
    assert_eq!(recorded.digest.as_ref(), DIGEST_A);
    assert_eq!(recorded.tag.as_ref(), "v1.0.0");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_symlink_in_backup_is_not_followed() {
    // Version B also replaces a file with a link out of the tree, which the
    // restore has to take away rather than write through.
    let stack = Stack::new(
        RunAs::Agent,
        &script_with("rm -f /data/db && ln -s /etc/hostname /data/db"),
    );
    let etc = etc_fingerprint();
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack
        .in_container("echo before > /data/db && ln -s /etc /data/link")
        .await;

    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let (report, b_ran) = stack
        .deploy_watching(&bad, "v2.0.0", DIGEST_B, stack.b_started())
        .await;

    assert_rolled_back(&report);
    assert!(b_ran, "version B never ran, so the restore proves nothing");

    let link = fs::symlink_metadata(stack.data("link")).unwrap();
    assert!(link.file_type().is_symlink());
    assert_eq!(
        fs::read_link(stack.data("link")).unwrap(),
        Path::new("/etc")
    );

    let db = fs::symlink_metadata(stack.data("db")).unwrap();
    assert!(db.file_type().is_file(), "{db:?}");
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");

    // The snapshot holds the link, not what it points at.
    let copied = stack.newest_backup().join("data/link");
    assert!(
        fs::symlink_metadata(&copied)
            .unwrap()
            .file_type()
            .is_symlink()
    );

    assert_eq!(etc_fingerprint(), etc, "/etc changed");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_first_deploy_failure_with_no_base_image() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));

    let report = stack.deploy(FAILS, "v1.0.0", DIGEST_A).await;

    assert!(
        matches!(report.outcome, Outcome::FailedNoPrevious { .. }),
        "{:?}",
        report.outcome
    );
    assert_eq!(
        stack.docker.container(&stack.dir, "app").await.unwrap(),
        None,
        "the service is stopped"
    );
    let containers = stack.project.all_containers();
    assert_eq!(containers.len(), 1, "{containers:?}");
    let id: ContainerId = containers[0].parse().unwrap();
    assert_eq!(stack.docker.inspect(&id).await.unwrap().status, "exited");
    assert_eq!(
        fs::read_to_string(stack.dir.join(OVERRIDE_FILE)).unwrap(),
        PLACEHOLDER
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(stack.state.deployed().unwrap(), None);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_first_deploy_needs_its_backup_paths_to_exist() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    fs::remove_dir(stack.dir.join("data")).unwrap();

    let report = stack
        .deploy(&format!("{PASSES}{BACKUP}"), "v1.0.0", DIGEST_A)
        .await;

    assert!(
        matches!(&report.outcome, Outcome::FailedNoPrevious { reason } if reason.starts_with("backup:")),
        "{:?}",
        report.outcome
    );
    assert_eq!(stack.project.all_containers(), Vec::<String>::new());
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_leftover_one_off_does_not_disturb_deploy_or_rollback() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let good = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&good, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let run = StdCommand::new("docker")
        .args(["compose", "run", "-d", "--no-deps", "app", "sleep", "300"])
        .current_dir(&stack.dir)
        .output()
        .unwrap();
    assert!(run.status.success(), "{run:?}");
    assert_eq!(stack.project.all_containers().len(), 2);

    // A deploy goes through with it there.
    let second = stack.deploy(&good, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    // So does a rollback.
    let bad = format!("{}{BACKUP}", passes_only_on("v1.28"));
    let third = stack.deploy(&bad, "v3.0.0", DIGEST_A).await;
    assert_rolled_back(&third);
    assert_eq!(stack.running_image().await, image(DIGEST_B));
    assert_eq!(stack.project.all_containers().len(), 2);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_recover_rolls_back_an_interrupted_deploy() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    stack.in_container("echo before > /data/db").await;

    // An agent that died with version B up: it had stopped the service, taken
    // a backup, written the override and started B, which wrote to the data.
    stack.docker.compose_stop(&stack.dir, "app").await.unwrap();
    let previous = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let backup = "2026-11-01T10-00-00-000000000Z";
    safefs::snapshot(
        &Root::open(&stack.dir).unwrap(),
        &[RelPath::new("data").unwrap()],
        &stack.state.backups_dir().join(backup),
    )
    .unwrap();
    stack.state.set_previous_override(&previous).unwrap();
    stack
        .state
        .set_previous_deployed(stack.state.deployed().unwrap().as_ref())
        .unwrap();
    stack
        .state
        .set_in_progress(&InProgress {
            deploy_id: "interrupted".to_owned(),
            phase: Phase::Deploying,
            tag: "v2.0.0".parse().unwrap(),
            digest: DIGEST_B.parse().unwrap(),
            previous_can_start: true,
            backup: Some(RecordedBackup {
                id: backup.to_owned(),
                paths: vec!["data".to_owned()],
            }),
            started_at: Timestamp::now(),
        })
        .unwrap();
    stack.write_override_for(&rest, DIGEST_B);
    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    stack.docker.compose_up(&stack.dir, "app").await.unwrap();
    assert_eq!(stack.running_image().await, image(DIGEST_B));
    fs::write(stack.data("db"), "half migrated\n").unwrap();

    let status = stack.status(&rest).await;
    assert_eq!(status["in_progress"], true);
    assert_eq!(status["phase"], "deploying");

    // Through the binary, with the engine's real timing.
    let config = stack.config_file(&rest);
    let args = [
        "recover",
        "--config",
        config.to_str().unwrap(),
        "--deployment",
        DEPLOYMENT,
    ];
    let out = stack.binary(&args).await;
    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let report: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(report["outcome"]["kind"], "rolled_back", "{report}");

    assert_eq!(stack.running_image().await, image(DIGEST_A));
    assert_eq!(fs::read_to_string(stack.data("db")).unwrap(), "before\n");
    assert_eq!(fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap(), previous);

    let again = stack.binary(&args).await;
    assert_eq!(again.status.code(), Some(2), "nothing left to recover");
    assert_eq!(again.stdout, b"");
}
