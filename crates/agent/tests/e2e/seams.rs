//! Where a fleet can get stuck, and the way out of each: a refusal for a cause that
//! passes, a controller that starts over, a wait with no bound and a database that
//! has to be restored.

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::harness::{DEPLOYMENT, DeployRow, Fleet, Process};
use crate::world::digest_of;

/// Waits for a deploy of `tag` to have ended as `outcome`, and gives it.
async fn wait_outcome(fleet: &Fleet, tag: &str, outcome: &str) -> DeployRow {
    fleet
        .wait_until(&format!("{tag} ending as {outcome}"), async || {
            fleet
                .deploys()
                .await
                .iter()
                .any(|deploy| deploy.tag == tag && deploy.outcome.as_deref() == Some(outcome))
        })
        .await;
    fleet
        .deploys()
        .await
        .into_iter()
        .rfind(|deploy| deploy.tag == tag && deploy.outcome.as_deref() == Some(outcome))
        .unwrap()
}

/// A controller and an agent, with `v1.2.3` deployed and known to the controller.
async fn running_fleet() -> (Fleet, Process, Process) {
    let fleet = Fleet::new();
    let controller = fleet.controller().await;
    fleet.enrol();
    fleet.seed("v1.2.3").await;
    let agent = fleet.agent();
    fleet.wait_running("v1.2.3").await;
    (fleet, controller, agent)
}

#[tokio::test]
async fn drift_the_controller_had_not_heard_of_only_puts_a_release_off() {
    let (fleet, mut controller, mut agent) = running_fleet().await;

    let image = fleet.world.0.join("image");
    let good = fs::read_to_string(&image).unwrap();
    let by_hand = digest_of("something-by-hand");
    fs::write(&image, format!("ghcr.io/example/app@{}", by_hand.as_ref())).unwrap();
    fleet.world.publish("v1.2.4");
    let first = fleet.wait_finished("v1.2.4").await;
    assert_eq!(first.outcome.as_deref(), Some("deferred"), "{first:?}");
    assert_eq!(fleet.world.ups(), 1, "nothing ran");
    assert!(
        !fleet.audit().await.iter().any(|row| {
            row.kind == "deploy_refused"
                || (row.detail["tag"] == "v1.2.4" && row.detail["decision"] == "refused")
        }),
        "not now is not no"
    );

    // With the cause gone the same release goes, under a number of its own.
    fs::write(&image, good).unwrap();
    agent.stop().await;
    let mut agent = fleet.agent();
    let deployed = wait_outcome(&fleet, "v1.2.4", "deployed").await;
    assert!(deployed.id > first.id);
    fleet.wait_running("v1.2.4").await;

    agent.stop().await;
    controller.stop().await;
}

#[tokio::test]
async fn a_host_clock_behind_a_fresh_release_only_puts_it_off() {
    let (fleet, mut controller, mut agent) = running_fleet().await;

    fleet.world.fail_verification("clock");
    fleet.world.publish("v1.2.4");
    let first = wait_outcome(&fleet, "v1.2.4", "deferred").await;
    assert_eq!(fleet.world.ups(), 1, "nothing ran");
    assert!(fleet.journalled("controller_work_deferred") >= 1);

    // The clock is set, and the same release goes.
    fleet.world.pass_verification();
    let deployed = wait_outcome(&fleet, "v1.2.4", "deployed").await;
    assert!(deployed.id > first.id);

    agent.stop().await;
    controller.stop().await;
}

/// Takes the fleet through two more releases, so that the ledger holds numbers a
/// controller that starts over will use again.
async fn deploy_two_more(fleet: &Fleet) {
    for tag in ["v1.2.4", "v1.2.5"] {
        fleet.world.publish(tag);
        assert_eq!(
            fleet.wait_finished(tag).await.outcome.as_deref(),
            Some("deployed")
        );
        fleet.wait_running(tag).await;
    }
}

fn beside(db: &Path, suffix: &str) -> PathBuf {
    let mut name = db.as_os_str().to_owned();
    name.push(suffix);
    PathBuf::from(name)
}

fn remove_database(db: &Path) {
    for suffix in ["", "-wal", "-shm"] {
        match fs::remove_file(beside(db, suffix)) {
            Ok(()) => {}
            Err(error) => assert_eq!(error.kind(), std::io::ErrorKind::NotFound, "{error}"),
        }
    }
}

/// A controller given a database of old numbers: new releases deploy, for every
/// number the host has seen before and every one it has not.
async fn new_releases_deploy(fleet: &Fleet) {
    for tag in ["v1.2.6", "v1.2.7", "v1.2.8"] {
        fleet.world.publish(tag);
        let deploy = fleet.wait_finished(tag).await;
        assert_eq!(deploy.outcome.as_deref(), Some("deployed"), "{deploy:?}");
        fleet.wait_running(tag).await;
    }
}

#[tokio::test]
async fn a_controller_rebuilt_from_nothing_loses_no_release_to_a_reused_number() {
    let (fleet, mut controller, mut agent) = running_fleet().await;
    deploy_two_more(&fleet).await;

    agent.stop().await;
    controller.stop().await;
    remove_database(&fleet.db);
    let mut controller = fleet.controller().await;
    fleet.enrol();
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.5").await;

    new_releases_deploy(&fleet).await;
    assert_eq!(fleet.audit_verify(None).status, 0);

    agent.stop().await;
    controller.stop().await;
}

#[tokio::test]
async fn a_controller_restored_from_a_copy_loses_no_release_to_a_reused_number() {
    let (fleet, mut controller, mut agent) = running_fleet().await;
    deploy_two_more(&fleet).await;

    controller.stop().await;
    let copy = fleet.db.with_extension("copy");
    fs::copy(&fleet.db, &copy).unwrap();
    let kept_wal = fs::copy(beside(&fleet.db, "-wal"), beside(&copy, "-wal")).is_ok();
    let mut controller = fleet.controller().await;
    for tag in ["v1.2.6", "v1.2.7"] {
        fleet.world.publish(tag);
        fleet.wait_finished(tag).await;
        fleet.wait_running(tag).await;
    }

    agent.stop().await;
    controller.stop().await;
    remove_database(&fleet.db);
    fs::copy(&copy, &fleet.db).unwrap();
    if kept_wal {
        fs::copy(beside(&copy, "-wal"), beside(&fleet.db, "-wal")).unwrap();
    }
    let mut controller = fleet.controller().await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.7").await;

    // The database is behind by two deploys, so these numbers name others on the host.
    for tag in ["v1.2.8", "v1.2.9"] {
        fleet.world.publish(tag);
        let deploy = fleet.wait_finished(tag).await;
        assert_eq!(deploy.outcome.as_deref(), Some("deployed"), "{deploy:?}");
        fleet.wait_running(tag).await;
    }

    agent.stop().await;
    controller.stop().await;
}

/// As if the host had waited ten hours for deploy 1 already: the bound is an hour.
fn waited_ten_hours(fleet: &Fleet) {
    let dir = fleet.state_dir.join(DEPLOYMENT.replace('/', "__"));
    fs::write(
        dir.join("verification-wait.json"),
        r#"{"deploy_id":1,"waited_millis":36000000}"#,
    )
    .unwrap();
}

/// However the wait goes, past its bound the claim ends, nothing has run, and the
/// release can go when it verifies.
async fn a_wait_ends_past_its_bound(how: &str) {
    let (fleet, mut controller, agent) = running_fleet().await;
    let mut agent = agent;
    agent.stop().await;
    waited_ten_hours(&fleet);
    fleet.world.fail_verification(how);
    fleet.world.publish("v1.2.4");
    let mut agent = fleet.agent();

    fleet
        .wait_for(
            Duration::from_secs(20),
            "the wait ending the claim",
            async || {
                fleet
                    .deploys()
                    .await
                    .first()
                    .is_some_and(|deploy| deploy.state == "finished")
            },
        )
        .await;
    let first = fleet.deploys().await.remove(0);
    assert_eq!(
        first.outcome.as_deref(),
        Some("deferred"),
        "{how}: {first:?}"
    );
    assert_eq!(fleet.world.ups(), 1, "{how}: nothing ran");

    fleet.world.pass_verification();
    wait_outcome(&fleet, "v1.2.4", "deployed").await;

    agent.stop().await;
    controller.stop().await;
}

#[tokio::test]
async fn a_wait_on_a_wrong_shaped_answer_ends_past_its_bound() {
    a_wait_ends_past_its_bound("shape").await;
}

#[tokio::test]
async fn a_wait_on_a_missing_release_ends_past_its_bound() {
    a_wait_ends_past_its_bound("missing").await;
}

#[tokio::test]
async fn a_clean_stop_leaves_everything_in_the_database_file() {
    let (fleet, mut controller, mut agent) = running_fleet().await;
    fleet.world.publish("v1.2.4");
    fleet.wait_finished("v1.2.4").await;
    agent.stop().await;
    controller.stop().await;

    // A copy of the one file holds all of it, with nothing left beside it.
    let wal = beside(&fleet.db, "-wal");
    assert!(
        fs::metadata(&wal).map_or(true, |meta| meta.len() == 0),
        "{wal:?} still holds data"
    );
    let copy = fleet.db.with_extension("copy");
    fs::copy(&fleet.db, &copy).unwrap();
    let full = fleet.audit_verify(None);
    assert_eq!(full.status, 0, "{:?}", full.printed);
    let from_copy = fleet.audit_verify_of(&copy, None);
    assert_eq!(from_copy.status, 0, "{:?}", from_copy.printed);
    assert_eq!(from_copy.printed["head_hash"], full.printed["head_hash"]);
    assert!(from_copy.printed["rows"].as_i64().unwrap() > 0);
}

/// A real `backup` of the fleet's database to `dest`: its status and what it printed.
fn backup(fleet: &Fleet, dest: &Path) -> (i32, String) {
    let args = [
        "backup",
        "--db",
        fleet.db.to_str().unwrap(),
        dest.to_str().unwrap(),
    ];
    fleet.server_command(args.map(str::to_owned).to_vec())
}

#[tokio::test]
async fn a_backup_taken_while_the_controller_writes_is_whole_and_a_true_prefix() {
    let (fleet, mut controller, mut agent) = running_fleet().await;
    for (n, tag) in ["v1.2.4", "v1.2.5", "v1.2.6"].into_iter().enumerate() {
        // The release is on its way as the backup runs.
        fleet.world.publish(tag);
        let dest = fleet.db.with_extension(format!("backup{n}"));
        let (status, printed) = backup(&fleet, &dest);
        assert_eq!(status, 0, "{printed}");
        let printed: serde_json::Value = serde_json::from_str(&printed).unwrap();
        assert_eq!(printed["first_bad"], serde_json::Value::Null);

        let verified = fleet.audit_verify_of(&dest, None);
        assert_eq!(verified.status, 0, "{:?}", verified.printed);
        assert_eq!(verified.printed["head_hash"], printed["head_hash"]);
        // What it holds is what the live log says at that row.
        let seq = verified.printed["head_seq"].as_i64().unwrap();
        let live = fleet.audit_verify(Some(seq));
        assert_eq!(live.status, 0, "{:?}", live.printed);
        assert_eq!(live.printed["at_hash"], verified.printed["head_hash"]);

        // It is private, and nothing is written over.
        let mode =
            std::os::unix::fs::PermissionsExt::mode(&fs::metadata(&dest).unwrap().permissions());
        assert_eq!(mode & 0o077, 0, "{mode:o}");
        let before = fs::read(&dest).unwrap();
        assert_eq!(backup(&fleet, &dest).0, 2, "an existing destination");
        assert_eq!(fs::read(&dest).unwrap(), before);

        fleet.wait_finished(tag).await;
        fleet.wait_running(tag).await;
    }
    agent.stop().await;
    controller.stop().await;

    // And a controller starts from one, and what it has moved on from is gone.
    let restored = fleet.db.with_extension("backup2");
    let at_backup = fleet.audit_verify_of(&restored, None);
    remove_database(&fleet.db);
    fs::copy(&restored, &fleet.db).unwrap();
    let mut controller = fleet.controller().await;
    let mut agent = fleet.agent();
    fleet.wait_running("v1.2.6").await;
    assert_eq!(fleet.audit_verify(None).status, 0);
    assert!(
        fleet.audit_verify(None).printed["head_seq"].as_i64()
            >= at_backup.printed["head_seq"].as_i64()
    );
    agent.stop().await;
    controller.stop().await;
}
