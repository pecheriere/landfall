//! What is refused before the service is stopped, and compose projects found by directory.

use std::fs;
use std::path::Path;
use std::process::Command as StdCommand;

use jiff::Timestamp;
use landfall_agent::compose::OVERRIDE_FILE;
use landfall_agent::deploy::{DeployError, Outcome};
use landfall_agent::docker::Docker;
use landfall_agent::state::{InProgress, Phase};

use super::harness::{
    BACKUP, DEPLOYMENT, DIGEST_A, DIGEST_B, OtherProject, PASSES, RunAs, Stack, assert_rolled_back,
    image, labelled_working_dir, passes_only_on, script_with,
};

/// A scaled service used to pass the preflight, get stopped and end in a false
/// critical: its checks could not tell one container.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_scaled_service_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;
    let override_before = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let plain = fs::read_to_string(stack.dir.join("compose.yaml")).unwrap();

    for asked in ["    scale: 2\n", "    deploy:\n      replicas: 2\n"] {
        stack.edit_compose("  app:\n", &format!("  app:\n{asked}"));
        let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
        assert!(
            matches!(err, DeployError::Scaled { replicas: 2, .. }),
            "{asked}: {err}"
        );
        assert_eq!(stack.running_since().await, before, "{asked}");
        assert_eq!(stack.state.in_progress().unwrap(), None, "{asked}");
        fs::write(stack.dir.join("compose.yaml"), &plain).unwrap();
    }
    // None at all used to pass too, and end in a false critical.
    for asked in ["    scale: 0\n", "    deploy:\n      replicas: 0\n"] {
        stack.edit_compose("  app:\n", &format!("  app:\n{asked}"));
        let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
        assert!(
            matches!(err, DeployError::Scaled { replicas: 0, .. }),
            "{asked}: {err}"
        );
        assert_eq!(stack.running_since().await, before, "{asked}");
        assert_eq!(stack.state.in_progress().unwrap(), None, "{asked}");
        fs::write(stack.dir.join("compose.yaml"), &plain).unwrap();
    }
    assert_eq!(
        fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap(),
        override_before
    );

    // Scaled by hand, which the files don't show.
    stack.compose_by_hand(&["up", "-d", "--no-deps", "--scale", "app=2", "app"]);
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);
    assert_eq!(
        stack.project.all_containers().len(),
        2,
        "neither was stopped or removed"
    );

    // What the error says to do works.
    stack.compose_by_hand(&["up", "-d", "--no-deps", "--scale", "app=1", "app"]);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// A second project in the directory has its own container, and shares the
/// directory's data with a backup and a restore.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_second_project_in_the_directory_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;

    let other = OtherProject(format!("{}-other", stack.project.name));
    stack.compose_by_hand(&["-p", &other.0, "up", "-d", "--no-deps", "app"]);

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.running_since().await, before);
    assert_eq!(stack.state.in_progress().unwrap(), None);

    // `status` can't tell them apart without loading the project, and says so.
    let (code, lines) = stack.status_lines(&rest).await;
    assert_eq!(code, Some(2), "{lines:?}");
    assert!(
        lines[0]["error"]
            .as_str()
            .unwrap()
            .contains("more than one running container"),
        "{lines:?}"
    );

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// `name:` edited while the container runs: the project no longer has it, and a
/// restore would have run under it while it wrote.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_container_left_behind_by_a_renamed_project_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let (id, started_at) = stack.running_since().await;
    let name = stack.project.name.clone();
    // Nothing should run under the new name; if a deploy starts it, it goes too.
    let _renamed = OtherProject(format!("{name}-renamed"));

    stack.edit_compose(
        &format!("name: {name}\n"),
        &format!("name: {name}-renamed\n"),
    );
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    let info = stack.docker.inspect(&id).await.unwrap();
    assert_eq!(
        (info.status.as_str(), info.started_at),
        ("running", started_at)
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    stack.edit_compose(
        &format!("name: {name}-renamed\n"),
        &format!("name: {name}\n"),
    );
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// Another project runs alone from the directory, with the deployment's own
/// stopped: the lookup by the project's name finds nothing.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_lone_container_of_another_project_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.compose_by_hand(&["stop", "app"]);
    let other = OtherProject(format!("{}-other", stack.project.name));
    stack.compose_by_hand(&["-p", &other.0, "up", "-d", "--no-deps", "app"]);
    let lone = stack
        .docker
        .container_at(&stack.dir, "app")
        .await
        .unwrap()
        .expect("the other project's container runs from this directory");
    let started_at = stack.docker.inspect(&lone).await.unwrap().started_at;

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    let info = stack.docker.inspect(&lone).await.unwrap();
    assert_eq!(
        (info.status.as_str(), info.started_at),
        ("running", started_at)
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// Two directories with one project's name. Deploying the second used to stop
/// and replace the first's service, end `Deployed`, and leave the first's
/// `status` clean.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_project_name_shared_with_another_directory_is_refused_before_stop() {
    let first_stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = first_stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = first_stack.running_since().await;

    let second_stack = Stack::new(RunAs::Agent, &script_with(":"));
    second_stack.edit_compose(
        &format!("name: {}\n", second_stack.project.name),
        &format!("name: {}\n", first_stack.project.name),
    );
    let err = second_stack
        .attempt(&rest, "v2.0.0", DIGEST_B)
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    let text = err.to_string();
    assert!(
        text.contains("`name:`") && text.contains("`COMPOSE_PROJECT_NAME`"),
        "{text}"
    );
    assert!(
        text.contains(&format!("\"{}\"", first_stack.dir.display())),
        "the other directory is named, quoted: {text}"
    );
    assert_eq!(first_stack.running_since().await, before);
    assert_eq!(second_stack.state.in_progress().unwrap(), None);
    let status = first_stack.status(&rest).await;
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
}

/// The other directory's service is stopped. `up` under the shared name would
/// recreate its container all the same, so it is no less in the way.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_stopped_service_of_another_directory_is_refused_before_stop() {
    let first_stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = first_stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    first_stack.compose_by_hand(&["stop", "app"]);
    let before = first_stack.project.all_containers();
    assert_eq!(before.len(), 1);

    let second_stack = Stack::new(RunAs::Agent, &script_with(":"));
    second_stack.edit_compose(
        &format!("name: {}\n", second_stack.project.name),
        &format!("name: {}\n", first_stack.project.name),
    );
    let err = second_stack
        .attempt(&rest, "v2.0.0", DIGEST_B)
        .await
        .unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    assert_eq!(
        first_stack.project.all_containers(),
        before,
        "the stopped container was not replaced"
    );
    assert_eq!(second_stack.state.in_progress().unwrap(), None);
}

/// A second project started through a symlink is labelled with the link, which
/// the lookup by the directory's path doesn't match.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_second_project_started_through_a_symlink_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let before = stack.running_since().await;

    let other = OtherProject(format!("{}-other", stack.project.name));
    let link = stack.symlink_to_dir();
    let out = StdCommand::new("docker")
        .args(["compose", "-p", &other.0, "up", "-d", "--no-deps", "app"])
        .current_dir(&link)
        .env("PWD", &link)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    assert_eq!(
        stack.docker.container_at(&stack.dir, "app").await.unwrap(),
        Some(before.0.clone()),
        "only the deployment's own is found by the real path, or this proves nothing"
    );

    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert_eq!(stack.running_since().await, before);

    // With its own stopped, it is the only one running from the directory.
    stack.compose_by_hand(&["stop", "app"]);
    let err = stack.attempt(&rest, "v2.0.0", DIGEST_B).await.unwrap_err();
    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    assert_eq!(stack.state.in_progress().unwrap(), None);

    drop(other);
    let second = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(second.outcome, Outcome::Deployed, "{second:?}");
}

/// A service started by hand through a symlink is labelled with the symlink's
/// path. That used to turn a healthy service into a permanent critical.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_service_started_through_a_symlink_is_found() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = format!("{PASSES}{BACKUP}");
    let first = stack.deploy(&rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let link = stack.symlink_to_dir();
    let out = StdCommand::new("docker")
        .args([
            "compose",
            "up",
            "-d",
            "--no-deps",
            "--force-recreate",
            "app",
        ])
        .current_dir(&link)
        .env("PWD", &link)
        .output()
        .unwrap();
    assert!(out.status.success(), "{out:?}");
    let id = stack.container().await;
    assert_eq!(
        Path::new(&labelled_working_dir(&id)),
        link,
        "the container is not labelled with the link, so this proves nothing"
    );
    assert_eq!(
        stack.docker.container_at(&stack.dir, "app").await.unwrap(),
        None,
        "`status` goes by the directory, as the operations guide says"
    );

    // A release that fails its check on the version running goes back to it.
    let bad = format!("{}{BACKUP}", passes_only_on("v1.36"));
    let second = stack.deploy(&bad, "v2.0.0", DIGEST_B).await;
    assert_rolled_back(&second);
    assert_eq!(stack.running_image().await, image(DIGEST_A));
    let third = stack.deploy(&rest, "v2.0.0", DIGEST_B).await;
    assert_eq!(third.outcome, Outcome::Deployed, "{third:?}");
}

/// The base file lives elsewhere, so that is the working directory compose
/// labels the container with. The container can't be told from another stack's,
/// so the compose file has to live in the compose directory.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_compose_file_in_another_directory_is_refused_before_stop() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let elsewhere = stack.dir.join("elsewhere");
    fs::create_dir_all(elsewhere.join("data")).unwrap();
    fs::rename(
        stack.dir.join("compose.yaml"),
        elsewhere.join("compose.yaml"),
    )
    .unwrap();
    fs::write(
        stack.dir.join(".env"),
        format!("COMPOSE_FILE=elsewhere/compose.yaml:{OVERRIDE_FILE}\n"),
    )
    .unwrap();

    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let id = stack.container().await;
    assert_eq!(
        Path::new(&labelled_working_dir(&id)),
        elsewhere,
        "the working directory is the agent's, so this proves nothing"
    );
    let before = stack.running_since().await;

    let err = stack.attempt(PASSES, "v2.0.0", DIGEST_B).await.unwrap_err();

    assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
    assert!(err.to_string().contains("compose directory"), "{err}");
    assert_eq!(stack.running_since().await, before);
    assert_eq!(stack.state.in_progress().unwrap(), None);
}

/// An agent started with `PWD` on a symlink to the directory must not hand it to
/// compose, whose label would then keep `status` from finding the service.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_pwd_on_a_symlink_does_not_reach_the_label() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    // An agent that died with version B up, and no backup to restore.
    let previous = fs::read(stack.dir.join(OVERRIDE_FILE)).unwrap();
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
            backup: None,
            started_at: Timestamp::now(),
        })
        .unwrap();
    stack.write_override_for(PASSES, DIGEST_B);
    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    stack.docker.compose_up(&stack.dir, "app").await.unwrap();

    let link = stack.symlink_to_dir();
    let config = stack.config_file(PASSES);
    let out = stack
        .binary_command(&[
            "recover",
            "--config",
            config.to_str().unwrap(),
            "--deployment",
            DEPLOYMENT,
        ])
        .env("PWD", &link)
        .output()
        .await
        .unwrap();

    assert_eq!(out.status.code(), Some(0), "{out:?}");
    let id = stack.container().await;
    assert_eq!(Path::new(&labelled_working_dir(&id)), stack.dir);
    let status = stack.status(PASSES).await;
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
}

/// `config` leaves out a service behind a profile that isn't active.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_service_behind_an_inactive_profile_is_refused() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    stack.edit_compose("  app:\n", "  app:\n    profiles: [off]\n");

    let err = stack.attempt(PASSES, "v1.0.0", DIGEST_A).await.unwrap_err();

    assert!(matches!(err, DeployError::NoSuchService { .. }), "{err}");
    assert_eq!(stack.project.all_containers(), Vec::<String>::new());
    assert_eq!(stack.state.in_progress().unwrap(), None);
}
