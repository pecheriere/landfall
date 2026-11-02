//! `landfall-agent status` against a real Docker.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::process::Command as StdCommand;

use landfall_agent::compose::OVERRIDE_FILE;
use landfall_agent::deploy::Outcome;
use landfall_agent::docker::Docker;
use serde_json::Value;

use super::harness::{
    DEPLOYMENT, DIGEST_A, DIGEST_B, PASSES, REPO, RunAs, Stack, image, script_with,
};

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_reports_drift() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let rest = PASSES;
    let first = stack.deploy(rest, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    let status = stack.status(rest).await;
    assert_eq!(status["deployment"], DEPLOYMENT);
    assert_eq!(status["dir"], stack.dir.to_str().unwrap());
    assert_eq!(status["deployed"]["digest"], DIGEST_A);
    assert_eq!(status["in_progress"], false);
    assert_eq!(status["phase"], Value::Null);
    assert_eq!(status["running_image"], format!("{:?}", image(DIGEST_A)));
    assert_eq!(status["running_image_matches"], true);
    assert_eq!(status["drift"], false);

    // The override moves on and the container doesn't.
    stack.write_override_for(rest, DIGEST_B);
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);

    // The override is gone, with a deploy on record.
    fs::remove_file(stack.dir.join(OVERRIDE_FILE)).unwrap();
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "missing");
    assert_eq!(status["drift"], true);

    // A hand-edited override isn't the agent's to go by.
    fs::write(
        stack.dir.join(OVERRIDE_FILE),
        format!("services:\n  app:\n    image: {}\n", image(DIGEST_A)),
    )
    .unwrap();
    let status = stack.status(rest).await;
    assert_eq!(status["override_file"], "unrecognised");
    assert_eq!(status["drift"], true);
}

/// The project no longer uses the override: `.env` is emptied and the base file
/// names an image, which is what `docker compose` then resolves to and runs.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_drift_goes_by_the_override_not_by_what_env_resolves_to() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    fs::write(stack.dir.join(".env"), "").unwrap();
    let base = fs::read_to_string(stack.dir.join("compose.yaml")).unwrap();
    fs::write(
        stack.dir.join("compose.yaml"),
        base.replace(
            "  app:\n",
            &format!("  app:\n    image: {}\n", image(DIGEST_B)),
        ),
    )
    .unwrap();
    let up = StdCommand::new("docker")
        .args(["compose", "up", "-d", "--no-deps", "app"])
        .current_dir(&stack.dir)
        .output()
        .unwrap();
    assert!(up.status.success(), "{up:?}");
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    let status = stack.status(PASSES).await;
    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);
}

/// `image: ${IMG}` puts whatever `.env` says into the container's image, so an
/// image other than the pinned one can hold a secret. Here that value is the
/// other version's reference, which nothing else in the row has a reason to name.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_status_never_prints_an_image_it_did_not_pin() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");

    stack.docker.pull(&image(DIGEST_B)).await.unwrap();
    fs::write(stack.dir.join(".env"), format!("IMG={}\n", image(DIGEST_B))).unwrap();
    stack.edit_compose("  app:\n", "  app:\n    image: ${IMG}\n");
    stack.compose_by_hand(&["up", "-d", "--no-deps", "app"]);
    assert_eq!(stack.running_image().await, image(DIGEST_B));

    let status = stack.status(PASSES).await;

    assert_eq!(status["override_file"], "pinned");
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["running_image_matches"], false);
    assert_eq!(status["drift"], true);
    assert!(!status.to_string().contains(DIGEST_B), "{status}");
}

/// Before a first deploy: no override, and a stack the agent's user can't read.
#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_needs_neither_an_override_nor_compose() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    fs::set_permissions(stack.dir.join(".env"), fs::Permissions::from_mode(0o000)).unwrap();
    fs::remove_file(stack.dir.join("compose.yaml")).unwrap();

    let status = stack.status(PASSES).await;

    assert_eq!(status["override_file"], "missing");
    assert_eq!(status["deployed"], Value::Null);
    assert_eq!(status["in_progress"], false);
    assert_eq!(status["running_image"], Value::Null);
    assert_eq!(status["drift"], false);
    assert_eq!(status["error"], Value::Null);
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_real_status_reports_every_deployment_and_exits_2_if_one_is_bad() {
    let stack = Stack::new(RunAs::Agent, &script_with(":"));
    let first = stack.deploy(PASSES, "v1.0.0", DIGEST_A).await;
    assert_eq!(first.outcome, Outcome::Deployed, "{first:?}");
    let gone = stack.dir.join("gone");
    let rest = format!(
        "{PASSES}[[deployment]]\nid = \"app/gone\"\nrepo = {{ name = \"{REPO}\", id = 1, owner_id = 2 }}\n\
         host = \"home-1\"\ncompose = {{ dir = {:?}, service = \"app\" }}\n\
         origin = {{ workflow = \".github/workflows/release.yml\", tags = \"v*\", signers = [\"maintainer\"] }}\n\
         rule = {{ auto = \"any\", approvers = [\"operator\"] }}\n{PASSES}",
        gone.to_str().unwrap()
    );

    let (code, lines) = stack.status_lines(&rest).await;

    assert_eq!(code, Some(2), "{lines:?}");
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert_eq!(lines[0]["deployment"], DEPLOYMENT);
    assert_eq!(lines[0]["drift"], false);
    assert_eq!(lines[0]["error"], Value::Null);
    assert_eq!(lines[1]["deployment"], "app/gone");
    assert_eq!(lines[1]["drift"], Value::Null);
    assert!(lines[1]["error"].is_string(), "{lines:?}");
}
