//! Drift: the running image against the override.

use std::fs;

use super::super::{DriftError, OverrideFile, drift};
use super::{Fixture, OLD, PINNED, changes, container, fixture};
use crate::compose::{self, OVERRIDE_FILE, PLACEHOLDER};
use crate::testing::Call;

/// A fixture whose override pins `image`.
fn pinned_to(image: &str) -> Fixture {
    let f = fixture("");
    let file = compose::render_override(
        "app",
        image,
        f.plan.deployment(),
        f.plan.tag(),
        f.plan.commit(),
    );
    fs::write(f.dir.join(OVERRIDE_FILE), file).unwrap();
    f
}

#[tokio::test]
async fn drift_is_reported() {
    let f = pinned_to(PINNED);
    f.docker.script_inspect([Ok(container(OLD, true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert!(seen.drift);
    assert_eq!(seen.override_file, OverrideFile::Pinned);
    assert_eq!(seen.running_image_matches, Some(false));
    assert_eq!(seen.running_image, None, "it can hold a secret");
}

#[tokio::test]
async fn no_drift_when_images_match() {
    let f = pinned_to(PINNED);
    f.docker.script_inspect([Ok(container(PINNED, true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert!(!seen.drift);
    assert_eq!(seen.running_image_matches, Some(true));
    assert_eq!(seen.running_image, Some(format!("{PINNED:?}")));
}

#[tokio::test]
async fn drift_never_asks_compose() {
    let f = pinned_to(PINNED);
    f.docker.script_inspect([Ok(container(PINNED, true))]);
    drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert_eq!(changes(&f), Vec::<&str>::new());
    assert_eq!(
        f.docker.count(|c| matches!(c, Call::Container { .. })),
        0,
        "the lookup by project loads the stack's files"
    );
}

#[tokio::test]
async fn nothing_pinned_and_nothing_on_record_is_not_drift() {
    let f = fixture("");
    for (file, expected) in [
        (None, OverrideFile::Missing),
        (Some(PLACEHOLDER), OverrideFile::Placeholder),
    ] {
        match file {
            Some(text) => fs::write(f.dir.join(OVERRIDE_FILE), text).unwrap(),
            None => fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap(),
        }
        f.docker.script_inspect([Ok(container(OLD, true))]);
        let seen = drift(&f.docker, &f.dir, "app", false).await.unwrap();
        assert_eq!(seen.override_file, expected);
        assert!(!seen.drift, "{expected:?}");
        assert_eq!(seen.running_image, None, "{expected:?}");
        assert_eq!(seen.running_image_matches, Some(false), "{expected:?}");
    }
}

#[tokio::test]
async fn a_missing_override_with_a_deploy_on_record_is_drift() {
    let f = fixture("");
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    f.docker.script_inspect([Ok(container(OLD, true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert_eq!(seen.override_file, OverrideFile::Missing);
    assert!(seen.drift);
    assert_eq!(seen.running_image, None);

    // Nothing running, nothing to differ.
    f.docker.script_container([Ok(None)]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert!(!seen.drift);
    assert_eq!(seen.running_image_matches, None);
}

#[tokio::test]
async fn an_override_the_agent_did_not_write_is_drift_and_is_not_quoted() {
    let f = fixture("");
    fs::write(f.dir.join(OVERRIDE_FILE), "services: {} # SECRET=hunter2\n").unwrap();
    f.docker.script_inspect([Ok(container(PINNED, true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert_eq!(seen.override_file, OverrideFile::Unrecognised);
    assert!(seen.drift);
    assert!(!format!("{seen:?}").contains("hunter2"));
}

#[tokio::test]
async fn a_stopped_service_has_not_drifted() {
    let f = pinned_to(PINNED);
    f.docker.script_container([Ok(None)]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert!(!seen.drift);
    assert_eq!(seen.running_image, None);
    assert_eq!(seen.running_image_matches, None);
}

#[tokio::test]
async fn a_symlinked_override_is_not_followed_by_drift() {
    let f = fixture("");
    let elsewhere = f.dir.join("elsewhere");
    fs::write(&elsewhere, PLACEHOLDER).unwrap();
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.dir.join(OVERRIDE_FILE)).unwrap();
    let err = drift(&f.docker, &f.dir, "app", true).await.unwrap_err();
    assert!(matches!(err, DriftError::Override(_)), "{err}");
}

#[tokio::test]
async fn a_long_pinned_image_is_quoted_and_truncated_by_drift() {
    let long = format!("ghcr.io/example/{}", "x".repeat(4096));
    let f = pinned_to(&long);
    f.docker.script_inspect([Ok(container(&long, true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    let shown = seen.running_image.unwrap();
    assert!(shown.starts_with("\"ghcr.io/example/"), "{shown}");
    assert!(shown.len() < 512, "{}", shown.len());
}

#[tokio::test]
async fn an_image_that_is_not_the_pinned_one_is_never_shown() {
    let f = pinned_to(PINNED);
    f.docker
        .script_inspect([Ok(container("registry.example/app:hunter2", true))]);
    let seen = drift(&f.docker, &f.dir, "app", true).await.unwrap();
    assert!(!format!("{seen:?}").contains("hunter2"), "{seen:?}");
    assert_eq!(seen.running_image_matches, Some(false));
}

/// Against a real Docker daemon, as in `checks/tests/real.rs`.
mod real {
    use super::super::{
        DeployError, DeployPlan, OVERRIDE_FILE, PREVIOUS, STOP_TRUE, StateDir, deployment, fs,
        options, run,
    };
    use crate::docker::{Docker, DockerCli};
    use crate::testing::{ComposeProject, TEST_IMAGE};

    #[tokio::test]
    #[ignore = "docker: runs in ci.yml"]
    async fn docker_broken_compose_file_is_refused_before_stop() {
        let cli = DockerCli::new();
        let services = format!(
            "  app:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n"
        );
        let project = ComposeProject::new(&cli, &services).await;
        let dir = project.path().canonicalize().unwrap();
        let file = dir.join("compose.yaml");
        fs::write(
            dir.join(".env"),
            format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
        )
        .unwrap();
        fs::write(dir.join(OVERRIDE_FILE), PREVIOUS).unwrap();
        cli.compose_up(&dir, "app").await.unwrap();
        let id = cli.container(&dir, "app").await.unwrap().unwrap();
        let started = cli.inspect(&id).await.unwrap().started_at;

        // A file that `up` cannot use: the lenient read does not mind.
        fs::write(
            &file,
            format!(
                "name: {}\nservices:\n{services}    networks: [missing]\n",
                project.name
            ),
        )
        .unwrap();
        let lenient = cli.compose_service(&dir, "app").await;

        let state_root = tempfile::tempdir().unwrap();
        let d = deployment(STOP_TRUE);
        let state = StateDir::open(state_root.path())
            .unwrap()
            .deployment(d.id())
            .unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let plan = DeployPlan::for_test(&d, "v1.2.3", &digest, &"b".repeat(40));
        let result = run(&cli, &state, &d, &dir, &plan, &options()).await;

        lenient.expect("the lenient read lets the broken file through");
        let err = result.expect_err("a project `up` cannot use is refused");
        assert!(matches!(err, DeployError::Compose { .. }), "{err}");
        let after = cli.inspect(&id).await.unwrap();
        assert_eq!(after.status, "running");
        assert_eq!(after.started_at, started, "never stopped or restarted");
        assert_eq!(
            fs::read_to_string(dir.join(OVERRIDE_FILE)).unwrap(),
            PREVIOUS
        );
        assert_eq!(state.in_progress().unwrap(), None);
    }
}
