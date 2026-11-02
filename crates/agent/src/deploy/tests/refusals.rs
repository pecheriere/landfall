//! What the preflight refuses, before anything changes.

use std::fs;

use super::super::{DeployError, Outcome};
use super::{
    Fixture, OLD, PREVIOUS, STOP_TRUE, changes, deploy, fixture, healthy_deploy, image,
    override_text, recovered,
};
use crate::compose::OVERRIDE_FILE;
use crate::docker::{ServiceConfig, ServiceContainer};

#[tokio::test]
async fn recover_without_in_progress_is_an_error() {
    let f = fixture("");
    let err = recovered(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::NothingToRecover(_)), "{err}");
    assert_eq!(f.docker.calls(), []);
}

#[tokio::test]
async fn missing_compose_file_entry_refuses_before_stop() {
    let f = fixture(STOP_TRUE);
    let secret = "registry.example/app:token-s3cret";
    f.docker
        .script_compose_service([Ok(image(Some(secret))), Ok(image(Some(secret)))]);

    let err = deploy(&f).await.unwrap_err();

    assert!(
        matches!(err, DeployError::OverrideNotApplied { .. }),
        "{err}"
    );
    let text = format!("{err} {err:?}");
    assert!(
        text.contains("COMPOSE_FILE=compose.yaml:compose.landfall.yaml") && text.contains(".env"),
        "{text}"
    );
    assert!(!text.contains("s3cret"), "{text}");
    assert_eq!(changes(&f), ["config", "config"], "no pull, stop or up");
    assert_eq!(override_text(&f.dir), PREVIOUS);
    assert_eq!(f.state.in_progress().unwrap(), None);
}

/// A refusal in the preflight: nothing was run after it, and nothing is left.
fn refused_before_anything_changed(f: &Fixture, err: &DeployError) {
    assert_eq!(changes(f), ["config"], "{err}");
    assert_eq!(override_text(&f.dir), PREVIOUS, "{err}");
    assert_eq!(f.state.in_progress().unwrap(), None, "{err}");
}

#[tokio::test]
async fn a_service_asking_for_several_containers_is_refused_naming_the_fix() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(ServiceConfig {
        replicas: 2,
        ..image(Some(OLD))
    })]);
    let err = deploy(&f).await.unwrap_err();
    assert!(
        matches!(err, DeployError::Scaled { replicas: 2, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("deploy.replicas"), "{err}");
    refused_before_anything_changed(&f, &err);
}

#[tokio::test]
async fn a_service_asking_for_no_container_is_refused() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(ServiceConfig {
        replicas: 0,
        ..image(Some(OLD))
    })]);
    let err = deploy(&f).await.unwrap_err();
    assert!(
        matches!(err, DeployError::Scaled { replicas: 0, .. }),
        "{err}"
    );
    assert!(err.to_string().contains("exactly one"), "{err}");
    refused_before_anything_changed(&f, &err);
}

/// A container of the service, with how the lookup describes it.
fn found(running: bool, in_project: bool, working_dir: Option<&str>) -> ServiceContainer {
    ServiceContainer {
        id: crate::testing::container_id(),
        running,
        in_project,
        working_dir: working_dir.map(str::to_owned),
    }
}

fn found_dir(f: &Fixture) -> &str {
    f.dir.to_str().unwrap()
}

/// The preflight finds these, and refuses.
async fn refused_finding(f: &Fixture, containers: Vec<ServiceContainer>) -> DeployError {
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker.script_service_containers([Ok(containers)]);
    let err = deploy(f).await.unwrap_err();
    refused_before_anything_changed(f, &err);
    err
}

#[tokio::test]
async fn a_lone_running_container_outside_the_project_is_refused() {
    let f = fixture(STOP_TRUE);
    let dir = found_dir(&f).to_owned();
    // Its own project is stopped, or was renamed away from it.
    let err = refused_finding(
        &f,
        vec![
            found(false, true, Some(&dir)),
            found(true, false, Some(&dir)),
        ],
    )
    .await;
    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
    assert!(
        err.to_string().contains("docker compose -p <other> down"),
        "{err}"
    );
}

#[tokio::test]
async fn a_second_project_through_a_symlink_to_this_directory_is_outside_too() {
    let f = fixture(STOP_TRUE);
    let link = f.dir.with_file_name("link");
    std::os::unix::fs::symlink(&f.dir, &link).unwrap();
    let err = refused_finding(&f, vec![found(true, false, link.to_str())]).await;
    assert!(
        matches!(err, DeployError::OutsideTheProject { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn a_container_of_the_project_started_elsewhere_is_refused_running_or_not() {
    for running in [true, false] {
        let f = fixture(STOP_TRUE);
        let elsewhere = f.dir.with_file_name("elsewhere");
        fs::create_dir(&elsewhere).unwrap();
        let err = refused_finding(&f, vec![found(running, true, elsewhere.to_str())]).await;
        assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
        let text = err.to_string();
        assert!(
            text.contains("`name:`") && text.contains("`COMPOSE_PROJECT_NAME`"),
            "{text}"
        );
        assert!(text.contains(elsewhere.to_str().unwrap()), "{text}");
    }
}

#[tokio::test]
async fn a_working_dir_label_of_the_project_that_names_nothing_here_is_refused_and_quoted() {
    for label in [
        None,
        Some("relative/path"),
        Some("/does/not/exist\"\n\u{1b}[31mforged"),
    ] {
        let f = fixture(STOP_TRUE);
        let err = refused_finding(&f, vec![found(true, true, label)]).await;
        assert!(matches!(err, DeployError::StartedElsewhere { .. }), "{err}");
        let text = err.to_string();
        assert!(
            !text.contains('\n') && !text.contains('\u{1b}'),
            "the label is quoted: {text}"
        );
    }
}

#[tokio::test]
async fn another_project_elsewhere_with_the_same_service_name_passes() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);
    let elsewhere = f.dir.with_file_name("elsewhere");
    fs::create_dir(&elsewhere).unwrap();
    f.docker.script_service_containers([Ok(vec![
        found(true, false, elsewhere.to_str()),
        found(false, false, elsewhere.to_str()),
        // Its label can't be resolved, which only matters in this project.
        found(true, false, Some("/does/not/exist")),
        found(true, false, None),
    ])]);

    let report = deploy(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
}

#[tokio::test]
async fn a_stopped_container_of_another_project_in_this_directory_passes() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);
    let dir = found_dir(&f).to_owned();
    f.docker
        .script_service_containers([Ok(vec![found(false, false, Some(&dir))])]);

    let report = deploy(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
}

#[tokio::test]
async fn a_start_through_a_symlink_to_this_directory_is_not_elsewhere() {
    let f = fixture(STOP_TRUE);
    healthy_deploy(&f);
    let link = f.dir.with_file_name("link");
    std::os::unix::fs::symlink(&f.dir, &link).unwrap();
    f.docker
        .script_service_containers([Ok(vec![found(true, true, link.to_str())])]);

    let report = deploy(&f).await.unwrap();

    assert_eq!(report.outcome, Outcome::Deployed);
}

#[tokio::test]
async fn several_running_containers_are_refused_naming_the_fix() {
    let f = fixture(STOP_TRUE);
    let dir = found_dir(&f).to_owned();
    let err = refused_finding(
        &f,
        vec![found(true, true, Some(&dir)), found(true, true, Some(&dir))],
    )
    .await;
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
    assert!(err.to_string().contains("--scale app=1"), "{err}");
}

#[tokio::test]
async fn a_second_project_in_the_directory_is_refused() {
    let f = fixture(STOP_TRUE);
    let dir = found_dir(&f).to_owned();
    let err = refused_finding(
        &f,
        vec![
            found(true, true, Some(&dir)),
            found(true, false, Some(&dir)),
        ],
    )
    .await;
    assert!(
        matches!(err, DeployError::SeveralContainers { .. }),
        "{err}"
    );
}

#[tokio::test]
async fn a_failing_container_lookup_is_refused_before_the_marker() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(image(Some(OLD)))]);
    f.docker.script_service_containers([Err("daemon gone")]);
    let err = deploy(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::Compose { .. }), "{err}");
    refused_before_anything_changed(&f, &err);
}

#[tokio::test]
async fn service_without_an_image_after_the_override_is_refused_too() {
    let f = fixture("");
    f.docker.script_compose_service([Ok(image(None))]);
    let err = deploy(&f).await.unwrap_err();
    assert!(
        matches!(err, DeployError::OverrideNotApplied { .. }),
        "{err}"
    );
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn failing_compose_during_preflight_puts_the_override_back() {
    let f = fixture("");
    f.docker
        .script_compose_service([Ok(image(Some(OLD))), Err("bad project")]);
    let err = deploy(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::Compose { .. }), "{err}");
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn build_service_is_refused() {
    let f = fixture(STOP_TRUE);
    f.docker.script_compose_service([Ok(ServiceConfig {
        image: None,
        has_build: true,
        replicas: 1,
    })]);

    let err = deploy(&f).await.unwrap_err();

    assert!(matches!(err, DeployError::HasBuild { .. }), "{err}");
    assert!(err.to_string().contains("build"), "{err}");
    assert_eq!(changes(&f), ["config"]);
    assert_eq!(override_text(&f.dir), PREVIOUS);
}

#[tokio::test]
async fn symlinked_override_is_refused() {
    let f = fixture("");
    let elsewhere = f.dir.join("elsewhere");
    fs::write(&elsewhere, "not ours").unwrap();
    fs::remove_file(f.dir.join(OVERRIDE_FILE)).unwrap();
    std::os::unix::fs::symlink(&elsewhere, f.dir.join(OVERRIDE_FILE)).unwrap();

    let err = deploy(&f).await.unwrap_err();

    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(f.docker.calls(), []);
    assert_eq!(fs::read_to_string(&elsewhere).unwrap(), "not ours");
}

#[tokio::test]
async fn oversized_override_is_refused() {
    let f = fixture("");
    fs::write(f.dir.join(OVERRIDE_FILE), vec![b'#'; 2 * 1024 * 1024]).unwrap();
    let err = deploy(&f).await.unwrap_err();
    assert!(matches!(err, DeployError::File { .. }), "{err}");
    assert_eq!(f.docker.calls(), []);
}
