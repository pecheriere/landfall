//! Tests against a real Docker daemon: `cargo test -p landfall-agent
//! -- --ignored docker`.

use std::fs;
use std::net::IpAddr;
use std::process::Command as StdCommand;
use std::time::Duration;

use jiff::Timestamp;

use super::super::{Docker, DockerCli};
use crate::testing::{ComposeProject, TEST_IMAGE};

/// Two long-running services on the project's network, one with a
/// healthcheck.
async fn project(cli: &DockerCli) -> ComposeProject {
    let services = format!(
        "  plain:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n    networks: [net]\n  healthy:\n    image: {TEST_IMAGE}\n    command: [sleep, '300']\n    stop_grace_period: 1s\n    networks: [net]\n    healthcheck:\n      test: [CMD, 'true']\n      interval: 1s\n"
    );
    ComposeProject::new(cli, &services).await
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_inspect_reads_what_the_template_asks_for() {
    let cli = DockerCli::new();
    let project = project(&cli).await;
    let before = Timestamp::now();
    cli.compose_up(project.path(), "plain").await.unwrap();
    cli.compose_up(project.path(), "healthy").await.unwrap();

    let svc = cli.compose_service(project.path(), "plain").await.unwrap();
    assert_eq!(svc.image.as_deref(), Some(TEST_IMAGE));
    assert!(!svc.has_build);

    let plain = cli
        .container(project.path(), "plain")
        .await
        .unwrap()
        .unwrap();
    let info = cli.inspect(&plain).await.unwrap();
    // Started by digest: the container keeps the digest reference.
    assert_eq!(info.image, TEST_IMAGE);
    assert_eq!(info.status, "running");
    assert_eq!(info.health, None);
    assert!(
        info.started_at
            >= before
                .checked_sub(jiff::SignedDuration::from_secs(5))
                .unwrap()
    );
    assert!(info.started_at <= Timestamp::now());
    let net = format!("{}-net", project.name);
    assert_eq!(info.networks.len(), 1, "{:?}", info.networks);
    assert!(
        matches!(info.networks[&net], Some(IpAddr::V4(_))),
        "{:?}",
        info.networks
    );

    let healthy = cli
        .container(project.path(), "healthy")
        .await
        .unwrap()
        .unwrap();
    let mut health = None;
    for _ in 0..30 {
        health = cli.inspect(&healthy).await.unwrap().health;
        if health.as_deref() == Some("healthy") {
            break;
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
    assert_eq!(health.as_deref(), Some("healthy"));

    assert!(cli.exec(&plain, &["true".into()]).await.unwrap());
    assert!(!cli.exec(&plain, &["false".into()]).await.unwrap());
    assert!(
        !cli.logs_contain(&plain, before, Timestamp::now(), "never-logged")
            .await
            .unwrap()
    );

    cli.compose_stop(project.path(), "plain").await.unwrap();
    assert_eq!(cli.container(project.path(), "plain").await.unwrap(), None);
    assert_eq!(
        cli.container_at(project.path(), "plain").await.unwrap(),
        None
    );
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_config_ps_and_stop_work_on_a_service_without_an_image() {
    let cli = DockerCli::new();
    let project = project(&cli).await;
    cli.compose_up(project.path(), "plain").await.unwrap();
    let id = cli
        .container(project.path(), "plain")
        .await
        .unwrap()
        .unwrap();
    // The override of a failed first deploy has been taken back out.
    fs::write(
        project.path().join("compose.yaml"),
        format!(
            "name: {}\nservices:\n  plain:\n    command: [sleep, '300']\n    stop_grace_period: 1s\n",
            project.name
        ),
    )
    .unwrap();

    let svc = cli.compose_service(project.path(), "plain").await.unwrap();
    assert_eq!(svc.image, None);
    assert!(!svc.has_build);
    assert_eq!(
        cli.container(project.path(), "plain")
            .await
            .unwrap()
            .as_ref(),
        Some(&id)
    );

    cli.compose_stop(project.path(), "plain").await.unwrap();
    assert_eq!(cli.inspect(&id).await.unwrap().status, "exited");
}

#[tokio::test]
#[ignore = "docker: runs in ci.yml"]
async fn docker_ps_ignores_one_off_containers() {
    let cli = DockerCli::new();
    let project = project(&cli).await;
    assert_eq!(cli.container(project.path(), "plain").await.unwrap(), None);
    cli.compose_up(project.path(), "plain").await.unwrap();
    let service = cli
        .container(project.path(), "plain")
        .await
        .unwrap()
        .unwrap();

    let run = StdCommand::new("docker")
        .args(["compose", "run", "-d", "--no-deps", "plain", "sleep", "300"])
        .current_dir(project.path())
        .output()
        .unwrap();
    assert!(run.status.success());
    assert_eq!(project.all_containers().len(), 2);

    assert_eq!(
        cli.container(project.path(), "plain").await.unwrap(),
        Some(service)
    );
}
