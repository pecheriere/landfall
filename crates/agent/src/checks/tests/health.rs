//! The container's own health.

use std::time::Duration;

use landfall_core::config::Check;
use tokio::time::Instant;

use super::super::{CheckOptions, run_checks};
use super::{before_up, dir, inspects};
use crate::testing::{FakeDocker, running};

#[tokio::test(start_paused = true)]
async fn healthy_container_passes() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(summary.checks.len(), 1);
    assert_eq!(summary.checks[0].attempts, 2, "a pass and its confirmation");
}

#[tokio::test(start_paused = true)]
async fn no_healthcheck_fails_at_once() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[]))]);
    let start = Instant::now();
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[0] container_healthy");
    assert!(failure.reason.contains("no healthcheck"), "{failure}");
    assert_eq!(inspects(&docker), 1);
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn starting_then_healthy_passes() {
    let docker = FakeDocker::new();
    docker.script_inspect([
        Ok(running(Some("starting"), &[])),
        Ok(running(Some("unhealthy"), &[])),
        Ok(running(Some("healthy"), &[])),
    ]);
    let options = CheckOptions::default();
    let start = Instant::now();
    let summary = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy],
        before_up(),
        &options,
    )
    .await
    .unwrap();
    assert_eq!(summary.checks[0].attempts, 4);
    assert_eq!(start.elapsed(), options.interval * 2 + options.settle);
}

#[tokio::test(start_paused = true)]
async fn container_that_goes_away_is_retried() {
    let docker = FakeDocker::new();
    docker.script_container([
        Ok(None),
        Err("gone"),
        Ok(Some(crate::testing::container_id())),
    ]);
    docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
    run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap();
    assert_eq!(inspects(&docker), 4, "two looks in each of two rounds");
}
