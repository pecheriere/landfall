//! How a failing probe says why.

use std::time::Duration;

use landfall_core::config::Check;
use tokio::net::TcpListener;
use tokio::time::Instant;

use super::super::{CheckOptions, run_checks};
use super::{LOCALHOST, before_up, dir, http, serve, short};
use crate::testing::{FakeDocker, running};

#[tokio::test]
async fn http_on_a_container_not_running_yet_is_retried() {
    let (port, _) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
    let docker = FakeDocker::new();
    // What Docker reports for a restarting container: the network with no
    // address.
    let mut restarting = running(None, &[("app", None)]);
    restarting.status = "restarting".to_owned();
    docker.script_inspect([
        Ok(restarting),
        Ok(running(None, &[("app", Some(LOCALHOST))])),
    ]);
    run_checks(
        &docker,
        dir(),
        "app",
        &[http(port, 200)],
        before_up(),
        &short(),
    )
    .await
    .unwrap();
}

#[tokio::test(start_paused = true)]
async fn status_that_never_becomes_running_fails_naming_it() {
    let docker = FakeDocker::new();
    let mut info = running(None, &[("app", None)]);
    info.status = "restarting\nFAKE".to_owned();
    docker.script_inspect([Ok(info)]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[http(8080, 200)],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.reason, "status is \"restarting\\nFAKE\"");
}

#[tokio::test]
async fn refused_connection_says_so() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[("app", Some(LOCALHOST))]))]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[http(port, 200)],
        before_up(),
        &short(),
    )
    .await
    .unwrap_err();
    assert!(failure.reason.contains("cannot connect"), "{failure}");
    assert!(failure.reason.contains("firewall"), "{failure}");
}

#[tokio::test]
async fn silent_server_says_it_timed_out() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[("app", Some(LOCALHOST))]))]);
    let options = CheckOptions {
        http_timeout: Duration::from_millis(50),
        deadline: Duration::from_millis(200),
        ..short()
    };
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[http(port, 200)],
        before_up(),
        &options,
    )
    .await
    .unwrap_err();
    assert!(failure.reason.contains("no answer within"), "{failure}");
    drop(listener);
}

#[tokio::test(start_paused = true)]
async fn an_argument_the_driver_refuses_fails_at_once() {
    // The real driver, which refuses this before it runs anything.
    let docker = crate::docker::DockerCli::with_binary("/nonexistent/docker");
    let start = Instant::now();
    let failure = run_checks(
        &docker,
        dir(),
        "--help",
        &[Check::ContainerHealthy],
        before_up(),
        &CheckOptions::default(),
    )
    .await
    .unwrap_err();
    assert!(failure.reason.contains("refused argument"), "{failure}");
    assert_eq!(start.elapsed(), Duration::ZERO);
}
