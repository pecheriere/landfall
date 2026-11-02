//! The HTTP probe.

use std::net::IpAddr;
use std::time::Duration;

use landfall_core::config::Check;
use tokio::time::Instant;

use super::super::{CheckOptions, probe_url, run_checks};
use super::{LOCALHOST, before_up, dir, http, inspects, serve, short};
use crate::testing::{FakeDocker, running};

#[tokio::test]
async fn http_matching_status_passes() {
    let (port, seen) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("healthy"), &[("app", Some(LOCALHOST))]))]);
    run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy, http(port, 200)],
        before_up(),
        &short(),
    )
    .await
    .unwrap();
    assert_eq!(
        seen.lock().unwrap().as_slice(),
        ["GET /health HTTP/1.1", "GET /health HTTP/1.1"]
    );
}

#[tokio::test]
async fn http_wrong_status_fails_naming_it() {
    let (port, _) = serve("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").await;
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(Some("healthy"), &[("app", Some(LOCALHOST))]))]);
    let failure = run_checks(
        &docker,
        dir(),
        "app",
        &[Check::ContainerHealthy, http(port, 200)],
        before_up(),
        &short(),
    )
    .await
    .unwrap_err();
    assert_eq!(failure.check, "checks[1] http /health on app");
    assert_eq!(failure.reason, "expected 200, got 503");
    assert!(inspects(&docker) > 1, "a failing probe is retried");
}

#[tokio::test]
async fn http_does_not_follow_redirects() {
    let (port, seen) = serve(
        "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\n\r\n",
    )
    .await;
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
    assert_eq!(failure.reason, "expected 200, got 302");
    let seen = seen.lock().unwrap();
    assert!(!seen.is_empty());
    assert!(seen.iter().all(|line| line == "GET /health HTTP/1.1"));
}

#[tokio::test(start_paused = true)]
async fn http_network_not_attached_fails_at_once() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[("other", Some(LOCALHOST))]))]);
    let start = Instant::now();
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
    assert_eq!(failure.check, "checks[0] http /health on app");
    assert!(
        failure.reason.contains("not attached to network app"),
        "{failure}"
    );
    assert_eq!(inspects(&docker), 1);
    assert_eq!(start.elapsed(), Duration::ZERO);
}

#[tokio::test(start_paused = true)]
async fn http_network_without_address_fails_at_once() {
    let docker = FakeDocker::new();
    docker.script_inspect([Ok(running(None, &[("app", None)]))]);
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
    assert!(
        failure.reason.contains("no address on network app"),
        "{failure}"
    );
    assert_eq!(inspects(&docker), 1);
}

#[test]
fn ipv6_addresses_are_bracketed() {
    let ip: IpAddr = "fd00::2".parse().unwrap();
    assert_eq!(
        probe_url(ip, 8080, "/health").unwrap().as_str(),
        "http://[fd00::2]:8080/health"
    );
}
