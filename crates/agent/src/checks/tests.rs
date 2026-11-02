//! The checks against a fake Docker and a local server, and against a real Docker.

use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Arc;
use std::sync::Mutex;
use std::time::Duration;

use jiff::SignedDuration;
use jiff::Timestamp;
use landfall_core::config::Check;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

use super::CheckOptions;
use crate::docker::ContainerInfo;
use crate::testing::{Call, FakeDocker};

mod commands_and_logs;
mod deadlines;
mod failures;
mod health;
mod http_checks;
mod real;
mod restarts;

const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

fn dir() -> &'static Path {
    Path::new("/srv/compose/app")
}

fn short() -> CheckOptions {
    CheckOptions {
        interval: Duration::from_millis(10),
        deadline: Duration::from_millis(500),
        http_timeout: Duration::from_millis(400),
        settle: Duration::from_millis(10),
    }
}

/// For the tests that do not look at where a log scan starts.
fn before_up() -> Timestamp {
    Timestamp::UNIX_EPOCH
}

fn http(port: u16, expect: u16) -> Check {
    Check::Http {
        path: "/health".to_owned(),
        network: "app".to_owned(),
        port,
        expect,
    }
}

fn inspects(docker: &FakeDocker) -> usize {
    docker.count(|c| matches!(c, Call::Inspect(_)))
}

/// A local server answering every request with `response`; the request
/// lines it saw are collected.
async fn serve(response: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let seen = Arc::new(Mutex::new(Vec::new()));
    let log = Arc::clone(&seen);
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let log = Arc::clone(&log);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                let n = socket.read(&mut buf).await.unwrap_or(0);
                let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                log.lock()
                    .unwrap()
                    .push(text.lines().next().unwrap_or_default().to_owned());
                let _ = socket.write_all(response.as_bytes()).await;
            });
        }
    });
    (port, seen)
}

/// `info` from a start `secs` later.
fn restarted(info: &ContainerInfo, secs: i64) -> ContainerInfo {
    let mut later = info.clone();
    later.started_at = info
        .started_at
        .checked_add(SignedDuration::from_secs(secs))
        .unwrap();
    later
}

fn command() -> Check {
    Check::Command {
        argv: vec!["/bin/check".to_owned()],
    }
}

fn no_log_match(within_secs: u32) -> Check {
    Check::NoLogMatch {
        pattern: "panic".to_owned(),
        within_secs,
    }
}
