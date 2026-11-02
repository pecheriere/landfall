//! Timeouts and process groups.

use std::fs;
use std::time::Duration;

use jiff::Timestamp;

use super::super::process::await_killed;
use super::super::{Docker, DockerError, KILL_WAIT};
use super::{Stub, id};

#[tokio::test]
async fn timeout_kills_the_child() {
    let stub = Stub::new("echo $$ > \"$(dirname \"$0\")/pid\"\nexec sleep 30");
    let mut cli = stub.cli();
    cli.timeout = Duration::from_millis(500);
    let started = std::time::Instant::now();
    let err = cli
        .compose_service(stub.dir.path(), "app")
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10));
    let pid: i32 = fs::read_to_string(stub.path("pid"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let pid = rustix::process::Pid::from_raw(pid).unwrap();
    assert!(
        rustix::process::test_kill_process(pid).is_err(),
        "the child is still running"
    );
}

/// Whether a zombie: killed, and waiting for a reaper. A container without
/// an init process never reaps an orphan, so it stays one.
fn is_zombie(pid: i32) -> bool {
    fs::read_to_string(format!("/proc/{pid}/stat")).is_ok_and(|stat| {
        stat.rsplit_once(')')
            .is_some_and(|(_, rest)| rest.trim_start().starts_with('Z'))
    })
}

/// Whether `pid` has stopped running, polling briefly for it to die.
async fn gone(raw: i32) -> bool {
    let pid = rustix::process::Pid::from_raw(raw).unwrap();
    for _ in 0..40 {
        if rustix::process::test_kill_process(pid).is_err() || is_zombie(raw) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

#[tokio::test]
async fn timeout_kills_the_whole_process_group() {
    // The stub stands for `docker`, the sleeper for the compose plugin.
    let stub = Stub::new("sleep 30 &\necho $! > \"$(dirname \"$0\")/grandchild\"\nwait");
    let mut cli = stub.cli();
    cli.long_timeout = Duration::from_millis(500);
    let err = cli.compose_up(stub.dir.path(), "app").await.unwrap_err();
    assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
    let pid: i32 = fs::read_to_string(stub.path("grandchild"))
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    assert!(gone(pid).await, "the grandchild is still running");
}

#[tokio::test]
async fn dropping_a_call_kills_the_whole_process_group() {
    let stub = Stub::new(
        "sleep 30 &\necho $! > \"$(dirname \"$0\")/grandchild.tmp\"\nmv \"$(dirname \"$0\")/grandchild.tmp\" \"$(dirname \"$0\")/grandchild\"\nwait",
    );
    let cli = stub.cli();
    let mut call = Box::pin(cli.compose_up(stub.dir.path(), "app"));
    let pid = loop {
        tokio::select! {
            result = &mut call => panic!("the call ended: {result:?}"),
            () = tokio::time::sleep(Duration::from_millis(20)) => {
                if let Ok(text) = fs::read_to_string(stub.path("grandchild")) {
                    break text.trim().parse::<i32>().unwrap();
                }
            }
        }
    };
    drop(call);
    assert!(gone(pid).await, "the grandchild is still running");
}

#[tokio::test(start_paused = true)]
async fn a_command_that_outlives_its_kill_is_reported() {
    let err = await_killed("docker pull", std::future::pending::<()>(), KILL_WAIT)
        .await
        .unwrap_err();
    assert!(
        matches!(
            err,
            DockerError::Unkillable {
                command: "docker pull"
            }
        ),
        "{err}"
    );
}

#[tokio::test]
async fn a_withheld_failure_names_the_command_to_rerun() {
    let stub = Stub::new("echo 'SECRET=hunter2' >&2\nexit 1");
    let err = stub
        .cli()
        .compose_up(stub.dir.path(), "app")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("docker compose up -d --no-deps -- app in the compose directory"),
        "{text}"
    );
    assert!(!text.contains("hunter2"), "{text}");

    let err = stub
        .cli()
        .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "x")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains(
            "docker logs --since 1970-01-01T00:00:00Z --until 1970-01-01T00:00:00Z -- 0123456789ab"
        ),
        "{text}"
    );
}

#[tokio::test]
async fn a_withheld_failure_leaves_out_the_project_name_and_odd_arguments() {
    let stub = Stub::new(
        "case \"$2\" in config) echo '{\"name\":\"s3cretproject\",\"services\":{}}';; *) exit 1;; esac",
    );
    let err = stub
        .cli()
        .compose_stop(stub.dir.path(), "app")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(
        text.contains("docker compose -p <project> stop -- app"),
        "{text}"
    );
    assert!(!text.contains("s3cretproject"), "{text}");

    let err = stub
        .cli()
        .compose_up(stub.dir.path(), "a$(b) c")
        .await
        .unwrap_err();
    let text = err.to_string();
    assert!(text.contains("-- <value> in the"), "{text}");
    assert!(!text.contains("$(b)"), "{text}");
}
