//! The arguments of each call, and what is refused before running.

use std::fs;
use std::path::Path;
use std::time::Duration;

use jiff::Timestamp;
use landfall_core::config::LOG_PATTERN_LIMIT;

use super::super::{Docker, DockerCli, DockerError};
use super::{Stub, id};

#[tokio::test]
async fn compose_calls_run_in_the_directory_with_plain_argv() {
    let stub = Stub::new(
        "{ pwd -P; for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"",
    );
    let work = tempfile::tempdir().unwrap();
    stub.cli().compose_up(work.path(), "app").await.unwrap();
    let seen = fs::read_to_string(stub.path("seen")).unwrap();
    let mut lines = seen.lines();
    assert_eq!(
        lines.next().unwrap(),
        work.path().canonicalize().unwrap().to_str().unwrap()
    );
    let args: Vec<&str> = lines.collect();
    assert_eq!(
        args,
        [
            "arg:compose",
            "arg:up",
            "arg:-d",
            "arg:--no-deps",
            "arg:--",
            "arg:app"
        ]
    );
}

#[tokio::test]
async fn names_that_look_like_flags_are_refused_before_running() {
    let cli = DockerCli::with_binary("/nonexistent/docker");
    let dir = Path::new("/");
    assert!(matches!(
        cli.compose_up(dir, "--help").await,
        Err(DockerError::BadArgument { .. })
    ));
    assert!(matches!(
        cli.compose_stop(dir, "-x").await,
        Err(DockerError::BadArgument { .. })
    ));
    assert!(matches!(
        cli.pull("--all-tags").await,
        Err(DockerError::BadArgument { .. })
    ));
    assert!(matches!(
        cli.exec(&id(), &[]).await,
        Err(DockerError::BadArgument { .. })
    ));
    let since = Timestamp::UNIX_EPOCH;
    let long = "x".repeat(LOG_PATTERN_LIMIT + 1);
    for needle in ["", "a\nb", long.as_str()] {
        assert!(matches!(
            cli.logs_contain(&id(), since, since, needle).await,
            Err(DockerError::BadArgument { .. })
        ));
    }
}

#[tokio::test]
async fn exec_passes_dashed_arguments_to_the_command() {
    let stub = Stub::new(
        "{ for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"\nexit 1",
    );
    let ok = stub
        .cli()
        .exec(&id(), &["ls".into(), "-la".into()])
        .await
        .unwrap();
    assert!(!ok);
    let seen = fs::read_to_string(stub.path("seen")).unwrap();
    assert_eq!(
        seen.lines().collect::<Vec<_>>(),
        [
            "arg:exec",
            "arg:--",
            "arg:0123456789ab",
            "arg:ls",
            "arg:-la"
        ]
    );
}

#[tokio::test]
async fn logs_on_either_stream_are_scanned() {
    let since: Timestamp = "2026-11-01T10:00:00.9Z".parse().unwrap();
    let until: Timestamp = "2026-11-01T10:00:30.1Z".parse().unwrap();
    let on_stderr = Stub::new(
        "echo \"$@\" > \"$(dirname \"$0\")/seen\"\necho out line\necho 'panic: boom' >&2",
    );
    let cli = on_stderr.cli();
    assert!(
        cli.logs_contain(&id(), since, until, "panic:")
            .await
            .unwrap()
    );
    assert!(
        !cli.logs_contain(&id(), since, until, "absent")
            .await
            .unwrap()
    );
    let seen = fs::read_to_string(on_stderr.path("seen")).unwrap();
    assert_eq!(
        seen.trim(),
        "logs --since 2026-11-01T10:00:00Z --until 2026-11-01T10:00:31Z -- 0123456789ab"
    );

    drop(on_stderr);
    let on_stdout = Stub::new("echo 'listening on :8080'");
    assert!(
        on_stdout
            .cli()
            .logs_contain(&id(), since, until, "listening")
            .await
            .unwrap()
    );
}

#[tokio::test]
async fn a_log_match_stops_and_kills_the_reader() {
    let stub = Stub::new("echo 'ready'\nexec sleep 30");
    let started = std::time::Instant::now();
    assert!(
        stub.cli()
            .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "ready")
            .await
            .unwrap()
    );
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn a_failing_logs_command_reports_only_its_status() {
    let stub = Stub::new("echo 'Error: No such container: SECRET=hunter2' >&2\nexit 1");
    let err = stub
        .cli()
        .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "x")
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::FailedQuietly { .. }), "{err}");
    assert!(!format!("{err} {err:?}").contains("hunter2"));
}
