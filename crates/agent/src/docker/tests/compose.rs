//! The `docker compose` calls, and what their failures reveal.

use std::fs;
use std::path::Path;

use super::super::{Docker, DockerError};
use super::{Stub, id};

#[tokio::test]
async fn oversized_output_is_refused() {
    let stub = Stub::new("head -c 17000000 /dev/zero");
    let err = stub.cli().pull("example").await.unwrap_err();
    assert!(matches!(err, DockerError::TooMuchOutput { .. }), "{err}");
}

#[tokio::test]
async fn config_failure_reports_only_the_status() {
    let stub = Stub::new("echo 'SECRET=hunter2 is invalid' >&2\nexit 3");
    let err = stub
        .cli()
        .compose_service(stub.dir.path(), "app")
        .await
        .unwrap_err();
    let text = format!("{err} {err:?}");
    assert!(matches!(err, DockerError::FailedQuietly { .. }), "{text}");
    assert!(!text.contains("hunter2"), "{text}");
    assert!(text.contains('3'), "{text}");
}

#[tokio::test]
async fn compose_siblings_never_quote_stderr() {
    let stub = Stub::new(
        "echo 'failed to read .env: line 3: unterminated quoted value \"hunter2' >&2\nexit 1",
    );
    let cli = stub.cli();
    let dir = stub.dir.path();
    let errors = [
        cli.compose_up(dir, "app").await.unwrap_err(),
        cli.compose_stop(dir, "app").await.unwrap_err(),
    ];
    for err in errors {
        let text = format!("{err} {err:?}");
        assert!(matches!(err, DockerError::FailedQuietly { .. }), "{text}");
        assert!(!text.contains("hunter2"), "{text}");
        assert!(text.contains("docker compose"), "{text}");
    }
}

#[tokio::test]
async fn container_lookup_goes_by_the_project_and_leaves_out_one_offs() {
    let stub = Stub::new(
        "case \"$1\" in compose) echo '{\"name\":\"stack\",\"services\":{}}'; exit 0;; esac\n{ for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"\necho 0123456789ab",
    );
    let found = stub.cli().container(stub.dir.path(), "app").await.unwrap();
    assert_eq!(found, Some(id()));
    let seen = fs::read_to_string(stub.path("seen")).unwrap();
    assert_eq!(
        seen.lines().collect::<Vec<_>>(),
        [
            "arg:ps",
            "arg:--quiet",
            "arg:--no-trunc",
            "arg:--filter",
            "arg:label=com.docker.compose.project=stack",
            "arg:--filter",
            "arg:label=com.docker.compose.service=app",
            "arg:--filter",
            "arg:label=com.docker.compose.oneoff=False",
        ]
    );
}

#[tokio::test]
async fn a_failed_lookup_by_project_does_not_repeat_the_name() {
    let stub = Stub::new(
        "case \"$1\" in compose) echo '{\"name\":\"s3cretproject\",\"services\":{}}'; exit 0;; esac\necho 's3cretproject: bad filter' >&2\nexit 1",
    );
    let err = stub
        .cli()
        .container(stub.dir.path(), "app")
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::FailedQuietly { .. }), "{err}");
    let text = format!("{err} {err:?}");
    assert!(!text.contains("s3cretproject"), "{text}");
}

#[tokio::test]
async fn lookup_by_directory_loads_no_project() {
    let stub = Stub::new(
        "{ for a in \"$@\"; do echo \"arg:$a\"; done; } >> \"$(dirname \"$0\")/seen\"\necho 0123456789ab",
    );
    let found = stub
        .cli()
        .container_at(Path::new("/srv/app"), "app")
        .await
        .unwrap();
    assert_eq!(found, Some(id()));
    let seen = fs::read_to_string(stub.path("seen")).unwrap();
    assert_eq!(
        seen.lines().collect::<Vec<_>>(),
        [
            "arg:ps",
            "arg:--quiet",
            "arg:--no-trunc",
            "arg:--filter",
            "arg:label=com.docker.compose.project.working_dir=/srv/app",
            "arg:--filter",
            "arg:label=com.docker.compose.service=app",
            "arg:--filter",
            "arg:label=com.docker.compose.oneoff=False",
        ]
    );
}
