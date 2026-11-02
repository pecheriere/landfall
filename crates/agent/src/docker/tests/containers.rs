//! Listing containers, and `exec` and `logs`.

use std::fs;
use std::time::Duration;

use jiff::Timestamp;

use super::super::{
    ContainerId, Docker, DockerError, SERVICE_CONTAINER_FORMAT, STDERR_TAIL, ServiceContainer,
};
use super::{Stub, id};

#[tokio::test]
async fn service_containers_are_listed_in_any_state_and_project() {
    let stub = Stub::new(
        "case \"$1\" in compose) echo '{\"name\":\"stack\",\"services\":{}}'; exit 0;; esac\n{ for a in \"$@\"; do echo \"arg:$a\"; done; } > \"$(dirname \"$0\")/seen\"\ncat \"$(dirname \"$0\")/reply\"",
    );
    let cli = stub.cli();
    fs::write(
        stub.path("reply"),
        "[\"0123456789ab\",\"running\",\"stack\",\"/srv/compose/app\"]\n\
             [\"0123456789ac\",\"exited\",\"other\",\"\"]\n\
             [\"0123456789ad\",\"paused\",\"stack\",\"/srv/a,b\"]\n",
    )
    .unwrap();

    let found = cli
        .service_containers(stub.dir.path(), "app")
        .await
        .unwrap();

    let ids = |text: &str| text.parse::<ContainerId>().unwrap();
    assert_eq!(
        found,
        [
            ServiceContainer {
                id: ids("0123456789ab"),
                running: true,
                in_project: true,
                working_dir: Some("/srv/compose/app".to_owned()),
            },
            ServiceContainer {
                id: ids("0123456789ac"),
                running: false,
                in_project: false,
                working_dir: None,
            },
            ServiceContainer {
                id: ids("0123456789ad"),
                running: true,
                in_project: true,
                working_dir: Some("/srv/a,b".to_owned()),
            },
        ]
    );
    let seen = fs::read_to_string(stub.path("seen")).unwrap();
    let seen: Vec<&str> = seen.lines().collect();
    assert_eq!(
        seen,
        [
            "arg:ps",
            "arg:--all",
            "arg:--no-trunc",
            "arg:--filter",
            "arg:label=com.docker.compose.service=app",
            "arg:--filter",
            "arg:label=com.docker.compose.oneoff=False",
            "arg:--format",
            format!("arg:{SERVICE_CONTAINER_FORMAT}").as_str(),
        ]
    );

    fs::write(stub.path("reply"), "").unwrap();
    assert_eq!(
        cli.service_containers(stub.dir.path(), "app")
            .await
            .unwrap(),
        []
    );

    for reply in [
        "s3cret, not JSON\n",
        "[\"s3cret\",\"running\",\"stack\",\"\"]\n",
    ] {
        fs::write(stub.path("reply"), reply).unwrap();
        let err = cli
            .service_containers(stub.dir.path(), "app")
            .await
            .unwrap_err();
        assert!(matches!(err, DockerError::BadOutput { .. }), "{err}");
        assert!(!format!("{err} {err:?}").contains("s3cret"), "{err}");
    }
}

#[tokio::test]
async fn a_service_name_that_looks_like_a_flag_is_refused_before_listing() {
    let stub = Stub::new("exit 0");
    let err = stub
        .cli()
        .service_containers(stub.dir.path(), "--all")
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::BadArgument { .. }), "{err}");
}

#[tokio::test]
async fn logs_use_the_short_timeout() {
    let stub = Stub::new("exec sleep 30");
    let mut cli = stub.cli();
    cli.timeout = Duration::from_millis(300);
    let started = std::time::Instant::now();
    let err = cli
        .logs_contain(&id(), Timestamp::UNIX_EPOCH, Timestamp::UNIX_EPOCH, "never")
        .await
        .unwrap_err();
    assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
    assert!(started.elapsed() < Duration::from_secs(10));
}

#[tokio::test]
async fn exec_output_is_discarded_not_buffered() {
    let stub = Stub::new("head -c 40000000 /dev/zero\nexit 0");
    assert!(stub.cli().exec(&id(), &["true".into()]).await.unwrap());
}

#[tokio::test]
async fn exec_times_out() {
    let stub = Stub::new("exec sleep 30");
    let mut cli = stub.cli();
    cli.timeout = Duration::from_millis(300);
    let err = cli.exec(&id(), &["true".into()]).await.unwrap_err();
    assert!(matches!(err, DockerError::Timeout { .. }), "{err}");
}

#[tokio::test]
async fn other_failures_quote_the_end_of_stderr() {
    let stub = Stub::new(
        "head -c 10000 /dev/zero | tr '\\0' 'a' >&2\necho 'pull access denied' >&2\nexit 1",
    );
    let err = stub.cli().pull("example").await.unwrap_err();
    let DockerError::Failed { stderr, .. } = &err else {
        panic!("{err}");
    };
    assert!(stderr.len() <= STDERR_TAIL, "{}", stderr.len());
    assert!(stderr.ends_with("pull access denied\n"));
}
