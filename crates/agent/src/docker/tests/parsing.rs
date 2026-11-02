//! Reading `docker` output, and scanning for a needle.

use super::super::parse::{parse_config, parse_container, parse_inspect};
use super::super::scan::LineScanner;
use super::super::{
    ContainerId, DockerCli, DockerError, INSPECT_FORMAT, LINE_LIMIT, READ_CHUNK, SCRUBBED_ENV,
};
use super::id;

#[test]
fn compose_config_finds_image_and_build() {
    let raw = br#"{"name":"stack","services":{
            "app":{"image":"ghcr.io/example/app@sha256:00","environment":{"TOKEN":"s3cret"}},
            "worker":{"build":{"context":"."},"command":["run"]},
            "db":{"image":"postgres:17","ports":[{"target":5432}]}},
            "networks":{"default":{"name":"stack_default"}}}"#;
    let app = parse_config(raw, "app").unwrap();
    assert_eq!(app.image.as_deref(), Some("ghcr.io/example/app@sha256:00"));
    assert!(!app.has_build);
    let worker = parse_config(raw, "worker").unwrap();
    assert_eq!(worker.image, None);
    assert!(worker.has_build);
    assert!(matches!(
        parse_config(raw, "nope"),
        Err(DockerError::NoSuchService { service }) if service == "nope"
    ));
    assert!(matches!(
        parse_config(br#"{"name":"stack"}"#, "app"),
        Err(DockerError::NoSuchService { .. })
    ));
}

#[test]
fn compose_config_reads_how_many_containers_the_service_asks_for() {
    let raw = br#"{"services":{
            "plain":{"image":"i"},
            "one":{"image":"i","scale":1,"deploy":{"replicas":1}},
            "scaled":{"image":"i","scale":2},
            "replicated":{"image":"i","deploy":{"replicas":3,"resources":{"limits":{"memory":"1"}}}},
            "other":{"image":"i","deploy":{"resources":{}}},
            "no_scale":{"image":"i","scale":0},
            "no_replicas":{"image":"i","deploy":{"replicas":0}},
            "one_and_none":{"image":"i","scale":1,"deploy":{"replicas":0}}}}"#;
    for (service, replicas) in [
        ("plain", 1),
        ("one", 1),
        ("scaled", 2),
        ("replicated", 3),
        ("other", 1),
        ("no_scale", 0),
        ("no_replicas", 0),
        ("one_and_none", 0),
    ] {
        assert_eq!(
            parse_config(raw, service).unwrap().replicas,
            replicas,
            "{service}"
        );
    }
}

#[test]
fn compose_config_error_never_contains_the_output() {
    // `image` has the wrong type, so serde would quote the offending
    // value; the secret sits in the value and in the key.
    let raw = br#"{"services":{"app":{"image":"hunter2","environment":{"SECRET=hunter2":1}},
            "other":{"image":{"SECRET":"hunter2"}}}}"#;
    let err = parse_config(raw, "app").unwrap_err();
    assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
    let truncated = br#"{"services":{"app":{"image":"x","environment":{"SECRET":"hunter2"#;
    let err = parse_config(truncated, "app").unwrap_err();
    assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
    let err = parse_config(b"SECRET=hunter2", "app").unwrap_err();
    assert!(!format!("{err} {err:?}").contains("hunter2"), "{err}");
}

#[test]
fn inspect_output_parses() {
    let raw = br#"{"image":"ghcr.io/example/app@sha256:00","status":"running","health":null,"started_at":"2026-11-01T10:00:00.123456789Z","networks":[["app_default","172.18.0.2",""],["host-only","",""],["v6","","fd00::2"],["dual","172.19.0.3","fd00::3"],null]}
"#;
    let info = parse_inspect(raw).unwrap();
    assert_eq!(info.image, "ghcr.io/example/app@sha256:00");
    assert_eq!(info.status, "running");
    assert_eq!(info.health, None);
    assert_eq!(
        info.started_at,
        "2026-11-01T10:00:00.123456789Z".parse().unwrap()
    );
    assert_eq!(info.networks.len(), 4);
    assert_eq!(
        info.networks["app_default"],
        Some("172.18.0.2".parse().unwrap())
    );
    assert_eq!(info.networks["host-only"], None);
    assert_eq!(info.networks["v6"], Some("fd00::2".parse().unwrap()));
    assert_eq!(info.networks["dual"], Some("172.19.0.3".parse().unwrap()));

    let healthy = br#"{"image":"i","status":"running","health":"healthy","started_at":"2026-11-01T10:00:00Z","networks":[null]}"#;
    let info = parse_inspect(healthy).unwrap();
    assert_eq!(info.health.as_deref(), Some("healthy"));
    assert!(info.networks.is_empty());
}

#[test]
fn inspect_refuses_what_it_cannot_read() {
    for raw in [
        &br#"{"image":"i"}"#[..],
        br#"{"image":"i","status":"s","health":null,"started_at":"yesterday","networks":[null]}"#,
        br#"{"image":"i","status":"s","health":null,"started_at":"2026-11-01T10:00:00Z","networks":[["n","999.1.1.1",""],null]}"#,
        b"not json",
    ] {
        assert!(matches!(
            parse_inspect(raw),
            Err(DockerError::BadOutput { .. })
        ));
    }
}

#[test]
fn commands_lose_the_compose_selection_variables() {
    let cli = DockerCli::with_binary("docker");
    let cmd = cli.command(None);
    let envs: Vec<_> = cmd.as_std().get_envs().collect();
    for var in SCRUBBED_ENV {
        assert!(
            envs.iter().any(|(k, v)| *k == var && v.is_none()),
            "{var} is not removed"
        );
    }
}

#[test]
fn inspect_template_reads_no_environment() {
    assert!(!INSPECT_FORMAT.contains("Env"));
    assert!(INSPECT_FORMAT.contains("{{if .State.Health}}"));
}

#[test]
fn container_id_rejects_non_hex() {
    for bad in [
        "",
        "0123456789a",
        "0123456789AB",
        "0123456789ag",
        "--all0123456",
        "0123456789ab\n",
        &"a".repeat(65),
    ] {
        assert!(bad.parse::<ContainerId>().is_err(), "{bad:?}");
    }
    assert!("0123456789ab".parse::<ContainerId>().is_ok());
    assert!("a".repeat(64).parse::<ContainerId>().is_ok());
}

#[test]
fn container_output_is_zero_or_one_id() {
    assert_eq!(parse_container(b"").unwrap(), None);
    assert_eq!(parse_container(b"\n").unwrap(), None);
    assert_eq!(parse_container(b"0123456789ab\n").unwrap(), Some(id()));
    assert!(matches!(
        parse_container(b"0123456789ab\n0123456789ac\n"),
        Err(DockerError::SeveralContainers { .. })
    ));
    assert!(parse_container(b"not-an-id\n").is_err());
}

#[test]
fn scanner_finds_a_needle_across_chunks_and_not_across_lines() {
    let mut s = LineScanner::new(b"fatal error");
    assert!(!s.feed(b"all fine\nfat"));
    assert!(s.feed(b"al error here\n"));

    let mut s = LineScanner::new(b"ab");
    assert!(!s.feed(b"xa\nbx\n"));
    assert!(!s.finish());

    let mut s = LineScanner::new(b"tail");
    assert!(!s.feed(b"no newline at the end, just the tai"));
    assert!(!s.finish());
    assert!(s.feed(b"l"));
}

#[test]
fn scanner_scans_a_long_line_in_bounded_chunks() {
    let needle = b"NEEDLE";
    let mut s = LineScanner::new(needle);
    // A match straddling the 1 MiB boundary.
    let mut line = vec![b'x'; LINE_LIMIT - 3];
    line.extend_from_slice(needle);
    line.extend_from_slice(b"yyy");
    assert!(s.feed(&line));
    assert!(s.line.len() <= LINE_LIMIT);

    // Several limits of filler never grow the buffer.
    let mut s = LineScanner::new(needle);
    let filler = vec![b'x'; READ_CHUNK];
    for _ in 0..(3 * LINE_LIMIT / READ_CHUNK) {
        assert!(!s.feed(&filler));
        assert!(s.line.len() <= LINE_LIMIT);
    }
    assert!(s.feed(b"NEEDLE"));
}
