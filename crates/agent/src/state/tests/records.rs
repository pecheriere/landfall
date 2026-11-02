//! Opening the directory, locking, and the per-deployment records.

use std::fs;
use std::fs::Permissions;
use std::os::unix::fs::PermissionsExt;

use super::super::{
    DEPLOYED, IN_PROGRESS, InProgress, Phase, RecordedBackup, StateDir, StateError,
};
use super::{deployed, id, once_released, state};

#[test]
fn state_dir_must_not_be_group_writable() {
    let tmp = tempfile::tempdir().unwrap();
    fs::set_permissions(tmp.path(), Permissions::from_mode(0o770)).unwrap();
    let err = StateDir::open(tmp.path()).unwrap_err();
    assert!(matches!(err, StateError::Writable { .. }), "{err}");
    fs::set_permissions(tmp.path(), Permissions::from_mode(0o702)).unwrap();
    assert!(matches!(
        StateDir::open(tmp.path()).unwrap_err(),
        StateError::Writable { .. }
    ));
    fs::set_permissions(tmp.path(), Permissions::from_mode(0o750)).unwrap();
    StateDir::open(tmp.path()).unwrap();
}

#[test]
fn state_dir_must_be_an_existing_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let err = StateDir::open(&tmp.path().join("missing")).unwrap_err();
    assert!(matches!(err, StateError::Io { .. }), "{err}");
    let link = tmp.path().join("link");
    std::os::unix::fs::symlink(tmp.path(), &link).unwrap();
    let err = StateDir::open(&link).unwrap_err();
    assert!(matches!(err, StateError::NotADirectory(_)), "{err}");
}

#[test]
fn second_lock_is_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let first = state(&tmp);
    let second = state(&tmp);
    let held = first.lock().unwrap();
    let err = second.lock().unwrap_err();
    assert!(matches!(&err, StateError::Busy(d) if *d == id("example/prod")));
    assert!(err.to_string().contains("example/prod"));
    drop(held);
    once_released(|| second.lock()).unwrap();
}

#[test]
fn deployments_get_distinct_directories() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    dir.deployment(&id("example/prod")).unwrap();
    assert!(tmp.path().join("example__prod").is_dir());
    let other = dir.deployment(&id("example/staging")).unwrap();
    other.set_deployed(&deployed()).unwrap();
    assert_eq!(
        dir.deployment(&id("example/prod"))
            .unwrap()
            .deployed()
            .unwrap(),
        None
    );
}

#[test]
fn deployed_round_trips() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.deployed().unwrap(), None);
    s.set_deployed(&deployed()).unwrap();
    assert_eq!(s.deployed().unwrap(), Some(deployed()));
    let mut newer = deployed();
    newer.version = semver::Version::new(1, 3, 0);
    s.set_deployed(&newer).unwrap();
    assert_eq!(s.deployed().unwrap(), Some(newer));
}

#[test]
fn in_progress_round_trips_and_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.in_progress().unwrap(), None);
    let marker = InProgress {
        deploy_id: "2026-11-01T10-00-00-000000000Z".to_owned(),
        phase: Phase::RollingBack,
        tag: "v1.2.3".parse().unwrap(),
        digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
        previous_can_start: true,
        backup: Some(RecordedBackup {
            id: "2026-11-01T10-00-00Z".to_owned(),
            paths: vec!["data".to_owned()],
        }),
        started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
    };
    s.set_in_progress(&marker).unwrap();
    assert_eq!(s.in_progress().unwrap(), Some(marker));
    s.clear_in_progress().unwrap();
    assert_eq!(s.in_progress().unwrap(), None);
    s.clear_in_progress().unwrap();
}

#[test]
fn previous_deployed_tells_nothing_saved_from_nothing_deployed() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.previous_deployed().unwrap(), None);
    s.set_previous_deployed(None).unwrap();
    assert_eq!(s.previous_deployed().unwrap(), Some(None));
    s.set_previous_deployed(Some(&deployed())).unwrap();
    assert_eq!(s.previous_deployed().unwrap(), Some(Some(deployed())));
}

#[test]
fn deployed_record_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    s.set_deployed(&deployed()).unwrap();
    s.clear_deployed().unwrap();
    assert_eq!(s.deployed().unwrap(), None);
    s.clear_deployed().unwrap();
}

#[test]
fn corrupt_state_is_an_error_not_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    for (name, content) in [
        (DEPLOYED, "not json"),
        (DEPLOYED, ""),
        (DEPLOYED, r#"{"tag":"v1.2.3","surprise":1}"#),
        (IN_PROGRESS, "{"),
    ] {
        fs::write(tmp.path().join("example__prod").join(name), content).unwrap();
        let err = if name == DEPLOYED {
            s.deployed().unwrap_err()
        } else {
            s.in_progress().unwrap_err()
        };
        assert!(
            matches!(&err, StateError::Corrupt { path, .. } if path.ends_with(name)),
            "{content}: {err}"
        );
        assert!(err.to_string().contains(name), "{err}");
    }
}

#[test]
fn deployment_directory_that_is_a_symlink_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let elsewhere = tempfile::tempdir().unwrap();
    std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("example__prod")).unwrap();
    let err = StateDir::open(tmp.path())
        .unwrap()
        .deployment(&id("example/prod"))
        .unwrap_err();
    assert!(matches!(err, StateError::NotADirectory(_)), "{err}");
}

#[test]
fn deployment_directory_with_a_loose_mode_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("example__prod");
    fs::create_dir(&dir).unwrap();
    for loose in [0o770, 0o702] {
        fs::set_permissions(&dir, Permissions::from_mode(loose)).unwrap();
        let err = StateDir::open(tmp.path())
            .unwrap()
            .deployment(&id("example/prod"))
            .unwrap_err();
        assert!(matches!(err, StateError::Writable { .. }), "{err}");
    }
}

#[test]
fn a_failed_write_keeps_the_old_content() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    s.set_deployed(&deployed()).unwrap();
    // A directory where the temporary file goes fails the write whoever
    // runs this; permissions would not stop root.
    fs::create_dir(tmp.path().join("example__prod").join(".deployed.json.tmp")).unwrap();

    let mut newer = deployed();
    newer.version = semver::Version::new(9, 9, 9);
    let err = s.set_deployed(&newer).unwrap_err();

    assert!(matches!(err, StateError::Io { .. }), "{err}");
    assert_eq!(s.deployed().unwrap(), Some(deployed()));
}

#[test]
fn previous_override_round_trips_bytes() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.previous_override().unwrap(), None);
    s.set_previous_override(b"services: {}\n").unwrap();
    assert_eq!(
        s.previous_override().unwrap().as_deref(),
        Some(&b"services: {}\n"[..])
    );
}

#[test]
fn reports_are_written_under_a_validated_id() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    s.write_report(
        "2026-11-01T10-00-00Z",
        &serde_json::json!({"outcome": "ok"}),
    )
    .unwrap();
    let written = fs::read_to_string(
        tmp.path()
            .join("example__prod/reports/2026-11-01T10-00-00Z.json"),
    )
    .unwrap();
    assert!(written.contains("\"outcome\""));
    for bad in ["", "../x", "a/b", ".hidden", "a b"] {
        let err = s.write_report(bad, &serde_json::json!({})).unwrap_err();
        assert!(matches!(err, StateError::InvalidReportId(_)), "{bad}");
    }
}
