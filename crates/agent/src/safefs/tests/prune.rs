//! Pruning old backups.

use std::fs;
use std::os::unix::fs::symlink;

use super::super::prune;
use super::{assert_sentinel_untouched, mkdir, sentinel};

#[test]
fn prune_keeps_newest() {
    let tmp = tempfile::tempdir().unwrap();
    let backups = tmp.path().join("backups");
    mkdir(&backups, 0o700);
    for name in [
        "2026-11-01T10-00-00Z",
        "2026-11-03T10-00-00Z",
        "2026-11-02T10-00-00Z",
        "2026-10-31T10-00-00Z",
        "2026-11-04T10-00-00Z.partial",
    ] {
        fs::create_dir_all(backups.join(name).join("data/sub")).unwrap();
    }
    let outside = sentinel(tmp.path());
    symlink(&outside, backups.join("2026-10-31T10-00-00Z/data/link")).unwrap();

    prune(&backups, 2, None).unwrap();

    let mut left: Vec<_> = fs::read_dir(&backups)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["2026-11-02T10-00-00Z", "2026-11-03T10-00-00Z"]);
    assert_sentinel_untouched(&outside);

    prune(&backups, 0, None).unwrap();
    assert_eq!(fs::read_dir(&backups).unwrap().count(), 0);
}

#[test]
fn prune_spares_the_backup_it_is_told_to() {
    let tmp = tempfile::tempdir().unwrap();
    let backups = tmp.path().join("backups");
    mkdir(&backups, 0o700);
    for name in [
        "2026-11-01T00-00-00Z",
        "2026-11-02T00-00-00Z",
        "2026-11-03T00-00-00Z",
    ] {
        fs::create_dir(backups.join(name)).unwrap();
    }

    prune(&backups, 1, Some("2026-11-01T00-00-00Z")).unwrap();

    let mut left: Vec<_> = fs::read_dir(&backups)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    left.sort();
    assert_eq!(left, ["2026-11-01T00-00-00Z", "2026-11-03T00-00-00Z"]);
}

#[test]
fn prune_of_an_absent_directory_does_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    prune(&tmp.path().join("absent"), 3, None).unwrap();
}
