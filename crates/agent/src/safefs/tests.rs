//! The file operations against hostile trees and races.

use std::fs::{self, File, Permissions};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, SystemTime};

use super::{RelPath, Root};

mod copy_details;
mod files;
mod prune;
mod removal;
mod snapshot;

const SECRET: &[u8] = b"sentinel content, must not be copied";

const SENTINEL_MTIME: i64 = 1_500_000_000;

fn rel(path: &str) -> RelPath {
    RelPath::new(path).unwrap()
}

fn root(path: &Path) -> Root {
    Root::open(path).unwrap()
}

fn write(path: &Path, content: &[u8], mode: u32) {
    fs::write(path, content).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn mkdir(path: &Path, mode: u32) {
    fs::create_dir(path).unwrap();
    fs::set_permissions(path, Permissions::from_mode(mode)).unwrap();
}

fn set_mtime(path: &Path, secs: u64) {
    let time = SystemTime::UNIX_EPOCH + Duration::from_secs(secs);
    File::open(path).unwrap().set_modified(time).unwrap();
}

fn mkfifo(path: &Path) {
    let status = Command::new("mkfifo").arg(path).status().unwrap();
    assert!(status.success());
}

fn mode(path: &Path) -> u32 {
    fs::symlink_metadata(path).unwrap().mode() & 0o7777
}

fn mtime(path: &Path) -> i64 {
    fs::symlink_metadata(path).unwrap().mtime()
}

/// A directory holding one file: what a hostile link would point at.
fn sentinel(base: &Path) -> PathBuf {
    let dir = base.join("sentinel");
    mkdir(&dir, 0o755);
    write(&dir.join("keep"), SECRET, 0o644);
    let secs = u64::try_from(SENTINEL_MTIME).unwrap();
    set_mtime(&dir.join("keep"), secs);
    set_mtime(&dir, secs);
    dir
}

/// Owner is compared with the sentinel's parent, which nothing under test
/// is pointed at, because a new entry's group depends on the platform.
fn assert_sentinel_untouched(dir: &Path) {
    let parent = fs::symlink_metadata(dir.parent().unwrap()).unwrap();
    for entry in [dir.to_owned(), dir.join("keep")] {
        let seen = fs::symlink_metadata(&entry).unwrap();
        assert_eq!(seen.uid(), parent.uid(), "{entry:?}");
        assert_eq!(seen.gid(), parent.gid(), "{entry:?}");
        assert_eq!(seen.mtime(), SENTINEL_MTIME, "{entry:?}");
    }
    assert_eq!(mode(dir), 0o755);
    assert_eq!(fs::read(dir.join("keep")).unwrap(), SECRET);
    assert_eq!(mode(&dir.join("keep")), 0o644);
    assert_eq!(fs::read_dir(dir).unwrap().count(), 1);
}

fn assert_no_secret_in(dir: &Path) {
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let kind = entry.file_type().unwrap();
        if kind.is_dir() {
            assert_no_secret_in(&entry.path());
        } else if kind.is_file() {
            assert_ne!(fs::read(entry.path()).unwrap(), SECRET, "{entry:?}");
        }
    }
}
