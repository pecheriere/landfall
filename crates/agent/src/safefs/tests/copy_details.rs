//! What a copy keeps: times, owners, names and limits.

use std::fs;
#[cfg(target_os = "linux")]
use std::fs::Permissions;
use std::os::unix::fs::symlink;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};

use rustix::fs::{AtFlags, CWD, Timespec, Timestamps, utimensat};

use super::super::{MAX_DEPTH, SafeFsError, restore, seam, snapshot};
use super::{assert_sentinel_untouched, mkfifo, mtime, rel, root, sentinel};
#[cfg(target_os = "linux")]
use super::{mode, write};

#[test]
fn symlink_times_survive_the_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    symlink("elsewhere", data.join("link")).unwrap();
    let time = Timespec {
        tv_sec: 1_600_000_000,
        tv_nsec: 0,
    };
    let times = Timestamps {
        last_access: time,
        last_modification: time,
    };
    let flags = AtFlags::SYMLINK_NOFOLLOW;
    utimensat(CWD, data.join("link"), &times, flags).unwrap();

    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
    assert_eq!(mtime(&dest.join("data/link")), 1_600_000_000);

    fs::remove_file(data.join("link")).unwrap();
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();
    assert_eq!(mtime(&data.join("link")), 1_600_000_000);
}

/// A snapshot of one symlink, where `swap` replaces the new copy of it
/// before its metadata is set.
fn snapshot_with_new_symlink_swapped(
    tmp: &Path,
    swap: impl Fn(&Path) + 'static,
) -> Result<(), SafeFsError> {
    let compose = tmp.join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    symlink("elsewhere", data.join("link")).unwrap();

    let created = tmp.join("snap.partial/data/link");
    seam::set(move |point, name| {
        if point == seam::Point::SymlinkCreated && name == c"link" {
            fs::remove_file(&created).unwrap();
            swap(&created);
        }
    });
    let dest = tmp.join("snap");
    let result = snapshot(&root(&compose), &[rel("data")], &dest).map(|_| ());
    assert_eq!(result.is_err(), !dest.exists());
    result
}

/// An entry swapped in for a new symlink, here a hard link to an outside
/// file, must not receive the symlink's owner and times.
#[test]
fn symlink_replaced_before_its_metadata_is_set_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let keep = outside.join("keep");

    let err = snapshot_with_new_symlink_swapped(tmp.path(), move |created| {
        fs::hard_link(&keep, created).unwrap();
    })
    .unwrap_err();

    assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
    assert_sentinel_untouched(&outside);
}

#[test]
fn symlink_replaced_by_another_symlink_is_refused() {
    let tmp = tempfile::tempdir().unwrap();

    let err = snapshot_with_new_symlink_swapped(tmp.path(), |created| {
        symlink("planted", created).unwrap();
    })
    .unwrap_err();

    assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
}

/// A hard link to another symlink with the same target looks like the new
/// one in every way but its link count. Only Linux: there, `link` makes a
/// hard link to the symlink itself.
#[cfg(target_os = "linux")]
#[test]
fn symlink_replaced_by_a_hard_link_to_a_symlink_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let other = tmp.path().join("other");
    symlink("elsewhere", &other).unwrap();

    let err = snapshot_with_new_symlink_swapped(tmp.path(), move |created| {
        fs::hard_link(&other, created).unwrap();
    })
    .unwrap_err();

    assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
}

#[cfg(target_os = "linux")]
const FOREIGN_UID: u32 = 1234;

#[cfg(target_os = "linux")]
const FOREIGN_GID: u32 = 2345;

/// Whether this test can run: it needs root. Where root is required, as
/// it is in CI, not having it is a failure.
#[cfg(target_os = "linux")]
#[expect(
    clippy::print_stderr,
    reason = "a test skipped for lack of privileges has to say so; libtest has no runtime skip"
)]
fn can_chown(test: &str) -> bool {
    let root = rustix::process::geteuid().is_root();
    if !root {
        assert!(
            std::env::var_os("LANDFALL_TEST_REQUIRE_ROOT").is_none(),
            "{test} must run as root here"
        );
        eprintln!("{test}: skipped, it needs root to give a file another owner");
    }
    root
}

#[cfg(target_os = "linux")]
fn owner(path: &Path) -> (u32, u32) {
    let seen = fs::symlink_metadata(path).unwrap();
    (seen.uid(), seen.gid())
}

#[cfg(target_os = "linux")]
#[test]
fn foreign_owner_survives_the_round_trip() {
    use std::os::unix::fs::{chown, lchown};

    if !can_chown("foreign_owner_survives_the_round_trip") {
        return;
    }
    let foreign = (FOREIGN_UID, FOREIGN_GID);
    let ids = (Some(FOREIGN_UID), Some(FOREIGN_GID));
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    let (file, tool, link) = (data.join("file"), data.join("tool"), data.join("link"));
    write(&file, b"x", 0o640);
    write(&tool, b"x", 0o644);
    symlink("elsewhere", &link).unwrap();
    chown(&file, ids.0, ids.1).unwrap();
    chown(&tool, ids.0, ids.1).unwrap();
    lchown(&link, ids.0, ids.1).unwrap();
    chown(&data, ids.0, ids.1).unwrap();
    // After the `chown`, which would clear it.
    fs::set_permissions(&tool, Permissions::from_mode(0o4755)).unwrap();

    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
    for name in ["data", "data/file", "data/tool", "data/link"] {
        assert_eq!(owner(&dest.join(name)), foreign, "{name}");
    }
    assert_eq!(mode(&dest.join("data/tool")), 0o4755);

    fs::remove_dir_all(&data).unwrap();
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();
    for path in [&data, &file, &tool, &link] {
        assert_eq!(owner(path), foreign, "{path:?}");
    }
    assert_eq!(mode(&tool), 0o4755);
    assert_eq!(fs::read_link(&link).unwrap(), Path::new("elsewhere"));
}

/// With a foreign owner to hand on, a swapped-in entry receiving it would
/// show: this is what makes the owner check of the sentinel able to fail.
#[cfg(target_os = "linux")]
#[test]
fn foreign_owner_does_not_reach_an_entry_swapped_in() {
    use std::os::unix::fs::lchown;

    if !can_chown("foreign_owner_does_not_reach_an_entry_swapped_in") {
        return;
    }
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    let link = data.join("link");
    symlink("elsewhere", &link).unwrap();
    lchown(&link, Some(FOREIGN_UID), Some(FOREIGN_GID)).unwrap();

    let created = tmp.path().join("snap.partial/data/link");
    let keep = outside.join("keep");
    seam::set(move |point, name| {
        if point == seam::Point::SymlinkCreated && name == c"link" {
            fs::remove_file(&created).unwrap();
            fs::hard_link(&keep, &created).unwrap();
        }
    });
    let result = snapshot(&root(&compose), &[rel("data")], &tmp.path().join("snap"));

    assert_sentinel_untouched(&outside);
    let err = result.unwrap_err();
    assert!(matches!(err, SafeFsError::Replaced { .. }), "{err}");
}

/// Only Linux: other filesystems, like APFS, refuse such a name.
#[cfg(target_os = "linux")]
#[test]
fn non_utf8_names_round_trip() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    let name = OsStr::from_bytes(b"caf\xe9");
    write(&data.join(name), b"content", 0o644);

    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();
    assert_eq!(fs::read(dest.join("data").join(name)).unwrap(), b"content");

    fs::remove_file(data.join(name)).unwrap();
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();
    assert_eq!(fs::read(data.join(name)).unwrap(), b"content");
}

#[test]
fn tree_deeper_than_the_limit_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let mut deep = compose.clone();
    for _ in 0..=MAX_DEPTH {
        deep.push("d");
    }
    fs::create_dir_all(&deep).unwrap();

    let dest = tmp.path().join("snap");
    let err = snapshot(&root(&compose), &[rel("d")], &dest).unwrap_err();
    assert!(matches!(err, SafeFsError::TooDeep { .. }), "{err}");
    assert!(!dest.exists());
    assert!(!tmp.path().join("snap.partial").exists());
}

#[test]
fn error_text_quotes_and_truncates_hostile_names() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    mkfifo(&data.join("evil\nline"));

    let dest = tmp.path().join("snap");
    let err = snapshot(&root(&compose), &[rel("data")], &dest).unwrap_err();
    let text = err.to_string();
    assert!(!text.contains('\n'), "{text}");
    assert!(text.contains(r"evil\nline"), "{text}");

    let long = SafeFsError::Missing {
        path: PathBuf::from("x/".repeat(5_000)),
    };
    assert!(long.to_string().len() < 1_000);
}
