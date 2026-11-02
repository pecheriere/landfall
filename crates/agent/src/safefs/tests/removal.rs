//! Removing deep, wide and changing trees.

use std::fs::{self, File};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};

use rustix::fs::{CWD, Mode, OFlags, mkdirat, openat};

use super::super::removal::{empty_dir, move_to_top, remove_entry};
use super::super::snapshot::snapshot_limited;
use super::super::{MAX_DEPTH, REMOVAL_BATCH, Root, SafeFsError, restore, seam, snapshot};
use super::{mkdir, rel, root, write};

/// Makes `levels` nested directories, one at a time by descriptor, since
/// a path to the bottom of a long chain is too long to be used whole.
fn plant_chain(base: &Path, levels: usize) {
    let flags = OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC;
    let mut current = openat(CWD, base, flags, Mode::empty()).unwrap();
    for _ in 0..levels {
        mkdirat(&current, c"d", Mode::RWXU).unwrap();
        current = openat(&current, c"d", flags, Mode::empty()).unwrap();
    }
}

/// A snapshot of `data` with one file, then `plant` changing `data`.
fn restore_after(plant: impl FnOnce(&Path)) {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    write(&data.join("kept"), b"original", 0o644);
    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

    plant(&data);
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();

    assert_eq!(fs::read(data.join("kept")).unwrap(), b"original");
    assert_eq!(fs::read_dir(&data).unwrap().count(), 1);
}

#[test]
fn restore_succeeds_over_a_tree_deeper_than_the_limit() {
    restore_after(|data| plant_chain(data, MAX_DEPTH + 5));
}

#[test]
fn restore_succeeds_over_a_chain_needing_several_passes() {
    restore_after(|data| plant_chain(data, MAX_DEPTH * 3 + 7));
}

#[test]
fn restore_clears_deep_directories_side_by_side() {
    restore_after(|data| {
        for name in ["one", "two"] {
            let branch = data.join(name);
            mkdir(&branch, 0o755);
            plant_chain(&branch, MAX_DEPTH + 5);
        }
    });
}

/// The names a deep directory would move to are taken, by a file and by a
/// directory with something in it: it takes the next, and they stay for
/// the removal to reach in its own time.
#[test]
fn a_deep_directory_moves_past_planted_names() {
    let tmp = tempfile::tempdir().unwrap();
    let top = tmp.path().join("top");
    mkdir(&top, 0o755);
    write(&top.join(".landfall-deep-0"), b"planted", 0o644);
    fs::create_dir_all(top.join(".landfall-deep-1/full")).unwrap();
    fs::create_dir_all(top.join("below/deep/inside")).unwrap();
    let (top_root, below_root) = (root(&top), root(&top.join("below")));

    let mut moved = 0;
    move_to_top(
        top_root.fd.as_fd(),
        below_root.fd.as_fd(),
        c"deep",
        &top.join("below/deep"),
        &mut moved,
    )
    .unwrap();

    assert_eq!(moved, 3);
    assert!(top.join(".landfall-deep-2/inside").is_dir());
    assert!(!top.join("below/deep").exists());
    assert_eq!(fs::read(top.join(".landfall-deep-0")).unwrap(), b"planted");
    assert!(top.join(".landfall-deep-1/full").is_dir());
}

/// A directory at the depth limit, in a directory `top` of its own, with
/// that directory opened and `top` already removed if `remove_top`.
fn deep_child(tmp: &Path, remove_top: bool) -> (Root, Root, PathBuf) {
    let top = tmp.join("top");
    mkdir(&top, 0o755);
    let dir = tmp.join("dir");
    fs::create_dir_all(dir.join("deep/inside")).unwrap();
    let (top_root, dir_root) = (root(&top), root(&dir));
    if remove_top {
        fs::remove_dir(&top).unwrap();
    }
    (top_root, dir_root, dir)
}

#[test]
fn removal_errors_when_the_top_directory_is_gone() {
    let tmp = tempfile::tempdir().unwrap();
    let (top, dir, dir_path) = deep_child(tmp.path(), true);
    let (top, dir) = (top.fd.as_fd(), dir.fd.as_fd());
    let deep = dir_path.join("deep");

    let err = move_to_top(top, dir, c"deep", &deep, &mut 0).unwrap_err();
    assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");

    let err = empty_dir(top, dir, &dir_path, MAX_DEPTH, &mut 0).unwrap_err();
    assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");
    assert!(err.to_string().contains("deep"), "{err}");
    assert!(deep.join("inside").is_dir());
}

#[test]
fn deep_directory_vanishing_before_its_move_is_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let (top, dir, dir_path) = deep_child(tmp.path(), false);
    let deep = dir_path.join("deep");
    let gone = deep.clone();
    seam::set(move |point, name| {
        if point == seam::Point::MoveUp && name == c"deep" {
            fs::remove_dir_all(&gone).unwrap();
        }
    });

    let (top_fd, dir_fd) = (top.fd.as_fd(), dir.fd.as_fd());
    let moved = move_to_top(top_fd, dir_fd, c"deep", &deep, &mut 0).unwrap();
    assert!(!moved);

    fs::create_dir_all(&deep).unwrap();
    empty_dir(top_fd, dir_fd, &dir_path, MAX_DEPTH, &mut 0).unwrap();
    assert_eq!(fs::read_dir(&dir_path).unwrap().count(), 0);
    assert_eq!(fs::read_dir(top.path()).unwrap().count(), 0);
}

#[test]
fn entry_vanishing_during_removal_is_not_an_error() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dir");
    mkdir(&dir, 0o755);
    write(&dir.join("file"), b"x", 0o644);
    let file = dir.join("file");
    seam::set(move |point, _| {
        if point == seam::Point::RemovalOpen {
            fs::remove_file(&file).unwrap();
        }
    });

    remove_entry(root(tmp.path()).fd.as_fd(), c"dir", &dir).unwrap();
    assert!(!dir.exists());
}

/// Every name listed is gone when it is opened, yet the directory never
/// empties. This would spin forever if a pass removing nothing were
/// accepted, so the hook gives up by panicking.
#[test]
fn removal_errors_when_a_pass_removes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dir");
    mkdir(&dir, 0o755);
    write(&dir.join("0"), b"x", 0o644);
    let listed = dir.clone();
    let mut renames = 0;
    seam::set(move |point, name| {
        if point == seam::Point::RemovalOpen {
            renames += 1;
            assert!(renames < 100, "the removal does not stop");
            let from = listed.join(name.to_str().unwrap());
            fs::rename(from, listed.join(renames.to_string())).unwrap();
        }
    });

    let err = remove_entry(root(tmp.path()).fd.as_fd(), c"dir", &dir).unwrap_err();

    assert!(matches!(err, SafeFsError::RemovalStalled { .. }), "{err}");
    assert!(err.to_string().contains("dir"), "{err}");
}

#[test]
fn restore_clears_a_directory_larger_than_a_batch() {
    restore_after(|data| {
        let added = data.join("added");
        mkdir(&added, 0o755);
        for index in 0..=REMOVAL_BATCH {
            File::create(added.join(index.to_string())).unwrap();
        }
    });
}

#[test]
fn directory_over_the_entry_limit_is_refused_naming_it() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    for index in 0..4 {
        File::create(data.join(index.to_string())).unwrap();
    }
    let compose_root = root(&compose);
    let dest = tmp.path().join("snap");

    let err = snapshot_limited(&compose_root, &[rel("data")], &dest, 3).unwrap_err();
    assert!(matches!(err, SafeFsError::TooManyEntries { .. }), "{err}");
    assert!(err.to_string().contains("data"), "{err}");
    assert!(!dest.exists());
    assert!(!tmp.path().join("snap.partial").exists());

    snapshot_limited(&compose_root, &[rel("data")], &dest, 4).unwrap();
    assert_eq!(fs::read_dir(dest.join("data")).unwrap().count(), 4);
}
