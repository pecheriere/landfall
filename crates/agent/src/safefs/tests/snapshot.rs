//! Snapshot and restore, and races while they run.

use std::fs::{self, Permissions};
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use super::super::{SafeFsError, restore, seam, snapshot};
use super::{
    assert_no_secret_in, assert_sentinel_untouched, mkdir, mkfifo, mode, mtime, rel, root,
    sentinel, set_mtime, write,
};

#[test]
fn snapshot_and_restore_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    let data = compose.join("data");
    mkdir(&data, 0o750);
    let sub = data.join("sub");
    mkdir(&sub, 0o750);
    mkdir(&data.join("empty"), 0o750);
    write(&sub.join("a.txt"), b"first", 0o640);
    write(&data.join("b.bin"), &vec![0_u8; 200_000], 0o750);
    mkdir(&compose.join("conf"), 0o710);
    write(&compose.join("conf/app.ini"), b"second", 0o640);
    set_mtime(&sub.join("a.txt"), 1_600_000_000);
    set_mtime(&sub, 1_600_000_100);
    set_mtime(&data, 1_600_000_200);
    set_mtime(&compose.join("conf"), 1_600_000_300);

    let dest = tmp.path().join("2026-11-01T10-00-00Z");
    let paths = [rel("data"), rel("conf/app.ini")];
    let stats = snapshot(&root(&compose), &paths, &dest).unwrap();
    assert_eq!(stats.files, 3);
    assert_eq!(stats.directories, 4);
    assert_eq!(stats.bytes, 200_011);
    assert!(!tmp.path().join("2026-11-01T10-00-00Z.partial").exists());
    assert_eq!(fs::read(dest.join("data/sub/a.txt")).unwrap(), b"first");
    assert_eq!(mode(&dest.join("data")), 0o750);
    assert_eq!(mtime(&dest.join("data")), 1_600_000_200);
    assert_eq!(mode(&dest.join("conf")), 0o710);
    assert_eq!(mtime(&dest.join("conf")), 1_600_000_300);

    fs::remove_dir_all(&data).unwrap();
    fs::remove_dir_all(compose.join("conf")).unwrap();
    restore(&dest, &root(&compose), &paths).unwrap();

    assert_eq!(fs::read(sub.join("a.txt")).unwrap(), b"first");
    assert_eq!(mode(&sub.join("a.txt")), 0o640);
    assert_eq!(mtime(&sub.join("a.txt")), 1_600_000_000);
    assert_eq!(mode(&sub), 0o750);
    assert_eq!(mtime(&sub), 1_600_000_100);
    assert_eq!(mode(&data), 0o750);
    assert_eq!(mtime(&data), 1_600_000_200);
    assert_eq!(fs::read(data.join("b.bin")).unwrap().len(), 200_000);
    assert_eq!(mode(&data.join("b.bin")), 0o750);
    assert!(data.join("empty").is_dir());
    assert_eq!(fs::read_dir(data.join("empty")).unwrap().count(), 0);
    assert_eq!(fs::read(compose.join("conf/app.ini")).unwrap(), b"second");
    assert_eq!(mode(&compose.join("conf")), 0o710);
    assert_eq!(mtime(&compose.join("conf")), 1_600_000_300);
}

#[test]
fn set_id_bits_survive_the_round_trip() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    write(&compose.join("tool"), b"x", 0o4755);
    mkdir(&compose.join("shared"), 0o2750);

    let dest = tmp.path().join("snap");
    let paths = [rel("tool"), rel("shared")];
    snapshot(&root(&compose), &paths, &dest).unwrap();
    assert_eq!(mode(&dest.join("tool")), 0o4755);
    assert_eq!(mode(&dest.join("shared")), 0o2750);

    fs::remove_file(compose.join("tool")).unwrap();
    restore(&dest, &root(&compose), &paths).unwrap();
    assert_eq!(mode(&compose.join("tool")), 0o4755);
    assert_eq!(mode(&compose.join("shared")), 0o2750);
}

#[test]
fn snapshot_copies_symlinks_as_symlinks() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    symlink(outside.join("keep"), data.join("link")).unwrap();
    symlink(&outside, data.join("dirlink")).unwrap();

    let dest = tmp.path().join("snap");
    let stats = snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

    assert_eq!(stats.symlinks, 2);
    assert_eq!(stats.files, 0);
    assert_eq!(
        fs::read_link(dest.join("data/link")).unwrap(),
        outside.join("keep")
    );
    assert_eq!(fs::read_link(dest.join("data/dirlink")).unwrap(), outside);
    assert_no_secret_in(&dest);

    fs::remove_dir_all(&data).unwrap();
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();
    assert_eq!(
        fs::read_link(data.join("link")).unwrap(),
        outside.join("keep")
    );
    assert_sentinel_untouched(&outside);
}

#[test]
fn special_file_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    write(&data.join("before"), b"copied first", 0o644);
    mkfifo(&data.join("pipe"));

    let dest = tmp.path().join("snap");
    let err = snapshot(&root(&compose), &[rel("data")], &dest).unwrap_err();

    assert!(matches!(err, SafeFsError::SpecialFile { .. }), "{err}");
    assert!(err.to_string().contains("data/pipe"), "{err}");
    assert!(!dest.exists());
    assert!(!tmp.path().join("snap.partial").exists());
}

#[test]
fn stale_partial_is_replaced_and_existing_dest_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    write(&compose.join("file"), b"new", 0o644);
    let dest = tmp.path().join("snap");
    fs::create_dir(tmp.path().join("snap.partial")).unwrap();
    write(&tmp.path().join("snap.partial/stale"), b"old", 0o644);

    snapshot(&root(&compose), &[rel("file")], &dest).unwrap();
    assert!(!dest.join("stale").exists());

    let err = snapshot(&root(&compose), &[rel("file")], &dest).unwrap_err();
    assert!(matches!(err, SafeFsError::AlreadyExists { .. }), "{err}");
    assert_eq!(fs::read(dest.join("file")).unwrap(), b"new");
}

#[test]
fn missing_path_is_missing() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    let dest = tmp.path().join("snap");

    for path in ["absent", "absent/below"] {
        let err = snapshot(&root(&compose), &[rel(path)], &dest).unwrap_err();
        assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
        assert!(err.to_string().contains("absent"), "{err}");
        assert!(!dest.exists());
        assert!(!tmp.path().join("snap.partial").exists());
    }
}

#[test]
fn parent_symlink_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    symlink(&outside, compose.join("data")).unwrap();

    let dest = tmp.path().join("snap");
    let err = snapshot(&root(&compose), &[rel("data/keep")], &dest).unwrap_err();

    assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
    assert!(!dest.exists());
}

#[test]
fn overlapping_paths_are_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    fs::create_dir_all(compose.join("data/x")).unwrap();
    let dest = tmp.path().join("snap");

    for paths in [[rel("data"), rel("data/x")], [rel("data/x"), rel("data")]] {
        let err = snapshot(&root(&compose), &paths, &dest).unwrap_err();
        assert!(matches!(err, SafeFsError::OverlappingPaths { .. }), "{err}");
    }
}

#[test]
fn restore_removes_what_the_container_added() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    write(&data.join("kept"), b"original", 0o644);
    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

    write(&data.join("kept"), b"tampered", 0o644);
    fs::create_dir_all(data.join("added/deep")).unwrap();
    write(&data.join("added/deep/file"), b"x", 0o444);
    mkfifo(&data.join("added/pipe"));
    symlink("/", data.join("added/link")).unwrap();

    restore(&dest, &root(&compose), &[rel("data")]).unwrap();

    assert_eq!(fs::read(data.join("kept")).unwrap(), b"original");
    assert!(!data.join("added").exists());
}

#[test]
fn symlink_swapped_during_restore_stays_inside() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(data.join("sub")).unwrap();
    write(&data.join("keep"), b"from the snapshot", 0o600);
    write(&data.join("sub/file"), b"nested", 0o600);
    fs::set_permissions(&data, Permissions::from_mode(0o700)).unwrap();

    // The whole path is swapped for a link, then a parent of the path.
    for paths in [vec![rel("data")], vec![rel("data/keep"), rel("data/sub")]] {
        let dest = tmp.path().join(format!("snap-{}", paths.len()));
        snapshot(&root(&compose), &paths, &dest).unwrap();

        fs::remove_dir_all(&data).unwrap();
        symlink(&outside, &data).unwrap();

        restore(&dest, &root(&compose), &paths).unwrap();

        assert_sentinel_untouched(&outside);
        assert!(fs::symlink_metadata(&data).unwrap().is_dir());
        assert_eq!(mode(&data), 0o700);
        assert_eq!(fs::read(data.join("keep")).unwrap(), b"from the snapshot");
        assert_eq!(fs::read(data.join("sub/file")).unwrap(), b"nested");
    }
}

#[test]
fn links_planted_below_the_path_are_removed_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(data.join("sub")).unwrap();
    write(&data.join("sub/file"), b"nested", 0o600);
    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).unwrap();

    fs::remove_dir_all(data.join("sub")).unwrap();
    symlink(&outside, data.join("sub")).unwrap();
    restore(&dest, &root(&compose), &[rel("data")]).unwrap();

    assert_sentinel_untouched(&outside);
    assert!(fs::symlink_metadata(data.join("sub")).unwrap().is_dir());
    assert_eq!(fs::read(data.join("sub/file")).unwrap(), b"nested");
}

#[test]
fn a_fifo_in_place_of_the_path_does_not_block_restore() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    write(&compose.join("file"), b"original", 0o644);
    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("file")], &dest).unwrap();

    fs::remove_file(compose.join("file")).unwrap();
    mkfifo(&compose.join("file"));
    restore(&dest, &root(&compose), &[rel("file")]).unwrap();

    // Checked first: reading a FIFO left in place would hang the test.
    assert!(
        fs::symlink_metadata(compose.join("file"))
            .unwrap()
            .is_file()
    );
    assert_eq!(fs::read(compose.join("file")).unwrap(), b"original");
}

#[test]
fn incomplete_snapshot_removes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    write(&compose.join("one"), b"live", 0o644);
    write(&compose.join("two"), b"live", 0o644);
    let dest = tmp.path().join("snap");
    snapshot(&root(&compose), &[rel("one")], &dest).unwrap();

    let err = restore(&dest, &root(&compose), &[rel("one"), rel("two")]).unwrap_err();

    assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
    assert!(err.to_string().contains("two"), "{err}");
    assert_eq!(fs::read(compose.join("two")).unwrap(), b"live");
}

/// A container keeps swapping a directory for a link to the sentinel
/// while snapshots and restores run. Either may fail; neither may touch
/// or copy the sentinel.
#[test]
fn racing_swaps_never_reach_the_sentinel() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    let data = compose.join("data");
    fs::create_dir_all(data.join("sub")).unwrap();
    write(&data.join("sub/file"), b"nested", 0o600);
    let clean = tmp.path().join("clean");
    snapshot(&root(&compose), &[rel("data")], &clean).unwrap();

    let stop = Arc::new(AtomicBool::new(false));
    let swapper = std::thread::spawn({
        let stop = Arc::clone(&stop);
        let data = data.clone();
        let outside = outside.clone();
        move || {
            let (sub, held) = (data.join("sub"), data.join("held"));
            while !stop.load(Ordering::Relaxed) {
                // Failures are expected: restore removes these under us.
                let _ = fs::rename(&sub, &held);
                let _ = symlink(&outside, &sub);
                std::thread::yield_now();
                let _ = fs::remove_file(&sub);
                let _ = fs::rename(&held, &sub);
            }
        }
    });

    let compose_root = root(&compose);
    for round in 0..100 {
        let dest = tmp.path().join(format!("race-{round}"));
        if snapshot(&compose_root, &[rel("data")], &dest).is_ok() {
            assert_no_secret_in(&dest);
        }
        // Restore fails when it collides with the swapper; that is fine.
        let _ = restore(&clean, &compose_root, &[rel("data")]);
    }
    stop.store(true, Ordering::Relaxed);
    swapper.join().unwrap();

    assert_sentinel_untouched(&outside);
}

/// A source tree with one file, and a snapshot's destination, where
/// `swap` replaces that file between `lstat` and open.
fn snapshot_with_swap_in_open_window(
    tmp: &Path,
    swap: impl Fn(&Path) + 'static,
) -> Result<PathBuf, SafeFsError> {
    let compose = tmp.join("compose");
    let data = compose.join("data");
    fs::create_dir_all(&data).unwrap();
    let file = data.join("file");
    write(&file, b"ordinary", 0o644);

    seam::set(move |point, name| {
        if point == seam::Point::LstatToOpen && name == c"file" {
            swap(&file);
        }
    });
    let dest = tmp.join("snap");
    snapshot(&root(&compose), &[rel("data")], &dest).map(|_| dest)
}

#[test]
fn swap_to_symlink_in_open_window_is_refused() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let keep = outside.join("keep");

    let result = snapshot_with_swap_in_open_window(tmp.path(), move |file| {
        fs::remove_file(file).unwrap();
        symlink(&keep, file).unwrap();
    });

    let err = result.unwrap_err();
    assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
    assert!(err.to_string().contains("data/file"), "{err}");
    assert!(!tmp.path().join("snap").exists());
    assert!(!tmp.path().join("snap.partial").exists());
    assert_sentinel_untouched(&outside);
}

#[test]
fn swap_to_fifo_in_open_window_is_refused() {
    let tmp = tempfile::tempdir().unwrap();

    let result = snapshot_with_swap_in_open_window(tmp.path(), |file| {
        fs::remove_file(file).unwrap();
        mkfifo(file);
    });

    let err = result.unwrap_err();
    assert!(matches!(err, SafeFsError::SpecialFile { .. }), "{err}");
    assert!(err.to_string().contains("data/file"), "{err}");
    assert!(!tmp.path().join("snap").exists());
    assert!(!tmp.path().join("snap.partial").exists());
}

#[test]
fn entry_vanishing_in_open_window_is_missing() {
    let tmp = tempfile::tempdir().unwrap();

    let result = snapshot_with_swap_in_open_window(tmp.path(), |file| {
        fs::remove_file(file).unwrap();
    });

    let err = result.unwrap_err();
    assert!(matches!(err, SafeFsError::Missing { .. }), "{err}");
    assert!(err.to_string().contains("data/file"), "{err}");
    assert!(!tmp.path().join("snap.partial").exists());
}
