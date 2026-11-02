//! Roots, relative paths, atomic writes and reads.

use std::fs;
use std::os::unix::fs::symlink;
use std::path::Path;

use super::super::files::temp_name;
use super::super::{MAX_DEPTH, RelPath, Root, SafeFsError, read_file, seam, write_atomic};
use super::{assert_sentinel_untouched, mkdir, mkfifo, mode, rel, root, sentinel, write};

#[test]
fn root_escape_paths_are_rejected() {
    for bad in [
        "", "..", ".", "/etc", "a//b", "a/", "../a", "a/..", "a/../b", "./a", "a/./b", "a\0b",
    ] {
        assert!(
            matches!(RelPath::new(bad), Err(SafeFsError::InvalidPath { .. })),
            "{bad:?}"
        );
    }
    let too_deep = vec!["d"; MAX_DEPTH + 1].join("/");
    assert!(RelPath::new(&too_deep).is_err());
    assert!(RelPath::new("a/b.c/..d").is_ok());
}

#[test]
fn root_must_be_an_absolute_real_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = tmp.path().join("dir");
    mkdir(&dir, 0o755);
    symlink(&dir, tmp.path().join("link")).unwrap();

    assert!(matches!(
        Root::open(Path::new("relative")),
        Err(SafeFsError::NotAbsolute { .. })
    ));
    assert!(matches!(
        Root::open(&tmp.path().join("link")),
        Err(SafeFsError::NotADirectory { .. })
    ));
    assert!(matches!(
        Root::open(&tmp.path().join("absent")),
        Err(SafeFsError::Missing { .. })
    ));
}

#[test]
fn write_atomic_replaces_but_refuses_symlink_temp() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    let compose_root = root(&compose);
    let target = compose.join("override.yaml");
    let name = rel("override.yaml");

    write_atomic(&compose_root, &name, b"one", 0o640).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"one");
    assert_eq!(mode(&target), 0o640);
    write_atomic(&compose_root, &name, b"two", 0o600).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"two");
    assert_eq!(mode(&target), 0o600);
    assert_eq!(fs::read_dir(&compose).unwrap().count(), 1);

    let leftover = compose.join(temp_name(c"override.yaml").unwrap().to_str().unwrap());
    symlink(outside.join("keep"), &leftover).unwrap();
    let err = write_atomic(&compose_root, &name, b"three", 0o644).unwrap_err();
    assert!(matches!(err, SafeFsError::AlreadyExists { .. }), "{err}");
    assert_sentinel_untouched(&outside);
    assert_eq!(fs::read(&target).unwrap(), b"two");
    fs::remove_file(&leftover).unwrap();

    // What a crash leaves behind does not block the next write.
    write(&leftover, b"partial", 0o600);
    write_atomic(&compose_root, &name, b"four", 0o644).unwrap();
    assert_eq!(fs::read(&target).unwrap(), b"four");
    assert!(!leftover.exists());
}

#[test]
fn write_atomic_replaces_a_symlink_without_following_it() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    symlink(outside.join("keep"), compose.join("override.yaml")).unwrap();

    write_atomic(&root(&compose), &rel("override.yaml"), b"new", 0o644).unwrap();

    assert_sentinel_untouched(&outside);
    assert!(
        fs::symlink_metadata(compose.join("override.yaml"))
            .unwrap()
            .is_file()
    );
}

#[test]
fn write_atomic_refuses_a_symlinked_parent_and_set_id_modes() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    symlink(&outside, compose.join("data")).unwrap();
    let compose_root = root(&compose);

    let err = write_atomic(&compose_root, &rel("data/new"), b"x", 0o644).unwrap_err();
    assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
    assert_sentinel_untouched(&outside);

    let err = write_atomic(&compose_root, &rel("file"), b"x", 0o4755).unwrap_err();
    assert!(matches!(err, SafeFsError::InvalidMode { .. }), "{err}");
    assert!(!compose.join("file").exists());
}

#[test]
fn read_file_refuses_symlink() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    symlink(outside.join("keep"), compose.join("link")).unwrap();
    symlink(&outside, compose.join("dirlink")).unwrap();
    let compose_root = root(&compose);

    let err = read_file(&compose_root, &rel("link"), 1024).unwrap_err();
    assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
    let err = read_file(&compose_root, &rel("dirlink/keep"), 1024).unwrap_err();
    assert!(matches!(err, SafeFsError::NotADirectory { .. }), "{err}");
}

#[test]
fn read_file_returns_content_none_when_absent_and_enforces_the_cap() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    write(&compose.join("file"), b"12345", 0o644);
    let compose_root = root(&compose);

    let content = read_file(&compose_root, &rel("file"), 5).unwrap();
    assert_eq!(content.as_deref(), Some(&b"12345"[..]));
    assert_eq!(read_file(&compose_root, &rel("absent"), 5).unwrap(), None);
    assert_eq!(read_file(&compose_root, &rel("no/such"), 5).unwrap(), None);
    let err = read_file(&compose_root, &rel("file"), 4).unwrap_err();
    assert!(matches!(err, SafeFsError::TooLarge { .. }), "{err}");
}

/// Reads a file that `swap` replaces between `lstat` and open.
fn read_with_swap_in_open_window(
    tmp: &Path,
    swap: impl Fn(&Path) + 'static,
) -> Result<Option<Vec<u8>>, SafeFsError> {
    let compose = tmp.join("compose");
    mkdir(&compose, 0o755);
    let file = compose.join("file");
    write(&file, b"ordinary", 0o644);
    seam::set(move |point, name| {
        if point == seam::Point::LstatToOpen && name == c"file" {
            fs::remove_file(&file).unwrap();
            swap(&file);
        }
    });
    read_file(&root(&compose), &rel("file"), 1024)
}

#[test]
fn read_file_refuses_a_fifo_swapped_in_the_open_window() {
    let tmp = tempfile::tempdir().unwrap();
    let err = read_with_swap_in_open_window(tmp.path(), mkfifo).unwrap_err();
    assert!(matches!(err, SafeFsError::NotRegularFile { .. }), "{err}");
}

#[test]
fn read_file_refuses_a_symlink_swapped_in_the_open_window() {
    let tmp = tempfile::tempdir().unwrap();
    let outside = sentinel(tmp.path());
    let keep = outside.join("keep");
    let err = read_with_swap_in_open_window(tmp.path(), move |file| {
        symlink(&keep, file).unwrap();
    })
    .unwrap_err();
    assert!(matches!(err, SafeFsError::SymlinkRefused { .. }), "{err}");
}

#[test]
fn read_file_of_an_entry_vanishing_in_the_open_window_is_none() {
    let tmp = tempfile::tempdir().unwrap();
    let content = read_with_swap_in_open_window(tmp.path(), |_| {}).unwrap();
    assert_eq!(content, None);
}

#[test]
fn read_file_refuses_fifo_and_directory_without_blocking() {
    let tmp = tempfile::tempdir().unwrap();
    let compose = tmp.path().join("compose");
    mkdir(&compose, 0o755);
    mkfifo(&compose.join("pipe"));
    mkdir(&compose.join("dir"), 0o755);
    let compose_root = root(&compose);

    for name in ["pipe", "dir"] {
        let err = read_file(&compose_root, &rel(name), 1024).unwrap_err();
        assert!(matches!(err, SafeFsError::NotRegularFile { .. }), "{err}");
    }
}
