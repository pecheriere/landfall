//! The log of used approval nonces: an approval works once, across restarts, and a log
//! that can't be trusted refuses rather than reads as empty.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::nonces::{append_line, locked};
use super::super::{MAX_NONCE_LOG_BYTES, NONCE_LOG, NonceSpend, StateDir, StateError};
use crate::testing::test_nonce;

/// The nonce most of these spend. It is also writer 7's own: see the test with the writers.
fn shared() -> [u8; 32] {
    test_nonce("writer 7")
}

fn dir(tmp: &tempfile::TempDir) -> StateDir {
    StateDir::open(tmp.path()).unwrap()
}

/// Spends `nonce`, going round for as long as another writer has the log.
fn until_free(root: &StateDir, nonce: &[u8; 32]) -> NonceSpend {
    loop {
        match root.spend_nonce(nonce) {
            Err(StateError::NonceLogBusy(_)) => std::thread::yield_now(),
            other => return other.unwrap(),
        }
    }
}

fn line(label: &str) -> String {
    format!("{}\n", hex::encode(test_nonce(label)))
}

fn assert_refused(root: &StateDir) {
    assert!(
        matches!(root.nonce_used(&shared()), Err(StateError::NonceLog { .. })),
        "{:?}",
        root.nonce_used(&shared())
    );
    assert!(
        matches!(
            root.spend_nonce(&shared()),
            Err(StateError::NonceLog { .. })
        ),
        "a log that can't be read is not added to"
    );
    assert!(matches!(
        root.check_nonce_log(),
        Err(StateError::NonceLog { .. })
    ));
}

#[test]
fn a_nonce_is_spent_once_and_the_log_survives_a_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert!(!root.nonce_used(&shared()).unwrap());
    assert!(
        !tmp.path().join(NONCE_LOG).exists(),
        "reading makes no file"
    );
    root.check_nonce_log().unwrap();

    assert_eq!(root.spend_nonce(&shared()).unwrap(), NonceSpend::Recorded);

    assert!(root.nonce_used(&shared()).unwrap());
    assert!(!root.nonce_used(&test_nonce("other")).unwrap());
    assert_eq!(
        root.spend_nonce(&shared()).unwrap(),
        NonceSpend::AlreadyUsed
    );
    let reopened = dir(&tmp);
    assert!(reopened.nonce_used(&shared()).unwrap());
    assert_eq!(
        reopened.spend_nonce(&shared()).unwrap(),
        NonceSpend::AlreadyUsed
    );
    assert_eq!(
        reopened.spend_nonce(&test_nonce("other")).unwrap(),
        NonceSpend::Recorded
    );

    let log = reopened.nonce_log_path();
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        format!("{}{}", line("writer 7"), line("other")),
        "one line per nonce"
    );
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_torn_or_corrupt_log_refuses_and_is_left_as_it_is() {
    let good = line("first");
    let long = format!("{}0\n", hex::encode(test_nonce("first")));
    for bad in [
        // A crash in the middle of the last line.
        format!("{good}{}", &line("second")[..20]),
        // A whole line's length without the end of a line.
        format!("{good}{}0", hex::encode(test_nonce("second"))),
        "\n".to_owned(),
        format!("{}\n", "x".repeat(64)),
        format!("{}\n", "AB".repeat(32)),
        format!("{}\r\n", hex::encode(test_nonce("first"))),
        long,
        // Whole lines' worth of bytes, with the damage early on.
        format!("{}\n{good}", "!".repeat(64)),
    ] {
        let tmp = tempfile::tempdir().unwrap();
        let root = dir(&tmp);
        fs::write(root.nonce_log_path(), &bad).unwrap();
        assert_refused(&root);
        assert_eq!(fs::read_to_string(root.nonce_log_path()).unwrap(), bad);
    }
}

#[test]
fn a_log_past_its_bound_refuses_without_being_read() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    let file = fs::File::create(root.nonce_log_path()).unwrap();
    // Sparse: whole lines' worth of zeros. Read, line 1 would refuse it for what it holds,
    // so what is refused for its length wasn't read.
    let says = |root: &StateDir| match root.nonce_used(&shared()) {
        Err(StateError::NonceLog { reason, .. }) => reason,
        other => panic!("{other:?}"),
    };
    assert_eq!(MAX_NONCE_LOG_BYTES % 65, 0, "the bound falls between lines");

    // One line short of the bound it may take one more, which brings it to the bound.
    file.set_len(MAX_NONCE_LOG_BYTES - 65).unwrap();
    assert!(says(&root).contains("line 1"), "{}", says(&root));

    // At the bound it takes no more, so it never gets past it.
    file.set_len(MAX_NONCE_LOG_BYTES).unwrap();
    assert!(says(&root).contains("full"), "{}", says(&root));
    assert_refused(&root);
    assert_eq!(file.metadata().unwrap().len(), MAX_NONCE_LOG_BYTES);

    file.set_len(MAX_NONCE_LOG_BYTES + 65).unwrap();
    assert!(says(&root).contains("full"), "{}", says(&root));
}

/// Writes part of what it's given to the log, as a disk that has just filled up does.
struct FullDisk<'a>(&'a fs::File);

impl Write for FullDisk<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let mut log = self.0;
        if log.metadata()?.len() % 65 == 0 {
            log.write(&bytes[..20])
        } else {
            Err(io::Error::from(io::ErrorKind::StorageFull))
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn appender(path: &Path) -> fs::File {
    fs::OpenOptions::new().append(true).open(path).unwrap()
}

#[test]
fn a_failed_write_takes_back_what_it_wrote() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert_eq!(
        root.spend_nonce(&test_nonce("first")).unwrap(),
        NonceSpend::Recorded
    );
    let log = root.nonce_log_path();
    let line = self::line("second");

    let error = append_line(
        &appender(&log),
        &mut FullDisk(&appender(&log)),
        line.as_bytes(),
        &log,
    )
    .unwrap_err();

    assert!(
        matches!(error, StateError::Io { op: "write", .. }),
        "{error}"
    );
    assert_eq!(fs::read_to_string(&log).unwrap(), self::line("first"));
    // So the next one, with room on the disk, goes through.
    assert!(!root.nonce_used(&test_nonce("second")).unwrap());
    assert_eq!(
        root.spend_nonce(&test_nonce("second")).unwrap(),
        NonceSpend::Recorded
    );
}

#[test]
fn a_failed_write_that_cannot_be_taken_back_stays_closed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert_eq!(
        root.spend_nonce(&test_nonce("first")).unwrap(),
        NonceSpend::Recorded
    );
    let log = root.nonce_log_path();
    let line = self::line("second");
    // Not open for writing, so it can't be truncated.
    let read_only = fs::File::open(&log).unwrap();

    let error = append_line(
        &read_only,
        &mut FullDisk(&appender(&log)),
        line.as_bytes(),
        &log,
    )
    .unwrap_err();

    assert!(matches!(error, StateError::NonceLog { .. }), "{error}");
    assert_refused(&root);
}

#[test]
fn a_symlink_in_the_logs_place_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    let elsewhere = tmp.path().join("elsewhere");
    fs::write(&elsewhere, line("writer 7")).unwrap();
    symlink(&elsewhere, root.nonce_log_path()).unwrap();

    assert!(root.nonce_used(&shared()).is_err(), "not read through");
    assert!(
        root.spend_nonce(&test_nonce("elsewhere")).is_err(),
        "not written through"
    );
    assert!(root.check_nonce_log().is_err());
    assert_eq!(fs::read_to_string(&elsewhere).unwrap(), line("writer 7"));

    // Nor one that points nowhere, which a plain create would make the target of.
    fs::remove_file(root.nonce_log_path()).unwrap();
    let nowhere = tmp.path().join("nowhere");
    symlink(&nowhere, root.nonce_log_path()).unwrap();
    assert!(root.spend_nonce(&shared()).is_err());
    assert!(!nowhere.exists());
}

#[test]
fn something_other_than_a_private_file_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    fs::create_dir(root.nonce_log_path()).unwrap();
    assert!(root.nonce_used(&shared()).is_err());
    assert!(root.spend_nonce(&shared()).is_err());
    fs::remove_dir(root.nonce_log_path()).unwrap();

    // A FIFO would hold a plain open for reading until a writer came along.
    let made = std::process::Command::new("mkfifo")
        .arg(root.nonce_log_path())
        .status()
        .unwrap();
    assert!(made.success());
    assert!(matches!(
        root.nonce_used(&shared()),
        Err(StateError::NonceLog { .. })
    ));
    assert!(root.spend_nonce(&shared()).is_err());
    fs::remove_file(root.nonce_log_path()).unwrap();

    fs::write(root.nonce_log_path(), line("first")).unwrap();
    fs::set_permissions(root.nonce_log_path(), fs::Permissions::from_mode(0o620)).unwrap();
    assert!(
        matches!(root.nonce_used(&shared()), Err(StateError::Writable { .. })),
        "someone else could forge or erase what it says"
    );
    assert!(matches!(
        root.spend_nonce(&shared()),
        Err(StateError::Writable { .. })
    ));
}

#[test]
fn of_writers_at_once_exactly_one_spends_a_nonce() {
    let tmp = tempfile::tempdir().unwrap();
    let recorded = Arc::new(AtomicUsize::new(0));
    let writers: Vec<_> = (0_u8..16)
        .map(|writer| {
            let (path, recorded) = (tmp.path().to_owned(), Arc::clone(&recorded));
            std::thread::spawn(move || {
                // Each has its own descriptor, as another process would.
                let root = StateDir::open(&path).unwrap();
                if until_free(&root, &shared()) == NonceSpend::Recorded {
                    recorded.fetch_add(1, Ordering::SeqCst);
                }
                let _ = until_free(&root, &test_nonce(&format!("writer {writer}")));
            })
        })
        .collect();
    for writer in writers {
        writer.join().unwrap();
    }
    assert_eq!(recorded.load(Ordering::SeqCst), 1);
    let root = dir(&tmp);
    assert_eq!(
        fs::read_to_string(root.nonce_log_path())
            .unwrap()
            .lines()
            .count(),
        16,
        "the 16 writers' own nonces, one of them the same as the shared one"
    );
    root.check_nonce_log().unwrap();
}

/// A child forked in another thread has a copy of the descriptor until it execs, and that mustn't
/// keep the lock from the next spend, for as long as it takes under load.
#[test]
fn a_lock_let_go_is_free_while_a_copy_of_its_descriptor_lives_on() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert_eq!(root.spend_nonce(&shared()).unwrap(), NonceSpend::Recorded);
    let path = root.nonce_log_path();
    let file = fs::File::open(&path).unwrap();
    let in_a_child = file.try_clone().unwrap();

    drop(locked(file, fs::File::try_lock, &path).unwrap());

    assert_eq!(
        root.spend_nonce(&test_nonce("other")).unwrap(),
        NonceSpend::Recorded
    );
    drop(in_a_child);
}

/// Something else that has the log for a moment is no reason to send the work round again.
#[test]
fn a_lock_let_go_in_a_moment_is_gone_through() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert_eq!(root.spend_nonce(&shared()).unwrap(), NonceSpend::Recorded);
    let holder = fs::File::open(root.nonce_log_path()).unwrap();
    holder.lock().unwrap();
    let letting_go = std::thread::spawn(move || {
        std::thread::sleep(std::time::Duration::from_millis(50));
        drop(holder);
    });

    assert_eq!(
        root.spend_nonce(&test_nonce("other")).unwrap(),
        NonceSpend::Recorded
    );
    letting_go.join().unwrap();
}

#[test]
fn a_lock_held_on_the_log_is_said_and_changes_nothing() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    assert_eq!(root.spend_nonce(&shared()).unwrap(), NonceSpend::Recorded);
    let before = fs::read(root.nonce_log_path()).unwrap();
    let holder = fs::File::open(root.nonce_log_path()).unwrap();
    let busy = |result: Result<NonceSpend, StateError>| {
        assert!(
            matches!(result, Err(StateError::NonceLogBusy(_))),
            "{result:?}"
        );
    };

    // Held to read: it can still be read, and can't be written.
    holder.lock_shared().unwrap();
    assert!(root.nonce_used(&shared()).unwrap());
    busy(root.spend_nonce(&test_nonce("other")));

    // Held to write: neither.
    holder.unlock().unwrap();
    holder.lock().unwrap();
    assert!(matches!(
        root.nonce_used(&shared()),
        Err(StateError::NonceLogBusy(_))
    ));
    busy(root.spend_nonce(&test_nonce("other")));
    assert_eq!(fs::read(root.nonce_log_path()).unwrap(), before);

    drop(holder);
    assert_eq!(
        root.spend_nonce(&test_nonce("other")).unwrap(),
        NonceSpend::Recorded
    );
}
