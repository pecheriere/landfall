//! The log of used approval nonces: an approval works once, across restarts, and a log
//! that can't be trusted refuses rather than reads as empty.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use super::super::{MAX_NONCE_LOG_BYTES, NONCE_LOG, NonceSpend, StateDir, StateError};

const NONCE: [u8; 32] = [7; 32];

fn dir(tmp: &tempfile::TempDir) -> StateDir {
    StateDir::open(tmp.path()).unwrap()
}

fn line(byte: u8) -> String {
    format!("{}\n", hex::encode([byte; 32]))
}

fn assert_refused(root: &StateDir) {
    assert!(
        matches!(root.nonce_used(&NONCE), Err(StateError::NonceLog { .. })),
        "{:?}",
        root.nonce_used(&NONCE)
    );
    assert!(
        matches!(root.spend_nonce(&NONCE), Err(StateError::NonceLog { .. })),
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
    assert!(!root.nonce_used(&NONCE).unwrap());
    assert!(
        !tmp.path().join(NONCE_LOG).exists(),
        "reading makes no file"
    );
    root.check_nonce_log().unwrap();

    assert_eq!(root.spend_nonce(&NONCE).unwrap(), NonceSpend::Recorded);

    assert!(root.nonce_used(&NONCE).unwrap());
    assert!(!root.nonce_used(&[8; 32]).unwrap());
    assert_eq!(root.spend_nonce(&NONCE).unwrap(), NonceSpend::AlreadyUsed);
    let reopened = dir(&tmp);
    assert!(reopened.nonce_used(&NONCE).unwrap());
    assert_eq!(
        reopened.spend_nonce(&NONCE).unwrap(),
        NonceSpend::AlreadyUsed
    );
    assert_eq!(
        reopened.spend_nonce(&[8; 32]).unwrap(),
        NonceSpend::Recorded
    );

    let log = reopened.nonce_log_path();
    assert_eq!(
        fs::read_to_string(&log).unwrap(),
        format!("{}{}", line(7), line(8)),
        "one line per nonce"
    );
    let mode = fs::metadata(&log).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o600);
}

#[test]
fn a_torn_or_corrupt_log_refuses_and_is_left_as_it_is() {
    let good = line(1);
    let long = format!("{}0\n", hex::encode([1_u8; 32]));
    for bad in [
        // A crash in the middle of the last line.
        format!("{good}{}", &line(2)[..20]),
        // A whole line's length without the end of a line.
        format!("{good}{}0", hex::encode([2_u8; 32])),
        "\n".to_owned(),
        format!("{}\n", "x".repeat(64)),
        format!("{}\n", "AB".repeat(32)),
        format!("{}\r\n", hex::encode([1_u8; 32])),
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
    // Whole lines' worth, so this can only be the bound: sparse, and not read.
    file.set_len((MAX_NONCE_LOG_BYTES / 65 + 1) * 65).unwrap();
    assert_refused(&root);
}

#[test]
fn a_symlink_in_the_logs_place_is_not_followed() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    let elsewhere = tmp.path().join("elsewhere");
    fs::write(&elsewhere, line(7)).unwrap();
    symlink(&elsewhere, root.nonce_log_path()).unwrap();

    assert!(root.nonce_used(&NONCE).is_err(), "not read through");
    assert!(root.spend_nonce(&[9; 32]).is_err(), "not written through");
    assert!(root.check_nonce_log().is_err());
    assert_eq!(fs::read_to_string(&elsewhere).unwrap(), line(7));

    // Nor one that points nowhere, which a plain create would make the target of.
    fs::remove_file(root.nonce_log_path()).unwrap();
    let nowhere = tmp.path().join("nowhere");
    symlink(&nowhere, root.nonce_log_path()).unwrap();
    assert!(root.spend_nonce(&NONCE).is_err());
    assert!(!nowhere.exists());
}

#[test]
fn something_other_than_a_private_file_refuses() {
    let tmp = tempfile::tempdir().unwrap();
    let root = dir(&tmp);
    fs::create_dir(root.nonce_log_path()).unwrap();
    assert!(root.nonce_used(&NONCE).is_err());
    assert!(root.spend_nonce(&NONCE).is_err());
    fs::remove_dir(root.nonce_log_path()).unwrap();

    // A FIFO would hold a plain open for reading until a writer came along.
    let made = std::process::Command::new("mkfifo")
        .arg(root.nonce_log_path())
        .status()
        .unwrap();
    assert!(made.success());
    assert!(matches!(
        root.nonce_used(&NONCE),
        Err(StateError::NonceLog { .. })
    ));
    assert!(root.spend_nonce(&NONCE).is_err());
    fs::remove_file(root.nonce_log_path()).unwrap();

    fs::write(root.nonce_log_path(), line(1)).unwrap();
    fs::set_permissions(root.nonce_log_path(), fs::Permissions::from_mode(0o620)).unwrap();
    assert!(
        matches!(root.nonce_used(&NONCE), Err(StateError::Writable { .. })),
        "someone else could forge or erase what it says"
    );
    assert!(matches!(
        root.spend_nonce(&NONCE),
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
                if root.spend_nonce(&NONCE).unwrap() == NonceSpend::Recorded {
                    recorded.fetch_add(1, Ordering::SeqCst);
                }
                let _ = root.spend_nonce(&[writer; 32]).unwrap();
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
