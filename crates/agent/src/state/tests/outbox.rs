//! The outbox, the daemon lock and the controller's claim.

use std::fs;

use landfall_core::protocol::DeployId;

use super::super::{CLAIM, ControllerClaim, StateDir, StateError};
use super::{body, once_released, state};
use crate::journal::{self, Priority};

#[test]
fn the_outbox_keeps_reports_in_order_until_removed() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    assert_eq!(dir.outbox().unwrap(), Vec::new());
    // In number order, not name order, and past a leftover temporary file.
    dir.outbox_put(&body(10)).unwrap();
    dir.outbox_put(&body(9)).unwrap();
    fs::write(tmp.path().join("outbox/.11.json.tmp"), "half").unwrap();
    assert_eq!(dir.outbox().unwrap(), vec![body(9), body(10)]);
    dir.outbox_remove(DeployId(9)).unwrap();
    dir.outbox_remove(DeployId(9)).unwrap();
    assert_eq!(dir.outbox().unwrap(), vec![body(10)]);
}

#[test]
fn a_corrupt_report_in_the_outbox_is_set_aside_and_the_others_carry_on() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    dir.outbox_put(&body(1)).unwrap();
    dir.outbox_put(&body(2)).unwrap();
    fs::write(tmp.path().join("outbox/1.json"), "{").unwrap();
    assert_eq!(dir.outbox().unwrap(), vec![body(2)]);
    assert!(tmp.path().join("outbox/1.json.corrupt.1").exists());
    assert_eq!(
        dir.outbox().unwrap(),
        vec![body(2)],
        "and it isn't taken for a report afterwards"
    );
    assert_eq!(
        journal::capture::events("state_file_set_aside").len(),
        1,
        "said once"
    );
}

#[test]
fn a_second_daemon_is_busy() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    let held = dir.lock_daemon().unwrap();
    let err = dir.lock_daemon().unwrap_err();
    assert!(matches!(err, StateError::DaemonBusy(_)), "{err}");
    drop(held);
    once_released(|| dir.lock_daemon()).unwrap();
}

#[test]
fn a_claim_round_trips_and_clears() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.claim().unwrap(), None);
    let claim = ControllerClaim {
        deploy_id: DeployId(7),
        tag: "v1.2.3".parse().unwrap(),
        digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
        reports_before: vec!["a.json".to_owned()],
    };
    s.set_claim(&claim).unwrap();
    assert_eq!(s.claim().unwrap(), Some(claim));
    s.clear_claim().unwrap();
    assert_eq!(s.claim().unwrap(), None);
}

#[test]
fn a_corrupt_claim_is_set_aside() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    let file = tmp.path().join("example__prod").join(CLAIM);
    fs::write(&file, "{").unwrap();
    assert_eq!(s.claim().unwrap(), None);
    assert!(!file.exists());
    assert_eq!(
        fs::read_to_string(file.with_file_name(format!("{CLAIM}.corrupt.1"))).unwrap(),
        "{"
    );
    let events = journal::capture::events("state_file_set_aside");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].0, Priority::Error);
}
