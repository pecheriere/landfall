//! The ledger of finished deploys, set-aside files and reports.

use std::fs;

use landfall_core::protocol::{DeployId, DeployWork};

use super::super::dir::{ledger_key, write_order};
use super::super::{
    CLAIM, CORRUPT_KEPT, Deployed, FAILED_KEPT, FAILED_RELEASES, FINISHED, FINISHED_KEPT,
    FINISHED_ORDER, FailedRelease, FinishedDeploy, StateDir,
};
use super::{body, deployed, id, state};

fn finished_entry(id: u64) -> FinishedDeploy {
    FinishedDeploy {
        deployment: self::id("example/prod"),
        tag: "v1.2.3".parse().unwrap(),
        digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
        report: body(id),
    }
}

/// The work item that [`finished_entry`] is the end of.
fn asked(id: u64) -> DeployWork {
    let entry = finished_entry(id);
    DeployWork {
        deploy_id: DeployId(id),
        deployment: entry.deployment,
        tag: entry.tag,
        digest: entry.digest,
        commit: "b".repeat(40).parse().unwrap(),
    }
}

fn key_of(id: u64) -> String {
    let entry = finished_entry(id);
    ledger_key(DeployId(id), &entry.deployment, &entry.tag, &entry.digest)
}

#[test]
fn the_ledger_evicts_the_longest_on_record_whatever_the_numbers() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    assert_eq!(dir.finished(&asked(1)).unwrap(), None);
    // A full ledger, written directly as a thousand synced writes are slow. A
    // very high number came first: by number it would be the last to go.
    dir.finished_put(&finished_entry(u64::MAX)).unwrap();
    dir.finished_put(&finished_entry(u64::MAX - 1)).unwrap();
    let ledger = tmp.path().join(FINISHED);
    let mut order = vec![key_of(u64::MAX), key_of(u64::MAX - 1)];
    for id in 1..=u64::try_from(FINISHED_KEPT - 2).unwrap() {
        let entry = serde_json::to_vec(&finished_entry(id)).unwrap();
        fs::write(ledger.join(format!("{}.json", key_of(id))), entry).unwrap();
        order.push(key_of(id));
    }
    write_order(&ledger, &order).unwrap();

    dir.finished_put(&finished_entry(5000)).unwrap();

    assert_eq!(dir.finished(&asked(u64::MAX)).unwrap(), None);
    assert!(dir.finished(&asked(u64::MAX - 1)).unwrap().is_some());
    assert!(dir.finished(&asked(1)).unwrap().is_some());
    assert!(dir.finished(&asked(5000)).unwrap().is_some());
    let kept = fs::read_dir(&ledger).unwrap().count();
    assert_eq!(kept, FINISHED_KEPT + 1, "with the order file");
}

#[test]
fn a_ledger_entry_keeps_its_report_and_its_place() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    let first = finished_entry(1);
    dir.finished_put(&first).unwrap();
    let mut again = finished_entry(1);
    again.report.steps.clear();
    again.report.outcome = landfall_core::protocol::ReportedOutcome::Refused {
        reason: "no".to_owned(),
    };
    dir.finished_put(&again).unwrap();
    assert_eq!(dir.finished(&asked(1)).unwrap(), Some(first));
}

#[test]
fn the_ledger_goes_by_number_and_release() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    let first = finished_entry(1);
    dir.finished_put(&first).unwrap();

    for other in [
        DeployWork {
            tag: "v9.9.9".parse().unwrap(),
            ..asked(1)
        },
        DeployWork {
            digest: format!("sha256:{}", "e".repeat(64)).parse().unwrap(),
            ..asked(1)
        },
        DeployWork {
            deployment: id("example/other"),
            ..asked(1)
        },
        asked(2),
    ] {
        assert_eq!(dir.finished(&other).unwrap(), None, "{other:?}");
    }

    // The same number, for another release, has a record of its own.
    let mut second = finished_entry(1);
    second.tag = "v9.9.9".parse().unwrap();
    dir.finished_put(&second).unwrap();
    assert_eq!(dir.finished(&asked(1)).unwrap(), Some(first));
    let ask = DeployWork {
        tag: "v9.9.9".parse().unwrap(),
        ..asked(1)
    };
    assert_eq!(dir.finished(&ask).unwrap(), Some(second));
}

#[test]
fn a_lost_order_is_rebuilt_from_what_is_on_record() {
    let tmp = tempfile::tempdir().unwrap();
    let dir = StateDir::open(tmp.path()).unwrap();
    dir.finished_put(&finished_entry(5)).unwrap();
    fs::write(tmp.path().join(FINISHED).join(FINISHED_ORDER), "{").unwrap();
    dir.finished_put(&finished_entry(6)).unwrap();
    let order: Vec<String> =
        serde_json::from_slice(&fs::read(tmp.path().join(FINISHED).join(FINISHED_ORDER)).unwrap())
            .unwrap();
    assert_eq!(order, [key_of(5), key_of(6)]);
    assert!(dir.finished(&asked(5)).unwrap().is_some());
}

#[test]
fn set_aside_files_keep_earlier_evidence_up_to_a_bound() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    let dir = tmp.path().join("example__prod");
    for round in 1..=CORRUPT_KEPT + 3 {
        fs::write(dir.join(CLAIM), format!("{{{round}")).unwrap();
        assert_eq!(s.claim().unwrap(), None);
    }
    let name = |n: usize| dir.join(format!("{CLAIM}.corrupt.{n}"));
    let last = CORRUPT_KEPT + 3;
    assert_eq!(fs::read_to_string(name(last)).unwrap(), format!("{{{last}"));
    assert_eq!(fs::read_to_string(name(4)).unwrap(), "{4");
    assert!(!name(3).exists(), "the oldest went");
}

#[test]
fn failed_releases_keep_the_newest_and_never_read_as_empty_when_corrupt() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.failed_releases().unwrap(), []);
    let release = |n: usize| FailedRelease {
        tag: format!("v1.0.{n}").parse().unwrap(),
        digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
    };
    let full: Vec<FailedRelease> = (0..FAILED_KEPT).map(release).collect();
    s.write_json(FAILED_RELEASES, &full).unwrap();
    s.add_failed_release(&release(FAILED_KEPT)).unwrap();
    s.add_failed_release(&release(5)).unwrap();
    let kept = s.failed_releases().unwrap();
    assert_eq!(kept.len(), FAILED_KEPT);
    assert_eq!(kept[0], release(1), "the oldest went");
    assert_eq!(kept[FAILED_KEPT - 1], release(FAILED_KEPT));

    fs::write(s.failed_releases_path(), "{").unwrap();
    assert!(s.failed_releases().is_err());
    assert!(s.add_failed_release(&release(0)).is_err());
}

#[test]
fn reports_read_back_by_name() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.report_names().unwrap(), Vec::<String>::new());
    s.write_report("good", &deployed()).unwrap();
    s.write_report("other", &serde_json::json!({"not": "a report"}))
        .unwrap();
    let mut names = s.report_names().unwrap();
    names.sort();
    assert_eq!(names, ["good.json", "other.json"]);
    assert_eq!(s.report::<Deployed>("good.json").unwrap(), deployed());
    assert!(s.report::<Deployed>("other.json").is_err());
}

#[test]
fn backups_dir_is_inside_the_deployment_directory() {
    let tmp = tempfile::tempdir().unwrap();
    let s = state(&tmp);
    assert_eq!(s.backups_dir(), tmp.path().join("example__prod/backups"));
}
