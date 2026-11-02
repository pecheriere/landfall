//! The state directory against a real temporary directory.

use landfall_core::ids::DeploymentId;
use landfall_core::protocol::{DeployId, DeployReportBody};

use super::{Deployed, DeploymentState, StateDir, StateError};

mod ledger;
mod outbox;
mod records;

fn id(s: &str) -> DeploymentId {
    s.parse().unwrap()
}

fn deployed() -> Deployed {
    Deployed {
        deploy_id: "2026-11-01T09-00-00-000000000Z".to_owned(),
        tag: "v1.2.3".parse().unwrap(),
        version: semver::Version::new(1, 2, 3),
        digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
        commit: "b".repeat(40).parse().unwrap(),
        deployed_at: "2026-11-01T10:00:00Z".parse().unwrap(),
    }
}

/// `take`, again while a lock it takes still seems held. Tests run on threads
/// of one process and others start children all the time: a child between
/// `fork` and `exec` has a copy of every descriptor, a released lock's
/// included, and a `flock` lasts until the last copy closes. So a lock can seem
/// held for a moment after it was let go. A lock really held stays busy, and
/// the last answer is returned after the bound.
fn once_released<T>(mut take: impl FnMut() -> Result<T, StateError>) -> Result<T, StateError> {
    let mut tries = 1;
    loop {
        match take() {
            Err(StateError::Busy(_) | StateError::DaemonBusy(_)) if tries < 1000 => {
                tries += 1;
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            other => return other,
        }
    }
}

fn state(tmp: &tempfile::TempDir) -> DeploymentState {
    StateDir::open(tmp.path())
        .unwrap()
        .deployment(&id("example/prod"))
        .unwrap()
}

fn body(id: u64) -> DeployReportBody {
    DeployReportBody {
        deploy_id: DeployId(id),
        deployment: self::id("example/prod"),
        tag: "v1.2.3".parse().unwrap(),
        digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
        outcome: landfall_core::protocol::ReportedOutcome::Deployed {},
        steps: Vec::new(),
    }
}
