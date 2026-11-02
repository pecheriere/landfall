//! The agent's own state directory: what is deployed, what is in progress,
//! the previous override and the deploy reports, per deployment.
//!
//! The directory belongs to the agent's user and is not writable by anyone
//! else, so nothing in it is hostile and plain file operations are enough.
//! Every write is a temporary file, `fsync`, rename and a directory `fsync`,
//! so a crash leaves the old content or the new, never a mix. The temporary
//! file's name is fixed, so a writer must hold the deployment's lock
//! ([`DeploymentState::lock`]): two at once could mix their bytes in it. The
//! controller's claim and the outbox have one writer, the daemon, which holds
//! the state directory's own lock ([`StateDir::lock_daemon`]) instead.

mod deployment;
mod dir;
mod error;
mod records;
#[cfg(test)]
mod tests;

pub use deployment::{DeployLock, DeploymentState};
pub use dir::StateDir;
pub use error::StateError;
pub use records::{
    ControllerClaim, Deployed, FailedRelease, FinishedDeploy, InProgress, Phase, RecordedBackup,
    VerificationWait,
};

const DEPLOYED: &str = "deployed.json";

const IN_PROGRESS: &str = "in-progress.json";

const PREVIOUS_OVERRIDE: &str = "previous-override.yaml";

const PREVIOUS_DEPLOYED: &str = "previous-deployed.json";

const LOCK: &str = "lock";

const BACKUPS: &str = "backups";

const REPORTS: &str = "reports";

const CLAIM: &str = "controller-claim.json";

const VERIFICATION_WAIT: &str = "verification-wait.json";

// Directly in the state directory. A deployment's directory always has `__` in
// its name, so these can't be taken for one.
const OUTBOX: &str = "outbox";

const FINISHED: &str = "finished";

const FINISHED_ORDER: &str = "order.json";

const DAEMON_LOCK: &str = "daemon.lock";

const FAILED_RELEASES: &str = "failed-releases.json";

/// How many finished deploys are remembered by number.
pub const FINISHED_KEPT: usize = 1024;

/// How many failed releases a deployment remembers. Only a deploy that really
/// ran and failed adds one, so a controller can't push them out cheaply.
pub const FAILED_KEPT: usize = 1024;

/// How many files of one name are kept set aside as corrupt.
pub const CORRUPT_KEPT: usize = 8;
