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

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{DeployId, DeployReportBody};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::journal::{self, Priority};

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

/// A failure reading or writing the agent's state.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// A filesystem operation failed.
    #[error("state: {op} {path}: {source}")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The path involved.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The state path is not a directory (a symlink is not followed).
    #[error("state: {0} is not a directory")]
    NotADirectory(PathBuf),
    /// The directory belongs to another user.
    #[error("state: {path} is owned by uid {owner}, not by the agent's uid {agent}")]
    WrongOwner {
        /// The directory.
        path: PathBuf,
        /// Its owner.
        owner: u32,
        /// The agent's user.
        agent: u32,
    },
    /// The directory is writable by its group or by everyone.
    #[error("state: {path} has mode {mode:o}; it must not be group- or world-writable")]
    Writable {
        /// The directory.
        path: PathBuf,
        /// Its permission bits.
        mode: u32,
    },
    /// Another process holds the deployment's lock.
    #[error("deployment {0} is busy: another agent process holds its lock")]
    Busy(DeploymentId),
    /// Another `run` or `enrol` is working in this state directory.
    #[error("state: another landfall-agent run or enrol holds {0}")]
    DaemonBusy(PathBuf),
    /// A state file exists but cannot be read as what it should hold. It is
    /// never treated as empty: that could deploy over an unknown state.
    #[error("state: {path} is corrupt: {source}")]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// Why it did not parse.
        source: serde_json::Error,
    },
    /// A state value could not be serialised.
    #[error("state: cannot serialise {path}: {source}")]
    Serialise {
        /// The file that was to be written.
        path: PathBuf,
        /// Why it did not serialise.
        source: serde_json::Error,
    },
    /// A report id is not a plain file name.
    #[error("state: report id {0:?} must be 1 to 128 of [A-Za-z0-9_-]")]
    InvalidReportId(String),
}

fn io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> StateError {
    let path = path.to_owned();
    move |source| StateError::Io { op, path, source }
}

/// What is running for a deployment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Deployed {
    /// The deploy that recorded this, as in [`InProgress::deploy_id`].
    pub deploy_id: String,
    /// The release tag.
    pub tag: ReleaseTag,
    /// The version the tag parses to.
    pub version: semver::Version,
    /// The image digest that was started.
    pub digest: ImageDigest,
    /// The commit the tag points at.
    pub commit: CommitSha,
    /// When the deploy finished.
    pub deployed_at: Timestamp,
}

/// How far an unfinished deploy got, which is what `recover` goes by. Each
/// value is on disk before the work it announces starts.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Checking the project and pulling the image. No service has been
    /// touched; only the override can be out of place.
    Preflight,
    /// Going forward: the service may have been touched. The deploy has finished only if [`Deployed`] names its
    /// id: that is written once the checks have passed.
    Deploying,
    /// Going back. A [`Deployed`] that names this deploy means nothing here:
    /// the record can have been left by a write reported as failed, and the
    /// release is on its way out.
    RollingBack,
    /// Going back, and the backup has been restored in full: the override and
    /// the record were put back before it. What remains is to start the
    /// previous version and check it. It may well be running by now and have
    /// written to its data, so the service is not stopped and the backup is
    /// not restored again. A restore that did not finish stays [`Self::RollingBack`].
    Restored,
    /// Back, and checked. Only the marker is left to remove; restoring again
    /// would discard what the previous version wrote since.
    RolledBack,
}

/// A backup that is complete, and what it holds. The paths are the ones it was
/// taken of, whatever the configuration says by the time it is restored.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordedBackup {
    /// The backup's directory name.
    pub id: String,
    /// The paths it holds, relative to the compose directory.
    pub paths: Vec<String>,
}

/// A deploy that has started and not finished. While it exists, further
/// deploys of the deployment are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InProgress {
    /// Tells this deploy from every other one, also of the same release.
    pub deploy_id: String,
    /// How far it got.
    pub phase: Phase,
    /// The release being deployed.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
    /// Whether there is a previous version to start: the compose project gave
    /// the service an image before the deploy. On a first deploy from a base
    /// file without one, rollback stops the service instead.
    pub previous_can_start: bool,
    /// The backup taken for this deploy, if any.
    pub backup: Option<RecordedBackup>,
    /// When the deploy began.
    pub started_at: Timestamp,
}

/// The controller's deploy a deployment is working on, written before the
/// engine starts and removed once the report is safely in the outbox. It is
/// what ties the controller's number to the agent's own deploy: only one can
/// exist per deployment and none is written while a marker is there, so the
/// marker or the report the engine leaves after a crash, or after a `recover`,
/// is this deploy's. Only the daemon writes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ControllerClaim {
    /// The controller's id for the deploy.
    pub deploy_id: DeployId,
    /// The release the deploy is of.
    pub tag: ReleaseTag,
    /// Its verified image digest.
    pub digest: ImageDigest,
    /// The engine's report files that existed when the claim was made. Whatever
    /// the engine reports for this deploy is not among them, whatever the clock
    /// did in between.
    pub reports_before: Vec<String>,
}

/// How a controller's deploy ended, and what it was of, so that the same number
/// naming another release can be told apart.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinishedDeploy {
    /// The deployment it was for.
    pub deployment: DeploymentId,
    /// The release it was of.
    pub tag: ReleaseTag,
    /// Its image digest, as it was asked for.
    pub digest: ImageDigest,
    /// How it ended.
    pub report: DeployReportBody,
}

/// A release that failed on this host and isn't retried automatically.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FailedRelease {
    /// The release tag.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
}

/// How long verification of one work item has been unable to run. The time is
/// summed from the monotonic clock, one poll to the next, so a wall clock that
/// jumps doesn't move it, and time the agent was stopped doesn't count.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerificationWait {
    /// The controller's id for the deploy.
    pub deploy_id: DeployId,
    /// How long so far.
    pub waited_millis: u64,
    /// How many periods of waiting the journal has been told about.
    pub warned_periods: u64,
}

/// The agent's state directory.
#[derive(Debug, Clone)]
pub struct StateDir {
    path: PathBuf,
}

/// Checks that `path` is a real directory (not a symlink), owned by the
/// agent's user and not writable by group or others.
fn check_private_dir(path: &Path) -> Result<(), StateError> {
    let meta = fs::symlink_metadata(path).map_err(io_err("inspect", path))?;
    if !meta.is_dir() {
        return Err(StateError::NotADirectory(path.to_owned()));
    }
    let agent = rustix::process::geteuid().as_raw();
    if meta.uid() != agent {
        return Err(StateError::WrongOwner {
            path: path.to_owned(),
            owner: meta.uid(),
            agent,
        });
    }
    let mode = meta.mode() & 0o7777;
    if mode & 0o022 != 0 {
        return Err(StateError::Writable {
            path: path.to_owned(),
            mode,
        });
    }
    Ok(())
}

impl StateDir {
    /// Opens the state directory. It must exist, be owned by the agent's
    /// user and not be group- or world-writable.
    ///
    /// # Errors
    ///
    /// [`StateError`] naming the path and which requirement failed.
    pub fn open(path: &Path) -> Result<StateDir, StateError> {
        check_private_dir(path)?;
        Ok(StateDir {
            path: path.to_owned(),
        })
    }

    /// The state of one deployment, creating its directory (mode 0700) if
    /// needed. The directory name is the id with `/` replaced by `__`; ids
    /// contain no `_`, so two ids never share a name.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the directory cannot be created or is not private.
    pub fn deployment(&self, id: &DeploymentId) -> Result<DeploymentState, StateError> {
        let dir = self.path.join(id.as_ref().replace('/', "__"));
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err("create", &dir)(e)),
        }
        check_private_dir(&dir)?;
        Ok(DeploymentState {
            id: id.clone(),
            dir,
        })
    }

    /// The directory itself.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Takes the state directory's own lock without waiting: one `run` or
    /// `enrol` at a time. The outbox, the claims and the key are written only
    /// under it. `status` and `recover` don't need it: they go by the lock of
    /// the deployment they work on.
    ///
    /// # Errors
    ///
    /// [`StateError::DaemonBusy`] if another process holds it.
    pub fn lock_daemon(&self) -> Result<DeployLock, StateError> {
        let path = self.path.join(DAEMON_LOCK);
        lock_file(&path, || StateError::DaemonBusy(path.clone()))
    }

    /// Keeps a finished report until the controller has acknowledged it. A
    /// report for the same deploy replaces the earlier one.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn outbox_put(&self, report: &DeployReportBody) -> Result<(), StateError> {
        let dir = self.path.join(OUTBOX);
        create_private(&self.path, &dir)?;
        let name = format!("{}.json", report.deploy_id);
        let bytes = serde_json::to_vec_pretty(report).map_err(|source| StateError::Serialise {
            path: dir.join(&name),
            source,
        })?;
        write_atomic(&dir, &name, &bytes)
    }

    /// Every report waiting to be acknowledged, oldest deploy first. One that
    /// cannot be read as a report is set aside as `<name>.corrupt` and journalled,
    /// so that it can't stop the others.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the directory cannot be read.
    pub fn outbox(&self) -> Result<Vec<DeployReportBody>, StateError> {
        let dir = self.path.join(OUTBOX);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err("list", &dir)(e)),
        };
        let mut reports = Vec::new();
        for entry in entries {
            let path = entry.map_err(io_err("list", &dir))?.path();
            // A leftover temporary file starts with a dot and isn't a report.
            let is_report = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .is_some_and(|stem| stem.parse::<u64>().is_ok());
            if is_report && let Some(report) = read_or_set_aside(&path)? {
                reports.push(report);
            }
        }
        reports.sort_by_key(|report: &DeployReportBody| report.deploy_id);
        Ok(reports)
    }

    /// Records for good how the controller's deploy ended, so that it is answered
    /// with this report if it is ever delivered again, and never runs again. The
    /// [`FINISHED_KEPT`] most recently added are kept, by the order they were
    /// added in and whatever their numbers: a controller can ask for as many
    /// numbers as it likes, and one that comes back after that is judged afresh,
    /// by a rule that refuses what ran or failed. An id already on record keeps
    /// its report and its place.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn finished_put(&self, entry: &FinishedDeploy) -> Result<(), StateError> {
        let dir = self.path.join(FINISHED);
        create_private(&self.path, &dir)?;
        let id = entry.report.deploy_id.0;
        let mut order: Vec<u64> = read_or_set_aside(&dir.join(FINISHED_ORDER))?.unwrap_or_default();
        // Records the order doesn't name, after a crash or with the order lost,
        // count as older than what it does, lowest number first.
        let mut unlisted = Vec::new();
        for file in fs::read_dir(&dir).map_err(io_err("list", &dir))? {
            let path = file.map_err(io_err("list", &dir))?.path();
            if let Some(found) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .and_then(|stem| stem.parse::<u64>().ok())
                && !order.contains(&found)
            {
                unlisted.push(found);
            }
        }
        unlisted.sort_unstable();
        unlisted.append(&mut order);
        let mut order = unlisted;
        if order.contains(&id) {
            return write_order(&dir, &order);
        }
        order.push(id);
        let evicted = order.len().saturating_sub(FINISHED_KEPT);
        let gone: Vec<u64> = order.drain(..evicted).collect();
        write_order(&dir, &order)?;
        for old in gone {
            remove_in(&dir, &format!("{old}.json"))?;
        }
        let name = format!("{id}.json");
        let bytes = serde_json::to_vec_pretty(entry).map_err(|source| StateError::Serialise {
            path: dir.join(&name),
            source,
        })?;
        write_atomic(&dir, &name, &bytes)
    }

    /// How the controller's deploy ended, if it is on record. A record that
    /// cannot be read is set aside and counts as none.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the file cannot be read.
    pub fn finished(&self, deploy_id: DeployId) -> Result<Option<FinishedDeploy>, StateError> {
        read_or_set_aside(&self.path.join(FINISHED).join(format!("{deploy_id}.json")))
    }

    /// Removes an acknowledged report; absent is fine.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the removal fails.
    pub fn outbox_remove(&self, deploy_id: DeployId) -> Result<(), StateError> {
        let dir = self.path.join(OUTBOX);
        remove_in(&dir, &format!("{deploy_id}.json"))
    }
}

/// Opens `path` and takes its lock without waiting; `busy` is the error when
/// another process holds it.
fn lock_file(path: &Path, busy: impl FnOnce() -> StateError) -> Result<DeployLock, StateError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err("open", path))?;
    match file.try_lock() {
        Ok(()) => Ok(DeployLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(busy()),
        Err(TryLockError::Error(e)) => Err(io_err("lock", path)(e)),
    }
}

fn write_order(dir: &Path, order: &[u64]) -> Result<(), StateError> {
    let bytes = serde_json::to_vec(order).map_err(|source| StateError::Serialise {
        path: dir.join(FINISHED_ORDER),
        source,
    })?;
    write_atomic(dir, FINISHED_ORDER, &bytes)
}

/// Moves a file aside as `<name>.corrupt.<n>`, with a number no earlier one had,
/// keeping the newest [`CORRUPT_KEPT`] of that name: evidence isn't overwritten,
/// and a file that keeps going bad can't fill the disk.
fn set_aside(path: &Path) -> Result<(), StateError> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name().and_then(|n| n.to_str())) else {
        return Err(StateError::NotADirectory(path.to_owned()));
    };
    let prefix = format!("{name}.corrupt.");
    let mut numbers = Vec::new();
    for entry in fs::read_dir(dir).map_err(io_err("list", dir))? {
        let file = entry.map_err(io_err("list", dir))?.file_name();
        if let Some(number) = file
            .to_str()
            .and_then(|file| file.strip_prefix(&prefix))
            .and_then(|number| number.parse::<u64>().ok())
        {
            numbers.push(number);
        }
    }
    numbers.sort_unstable();
    let next = numbers.last().map_or(1, |last| last.saturating_add(1));
    let aside = dir.join(format!("{prefix}{next}"));
    fs::rename(path, &aside).map_err(io_err("set aside", path))?;
    numbers.push(next);
    let excess = numbers.len().saturating_sub(CORRUPT_KEPT);
    for old in &numbers[..excess] {
        remove_in(dir, &format!("{prefix}{old}"))?;
    }
    Ok(())
}

/// Reads a JSON file the daemon can do without. One that doesn't parse is set
/// aside (see [`set_aside`]) and journalled, rather than stop everything else.
fn read_or_set_aside<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, StateError> {
    #[derive(Serialize)]
    struct SetAside<'a> {
        event: &'static str,
        file: &'a Path,
        error: String,
    }
    let bytes = match fs::read(path) {
        Ok(bytes) => bytes,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(io_err("read", path)(e)),
    };
    match serde_json::from_slice(&bytes) {
        Ok(value) => Ok(Some(value)),
        Err(error) => {
            set_aside(path)?;
            journal::emit(
                Priority::Error,
                &SetAside {
                    event: "state_file_set_aside",
                    file: path,
                    error: error.to_string(),
                },
            );
            Ok(None)
        }
    }
}

/// Creates `dir` (mode 0700) in `parent` if it isn't there.
fn create_private(parent: &Path, dir: &Path) -> Result<(), StateError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => sync_dir(parent),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(io_err("create", dir)(e)),
    }
}

/// Removes `name` from `dir`; absent is fine.
fn remove_in(dir: &Path, name: &str) -> Result<(), StateError> {
    let path = dir.join(name);
    match fs::remove_file(&path) {
        Ok(()) => sync_dir(dir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("remove", &path)(e)),
    }
}

/// The state files of one deployment. Reading needs no lock; whoever writes
/// holds [`Self::lock`].
#[derive(Debug, Clone)]
pub struct DeploymentState {
    id: DeploymentId,
    dir: PathBuf,
}

/// The exclusive right to deploy one deployment, held until dropped.
#[derive(Debug)]
pub struct DeployLock {
    _file: File,
}

impl DeploymentState {
    /// Takes the deployment's lock without waiting.
    ///
    /// # Errors
    ///
    /// [`StateError::Busy`] if another process holds it.
    pub fn lock(&self) -> Result<DeployLock, StateError> {
        lock_file(&self.dir.join(LOCK), || StateError::Busy(self.id.clone()))
    }

    /// The controller's deploy this deployment is working on, if any. A claim
    /// that cannot be read is set aside and counts as none: what the controller
    /// was told of that deploy is then up to it to redeliver.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the file cannot be read.
    pub fn claim(&self) -> Result<Option<ControllerClaim>, StateError> {
        read_or_set_aside(&self.dir.join(CLAIM))
    }

    /// The releases that failed on this host. Written only by the daemon, from
    /// the outcome it holds. Never read as empty when it can't be read: that
    /// would let a failed release run again.
    ///
    /// # Errors
    ///
    /// [`StateError`] if it exists and cannot be read.
    pub fn failed_releases(&self) -> Result<Vec<FailedRelease>, StateError> {
        Ok(self.read_json(FAILED_RELEASES)?.unwrap_or_default())
    }

    /// Where [`Self::failed_releases`] are kept.
    #[must_use]
    pub fn failed_releases_path(&self) -> PathBuf {
        self.dir.join(FAILED_RELEASES)
    }

    /// Remembers that a release failed. The newest [`FAILED_KEPT`] are kept, by
    /// the order they failed in.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the record can't be read or written.
    pub fn add_failed_release(&self, release: &FailedRelease) -> Result<(), StateError> {
        let mut failed = self.failed_releases()?;
        if failed.contains(release) {
            return Ok(());
        }
        failed.push(release.clone());
        let excess = failed.len().saturating_sub(FAILED_KEPT);
        failed.drain(..excess);
        self.write_json(FAILED_RELEASES, &failed)
    }

    /// How long verification has been unable to run, if it has. One that cannot
    /// be read is set aside and counts as none.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the file cannot be read.
    pub fn verification_wait(&self) -> Result<Option<VerificationWait>, StateError> {
        read_or_set_aside(&self.dir.join(VERIFICATION_WAIT))
    }

    /// Records how long verification has been unable to run.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_verification_wait(&self, wait: &VerificationWait) -> Result<(), StateError> {
        self.write_json(VERIFICATION_WAIT, wait)
    }

    /// Removes the record of a wait; absent is fine.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the removal fails.
    pub fn clear_verification_wait(&self) -> Result<(), StateError> {
        self.remove(VERIFICATION_WAIT)
    }

    /// Records the controller's deploy before the engine starts on it.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_claim(&self, claim: &ControllerClaim) -> Result<(), StateError> {
        self.write_json(CLAIM, claim)
    }

    /// Removes the claim; absent is fine.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the removal fails.
    pub fn clear_claim(&self) -> Result<(), StateError> {
        self.remove(CLAIM)
    }

    /// The file names of the engine's reports of this deployment.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the directory cannot be listed.
    pub fn report_names(&self) -> Result<Vec<String>, StateError> {
        let dir = self.dir.join(REPORTS);
        let entries = match fs::read_dir(&dir) {
            Ok(entries) => entries,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(e) => return Err(io_err("list", &dir)(e)),
        };
        let mut names = Vec::new();
        for entry in entries {
            let name = entry.map_err(io_err("list", &dir))?.file_name();
            let is_report = Path::new(&name)
                .extension()
                .is_some_and(|extension| extension == "json");
            if let (true, Some(name)) = (is_report, name.to_str()) {
                names.push(name.to_owned());
            }
        }
        Ok(names)
    }

    /// Where the engine's report of this name is.
    #[must_use]
    pub fn report_path(&self, name: &str) -> PathBuf {
        self.dir.join(REPORTS).join(name)
    }

    /// One of the engine's reports, by the name [`Self::report_names`] gave.
    ///
    /// # Errors
    ///
    /// [`StateError`] if it can't be read as an `R`.
    pub fn report<R: DeserializeOwned>(&self, name: &str) -> Result<R, StateError> {
        let path = self.dir.join(REPORTS).join(name);
        let bytes = fs::read(&path).map_err(io_err("read", &path))?;
        serde_json::from_slice(&bytes).map_err(|source| StateError::Corrupt { path, source })
    }

    /// What is deployed, or `None` if nothing ever was.
    ///
    /// # Errors
    ///
    /// [`StateError::Corrupt`] if the file exists and is not valid.
    pub fn deployed(&self) -> Result<Option<Deployed>, StateError> {
        self.read_json(DEPLOYED)
    }

    /// Records what is deployed.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_deployed(&self, deployed: &Deployed) -> Result<(), StateError> {
        self.write_json(DEPLOYED, deployed)
    }

    /// The unfinished deploy, if any.
    ///
    /// # Errors
    ///
    /// [`StateError::Corrupt`] if the file exists and is not valid.
    pub fn in_progress(&self) -> Result<Option<InProgress>, StateError> {
        self.read_json(IN_PROGRESS)
    }

    /// Records that a deploy has started.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_in_progress(&self, in_progress: &InProgress) -> Result<(), StateError> {
        self.write_json(IN_PROGRESS, in_progress)
    }

    /// Removes the unfinished-deploy marker; absent is fine.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the removal fails.
    pub fn clear_in_progress(&self) -> Result<(), StateError> {
        self.remove(IN_PROGRESS)
    }

    /// Removes the record of what is deployed; absent is fine.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the removal fails.
    pub fn clear_deployed(&self) -> Result<(), StateError> {
        self.remove(DEPLOYED)
    }

    /// What [`Self::deployed`] returned when the current deploy started, or
    /// `None` if that was not saved.
    ///
    /// # Errors
    ///
    /// [`StateError::Corrupt`] if the file exists and is not valid.
    pub fn previous_deployed(&self) -> Result<Option<Option<Deployed>>, StateError> {
        self.read_json(PREVIOUS_DEPLOYED)
    }

    /// Saves what a rollback puts back with [`Self::set_deployed`] or
    /// [`Self::clear_deployed`].
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_previous_deployed(&self, deployed: Option<&Deployed>) -> Result<(), StateError> {
        self.write_json(PREVIOUS_DEPLOYED, &deployed)
    }

    /// The previous override file's bytes, if one was saved.
    ///
    /// # Errors
    ///
    /// [`StateError::Io`] if it exists and cannot be read.
    pub fn previous_override(&self) -> Result<Option<Vec<u8>>, StateError> {
        let path = self.dir.join(PREVIOUS_OVERRIDE);
        match fs::read(&path) {
            Ok(bytes) => Ok(Some(bytes)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(io_err("read", &path)(e)),
        }
    }

    /// Saves the previous override's bytes.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn set_previous_override(&self, bytes: &[u8]) -> Result<(), StateError> {
        write_atomic(&self.dir, PREVIOUS_OVERRIDE, bytes)
    }

    /// Writes a deploy report as `reports/<id>.json`.
    ///
    /// # Errors
    ///
    /// [`StateError::InvalidReportId`] if `id` is not a plain name, or
    /// [`StateError`] if the write fails.
    pub fn write_report<R: Serialize>(&self, id: &str, report: &R) -> Result<(), StateError> {
        let valid = (1..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(StateError::InvalidReportId(id.to_owned()));
        }
        let dir = self.dir.join(REPORTS);
        create_private(&self.dir, &dir)?;
        let name = format!("{id}.json");
        let bytes = serde_json::to_vec_pretty(report).map_err(|source| StateError::Serialise {
            path: dir.join(&name),
            source,
        })?;
        write_atomic(&dir, &name, &bytes)
    }

    /// Where this deployment's backups live. The directory is not created.
    #[must_use]
    pub fn backups_dir(&self) -> PathBuf {
        self.dir.join(BACKUPS)
    }

    fn remove(&self, name: &str) -> Result<(), StateError> {
        remove_in(&self.dir, name)
    }

    fn read_json<T: DeserializeOwned>(&self, name: &str) -> Result<Option<T>, StateError> {
        let path = self.dir.join(name);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(io_err("read", &path)(e)),
        };
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|source| StateError::Corrupt { path, source })
    }

    fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StateError> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|source| StateError::Serialise {
            path: self.dir.join(name),
            source,
        })?;
        write_atomic(&self.dir, name, &bytes)
    }
}

/// Temporary file, `fsync`, rename, directory `fsync`.
fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
    let tmp = dir.join(format!(".{name}.tmp"));
    let target = dir.join(name);
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .map_err(io_err("create", &tmp))?;
    file.write_all(bytes).map_err(io_err("write", &tmp))?;
    file.sync_all().map_err(io_err("sync", &tmp))?;
    drop(file);
    fs::rename(&tmp, &target).map_err(io_err("rename", &target))?;
    sync_dir(dir)
}

fn sync_dir(dir: &Path) -> Result<(), StateError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_err("sync", dir))
}

#[cfg(test)]
mod tests {
    use std::fs::Permissions;
    use std::os::unix::fs::PermissionsExt;

    use super::*;

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

    fn state(tmp: &tempfile::TempDir) -> DeploymentState {
        StateDir::open(tmp.path())
            .unwrap()
            .deployment(&id("example/prod"))
            .unwrap()
    }

    #[test]
    fn state_dir_must_not_be_group_writable() {
        let tmp = tempfile::tempdir().unwrap();
        fs::set_permissions(tmp.path(), Permissions::from_mode(0o770)).unwrap();
        let err = StateDir::open(tmp.path()).unwrap_err();
        assert!(matches!(err, StateError::Writable { .. }), "{err}");
        fs::set_permissions(tmp.path(), Permissions::from_mode(0o702)).unwrap();
        assert!(matches!(
            StateDir::open(tmp.path()).unwrap_err(),
            StateError::Writable { .. }
        ));
        fs::set_permissions(tmp.path(), Permissions::from_mode(0o750)).unwrap();
        StateDir::open(tmp.path()).unwrap();
    }

    #[test]
    fn state_dir_must_be_an_existing_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let err = StateDir::open(&tmp.path().join("missing")).unwrap_err();
        assert!(matches!(err, StateError::Io { .. }), "{err}");
        let link = tmp.path().join("link");
        std::os::unix::fs::symlink(tmp.path(), &link).unwrap();
        let err = StateDir::open(&link).unwrap_err();
        assert!(matches!(err, StateError::NotADirectory(_)), "{err}");
    }

    #[test]
    fn second_lock_is_busy() {
        let tmp = tempfile::tempdir().unwrap();
        let first = state(&tmp);
        let second = state(&tmp);
        let held = first.lock().unwrap();
        let err = second.lock().unwrap_err();
        assert!(matches!(&err, StateError::Busy(d) if *d == id("example/prod")));
        assert!(err.to_string().contains("example/prod"));
        drop(held);
        second.lock().unwrap();
    }

    #[test]
    fn deployments_get_distinct_directories() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path()).unwrap();
        dir.deployment(&id("example/prod")).unwrap();
        assert!(tmp.path().join("example__prod").is_dir());
        let other = dir.deployment(&id("example/staging")).unwrap();
        other.set_deployed(&deployed()).unwrap();
        assert_eq!(
            dir.deployment(&id("example/prod"))
                .unwrap()
                .deployed()
                .unwrap(),
            None
        );
    }

    #[test]
    fn deployed_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        assert_eq!(s.deployed().unwrap(), None);
        s.set_deployed(&deployed()).unwrap();
        assert_eq!(s.deployed().unwrap(), Some(deployed()));
        let mut newer = deployed();
        newer.version = semver::Version::new(1, 3, 0);
        s.set_deployed(&newer).unwrap();
        assert_eq!(s.deployed().unwrap(), Some(newer));
    }

    #[test]
    fn in_progress_round_trips_and_clears() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        assert_eq!(s.in_progress().unwrap(), None);
        let marker = InProgress {
            deploy_id: "2026-11-01T10-00-00-000000000Z".to_owned(),
            phase: Phase::RollingBack,
            tag: "v1.2.3".parse().unwrap(),
            digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            previous_can_start: true,
            backup: Some(RecordedBackup {
                id: "2026-11-01T10-00-00Z".to_owned(),
                paths: vec!["data".to_owned()],
            }),
            started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
        };
        s.set_in_progress(&marker).unwrap();
        assert_eq!(s.in_progress().unwrap(), Some(marker));
        s.clear_in_progress().unwrap();
        assert_eq!(s.in_progress().unwrap(), None);
        s.clear_in_progress().unwrap();
    }

    #[test]
    fn previous_deployed_tells_nothing_saved_from_nothing_deployed() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        assert_eq!(s.previous_deployed().unwrap(), None);
        s.set_previous_deployed(None).unwrap();
        assert_eq!(s.previous_deployed().unwrap(), Some(None));
        s.set_previous_deployed(Some(&deployed())).unwrap();
        assert_eq!(s.previous_deployed().unwrap(), Some(Some(deployed())));
    }

    #[test]
    fn deployed_record_clears() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        s.set_deployed(&deployed()).unwrap();
        s.clear_deployed().unwrap();
        assert_eq!(s.deployed().unwrap(), None);
        s.clear_deployed().unwrap();
    }

    #[test]
    fn corrupt_state_is_an_error_not_empty() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        for (name, content) in [
            (DEPLOYED, "not json"),
            (DEPLOYED, ""),
            (DEPLOYED, r#"{"tag":"v1.2.3","surprise":1}"#),
            (IN_PROGRESS, "{"),
        ] {
            fs::write(tmp.path().join("example__prod").join(name), content).unwrap();
            let err = if name == DEPLOYED {
                s.deployed().unwrap_err()
            } else {
                s.in_progress().unwrap_err()
            };
            assert!(
                matches!(&err, StateError::Corrupt { path, .. } if path.ends_with(name)),
                "{content}: {err}"
            );
            assert!(err.to_string().contains(name), "{err}");
        }
    }

    #[test]
    fn deployment_directory_that_is_a_symlink_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), tmp.path().join("example__prod")).unwrap();
        let err = StateDir::open(tmp.path())
            .unwrap()
            .deployment(&id("example/prod"))
            .unwrap_err();
        assert!(matches!(err, StateError::NotADirectory(_)), "{err}");
    }

    #[test]
    fn deployment_directory_with_a_loose_mode_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = tmp.path().join("example__prod");
        fs::create_dir(&dir).unwrap();
        for loose in [0o770, 0o702] {
            fs::set_permissions(&dir, Permissions::from_mode(loose)).unwrap();
            let err = StateDir::open(tmp.path())
                .unwrap()
                .deployment(&id("example/prod"))
                .unwrap_err();
            assert!(matches!(err, StateError::Writable { .. }), "{err}");
        }
    }

    #[test]
    fn a_failed_write_keeps_the_old_content() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        s.set_deployed(&deployed()).unwrap();
        // A directory where the temporary file goes fails the write whoever
        // runs this; permissions would not stop root.
        fs::create_dir(tmp.path().join("example__prod").join(".deployed.json.tmp")).unwrap();

        let mut newer = deployed();
        newer.version = semver::Version::new(9, 9, 9);
        let err = s.set_deployed(&newer).unwrap_err();

        assert!(matches!(err, StateError::Io { .. }), "{err}");
        assert_eq!(s.deployed().unwrap(), Some(deployed()));
    }

    #[test]
    fn previous_override_round_trips_bytes() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        assert_eq!(s.previous_override().unwrap(), None);
        s.set_previous_override(b"services: {}\n").unwrap();
        assert_eq!(
            s.previous_override().unwrap().as_deref(),
            Some(&b"services: {}\n"[..])
        );
    }

    #[test]
    fn reports_are_written_under_a_validated_id() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        s.write_report(
            "2026-11-01T10-00-00Z",
            &serde_json::json!({"outcome": "ok"}),
        )
        .unwrap();
        let written = fs::read_to_string(
            tmp.path()
                .join("example__prod/reports/2026-11-01T10-00-00Z.json"),
        )
        .unwrap();
        assert!(written.contains("\"outcome\""));
        for bad in ["", "../x", "a/b", ".hidden", "a b"] {
            let err = s.write_report(bad, &serde_json::json!({})).unwrap_err();
            assert!(matches!(err, StateError::InvalidReportId(_)), "{bad}");
        }
    }

    fn body(id: u64) -> DeployReportBody {
        DeployReportBody {
            deploy_id: DeployId(id),
            outcome: landfall_core::protocol::ReportedOutcome::Deployed {},
            steps: Vec::new(),
        }
    }

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
        dir.lock_daemon().unwrap();
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

    fn finished_entry(id: u64) -> FinishedDeploy {
        FinishedDeploy {
            deployment: self::id("example/prod"),
            tag: "v1.2.3".parse().unwrap(),
            digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            report: body(id),
        }
    }

    #[test]
    fn the_ledger_evicts_the_longest_on_record_whatever_the_numbers() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path()).unwrap();
        assert_eq!(dir.finished(DeployId(1)).unwrap(), None);
        // A full ledger, written directly as a thousand synced writes are slow. A
        // very high number came first: by number it would be the last to go.
        dir.finished_put(&finished_entry(u64::MAX)).unwrap();
        dir.finished_put(&finished_entry(u64::MAX - 1)).unwrap();
        let ledger = tmp.path().join(FINISHED);
        let mut order = vec![u64::MAX, u64::MAX - 1];
        for id in 1..=u64::try_from(FINISHED_KEPT - 2).unwrap() {
            let entry = serde_json::to_vec(&finished_entry(id)).unwrap();
            fs::write(ledger.join(format!("{id}.json")), entry).unwrap();
            order.push(id);
        }
        write_order(&ledger, &order).unwrap();

        dir.finished_put(&finished_entry(5000)).unwrap();

        assert_eq!(dir.finished(DeployId(u64::MAX)).unwrap(), None);
        assert!(dir.finished(DeployId(u64::MAX - 1)).unwrap().is_some());
        assert!(dir.finished(DeployId(1)).unwrap().is_some());
        assert!(dir.finished(DeployId(5000)).unwrap().is_some());
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
        again.tag = "v9.9.9".parse().unwrap();
        dir.finished_put(&again).unwrap();
        assert_eq!(dir.finished(DeployId(1)).unwrap(), Some(first));
    }

    #[test]
    fn a_lost_order_is_rebuilt_from_what_is_on_record() {
        let tmp = tempfile::tempdir().unwrap();
        let dir = StateDir::open(tmp.path()).unwrap();
        dir.finished_put(&finished_entry(5)).unwrap();
        fs::write(tmp.path().join(FINISHED).join(FINISHED_ORDER), "{").unwrap();
        dir.finished_put(&finished_entry(6)).unwrap();
        let order: Vec<u64> = serde_json::from_slice(
            &fs::read(tmp.path().join(FINISHED).join(FINISHED_ORDER)).unwrap(),
        )
        .unwrap();
        assert_eq!(order, [5, 6]);
        assert!(dir.finished(DeployId(5)).unwrap().is_some());
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
}
