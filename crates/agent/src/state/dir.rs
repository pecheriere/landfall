//! The state directory as a whole: the daemon's lock, the outbox and the ledger of finished deploys.

use std::fs::{self, DirBuilder, OpenOptions, TryLockError};
use std::io;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use landfall_core::ids::{DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::protocol::{DeployId, DeployReportBody, DeployWork};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest as _, Sha256};

use super::deployment::{sync_dir, write_atomic};
use super::error::io_err;
use super::{
    CORRUPT_KEPT, DAEMON_LOCK, DeployLock, DeploymentState, FINISHED, FINISHED_KEPT,
    FINISHED_ORDER, FinishedDeploy, OUTBOX, StateError,
};
use crate::journal::{self, Priority};

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
    /// with this report if it is ever delivered again, and never runs again. A
    /// record goes by number and release: the same number naming another release
    /// has a record of its own, or none. The [`FINISHED_KEPT`] most recently added
    /// are kept, by the order they were added in and whatever their numbers: a
    /// controller can ask for as many numbers as it likes, and one that comes back
    /// after that is judged afresh, by a rule that refuses what ran or failed. A
    /// record already there keeps its report and its place.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the write fails.
    pub fn finished_put(&self, entry: &FinishedDeploy) -> Result<(), StateError> {
        let dir = self.path.join(FINISHED);
        create_private(&self.path, &dir)?;
        let key = ledger_key(
            entry.report.deploy_id,
            &entry.deployment,
            &entry.tag,
            &entry.digest,
        );
        let mut order: Vec<String> =
            read_or_set_aside(&dir.join(FINISHED_ORDER))?.unwrap_or_default();
        // Records the order doesn't name, after a crash or with the order lost,
        // count as older than what it does, lowest number first.
        let mut unlisted = Vec::new();
        for file in fs::read_dir(&dir).map_err(io_err("list", &dir))? {
            let path = file.map_err(io_err("list", &dir))?.path();
            if let Some((found, number)) = path
                .file_stem()
                .and_then(|stem| stem.to_str())
                .filter(|_| {
                    path.extension()
                        .is_some_and(|extension| extension == "json")
                })
                .and_then(|stem| Some((stem, ledger_number(stem)?)))
                && !order.iter().any(|known| known == found)
            {
                unlisted.push((number, found.to_owned()));
            }
        }
        unlisted.sort_unstable();
        let mut listed: Vec<String> = unlisted.into_iter().map(|(_, key)| key).collect();
        listed.append(&mut order);
        let mut order = listed;
        if order.contains(&key) {
            return write_order(&dir, &order);
        }
        order.push(key.clone());
        let evicted = order.len().saturating_sub(FINISHED_KEPT);
        let gone: Vec<String> = order.drain(..evicted).collect();
        write_order(&dir, &order)?;
        for old in gone {
            remove_in(&dir, &format!("{old}.json"))?;
        }
        let name = format!("{key}.json");
        let bytes = serde_json::to_vec_pretty(entry).map_err(|source| StateError::Serialise {
            path: dir.join(&name),
            source,
        })?;
        write_atomic(&dir, &name, &bytes)
    }

    /// How this work item ended, if it is on record: the same number and the same
    /// release. A record that cannot be read is set aside and counts as none.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the file cannot be read.
    pub fn finished(&self, work: &DeployWork) -> Result<Option<FinishedDeploy>, StateError> {
        let key = ledger_key(work.deploy_id, &work.deployment, &work.tag, &work.digest);
        read_or_set_aside(&self.path.join(FINISHED).join(format!("{key}.json")))
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
pub(super) fn lock_file(
    path: &Path,
    busy: impl FnOnce() -> StateError,
) -> Result<DeployLock, StateError> {
    let file = OpenOptions::new()
        .create(true)
        .truncate(false)
        .write(true)
        .mode(0o600)
        .open(path)
        .map_err(io_err("open", path))?;
    match file.try_lock() {
        Ok(()) => Ok(DeployLock {
            _file: file,
            path: path.to_owned(),
        }),
        Err(TryLockError::WouldBlock) => Err(busy()),
        Err(TryLockError::Error(e)) => Err(io_err("lock", path)(e)),
    }
}

/// The name of a ledger record: the number, then a hash of the release, which keeps
/// what a controller named out of the file name.
pub(super) fn ledger_key(
    deploy_id: DeployId,
    deployment: &DeploymentId,
    tag: &ReleaseTag,
    digest: &ImageDigest,
) -> String {
    let mut release = Sha256::new();
    for part in [deployment.as_ref(), tag.as_ref(), digest.as_ref()] {
        release.update(part.as_bytes());
        release.update([0]);
    }
    format!("{deploy_id}-{}", hex::encode(&release.finalize()[..16]))
}

/// The number in a ledger record's name, if it is the name of one.
fn ledger_number(key: &str) -> Option<u64> {
    key.split_once('-')?.0.parse().ok()
}

pub(super) fn write_order(dir: &Path, order: &[String]) -> Result<(), StateError> {
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
pub(super) fn read_or_set_aside<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, StateError> {
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
pub(super) fn create_private(parent: &Path, dir: &Path) -> Result<(), StateError> {
    match DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => sync_dir(parent),
        Err(e) if e.kind() == io::ErrorKind::AlreadyExists => Ok(()),
        Err(e) => Err(io_err("create", dir)(e)),
    }
}

/// Removes `name` from `dir`; absent is fine.
pub(super) fn remove_in(dir: &Path, name: &str) -> Result<(), StateError> {
    let path = dir.join(name);
    match fs::remove_file(&path) {
        Ok(()) => sync_dir(dir),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(io_err("remove", &path)(e)),
    }
}
