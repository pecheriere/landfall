//! One deployment's directory, and the lock that guards writing to it.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

use landfall_core::ids::DeploymentId;
use serde::Serialize;
use serde::de::DeserializeOwned;

use super::dir::{create_private, lock_file, read_or_set_aside, remove_in};
use super::error::io_err;
use super::{
    BACKUPS, CLAIM, ControllerClaim, DEPLOYED, Deployed, FAILED_KEPT, FAILED_RELEASES,
    FailedRelease, IN_PROGRESS, InProgress, LOCK, PREVIOUS_DEPLOYED, PREVIOUS_OVERRIDE, REPORTS,
    StateError, VERIFICATION_WAIT, VerificationWait,
};

/// The state files of one deployment. Reading needs no lock; whoever writes
/// holds [`Self::lock`].
#[derive(Debug, Clone)]
pub struct DeploymentState {
    pub(super) id: DeploymentId,
    pub(super) dir: PathBuf,
}

/// The exclusive right to deploy one deployment, held until dropped.
#[derive(Debug)]
pub struct DeployLock {
    pub(super) _file: File,
    /// The file it locks, which says whose lock it is.
    pub(super) path: PathBuf,
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

    /// Whether `lock` is this deployment's, rather than another's or the daemon's.
    #[must_use]
    pub fn is_locked_by(&self, lock: &DeployLock) -> bool {
        lock.path == self.dir.join(LOCK)
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

    /// Takes a release off the record: it has deployed since it failed. Written only if
    /// it was on it.
    ///
    /// # Errors
    ///
    /// [`StateError`] if the record can't be read or written.
    pub fn remove_failed_release(&self, release: &FailedRelease) -> Result<(), StateError> {
        let mut failed = self.failed_releases()?;
        let before = failed.len();
        failed.retain(|listed| listed != release);
        if failed.len() == before {
            return Ok(());
        }
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

    pub(super) fn write_json<T: Serialize>(&self, name: &str, value: &T) -> Result<(), StateError> {
        let bytes = serde_json::to_vec_pretty(value).map_err(|source| StateError::Serialise {
            path: self.dir.join(name),
            source,
        })?;
        write_atomic(&self.dir, name, &bytes)
    }
}

/// Temporary file, `fsync`, rename, directory `fsync`.
pub(super) fn write_atomic(dir: &Path, name: &str, bytes: &[u8]) -> Result<(), StateError> {
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

pub(super) fn sync_dir(dir: &Path) -> Result<(), StateError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(io_err("sync", dir))
}
