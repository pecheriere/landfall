//! The agent's own state directory: what is deployed, what is in progress,
//! the previous override and the deploy reports, per deployment.
//!
//! The directory belongs to the agent's user and is not writable by anyone
//! else, so nothing in it is hostile and plain file operations are enough.
//! Every write is a temporary file, `fsync`, rename and a directory `fsync`,
//! so a crash leaves the old content or the new, never a mix.

use std::fs::{self, DirBuilder, File, OpenOptions, TryLockError};
use std::io::{self, Write};
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

const DEPLOYED: &str = "deployed.json";
const IN_PROGRESS: &str = "in-progress.json";
const PREVIOUS_OVERRIDE: &str = "previous-override.yaml";
const LOCK: &str = "lock";
const BACKUPS: &str = "backups";
const REPORTS: &str = "reports";

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

/// A deploy that has started and not finished. While it exists, further
/// deploys of the deployment are refused.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InProgress {
    /// The release being deployed.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
    /// Whether the previous version was running when the deploy began.
    pub previous_can_start: bool,
    /// The backup taken for this deploy, if any.
    pub backup: Option<String>,
    /// When the deploy began.
    pub started_at: Timestamp,
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
    let agent = rustix::process::getuid().as_raw();
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
}

/// The state files of one deployment.
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
        let path = self.dir.join(LOCK);
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .mode(0o600)
            .open(&path)
            .map_err(io_err("open", &path))?;
        match file.try_lock() {
            Ok(()) => Ok(DeployLock { _file: file }),
            Err(TryLockError::WouldBlock) => Err(StateError::Busy(self.id.clone())),
            Err(TryLockError::Error(e)) => Err(io_err("lock", &path)(e)),
        }
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
        let path = self.dir.join(IN_PROGRESS);
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(e) => return Err(io_err("remove", &path)(e)),
        }
        sync_dir(&self.dir)
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
        match DirBuilder::new().mode(0o700).create(&dir) {
            Ok(()) => sync_dir(&self.dir)?,
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(io_err("create", &dir)(e)),
        }
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
            tag: "v1.2.3".parse().unwrap(),
            digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            previous_can_start: true,
            backup: Some("2026-11-01T10-00-00Z".to_owned()),
            started_at: "2026-11-01T10:00:00Z".parse().unwrap(),
        };
        s.set_in_progress(&marker).unwrap();
        assert_eq!(s.in_progress().unwrap(), Some(marker));
        s.clear_in_progress().unwrap();
        assert_eq!(s.in_progress().unwrap(), None);
        s.clear_in_progress().unwrap();
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

    #[test]
    fn backups_dir_is_inside_the_deployment_directory() {
        let tmp = tempfile::tempdir().unwrap();
        let s = state(&tmp);
        assert_eq!(s.backups_dir(), tmp.path().join("example__prod/backups"));
    }
}
