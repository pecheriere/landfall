//! A compose project on a real Docker daemon, for tests.
//!
//! Compiled into both the library's unit tests (`testing.rs`) and the
//! end-to-end tests (`docker_e2e.rs`) with `#[path]`, so it depends on neither.

use std::fs;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustix::process::{Pid, Signal, kill_process_group};

/// How long removing a project may take. A daemon that hangs must not hang the
/// test run in a destructor, where a timeout in the test harness can't help.
const DOWN_LIMIT: Duration = Duration::from_secs(60);

/// A compose project with a unique name, removed on drop with its network and
/// containers (one-offs included), even when the test fails.
#[derive(Debug)]
pub struct ComposeProject {
    /// The project's name.
    pub name: String,
    path: PathBuf,
    _dir: tempfile::TempDir,
}

impl ComposeProject {
    /// Writes a project with the YAML of `services` (indented by two spaces).
    /// Services may join the network `net`, which Docker knows as
    /// `<name>-net`. The images are the caller's to pull.
    ///
    /// # Panics
    ///
    /// When any of that fails: this is test setup.
    #[must_use]
    pub fn create(services: &str) -> Self {
        // Tests start together and a clock may tick in microseconds: only the
        // counter tells them apart. The time tells this run from an earlier
        // one that had the same process id and left something behind.
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let serial = NEXT.fetch_add(1, Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("landfall-test-{}-{nanos}-{serial}", std::process::id());
        let dir = tempfile::tempdir().unwrap();
        fs::write(
            dir.path().join("compose.yaml"),
            format!("name: {name}\nservices:\n{services}networks:\n  net:\n    name: {name}-net\n"),
        )
        .unwrap();
        // Canonical, as the agent's directories are: compose labels a
        // container with the real path it ran in.
        let path = dir.path().canonicalize().unwrap();
        Self {
            name,
            path,
            _dir: dir,
        }
    }

    /// The compose directory.
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The ids of the project's containers, one-offs included.
    ///
    /// # Panics
    ///
    /// When the Docker client cannot be run.
    #[must_use]
    pub fn all_containers(&self) -> Vec<String> {
        let out = Command::new("docker")
            .args(["ps", "-a", "-q", "--no-trunc", "--filter"])
            .arg(format!("label=com.docker.compose.project={}", self.name))
            .output()
            .unwrap();
        String::from_utf8(out.stdout)
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

/// Waits up to `limit` for `child`, then kills its process group: `docker
/// compose` is a plugin the `docker` client runs.
fn wait_bounded(child: &mut Child, limit: Duration) {
    let started = Instant::now();
    while started.elapsed() < limit {
        match child.try_wait() {
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Ok(Some(_)) | Err(_) => return,
        }
    }
    let group = i32::try_from(child.id()).ok().and_then(Pid::from_raw);
    if let Some(group) = group {
        let _ = kill_process_group(group, Signal::KILL);
    }
    let _ = child.wait();
}

impl Drop for ComposeProject {
    fn drop(&mut self) {
        // By name from outside the directory, so it works whatever a test
        // left in the project's files.
        let down = Command::new("docker")
            .args(["compose", "-p", &self.name, "down"])
            .args(["--volumes", "--remove-orphans", "--timeout", "1"])
            .current_dir("/")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .process_group(0)
            .spawn();
        if let Ok(mut child) = down {
            wait_bounded(&mut child, DOWN_LIMIT);
        }
    }
}
