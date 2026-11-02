//! The driver against a fake `docker` script, and against a real one.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::{ContainerId, DockerCli};

mod arguments;
mod compose;
mod containers;
mod parsing;
mod processes;
mod real;

/// A fake `docker` in a temp directory.
struct Stub {
    dir: tempfile::TempDir,
}

impl Stub {
    /// Executing a file fails with `ETXTBSY` while any process holds it open
    /// for writing. A file this process writes is open in every child some
    /// other test's thread forks in that moment, from the fork until its
    /// `exec` closes it, whichever thread does the writing, and renaming the
    /// file changes nothing. So the script itself is made by `cp`, a process
    /// of its own, gone by the time it is run: no descriptor for writing to
    /// it ever exists in this one.
    fn new(body: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("script");
        fs::write(&script, format!("#!/bin/sh\n{body}\n")).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        let copied = std::process::Command::new("cp")
            .arg(&script)
            .arg(dir.path().join("docker"))
            .status()
            .unwrap();
        assert!(copied.success());
        Self { dir }
    }

    fn cli(&self) -> DockerCli {
        DockerCli::with_binary(self.dir.path().join("docker"))
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }
}

fn id() -> ContainerId {
    "0123456789ab".parse().unwrap()
}
