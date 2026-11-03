//! Which of this process's streams `ssh` gets, seen from a process with real ones: a test runner
//! gives its tests an empty stdin, where inheriting one can't be told from being given none. So
//! each test here runs its other half as a child of its own, with pipes.

use std::fs;
use std::io::Write as _;
use std::path::Path;
use std::process::{Command, Stdio};

use super::Fake;
use crate::host::ssh::Remote;

/// Where a half that is run as a child writes what it finds.
const FOUND: &str = "LANDFALL_TEST_STREAMS_FOUND";

/// Runs the ignored test `name` of this file as a child, with something on its stdin and its
/// stdout a pipe, and gives what it found. It does nothing unless it's run this way.
fn found_by_child(name: &str) -> String {
    let dir = tempfile::TempDir::new().unwrap();
    let found = dir.path().join("found");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            &format!("host::tests::ssh::streams::{name}"),
            "--ignored",
            "--nocapture",
        ])
        .env(FOUND, &found)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"what's piped in\n")
        .unwrap();
    let output = child.wait_with_output().unwrap();
    assert!(output.status.success(), "{output:?}");
    fs::read_to_string(found).unwrap()
}

fn found_path() -> Option<std::path::PathBuf> {
    std::env::var_os(FOUND).map(Into::into)
}

/// A master outlives this process by `ControlPersist`. Holding its stdout, it would keep
/// `landfall | tee` waiting for that long, and holding its stdin it could read what's next.
#[test]
fn a_master_holds_none_of_this_process_s_streams() {
    assert_eq!(
        found_by_child("master_streams"),
        "stdin nothing\nstdout nothing\nstderr a file\n"
    );
}

#[test]
#[ignore = "the other half of a test, which it does nothing without"]
fn master_streams() {
    let Some(found) = found_path() else {
        return;
    };
    let fake = Fake::new("exit 0");
    fake.set_master(&looks_at_streams(&found));
    fake.open().run("the command", b"").unwrap();
}

fn looks_at_streams(found: &Path) -> String {
    let found = found.display();
    format!(
        r"if [ /dev/fd/0 -ef /dev/null ]; then echo 'stdin nothing'; else echo 'stdin something'; fi >> {found}
if [ /dev/fd/1 -ef /dev/null ]; then echo 'stdout nothing' >> {found}; else echo 'stdout something' >> {found}; fi
if [ -f /dev/fd/2 ]; then echo 'stderr a file' >> {found}; else echo 'stderr something' >> {found}; fi"
    )
}

/// In a loop over hosts, what's piped in is the next host.
#[test]
fn an_unattended_script_is_given_no_input() {
    assert_eq!(found_by_child("unattended_input"), "");
}

#[test]
#[ignore = "the other half of a test, which it does nothing without"]
fn unattended_input() {
    let Some(found) = found_path() else {
        return;
    };
    let fake = Fake::new(&format!("cat > {}\nexit 0", found.display()));
    assert_eq!(fake.open().run_privileged("the script", false).unwrap(), 0);
}
