//! What every script has, whatever its steps: its setup, cleanup, signals and health check.

use std::fs;
use std::process::{Command, Output};
use std::time::{Duration, Instant};

use super::plan::{CODE, CODE_PATH, UPLOAD, assert_status, exists};
use super::{Sandbox, stderr, stdout};
use crate::host::plan::{Step, UPLOAD_CODE, render};
use crate::host::shell::SYSTEM_PATH;

#[test]
fn steps_print_in_order() {
    let steps = ["one", "two", "three"].map(|title| Step {
        title: title.to_owned(),
        shell: format!("echo ran-{title}\n"),
    });
    let ran = Sandbox::new().run(&render(&steps));
    assert_status(&ran, 0);
    assert_eq!(
        stdout(&ran),
        "landfall: step 1: one\nran-one\n\
         landfall: step 2: two\nran-two\n\
         landfall: step 3: three\nran-three\n"
    );
}

#[test]
fn a_title_is_quoted() {
    let steps = [Step {
        title: "it's $(echo not run)".to_owned(),
        shell: String::new(),
    }];
    let ran = Sandbox::new().run(&render(&steps));
    assert_eq!(stdout(&ran), "landfall: step 1: it's $(echo not run)\n");
}

#[test]
fn script_sets_its_own_path() {
    let script = render(&[]);
    assert!(
        script.contains(&format!("PATH={SYSTEM_PATH}\n")),
        "{script}"
    );
    assert!(script.contains("export PATH"), "{script}");
    assert_eq!(
        SYSTEM_PATH,
        "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
    );
    let position = |needle: &str| script.find(needle).unwrap();
    assert!(position("set -eu") < position("umask 077"));
    assert!(position("umask 077") < position("PATH="));
}

#[test]
fn a_failing_step_keeps_its_status_and_cleans_up() {
    let sandbox = Sandbox::new();
    fs::create_dir_all(sandbox.path(UPLOAD)).unwrap();
    let steps = [
        Step {
            title: "first".to_owned(),
            shell: format!("upload={UPLOAD}\n(exit 7)\n"),
        },
        Step {
            title: "second".to_owned(),
            shell: ": > /tmp/second\n".to_owned(),
        },
    ];

    let ran = sandbox.run(&render(&steps));

    assert_status(&ran, 7);
    assert!(!exists(&sandbox, UPLOAD));
    assert!(!exists(&sandbox, "/tmp/second"));
}

#[test]
fn cleanup_failing_does_not_change_a_success() {
    let sandbox = Sandbox::new();
    sandbox.stub("find", "exit 1");
    assert_status(&sandbox.run(&render(&[])), 0);
}

#[test]
fn an_upload_older_than_an_hour_is_removed_and_a_recent_one_kept() {
    let sandbox = Sandbox::new();
    let old = sandbox.path("/tmp/landfall-install.old");
    let recent = sandbox.path("/tmp/landfall-install.recent");
    let other = sandbox.path("/tmp/something-else");
    for path in [&old, &recent, &other] {
        fs::create_dir_all(path).unwrap();
    }
    for path in [&old, &other] {
        let touched = Command::new("touch")
            .args(["-t", "202001010000"])
            .arg(path)
            .status()
            .unwrap();
        assert!(touched.success());
    }

    assert_status(&sandbox.run(&render(&[])), 0);

    assert!(!old.exists());
    assert!(recent.exists());
    assert!(other.exists());
}

fn wait_for(path: &std::path::Path) {
    let start = Instant::now();
    while !path.exists() {
        assert!(start.elapsed() < Duration::from_secs(10), "never started");
        std::thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn a_signal_stops_the_script_and_cleans_up() {
    for signal in ["TERM", "HUP", "INT"] {
        let sandbox = Sandbox::new();
        for path in [UPLOAD, "/var/lib/landfall-agent"] {
            fs::create_dir_all(sandbox.path(path)).unwrap();
        }
        fs::write(sandbox.path(UPLOAD).join(UPLOAD_CODE), CODE).unwrap();
        fs::write(sandbox.path(CODE_PATH), CODE).unwrap();
        let leftovers = [
            "/usr/local/bin/.landfall-agent.new",
            "/etc/landfall/.fleet.toml.new",
            "/etc/systemd/system/.landfall-agent.service.new",
            "/etc/systemd/system/.landfall-agent-recover@.service.new",
            "/etc/landfall/fleet.toml.previous.new",
        ];
        for path in leftovers {
            fs::write(sandbox.path(path), "").unwrap();
        }
        let steps = [
            Step {
                title: "first".to_owned(),
                // A real sleep: the signal is taken when it ends, as the shell defers it.
                shell: format!("upload={UPLOAD}\n: > /tmp/started\n/bin/sleep 1\n"),
            },
            Step {
                title: "second".to_owned(),
                shell: ": > /tmp/second\n".to_owned(),
            },
        ];

        let child = sandbox.spawn(&render(&steps));
        wait_for(&sandbox.path("/tmp/started"));
        let sent = Command::new("kill")
            .args([format!("-{signal}"), child.id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
        let ran = child.wait_with_output().unwrap();

        assert_status(&ran, 129);
        assert!(!exists(&sandbox, "/tmp/second"), "{signal}: went on");
        assert!(!stdout(&ran).contains("step 2"), "{signal}");
        assert!(!exists(&sandbox, UPLOAD), "{signal}: upload stays");
        assert!(!exists(&sandbox, CODE_PATH), "{signal}: code stays");
        for path in leftovers {
            assert!(!exists(&sandbox, path), "{signal}: {path} stays");
        }
    }
}

/// `wait_healthy old` in the sandbox, through `rows`.
fn health(rows: &[(&str, &str, u32)]) -> (Sandbox, Output) {
    let sandbox = Sandbox::new();
    sandbox.set_states(rows);
    let steps = [Step {
        title: "health".to_owned(),
        shell: "stable_secs=1\ngive_up_secs=3\nwait_healthy old\n".to_owned(),
    }];
    let ran = sandbox.run(&render(&steps));
    (sandbox, ran)
}

#[test]
fn health_check_branches() {
    // A new id that holds still.
    let (_, ran) = health(&[("active", "new", 0)]);
    assert_status(&ran, 0);

    // Starting up first.
    let (_, ran) = health(&[("activating", "new", 0), ("active", "new", 0)]);
    assert_status(&ran, 0);

    // The same id after a restart: nothing restarted.
    let (sandbox, ran) = health(&[("active", "old", 0)]);
    assert_status(&ran, 1);
    assert!(sandbox.log().contains("journalctl"), "{}", sandbox.log());
    assert!(stdout(&ran).contains("a journal line") || stderr(&ran).contains("a journal line"));

    // Restarts rising, in the window: it crashes.
    let (sandbox, ran) = health(&[("active", "new", 0), ("active", "newer", 1)]);
    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("restart"), "{}", stderr(&ran));
    assert!(sandbox.log().contains("journalctl"), "{}", sandbox.log());

    // Restarts rising after going down in the window.
    let (_, ran) = health(&[
        ("active", "new", 0),
        ("activating", "new", 0),
        ("active", "newer", 1),
    ]);
    assert_status(&ran, 1);

    // Still starting at the limit.
    let (sandbox, ran) = health(&[("activating", "new", 0)]);
    assert_status(&ran, 1);
    assert!(sandbox.log().contains("journalctl"), "{}", sandbox.log());

    // Never up.
    let (_, ran) = health(&[("failed", "old", 0)]);
    assert_status(&ran, 1);

    // Still stopping at the limit: a deploy is finishing, and that isn't failure.
    let (sandbox, ran) = health(&[("deactivating", "old", 0)]);
    assert_status(&ran, 0);
    assert!(
        stdout(&ran).contains("a deploy is finishing"),
        "{}",
        stdout(&ran)
    );
    assert!(!sandbox.log().contains("journalctl"), "{}", sandbox.log());

    // Stopping for a while, then up on a new id.
    let (_, ran) = health(&[("deactivating", "old", 0), ("active", "new", 0)]);
    assert_status(&ran, 0);
}
