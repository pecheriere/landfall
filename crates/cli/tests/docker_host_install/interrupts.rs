//! A run cut off at any point: between steps, during one, and with its connection gone.

use std::path::Path;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use landfall_cli::host::install::InstallArgs;
use landfall_cli::host::plan::{Step, render};
use landfall_cli::host::shell::{privileged_command, quote};
use landfall_cli::host::ssh::{Destination, Known, Remote, Tty, args};

use crate::harness::{CODE_PATH, KEY_PATH, Target, UPLOAD, dest_as, steps, upload, wait_until};

/// Where the script says it's waiting, and its `sh`'s pid.
const SLEEPING: &str = "/tmp/script-is-sleeping";

/// What only the steps after the wait would make.
const WENT_ON: &str = "/tmp/script-went-on";

/// A script that stops with `.enrol-code` in place, for long enough to be interrupted, and would
/// go on after it: the real steps up to there, the real enrol step's first part, and a wait.
fn script_that_waits() -> String {
    let all = steps(UPLOAD, true, false);
    let mut chosen: Vec<Step> = all
        .iter()
        .take_while(|step| step.title != "binary")
        .cloned()
        .collect();
    let enrol = all.iter().find(|step| step.title == "enrol").unwrap();
    let writing: Vec<&str> = enrol
        .shell
        .lines()
        .take_while(|line| !line.contains(" enrol --controller"))
        .collect();
    let writing = writing.join("\n");
    chosen.push(Step {
        title: "the code in place".to_owned(),
        shell: format!("{writing}\necho $$ > {SLEEPING}\nsleep 6\n"),
    });
    chosen.push(Step {
        title: "the next".to_owned(),
        shell: format!(": > {WENT_ON}\n"),
    });
    render(&chosen)
}

fn pid_of_script(target: &Target) -> String {
    wait_until("the script to reach its wait", || target.exists(SLEEPING));
    target.sh_ok(&format!("cat {SLEEPING}")).trim().to_owned()
}

/// A machine that has had an install, with its unit stopped so that a code can be given.
fn installed_and_stopped(target: &Target) -> String {
    target.installed();
    target.stop_unit();
    target.key()
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_interrupted_at_every_step_converges() {
    let clean = Target::start();
    clean.installed();
    let want = clean.end_state();
    let count = steps(UPLOAD, true, false).len();
    drop(clean);

    let want = &want;
    thread::scope(|scope| {
        for first in 1..=count {
            scope.spawn(move || {
                let target = Target::start();
                let code = target.code_file(false);
                let remote = target.remote_as("operator");
                upload(&remote, UPLOAD, Some(&code));
                let script = render(&steps(UPLOAD, true, false)[..first]);
                assert_eq!(remote.run_privileged(&script, false).unwrap(), 0, "{first}");
                let key = target.exists(KEY_PATH).then(|| target.key());

                // With the code, unless it was spent, as an operator would.
                let args = if key.is_some() {
                    target.args_with_no_code()
                } else {
                    target.args()
                };
                let ran = target.install(&args);

                assert_eq!(
                    ran.status(),
                    0,
                    "{first}: {}\n{}",
                    ran.error_text(),
                    ran.out
                );
                assert_eq!(&target.end_state(), want, "after {first} steps");
                if let Some(key) = key {
                    assert_eq!(target.key(), key, "after {first} steps");
                }
            });
        }
    });
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_killed_during_a_step_cleans_up() {
    for (signal, cleans_up) in [("TERM", true), ("HUP", true), ("KILL", false)] {
        let target = Target::start();
        let key = installed_and_stopped(&target);
        let code = target.code_file(true);
        upload(&target.remote_as("operator"), UPLOAD, Some(&code));
        let script = script_that_waits();

        let status = thread::scope(|scope| {
            let running =
                scope.spawn(|| target.remote_as("operator").run_privileged(&script, false));
            let pid = pid_of_script(&target);
            assert!(target.exists(CODE_PATH), "{signal}: no code yet");
            target.sh_ok(&format!("kill -{signal} {pid}"));
            running.join().unwrap()
        });

        assert!(!target.exists(WENT_ON), "{signal}: later steps ran");
        if cleans_up {
            assert_eq!(status.unwrap(), 129, "{signal}");
            assert!(!target.exists(CODE_PATH), "{signal}: code stays");
            assert!(!target.exists(UPLOAD), "{signal}: upload stays");
        } else {
            // No trap runs: a status, or a connection taken down with it, and never 0.
            assert!(!matches!(status, Ok(0)), "{signal}: {status:?}");
            assert!(target.exists(CODE_PATH), "{signal}: gone by itself");
        }

        // The next run removes what's left, and it all comes right, with the same key.
        let args = InstallArgs {
            code_file: Some(target.code_file(true)),
            ..target.args_with_no_code()
        };
        let ran = target.install(&args);
        assert_eq!(
            ran.status(),
            0,
            "{signal}: {}\n{}",
            ran.error_text(),
            ran.out
        );
        assert_eq!(target.key(), key, "{signal}");
        assert!(!target.exists(CODE_PATH), "{signal}");
        assert!(!target.exists(UPLOAD), "{signal}");
    }
}

/// A second signal, as from someone pressing `^C` again, mustn't stop what has begun cleaning up:
/// that would leave the code behind. The stand-in `rm` holds it there long enough to be sure.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_second_signal_does_not_stop_the_cleanup() {
    let target = Target::start();
    let key = installed_and_stopped(&target);
    let code = target.code_file(true);
    upload(&target.remote_as("operator"), UPLOAD, Some(&code));
    let cleaning = "/tmp/cleaning-up";
    target.sh_ok(&format!(
        "printf '#!/bin/sh\\ntouch {cleaning}\\n/bin/sleep 2\\nexec /bin/rm \"$@\"\\n' > /usr/local/sbin/rm && chmod 0755 /usr/local/sbin/rm"
    ));
    let script = script_that_waits();

    let status = thread::scope(|scope| {
        let running = scope.spawn(|| target.remote_as("operator").run_privileged(&script, false));
        let pid = pid_of_script(&target);
        target.sh_ok(&format!("rm -f {cleaning}"));
        target.sh_ok(&format!("kill -TERM {pid}"));
        wait_until("the cleanup to start", || target.exists(cleaning));
        target.sh_ok(&format!("kill -TERM {pid}"));
        running.join().unwrap()
    });
    target.sh_ok("/bin/rm /usr/local/sbin/rm");

    assert_eq!(status.unwrap(), 129);
    assert!(!target.exists(CODE_PATH));
    assert!(!target.exists(UPLOAD));
    assert_eq!(target.key(), key);
}

/// With no terminal the target isn't told: the next thing the script says gets `SIGPIPE`.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_cut_connection_cleans_up() {
    let target = Target::start();
    installed_and_stopped(&target);
    let code = target.code_file(true);
    let remote = target.remote_as("operator");
    upload(&remote, UPLOAD, Some(&code));
    drop(remote);
    let script = script_that_waits();

    // The local `ssh` itself, to kill it.
    let known = Known::ask("ssh".as_ref()).unwrap();
    let dest = Destination::parse(&dest_as("operator")).unwrap();
    let mut ssh = Command::new("ssh")
        .args(args(
            &dest,
            Path::new("/nonexistent/landfall-no-connection"),
            Some(&target.ssh_config()),
            Tty::Never,
            &known,
            &privileged_command(&script, false),
        ))
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    pid_of_script(&target);
    assert!(target.exists(CODE_PATH));
    ssh.kill().unwrap();
    ssh.wait().unwrap();

    let start = Instant::now();
    while target.exists(CODE_PATH) || target.exists(UPLOAD) {
        assert!(start.elapsed() < Duration::from_secs(30), "still there");
        thread::sleep(Duration::from_millis(200));
    }
    assert!(!target.exists(WENT_ON));
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_nothing_secret_is_left_behind() {
    // After a success.
    let target = Target::start();
    target.installed();
    assert!(!target.exists(CODE_PATH));
    assert_eq!(target.sh("ls -d /tmp/landfall-install.*").stdout, b"");

    // After an enrolment that fails: a code it wasn't given.
    target.stop_unit();
    let bad = target.file_in_temp(
        "bad",
        "0000000000000000000000000000000000000000000000000000000000000000",
    );
    let args = InstallArgs {
        code_file: Some(bad),
        ..target.args_with_no_code()
    };
    let ran = target.install(&args);
    assert_ne!(ran.status(), 0, "{}", ran.out);
    assert!(!target.exists(CODE_PATH));
    assert_eq!(target.sh("ls -d /tmp/landfall-install.*").stdout, b"");

    // After an upload that was killed: this login's goes on the next run, and another user's once
    // it has aged, by the root script.
    let stale = "/tmp/landfall-install.stale";
    let others = "/tmp/landfall-install.others";
    let others_recent = "/tmp/landfall-install.others-recent";
    target.sh_ok(&format!(
        "runuser -u operator -- sh -c {}",
        quote(&format!(
            "mkdir -m 700 {stale} && echo code > {stale}/enrol-code"
        ))
    ));
    target.sh_ok(&format!(
        "runuser -u needs-password -- sh -c {}",
        quote(&format!("mkdir -m 700 {others} {others_recent}"))
    ));
    target.sh_ok(&format!("touch -d '2 hours ago' {others}"));

    let ran = target.install(&target.args_with_no_code());

    ran.assert_ok();
    assert!(!target.exists(stale));
    assert!(!target.exists(others));
    assert!(target.exists(others_recent));
}
