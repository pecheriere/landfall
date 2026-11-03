//! The connection: which keys it takes, what a configuration can't do to it, and how many there
//! are, seen from the target's own log and from what really comes back.

use std::process::Command;
use std::time::Duration;

use landfall_cli::host::install::InstallArgs;
use landfall_cli::host::ssh::Remote;

use crate::harness::{FixedSource, SlowYes, Target, install_through, wait_until};

/// A run that stops for its host key: exit 2, saying `words`, with nobody having logged in.
fn assert_refused_for_its_key(target: &Target, words: &str) {
    let logins = target.logins();
    let ran = target.install_captured(&target.args_with_no_code(), &FixedSource::real());
    assert_eq!(ran.status(), 2, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.error_text().contains(words), "{}", ran.error_text());
    assert_eq!(target.logins(), logins, "it got as far as logging in");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_unknown_host_key_is_refused() {
    let target = Target::start();
    std::fs::write(&target.known_hosts, "").unwrap();

    assert_refused_for_its_key(&target, "connect once by hand");

    assert_eq!(std::fs::read(&target.known_hosts).unwrap(), b"");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_changed_host_key_is_refused() {
    let target = Target::start();
    target.write_another_host_key();

    assert_refused_for_its_key(&target, "has CHANGED");
    assert_refused_for_its_key(&target, "SHA256:");

    // Whatever a config would have it shown as.
    target.write_ssh_config("FingerprintHash md5");
    assert_refused_for_its_key(&target, "SHA256:");
}

/// One test run per line, and none gets past an unknown key, whatever `-G` might say.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_config_that_turns_off_checking_is_still_refused() {
    let target = Target::start();
    std::fs::write(&target.known_hosts, "").unwrap();
    let port = target.port();
    for line in [
        "StrictHostKeyChecking no".to_owned(),
        "UserKnownHostsFile /dev/null".to_owned(),
        "NoHostAuthenticationForLocalhost yes".to_owned(),
        format!(
            "IgnoreUnknown NoHostAuthenticationForProxyCommand\nNoHostAuthenticationForProxyCommand yes\nProxyCommand nc 127.0.0.1 {port}"
        ),
        "LogLevel QUIET".to_owned(),
        "IgnoreUnknown ForkAfterAuthentication\nForkAfterAuthentication yes".to_owned(),
        "IgnoreUnknown StdinNull\nStdinNull yes".to_owned(),
        "ControlMaster yes".to_owned(),
        "IgnoreUnknown UseKeychain,SomeOptionFromTheFuture\nUseKeychain yes\nSomeOptionFromTheFuture yes".to_owned(),
    ] {
        target.write_ssh_config(&line);
        assert_refused_for_its_key(&target, "connect once by hand");
    }
}

/// What a real connection does with each: `-G` shows a setting, and not its effect. With
/// `ForkAfterAuthentication` every status read 0 while the command went on running.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_config_changes_no_status_or_stream() {
    let target = Target::start();
    for line in [
        "",
        "IgnoreUnknown ForkAfterAuthentication\nForkAfterAuthentication yes",
        "IgnoreUnknown StdinNull\nStdinNull yes",
        "IgnoreUnknown SessionType\nSessionType none",
        "ControlMaster yes",
        "ControlMaster auto",
        "IgnoreUnknown UseKeychain,SomeOptionFromTheFuture\nUseKeychain yes\nSomeOptionFromTheFuture yes",
    ] {
        target.write_ssh_config(line);
        let logins = target.logins();
        let ssh = target.remote_as("operator");

        let output = ssh.run("echo said; echo also >&2; exit 3", b"").unwrap();
        assert_eq!(output.status, 3, "{line}");
        assert_eq!(output.stdout, b"said\n", "{line}");
        assert_eq!(output.stderr, b"also\n", "{line}");

        let output = ssh.run("cat", b"what was sent").unwrap();
        assert_eq!(output.stdout, b"what was sent", "{line}");

        assert_eq!(ssh.run_privileged("exit 3", false).unwrap(), 3, "{line}");
        // It ran to its end, and wasn't left going while this went on.
        let done = "/tmp/done";
        target.sh_ok(&format!("rm -f {done}"));
        assert_eq!(
            ssh.run_privileged(&format!("sleep 1; touch {done}; exit 4"), false)
                .unwrap(),
            4,
            "{line}"
        );
        assert!(target.exists(done), "{line}");
        drop(ssh);

        // One login for all of that, the closing of it included.
        assert_eq!(target.logins(), logins + 1, "{line}");
    }
}

/// The connection goes when `ControlPersist` is up, with someone still reading the script at
/// `y/N`. What follows costs one more approval, and not one for each command.
/// The `ssh` processes on this machine for this test's connection, by its own `ssh_config`.
fn masters_of(target: &Target) -> Vec<String> {
    let found = Command::new("pgrep")
        .arg("-f")
        .arg(format!("^ssh -fNM -F {}", target.ssh_config().display()))
        .output()
        .unwrap();
    String::from_utf8_lossy(&found.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// `kill -9` of the master, which is this test's own and leaves its socket file. One more login
/// for all that follows, and nothing logged in left behind.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_master_killed_leaves_nothing_behind() {
    let target = Target::start();
    let ssh = target.remote_as("operator");
    assert_eq!(ssh.run("exit 3", b"").unwrap().status, 3);
    assert_eq!(target.logins(), 1);
    let masters = masters_of(&target);
    assert_eq!(masters.len(), 1, "{masters:?}");
    let killed = Command::new("kill")
        .args(["-9", &masters[0]])
        .status()
        .unwrap();
    assert!(killed.success());

    for status in [4, 5, 6] {
        let command = format!("exit {status}");
        assert_eq!(ssh.run(&command, b"").unwrap().status, status);
    }
    assert_eq!(ssh.run_privileged("exit 7", false).unwrap(), 7);

    assert_eq!(target.logins(), 2);
    let masters = masters_of(&target);
    assert_eq!(masters.len(), 1, "{masters:?}");
    drop(ssh);
    wait_until("the connection to end", || masters_of(&target).is_empty());
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_slow_answer_costs_one_more_connection() {
    let target = Target::start();
    let args = InstallArgs {
        yes: false,
        ..target.args()
    };
    let remote = target.remote_as("operator");
    let mut slow = SlowYes {
        pause: Duration::from_secs(70),
    };

    let ran = install_through(&args, &FixedSource::real(), &remote, &mut slow);

    ran.assert_ok();
    assert_eq!(target.unit_state(), "active");
    drop(remote);
    assert_eq!(target.logins(), 2);
}
