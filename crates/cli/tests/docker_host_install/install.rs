//! What an install does on a machine, from nothing and over what's there.

use std::panic::{AssertUnwindSafe, catch_unwind};
use std::process::Command;
use std::time::{Duration, Instant};

use landfall_cli::host::install::{InstallArgs, Outcome};
use landfall_cli::host::plan::{UPLOAD_AGENT, UPLOAD_CODE, render};
use landfall_cli::host::shell::quote;
use landfall_cli::host::ssh::{self, Remote, SshError};

use crate::harness::{
    AGENT_NEW, AGENT_PATH, CODE_PATH, CONFIG_PATH, Captured, FLEET, FixedSource, KEY_PATH, MARKER,
    RECOVER_PATH, STATE_DIR, Target, UNIT_PATH, UPLOAD, Unattended, dest_as, install_through,
    real_agent, sha256_hex, steps, upload_with_config, wait_until,
};

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_install_from_nothing_to_enrolled() {
    let target = Target::start();

    let ran = target.install(&target.args());

    ran.assert_ok();
    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert_eq!(target.unit_state(), "active");
    assert_eq!(
        target.sh_ok(&format!("stat -c '%U %a' {STATE_DIR}")).trim(),
        "landfall-agent 700"
    );
    assert_eq!(
        target.sh_ok(&format!("stat -c '%U %a' {KEY_PATH}")).trim(),
        "landfall-agent 600"
    );
    assert_eq!(
        target
            .sh_ok("getent passwd landfall-agent | cut -d: -f6,7")
            .trim(),
        "/var/lib/landfall-agent:/usr/sbin/nologin"
    );
    let audit = target.audit();
    assert!(
        audit
            .lines()
            .any(|line| line.contains("host_enrolled") && line.contains("home-1")),
        "{audit}"
    );
}

/// The real agent, as the real unit runs it, in what these containers can give: without this, a
/// container that can't do the unit's mounts could pass everything else.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_the_unit_runs_the_agent_in_its_sandbox() {
    let target = Target::start();
    target.installed();
    let pid = target.sh_ok("systemctl show -p MainPID --value landfall-agent");
    let pid = pid.trim();

    assert_eq!(
        target.sh_ok(&format!("stat -c %U /proc/{pid}")).trim(),
        "landfall-agent"
    );
    let status = target.sh_ok(&format!("cat /proc/{pid}/status"));
    assert!(status.contains("NoNewPrivs:\t1"), "{status}");
    // CAP_CHOWN, CAP_DAC_OVERRIDE, CAP_FOWNER and CAP_FSETID.
    assert!(status.contains("CapAmb:\t000000000000001b"), "{status}");
    assert!(status.contains("CapBnd:\t000000000000001b"), "{status}");
    let mounts = target.sh_ok(&format!("cat /proc/{pid}/mountinfo"));
    let options_of = |mount: &str| {
        mounts
            .lines()
            .map(|line| line.split(' ').collect::<Vec<_>>())
            .filter(|fields| fields[4] == mount)
            .map(|fields| fields[5].to_owned())
            .next_back()
            .unwrap_or_else(|| panic!("no {mount} in {mounts}"))
    };
    assert!(options_of("/").starts_with("ro"), "{mounts}");
    assert!(options_of(STATE_DIR).starts_with("rw"), "{mounts}");
    assert!(options_of("/srv/compose/app").starts_with("rw"), "{mounts}");
    assert!(options_of("/home").starts_with("ro"), "{mounts}");
    assert!(options_of("/tmp").starts_with("rw"), "{mounts}");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_install_twice_changes_nothing() {
    let target = Target::start();
    target.installed();
    let times = || {
        target.sh_ok(&format!(
            "stat -c '%n %y' {AGENT_PATH} {CONFIG_PATH} {UNIT_PATH} {RECOVER_PATH}"
        ))
    };
    let (files, key, started) = (times(), target.key(), target.main_start());

    let ran = target.install(&target.args_with_no_code());

    ran.assert_ok();
    assert_eq!(times(), files);
    assert_eq!(target.key(), key);
    assert_eq!(target.main_start(), started);
    assert_eq!(target.unit_state(), "active");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_existing_key_survives_a_new_code() {
    let target = Target::start();
    target.installed();
    let key = target.key();
    target.stop_unit();
    let args = InstallArgs {
        code_file: Some(target.code_file(true)),
        ..target.args_with_no_code()
    };

    let ran = target.install(&args);

    ran.assert_ok();
    assert_eq!(target.key(), key);
    assert_eq!(target.unit_state(), "active");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_dry_run_changes_nothing() {
    let target = Target::start();
    let listing = || {
        target.sh(
            "ls -la --time-style=full-iso /usr/local/bin /etc/landfall /etc/systemd/system /var/lib /tmp 2>&1; sha256sum /etc/passwd",
        ).stdout
    };
    let before = listing();
    let args = InstallArgs {
        dry_run: true,
        yes: false,
        ..target.args()
    };

    let ran = target.install(&args);

    ran.assert_ok();
    assert!(ran.out.contains("set -eu"), "{}", ran.out);
    assert_eq!(ran.result.unwrap(), Outcome::DryRun);
    assert_eq!(
        String::from_utf8_lossy(&listing()),
        String::from_utf8_lossy(&before)
    );
}

/// Flips a byte of the agent on its way up.
struct Tampering<R>(R);

impl<R: Remote> Remote for Tampering<R> {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<ssh::Output, SshError> {
        if command.contains("/landfall-agent'") {
            let mut flipped = stdin.to_vec();
            flipped[0] ^= 1;
            return self.0.run(command, &flipped);
        }
        self.0.run(command, stdin)
    }

    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError> {
        self.0.run_privileged(script, interactive)
    }
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_tampered_upload_is_refused() {
    let target = Target::start();
    let remote = Tampering(target.remote_as("operator"));

    let ran = install_through(
        &target.args(),
        &FixedSource::real(),
        &remote,
        &mut Unattended,
    );

    assert_eq!(ran.status(), 1, "{}", ran.error_text());
    assert!(!target.exists(AGENT_PATH));
    assert!(!target.exists(AGENT_NEW));
}

/// Swaps a file of the upload for a link to what the login can't read, just before the script runs.
struct Swapping<R> {
    inner: R,
    file: &'static str,
}

impl<R: Remote> Remote for Swapping<R> {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<ssh::Output, SshError> {
        self.inner.run(command, stdin)
    }

    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError> {
        let upload = script
            .lines()
            .find_map(|line| line.strip_prefix("upload='"))
            .unwrap()
            .trim_end_matches('\'');
        let swapped = self.inner.run(
            &format!(
                "ln -sf /etc/shadow {}",
                quote(&format!("{upload}/{}", self.file))
            ),
            b"",
        )?;
        assert_eq!(swapped.status, 0);
        self.inner.run_privileged(script, interactive)
    }
}

/// `enrol-code` is the file that shows it, having no hash: read as root, what's in `/etc/shadow`
/// would be on its way to the agent.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_symlink_in_the_upload_gains_nothing() {
    for file in [UPLOAD_AGENT, UPLOAD_CODE] {
        let target = Target::start();
        let remote = Swapping {
            inner: Captured::new(target.remote_as("operator")),
            file,
        };

        let ran = install_through(
            &target.args(),
            &FixedSource::real(),
            &remote,
            &mut Unattended,
        );

        assert_eq!(ran.status(), 1, "{file}: {}", ran.error_text());
        let said = String::from_utf8_lossy(&remote.inner.said.borrow()).into_owned();
        assert!(said.contains("Permission denied"), "{file}: {said}");
        assert!(!target.exists(CODE_PATH), "{file}");
        assert!(!target.exists(AGENT_NEW), "{file}");
        // The agent's own is refused in preflight. The code's comes after the agent is in place.
        assert_eq!(
            target
                .sh_ok(&format!("[ -e {AGENT_PATH} ] && echo there || echo gone"))
                .trim(),
            if file == UPLOAD_AGENT {
                "gone"
            } else {
                "there"
            },
            "{file}"
        );
        let shadow_root = target.sh_ok("grep ^root: /etc/shadow");
        let found = target.sh(&format!(
            "grep -rlF {} /usr/local/bin /etc/landfall /var/lib/landfall-agent /tmp",
            quote(shadow_root.trim())
        ));
        assert_eq!(String::from_utf8_lossy(&found.stdout), "", "{file}");
    }
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_changed_config_is_refused() {
    let target = Target::start();
    target.installed();
    let changed = format!("{FLEET}\n# a change\n");
    let args = InstallArgs {
        config: target.file_in_temp("changed.toml", &changed),
        ..target.args_with_no_code()
    };

    let ran = target.install_captured(&args, &FixedSource::real());

    assert_eq!(ran.status(), 1, "{}", ran.error_text());
    assert!(ran.out.contains("+# a change"), "{}", ran.out);
    assert!(ran.out.contains("--replace-config"), "{}", ran.out);
    assert_eq!(target.sh_ok(&format!("cat {CONFIG_PATH}")), FLEET);

    let args = InstallArgs {
        config: target.file_in_temp("changed.toml", &changed),
        replace_config: true,
        ..target.args_with_no_code()
    };
    target.install(&args).assert_ok();
    assert_eq!(target.sh_ok(&format!("cat {CONFIG_PATH}")), changed);
    assert_eq!(target.sh_ok(&format!("cat {CONFIG_PATH}.previous")), FLEET);
    assert_eq!(
        target
            .sh_ok(&format!("stat -c '%u:%g %a' {CONFIG_PATH}.previous"))
            .trim(),
        "0:0 644"
    );
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_changed_unit_is_refused() {
    let target = Target::start();
    target.installed();
    let unit = target.sh_ok(&format!("cat {UNIT_PATH}"));
    let changed = format!("{unit}# the host's own\n");
    target.sh_ok(&format!("printf '%s' {} > {UNIT_PATH}", quote(&changed)));

    let ran = target.install_captured(&target.args_with_no_code(), &FixedSource::real());

    assert_eq!(ran.status(), 1, "{}", ran.error_text());
    assert!(ran.out.contains("-# the host's own"), "{}", ran.out);
    assert!(ran.out.contains("--replace-unit"), "{}", ran.out);
    assert_eq!(target.sh_ok(&format!("cat {UNIT_PATH}")), changed);

    let args = InstallArgs {
        replace_unit: true,
        ..target.args_with_no_code()
    };
    let started = target.main_start();
    target.install(&args).assert_ok();
    assert_eq!(target.sh_ok(&format!("cat {UNIT_PATH}")), unit);
    assert_eq!(target.sh_ok(&format!("cat {UNIT_PATH}.previous")), changed);
    assert_ne!(target.main_start(), started, "a new unit takes effect");

    // The recover template is restarted for too, as a marker doesn't say which file it was.
    let started = target.main_start();
    let recover = target.sh_ok(&format!("cat {RECOVER_PATH}"));
    target.sh_ok(&format!(
        "printf '%s' {} > {RECOVER_PATH}",
        quote(&format!("{recover}# the host's own\n"))
    ));
    target.install(&args).assert_ok();
    assert_eq!(target.sh_ok(&format!("cat {RECOVER_PATH}")), recover);
    assert_ne!(target.main_start(), started);
}

/// The agent says what it read to the controller, which writes down a hash that isn't its own.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_replaced_config_restarts_the_agent() {
    let target = Target::start();
    target.installed();
    let started = target.main_start();
    let changed = format!("{FLEET}\n# a change\n");
    let hash = sha256_hex(changed.as_bytes());
    let args = InstallArgs {
        config: target.file_in_temp("changed.toml", &changed),
        replace_config: true,
        ..target.args_with_no_code()
    };

    target.install(&args).assert_ok();

    assert_ne!(target.main_start(), started);
    assert!(!target.exists(MARKER));
    wait_until("the agent to report the new configuration", || {
        target.audit().contains(&hash)
    });
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_interrupted_replacement_still_restarts() {
    let target = Target::start();
    target.installed();
    let started = target.main_start();
    let changed = format!("{FLEET}\n# a change\n");
    // Up to the config step, as a run that was stopped there leaves it.
    let remote = target.remote_as("operator");
    let mut steps = steps(UPLOAD, false, true);
    let hash = sha256_hex(changed.as_bytes());
    for step in &mut steps {
        step.shell = step.shell.replace(&sha256_hex(FLEET.as_bytes()), &hash);
    }
    let config_at = steps
        .iter()
        .position(|step| step.title == "config")
        .unwrap();
    upload_with_config(&remote, UPLOAD, changed.as_bytes());
    let status = remote
        .run_privileged(&render(&steps[..=config_at]), false)
        .unwrap();
    assert_eq!(status, 0);
    assert!(target.exists(MARKER));
    assert_eq!(target.main_start(), started);

    // A rerun with no flag sees no difference, and restarts all the same.
    let args = InstallArgs {
        config: target.file_in_temp("changed.toml", &changed),
        ..target.args_with_no_code()
    };
    target.install(&args).assert_ok();

    assert_ne!(target.main_start(), started);
    assert!(!target.exists(MARKER));
}

/// The fixed source's binary wraps the real one, and goes down inside the stable window.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_agent_that_crashes_after_starting_is_reported() {
    let target = Target::start();
    let source = FixedSource {
        bytes: b"#!/bin/sh\ncase \"$1\" in\n  run)\n    /usr/local/lib/landfall/landfall-agent \"$@\" &\n    sleep 1\n    exit 2\n    ;;\n  *) exec /usr/local/lib/landfall/landfall-agent \"$@\" ;;\nesac\n"
            .to_vec(),
    };
    let args = target.args();

    let ran = target.install_captured(&args, &source);

    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.out.contains("isn't healthy"), "{}", ran.out);
    assert!(ran.out.contains("landfall-agent.service"), "{}", ran.out);
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_sudo_needing_a_password_without_a_terminal_is_refused() {
    let target = Target::start();
    let args = InstallArgs {
        dest: dest_as("needs-password"),
        ..target.args()
    };

    let ran = target.install_captured(&args, &FixedSource::real());

    assert_eq!(ran.status(), 1, "{}", ran.error_text());
    assert!(ran.error_text().contains("sudo"), "{}", ran.error_text());
    assert_eq!(target.uploads_left(), "");
    assert!(!target.exists(AGENT_PATH));
    assert!(!target.exists(CONFIG_PATH));
    assert_eq!(target.sh_ok("getent passwd landfall-agent || true"), "");
}

/// What a refusal by `AppArmor` or seccomp on a runner would look like: it must read well in CI's log,
/// and not wait, and leave no container. A container that stops at once, and one that stops later.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_container_that_cannot_boot_says_why() {
    for (shell, code, words) in [
        ("echo mount said no >&2; exit 32", "32", "mount said no"),
        ("sleep 2; echo died later >&2; exit 33", "33", "died later"),
    ] {
        let label = format!("landfall-test-cannot-boot={}-{code}", std::process::id());
        let start = Instant::now();

        let panicked = catch_unwind(AssertUnwindSafe(|| {
            Target::boot(&["sh", "-c", shell], &label);
        }))
        .unwrap_err();

        assert!(start.elapsed() < Duration::from_secs(60), "{shell}");
        let message = panicked.downcast_ref::<String>().unwrap();
        assert!(message.contains(&format!("exit code {code}")), "{message}");
        assert!(message.contains(words), "{message}");
        assert!(message.contains("README.md"), "{message}");
        let left = Command::new("docker")
            .args(["ps", "-aq", "--filter", &format!("label={label}")])
            .output()
            .unwrap();
        assert_eq!(String::from_utf8_lossy(&left.stdout), "", "{shell}");
    }
}

/// The real agent must be what these tests put in place, or they'd show nothing of it.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_what_is_installed_is_what_was_given() {
    let target = Target::start();
    target.installed();
    let hash = target.sh_ok(&format!("sha256sum < {AGENT_PATH}"));
    assert_eq!(
        hash.split_whitespace().next().unwrap(),
        sha256_hex(&real_agent())
    );
    // And `Captured`'s way of running a script ends the same way as the real one's.
    let remote = Captured::new(target.remote_as("operator"));
    assert_eq!(remote.run_privileged("exit 3", false).unwrap(), 3);
}
