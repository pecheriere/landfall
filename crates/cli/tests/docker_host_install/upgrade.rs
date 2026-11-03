//! `host upgrade` on a machine an install has been through. The new agent is the real one, wrapped
//! in a script that says what version it is, as a real release can't be had here.

use landfall_cli::host::HostError;
use landfall_cli::host::install::Outcome;
use landfall_cli::host::plan::{UpgradeRequest, render, upgrade_steps};
use landfall_cli::host::ssh::Remote;
use landfall_cli::host::upgrade::{UpgradeArgs, run_with};
use semver::Version;

use crate::harness::{
    AGENT_PATH, CONFIG_PATH, Captured, FixedSource, KEY_PATH, RECOVER_PATH, Ran, STATE_DIR, TIMING,
    Target, UNIT_PATH, UPLOAD, Unattended, dest_as, real_agent, runtime, sha256_hex, text,
    upload_agent, wait_until,
};

const AGENT_PREVIOUS: &str = "/usr/local/bin/landfall-agent.previous";

/// The real agent, saying it's `version`.
fn wrapped(version: &str) -> FixedSource {
    wrapped_running(
        version,
        "exec /usr/local/lib/landfall/landfall-agent \"$@\"",
    )
}

/// An agent saying it's `version`, which does `run_it` for `run`.
fn wrapped_running(version: &str, run_it: &str) -> FixedSource {
    FixedSource {
        bytes: format!(
            "#!/bin/sh\ncase \"$1\" in\n  --version) echo 'landfall-agent {version}' ;;\n  run) {run_it} ;;\n  *) exec /usr/local/lib/landfall/landfall-agent \"$@\" ;;\nesac\n"
        )
        .into_bytes(),
        version: version.parse::<Version>().unwrap(),
    }
}

fn args() -> UpgradeArgs {
    UpgradeArgs {
        dest: dest_as("operator"),
        tag: Some("v1.2.3".parse().unwrap()),
        allow_downgrade: false,
        dry_run: false,
        yes: true,
        ssh_config: None,
        cache_dir: None,
        timing: TIMING,
    }
}

/// An upgrade by real `ssh`, with what the script said in `out`.
fn upgrade(target: &Target, args: UpgradeArgs, source: &FixedSource) -> Ran {
    let args = UpgradeArgs {
        ssh_config: Some(target.ssh_config()),
        ..args
    };
    let remote = Captured::new(target.remote_as("operator"));
    let mut out = Vec::new();
    let result = run_with(
        &args,
        source,
        &remote,
        &runtime(),
        &mut out,
        &mut Unattended,
    );
    let mut said = text(&out);
    said.push_str(&text(&remote.said.borrow()));
    Ran { result, out: said }
}

fn the_rest(target: &Target) -> String {
    target.sh_ok(&format!(
        "stat -c '%n %y' {CONFIG_PATH} {UNIT_PATH} {RECOVER_PATH} {KEY_PATH}; sha256sum {CONFIG_PATH} {UNIT_PATH} {RECOVER_PATH} {KEY_PATH}"
    ))
}

fn invocation(target: &Target) -> String {
    target.sh_ok("systemctl show -p InvocationID --value landfall-agent")
}

fn agent_hash(target: &Target) -> String {
    let said = target.sh_ok(&format!("sha256sum < {AGENT_PATH}"));
    said.split_whitespace().next().unwrap().to_owned()
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_upgrade_replaces_only_the_binary() {
    let target = Target::start();
    target.installed();
    let (rest, id) = (the_rest(&target), invocation(&target));
    let source = wrapped("99.0.0");

    let ran = upgrade(&target, args(), &source);

    ran.assert_ok();
    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert_eq!(the_rest(&target), rest);
    assert_eq!(agent_hash(&target), sha256_hex(&source.bytes));
    assert_eq!(
        target
            .sh_ok(&format!("sha256sum < {AGENT_PREVIOUS}"))
            .split_whitespace()
            .next()
            .unwrap(),
        sha256_hex(&real_agent())
    );
    assert_ne!(invocation(&target), id);
    assert_eq!(target.unit_state(), "active");

    // And again is nothing.
    let id = invocation(&target);
    let ran = upgrade(&target, args(), &source);
    ran.assert_ok();
    assert_eq!(ran.result.unwrap(), Outcome::Nothing);
    assert_eq!(invocation(&target), id);
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_downgrade_is_refused_then_allowed() {
    let target = Target::start();
    target.installed();
    let newer = wrapped("99.0.0");
    upgrade(&target, args(), &newer).assert_ok();
    let older = wrapped("98.0.0");

    let ran = upgrade(&target, args(), &older);

    assert!(
        matches!(ran.result, Err(HostError::OlderVersion { .. })),
        "{}",
        ran.out
    );
    assert_eq!(ran.status(), 1);
    assert_eq!(agent_hash(&target), sha256_hex(&newer.bytes));

    let ran = upgrade(
        &target,
        UpgradeArgs {
            allow_downgrade: true,
            ..args()
        },
        &older,
    );
    ran.assert_ok();
    assert_eq!(agent_hash(&target), sha256_hex(&older.bytes));
    assert_eq!(target.unit_state(), "active");
}

/// `Restart=always` cycles it through `activating`, and never `failed`.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_upgrade_that_cannot_start_says_how_to_go_back() {
    let target = Target::start();
    target.installed();
    let broken = wrapped_running("99.0.0", "exit 2");

    let ran = upgrade(&target, args(), &broken);

    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.out.contains("isn't healthy"), "{}", ran.out);
    assert!(ran.out.contains("landfall-agent.service"), "{}", ran.out);
    let restore = ran
        .out
        .lines()
        .find_map(|line| line.strip_prefix("landfall: to go back, as root: "))
        .unwrap_or_else(|| panic!("no way back in {}", ran.out));

    target.sh_ok(restore);

    assert_eq!(agent_hash(&target), sha256_hex(&real_agent()));
    wait_until("the old agent to hold still", || {
        target.unit_state() == "active"
    });
    let id = invocation(&target);
    std::thread::sleep(std::time::Duration::from_secs(u64::from(
        TIMING.stable_secs,
    )));
    assert_eq!(invocation(&target), id);
    assert_eq!(target.unit_state(), "active");
}

/// A wrapper that takes longer than the limit to end, from `TERM`, is what a deploy in flight looks like
/// from outside. The new binary is seen starting once it ends, by a file only it writes.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_upgrade_during_a_deploy_says_it_is_finishing() {
    let target = Target::start();
    let busy = wrapped_running(
        "98.0.0",
        "trap 'sleep 15; exit 0' TERM; while :; do sleep 1; done",
    );
    let args_with_busy = target.args();
    target.install_captured(&args_with_busy, &busy).assert_ok();
    let new_ran = format!("{STATE_DIR}/the-new-one-ran");
    let new = wrapped_running(
        "99.0.0",
        &format!(": > {new_ran}; exec /usr/local/lib/landfall/landfall-agent \"$@\""),
    );

    let ran = upgrade(
        &target,
        UpgradeArgs {
            timing: landfall_cli::host::plan::Timing {
                stable_secs: 1,
                give_up_secs: 4,
            },
            ..args()
        },
        &new,
    );

    ran.assert_ok();
    assert!(ran.out.contains("a deploy is finishing"), "{}", ran.out);
    assert!(!target.exists(&new_ran), "it can't have started yet");
    wait_until("the new agent to start after the old one ends", || {
        target.exists(&new_ran)
    });
    assert_eq!(agent_hash(&target), sha256_hex(&new.bytes));
}

/// What `host install` refuses, naming this command: it has to be able to take it from there.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_upgrade_takes_a_host_that_has_lost_its_agent() {
    let target = Target::start();
    target.installed();
    let id = invocation(&target);
    target.sh_ok(&format!("rm {AGENT_PATH}"));

    let ran = target.install_captured(&target.args_with_no_code(), &FixedSource::real());
    assert_eq!(ran.status(), 1, "{}", ran.out);
    assert!(ran.out.contains("use landfall host upgrade"), "{}", ran.out);

    let source = wrapped("99.0.0");
    let ran = upgrade(&target, args(), &source);

    ran.assert_ok();
    assert!(ran.out.contains("the target has nothing"), "{}", ran.out);
    assert_eq!(agent_hash(&target), sha256_hex(&source.bytes));
    assert!(!target.exists(AGENT_PREVIOUS));
    assert_ne!(invocation(&target), id, "the old process goes");
    assert_eq!(target.unit_state(), "active");
}

/// Stopped with the new file in place and no restart: a rerun has to look past the same bytes.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_interrupted_upgrade_still_restarts() {
    let target = Target::start();
    target.installed();
    let id = invocation(&target);
    let source = wrapped("99.0.0");
    let hash = sha256_hex(&source.bytes);
    let steps = upgrade_steps(&UpgradeRequest {
        sha256: &hash,
        upload: UPLOAD,
        timing: TIMING,
        only_if_none_there: false,
    });
    let remote = target.remote_as("operator");
    upload_agent(&remote, UPLOAD, &source.bytes);
    assert_eq!(
        remote.run_privileged(&render(&steps[..2]), false).unwrap(),
        0
    );
    drop(remote);
    assert_eq!(agent_hash(&target), hash);
    assert_eq!(invocation(&target), id);

    let ran = upgrade(&target, args(), &source);

    ran.assert_ok();
    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert_ne!(invocation(&target), id);
    assert!(!target.exists("/etc/landfall/.restart-pending"));
}

/// A login that owns `/etc/landfall` has planted a link where root would write the marker.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_upgrade_writes_nothing_through_a_link_in_a_directory_not_roots() {
    let target = Target::start();
    target.installed();
    target.sh_ok("printf 12345678 > /etc/victim; chown operator /etc/landfall");
    target.sh_ok("runuser -u operator -- ln -s /etc/victim /etc/landfall/.restart-pending");
    let before = agent_hash(&target);

    let ran = upgrade(&target, args(), &wrapped("99.0.0"));

    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.out.contains("/etc/landfall has owner"), "{}", ran.out);
    assert_eq!(target.sh_ok("cat /etc/victim"), "12345678");
    assert_eq!(agent_hash(&target), before);
}

/// With a broken agent cycling, and the login unable to see the marker that says so, a rerun must
/// not call that being on the version already.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_failed_upgrade_behind_a_closed_directory_is_not_success() {
    let target = Target::start();
    target.installed();
    target.sh_ok("chgrp staff /etc/landfall; chmod 2750 /etc/landfall");
    let broken = wrapped_running("99.0.0", "exit 2");
    let ran = upgrade(&target, args(), &broken);
    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);

    let ran = upgrade(&target, args(), &broken);

    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.out.contains("isn't healthy"), "{}", ran.out);
    assert!(target.exists("/etc/landfall/.restart-pending"));
}

/// What the login can't see reads as nothing there, and root's script knows better.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_an_agent_the_login_cannot_see_is_not_taken_for_none() {
    let target = Target::start();
    target.installed();
    target.sh_ok("chgrp staff /usr/local/bin; chmod 2750 /usr/local/bin");
    let before = agent_hash(&target);

    let ran = upgrade(&target, args(), &wrapped("99.0.0"));

    assert_eq!(ran.status(), 1, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.out.contains("can't see it"), "{}", ran.out);
    assert_eq!(agent_hash(&target), before);
}
