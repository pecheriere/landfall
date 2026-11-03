//! `host upgrade`: what it decides, what it does with fakes, and its script in the sandbox.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;

use landfall_core::ids::ReleaseTag;
use semver::Version;

use super::install::{
    AGENT_BYTES, Call, FakeConfirm, FakeRemote, FakeSource, Fetch, fit_probe, runtime,
};
use super::plan::{
    AGENT, AGENT_PATH, CONFIG_PATH, KEY_PATH, MARKER, RECOVER_PATH, UNIT_PATH, UPLOAD,
    assert_status, exists, place, read, sandbox,
};
use super::{Sandbox, stderr, stdout};
use crate::agent_release::{Arch, VerifiedAgent, sha256_hex as hash};
use crate::host::HostError;
use crate::host::install::Outcome;
use crate::host::plan::{Step, Timing, UPLOAD_AGENT, UpgradeRequest, render, upgrade_steps};
use crate::host::upgrade::{Decision, UpgradeArgs, decide, run_with};

const DEST: &str = "user@host.example";
const WANTED_VERSION: &str = "1.2.3";
const OLD_HASH: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";
const AGENT_PREVIOUS: &str = "/usr/local/bin/landfall-agent.previous";

fn wanted() -> VerifiedAgent {
    VerifiedAgent::new(
        "v1.2.3".parse::<ReleaseTag>().unwrap(),
        WANTED_VERSION.parse::<Version>().unwrap(),
        Arch::Arm64,
        AGENT_BYTES.to_vec(),
        "a test's".to_owned(),
    )
}

fn args() -> UpgradeArgs {
    UpgradeArgs {
        dest: DEST.to_owned(),
        tag: Some("v1.2.3".parse().unwrap()),
        allow_downgrade: false,
        dry_run: false,
        yes: true,
        ssh_config: None,
        cache_dir: None,
        timing: Timing::default(),
    }
}

/// A fit host with an older agent.
fn remote_with(overrides: &[(&str, &str)]) -> FakeRemote {
    let mut all = vec![
        ("unit_present", "1"),
        ("agent_version", "landfall-agent 1.2.2"),
        ("agent_sha256", OLD_HASH),
    ];
    all.extend(overrides);
    // The later of a key's two rows is what counts.
    all.reverse();
    FakeRemote {
        probe: fit_probe(&all),
        ..FakeRemote::new()
    }
}

struct Ran {
    result: Result<Outcome, HostError>,
    out: String,
}

fn upgrade(
    args: &UpgradeArgs,
    source: &FakeSource,
    remote: &FakeRemote,
    confirm: &mut FakeConfirm,
) -> Ran {
    let mut out = Vec::new();
    let result = run_with(args, source, remote, &runtime(), &mut out, confirm);
    Ran {
        result,
        out: String::from_utf8(out).unwrap(),
    }
}

fn plainly(args: &UpgradeArgs, remote: &FakeRemote) -> Ran {
    upgrade(
        args,
        &FakeSource::new(),
        remote,
        &mut FakeConfirm::no_terminal(),
    )
}

#[test]
fn newer_is_an_upgrade() {
    for running in [
        "landfall-agent 1.2.2",
        "landfall-agent 0.9.0",
        "1.0.0",
        "v1.2.2",
    ] {
        assert_eq!(
            decide(running, OLD_HASH, &wanted(), false).unwrap(),
            Decision::Upgrade,
            "{running}"
        );
    }
}

#[test]
fn same_version_and_hash_does_nothing_and_runs_nothing_privileged() {
    let sha256 = hash(AGENT_BYTES);
    assert_eq!(
        decide("landfall-agent 1.2.3", &sha256, &wanted(), false).unwrap(),
        Decision::Nothing
    );

    let remote = remote_with(&[
        ("agent_version", "landfall-agent 1.2.3"),
        ("agent_sha256", &sha256),
    ]);
    let ran = plainly(&args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Nothing);
    assert_eq!(remote.script(), None);
    remote.assert_only_probed();
    assert!(ran.out.contains("already"), "{}", ran.out);
}

/// Stopped after the rename: the file's right, what runs may not be, and only the marker says so.
#[test]
fn the_same_bytes_with_a_restart_pending_still_restart() {
    let sha256 = hash(AGENT_BYTES);
    let remote = remote_with(&[
        ("agent_version", "landfall-agent 1.2.3"),
        ("agent_sha256", &sha256),
        ("restart_pending", "1"),
    ]);

    let ran = plainly(&args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(remote.script().unwrap().contains("restart --no-block"));
}

#[test]
fn same_version_with_other_bytes_needs_the_flag() {
    let error = decide("landfall-agent 1.2.3", OLD_HASH, &wanted(), false).unwrap_err();
    assert!(matches!(error, HostError::OtherBytes { .. }), "{error:?}");
    let text = error.to_string();
    assert!(text.contains(OLD_HASH), "{text}");
    assert!(text.contains(&hash(AGENT_BYTES)), "{text}");
    assert!(text.contains("--allow-downgrade"), "{text}");
    assert_eq!(error.exit_code(), 1);
    assert_eq!(
        decide("landfall-agent 1.2.3", OLD_HASH, &wanted(), true).unwrap(),
        Decision::Replace
    );
}

#[test]
fn older_is_refused_without_the_flag() {
    let error = decide("landfall-agent 1.2.4", OLD_HASH, &wanted(), false).unwrap_err();
    assert!(matches!(error, HostError::OlderVersion { .. }), "{error:?}");
    assert!(error.to_string().contains("--allow-downgrade"), "{error}");
    assert_eq!(error.exit_code(), 1);

    let remote = remote_with(&[("agent_version", "landfall-agent 2.0.0")]);
    let ran = plainly(&args(), &remote);
    assert!(matches!(ran.result, Err(HostError::OlderVersion { .. })));
    remote.assert_only_probed();
}

#[test]
fn older_passes_with_the_flag() {
    assert_eq!(
        decide("landfall-agent 1.2.4", OLD_HASH, &wanted(), true).unwrap(),
        Decision::Downgrade
    );
    let remote = remote_with(&[("agent_version", "landfall-agent 2.0.0")]);
    let upgraded = UpgradeArgs {
        allow_downgrade: true,
        ..args()
    };
    assert_eq!(
        plainly(&upgraded, &remote).result.unwrap(),
        Outcome::Installed
    );
}

#[test]
fn prerelease_orders_below_its_release() {
    assert_eq!(
        decide("landfall-agent 1.2.3-rc.1", OLD_HASH, &wanted(), false).unwrap(),
        Decision::Upgrade
    );
    let rc = VerifiedAgent::new(
        "v1.2.3-rc.1".parse::<ReleaseTag>().unwrap(),
        "1.2.3-rc.1".parse::<Version>().unwrap(),
        Arch::Arm64,
        AGENT_BYTES.to_vec(),
        "a test's".to_owned(),
    );
    assert!(matches!(
        decide("landfall-agent 1.2.3", OLD_HASH, &rc, false),
        Err(HostError::OlderVersion { .. })
    ));
}

#[test]
fn unparseable_running_version_needs_the_flag() {
    for running in ["", "landfall-agent", "nonsense 1.x", "\u{1b}[31m1.2.2"] {
        let error = decide(running, OLD_HASH, &wanted(), false).unwrap_err();
        assert!(
            matches!(error, HostError::UnknownVersion { .. }),
            "{error:?}"
        );
        assert!(!error.to_string().contains('\u{1b}'), "{error}");
        assert_eq!(
            decide(running, OLD_HASH, &wanted(), true).unwrap(),
            Decision::Replace
        );
    }
}

/// `host install` refuses this case and names `host upgrade`, so it has to be taken.
#[test]
fn an_absent_binary_is_an_upgrade() {
    assert_eq!(decide("", "", &wanted(), false).unwrap(), Decision::Upgrade);
    let remote = remote_with(&[("agent_version", ""), ("agent_sha256", "")]);
    let ran = plainly(&args(), &remote);
    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(ran.out.contains("the target has nothing"), "{}", ran.out);
}

#[test]
fn no_unit_is_refused_naming_install() {
    let remote = remote_with(&[("unit_present", "0")]);
    let source = FakeSource::new();

    let ran = upgrade(&args(), &source, &remote, &mut FakeConfirm::no_terminal());

    let error = ran.result.unwrap_err();
    assert!(matches!(error, HostError::NoUnit), "{error:?}");
    assert!(error.to_string().contains("host install"), "{error}");
    assert_eq!(error.exit_code(), 1);
    remote.assert_only_probed();
    assert_eq!(source.asked_for.get(), None);
}

#[test]
fn what_an_upgrade_does_not_need_refuses_nothing() {
    let remote = remote_with(&[
        ("docker_client", ""),
        ("compose", ""),
        ("docker_group", "0"),
        ("docker_service", "0"),
        ("ca_bundle", "0"),
        ("has_diff", "0"),
    ]);
    assert_eq!(
        plainly(&args(), &remote).result.unwrap(),
        Outcome::Installed
    );
}

#[test]
fn what_it_does_need_is_refused() {
    for (key, value) in [
        ("os", "Darwin"),
        ("has_systemctl", "0"),
        ("has_sha256sum", "0"),
        ("has_runuser", "0"),
        ("has_timeout", "0"),
        ("quote_check", ""),
        ("systemd_version", "234"),
        ("has_sudo", "0"),
    ] {
        let remote = remote_with(&[(key, value)]);
        let ran = plainly(&args(), &remote);
        assert!(matches!(ran.result, Err(HostError::Refused(_))), "{key}");
        remote.assert_only_probed();
    }
}

#[test]
fn only_the_agent_is_uploaded_then_the_script_runs() {
    let remote = remote_with(&[]);

    let ran = plainly(&args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    let uploaded = remote
        .commands()
        .iter()
        .filter(|command| command.contains("cat >"))
        .count();
    assert_eq!(uploaded, 1);
    let calls = remote.calls();
    let Call::Run { command, stdin } = &calls[calls.len() - 2] else {
        panic!("{calls:?}");
    };
    assert!(command.contains("/landfall-agent'"), "{command}");
    assert_eq!(stdin, AGENT_BYTES);
    let script = remote.script().unwrap();
    assert!(ran.out.contains(&script));
    assert!(
        ran.out
            .contains(&format!("SHA-256 is {}\n", hash(script.as_bytes())))
    );
}

#[test]
fn dry_run_changes_nothing() {
    let remote = remote_with(&[]);
    let dry = UpgradeArgs {
        dry_run: true,
        yes: false,
        ..args()
    };

    let ran = plainly(&dry, &remote);

    assert_eq!(ran.result.unwrap(), Outcome::DryRun);
    remote.assert_only_probed();
    assert!(ran.out.contains("set -eu"), "{}", ran.out);
}

#[test]
fn no_signers_refuses_before_connecting() {
    for dry_run in [false, true] {
        let remote = remote_with(&[]);
        let source = FakeSource {
            not_ready: true,
            ..FakeSource::new()
        };
        let asked = UpgradeArgs { dry_run, ..args() };

        let ran = upgrade(&asked, &source, &remote, &mut FakeConfirm::no_terminal());

        let error = ran.result.unwrap_err();
        assert!(
            error.to_string().contains("trusts no release-signing key"),
            "{error}"
        );
        assert_eq!(remote.calls(), Vec::new());
    }
}

#[test]
fn nothing_is_sent_before_verification() {
    let remote = remote_with(&[]);
    let source = FakeSource {
        fetch: Fetch::Refused,
        ..FakeSource::new()
    };

    let ran = upgrade(&args(), &source, &remote, &mut FakeConfirm::no_terminal());

    let error = ran.result.unwrap_err();
    assert_eq!(error.exit_code(), 1);
    remote.assert_only_probed();
}

#[test]
fn it_asks_and_it_tries_sudo_as_an_install_does() {
    let remote = remote_with(&[]);
    let at_terminal = UpgradeArgs {
        yes: false,
        ..args()
    };
    let ran = upgrade(
        &at_terminal,
        &FakeSource::new(),
        &remote,
        &mut FakeConfirm::at_a_terminal(false),
    );
    assert_eq!(ran.result.unwrap(), Outcome::Declined);
    remote.assert_only_probed();

    let remote = FakeRemote {
        sudo: 1,
        ..remote_with(&[])
    };
    let ran = plainly(&args(), &remote);
    assert!(matches!(ran.result, Err(HostError::NoSudo)));
    assert_eq!(remote.script(), None);
}

#[test]
fn a_failed_script_removes_the_upload() {
    let remote = FakeRemote {
        script: Ok(1),
        ..remote_with(&[])
    };

    let ran = plainly(&args(), &remote);

    assert!(matches!(ran.result, Err(HostError::ScriptFailed(1))));
    assert!(
        remote
            .commands()
            .last()
            .is_some_and(|last| last.contains("rm -rf -- '")),
        "{:?}",
        remote.commands()
    );
}

/// The script itself, from here.
fn script_for(sha256: &str) -> String {
    render(&upgrade_steps(&UpgradeRequest {
        sha256,
        upload: UPLOAD,
        timing: Timing {
            stable_secs: 1,
            give_up_secs: 3,
        },
    }))
}

/// A sandbox with an old agent, a unit, a key and a config, and the agent's upload.
fn installed() -> Sandbox {
    let sandbox = sandbox();
    place(&sandbox, AGENT_PATH, "the old agent", 0o755);
    place(&sandbox, UNIT_PATH, "the unit", 0o644);
    place(&sandbox, RECOVER_PATH, "the recover unit", 0o644);
    place(&sandbox, CONFIG_PATH, "the config", 0o644);
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();
    sandbox.set_states(&[("active", "old", 0), ("active", "new", 0)]);
    sandbox
}

/// Preflight's check doesn't stand in for the one on what is about to be installed.
#[test]
fn an_upload_changed_after_preflight_is_refused_at_its_step() {
    let sandbox = installed();
    let sha256 = hash(AGENT.as_bytes());
    let steps = upgrade_steps(&UpgradeRequest {
        sha256: &sha256,
        upload: UPLOAD,
        timing: Timing::default(),
    });
    let script = render(&[
        steps[0].clone(),
        Step {
            title: "swap".to_owned(),
            shell: format!("printf tampered > \"$upload/{UPLOAD_AGENT}\"\n"),
        },
        steps[1].clone(),
    ]);

    let ran = sandbox.run(&script);

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("SHA-256"), "{}", stderr(&ran));
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");
    assert!(!exists(&sandbox, MARKER));
}

#[test]
fn upgrade_never_mentions_the_key_config_or_units() {
    let sha256 = hash(AGENT.as_bytes());
    for step in upgrade_steps(&UpgradeRequest {
        sha256: &sha256,
        upload: UPLOAD,
        timing: Timing::default(),
    }) {
        for word in ["agent.key", "fleet.toml", "enrol", "agent_unit", "recover"] {
            assert!(!step.shell.contains(word), "{word} in {}", step.shell);
        }
        for line in step.shell.lines().filter(|line| line.contains(".service")) {
            assert_eq!(step.title, "preflight", "{line}");
            assert!(line.starts_with("[ -e "), "{line}");
        }
    }
}

#[test]
fn it_replaces_only_the_binary_keeps_the_old_one_and_restarts() {
    let sandbox = installed();
    let before = [UNIT_PATH, RECOVER_PATH, CONFIG_PATH, KEY_PATH].map(|path| read(&sandbox, path));

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
    assert_eq!(read(&sandbox, AGENT_PREVIOUS), "the old agent");
    // As it was, as `umask 077` would otherwise have it, and going back would break the unit.
    let previous_mode = fs::metadata(sandbox.path(AGENT_PREVIOUS))
        .unwrap()
        .permissions()
        .mode();
    assert_eq!(previous_mode & 0o7777, 0o755);
    assert_eq!(
        [UNIT_PATH, RECOVER_PATH, CONFIG_PATH, KEY_PATH].map(|path| read(&sandbox, path)),
        before
    );
    let log = sandbox.log();
    assert!(
        log.contains("systemctl restart --no-block landfall-agent"),
        "{log}"
    );
    for word in ["daemon-reload", "enable", "useradd", "usermod", "docker"] {
        assert!(!log.contains(word), "{word} in {log}");
    }
    assert!(!exists(&sandbox, MARKER));
    assert!(!exists(&sandbox, UPLOAD));
    assert!(!exists(&sandbox, "/usr/local/bin/.landfall-agent.new"));
    assert!(!exists(
        &sandbox,
        "/usr/local/bin/.landfall-agent.previous.new"
    ));
}

#[test]
fn an_absent_binary_is_put_in_place_with_nothing_to_keep() {
    let sandbox = installed();
    fs::remove_file(sandbox.path(AGENT_PATH)).unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
    assert!(!exists(&sandbox, AGENT_PREVIOUS));
}

/// A kill just before the rename, or just after it: the next run restarts by the marker.
#[test]
fn the_marker_is_there_and_the_old_one_kept_before_the_rename() {
    let sandbox = installed();
    let target = sandbox.path(AGENT_PATH);
    sandbox.stub(
        "mv",
        &format!(
            r#"for last in "$@"; do :; done
if [ "$last" = {} ]; then exit 9; fi
exec /bin/mv "$@""#,
            target.display()
        ),
    );

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 9);
    assert!(exists(&sandbox, MARKER));
    assert_eq!(read(&sandbox, AGENT_PREVIOUS), "the old agent");
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");
}

/// Stopped between the rename and the restart.
#[test]
fn the_right_file_with_a_marker_restarts_and_clears_it() {
    let sandbox = installed();
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    fs::write(sandbox.path(MARKER), "").unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert!(sandbox.log().contains("restart --no-block"));
    assert!(!exists(&sandbox, AGENT_PREVIOUS), "the old one isn't lost");
    assert!(!exists(&sandbox, MARKER));
}

#[test]
fn an_agent_that_does_not_come_up_says_how_to_go_back() {
    let sandbox = installed();
    sandbox.set_states(&[("active", "old", 0), ("activating", "new", 1)]);

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 1);
    let said = stderr(&ran);
    assert!(said.contains("isn't healthy"), "{said}");
    assert!(said.contains("a journal line"), "{said}");
    assert!(said.contains("to go back, as root: mv -f "), "{said}");
    assert!(said.contains("landfall-agent.previous"), "{said}");
    assert!(exists(&sandbox, MARKER));
}

#[test]
fn with_nothing_kept_there_is_no_way_back_to_offer() {
    let sandbox = installed();
    fs::remove_file(sandbox.path(AGENT_PATH)).unwrap();
    sandbox.set_states(&[("active", "old", 0), ("activating", "new", 1)]);

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 1);
    let said = stderr(&ran);
    assert!(said.contains("no earlier agent"), "{said}");
    assert!(!said.contains("mv -f "), "{said}");
}

#[test]
fn a_deploy_finishing_passes_says_so_and_keeps_the_marker() {
    let sandbox = installed();
    sandbox.set_states(&[("active", "old", 0), ("deactivating", "old", 0)]);

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert!(
        stdout(&ran).contains("a deploy is finishing"),
        "{}",
        stdout(&ran)
    );
    assert!(exists(&sandbox, MARKER));
}

#[test]
fn no_unit_is_refused_in_the_script_too() {
    let sandbox = installed();
    fs::remove_file(sandbox.path(UNIT_PATH)).unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("host install"), "{}", stderr(&ran));
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");
    assert!(!stdout(&ran).contains("step 2"), "{}", stdout(&ran));
}

#[test]
fn what_is_refused_is_refused_before_any_change() {
    // Tampered in the upload.
    let sandbox = installed();
    let ran = sandbox.run(&script_for(&hash(b"something else")));
    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("SHA-256"), "{}", stderr(&ran));
    assert!(!stdout(&ran).contains("step 2"), "{}", stdout(&ran));
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");
    assert!(!exists(&sandbox, MARKER));

    // Installed with a wrong mode, or owner: no way round them, and no advice to remove it.
    let sandbox = installed();
    place(&sandbox, AGENT_PATH, "the old agent", 0o777);
    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));
    assert_status(&ran, 1);
    assert!(
        stderr(&ran).contains("owner, group and mode"),
        "{}",
        stderr(&ran)
    );
    assert!(!stderr(&ran).contains("remove it"), "{}", stderr(&ran));

    let sandbox = installed();
    sandbox.set_owner(AGENT_PATH, "1000:0");
    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));
    assert_status(&ran, 1);

    // A directory others can write to.
    let sandbox = installed();
    fs::set_permissions(
        sandbox.path("/usr/local/bin"),
        fs::Permissions::from_mode(0o777),
    )
    .unwrap();
    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));
    assert_status(&ran, 1);
    assert!(!sandbox.log().contains("restart"));
}

#[test]
fn the_timing_given_is_the_scripts() {
    let remote = remote_with(&[]);
    let timed = UpgradeArgs {
        timing: Timing {
            stable_secs: 17,
            give_up_secs: 41,
        },
        ..args()
    };
    let _ = plainly(&timed, &remote);
    let script = remote.script().unwrap();
    assert!(script.contains("stable_secs=17\n"), "{script}");
    assert!(script.contains("give_up_secs=41\n"), "{script}");
}

#[test]
fn it_uploads_no_config_and_no_code() {
    let remote = remote_with(&[]);
    let _ = plainly(&args(), &remote);
    for command in remote.commands() {
        assert!(!command.contains("fleet.toml"), "{command}");
        assert!(!command.contains("enrol-code"), "{command}");
    }
}
