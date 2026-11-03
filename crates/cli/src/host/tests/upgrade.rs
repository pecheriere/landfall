//! `host upgrade`: what it decides, what it does with fakes, and its script in the sandbox.

use std::fs;

use landfall_core::ids::ReleaseTag;
use semver::Version;

use super::install::{
    AGENT_BYTES, Call, FakeConfirm, FakeRemote, FakeSource, Fetch, fit_probe, runtime,
};
use super::plan::{AGENT, AGENT_PATH, UPLOAD, assert_status, put_upload, read};
use super::stderr;
use crate::agent_release::{Arch, VerifiedAgent, sha256_hex as hash};
use crate::host::HostError;
use crate::host::install::Outcome;
use crate::host::plan::{Timing, UpgradeRequest, render, upgrade_steps};
use crate::host::upgrade::{Decision, UpgradeArgs, decide, run_with};
use script::installed;

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

/// A version and no hash isn't an agent that's absent, and mustn't pass a downgrade.
#[test]
fn a_version_with_no_hash_is_compared_like_any_other() {
    let error = decide("landfall-agent 2.0.0", "", &wanted(), false).unwrap_err();
    assert!(matches!(error, HostError::OlderVersion { .. }), "{error:?}");
    assert_eq!(
        decide("landfall-agent 1.2.2", "", &wanted(), false).unwrap(),
        Decision::Upgrade
    );
}

/// With a failed upgrade behind it, on a host where the login can't look, and the unit cycling:
/// that isn't "on that version already". Root's script looks.
#[test]
fn the_same_bytes_where_the_login_cannot_look_run_the_script() {
    let sha256 = hash(AGENT_BYTES);
    for pending in ["unknown", ""] {
        let remote = remote_with(&[
            ("agent_version", "landfall-agent 1.2.3"),
            ("agent_sha256", &sha256),
            ("restart_pending", pending),
        ]);

        let ran = plainly(&args(), &remote);

        assert_eq!(ran.result.unwrap(), Outcome::Installed, "{pending:?}");
        assert!(remote.script().is_some(), "{pending:?}");
    }
}

/// Seen, and absent to the login: it must be absent to root as well.
#[test]
fn an_agent_the_login_saw_nothing_of_must_not_be_there_for_root() {
    let script_of = |overrides: &[(&str, &str)], allow_downgrade| {
        let remote = remote_with(overrides);
        let asked = UpgradeArgs {
            allow_downgrade,
            ..args()
        };
        let _ = plainly(&asked, &remote);
        remote.script().unwrap()
    };
    let refusal = "see it, so what version";
    let absent = [("agent_version", ""), ("agent_sha256", "")];
    assert!(script_of(&absent, false).contains(refusal));
    assert!(!script_of(&absent, true).contains(refusal));
    assert!(!script_of(&[], false).contains(refusal));

    let sandbox = installed();
    let sha256 = hash(AGENT.as_bytes());
    let script = render(&upgrade_steps(&UpgradeRequest {
        sha256: &sha256,
        upload: UPLOAD,
        timing: Timing::default(),
        only_if_none_there: true,
    }));
    let ran = sandbox.run(&script);
    assert_status(&ran, 1);
    assert!(stderr(&ran).contains(refusal), "{}", stderr(&ran));
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");

    fs::remove_file(sandbox.path(AGENT_PATH)).unwrap();
    put_upload(&sandbox);
    sandbox.set_states(&[("active", "old", 0), ("active", "new", 0)]);
    assert_status(&sandbox.run(&script), 0);
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
}

#[test]
fn a_clock_off_is_said() {
    let remote = remote_with(&[("clock", "1000")]);
    let ran = plainly(&args(), &remote);
    assert!(
        ran.out.contains("warning: the target's clock"),
        "{}",
        ran.out
    );
}

/// The tag is this build's, whichever version that is. A development build won't guess.
#[test]
fn the_tag_defaults_to_this_builds_own() {
    let remote = remote_with(&[]);
    let source = FakeSource::new();
    let asked = UpgradeArgs {
        tag: None,
        ..args()
    };

    let ran = upgrade(&asked, &source, &remote, &mut FakeConfirm::no_terminal());

    let version = env!("CARGO_PKG_VERSION");
    if version == "0.0.0" {
        let error = ran.result.unwrap_err();
        assert!(error.to_string().contains("--tag"), "{error}");
        assert_eq!(remote.calls(), Vec::new());
    } else {
        assert_eq!(ran.result.unwrap(), Outcome::Installed);
        let tag = source.asked_tag.borrow().clone().unwrap();
        assert_eq!(tag.as_ref(), format!("v{version}"));
    }
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

mod script;

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
