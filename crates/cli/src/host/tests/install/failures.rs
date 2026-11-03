//! What stops it once connected, and what is left to clean up when it does.

use super::{
    FakeConfirm, FakeRemote, FakeSource, Fetch, Files, error_of, fit_probe, run, run_plainly,
};
use crate::host::install::{InstallArgs, Outcome};
use crate::host::{HostError, finished, is_yes};

/// The directory the script named, and `rm -rf` of nothing else.
fn assert_upload_removed_last(remote: &FakeRemote, upload: &str) {
    let commands = remote.commands();
    let removals: Vec<&String> = commands.iter().filter(|c| c.contains("rm -rf")).collect();
    // The one for the login's stale directories is by `find`.
    assert_eq!(removals.len(), 2, "{commands:?}");
    assert_eq!(
        *removals[1],
        format!("exec sh -c 'rm -rf -- '\\''{upload}'\\'''")
    );
    assert_eq!(commands.last(), Some(removals[1]));
}

#[test]
fn nothing_is_sent_before_verification() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let source = FakeSource {
        fetch: Fetch::Refused,
        ..FakeSource::new()
    };

    let error = error_of(run(
        &files.args(),
        &source,
        &remote,
        &mut FakeConfirm::no_terminal(),
    ));

    remote.assert_only_probed();
    assert!(matches!(error, HostError::Release(_)), "{error:?}");
}

#[test]
fn verification_failure_exits_1() {
    let files = Files::new();
    let refused = FakeSource {
        fetch: Fetch::Refused,
        ..FakeSource::new()
    };
    let error = error_of(run(
        &files.args(),
        &refused,
        &FakeRemote::new(),
        &mut FakeConfirm::no_terminal(),
    ));
    assert_eq!(error.exit_code(), 1);

    let out_of_reach = FakeSource {
        fetch: Fetch::OutOfReach,
        ..FakeSource::new()
    };
    let error = error_of(run(
        &files.args(),
        &out_of_reach,
        &FakeRemote::new(),
        &mut FakeConfirm::no_terminal(),
    ));
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn connection_failure_exits_2() {
    let files = Files::new();
    let remote = FakeRemote {
        connects: false,
        ..FakeRemote::new()
    };

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::Ssh(_)), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    remote.assert_only_probed();
}

#[test]
fn a_host_unfit_for_an_agent_is_refused_with_all_of_it() {
    let files = Files::new();
    let mut remote = FakeRemote::new();
    remote.probe = fit_probe(&[("docker_group", "0"), ("dir_exists:1", "0")]);
    let source = FakeSource::new();

    let error = error_of(run(
        &files.args(),
        &source,
        &remote,
        &mut FakeConfirm::no_terminal(),
    ));

    let text = error.to_string();
    assert!(text.contains("docker` group"), "{text}");
    assert!(text.contains("/srv/compose/other"), "{text}");
    assert_eq!(error.exit_code(), 1);
    remote.assert_only_probed();
    assert_eq!(
        source.asked_for.get(),
        None,
        "fetched for a host that can't take it"
    );
}

/// Not a probe's output, as from a login shell that couldn't run it.
#[test]
fn output_that_is_not_a_probe_is_refused() {
    let files = Files::new();
    let mut remote = FakeRemote {
        probe_stderr: "This account is not available.",
        ..FakeRemote::new()
    };
    remote.probe = "fish: Unknown command\nand more\n".to_owned();

    let error = error_of(run_plainly(&files.args(), &remote));

    let HostError::Probe { source, .. } = &error else {
        panic!("{error:?}");
    };
    assert!(source.to_string().contains("login shell"), "{error}");
    assert!(
        error.to_string().contains("This account is not available"),
        "{error}"
    );
    assert!(
        error.to_string().contains("fish: Unknown command"),
        "{error}"
    );
    assert!(!error.to_string().contains("and more"), "{error}");
    assert_eq!(error.exit_code(), 1);
    remote.assert_only_probed();
}

#[test]
fn no_terminal_without_yes_refuses() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        yes: false,
        ..files.args()
    };

    let error = error_of(run_plainly(&args, &remote));

    assert!(matches!(error, HostError::NoTerminal), "{error:?}");
    assert_eq!(error.exit_code(), 1);
    remote.assert_only_probed();
}

#[test]
fn declining_changes_nothing() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        yes: false,
        ..files.args()
    };

    let ran = run(
        &args,
        &FakeSource::new(),
        &remote,
        &mut FakeConfirm::at_a_terminal(false),
    );

    assert_eq!(ran.result.unwrap(), Outcome::Declined);
    remote.assert_only_probed();
    let declined = finished(Outcome::Declined).unwrap_err();
    assert!(matches!(declined, HostError::Declined), "{declined:?}");
    assert_eq!(declined.exit_code(), 1);
    assert!(finished(Outcome::Installed).is_ok());
    assert!(finished(Outcome::DryRun).is_ok());
}

#[test]
fn sudo_is_tried_before_the_upload_without_a_terminal() {
    let files = Files::new();
    let remote = FakeRemote {
        sudo: 1,
        ..FakeRemote::new()
    };

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::NoSudo), "{error:?}");
    assert_eq!(error.exit_code(), 1);
    let commands = remote.commands();
    assert_eq!(commands.len(), 2, "{commands:?}");
    assert!(commands[1].contains("sudo -n true"), "{commands:?}");
    assert_eq!(remote.script(), None);
}

#[test]
fn a_failed_script_removes_the_upload() {
    let files = Files::new();
    let remote = FakeRemote {
        script: Ok(1),
        ..FakeRemote::new()
    };

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::ScriptFailed(1)), "{error:?}");
    assert_eq!(error.exit_code(), 1);
    let script = remote.script().unwrap();
    let upload = script
        .lines()
        .find_map(|line| line.strip_prefix("upload='"))
        .unwrap()
        .trim_end_matches('\'');
    assert_upload_removed_last(&remote, upload);
}

#[test]
fn a_lost_connection_in_the_script_tries_to_remove_the_upload_and_exits_2() {
    let files = Files::new();
    let remote = FakeRemote {
        script: Err(()),
        ..FakeRemote::new()
    };

    let error = error_of(run_plainly(&files.args(), &remote));

    assert_eq!(error.exit_code(), 2);
    assert!(
        remote
            .commands()
            .last()
            .is_some_and(|last| last.contains("rm -rf -- ")),
        "{:?}",
        remote.commands()
    );
}

/// What's there isn't this run's: nothing goes into it, least of all the code, and it isn't
/// removed.
#[test]
fn a_directory_already_there_stops_the_upload() {
    let files = Files::new();
    let remote = FakeRemote {
        mkdir_fails: true,
        ..FakeRemote::new()
    };

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::Upload { .. }), "{error:?}");
    assert!(error.to_string().contains("File exists"), "{error}");
    assert_eq!(error.exit_code(), 2);
    assert_eq!(remote.script(), None);
    let commands = remote.commands();
    assert!(
        commands
            .last()
            .is_some_and(|last| last.contains("mkdir -m 700")),
        "{commands:?}"
    );
    assert!(
        !commands.iter().any(|c| c.contains("cat >")),
        "{commands:?}"
    );
    assert!(
        !commands.iter().any(|c| c.contains("rm -rf -- '")),
        "{commands:?}"
    );
}

#[test]
fn a_failed_upload_removes_it_and_never_runs_the_script() {
    let files = Files::new();
    for name in ["landfall-agent", "fleet.toml", "enrol-code"] {
        let remote = FakeRemote {
            fail_upload_of: Some(name),
            ..FakeRemote::new()
        };

        let error = error_of(run_plainly(&files.args(), &remote));

        assert!(matches!(error, HostError::Upload { .. }), "{error:?}");
        assert!(error.to_string().contains("No space left"), "{error}");
        assert_eq!(error.exit_code(), 2);
        assert_eq!(remote.script(), None);
        assert!(
            remote
                .commands()
                .last()
                .is_some_and(|last| last.contains("rm -rf -- ")),
            "{name}"
        );
    }
}

#[test]
fn only_a_yes_is_a_yes() {
    for answer in ["y\n", "Y\n", "yes\n", "YES\n", " y \n"] {
        assert!(is_yes(answer), "{answer:?}");
    }
    for answer in ["", "\n", "n\n", "no\n", "yep\n", "y y\n"] {
        assert!(!is_yes(answer), "{answer:?}");
    }
}
