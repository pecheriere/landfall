//! What is refused with no connection made.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::{CODE, CONFIG, FakeConfirm, FakeRemote, FakeSource, Files, error_of, run, run_plainly};
use crate::host::install::InstallArgs;
use crate::host::ssh::SshError;
use crate::host::{HostError, remote_for, source_for};

#[test]
fn no_signers_refuses_before_connecting() {
    let files = Files::new();
    for dry_run in [false, true] {
        let remote = FakeRemote::new();
        let source = FakeSource {
            not_ready: true,
            ..FakeSource::new()
        };
        let args = InstallArgs {
            dry_run,
            ..files.args()
        };

        let error = error_of(run(
            &args,
            &source,
            &remote,
            &mut FakeConfirm::no_terminal(),
        ));

        assert_eq!(remote.calls(), Vec::new());
        assert!(
            error.to_string().contains("trusts no release-signing key"),
            "{error}"
        );
        assert_eq!(error.exit_code(), 2);
    }
}

/// The code isn't in any error, whatever went wrong with its file.
#[test]
fn a_bad_code_file_says_nothing_of_what_it_holds() {
    let files = Files::new();
    let secret = "not-a-code-but-still-secret";
    fs::write(files.path("code"), secret).unwrap();
    let remote = FakeRemote::new();

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::CodeInvalid(_)), "{error:?}");
    assert!(!error.to_string().contains(secret));
    assert!(!format!("{error:?}").contains(secret));
    assert_eq!(error.exit_code(), 2);
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn a_linked_code_file_is_refused() {
    let files = Files::new();
    let remote = FakeRemote::new();
    symlink(files.path("code"), files.path("link")).unwrap();
    let args = InstallArgs {
        code_file: Some(files.path("link")),
        ..files.args()
    };

    let error = error_of(run_plainly(&args, &remote));

    assert!(matches!(error, HostError::CodeNotRegular(_)), "{error:?}");
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn a_code_file_that_is_a_directory_or_missing_is_refused() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        code_file: Some(files.dir.path().to_owned()),
        ..files.args()
    };
    let error = error_of(run_plainly(&args, &remote));
    assert!(matches!(error, HostError::CodeNotRegular(_)), "{error:?}");

    let args = InstallArgs {
        code_file: Some(files.path("gone")),
        ..files.args()
    };
    let error = error_of(run_plainly(&args, &remote));
    assert!(matches!(error, HostError::CodeFile { .. }), "{error:?}");
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn a_host_with_no_deployment_is_refused_without_connecting() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        host: "home-2".parse().unwrap(),
        ..files.args()
    };

    let error = error_of(run_plainly(&args, &remote));

    assert!(matches!(error, HostError::NoDeployment { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn bad_controller_url_is_refused_without_connecting() {
    let files = Files::new();
    let remote = FakeRemote::new();
    for controller in [
        "not a url",
        "http://controller.example",
        "http://127.0.0.1:8080",
    ] {
        let args = InstallArgs {
            controller: controller.to_owned(),
            ..files.args()
        };

        let error = error_of(run_plainly(&args, &remote));

        assert!(matches!(error, HostError::Controller(_)), "{error:?}");
        assert_eq!(error.exit_code(), 2);
    }
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn unsafe_compose_path_is_refused_without_connecting() {
    let files = Files::new();
    fs::write(
        files.path("fleet.toml"),
        CONFIG.replace("/srv/compose/other", "/srv/compose/with space"),
    )
    .unwrap();
    let remote = FakeRemote::new();

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::UnsafePath(_)), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    assert_eq!(remote.calls(), Vec::new());
}

#[test]
fn a_bad_destination_or_configuration_is_refused_without_connecting() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let args = InstallArgs {
        dest: "-oProxyCommand=x".to_owned(),
        ..files.args()
    };
    let error = error_of(run_plainly(&args, &remote));
    assert!(matches!(error, HostError::Ssh(SshError::BadDestination(_))));
    assert_eq!(error.exit_code(), 2);

    let args = InstallArgs {
        config: files.path("gone"),
        ..files.args()
    };
    let error = error_of(run_plainly(&args, &remote));
    assert!(matches!(error, HostError::ReadConfig { .. }), "{error:?}");

    fs::write(files.path("fleet.toml"), "not = [valid").unwrap();
    let error = error_of(run_plainly(&files.args(), &remote));
    assert!(matches!(error, HostError::Config { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 2);

    assert_eq!(remote.calls(), Vec::new());
}

/// With a tag not given, it's this build's, whichever version that is. A development build won't
/// guess.
#[test]
fn the_tag_defaults_to_this_builds_own() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let source = FakeSource::new();
    let args = InstallArgs {
        tag: None,
        ..files.args()
    };

    let ran = run(&args, &source, &remote, &mut FakeConfirm::no_terminal());

    let version = env!("CARGO_PKG_VERSION");
    if version == "0.0.0" {
        let error = error_of(ran);
        assert!(error.to_string().contains("--tag"), "{error}");
        assert_eq!(error.exit_code(), 2);
        assert_eq!(remote.calls(), Vec::new());
    } else {
        assert!(ran.result.is_ok());
        let tag = source.asked_tag.borrow().clone().unwrap();
        assert_eq!(tag.as_ref(), format!("v{version}"));
    }
}

/// It's cut off at what a code could be, with the code past that.
#[test]
fn a_code_file_is_only_read_so_far() {
    let files = Files::new();
    fs::write(files.path("code"), format!("{}{CODE}", " ".repeat(8192))).unwrap();
    let remote = FakeRemote::new();

    let error = error_of(run_plainly(&files.args(), &remote));

    assert!(matches!(error, HostError::CodeInvalid(_)), "{error:?}");
}

#[test]
fn a_code_file_others_can_read_is_said_and_does_not_stop_it() {
    let files = Files::new();
    let warning = "others can read the enrolment code's file";
    for (mode, warned) in [(0o600, false), (0o400, false), (0o640, true), (0o644, true)] {
        fs::set_permissions(files.path("code"), fs::Permissions::from_mode(mode)).unwrap();
        let ran = run_plainly(&files.args(), &FakeRemote::new());
        assert!(ran.result.is_ok());
        assert_eq!(ran.out.contains(warning), warned, "{mode:o}");
    }
}

/// `--ssh-config` and `--cache-dir` reach what they're for, on the way a real run goes.
#[test]
fn what_a_real_run_uses_is_what_was_asked() {
    let files = Files::new();
    let args = InstallArgs {
        ssh_config: Some(files.path("the-ssh-config")),
        cache_dir: Some(files.path("the-cache")),
        ..files.args()
    };
    let remote = remote_for(&args.dest, args.ssh_config.as_ref()).unwrap();
    assert_eq!(
        remote.config(),
        Some(files.path("the-ssh-config").as_path())
    );
    assert!(
        format!("{:?}", source_for(args.cache_dir.as_ref())).contains("the-cache"),
        "{:?}",
        source_for(args.cache_dir.as_ref())
    );
}
