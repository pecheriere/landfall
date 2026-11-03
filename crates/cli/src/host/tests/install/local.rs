//! What is refused with no connection made.

use std::fs;
use std::os::unix::fs::symlink;

use super::{CONFIG, FakeConfirm, FakeRemote, FakeSource, Files, error_of, run, run_plainly};
use crate::host::HostError;
use crate::host::install::InstallArgs;
use crate::host::ssh::SshError;

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

/// With a tag not given, it's this build's: a development build won't guess.
#[test]
fn a_development_build_asks_for_a_tag() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        tag: None,
        ..files.args()
    };

    let error = error_of(run_plainly(&args, &remote));

    assert!(error.to_string().contains("--tag"), "{error}");
    assert_eq!(error.exit_code(), 2);
    assert_eq!(remote.calls(), Vec::new());
}
