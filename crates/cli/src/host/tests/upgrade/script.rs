//! An upgrade's script, in the sandbox.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::super::plan::{
    AGENT, AGENT_PATH, CONFIG_PATH, KEY_PATH, MARKER, RECOVER_PATH, UNIT_PATH, UPLOAD,
    assert_status, exists, place, read, sandbox,
};
use super::super::{Sandbox, stderr, stdout};
use super::AGENT_PREVIOUS;
use crate::agent_release::sha256_hex as hash;
use crate::host::plan::{Step, Timing, UPLOAD_AGENT, UpgradeRequest, render, upgrade_steps};

/// The script itself, from here.
fn script_for(sha256: &str) -> String {
    render(&upgrade_steps(&UpgradeRequest {
        sha256,
        upload: UPLOAD,
        timing: Timing {
            stable_secs: 1,
            give_up_secs: 3,
        },
        only_if_none_there: false,
    }))
}

/// A sandbox with an old agent, a unit, a key and a config, and the agent's upload.
pub(super) fn installed() -> Sandbox {
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
        only_if_none_there: false,
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

/// What's still the old id isn't the new agent, whatever state it's in.
#[test]
fn the_same_invocation_is_not_a_new_agent() {
    let sandbox = installed();
    sandbox.set_states(&[("active", "old", 0)]);

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("isn't healthy"), "{}", stderr(&ran));
    assert!(exists(&sandbox, MARKER));
}

/// A kill while it's being kept must not leave a torn `.previous` for the way back to install.
#[test]
fn the_old_agent_is_kept_by_rename() {
    let sandbox = installed();
    let previous = sandbox.path(AGENT_PREVIOUS);
    sandbox.stub(
        "mv",
        &format!(
            r#"for last in "$@"; do :; done
if [ "$last" = {} ]; then exit 9; fi
exec /bin/mv "$@""#,
            previous.display()
        ),
    );

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 9);
    assert!(!previous.exists());
    assert_eq!(read(&sandbox, AGENT_PATH), "the old agent");
    // Nothing has changed yet, so nothing is due, and a rerun keeps it again.
    assert!(!exists(&sandbox, MARKER));
}

/// Written through otherwise, as root.
#[test]
fn a_link_at_the_new_file_is_not_followed() {
    let sandbox = installed();
    let victim = sandbox.path("/victim");
    fs::write(&victim, "theirs").unwrap();
    symlink(&victim, sandbox.path("/usr/local/bin/.landfall-agent.new")).unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(fs::read_to_string(victim).unwrap(), "theirs");
}

/// A marker there before this run says what's on disk was never seen healthy, so the one kept
/// from before is the better way back.
#[test]
fn a_failed_upgrade_is_not_kept_as_the_way_back() {
    let sandbox = installed();
    place(&sandbox, AGENT_PREVIOUS, "the good agent", 0o755);
    fs::write(sandbox.path(MARKER), "").unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
    assert_eq!(read(&sandbox, AGENT_PREVIOUS), "the good agent");
}

/// With a marker left over and nothing kept, as after going back, what's there still gets kept:
/// something to go back to is better than nothing.
#[test]
fn with_nothing_kept_a_marker_does_not_stop_the_old_one_being_kept() {
    let sandbox = installed();
    fs::write(sandbox.path(MARKER), "").unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, AGENT_PREVIOUS), "the old agent");
}

/// Left there by whoever can write in a directory a group can.
#[test]
fn a_link_left_where_it_writes_is_not_followed() {
    let sandbox = installed();
    let victim = sandbox.path("/victim");
    fs::write(&victim, "theirs").unwrap();
    for planted in [MARKER, "/usr/local/bin/.landfall-agent.previous.new"] {
        symlink(&victim, sandbox.path(planted)).unwrap();
    }

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert_eq!(fs::read_to_string(victim).unwrap(), "theirs");
}

/// It may be an install's, stopped with its units written and no reload.
#[test]
fn a_marker_from_before_this_run_is_reloaded_for() {
    let sandbox = installed();
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    fs::write(sandbox.path(MARKER), "").unwrap();

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    let log = sandbox.log();
    let (reload, restart) = (log.find("daemon-reload"), log.find("restart --no-block"));
    assert!(reload.is_some() && reload < restart, "{log}");
}

/// Root's script looks for itself: nothing to do is nothing done.
#[test]
fn with_the_right_file_and_no_marker_nothing_restarts() {
    let sandbox = installed();
    place(&sandbox, AGENT_PATH, AGENT, 0o755);

    let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));

    assert_status(&ran, 0);
    assert!(!sandbox.log().contains("restart"), "{}", sandbox.log());
    assert!(
        stdout(&ran).contains("nothing is waiting for a restart"),
        "{}",
        stdout(&ran)
    );
}

#[test]
fn upgrade_never_mentions_the_key_config_or_units() {
    let sha256 = hash(AGENT.as_bytes());
    for step in upgrade_steps(&UpgradeRequest {
        sha256: &sha256,
        upload: UPLOAD,
        timing: Timing::default(),
        only_if_none_there: false,
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

/// The command that's printed for going back, as the script says it.
fn restore_command() -> String {
    let script = script_for(&hash(AGENT.as_bytes()));
    let (_, after) = script.split_once("to go back, as root: ").unwrap();
    let (command, _) = after.split_once("' >&2").unwrap();
    command.to_owned()
}

/// With Docker down, say, the restart fails. Cleared before that, the marker would be gone with the
/// agent not running, and a later run would say all's well.
#[test]
fn the_way_back_clears_the_marker_only_once_the_restart_has_worked() {
    let restoring = [Step {
        title: "going back".to_owned(),
        shell: format!("{}\n", restore_command()),
    }];

    let sandbox = installed();
    place(&sandbox, AGENT_PREVIOUS, "the good agent", 0o755);
    fs::write(sandbox.path(MARKER), "").unwrap();
    sandbox.stub("systemctl", "exit 1");
    let ran = sandbox.run(&render(&restoring));
    assert_status(&ran, 1);
    assert_eq!(read(&sandbox, AGENT_PATH), "the good agent");
    assert!(exists(&sandbox, MARKER));

    let sandbox = installed();
    place(&sandbox, AGENT_PREVIOUS, "the good agent", 0o755);
    fs::write(sandbox.path(MARKER), "").unwrap();
    assert_status(&sandbox.run(&render(&restoring)), 0);
    assert_eq!(read(&sandbox, AGENT_PATH), "the good agent");
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
    assert!(said.contains(".restart-pending"), "{said}");
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

    // A directory others can write to: where it goes, and where the marker goes.
    for dir in ["/usr/local/bin", "/etc/landfall"] {
        let sandbox = installed();
        fs::set_permissions(sandbox.path(dir), fs::Permissions::from_mode(0o777)).unwrap();
        let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));
        assert_status(&ran, 1);
        assert!(!sandbox.log().contains("restart"), "{dir}");
        assert_eq!(read(&sandbox, AGENT_PATH), "the old agent", "{dir}");

        let sandbox = installed();
        sandbox.set_owner(dir, "1000:0");
        let ran = sandbox.run(&script_for(&hash(AGENT.as_bytes())));
        assert_status(&ran, 1);
        assert!(!exists(&sandbox, MARKER), "{dir}");
    }
}
