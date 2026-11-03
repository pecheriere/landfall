//! What the script refuses on a host that isn't as an install left it, and what holds at the
//! moments a kill could land, seen from stubs that look at that moment.

use std::fs;
use std::os::unix::fs::{PermissionsExt as _, symlink};
use std::process::Command;

use super::plan::{
    AGENT, AGENT_PATH, CODE_PATH, CONFIG, CONFIG_PATH, Fixture, KEY_PATH, MARKER, RECOVER,
    RECOVER_PATH, UNIT, UNIT_PATH, UPLOAD, assert_status, exists, place, put_upload, read, sandbox,
    script_of, step,
};
use super::{Sandbox, stderr, stdout, write_executable};
use crate::agent_release::sha256_hex as hash;
use crate::host::plan::{InstallRequest, Step, UPLOAD_AGENT, UPLOAD_CONFIG, install_steps, render};
use crate::host::shell::SYSTEM_PATH;

const STATE_DIR: &str = "/var/lib/landfall-agent";
const AGENT_NEW: &str = "/usr/local/bin/.landfall-agent.new";

/// Each installed file with the bytes an install would leave, and the mode.
const INSTALLED: [(&str, &str, u32); 4] = [
    (AGENT_PATH, AGENT, 0o755),
    (CONFIG_PATH, CONFIG, 0o644),
    (UNIT_PATH, UNIT, 0o644),
    (RECOVER_PATH, RECOVER, 0o644),
];

fn full_script(request: &InstallRequest<'_>) -> String {
    render(&install_steps(request))
}

/// A request that may replace what differs, so that a refusal can't be for that.
fn replacing(fixture: &Fixture) -> InstallRequest<'_> {
    InstallRequest {
        replace_config: true,
        replace_unit: true,
        ..fixture.request()
    }
}

/// The script stopped in its first step, having changed nothing but what preflight may.
fn assert_stopped_at_preflight(sandbox: &Sandbox, ran: &std::process::Output) {
    assert_status(ran, 1);
    assert!(!stdout(ran).contains("step 2"), "{}", stdout(ran));
    let log = sandbox.log();
    for word in ["useradd", "usermod", "install ", "daemon-reload", "enable"] {
        assert!(!log.contains(word), "{word} in {log}");
    }
    assert!(!exists(sandbox, MARKER));
}

#[test]
fn the_sandbox_maps_a_directory_named_by_itself() {
    let sandbox = Sandbox::new();
    let text = sandbox.text(&format!(
        "PATH={SYSTEM_PATH}\nls /usr/local/bin /etc /var/lib /tmp\n"
    ));
    let root = sandbox.path("/");
    let root = root.display().to_string();
    let root = root.trim_end_matches('/');
    assert!(
        text.ends_with(&format!(
            "\nls {root}/usr/local/bin {root}/etc {root}/var/lib {root}/tmp\n"
        )),
        "{text}"
    );
}

/// Run as it is, it would find the real `useradd` and `systemctl`.
#[test]
#[should_panic(expected = "doesn't set")]
fn the_sandbox_wont_run_a_script_with_another_path() {
    Sandbox::new().text("PATH=/usr/sbin:/usr/bin\nuseradd someone\n");
}

#[test]
fn directories_that_exist_are_left_as_they_are() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_states(&[("inactive", "", 0), ("active", "first", 0)]);

    let ran = sandbox.run(&full_script(&fixture.request()));

    assert_status(&ran, 0);
    let log = sandbox.log();
    assert!(exists(&sandbox, CONFIG_PATH), "{log}");
    assert!(!log.contains("install -d -o root"), "{log}");
}

#[test]
fn directories_that_do_not_exist_are_made() {
    let fixture = Fixture::new();
    for (dir, title) in [("/etc/landfall", "config"), ("/usr/local/bin", "binary")] {
        let sandbox = sandbox();
        fs::remove_dir_all(sandbox.path(dir)).unwrap();

        let ran = sandbox.run(&script_of(&fixture.request(), &[title]));

        assert_status(&ran, 0);
        let want = format!(
            "install -d -o root -g root -m 0755 {}\n",
            sandbox.path(dir).display()
        );
        assert!(sandbox.log().contains(&want), "{}", sandbox.log());
    }

    // The marker can come first, with a user that has yet to join the group.
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent");
    fs::remove_dir_all(sandbox.path("/etc/landfall")).unwrap();
    assert_status(&sandbox.run(&script_of(&fixture.request(), &["user"])), 0);
    assert!(exists(&sandbox, MARKER));
}

/// The first of the script's own checks to run on it, and the one a reader of the host would race.
#[test]
fn the_agent_is_roots_and_private_until_its_hash_is_checked() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    let new = sandbox.path(AGENT_NEW);
    let seen = sandbox.path("/seen");
    sandbox.before(
        "sha256sum",
        &format!(
            "ls -l {} >> {} 2>/dev/null || true",
            new.display(),
            seen.display()
        ),
    );

    let ran = sandbox.run(&script_of(&fixture.request(), &["binary"]));

    assert_status(&ran, 0);
    let seen = fs::read_to_string(seen).unwrap();
    assert_ne!(seen, "");
    for line in seen.lines() {
        assert!(line.starts_with("-rwx------"), "{line}");
    }
    let want = format!("chown root:root {}\n", new.display());
    assert!(sandbox.log().contains(&want), "{}", sandbox.log());
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
}

/// A kill just before the rename: the next run must still see that a restart is due.
#[test]
fn the_configs_marker_and_previous_are_there_before_its_rename() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, CONFIG_PATH, "# old\n", 0o644);
    sandbox.stub(
        "mv",
        &format!(
            r#"for last in "$@"; do :; done
if [ "$last" = {} ]; then exit 9; fi
exec /bin/mv "$@""#,
            sandbox.path(CONFIG_PATH).display()
        ),
    );

    let ran = sandbox.run(&script_of(&replacing(&fixture), &["config"]));

    assert_status(&ran, 9);
    assert!(exists(&sandbox, MARKER));
    assert_eq!(read(&sandbox, CONFIG_PATH), "# old\n");
    assert_eq!(
        read(&sandbox, &format!("{CONFIG_PATH}.previous")),
        "# old\n"
    );
}

/// A kill while the old file is being kept mustn't leave a host with no file at all.
#[test]
fn the_live_file_stays_while_the_previous_one_is_kept() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    for path in [CONFIG_PATH, UNIT_PATH, RECOVER_PATH] {
        place(&sandbox, path, "# old\n", 0o644);
    }
    let seen = sandbox.path("/seen");
    sandbox.stub(
        "mv",
        &format!(
            r#"for last in "$@"; do :; done
/bin/mv "$@" || exit
case "$last" in
  *.previous)
    if [ -e "${{last%.previous}}" ]; then echo live >> {seen}; else echo gone >> {seen}; fi
    ;;
esac"#,
            seen = seen.display()
        ),
    );

    let ran = sandbox.run(&script_of(&replacing(&fixture), &["config", "units"]));

    assert_status(&ran, 0);
    assert_eq!(fs::read_to_string(seen).unwrap(), "live\nlive\nlive\n");
}

#[test]
fn docker_is_asked_as_the_agents_user() {
    let fixture = Fixture::new();
    let sandbox = sandbox();

    let ran = sandbox.run(&script_of(&fixture.request(), &["docker"]));

    assert_status(&ran, 0);
    assert!(
        sandbox
            .log()
            .contains("runuser -u landfall-agent -- timeout -k 5 30 docker version\n"),
        "{}",
        sandbox.log()
    );
}

/// By its own umask, as the stub's `runuser` sets another, as a PAM session may. And by the
/// agent's user, so that a link planted there is followed with no more than it can do already.
#[test]
fn the_agents_user_writes_the_code_and_keeps_it_private() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    let seen = sandbox.path("/seen");
    write_executable(
        &sandbox.path(AGENT_PATH),
        &format!(
            "ls -l {} > {}",
            sandbox.path(CODE_PATH).display(),
            seen.display()
        ),
    );
    let sha256 = hash(&fs::read(sandbox.path(AGENT_PATH)).unwrap());
    fs::copy(
        sandbox.path(AGENT_PATH),
        sandbox.path(UPLOAD).join(UPLOAD_AGENT),
    )
    .unwrap();
    let request = InstallRequest {
        sha256: &sha256,
        ..fixture.request()
    };

    let ran = sandbox.run(&script_of(&request, &["enrol"]));

    assert_status(&ran, 0);
    let seen = fs::read_to_string(seen).unwrap();
    assert!(seen.starts_with("-rw-------"), "{seen}");
    let want = format!(
        "runuser -u landfall-agent -- sh -c umask 077 && cat > \"$1\" sh {}\n",
        sandbox.path(CODE_PATH).display()
    );
    assert!(sandbox.log().contains(&want), "{}", sandbox.log());
    assert!(!exists(&sandbox, CODE_PATH));
}

#[test]
fn a_code_that_cannot_be_read_stops_before_enrolment() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::remove_file(sandbox.path(UPLOAD).join("enrol-code")).unwrap();

    let ran = sandbox.run(&script_of(&fixture.request(), &["enrol"]));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("enrolment code"), "{}", stderr(&ran));
    assert!(!sandbox.log().contains(" enrol "), "{}", sandbox.log());
}

#[test]
fn an_upload_that_differs_is_refused_before_any_change() {
    let fixture = Fixture::new();
    for name in [UPLOAD_AGENT, UPLOAD_CONFIG] {
        // Changed, and gone.
        for remove in [false, true] {
            let sandbox = sandbox();
            let path = sandbox.path(UPLOAD).join(name);
            if remove {
                fs::remove_file(path).unwrap();
            } else {
                fs::write(path, "tampered").unwrap();
            }

            let ran = sandbox.run(&full_script(&fixture.request()));

            assert_stopped_at_preflight(&sandbox, &ran);
            assert!(stderr(&ran).contains("SHA-256"), "{}", stderr(&ran));
        }
    }
}

/// Preflight's check doesn't stand in for the one on what is about to be installed.
#[test]
fn an_upload_changed_after_preflight_is_refused_at_its_step() {
    let fixture = Fixture::new();
    for (name, title, target) in [
        (UPLOAD_AGENT, "binary", AGENT_PATH),
        (UPLOAD_CONFIG, "config", CONFIG_PATH),
    ] {
        let sandbox = sandbox();
        let steps = install_steps(&fixture.request());
        let script = render(&[
            step(&steps, "preflight").clone(),
            Step {
                title: "swap".to_owned(),
                shell: format!("printf tampered > \"$upload/{name}\"\n"),
            },
            step(&steps, title).clone(),
        ]);

        let ran = sandbox.run(&script);

        assert_status(&ran, 1);
        assert!(stdout(&ran).contains(title), "{}", stdout(&ran));
        assert!(stderr(&ran).contains("SHA-256"), "{}", stderr(&ran));
        assert!(!exists(&sandbox, target), "{target}");
        assert!(!exists(&sandbox, MARKER));
    }
}

#[test]
fn right_bytes_with_the_wrong_mode_or_owner_are_refused() {
    let fixture = Fixture::new();
    for (path, text, mode) in INSTALLED {
        for wrong_mode in [0o777, 0o666, 0o775, 0o4755, 0o600] {
            let sandbox = sandbox();
            place(&sandbox, path, text, wrong_mode);

            let ran = sandbox.run(&full_script(&replacing(&fixture)));

            assert_stopped_at_preflight(&sandbox, &ran);
            assert!(stderr(&ran).contains("owner, group and mode"), "{path}");
            assert_eq!(read(&sandbox, path), text);
            // Removing the agent wouldn't get a different one past `host upgrade`.
            assert_eq!(
                stderr(&ran).contains("remove it"),
                path != AGENT_PATH,
                "{}",
                stderr(&ran)
            );
        }
        for owner in ["1000:0", "0:1000"] {
            let sandbox = sandbox();
            place(&sandbox, path, text, mode);
            sandbox.set_owner(path, owner);

            let ran = sandbox.run(&full_script(&replacing(&fixture)));

            assert_stopped_at_preflight(&sandbox, &ran);
            assert!(stderr(&ran).contains(owner), "{}", stderr(&ran));
        }
    }
}

#[test]
fn a_directory_others_can_write_to_is_refused() {
    let fixture = Fixture::new();
    for dir in ["/usr/local/bin", "/etc/landfall", "/etc/systemd/system"] {
        for wrong_mode in [0o777, 0o757, 0o1777, 0o753] {
            let sandbox = sandbox();
            fs::set_permissions(sandbox.path(dir), fs::Permissions::from_mode(wrong_mode)).unwrap();

            let ran = sandbox.run(&full_script(&fixture.request()));

            assert_stopped_at_preflight(&sandbox, &ran);
            assert!(stderr(&ran).contains("not writable by others"), "{dir}");
        }

        let sandbox = sandbox();
        sandbox.set_owner(dir, "1000:0");
        let ran = sandbox.run(&full_script(&fixture.request()));
        assert_stopped_at_preflight(&sandbox, &ran);
        assert!(stderr(&ran).contains("1000:755"), "{}", stderr(&ran));

        // As Debian's `root:staff` has had `/usr/local/bin`.
        let sandbox = self::sandbox();
        fs::set_permissions(sandbox.path(dir), fs::Permissions::from_mode(0o775)).unwrap();
        sandbox.set_owner(dir, "0:50");
        let steps = install_steps(&fixture.request());
        let ran = sandbox.run(&render(&[step(&steps, "preflight").clone()]));
        assert_status(&ran, 0);
    }
}

/// An agent can be running from what was removed, and a different version mustn't come in as if
/// there had never been one.
#[test]
fn a_removed_agent_with_its_unit_there_is_refused_naming_upgrade() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, UNIT_PATH, UNIT, 0o644);
    place(&sandbox, RECOVER_PATH, RECOVER, 0o644);

    let ran = sandbox.run(&full_script(&fixture.request()));

    assert_stopped_at_preflight(&sandbox, &ran);
    assert!(stderr(&ran).contains("host upgrade"), "{}", stderr(&ran));
    assert!(!exists(&sandbox, AGENT_PATH));
}

/// With no unit file to say so, as when one came from elsewhere: what runs isn't what's on disk.
#[test]
fn a_rewritten_agent_restarts_a_running_unit() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_states(&[("active", "old", 0), ("active", "new", 0)]);
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();

    let ran = sandbox.run(&script_of(&fixture.without_code(), &["binary", "start"]));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, AGENT_PATH), AGENT);
    assert!(
        sandbox
            .log()
            .contains("systemctl restart --no-block landfall-agent"),
        "{}",
        sandbox.log()
    );
    assert!(!exists(&sandbox, MARKER));
}

/// Where `/usr/local/bin` is a link, what counts is where it goes.
#[test]
fn a_directory_that_is_a_link_is_judged_by_where_it_goes() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    let real = sandbox.path("/real-bin");
    fs::create_dir_all(&real).unwrap();
    fs::set_permissions(&real, fs::Permissions::from_mode(0o755)).unwrap();
    fs::remove_dir_all(sandbox.path("/usr/local/bin")).unwrap();
    symlink(&real, sandbox.path("/usr/local/bin")).unwrap();
    // What a link's own mode is on Linux. On macOS it has one to set, and only macOS's `chmod`
    // takes this, which is fine where the link already has it.
    let _ = Command::new("chmod")
        .args(["-h", "777"])
        .arg(sandbox.path("/usr/local/bin"))
        .stderr(std::process::Stdio::null())
        .status();
    let steps = install_steps(&fixture.request());

    let ran = sandbox.run(&render(&[step(&steps, "preflight").clone()]));

    assert_status(&ran, 0);
}

/// A kill just before the rename: the next run finds the agent in place, and only the marker
/// says that what runs isn't it.
#[test]
fn the_agents_marker_is_there_before_its_rename() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.stub(
        "mv",
        &format!(
            r#"for last in "$@"; do :; done
if [ -e {marker} ]; then echo marked > {seen}; fi
exec /bin/mv "$@""#,
            marker = sandbox.path(MARKER).display(),
            seen = sandbox.path("/seen").display()
        ),
    );

    let ran = sandbox.run(&script_of(&fixture.request(), &["binary"]));

    assert_status(&ran, 0);
    assert!(exists(&sandbox, "/seen"));
}

#[test]
fn what_is_not_a_regular_file_is_refused_where_one_goes() {
    let fixture = Fixture::new();
    for (path, text, _) in INSTALLED {
        let sandbox = sandbox();
        let elsewhere = sandbox.path("/elsewhere");
        fs::write(&elsewhere, text).unwrap();
        symlink(&elsewhere, sandbox.path(path)).unwrap();
        let ran = sandbox.run(&full_script(&replacing(&fixture)));
        assert_stopped_at_preflight(&sandbox, &ran);
        assert!(stderr(&ran).contains("isn't a regular file"), "{path}");
        assert_eq!(fs::read_to_string(&elsewhere).unwrap(), text);

        let sandbox = self::sandbox();
        symlink(sandbox.path("/nothing-here"), sandbox.path(path)).unwrap();
        let ran = sandbox.run(&full_script(&replacing(&fixture)));
        assert_stopped_at_preflight(&sandbox, &ran);
        assert!(stderr(&ran).contains("isn't a regular file"), "{path}");

        let sandbox = self::sandbox();
        fs::create_dir(sandbox.path(path)).unwrap();
        let ran = sandbox.run(&full_script(&replacing(&fixture)));
        assert_stopped_at_preflight(&sandbox, &ran);
        assert!(stderr(&ran).contains("isn't a regular file"), "{path}");
    }
}

#[test]
fn an_agent_user_unlike_the_guides_is_refused() {
    let fixture = Fixture::new();
    for (uid, home, shell, others, word) in [
        ("999", None, "/bin/bash", "", "login shell"),
        ("999", None, "/usr/bin/zsh", "", "login shell"),
        ("999", None, "", "", "login shell"),
        (
            "999",
            Some("/home/landfall-agent"),
            "/usr/sbin/nologin",
            "",
            "home",
        ),
        ("999", Some(""), "/usr/sbin/nologin", "", "home"),
        (
            "999",
            None,
            "/usr/sbin/nologin",
            "someone:x:999:1000::/home/someone:/bin/sh\n",
            "shared",
        ),
    ] {
        let sandbox = sandbox();
        sandbox.set_agent_user(999, "landfall-agent");
        let state_dir = sandbox.path(STATE_DIR);
        let home = home.map_or_else(|| state_dir.display().to_string(), str::to_owned);
        sandbox.set_passwd(&format!(
            "landfall-agent:x:{uid}:{uid}::{home}:{shell}\n{others}"
        ));

        let ran = sandbox.run(&script_of(&fixture.request(), &["user", "state"]));

        assert_status(&ran, 1);
        assert!(stderr(&ran).contains(word), "{word}: {}", stderr(&ran));
        let log = sandbox.log();
        for done in ["usermod", "useradd", "install -d"] {
            assert!(!log.contains(done), "{done} in {log}");
        }
    }
}

#[test]
fn an_agent_user_with_any_shell_that_cannot_log_in_is_allowed() {
    let fixture = Fixture::new();
    for shell in [
        "/usr/sbin/nologin",
        "/sbin/nologin",
        "/usr/bin/nologin",
        "/bin/false",
        "/usr/bin/false",
    ] {
        let sandbox = sandbox();
        sandbox.set_agent_user(999, "landfall-agent docker");
        let home = sandbox.path(STATE_DIR);
        sandbox.set_passwd(&format!(
            "root:x:0:0::/root:/bin/sh\nlandfall-agent:x:999:999::{}:{shell}\n",
            home.display()
        ));
        let ran = sandbox.run(&script_of(&fixture.request(), &["user"]));
        assert_status(&ran, 0);
    }
}

/// A directory service may not list its users, and then no uid can be seen to be shared. That
/// says nothing against this one.
/// The uid is the third field, whatever the group is.
#[test]
fn the_agents_uid_is_read_from_its_own_field() {
    let fixture = Fixture::new();
    let entry = |sandbox: &Sandbox, uid: &str, gid: &str| {
        sandbox.set_agent_user(999, "landfall-agent docker");
        sandbox.set_passwd(&format!(
            "landfall-agent:x:{uid}:{gid}::{}:/usr/sbin/nologin\n",
            sandbox.path(STATE_DIR).display()
        ));
    };

    let sandbox = sandbox();
    entry(&sandbox, "0", "999");
    let ran = sandbox.run(&script_of(&fixture.request(), &["user"]));
    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("uid 0"), "{}", stderr(&ran));

    let sandbox = self::sandbox();
    entry(&sandbox, "999", "0");
    assert_status(&sandbox.run(&script_of(&fixture.request(), &["user"])), 0);
}

/// Another user's uid that only starts the same isn't this one.
#[test]
fn a_uid_that_only_looks_like_the_agents_is_not_shared() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    sandbox.set_passwd(&format!(
        "landfall-agent:x:999:999::{}:/usr/sbin/nologin\nsomeone:x:9990:9990::/home/someone:/bin/sh\nanother:x:1999:1999::/home/another:/bin/sh\ngrouped:x:1000:999::/home/grouped:/bin/sh\n",
        sandbox.path(STATE_DIR).display()
    ));

    assert_status(&sandbox.run(&script_of(&fixture.request(), &["user"])), 0);
}

#[test]
fn a_host_that_does_not_list_its_users_is_not_taken_for_a_shared_uid() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    sandbox.before("getent", "if [ $# = 1 ]; then exit 0; fi");

    let ran = sandbox.run(&script_of(&fixture.request(), &["user"]));

    assert_status(&ran, 0);
}

#[test]
fn a_state_directory_that_is_a_link_is_refused() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    let elsewhere = sandbox.path("/elsewhere");
    fs::create_dir_all(&elsewhere).unwrap();
    fs::write(elsewhere.join(".enrol-code"), "theirs").unwrap();
    fs::remove_dir_all(sandbox.path(STATE_DIR)).unwrap();
    symlink(&elsewhere, sandbox.path(STATE_DIR)).unwrap();

    let ran = sandbox.run(&full_script(&fixture.request()));

    assert_stopped_at_preflight(&sandbox, &ran);
    assert!(stderr(&ran).contains("is a link"), "{}", stderr(&ran));
    assert_eq!(
        fs::read_to_string(elsewhere.join(".enrol-code")).unwrap(),
        "theirs"
    );
}

#[test]
fn a_state_directory_that_is_a_file_is_refused() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::remove_dir_all(sandbox.path(STATE_DIR)).unwrap();
    fs::write(sandbox.path(STATE_DIR), "").unwrap();

    let ran = sandbox.run(&full_script(&fixture.request()));

    assert_stopped_at_preflight(&sandbox, &ran);
    assert!(
        stderr(&ran).contains("isn't a directory"),
        "{}",
        stderr(&ran)
    );
}

/// With nothing changed there was no marker, and without one the next run would look at nothing,
/// which isn't what the run's message says.
#[test]
fn an_agent_still_stopping_has_a_marker_even_with_nothing_changed() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();
    sandbox.set_states(&[("deactivating", "old", 0)]);

    let ran = sandbox.run(&script_of(&fixture.without_code(), &["start"]));

    assert_status(&ran, 0);
    assert!(stdout(&ran).contains("Run this again"));
    assert!(exists(&sandbox, MARKER));
}

/// A run that left an agent still stopping hasn't seen what replaced it, which could be broken.
/// So the next run looks.
#[test]
fn an_agent_still_stopping_keeps_the_marker_until_it_is_seen_healthy() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();
    fs::write(sandbox.path(MARKER), "").unwrap();
    let script = script_of(&fixture.without_code(), &["start"]);

    sandbox.set_states(&[("active", "old", 0), ("deactivating", "old", 0)]);
    let ran = sandbox.run(&script);
    assert_status(&ran, 0);
    assert!(stdout(&ran).contains("a deploy is finishing"));
    assert!(stdout(&ran).contains("Run this again"));
    assert!(exists(&sandbox, MARKER));

    // Started rather than restarted, as a stop that had already begun leaves it.
    put_upload(&sandbox);
    sandbox.set_states(&[("deactivating", "old", 0)]);
    assert_status(&sandbox.run(&script), 0);
    assert!(exists(&sandbox, MARKER));

    // What replaced it is crash-looping: that's seen now, and the marker stays for the next.
    put_upload(&sandbox);
    sandbox.set_states(&[("active", "next", 3), ("activating", "next", 4)]);
    assert_status(&sandbox.run(&script), 1);
    assert!(exists(&sandbox, MARKER));

    // What replaced it is well.
    put_upload(&sandbox);
    sandbox.set_states(&[("active", "next", 0), ("active", "last", 0)]);
    assert_status(&sandbox.run(&script), 0);
    assert!(!exists(&sandbox, MARKER));
}

#[test]
fn a_refusal_is_printed_as_written() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, AGENT_PATH, "another agent", 0o755);
    let request = InstallRequest {
        version: r"1.2\c.3",
        ..fixture.request()
    };

    let ran = sandbox.run(&full_script(&request));

    assert_status(&ran, 1);
    assert!(
        stderr(&ran).contains(r"1.2\c.3: use landfall host upgrade"),
        "{}",
        stderr(&ran)
    );
}
