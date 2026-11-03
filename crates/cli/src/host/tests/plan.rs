//! The script, by running what it says with every system path in a sandbox.

use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::process::{Command, Output};

use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::HostId;

use super::{Sandbox, stderr, stdout};
use crate::agent_release::sha256_hex as hash;
use crate::host::plan::{
    EnrolTarget, InstallRequest, Step, Timing, UPLOAD_AGENT, UPLOAD_CODE, UPLOAD_CONFIG,
    install_steps, render,
};

pub(super) const UPLOAD: &str = "/tmp/landfall-install.0123456789abcdef";
pub(super) const AGENT_PATH: &str = "/usr/local/bin/landfall-agent";
pub(super) const CONFIG_PATH: &str = "/etc/landfall/fleet.toml";
pub(super) const UNIT_PATH: &str = "/etc/systemd/system/landfall-agent.service";
pub(super) const RECOVER_PATH: &str = "/etc/systemd/system/landfall-agent-recover@.service";
pub(super) const MARKER: &str = "/etc/landfall/.restart-pending";
pub(super) const CODE_PATH: &str = "/var/lib/landfall-agent/.enrol-code";
pub(super) const KEY_PATH: &str = "/var/lib/landfall-agent/agent.key";
pub(super) const CODE: &str = "the-enrolment-code";
pub(super) const CONFIG: &str = "# the fleet\n";
pub(super) const UNIT: &str = "[Unit]\nDescription=it's a unit with $HOME in it\n";
pub(super) const RECOVER: &str = "[Unit]\nDescription=the recover unit\n";

/// What the agent's file does when run: says it ran.
pub(super) const AGENT: &str = "#!/bin/sh\necho \"landfall-agent $*\" >> \"$AGENT_LOG\"\n";

pub(super) struct Fixture {
    pub(super) controller: ControllerUrl,
    pub(super) host: HostId,
    pub(super) sha256: String,
    pub(super) config_sha256: String,
}

impl Fixture {
    pub(super) fn new() -> Self {
        Self {
            controller: ControllerUrl::parse("https://controller.example", false).unwrap(),
            host: "home-1".parse().unwrap(),
            sha256: hash(AGENT.as_bytes()),
            config_sha256: hash(CONFIG.as_bytes()),
        }
    }

    /// A request with a code, whose every field is here: no `..`, so that one holding a code
    /// could not be added without this file saying so.
    pub(super) fn request(&self) -> InstallRequest<'_> {
        InstallRequest {
            sha256: &self.sha256,
            version: "1.2.3",
            config_sha256: &self.config_sha256,
            replace_config: false,
            replace_unit: false,
            enrol: Some(EnrolTarget {
                controller: &self.controller,
                host: &self.host,
                allow_insecure: false,
            }),
            unit: UNIT,
            recover_unit: RECOVER,
            upload: UPLOAD,
            timing: Timing {
                stable_secs: 1,
                give_up_secs: 3,
            },
        }
    }

    pub(super) fn without_code(&self) -> InstallRequest<'_> {
        InstallRequest {
            enrol: None,
            ..self.request()
        }
    }
}

/// A sandbox with the upload in place, and the agent's log as `AGENT_LOG`.
pub(super) fn sandbox() -> Sandbox {
    let mut sandbox = Sandbox::new();
    put_upload(&sandbox);
    let log = sandbox.path("/log").display().to_string();
    sandbox.set_env("AGENT_LOG", &log);
    sandbox
}

/// The upload in place, as a script removes it when it ends.
pub(super) fn put_upload(sandbox: &Sandbox) {
    fs::create_dir_all(sandbox.path(UPLOAD)).unwrap();
    fs::write(sandbox.path(UPLOAD).join(UPLOAD_AGENT), AGENT).unwrap();
    fs::write(sandbox.path(UPLOAD).join(UPLOAD_CONFIG), CONFIG).unwrap();
    fs::write(sandbox.path(UPLOAD).join(UPLOAD_CODE), CODE).unwrap();
}

/// A file a script finds installed, with exactly that mode, whatever the runner's umask.
pub(super) fn place(sandbox: &Sandbox, path: &str, text: &str, mode: u32) {
    set_file(&sandbox.path(path), text, mode);
}

fn set_file(path: &Path, text: &str, mode: u32) {
    fs::write(path, text).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

pub(super) fn step<'a>(steps: &'a [Step], title: &str) -> &'a Step {
    steps
        .iter()
        .find(|step| step.title == title)
        .unwrap_or_else(|| panic!("no step {title}"))
}

/// The script of `titles`, after preflight, which sets what the rest go by.
pub(super) fn script_of(request: &InstallRequest<'_>, titles: &[&str]) -> String {
    let steps = install_steps(request);
    let mut chosen = vec![step(&steps, "preflight").clone()];
    chosen.extend(titles.iter().map(|title| step(&steps, title).clone()));
    render(&chosen)
}

pub(super) fn assert_status(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stdout: {}\nstderr: {}",
        stdout(output),
        stderr(output)
    );
}

pub(super) fn read(sandbox: &Sandbox, path: &str) -> String {
    fs::read_to_string(sandbox.path(path)).unwrap()
}

fn mode(sandbox: &Sandbox, path: &str) -> u32 {
    fs::metadata(sandbox.path(path))
        .unwrap()
        .permissions()
        .mode()
        & 0o7777
}

pub(super) fn exists(sandbox: &Sandbox, path: &str) -> bool {
    sandbox.path(path).exists()
}

#[test]
fn script_parses() {
    let fixture = Fixture::new();
    for request in [fixture.request(), fixture.without_code()] {
        let script = render(&install_steps(&request));
        let ran = Command::new("/bin/sh")
            .args(["-n", "-c", &script])
            .output()
            .unwrap();
        assert_status(&ran, 0);
    }
}

#[test]
fn steps_come_in_their_order() {
    let fixture = Fixture::new();
    let titles = |request: &InstallRequest<'_>| -> Vec<String> {
        install_steps(request)
            .into_iter()
            .map(|step| step.title)
            .collect()
    };
    assert_eq!(
        titles(&fixture.request()),
        [
            "preflight",
            "user",
            "state",
            "config",
            "binary",
            "docker",
            "units",
            "enrol",
            "start"
        ]
    );
    assert_eq!(
        titles(&fixture.without_code()),
        [
            "preflight",
            "user",
            "state",
            "config",
            "binary",
            "docker",
            "units",
            "start"
        ]
    );
}

#[test]
fn script_never_holds_the_code() {
    let fixture = Fixture::new();
    let script = render(&install_steps(&fixture.request()));
    assert!(!script.contains(CODE));
    // It goes by path: read from the upload, and given to the agent by name.
    assert!(script.contains(CODE_PATH), "{script}");
    assert!(
        script.contains(&format!("read_upload {UPLOAD_CODE} | ")),
        "{script}"
    );
    assert!(
        script.contains(&format!("--code-file {CODE_PATH}")),
        "{script}"
    );
    // With no code, no step asks for one.
    let script = render(&install_steps(&fixture.without_code()));
    assert!(
        !script.contains(&format!("read_upload {UPLOAD_CODE}")),
        "{script}"
    );
    assert!(
        !script.contains(&format!("--code-file {CODE_PATH}")),
        "{script}"
    );
}

#[test]
fn the_key_is_never_written_by_the_script() {
    let fixture = Fixture::new();
    for request in [fixture.request(), fixture.without_code()] {
        for step in install_steps(&request) {
            for line in step.shell.lines().filter(|line| line.contains("agent.key")) {
                assert_eq!(step.title, "preflight", "{line}");
                assert!(line.trim_start().starts_with("test -e "), "{line}");
            }
        }
    }
    assert!(!render(&[]).contains("agent.key"));
}

#[test]
fn a_code_for_a_running_agent_is_refused_in_the_script() {
    let fixture = Fixture::new();
    let steps = install_steps(&fixture.request());
    let preflight = render(&[step(&steps, "preflight").clone()]);
    for state in [
        "active",
        "activating",
        "deactivating",
        "reloading",
        "unknown",
    ] {
        let sandbox = sandbox();
        sandbox.set_states(&[(state, "running-id", 0)]);
        fs::write(sandbox.path(CODE_PATH), "an old code").unwrap();

        let ran = sandbox.run(&preflight);

        assert_status(&ran, 1);
        assert!(stderr(&ran).contains("stop it first"), "{}", stderr(&ran));
        assert!(!exists(&sandbox, CODE_PATH), "{state}: the old code stays");
    }
    for state in ["inactive", "failed"] {
        let sandbox = sandbox();
        sandbox.set_states(&[(state, "", 0)]);
        assert_status(&sandbox.run(&preflight), 0);
    }
}

/// When `systemctl` can't say, the agent may be running.
#[test]
fn a_code_is_refused_when_the_units_state_cannot_be_read() {
    let fixture = Fixture::new();
    let steps = install_steps(&fixture.request());
    let sandbox = sandbox();
    sandbox.stub("systemctl", "exit 1");

    let ran = sandbox.run(&render(&[step(&steps, "preflight").clone()]));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("is unknown"), "{}", stderr(&ran));
}

#[test]
fn no_code_and_no_key_is_refused() {
    let fixture = Fixture::new();
    let steps = install_steps(&fixture.without_code());
    let preflight = render(&[step(&steps, "preflight").clone()]);
    let sandbox = sandbox();

    let ran = sandbox.run(&preflight);
    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("--code-file"), "{}", stderr(&ran));

    put_upload(&sandbox);
    fs::write(sandbox.path(KEY_PATH), "a key").unwrap();
    assert_status(&sandbox.run(&preflight), 0);
    assert_eq!(read(&sandbox, KEY_PATH), "a key");
}

#[test]
fn a_differing_agent_is_refused_naming_upgrade() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, AGENT_PATH, "another agent", 0o755);

    let ran = sandbox.run(&render(&install_steps(&fixture.request())));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("host upgrade"), "{}", stderr(&ran));
    assert!(stderr(&ran).contains("1.2.3"), "{}", stderr(&ran));
    assert_eq!(read(&sandbox, AGENT_PATH), "another agent");
    assert!(!stdout(&ran).contains("step 2"), "{}", stdout(&ran));
    assert_eq!(
        sandbox.log(),
        "systemctl show -p ActiveState --value landfall-agent\n"
    );
}

#[test]
fn differing_config_is_refused_before_any_change() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, CONFIG_PATH, "# the host's own rules\n", 0o644);

    let ran = sandbox.run(&render(&install_steps(&fixture.request())));

    assert_status(&ran, 1);
    assert!(
        stderr(&ran).contains("--replace-config"),
        "{}",
        stderr(&ran)
    );
    assert!(
        stdout(&ran).contains("-# the host's own rules"),
        "{}",
        stdout(&ran)
    );
    assert!(stdout(&ran).contains("+# the fleet"), "{}", stdout(&ran));
    assert_eq!(read(&sandbox, CONFIG_PATH), "# the host's own rules\n");
    assert!(!stdout(&ran).contains("step 2"), "{}", stdout(&ran));
    assert!(!sandbox.log().contains("useradd"), "{}", sandbox.log());
    assert!(!exists(&sandbox, MARKER));
}

#[test]
fn differing_units_are_refused_before_any_change() {
    for path in [UNIT_PATH, RECOVER_PATH] {
        let fixture = Fixture::new();
        let sandbox = sandbox();
        place(
            &sandbox,
            path,
            "[Unit]\nDescription=the host's own\n",
            0o644,
        );

        let ran = sandbox.run(&render(&install_steps(&fixture.request())));

        assert_status(&ran, 1);
        assert!(stderr(&ran).contains("--replace-unit"), "{}", stderr(&ran));
        assert!(
            stdout(&ran).contains("-Description=the host's own"),
            "{}",
            stdout(&ran)
        );
        assert!(!sandbox.log().contains("useradd"), "{}", sandbox.log());
        assert!(!exists(&sandbox, MARKER));
    }
}

#[test]
fn a_host_with_nothing_goes_through_every_step() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_states(&[("inactive", "", 0), ("active", "first", 0)]);
    let code_seen = sandbox.path("/code-seen");
    fs::write(
        sandbox.path(UPLOAD).join(UPLOAD_AGENT),
        format!(
            "#!/bin/sh\necho \"landfall-agent $*\" >> \"$AGENT_LOG\"\ncat {} > {}\n",
            sandbox.path(CODE_PATH).display(),
            code_seen.display()
        ),
    )
    .unwrap();
    let agent = fs::read(sandbox.path(UPLOAD).join(UPLOAD_AGENT)).unwrap();
    let sha256 = hash(&agent);
    let request = InstallRequest {
        sha256: &sha256,
        ..fixture.request()
    };

    let ran = sandbox.run(&render(&install_steps(&request)));

    assert_status(&ran, 0);
    assert_eq!(fs::read(sandbox.path(AGENT_PATH)).unwrap(), agent);
    assert_eq!(mode(&sandbox, AGENT_PATH), 0o755);
    assert_eq!(read(&sandbox, CONFIG_PATH), CONFIG);
    assert_eq!(mode(&sandbox, CONFIG_PATH), 0o644);
    assert_eq!(read(&sandbox, UNIT_PATH), UNIT);
    assert_eq!(mode(&sandbox, UNIT_PATH), 0o644);
    assert_eq!(read(&sandbox, RECOVER_PATH), RECOVER);
    assert_eq!(fs::read_to_string(&code_seen).unwrap(), CODE);

    let log = sandbox.log();
    let position = |needle: &str| {
        log.find(needle)
            .unwrap_or_else(|| panic!("no {needle} in {log}"))
    };
    assert!(position("useradd --system --home-dir /") < position("install -d -o landfall-agent"));
    assert!(
        log.contains("--no-create-home --shell /usr/sbin/nologin --groups docker landfall-agent"),
        "{log}"
    );
    assert!(position("docker version") < position("daemon-reload"));
    assert!(position("daemon-reload") < position("landfall-agent enrol"));
    assert!(
        log.contains("enrol --controller https://controller.example --host home-1 --code-file "),
        "{log}"
    );
    assert!(position("landfall-agent enrol") < position("systemctl enable --now"));
    // It doesn't wait for a unit still stopping: `wait_healthy` says what became of it.
    assert!(
        log.contains("systemctl enable --now --no-block landfall-agent\n"),
        "{log}"
    );

    // Nothing is left of what it held on the way.
    assert!(!exists(&sandbox, CODE_PATH));
    assert!(!exists(&sandbox, UPLOAD));
    assert!(!exists(&sandbox, MARKER));
    for name in [
        "/usr/local/bin/.landfall-agent.new",
        "/etc/landfall/.fleet.toml.new",
        "/etc/systemd/system/.landfall-agent.service.new",
        "/etc/systemd/system/.landfall-agent-recover@.service.new",
    ] {
        assert!(!exists(&sandbox, name), "{name}");
    }
}

#[test]
fn a_second_run_changes_nothing() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    sandbox.set_states(&[("active", "running", 0)]);
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    place(&sandbox, CONFIG_PATH, CONFIG, 0o644);
    place(&sandbox, UNIT_PATH, UNIT, 0o644);
    place(&sandbox, RECOVER_PATH, RECOVER, 0o644);
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();
    let modified = |path: &str| {
        fs::metadata(sandbox.path(path))
            .unwrap()
            .modified()
            .unwrap()
    };
    let before = [AGENT_PATH, CONFIG_PATH, UNIT_PATH, RECOVER_PATH].map(modified);

    let ran = sandbox.run(&render(&install_steps(&fixture.without_code())));

    assert_status(&ran, 0);
    assert_eq!(
        [AGENT_PATH, CONFIG_PATH, UNIT_PATH, RECOVER_PATH].map(modified),
        before
    );
    let log = sandbox.log();
    for word in ["useradd", "usermod", "daemon-reload", "restart", "enable"] {
        assert!(!log.contains(word), "{word} in {log}");
    }
    assert!(!exists(&sandbox, &format!("{CONFIG_PATH}.previous")));
    assert!(!exists(&sandbox, &format!("{UNIT_PATH}.previous")));
}

#[test]
fn a_replacement_keeps_the_old_file_and_restarts() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    sandbox.set_states(&[("active", "old", 0), ("active", "new", 0)]);
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    place(&sandbox, CONFIG_PATH, "# old config\n", 0o644);
    place(&sandbox, UNIT_PATH, "old unit\n", 0o644);
    place(&sandbox, RECOVER_PATH, "old recover\n", 0o644);
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();
    let request = InstallRequest {
        replace_config: true,
        replace_unit: true,
        ..fixture.without_code()
    };

    let ran = sandbox.run(&render(&install_steps(&request)));

    assert_status(&ran, 0);
    assert_eq!(read(&sandbox, CONFIG_PATH), CONFIG);
    assert_eq!(
        read(&sandbox, &format!("{CONFIG_PATH}.previous")),
        "# old config\n"
    );
    assert_eq!(read(&sandbox, UNIT_PATH), UNIT);
    assert_eq!(
        read(&sandbox, &format!("{UNIT_PATH}.previous")),
        "old unit\n"
    );
    assert_eq!(
        read(&sandbox, &format!("{RECOVER_PATH}.previous")),
        "old recover\n"
    );
    // As it was, as `umask 077` would otherwise have it, and restoring it would then be refused.
    assert_eq!(mode(&sandbox, &format!("{CONFIG_PATH}.previous")), 0o644);
    assert_eq!(mode(&sandbox, &format!("{UNIT_PATH}.previous")), 0o644);
    let log = sandbox.log();
    assert!(
        log.contains("systemctl restart --no-block landfall-agent"),
        "{log}"
    );
    assert!(log.contains("systemctl daemon-reload"), "{log}");
    assert!(!exists(&sandbox, MARKER));
}

/// Left there by whoever can write in a directory a group can.
#[test]
fn a_link_left_where_it_writes_is_not_followed() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    let victim = sandbox.path("/victim");
    fs::write(&victim, "theirs").unwrap();
    place(&sandbox, CONFIG_PATH, "# old\n", 0o644);
    for planted in [MARKER, "/etc/landfall/fleet.toml.previous.new"] {
        std::os::unix::fs::symlink(&victim, sandbox.path(planted)).unwrap();
    }
    let request = InstallRequest {
        replace_config: true,
        ..fixture.request()
    };

    let ran = sandbox.run(&script_of(&request, &["config"]));

    assert_status(&ran, 0);
    assert_eq!(fs::read_to_string(victim).unwrap(), "theirs");
    assert_eq!(
        read(&sandbox, &format!("{CONFIG_PATH}.previous")),
        "# old\n"
    );
}

#[test]
fn an_interrupted_replacement_still_restarts() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent docker");
    sandbox.set_states(&[("active", "old", 0), ("active", "new", 0)]);
    place(&sandbox, CONFIG_PATH, CONFIG, 0o644);
    fs::write(sandbox.path(MARKER), "").unwrap();
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();

    let ran = sandbox.run(&script_of(&fixture.without_code(), &["start"]));

    assert_status(&ran, 0);
    assert!(
        sandbox.log().contains("restart --no-block"),
        "{}",
        sandbox.log()
    );
    assert!(!exists(&sandbox, MARKER));
}

/// The units are in place and the reload never ran, which nothing but the marker now says.
#[test]
fn an_interrupted_unit_change_still_reloads() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    place(&sandbox, AGENT_PATH, AGENT, 0o755);
    place(&sandbox, UNIT_PATH, UNIT, 0o644);
    place(&sandbox, RECOVER_PATH, RECOVER, 0o644);
    fs::write(sandbox.path(MARKER), "").unwrap();

    let ran = sandbox.run(&script_of(&fixture.request(), &["units"]));

    assert_status(&ran, 0);
    assert!(sandbox.log().contains("daemon-reload"), "{}", sandbox.log());
}

#[test]
fn a_marker_stays_when_the_restart_fails() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_states(&[("active", "old", 0)]);
    fs::write(sandbox.path(MARKER), "").unwrap();
    fs::write(sandbox.path(KEY_PATH), "the key").unwrap();

    let ran = sandbox.run(&script_of(&fixture.without_code(), &["start"]));

    assert_status(&ran, 1);
    assert!(exists(&sandbox, MARKER));
}

#[test]
fn joining_the_docker_group_sets_the_marker() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(999, "landfall-agent");

    let ran = sandbox.run(&script_of(&fixture.request(), &["user"]));

    assert_status(&ran, 0);
    assert!(
        sandbox.log().contains("usermod -aG docker landfall-agent"),
        "{}",
        sandbox.log()
    );
    assert!(exists(&sandbox, MARKER));
}

#[test]
fn an_agent_user_that_is_root_is_refused() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.set_agent_user(0, "root docker");

    let ran = sandbox.run(&script_of(&fixture.request(), &["user", "state"]));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("uid 0"), "{}", stderr(&ran));
    assert!(!sandbox.log().contains("install"), "{}", sandbox.log());
}

#[test]
fn a_tampered_agent_is_not_put_in_place() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::write(sandbox.path(UPLOAD).join(UPLOAD_AGENT), "tampered").unwrap();

    let ran = sandbox.run(&script_of(&fixture.request(), &["binary"]));

    assert_status(&ran, 1);
    assert!(!exists(&sandbox, AGENT_PATH));
    assert!(!exists(&sandbox, "/usr/local/bin/.landfall-agent.new"));
    assert!(stderr(&ran).contains("SHA-256"), "{}", stderr(&ran));
}

#[test]
fn a_tampered_config_is_not_put_in_place() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::write(sandbox.path(UPLOAD).join(UPLOAD_CONFIG), "tampered").unwrap();

    let ran = sandbox.run(&script_of(&fixture.request(), &["config"]));

    assert_status(&ran, 1);
    assert!(!exists(&sandbox, CONFIG_PATH));
    assert!(!exists(&sandbox, "/etc/landfall/.fleet.toml.new"));
    assert!(!exists(&sandbox, MARKER));
}

#[test]
fn a_missing_upload_stops_the_script() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    fs::remove_file(sandbox.path(UPLOAD).join(UPLOAD_AGENT)).unwrap();

    let ran = sandbox.run(&script_of(&fixture.request(), &["binary", "docker"]));

    assert_status(&ran, 1);
    assert!(
        !sandbox.log().contains("docker version"),
        "{}",
        sandbox.log()
    );
}

#[test]
fn the_upload_is_read_as_the_user_who_ran_sudo() {
    let fixture = Fixture::new();
    let mut sandbox = sandbox();
    sandbox.set_env("SUDO_USER", "operator");

    let ran = sandbox.run(&script_of(&fixture.request(), &["config"]));

    assert_status(&ran, 0);
    assert!(
        sandbox.log().contains("runuser -u operator -- cat "),
        "{}",
        sandbox.log()
    );
}

#[test]
fn the_upload_is_read_directly_with_no_sudo() {
    let fixture = Fixture::new();
    let sandbox = sandbox();

    let ran = sandbox.run(&script_of(&fixture.request(), &["config"]));

    assert_status(&ran, 0);
    assert!(!sandbox.log().contains("runuser"), "{}", sandbox.log());
}

#[test]
fn an_agent_user_that_cannot_reach_docker_stops_the_script() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    sandbox.stub("docker", "exit 1");

    let ran = sandbox.run(&script_of(&fixture.request(), &["docker", "units"]));

    assert_status(&ran, 1);
    assert!(stderr(&ran).contains("docker group"), "{}", stderr(&ran));
    assert!(!exists(&sandbox, UNIT_PATH));
}

#[test]
fn a_failed_enrolment_leaves_no_code() {
    let fixture = Fixture::new();
    let sandbox = sandbox();
    super::write_executable(&sandbox.path(AGENT_PATH), "exit 3");
    fs::copy(
        sandbox.path(AGENT_PATH),
        sandbox.path(UPLOAD).join(UPLOAD_AGENT),
    )
    .unwrap();
    let sha256 = hash(&fs::read(sandbox.path(AGENT_PATH)).unwrap());
    let request = InstallRequest {
        sha256: &sha256,
        ..fixture.request()
    };

    let ran = sandbox.run(&script_of(&request, &["enrol", "start"]));

    assert_status(&ran, 3);
    assert!(!exists(&sandbox, CODE_PATH));
    assert!(!exists(&sandbox, UPLOAD));
    assert!(!sandbox.log().contains("enable"), "{}", sandbox.log());
}

#[test]
fn the_insecure_flag_reaches_enrol() {
    let controller = ControllerUrl::parse("http://127.0.0.1:8080", true).unwrap();
    let fixture = Fixture::new();
    let request = InstallRequest {
        enrol: Some(EnrolTarget {
            controller: &controller,
            host: &fixture.host,
            allow_insecure: true,
        }),
        ..fixture.request()
    };
    let shell = install_steps(&request)
        .into_iter()
        .find(|step| step.title == "enrol")
        .unwrap()
        .shell;
    assert!(shell.contains(" --allow-insecure-controller"), "{shell}");
    assert!(
        !step(&install_steps(&fixture.request()), "enrol")
            .shell
            .contains("--allow-insecure")
    );
}

#[test]
fn timing_defaults_to_the_rulings() {
    assert_eq!(
        Timing::default(),
        Timing {
            stable_secs: 10,
            give_up_secs: 120
        }
    );
    let fixture = Fixture::new();
    let request = InstallRequest {
        timing: Timing {
            stable_secs: 17,
            give_up_secs: 41,
        },
        ..fixture.request()
    };
    let shell = &install_steps(&request)[0].shell;
    assert!(shell.contains("stable_secs=17\n"), "{shell}");
    assert!(shell.contains("give_up_secs=41\n"), "{shell}");
}
