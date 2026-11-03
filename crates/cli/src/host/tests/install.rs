//! `host install` with what reaches the outside world faked: what it does, and in what order.

use std::cell::{Cell, RefCell};
use std::fs;
use std::future::Future;
use std::io;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use landfall_core::ids::ReleaseTag;
use landfall_origin::artifact::FileError;
use semver::Version;
use tempfile::TempDir;
use tokio::runtime::Runtime;

use super::facts::{good, output as probe_output};
use crate::agent_release::{AgentReleaseError, AgentSource, Arch, VerifiedAgent, sha256_hex};
use crate::host::install::{Confirm, InstallArgs, Outcome, run_with};
use crate::host::plan::Timing;
use crate::host::ssh::{Output, Remote, SshError};
use crate::host::{HostError, upload_dir};
use crate::project::ProjectError;

mod failures;
mod local;

/// An approver's key is a COSE key, Ed25519's base point here.
const CONFIG: &str = r#"
[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYIFhmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZmZm" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "patch", approvers = ["operator"] }
checks = ["container-healthy"]

[[deployment]]
id = "other/prod"
repo = { name = "example/other", id = 3, owner_id = 2 }
host = "home-1"
compose = { dir = "/srv/compose/other", service = "other" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "patch", approvers = ["operator"] }
checks = ["container-healthy"]
"#;

const CODE: &str = "c0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0dec0de";
pub(super) const AGENT_BYTES: &[u8] = b"the agent's bytes";
const DEST: &str = "user@host.example";

/// What's said of a fake agent, in the output.
const SUMMARY: &str = "where the agent came from";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Call {
    Run { command: String, stdin: Vec<u8> },
    Privileged { script: String, interactive: bool },
}

pub(super) struct FakeRemote {
    pub(super) calls: RefCell<Vec<Call>>,
    pub(super) probe: String,
    pub(super) connects: bool,
    pub(super) sudo: i32,
    pub(super) script: Result<i32, ()>,
    pub(super) fail_upload_of: Option<&'static str>,
    pub(super) mkdir_fails: bool,
    pub(super) probe_stderr: &'static str,
}

impl FakeRemote {
    pub(super) fn new() -> Self {
        Self {
            calls: RefCell::new(Vec::new()),
            probe: fit_probe(&[]),
            connects: true,
            sudo: 0,
            script: Ok(0),
            fail_upload_of: None,
            mkdir_fails: false,
            probe_stderr: "",
        }
    }

    pub(super) fn calls(&self) -> Vec<Call> {
        self.calls.borrow().clone()
    }

    pub(super) fn commands(&self) -> Vec<String> {
        self.calls()
            .into_iter()
            .filter_map(|call| match call {
                Call::Run { command, .. } => Some(command),
                Call::Privileged { .. } => None,
            })
            .collect()
    }

    pub(super) fn script(&self) -> Option<String> {
        self.calls().into_iter().find_map(|call| match call {
            Call::Privileged { script, .. } => Some(script),
            Call::Run { .. } => None,
        })
    }

    /// Only the probe.
    pub(super) fn assert_only_probed(&self) {
        let calls = self.calls();
        assert_eq!(calls.len(), 1, "{calls:?}");
        assert!(self.commands()[0].contains("landfall-probe-begin"));
    }
}

impl Remote for FakeRemote {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<Output, SshError> {
        self.calls.borrow_mut().push(Call::Run {
            command: command.to_owned(),
            stdin: stdin.to_owned(),
        });
        if !self.connects {
            return Err(SshError::Connection("no route to host".to_owned()));
        }
        let mut output = Output {
            status: 0,
            stdout: Vec::new(),
            stderr: Vec::new(),
        };
        if command.contains("landfall-probe-begin") {
            output.stdout = self.probe.clone().into_bytes();
            output.stderr = self.probe_stderr.as_bytes().to_vec();
        }
        if self.mkdir_fails && command.contains("mkdir -m 700") {
            output.status = 1;
            output.stderr = b"cannot create directory: File exists".to_vec();
        }
        if command.contains("sudo -n true") {
            output.status = self.sudo;
        }
        if self
            .fail_upload_of
            .is_some_and(|name| command.contains(&format!("/{name}'")))
        {
            output.status = 1;
            output.stderr = b"No space left on device".to_vec();
        }
        Ok(output)
    }

    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError> {
        self.calls.borrow_mut().push(Call::Privileged {
            script: script.to_owned(),
            interactive,
        });
        self.script
            .map_err(|()| SshError::Connection("cut".to_owned()))
    }
}

/// What a fit host's probe prints, with the clock right, and `overrides`.
pub(super) fn fit_probe(overrides: &[(&str, &str)]) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
        .to_string();
    let mut rows = good();
    for row in &mut rows {
        if row.0 == "clock" {
            row.1.clone_from(&now);
        }
        if let Some((_, value)) = overrides.iter().find(|(key, _)| *key == row.0) {
            (*value).clone_into(&mut row.1);
        }
    }
    probe_output(&rows)
}

pub(super) enum Fetch {
    Good,
    Refused,
    OutOfReach,
}

pub(super) struct FakeSource {
    pub(super) not_ready: bool,
    pub(super) fetch: Fetch,
    pub(super) asked_for: Cell<Option<Arch>>,
    pub(super) asked_tag: RefCell<Option<ReleaseTag>>,
}

impl FakeSource {
    pub(super) fn new() -> Self {
        Self {
            not_ready: false,
            fetch: Fetch::Good,
            asked_for: Cell::new(None),
            asked_tag: RefCell::new(None),
        }
    }
}

impl AgentSource for FakeSource {
    fn ready(&self) -> Result<(), AgentReleaseError> {
        if self.not_ready {
            Err(AgentReleaseError::Project(ProjectError::NoSigners))
        } else {
            Ok(())
        }
    }

    fn agent(
        &self,
        tag: &ReleaseTag,
        arch: Arch,
    ) -> impl Future<Output = Result<VerifiedAgent, AgentReleaseError>> {
        self.asked_for.set(Some(arch));
        *self.asked_tag.borrow_mut() = Some(tag.clone());
        std::future::ready(match self.fetch {
            Fetch::Good => Ok(VerifiedAgent::new(
                tag.clone(),
                Version::new(1, 2, 3),
                arch,
                AGENT_BYTES.to_vec(),
                SUMMARY.to_owned(),
            )),
            Fetch::Refused => Err(AgentReleaseError::File {
                tag: tag.clone(),
                source: Box::new(FileError::NotInSums {
                    name: "the agent".to_owned(),
                }),
            }),
            Fetch::OutOfReach => Err(AgentReleaseError::File {
                tag: tag.clone(),
                source: Box::new(FileError::Interrupted),
            }),
        })
    }
}

pub(super) struct FakeConfirm {
    pub(super) terminal: bool,
    pub(super) answer: bool,
    pub(super) asked: Vec<String>,
}

impl FakeConfirm {
    pub(super) fn at_a_terminal(answer: bool) -> Self {
        Self {
            terminal: true,
            answer,
            asked: Vec::new(),
        }
    }

    pub(super) fn no_terminal() -> Self {
        Self {
            terminal: false,
            answer: false,
            asked: Vec::new(),
        }
    }
}

impl Confirm for FakeConfirm {
    fn is_terminal(&self) -> bool {
        self.terminal
    }

    fn ask(&mut self, script_sha256: &str) -> io::Result<bool> {
        self.asked.push(script_sha256.to_owned());
        Ok(self.answer)
    }
}

/// A configuration and a code in a temp directory, and arguments that name them.
struct Files {
    dir: TempDir,
}

impl Files {
    fn new() -> Self {
        let files = Self {
            dir: TempDir::new().unwrap(),
        };
        fs::write(files.path("fleet.toml"), CONFIG).unwrap();
        fs::write(files.path("code"), format!("{CODE}\n")).unwrap();
        files
    }

    fn path(&self, name: &str) -> PathBuf {
        self.dir.path().join(name)
    }

    fn args(&self) -> InstallArgs {
        InstallArgs {
            dest: DEST.to_owned(),
            host: "home-1".parse().unwrap(),
            config: self.path("fleet.toml"),
            controller: "https://controller.example".to_owned(),
            allow_insecure_controller: false,
            code_file: Some(self.path("code")),
            tag: Some("v1.2.3".parse().unwrap()),
            dry_run: false,
            yes: true,
            replace_config: false,
            replace_unit: false,
            ssh_config: None,
            cache_dir: None,
            timing: Timing::default(),
        }
    }
}

struct Ran {
    result: Result<Outcome, HostError>,
    out: String,
}

pub(super) fn runtime() -> Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn run(
    args: &InstallArgs,
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

/// With `--yes`, no terminal, a fit host and a good release.
fn run_plainly(args: &InstallArgs, remote: &FakeRemote) -> Ran {
    run(
        args,
        &FakeSource::new(),
        remote,
        &mut FakeConfirm::no_terminal(),
    )
}

fn error_of(ran: Ran) -> HostError {
    ran.result.unwrap_err()
}

#[test]
fn an_upload_directory_is_private_to_this_run() {
    let one = upload_dir().unwrap();
    let hex = one.strip_prefix("/tmp/landfall-install.").unwrap();
    assert_eq!(hex.len(), 32);
    assert!(hex.chars().all(|c| c.is_ascii_hexdigit()));
    assert_ne!(one, upload_dir().unwrap());
}

#[test]
fn a_good_install_goes_through_everything_in_order() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    let commands = remote.commands();
    let script = remote.script().unwrap();
    let upload = script
        .lines()
        .find_map(|line| line.strip_prefix("upload='"))
        .unwrap()
        .trim_end_matches('\'')
        .to_owned();
    let wanted = [
        "landfall-probe-begin".to_owned(),
        "sudo -n true".to_owned(),
        "find /tmp -maxdepth 1 -name '\\''landfall-install.*'\\'' -user".to_owned(),
        format!("mkdir -m 700 -- '\\''{upload}'\\''"),
        format!("umask 077 && cat > '\\''{upload}/landfall-agent'\\''"),
        format!("umask 077 && cat > '\\''{upload}/fleet.toml'\\''"),
        format!("umask 077 && cat > '\\''{upload}/enrol-code'\\''"),
    ];
    assert_eq!(commands.len(), wanted.len(), "{commands:?}");
    for (command, want) in commands.iter().zip(&wanted) {
        assert!(command.contains(want.as_str()), "{want}\nin {command}");
    }
    // The privileged step is the very last thing.
    assert!(matches!(
        remote.calls().last(),
        Some(Call::Privileged {
            interactive: false,
            ..
        })
    ));
    let stdin_of = |name: &str| {
        remote.calls().into_iter().find_map(|call| match call {
            Call::Run { command, stdin } if command.contains(&format!("/{name}'")) => Some(stdin),
            _ => None,
        })
    };
    assert_eq!(stdin_of("landfall-agent").unwrap(), AGENT_BYTES);
    assert_eq!(stdin_of("fleet.toml").unwrap(), CONFIG.as_bytes());
    assert_eq!(stdin_of("enrol-code").unwrap(), CODE.as_bytes());
}

/// `check_path` comes before a unit is rendered, and every directory of this host is in it.
#[test]
fn what_runs_is_for_this_request() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    let script = remote.script().unwrap();
    for word in [
        "ReadWritePaths=/srv/compose/app /srv/compose/other",
        "--controller https://controller.example --host home-1",
        &sha256_hex(AGENT_BYTES),
        &sha256_hex(CONFIG.as_bytes()),
        "use landfall host upgrade",
        "1.2.3: use",
    ] {
        assert!(script.contains(word), "{word}");
    }
}

#[test]
fn the_flags_reach_the_script() {
    let files = Files::new();
    let without = {
        let remote = FakeRemote::new();
        let _ = run_plainly(&files.args(), &remote);
        remote.script().unwrap()
    };
    assert!(without.contains("--replace-config replaces it"));
    assert!(without.contains("--replace-unit replaces it"));

    let remote = FakeRemote::new();
    let args = InstallArgs {
        replace_config: true,
        replace_unit: true,
        timing: Timing {
            stable_secs: 17,
            give_up_secs: 41,
        },
        ..files.args()
    };
    let _ = run_plainly(&args, &remote);
    let with = remote.script().unwrap();
    assert!(!with.contains("--replace-config replaces it"));
    assert!(!with.contains("--replace-unit replaces it"));
    assert!(with.contains("stable_secs=17\n"));
    assert!(with.contains("give_up_secs=41\n"));

    let remote = FakeRemote::new();
    let args = InstallArgs {
        controller: "http://127.0.0.1:8080".to_owned(),
        allow_insecure_controller: true,
        ..files.args()
    };
    let _ = run_plainly(&args, &remote);
    assert!(
        remote
            .script()
            .unwrap()
            .matches("--allow-insecure-controller")
            .count()
            >= 2,
        "the unit and enrol"
    );
}

#[test]
fn with_no_code_nothing_asks_for_one() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        code_file: None,
        ..files.args()
    };

    let ran = run_plainly(&args, &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(!remote.commands().iter().any(|c| c.contains("enrol-code")));
    assert!(!remote.script().unwrap().contains("enrol --controller"));
}

#[test]
fn the_host_s_architecture_is_the_one_asked_for() {
    let files = Files::new();
    for (machine, arch) in [("aarch64", Arch::Arm64), ("x86_64", Arch::Amd64)] {
        let mut remote = FakeRemote::new();
        remote.probe = fit_probe(&[("machine", machine)]);
        let source = FakeSource::new();
        let _ = run(
            &files.args(),
            &source,
            &remote,
            &mut FakeConfirm::no_terminal(),
        );
        assert_eq!(source.asked_for.get(), Some(arch));
    }
}

#[test]
fn a_clock_off_is_said_and_does_not_stop_it() {
    let files = Files::new();
    let mut remote = FakeRemote::new();
    remote.probe = fit_probe(&[("clock", "1000")]);

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(
        ran.out.contains("warning: the target's clock"),
        "{}",
        ran.out
    );
}

#[test]
fn dry_run_uploads_nothing_and_runs_nothing_privileged() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let args = InstallArgs {
        dry_run: true,
        yes: false,
        ..files.args()
    };

    let ran = run_plainly(&args, &remote);

    assert_eq!(ran.result.unwrap(), Outcome::DryRun);
    remote.assert_only_probed();
    assert!(ran.out.contains("the script's SHA-256 is"), "{}", ran.out);
}

#[test]
fn the_printed_script_is_the_one_that_runs() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    let script = remote.script().unwrap();
    assert!(ran.out.contains(&script), "{}", ran.out);
    assert!(
        ran.out
            .contains(&format!("SHA-256 is {}\n", sha256_hex(script.as_bytes()))),
        "{}",
        ran.out
    );
    // And it names the directory the upload made.
    let made = remote
        .commands()
        .into_iter()
        .find(|command| command.contains("mkdir -m 700"))
        .unwrap();
    let upload = script
        .lines()
        .find_map(|line| line.strip_prefix("upload='"))
        .unwrap()
        .trim_end_matches('\'');
    assert!(upload.starts_with("/tmp/landfall-install."), "{upload}");
    assert!(made.contains(upload), "{made}");
}

#[test]
fn plan_is_printed_before_it_runs() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let mut confirm = FakeConfirm::at_a_terminal(false);
    let args = InstallArgs {
        yes: false,
        ..files.args()
    };

    let ran = run(&args, &FakeSource::new(), &remote, &mut confirm);

    // By the time it's asked, the hash it's asked about has been shown, with the rest.
    assert_eq!(confirm.asked.len(), 1);
    for word in [
        SUMMARY,
        &sha256_hex(AGENT_BYTES),
        "preflight, user, state, config, binary, docker, units, enrol, start",
        "this is what runs as root on user@host.example",
        "set -eu",
        &format!("SHA-256 is {}\n", confirm.asked[0]),
    ] {
        assert!(ran.out.contains(word), "{word}\n{}", ran.out);
    }
}

#[test]
fn agreeing_at_a_terminal_runs_with_sudo_s_own_prompt() {
    let files = Files::new();
    let remote = FakeRemote {
        // It would be refused if it were asked.
        sudo: 1,
        ..FakeRemote::new()
    };
    let args = InstallArgs {
        yes: false,
        ..files.args()
    };

    let ran = run(
        &args,
        &FakeSource::new(),
        &remote,
        &mut FakeConfirm::at_a_terminal(true),
    );

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(!remote.commands().iter().any(|c| c.contains("sudo -n")));
    assert!(matches!(
        remote.calls().last(),
        Some(Call::Privileged {
            interactive: true,
            ..
        })
    ));
}

#[test]
fn yes_at_a_terminal_does_not_ask() {
    let files = Files::new();
    let remote = FakeRemote::new();
    let mut confirm = FakeConfirm::at_a_terminal(false);

    let ran = run(&files.args(), &FakeSource::new(), &remote, &mut confirm);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert_eq!(confirm.asked, Vec::<String>::new());
}

#[test]
fn root_needs_no_sudo() {
    let files = Files::new();
    let mut remote = FakeRemote {
        sudo: 1,
        ..FakeRemote::new()
    };
    remote.probe = fit_probe(&[("uid", "0"), ("has_sudo", "0")]);

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(!remote.commands().iter().any(|c| c.contains("sudo -n")));
}

#[test]
fn code_goes_by_stdin_and_never_in_a_command() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let ran = run_plainly(&files.args(), &remote);

    assert_eq!(ran.result.unwrap(), Outcome::Installed);
    assert!(!ran.out.contains(CODE));
    assert!(!remote.commands().iter().any(|c| c.contains(CODE)));
    assert!(!remote.script().unwrap().contains(CODE));
    let carrying = remote
        .calls()
        .into_iter()
        .filter(|call| matches!(call, Call::Run { stdin, .. } if stdin == CODE.as_bytes()))
        .count();
    assert_eq!(carrying, 1);
}

#[test]
fn code_is_uploaded_last() {
    let files = Files::new();
    let remote = FakeRemote::new();

    let _ = run_plainly(&files.args(), &remote);

    let calls = remote.calls();
    let Call::Run { command, .. } = &calls[calls.len() - 2] else {
        panic!("{calls:?}");
    };
    assert!(command.contains("/enrol-code'"), "{command}");
}
