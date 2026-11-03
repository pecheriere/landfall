//! A fresh container for each test, and what the tests do with one. Nothing here touches a real
//! host: the container has no host mounts, and its port is published on `127.0.0.1` only.

use std::cell::RefCell;
use std::fmt::Write as _;
use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use landfall_cli::agent_release::{AgentReleaseError, AgentSource, Arch, VerifiedAgent};
use landfall_cli::host::HostError;
use landfall_cli::host::install::{Confirm, InstallArgs, Outcome, run_with};
use landfall_cli::host::plan::{
    EnrolTarget, InstallRequest, Step, Timing, UPLOAD_AGENT, UPLOAD_CODE, UPLOAD_CONFIG,
    install_steps,
};
use landfall_cli::host::shell::{privileged_command, quote, remote_command};
use landfall_cli::host::ssh::{self, Destination, OpenSsh, Remote, SshError};
use landfall_cli::host::unit::{UnitInput, agent_unit, recover_unit};
use landfall_core::controller_url::ControllerUrl;
use landfall_core::ids::{HostId, ReleaseTag};
use semver::Version;
use sha2::{Digest as _, Sha256};
use tempfile::TempDir;

pub(crate) const IMAGE: &str = "landfall-test-sshd";
pub(crate) const FLEET: &str = include_str!("fleet.toml");
pub(crate) const CONTROLLER: &str = "http://127.0.0.1:8080";
pub(crate) const COMPOSE_DIR: &str = "/srv/compose/app";
pub(crate) const AGENT_PATH: &str = "/usr/local/bin/landfall-agent";
pub(crate) const AGENT_NEW: &str = "/usr/local/bin/.landfall-agent.new";
pub(crate) const CONFIG_PATH: &str = "/etc/landfall/fleet.toml";
pub(crate) const UNIT_PATH: &str = "/etc/systemd/system/landfall-agent.service";
pub(crate) const RECOVER_PATH: &str = "/etc/systemd/system/landfall-agent-recover@.service";
pub(crate) const MARKER: &str = "/etc/landfall/.restart-pending";
pub(crate) const STATE_DIR: &str = "/var/lib/landfall-agent";
pub(crate) const KEY_PATH: &str = "/var/lib/landfall-agent/agent.key";
pub(crate) const CODE_PATH: &str = "/var/lib/landfall-agent/.enrol-code";

const REAL_AGENT: &str = "/usr/local/lib/landfall/landfall-agent";
const SERVER: &str = "/usr/local/lib/landfall/landfall-server";
const SERVER_CONFIG: &str = "/usr/local/lib/landfall/fleet.toml";
const SERVER_DB: &str = "/var/lib/landfall-server/controller.db";
const SERVER_LOG: &str = "/var/lib/landfall-server/log";

/// Long enough to be sure of a booted machine under a loaded runner.
const BOOT_LIMIT: Duration = Duration::from_secs(180);

/// Short, as nothing here runs a real deploy, and long enough for an agent that crashes to do it.
pub(crate) const TIMING: Timing = Timing {
    stable_secs: 3,
    give_up_secs: 30,
};

/// Runs `docker` to its end, and hands back what it said, panicking if it couldn't be run at all.
fn docker(args: &[&str]) -> Output {
    Command::new("docker").args(args).output().unwrap()
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// `docker`, which must succeed.
fn docker_ok(args: &[&str]) -> String {
    let ran = docker(args);
    assert!(
        ran.status.success(),
        "docker {args:?}: {}{}",
        text(&ran.stdout),
        text(&ran.stderr)
    );
    text(&ran.stdout)
}

/// Where the real binaries are, or what to run to have them.
pub(crate) fn dist() -> PathBuf {
    let Some(dist) = std::env::var_os("LANDFALL_TEST_DIST") else {
        panic!(
            "LANDFALL_TEST_DIST isn't set. Build the binaries for this machine's platform, and say where:\n\
             docker buildx build --target binaries --provenance=false --sbom=false --output type=local,dest=<dir> .\n\
             LANDFALL_TEST_DIST=<dir> cargo test -p landfall-cli --locked -- --ignored docker_"
        );
    };
    PathBuf::from(dist)
}

fn check_image() {
    assert!(
        docker(&["image", "inspect", IMAGE]).status.success(),
        "no image {IMAGE}. Build it with:\ndocker build -t {IMAGE} crates/cli/tests/docker_host_install"
    );
}

/// The real agent's bytes.
pub(crate) fn real_agent() -> Vec<u8> {
    fs::read(dist().join("landfall-agent")).unwrap()
}

/// Hands out the same bytes whatever is asked, as a real release can't be had here.
pub(crate) struct FixedSource {
    pub(crate) bytes: Vec<u8>,
}

impl FixedSource {
    pub(crate) fn real() -> Self {
        Self {
            bytes: real_agent(),
        }
    }
}

impl AgentSource for FixedSource {
    fn ready(&self) -> Result<(), AgentReleaseError> {
        Ok(())
    }

    fn agent(
        &self,
        tag: &ReleaseTag,
        arch: Arch,
    ) -> impl Future<Output = Result<VerifiedAgent, AgentReleaseError>> {
        std::future::ready(Ok(VerifiedAgent::new(
            tag.clone(),
            Version::new(1, 2, 3),
            arch,
            self.bytes.clone(),
            "a test's own build".to_owned(),
        )))
    }
}

/// With nobody there.
pub(crate) struct Unattended;

impl Confirm for Unattended {
    fn is_terminal(&self) -> bool {
        false
    }

    fn ask(&mut self, _script_sha256: &str) -> io::Result<bool> {
        Ok(false)
    }
}

/// Someone at a terminal who takes `pause` to say yes.
pub(crate) struct SlowYes {
    pub(crate) pause: Duration,
}

impl Confirm for SlowYes {
    fn is_terminal(&self) -> bool {
        true
    }

    fn ask(&mut self, _script_sha256: &str) -> io::Result<bool> {
        std::thread::sleep(self.pause);
        Ok(true)
    }
}

/// [`OpenSsh`], with what the script says kept, for a test to read: the real one's goes straight
/// to this process's stdout, as `sudo`'s prompt needs. The same command, by the same connection.
pub(crate) struct Captured<R> {
    pub(crate) inner: R,
    pub(crate) said: RefCell<Vec<u8>>,
}

impl<R> Captured<R> {
    pub(crate) fn new(inner: R) -> Self {
        Self {
            inner,
            said: RefCell::new(Vec::new()),
        }
    }
}

impl<R: Remote> Remote for Captured<R> {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<ssh::Output, SshError> {
        self.inner.run(command, stdin)
    }

    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError> {
        let output = self
            .inner
            .run(&privileged_command(script, interactive), b"")?;
        let mut said = self.said.borrow_mut();
        said.extend_from_slice(&output.stdout);
        said.extend_from_slice(&output.stderr);
        Ok(output.status)
    }
}

pub(crate) struct Ran {
    pub(crate) result: Result<Outcome, HostError>,
    pub(crate) out: String,
}

impl Ran {
    /// The status the process would have ended with.
    pub(crate) fn status(&self) -> u8 {
        match &self.result {
            Ok(_) => 0,
            Err(error) => error.exit_code(),
        }
    }

    pub(crate) fn error_text(&self) -> String {
        self.result.as_ref().err().map(chain).unwrap_or_default()
    }

    #[track_caller]
    pub(crate) fn assert_ok(&self) {
        assert_eq!(self.status(), 0, "{}\n{}", self.error_text(), self.out);
    }
}

/// An error and its sources, as the command line shows them.
fn chain(error: &HostError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(next) = source {
        text.push_str(": ");
        text.push_str(&next.to_string());
        source = next.source();
    }
    text
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// `run_with`, as a real run does it but for its source.
pub(crate) fn install_through<R: Remote>(
    args: &InstallArgs,
    source: &FixedSource,
    remote: &R,
    confirm: &mut dyn Confirm,
) -> Ran {
    let mut out = Vec::new();
    let result = run_with(args, source, remote, &runtime(), &mut out, confirm);
    Ran {
        result,
        out: text(&out),
    }
}

/// A running container, removed when this is dropped.
pub(crate) struct Target {
    id: String,
    dir: TempDir,
    port: String,
    pub(crate) known_hosts: PathBuf,
    identity: PathBuf,
    host_key: String,
}

impl Target {
    /// A fresh machine, with sshd up, a controller running, and this test's key let in.
    pub(crate) fn start() -> Self {
        let dist = dist();
        Self::boot(&[], IMAGE).finish_starting(&dist)
    }

    /// A machine that has booted or has been seen not to, running `command` in place of the
    /// image's, with `label` to find it by. From `docker run` on, `Drop` has the container.
    pub(crate) fn boot(command: &[&str], label: &str) -> Self {
        check_image();
        let dir = TempDir::new().unwrap();
        let mut run = vec![
            "run",
            "-d",
            // Not `--privileged`: README.md says why each of these is needed.
            "--cap-add",
            "SYS_ADMIN",
            "--security-opt",
            "apparmor=unconfined",
            "--cgroupns=private",
            "--tmpfs",
            "/run",
            "--tmpfs",
            "/run/lock",
            "-p",
            "127.0.0.1::22",
            "--label",
            label,
            IMAGE,
        ];
        run.extend(command);
        let id = docker_ok(&run).trim().to_owned();
        let identity = dir.path().join("key");
        let known_hosts = dir.path().join("known_hosts");
        let mut target = Self {
            id,
            dir,
            port: String::new(),
            known_hosts,
            identity,
            host_key: String::new(),
        };
        let made = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&target.identity)
            .status()
            .unwrap();
        assert!(made.success());
        target.port = target.published_port();
        target.wait_for_boot();
        target
    }

    /// The port, once `docker` has one to say. It has none for a container that's stopped.
    fn published_port(&self) -> String {
        let start = Instant::now();
        loop {
            self.assert_still_running();
            let port = docker(&["port", &self.id, "22/tcp"]);
            if port.status.success() {
                return text(&port.stdout)
                    .lines()
                    .next()
                    .and_then(|line| line.rsplit(':').next())
                    .unwrap()
                    .to_owned();
            }
            assert!(
                start.elapsed() < BOOT_LIMIT,
                "no port for the container: {}\n{}",
                text(&port.stderr),
                self.how_it_stands()
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    /// A container that has stopped will never come up, so nothing should wait for it to.
    fn assert_still_running(&self) {
        let status = docker(&["inspect", "-f", "{{.State.Status}}", &self.id]);
        let status = text(&status.stdout);
        assert!(
            status.trim() == "running",
            "the machine stopped instead of booting.\n{}",
            self.how_it_stands()
        );
    }

    /// What can be said of the container, for a failure that needs reading from CI's log alone.
    fn how_it_stands(&self) -> String {
        let state = docker(&[
            "inspect",
            "-f",
            "status {{.State.Status}}, exit code {{.State.ExitCode}}, error {{.State.Error}}",
            &self.id,
        ]);
        let logs = docker(&["logs", "--tail", "50", &self.id]);
        format!(
            "container {id}: {state}\ndocker logs:\n{stdout}{stderr}\nIf `mount` was refused, README.md has the fallback.",
            id = self.id,
            state = text(&state.stdout).trim(),
            stdout = text(&logs.stdout),
            stderr = text(&logs.stderr),
        )
    }

    fn finish_starting(mut self, dist: &Path) -> Self {
        let public_key = fs::read_to_string(self.identity.with_extension("pub")).unwrap();
        for user in ["operator", "needs-password"] {
            let group = self.sh_ok(&format!("id -gn {user}"));
            let group = group.trim();
            self.sh_ok(&format!(
                "install -d -o {user} -g {group} -m 0700 /home/{user}/.ssh \
                 && printf '%s' {key} > /home/{user}/.ssh/authorized_keys \
                 && chown {user}:{group} /home/{user}/.ssh/authorized_keys \
                 && chmod 0600 /home/{user}/.ssh/authorized_keys",
                key = quote(&public_key),
            ));
        }
        let host_key = self.sh_ok("cat /etc/ssh/ssh_host_ed25519_key.pub");
        let host_key = host_key
            .split_whitespace()
            .take(2)
            .collect::<Vec<_>>()
            .join(" ");
        self.host_key = format!("[127.0.0.1]:{} {host_key}\n", self.port);
        self.write_known_host_key();
        self.write_ssh_config("");

        self.copy_in(&dist.join("landfall-server"), SERVER);
        self.copy_in(&dist.join("landfall-agent"), REAL_AGENT);
        let fleet = self.dir.path().join("server-fleet.toml");
        fs::write(&fleet, FLEET).unwrap();
        self.copy_in(&fleet, SERVER_CONFIG);
        self.sh_ok(&format!("chmod 0755 {SERVER} {REAL_AGENT}"));
        docker_ok(&[
            "exec",
            "-d",
            &self.id,
            "sh",
            "-c",
            &format!(
                "exec {SERVER} serve --config {SERVER_CONFIG} --db {SERVER_DB} --listen 127.0.0.1:8080 > {SERVER_LOG} 2>&1"
            ),
        ]);
        wait_until("the controller to listen", || {
            self.sh(&format!("grep -q listening {SERVER_LOG}"))
                .status
                .success()
        });
        self
    }

    fn wait_for_boot(&self) {
        let start = Instant::now();
        loop {
            self.assert_still_running();
            if self
                .sh("systemctl is-active --quiet ssh.service dbus.service docker.service")
                .status
                .success()
            {
                return;
            }
            assert!(
                start.elapsed() < BOOT_LIMIT,
                "the machine didn't boot in {BOOT_LIMIT:?}.\n{}\nInside it:\n{}",
                self.how_it_stands(),
                text(
                    &self
                        .sh("systemctl list-units --failed; systemctl status ssh.service")
                        .stdout
                )
            );
            std::thread::sleep(Duration::from_millis(200));
        }
    }

    fn copy_in(&self, from: &Path, to: &str) {
        docker_ok(&[
            "cp",
            "-q",
            &from.display().to_string(),
            &format!("{}:{to}", self.id),
        ]);
    }

    /// `script` as root on the target, whatever comes of it, with its input closed.
    pub(crate) fn sh(&self, script: &str) -> Output {
        Command::new("docker")
            .args(["exec", &self.id, "sh", "-c", script])
            .stdin(Stdio::null())
            .output()
            .unwrap()
    }

    /// `script` as root on the target, which must succeed, and its stdout.
    #[track_caller]
    pub(crate) fn sh_ok(&self, script: &str) -> String {
        let ran = self.sh(script);
        assert!(
            ran.status.success(),
            "{script}: {}{}",
            text(&ran.stdout),
            text(&ran.stderr)
        );
        text(&ran.stdout)
    }

    /// Whether `path` is there, on a machine that can say: a failed `docker exec` also has a
    /// status of 1, and would otherwise read as its not being there.
    #[track_caller]
    pub(crate) fn exists(&self, path: &str) -> bool {
        let ran = self.sh(&format!("[ -e {path} ]"));
        match ran.status.code() {
            Some(0) => true,
            Some(1) if ran.stderr.is_empty() => false,
            _ => panic!("couldn't look for {path}: {ran:?}"),
        }
    }

    /// The uploads in `/tmp`, on a machine that can say.
    #[track_caller]
    pub(crate) fn uploads_left(&self) -> String {
        self.sh_ok("ls -d /tmp/landfall-install.* 2>/dev/null || true")
    }

    /// The `ssh_config`, starting with `lines` so that they are the ones that count, and otherwise
    /// only what reaches this container, away from the agent and the files of whoever runs this.
    pub(crate) fn write_ssh_config(&self, lines: &str) {
        let config = format!(
            "{lines}\nPort {port}\nIdentityFile {identity}\nIdentitiesOnly yes\nIdentityAgent none\nUserKnownHostsFile {known}\nGlobalKnownHostsFile /dev/null\n",
            port = self.port,
            identity = self.identity.display(),
            known = self.known_hosts.display(),
        );
        fs::write(self.ssh_config(), config).unwrap();
    }

    pub(crate) fn ssh_config(&self) -> PathBuf {
        self.dir.path().join("ssh_config")
    }

    pub(crate) fn write_known_host_key(&self) {
        fs::write(&self.known_hosts, &self.host_key).unwrap();
    }

    /// Another machine's key, in place of this one's.
    pub(crate) fn write_another_host_key(&self) {
        let other = self.dir.path().join("other");
        let made = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", ""])
            .arg("-f")
            .arg(&other)
            .status()
            .unwrap();
        assert!(made.success());
        let key = fs::read_to_string(other.with_extension("pub")).unwrap();
        let key = key.split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        fs::write(
            &self.known_hosts,
            format!("[127.0.0.1]:{} {key}\n", self.port),
        )
        .unwrap();
    }

    /// A one-time code from the real controller, in a file of the test's. `replace` for a host
    /// that is enrolled already.
    pub(crate) fn code_file(&self, replace: bool) -> PathBuf {
        let replace = if replace { " --replace" } else { "" };
        let code = self.sh_ok(&format!(
            "{SERVER} enrol-code --host home-1 --db {SERVER_DB}{replace}"
        ));
        let path = self.dir.path().join("code");
        fs::write(&path, code.trim()).unwrap();
        path
    }

    pub(crate) fn file_in_temp(&self, name: &str, text: &str) -> PathBuf {
        let path = self.dir.path().join(name);
        fs::write(&path, text).unwrap();
        path
    }

    pub(crate) fn port(&self) -> &str {
        &self.port
    }

    /// Everything needed for a first install, with a new code, as `operator`.
    pub(crate) fn args(&self) -> InstallArgs {
        let code = self.code_file(false);
        InstallArgs {
            code_file: Some(code),
            ..self.args_with_no_code()
        }
    }

    pub(crate) fn args_with_no_code(&self) -> InstallArgs {
        InstallArgs {
            dest: dest_as("operator"),
            host: "home-1".parse().unwrap(),
            config: self.file_in_temp("fleet.toml", FLEET),
            controller: CONTROLLER.to_owned(),
            allow_insecure_controller: true,
            code_file: None,
            tag: Some("v1.2.3".parse().unwrap()),
            dry_run: false,
            yes: true,
            replace_config: false,
            replace_unit: false,
            ssh_config: Some(self.ssh_config()),
            cache_dir: None,
            timing: TIMING,
        }
    }

    pub(crate) fn remote_as(&self, user: &str) -> OpenSsh {
        OpenSsh::new(
            Destination::parse(&dest_as(user)).unwrap(),
            Some(self.ssh_config()),
        )
        .unwrap()
    }

    /// An install by real `ssh`, whose script's output goes to this process's.
    pub(crate) fn install(&self, args: &InstallArgs) -> Ran {
        let remote = self.remote_as("operator");
        install_through(args, &FixedSource::real(), &remote, &mut Unattended)
    }

    /// An install by real `ssh`, with what the script said in its `out`.
    pub(crate) fn install_captured(&self, args: &InstallArgs, source: &FixedSource) -> Ran {
        let user = args.dest.split('@').next().unwrap();
        let remote = Captured::new(self.remote_as(user));
        let mut ran = install_through(args, source, &remote, &mut Unattended);
        ran.out.push_str(&text(&remote.said.borrow()));
        ran
    }

    /// An install from nothing that went well, for a test of what comes after one.
    pub(crate) fn installed(&self) {
        self.install(&self.args()).assert_ok();
        assert_eq!(self.unit_state(), "active");
    }

    pub(crate) fn unit_state(&self) -> String {
        let ran = self.sh("systemctl is-active landfall-agent");
        text(&ran.stdout).trim().to_owned()
    }

    pub(crate) fn main_start(&self) -> String {
        self.sh_ok("systemctl show -p ExecMainStartTimestamp --value landfall-agent")
    }

    pub(crate) fn key(&self) -> String {
        self.sh_ok(&format!("sha256sum {KEY_PATH}"))
    }

    pub(crate) fn stop_unit(&self) {
        self.sh_ok("systemctl stop landfall-agent");
    }

    /// What the controller has written down.
    pub(crate) fn audit(&self) -> String {
        self.sh_ok(&format!("{SERVER} audit show --db {SERVER_DB}"))
    }

    /// How many times anyone has logged in over SSH.
    pub(crate) fn logins(&self) -> usize {
        self.login_log().len()
    }

    /// `sshd`'s line for each login, with its time.
    pub(crate) fn login_log(&self) -> Vec<String> {
        let log = self
            .sh_ok("journalctl --sync; journalctl -u ssh.service --no-pager -q -o short-precise");
        log.lines()
            .filter(|line| line.contains("Accepted publickey"))
            .map(str::to_owned)
            .collect()
    }

    /// How the machine stands, in text that two machines installed alike share.
    pub(crate) fn end_state(&self) -> String {
        self.sh_ok(&format!(
            "stat -c '%n %u:%g %a' {AGENT_PATH} {CONFIG_PATH} {UNIT_PATH} {RECOVER_PATH} {STATE_DIR} {KEY_PATH}
sha256sum {AGENT_PATH} {CONFIG_PATH} {UNIT_PATH} {RECOVER_PATH}
getent passwd landfall-agent
id -nG landfall-agent
systemctl is-active landfall-agent
systemctl is-enabled landfall-agent
ls -A /etc/landfall {STATE_DIR}
ls -A /tmp | grep landfall-install || echo no upload
ls -A /usr/local/bin /etc/systemd/system | grep -E '\\.new$|\\.previous' || echo no leftovers"
        ))
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        // There is nothing to do about it here, and the label says what it was.
        let _ = docker(&["rm", "-f", "-v", &self.id]);
    }
}

#[track_caller]
pub(crate) fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let start = Instant::now();
    while !done() {
        assert!(
            start.elapsed() < Duration::from_secs(90),
            "waiting for {what}"
        );
        std::thread::sleep(Duration::from_millis(100));
    }
}

pub(crate) fn dest_as(user: &str) -> String {
    format!("{user}@127.0.0.1")
}

/// The steps of an install of the real agent, for a script a test puts together itself.
pub(crate) fn steps(upload: &str, code: bool, replace_config: bool) -> Vec<Step> {
    let controller = ControllerUrl::parse(CONTROLLER, true).unwrap();
    let host: HostId = "home-1".parse().unwrap();
    let unit = agent_unit(&UnitInput {
        controller: &controller,
        host: &host,
        allow_insecure: true,
        compose_dirs: &[COMPOSE_DIR],
    });
    let recover = recover_unit(&[COMPOSE_DIR]);
    let sha256 = sha256_hex(&real_agent());
    let config_sha256 = sha256_hex(FLEET.as_bytes());
    install_steps(&InstallRequest {
        sha256: &sha256,
        version: "1.2.3",
        config_sha256: &config_sha256,
        replace_config,
        replace_unit: false,
        enrol: code.then_some(EnrolTarget {
            controller: &controller,
            host: &host,
            allow_insecure: true,
        }),
        unit: &unit,
        recover_unit: &recover,
        upload,
        timing: TIMING,
    })
}

/// Puts what a script reads in `upload`, as the command does.
pub(crate) fn upload<R: Remote>(remote: &R, upload: &str, code: Option<&Path>) {
    upload_files(remote, upload, FLEET.as_bytes(), code);
}

/// The same, with another configuration.
pub(crate) fn upload_with_config<R: Remote>(remote: &R, upload: &str, config: &[u8]) {
    upload_files(remote, upload, config, None);
}

fn upload_files<R: Remote>(remote: &R, upload: &str, config: &[u8], code: Option<&Path>) {
    let sent = |command: &str, stdin: &[u8]| {
        let output = remote.run(&remote_command(command), stdin).unwrap();
        assert_eq!(output.status, 0, "{command}: {}", text(&output.stderr));
    };
    sent(
        &format!("umask 077 && mkdir -m 700 -- {}", quote(upload)),
        b"",
    );
    let file = |name: &str| format!("umask 077 && cat > {}", quote(&format!("{upload}/{name}")));
    sent(&file(UPLOAD_AGENT), &real_agent());
    sent(&file(UPLOAD_CONFIG), config);
    if let Some(code) = code {
        sent(&file(UPLOAD_CODE), &fs::read(code).unwrap());
    }
}
pub(crate) fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .fold(String::new(), |mut hex, byte| {
            write!(hex, "{byte:02x}").unwrap();
            hex
        })
}

/// The upload directory a test's own script uses.
pub(crate) const UPLOAD: &str = "/tmp/landfall-install.0123456789abcdef0123456789abcdef";
