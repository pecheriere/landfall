//! The system's `ssh`, never a library, so that the operator's agent, jumps and hardware keys all
//! work and no key material comes near landfall.
//!
//! Every call forces the options that keep a user's configuration from weakening it, over one
//! connection. A time limit holds every call, but for the privileged step at a terminal, where a
//! person can stop it. A connection that has gone away is ended by its keepalive.

use std::cell::Cell;
use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs::{self, File};
use std::io::{self, Read, Write as _};
use std::net::Ipv6Addr;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::{Duration, Instant};

use landfall_core::text::{quoted, shown};

use super::shell::privileged_command;

/// The most of a command's stdout, or of its stderr, that is kept.
const MAX_OUTPUT: u64 = 1024 * 1024;

/// How much of ssh's stderr an error shows.
const SHOWN_STDERR: usize = 400;

/// How long the rest of a command's output may take once ssh has ended. Something ssh started,
/// such as a `ProxyCommand`, can hold the pipe for far longer.
const OUTPUT_GRACE: Duration = Duration::from_secs(5);

/// How often a child with a time limit is looked at.
const POLL: Duration = Duration::from_millis(20);

/// How slowly an upload is allowed to go, in bytes a second, before it is called hung.
const SLOWEST_UPLOAD: u64 = 32 * 1024;

/// `ssh` with no way to weaken it from a configuration. The first of each option is the one that
/// counts, and these come before any configuration is read. `-G` output for each is in
/// `tests/ssh.rs`. `ControlPath` and `ControlMaster` go by the call, in [`args`].
const FORCED: [&str; 21] = [
    // First, for a build without the option that comes next but one.
    "IgnoreUnknown=NoHostAuthenticationForProxyCommand",
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "NoHostAuthenticationForLocalhost=no",
    "NoHostAuthenticationForProxyCommand=no",
    "VerifyHostKeyDNS=no",
    "UpdateHostKeys=no",
    "ForwardAgent=no",
    "ForwardX11=no",
    "ForwardX11Trusted=no",
    "AddKeysToAgent=no",
    "Tunnel=no",
    "ClearAllForwardings=yes",
    "PermitLocalCommand=no",
    "RemoteCommand=none",
    "EscapeChar=none",
    // A configuration's `QUIET` would hide the host key message that is read.
    "LogLevel=ERROR",
    "ConnectTimeout=30",
    // A connection that has gone away ends within a minute or so, privileged step included.
    "ServerAliveInterval=15",
    "ServerAliveCountMax=4",
    "ControlPersist=60",
];

/// Why `ssh` couldn't do what was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// Not `[user@]host` or `ssh://[user@]host[:port]`.
    #[error(
        "{} isn't a destination: it must be [user@]host or ssh://[user@]host[:port], with letters, digits, `.`, `_` and `-`, or a bracketed IPv6 address",
        shown(.0)
    )]
    BadDestination(String),
    /// The private directory for the connection couldn't be made.
    #[error("cannot make a private directory for the connection")]
    ControlDir(#[source] io::Error),
    /// `ssh` couldn't be started.
    #[error("cannot run ssh")]
    Spawn(#[source] io::Error),
    /// The target's key isn't the one `known_hosts` has.
    #[error(
        "the target's host key is unknown or has changed, so nothing ran there. landfall never accepts a key itself: connect once by hand with ssh, and compare the fingerprint with the host's own. ssh said {}",
        quoted(.0, SHOWN_STDERR)
    )]
    HostKey(String),
    /// No connection, or it was lost.
    #[error("the SSH connection failed: ssh said {}", quoted(.0, SHOWN_STDERR))]
    Connection(String),
    /// It took too long, and was stopped.
    #[error("ssh took more than {0} s, and was stopped")]
    TimedOut(u64),
}

/// Whether a call has a terminal, for `sudo`'s prompt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tty {
    /// No terminal.
    Never,
    /// A terminal, whatever `ssh` would otherwise have decided.
    Force,
}

/// Where to connect. What it holds can't reach a `ProxyCommand ... %h` as anything but a name,
/// and can't be read as an option.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Destination {
    user: Option<String>,
    host: String,
    port: Option<u16>,
}

impl Destination {
    /// Reads `[user@]host` or `ssh://[user@]host[:port]`.
    ///
    /// # Errors
    ///
    /// [`SshError::BadDestination`] for anything else.
    pub fn parse(text: &str) -> Result<Self, SshError> {
        let refused = || SshError::BadDestination(text.to_owned());
        let (rest, is_uri) = match text.strip_prefix("ssh://") {
            Some(rest) => (rest, true),
            None => (text, false),
        };
        let (user, rest) = match rest.split_once('@') {
            Some((user, rest)) if is_name(user) => (Some(user.to_owned()), rest),
            Some(_) => return Err(refused()),
            None => (None, rest),
        };
        let (host, port) = if is_uri {
            split_port(rest).ok_or_else(refused)?
        } else {
            (rest, None)
        };
        let host = match host.strip_prefix('[') {
            Some(inner) => {
                let address = inner.strip_suffix(']').ok_or_else(refused)?;
                address.parse::<Ipv6Addr>().map_err(|_| refused())?;
                address
            }
            None if is_name(host) => host,
            None => return Err(refused()),
        };
        Ok(Self {
            user,
            host: host.to_owned(),
            port,
        })
    }
}

impl fmt::Display for Destination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if let Some(user) = &self.user {
            write!(f, "{user}@")?;
        }
        if self.host.contains(':') {
            write!(f, "[{}]", self.host)?;
        } else {
            f.write_str(&self.host)?;
        }
        if let Some(port) = self.port {
            write!(f, ":{port}")?;
        }
        Ok(())
    }
}

fn is_name(text: &str) -> bool {
    !text.is_empty()
        && !text.starts_with('-')
        && text
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// The host and port of what follows the `ssh://`.
fn split_port(rest: &str) -> Option<(&str, Option<u16>)> {
    let (host, port) = if rest.starts_with('[') {
        match rest.split_once("]:") {
            Some((inner, port)) => (rest.get(..=inner.len())?, Some(port)),
            None => (rest, None),
        }
    } else {
        match rest.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (rest, None),
        }
    };
    match port {
        None => Some((host, None)),
        Some(port) => {
            let port = port.parse::<u16>().ok().filter(|port| *port != 0)?;
            Some((host, Some(port)))
        }
    }
}

/// The options forced on every call, in order.
#[must_use]
pub fn options(tty: Tty) -> Vec<&'static str> {
    let mut options = FORCED.to_vec();
    options.push(match tty {
        Tty::Never => "RequestTTY=no",
        Tty::Force => "RequestTTY=force",
    });
    options
}

/// The options, then `--` and the host, so that nothing after can be read as an option.
fn with_options(
    first: &[&str],
    dest: &Destination,
    control: &Path,
    config: Option<&Path>,
    tty: Tty,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = first.iter().map(OsString::from).collect();
    if let Some(config) = config {
        args.push("-F".into());
        args.push(config.into());
    }
    for option in options(tty) {
        args.push("-o".into());
        args.push(option.into());
    }
    args.push("-o".into());
    let mut path = OsString::from("ControlPath=");
    path.push(control);
    args.push(path);
    if let Some(user) = &dest.user {
        args.push("-l".into());
        args.push(user.into());
    }
    if let Some(port) = dest.port {
        args.push("-p".into());
        args.push(port.to_string().into());
    }
    args
}

fn with_host(mut args: Vec<OsString>, dest: &Destination) -> Vec<OsString> {
    args.push("--".into());
    args.push((&dest.host).into());
    args
}

/// What `ssh` is given to run `command` over the connection at `control`.
#[must_use]
pub fn args(
    dest: &Destination,
    control: &Path,
    config: Option<&Path>,
    tty: Tty,
    command: &str,
) -> Vec<OsString> {
    let mut args = with_options(&[], dest, control, config, tty);
    args.push("-o".into());
    args.push("ControlMaster=no".into());
    let mut args = with_host(args, dest);
    args.push(command.into());
    args
}

/// What `ssh` is given to start the connection at `control`, which then goes to the background.
fn master_args(dest: &Destination, control: &Path, config: Option<&Path>) -> Vec<OsString> {
    with_host(
        with_options(&["-fNM"], dest, control, config, Tty::Never),
        dest,
    )
}

/// What `ssh` is given to close the connection at `control`.
fn exit_args(dest: &Destination, control: &Path, config: Option<&Path>) -> Vec<OsString> {
    with_host(
        with_options(&["-O", "exit"], dest, control, config, Tty::Never),
        dest,
    )
}

/// What came of a command on the target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Output {
    /// Its exit status.
    pub status: i32,
    /// Its stdout, up to 1 MiB. Hostile.
    pub stdout: Vec<u8>,
    /// Its stderr, up to 1 MiB. Hostile.
    pub stderr: Vec<u8>,
}

/// The target, as `host install` reaches it.
pub trait Remote {
    /// Runs `command` in the login's shell, with `stdin` as its input.
    ///
    /// # Errors
    ///
    /// [`SshError`] if it couldn't run: a command that failed is an [`Output`].
    fn run(&self, command: &str, stdin: &[u8]) -> Result<Output, SshError>;

    /// Runs `script` as root, through `sudo` unless the login is root, with this process's
    /// stdio, which is how `sudo`'s prompt reaches a person. `interactive` is whether there is
    /// one to prompt: without, `sudo` won't ask. The status is the script's.
    ///
    /// # Errors
    ///
    /// [`SshError`] if it couldn't run, or the connection was lost.
    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError>;
}

/// How long `ssh` may take for what isn't the privileged step.
#[derive(Debug, Clone, Copy)]
pub(super) struct Limits {
    /// To connect, including a hardware key's touch.
    pub(super) connect: Duration,
    /// For a command with no input to speak of.
    pub(super) command: Duration,
    /// To close the connection.
    pub(super) close: Duration,
    /// For the privileged step when nobody is there to stop it. With a person at a terminal
    /// there is no limit: `sudo`'s prompt waits for them, and they can stop it.
    pub(super) unattended_script: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            connect: Duration::from_secs(120),
            command: Duration::from_secs(120),
            close: Duration::from_secs(10),
            unattended_script: Duration::from_mins(30),
        }
    }
}

/// The operator's own `ssh`, over one connection, started when first needed and closed on drop.
#[derive(Debug)]
pub struct OpenSsh {
    program: OsString,
    dest: Destination,
    config: Option<PathBuf>,
    limits: Limits,
    /// Private to this user. Under `/tmp`, as a macOS `TMPDIR` is too long for a socket.
    dir: tempfile::TempDir,
    started: Cell<bool>,
}

impl OpenSsh {
    /// For `dest`, with `config` as its `ssh_config` if given. This connects to nothing yet.
    ///
    /// # Errors
    ///
    /// [`SshError::ControlDir`] if the private directory can't be made.
    pub fn new(dest: Destination, config: Option<PathBuf>) -> Result<Self, SshError> {
        Self::with_program("ssh".as_ref(), dest, config, Limits::default())
    }

    /// With another `ssh` and other limits, for a test's fake.
    pub(super) fn with_program(
        program: &OsStr,
        dest: Destination,
        config: Option<PathBuf>,
        limits: Limits,
    ) -> Result<Self, SshError> {
        let dir = tempfile::Builder::new()
            .prefix("landfall-ssh.")
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir_in("/tmp")
            .map_err(SshError::ControlDir)?;
        Ok(Self {
            program: program.to_owned(),
            dest,
            config,
            limits,
            dir,
            started: Cell::new(false),
        })
    }

    fn control(&self) -> PathBuf {
        self.dir.path().join("c")
    }

    /// `ssh`, without what must never go to a target.
    pub(super) fn command(&self, args: Vec<OsString>) -> Command {
        let mut command = Command::new(&self.program);
        command.args(args).env_remove("GITHUB_TOKEN");
        command
    }

    /// Starts the connection if it isn't up. Its stderr goes to a file, as a pipe would stay open
    /// for as long as it lives.
    fn connect(&self) -> Result<(), SshError> {
        if self.started.get() {
            return Ok(());
        }
        let stderr_path = self.dir.path().join("connect.stderr");
        let stderr = File::create(&stderr_path).map_err(SshError::ControlDir)?;
        let mut command = self.command(master_args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
        ));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        let mut child = command.spawn().map_err(SshError::Spawn)?;
        let status = wait_within(&mut child, self.limits.connect)?;
        if status.success() {
            self.started.set(true);
            Ok(())
        } else {
            let said = fs::read(&stderr_path).unwrap_or_default();
            Err(lost(&said))
        }
    }
}

impl Remote for OpenSsh {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<Output, SshError> {
        self.connect()?;
        let args = args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            Tty::Never,
            command,
        );
        let limit = self.limits.command + upload_time(stdin.len());
        let output = collect(self.command(args), stdin, limit)?;
        if output.status == SSH_FAILED {
            return Err(lost(&output.stderr));
        }
        Ok(output)
    }

    fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError> {
        self.connect()?;
        let tty = if interactive { Tty::Force } else { Tty::Never };
        let args = args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            tty,
            &privileged_command(script, interactive),
        );
        let mut child = self.command(args).spawn().map_err(SshError::Spawn)?;
        let status = if interactive {
            child.wait().map_err(SshError::Spawn)?
        } else {
            wait_within(&mut child, self.limits.unattended_script)?
        };
        match status.code() {
            Some(SSH_FAILED) => Err(SshError::Connection(
                "the connection was lost during the script".to_owned(),
            )),
            Some(status) => Ok(status),
            None => Err(SshError::Connection(
                "ssh was stopped by a signal".to_owned(),
            )),
        }
    }
}

impl Drop for OpenSsh {
    fn drop(&mut self) {
        if !self.started.get() {
            return;
        }
        let mut command = self.command(exit_args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
        ));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // It ends by itself soon enough if this fails, and nothing here could be done about it.
        if let Ok(mut child) = command.spawn() {
            let _ = wait_within(&mut child, self.limits.close);
        }
    }
}

/// What `ssh` itself exits with when it fails. A command's own 255 reads the same, which is why
/// nothing landfall runs there exits with it.
const SSH_FAILED: i32 = 255;

fn lost(stderr: &[u8]) -> SshError {
    let said = String::from_utf8_lossy(stderr).trim().to_owned();
    if said.contains("Host key verification failed") {
        SshError::HostKey(said)
    } else {
        SshError::Connection(said)
    }
}

/// How much longer `bytes` of input may take.
fn upload_time(bytes: usize) -> Duration {
    Duration::from_secs(u64::try_from(bytes).unwrap_or(u64::MAX) / SLOWEST_UPLOAD)
}

fn wait_within(child: &mut Child, limit: Duration) -> Result<ExitStatus, SshError> {
    let deadline = Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().map_err(SshError::Spawn)? {
            return Ok(status);
        }
        if Instant::now() >= deadline {
            // It may just have ended, and this is the only thing that could be done either way.
            let _ = child.kill();
            let _ = child.wait();
            return Err(SshError::TimedOut(limit.as_secs()));
        }
        thread::sleep(POLL);
    }
}

/// Runs `command` to its end within `limit`, writing `stdin` from a thread, as a command that
/// reads nothing until it has written must not hold this up, and keeping what is kept of its
/// output.
fn collect(mut command: Command, stdin: &[u8], limit: Duration) -> Result<Output, SshError> {
    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let mut child = command.spawn().map_err(SshError::Spawn)?;
    if let Some(mut pipe) = child.stdin.take() {
        let stdin = stdin.to_vec();
        thread::spawn(move || {
            // A command may well not read it all. Dropping the pipe is its end of input.
            let _ = pipe.write_all(&stdin);
        });
    }
    let stdout = child.stdout.take().map(read_capped);
    let stderr = child.stderr.take().map(read_capped);
    let status = wait_within(&mut child, limit)?;
    let Some(status) = status.code() else {
        return Err(SshError::Connection(
            "ssh was stopped by a signal".to_owned(),
        ));
    };
    let grace_ends = Instant::now() + OUTPUT_GRACE;
    let kept = |output: Option<Receiver<Vec<u8>>>| {
        output
            .and_then(|output| {
                output
                    .recv_timeout(grace_ends.saturating_duration_since(Instant::now()))
                    .ok()
            })
            .unwrap_or_default()
    };
    Ok(Output {
        status,
        stdout: kept(stdout),
        stderr: kept(stderr),
    })
}

/// Keeps the first [`MAX_OUTPUT`] of `pipe`, and reads the rest away so that its writer can end.
fn read_capped(mut pipe: impl Read + Send + 'static) -> Receiver<Vec<u8>> {
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut kept = Vec::new();
        // A pipe that fails has said all it will.
        let _ = pipe.by_ref().take(MAX_OUTPUT).read_to_end(&mut kept);
        let _ = io::copy(&mut pipe, &mut io::sink());
        // Whoever was waiting may have given up.
        let _ = sender.send(kept);
    });
    receiver
}
