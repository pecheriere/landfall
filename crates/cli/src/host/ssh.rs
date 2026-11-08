//! The system's `ssh`, never a library, so that the operator's agent, jumps and hardware keys all
//! work and no key material comes near landfall.
//!
//! Every call forces the options that keep a user's configuration from weakening it, over one
//! connection. A time limit holds every call, but for the privileged step at a terminal, where a
//! person can stop it. That limit only ends `ssh`: without a terminal, the target isn't told, and
//! the script there goes on until its next output fails. A connection that has gone away is ended
//! by its keepalive.

use std::cell::{Cell, OnceCell};
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

/// What keeps a configuration from weakening `ssh`, or changing what comes back from it. The
/// first of each option is the one that counts, and these come before any configuration is read.
/// `-G` output for each is in `tests/ssh.rs`. `ControlPath` and `ControlMaster` go by the call, in
/// [`args`], and only [`control_args`] has a `ProxyCommand`.
const FORCED: [&str; 21] = [
    "BatchMode=yes",
    "StrictHostKeyChecking=yes",
    "NoHostAuthenticationForLocalhost=no",
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
    "VisualHostKey=no",
    // What's shown of a changed key, and what the guide says to compare it with.
    "FingerprintHash=sha256",
    // A configuration's `QUIET` would hide the host key message that is read.
    "LogLevel=ERROR",
    "ConnectTimeout=30",
    // A connection that has gone away ends within a minute or so, privileged step included.
    "ServerAliveInterval=15",
    "ServerAliveCountMax=4",
    "ControlPersist=60",
];

/// The same, for what not every build of `ssh` has: on one that hasn't, a configuration can't say
/// it either, and forcing it would be fatal. An `IgnoreUnknown` can't be forced to get round that,
/// as it would replace the operator's own, so [`Known::ask`] finds out which there are.
///
/// In a configuration, the second makes every status 0 while the command goes on running, the
/// third gives every upload no input, and the fourth and fifth can leave a command unrun or cut
/// off. The last forwards credentials as `ForwardAgent` does. A build without GSSAPI takes it, and
/// says on every call that it does nothing, ahead of anything else it has to say.
const IN_SOME_BUILDS: [&str; 6] = [
    "NoHostAuthenticationForProxyCommand=no",
    "ForkAfterAuthentication=no",
    "StdinNull=no",
    "SessionType=default",
    "ChannelTimeout=none",
    "GSSAPIDelegateCredentials=no",
];

/// How long `ssh -G` may take to say what it knows, which needs no network.
const ASK_LIMIT: Duration = Duration::from_secs(10);

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
    /// `ssh` failed when asked what it has, for some reason other than not having it. That's
    /// not guessed at, as an option left out would be a config's to set.
    #[error("ssh couldn't say which options it has: it said {}", quoted(.0, SHOWN_STDERR))]
    CannotAsk(String),
    /// `ssh` couldn't be started.
    #[error("cannot run ssh")]
    Spawn(#[source] io::Error),
    /// `known_hosts` has no key for the target.
    #[error(
        "the target's host key isn't known, so nothing ran there. landfall never accepts a key itself: connect once by hand with ssh, and compare the fingerprint with the host's own. ssh said {}",
        quoted(.0, SHOWN_STDERR)
    )]
    HostKey(String),
    /// The target's key isn't the one `known_hosts` has.
    #[error(
        "the target's host key has CHANGED, so nothing ran there. It may have been reinstalled, or something may be in between. Compare this with the host's own fingerprint, by some other way than this connection, before removing the old key with ssh-keygen -R: {}",
        quoted(.0, SHOWN_STDERR)
    )]
    HostKeyChanged(String),
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

/// Which of the forced options that not every build of `ssh` has, this machine's has.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Known(Vec<&'static str>);

impl Known {
    /// Asks `program`, with no configuration and no connection, about each.
    ///
    /// # Errors
    ///
    /// [`SshError`] if it can't be run, takes too long to say, or fails for any reason other than
    /// not having an option.
    pub fn ask(program: &OsStr) -> Result<Self, SshError> {
        Self::ask_within(program, ASK_LIMIT)
    }

    /// The same, with this long for each question.
    pub(super) fn ask_within(program: &OsStr, limit: Duration) -> Result<Self, SshError> {
        let ask = |options: &[&str]| {
            let mut command = Command::new(program);
            command
                .args(["-G", "-F", "none"])
                .args(options)
                .args(["--", "x"])
                .env_remove("GITHUB_TOKEN");
            collect(command, b"", limit)
        };
        let plain = ask(&[])?;
        if plain.status != 0 {
            return Err(SshError::CannotAsk(text_of(&plain.stderr)));
        }
        let mut known = Vec::new();
        for option in IN_SOME_BUILDS {
            let answer = ask(&["-o", option])?;
            let said = text_of(&answer.stderr);
            if said.contains("Bad configuration option") || said.contains("Unsupported option") {
                continue;
            }
            if answer.status != 0 {
                return Err(SshError::CannotAsk(said));
            }
            known.push(option);
        }
        Ok(Self(known))
    }

    /// Whether `ssh` has `option`, as in [`options`].
    #[must_use]
    pub fn has(&self, option: &str) -> bool {
        self.0.contains(&option)
    }
}

/// The options forced on every call, in order.
#[must_use]
pub fn options(tty: Tty, known: &Known) -> Vec<&'static str> {
    let mut options = FORCED.to_vec();
    options.extend(&known.0);
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
    known: &Known,
) -> Vec<OsString> {
    let mut args: Vec<OsString> = first.iter().map(OsString::from).collect();
    if let Some(config) = config {
        args.push("-F".into());
        args.push(config.into());
    }
    for option in options(tty, known) {
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
    known: &Known,
    command: &str,
) -> Vec<OsString> {
    let mut args = with_host(client_options(&[], dest, control, config, tty, known), dest);
    args.push(command.into());
    args
}

/// A client of the connection, and never one, whatever a configuration says: it would log in
/// again, which is another approval, or start a master holding this call's streams.
fn client_options(
    first: &[&str],
    dest: &Destination,
    control: &Path,
    config: Option<&Path>,
    tty: Tty,
    known: &Known,
) -> Vec<OsString> {
    let mut args = with_options(first, dest, control, config, tty, known);
    args.push("-o".into());
    args.push("ControlMaster=no".into());
    args
}

/// What `ssh` is given to start the connection at `control`, which then goes to the background.
/// What's first here is what counts, so it isn't affected by what's forced for a command.
pub(super) fn master_args(
    dest: &Destination,
    control: &Path,
    config: Option<&Path>,
    known: &Known,
) -> Vec<OsString> {
    with_host(
        with_options(&["-fNM"], dest, control, config, Tty::Never, known),
        dest,
    )
}

/// What `ssh` is given to ask the connection at `control` to do `operation`, which reaches
/// nothing but its socket. A socket that takes the question and drops it, as a master killed that
/// instant does, has `ssh` connect to the host by itself: a check would log in, run a shell and
/// pass. A proxy that fails, ahead of any a configuration has, ends that before anything is sent.
pub(super) fn control_args(
    operation: &str,
    dest: &Destination,
    control: &Path,
    config: Option<&Path>,
    known: &Known,
) -> Vec<OsString> {
    let mut args = client_options(&["-O", operation], dest, control, config, Tty::Never, known);
    args.push("-o".into());
    args.push("ProxyCommand=false".into());
    with_host(args, dest)
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

/// The operator's own `ssh`, over one connection, started when first needed, started again if it
/// has ended by the next time it's needed, and closed on drop. A person at `y/N` for more than
/// `ControlPersist` is the ordinary way for it to end, and with each command then logging in by
/// itself, an agent or a hardware key would ask once for each.
///
/// Each has a socket of its own. A killed one leaves its file, and `ssh` starting at a path that's
/// taken turns multiplexing off and logs in all the same, which nothing would then ever end.
pub struct OpenSsh {
    program: OsString,
    dest: Destination,
    config: Option<PathBuf>,
    limits: Limits,
    /// Private to this user. Under `/tmp`, as a macOS `TMPDIR` is too long for a socket.
    dir: tempfile::TempDir,
    known: OnceCell<Known>,
    started: Cell<bool>,
    /// Which connection this is, for its socket's name.
    generation: Cell<u32>,
    say: Box<dyn Fn(&str)>,
}

impl fmt::Debug for OpenSsh {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpenSsh")
            .field("dest", &self.dest)
            .field("config", &self.config)
            .field("started", &self.started)
            .finish_non_exhaustive()
    }
}

/// Says it on stderr: nothing more can be done if that fails.
fn say_on_stderr(text: &str) {
    let _ = writeln!(io::stderr().lock(), "{text}");
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
            known: OnceCell::new(),
            started: Cell::new(false),
            generation: Cell::new(0),
            say: Box::new(say_on_stderr),
        })
    }

    /// With what's said to the operator going to `say`, rather than stderr.
    #[must_use]
    pub fn saying(mut self, say: impl Fn(&str) + 'static) -> Self {
        self.say = Box::new(say);
        self
    }

    /// The `ssh_config` it was given.
    #[cfg(test)]
    pub(super) fn config(&self) -> Option<&Path> {
        self.config.as_deref()
    }

    fn control(&self) -> PathBuf {
        self.dir.path().join(format!("c.{}", self.generation.get()))
    }

    /// `ssh`, without what must never go to a target.
    pub(super) fn command(&self, args: Vec<OsString>) -> Command {
        let mut command = Command::new(&self.program);
        command.args(args).env_remove("GITHUB_TOKEN");
        command
    }

    fn known(&self) -> Result<&Known, SshError> {
        if let Some(known) = self.known.get() {
            return Ok(known);
        }
        let known = Known::ask(&self.program)?;
        Ok(self.known.get_or_init(|| known))
    }

    /// Whether the connection is still there, asking only its socket.
    pub(super) fn alive(&self, known: &Known) -> bool {
        let mut command = self.command(control_args(
            "check",
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            known,
        ));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let Ok(mut child) = command.spawn() else {
            return false;
        };
        wait_within(&mut child, self.limits.close).is_ok_and(|status| status.success())
    }

    /// Starts the connection if it isn't up, and says so first: in `BatchMode`, `ssh` itself says
    /// nothing of a key that wants a touch, or an agent that wants an approval. Its stderr goes to
    /// a file, as a pipe would stay open for as long as it lives.
    fn connect(&self) -> Result<&Known, SshError> {
        let known = self.known()?;
        if self.started.get() {
            if self.alive(known) {
                return Ok(known);
            }
            // It may only be stalled. If so and this doesn't reach it, it can still end by itself,
            // having a socket of its own, as `ControlPersist` needs.
            self.close(known);
            self.started.set(false);
        }
        self.generation.set(self.generation.get() + 1);
        (self.say)(&format!(
            "landfall: opening an SSH connection to {}: approve it if your key or agent asks",
            self.dest
        ));
        let stderr_path = self.dir.path().join("connect.stderr");
        let stderr = File::create(&stderr_path).map_err(SshError::ControlDir)?;
        let mut command = self.command(master_args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            known,
        ));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(stderr);
        let mut child = command.spawn().map_err(SshError::Spawn)?;
        let status = wait_within(&mut child, self.limits.connect)?;
        if status.success() {
            self.started.set(true);
            Ok(known)
        } else {
            let said = fs::read(&stderr_path).unwrap_or_default();
            Err(lost(&said))
        }
    }

    /// Asks the connection to end. It ends by itself soon enough if this fails, and nothing here
    /// could be done about it.
    fn close(&self, known: &Known) {
        let mut command = self.command(control_args(
            "exit",
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            known,
        ));
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Ok(mut child) = command.spawn() {
            let _ = wait_within(&mut child, self.limits.close);
        }
    }
}

impl Remote for OpenSsh {
    fn run(&self, command: &str, stdin: &[u8]) -> Result<Output, SshError> {
        let known = self.connect()?;
        let args = args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            Tty::Never,
            known,
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
        let known = self.connect()?;
        let tty = if interactive { Tty::Force } else { Tty::Never };
        let args = args(
            &self.dest,
            &self.control(),
            self.config.as_deref(),
            tty,
            known,
            &privileged_command(script, interactive),
        );
        let mut command = self.command(args);
        // With nobody to prompt, what's piped in here is the next thing's, as in a loop over hosts.
        if !interactive {
            command.stdin(Stdio::null());
        }
        let mut child = command.spawn().map_err(SshError::Spawn)?;
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
        if let (true, Some(known)) = (self.started.get(), self.known.get()) {
            self.close(known);
        }
    }
}

/// What `ssh` itself exits with when it fails. A command's own 255 reads the same, which is why
/// nothing landfall runs there exits with it.
const SSH_FAILED: i32 = 255;

fn lost(stderr: &[u8]) -> SshError {
    let said = text_of(stderr);
    if said.contains("REMOTE HOST IDENTIFICATION HAS CHANGED") {
        // The banner would otherwise use up all that's shown, before the part worth seeing.
        let fingerprint: Vec<&str> = said.lines().filter(|l| l.contains("SHA256:")).collect();
        SshError::HostKeyChanged(fingerprint.join(" "))
    } else if said.contains("Host key verification failed") {
        SshError::HostKey(said)
    } else {
        SshError::Connection(said)
    }
}

fn text_of(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
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
