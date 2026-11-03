//! What `ssh` is given, what the real one makes of it offline, and what comes back from a fake on
//! `PATH`. Nothing here connects to anything.

use std::cell::RefCell;
use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::rc::Rc;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::write_executable;
use crate::host::shell::privileged_command;
use crate::host::ssh::{
    Destination, Known, Limits, OpenSsh, Remote, SshError, Tty, args, control_args, master_args,
    options,
};

mod asking;
mod masters;
mod streams;

const HOSTILE_CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/host/tests/hostile_ssh_config"
);

const KEYCHAIN_CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/host/tests/keychain_ssh_config"
);

/// What this machine's real `ssh` knows.
fn real_known() -> Known {
    Known::ask("ssh".as_ref()).unwrap()
}

/// What the real `ssh` makes of `args`: it connects to nothing with `-G`.
fn resolved(args: &[OsString]) -> Result<String, String> {
    let ran = Command::new("ssh").arg("-G").args(args).output().unwrap();
    if ran.status.success() {
        Ok(String::from_utf8(ran.stdout).unwrap())
    } else {
        Err(String::from_utf8_lossy(&ran.stderr).into_owned())
    }
}

fn value<'a>(said: &'a str, key: &str) -> Option<&'a str> {
    said.lines()
        .find_map(|line| line.strip_prefix(&format!("{key} ")))
}

fn text(args: &[OsString]) -> Vec<String> {
    args.iter()
        .map(|arg| arg.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn destination_table() {
    for bad in [
        "",
        "-oProxyCommand=x",
        "user@-x",
        "-user@host",
        "ssh://-x",
        "ssh://-u@host",
        "ssh://user@-x:22",
        "a;b",
        "$(x)",
        "user@$(x)",
        "`x`",
        "a b",
        "a\nb",
        "user@",
        "@host",
        "ssh://",
        "a@b@c",
        "host:22",
        "ssh://host:0",
        "ssh://host:65536",
        "ssh://host:x",
        "ssh://host/path",
        "[not-an-address]",
        "user@[2001:db8::1",
        "2001:db8::1",
        "ssh://user@[::1]x:22",
        "http://host",
    ] {
        assert!(
            matches!(Destination::parse(bad), Err(SshError::BadDestination(_))),
            "{bad:?}"
        );
    }
    for (good, shown) in [
        ("host.example", "host.example"),
        ("user@host.example", "user@host.example"),
        ("a_b-c.d@host-1", "a_b-c.d@host-1"),
        ("user@[2001:db8::1]", "user@[2001:db8::1]"),
        ("ssh://host.example", "host.example"),
        ("ssh://user@host.example:2222", "user@host.example:2222"),
        ("ssh://[::1]:2222", "[::1]:2222"),
        ("ssh://user@[2001:db8::1]", "user@[2001:db8::1]"),
    ] {
        assert_eq!(Destination::parse(good).unwrap().to_string(), shown);
    }
}

#[test]
fn forced_options_come_before_the_destination() {
    let dest = Destination::parse("ssh://user@host.example:2222").unwrap();
    let args = text(&args(
        &dest,
        Path::new("/tmp/control"),
        Some(Path::new("/some/config")),
        Tty::Never,
        &Known::default(),
        "the command",
    ));

    let separator = args.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(args[separator + 1..], ["host.example", "the command"]);
    let before = &args[..separator];
    for option in options(Tty::Never, &Known::default()) {
        let at = before.iter().position(|arg| arg == option);
        assert!(at.is_some_and(|at| before[at - 1] == "-o"), "{option}");
    }
    for pair in [
        ["-F", "/some/config"],
        ["-l", "user"],
        ["-p", "2222"],
        ["-o", "ControlPath=/tmp/control"],
        ["-o", "ControlMaster=no"],
    ] {
        assert!(before.windows(2).any(|found| found == pair), "{pair:?}");
    }
}

/// The list itself, as a new one wouldn't otherwise be noticed in a review.
#[test]
fn the_forced_options_are_these() {
    assert_eq!(
        options(Tty::Never, &Known::default()),
        [
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
            "FingerprintHash=sha256",
            "LogLevel=ERROR",
            "ConnectTimeout=30",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=4",
            "ControlPersist=60",
            "RequestTTY=no",
        ]
    );
    assert_eq!(
        options(Tty::Force, &Known::default()).last(),
        Some(&"RequestTTY=force")
    );
}

/// An `IgnoreUnknown` here would replace the operator's, and what theirs protects would be fatal.
#[test]
fn the_operators_ignore_unknown_is_left_to_them() {
    let known = real_known();
    assert!(
        !options(Tty::Never, &known)
            .iter()
            .any(|o| o.starts_with("IgnoreUnknown"))
    );
    let dest = Destination::parse("user@host.example").unwrap();
    let config = Some(Path::new(KEYCHAIN_CONFIG));
    let control = Path::new("/tmp/ours");
    for args in [
        args(&dest, control, config, Tty::Never, &known, "true"),
        master_args(&dest, control, config, &known),
    ] {
        assert_eq!(value(&resolved(&args).unwrap(), "user"), Some("user"));
    }
}

/// The real `ssh`, offline: `-G` says what it resolved, and connects to nothing.
#[test]
fn forced_options_hold_against_a_hostile_config() {
    let known = real_known();
    let dest = Destination::parse("user@host.example").unwrap();
    let config = Some(Path::new(HOSTILE_CONFIG));
    let control = Path::new("/tmp/ours");
    for (tty, requesttty) in [(Tty::Never, "false"), (Tty::Force, "force")] {
        let said = resolved(&args(&dest, control, config, tty, &known, "true")).unwrap();

        for (key, want) in [
            ("batchmode", "yes"),
            ("stricthostkeychecking", "true"),
            ("nohostauthenticationforlocalhost", "no"),
            ("verifyhostkeydns", "false"),
            ("updatehostkeys", "false"),
            ("forwardagent", "no"),
            ("forwardx11", "no"),
            ("forwardx11trusted", "no"),
            ("addkeystoagent", "false"),
            ("tunnel", "false"),
            ("clearallforwardings", "yes"),
            ("permitlocalcommand", "no"),
            ("escapechar", "none"),
            ("visualhostkey", "no"),
            ("fingerprinthash", "SHA256"),
            ("loglevel", "ERROR"),
            ("connecttimeout", "30"),
            ("serveraliveinterval", "15"),
            ("serveralivecountmax", "4"),
            ("requesttty", requesttty),
            ("controlpath", "/tmp/ours"),
            ("controlmaster", "false"),
            ("controlpersist", "60"),
            ("user", "user"),
            ("hostname", "host.example"),
        ] {
            assert_eq!(value(&said, key), Some(want), "{key}\n{said}");
        }
        // Only where this build has them, which it can't say otherwise.
        for (option, key, want) in [
            (
                "NoHostAuthenticationForProxyCommand=no",
                "nohostauthenticationforproxycommand",
                "no",
            ),
            (
                "ForkAfterAuthentication=no",
                "forkafterauthentication",
                "no",
            ),
            ("StdinNull=no", "stdinnull", "no"),
            ("SessionType=default", "sessiontype", "default"),
            ("ChannelTimeout=none", "channeltimeout", "none"),
        ] {
            if known.has(option) {
                assert_eq!(value(&said, key), Some(want), "{key}\n{said}");
            }
        }
        // Only on a build with GSSAPI, and every one that has it has the option.
        if let Some(found) = value(&said, "gssapidelegatecredentials") {
            assert_eq!(found, "no");
        }
        for gone in [
            "localforward",
            "remoteforward",
            "dynamicforward",
            "remotecommand",
        ] {
            assert_eq!(value(&said, gone), None, "{gone}\n{said}");
        }
    }
}

/// The master is what is forked, with no session, and what's forced for a command doesn't undo it.
#[test]
fn the_master_is_itself_against_a_hostile_config() {
    let known = real_known();
    let dest = Destination::parse("user@host.example").unwrap();
    let control = Path::new("/tmp/ours");
    let said = resolved(&master_args(
        &dest,
        control,
        Some(Path::new(HOSTILE_CONFIG)),
        &known,
    ))
    .unwrap();
    assert_eq!(value(&said, "controlmaster"), Some("true"), "{said}");
    assert_eq!(value(&said, "controlpath"), Some("/tmp/ours"), "{said}");
    for (option, key, want) in [
        (
            "ForkAfterAuthentication=no",
            "forkafterauthentication",
            "yes",
        ),
        ("StdinNull=no", "stdinnull", "yes"),
        ("SessionType=default", "sessiontype", "none"),
    ] {
        if known.has(option) {
            assert_eq!(value(&said, key), Some(want), "{key}\n{said}");
        }
    }
}

/// With a configuration's `ControlMaster yes`, these would skip the socket and log in again.
#[test]
fn asking_the_connection_is_only_ever_a_client() {
    let known = real_known();
    let dest = Destination::parse("user@host.example").unwrap();
    for operation in ["check", "exit"] {
        let args = control_args(
            operation,
            &dest,
            Path::new("/tmp/ours"),
            Some(Path::new(HOSTILE_CONFIG)),
            &known,
        );
        let said = resolved(&args).unwrap();
        assert_eq!(value(&said, "controlmaster"), Some("false"), "{said}");
    }
}

/// The real `ssh`, with no connection there: it answers from the socket's absence, at once, with
/// no network, as it must not log in to find out.
#[test]
fn a_connection_that_is_not_there_is_seen_with_nothing_sent() {
    let ssh = OpenSsh::new(
        Destination::parse("user@host.invalid").unwrap(),
        Some(HOSTILE_CONFIG.into()),
    )
    .unwrap();
    let start = Instant::now();
    assert!(!ssh.alive(&real_known()));
    assert!(start.elapsed() < Duration::from_secs(8));
}

/// A fake `ssh` that logs its arguments, answers for the connection by what's in its directory,
/// and otherwise runs `remote` there as the command.
struct Fake {
    dir: TempDir,
}

impl Fake {
    fn new(remote: &str) -> Self {
        let fake = Self {
            dir: TempDir::new().unwrap(),
        };
        let dir = fake.dir.path().display();
        write_executable(
            &fake.dir.path().join("ssh"),
            &format!(
                r#"if [ "$1" = -G ]; then
  printf '%s\n' "$*" >> {dir}/asked
  if [ -e {dir}/hang_ask ]; then exec sleep 30; fi
  for name in $(cat {dir}/unknown 2>/dev/null); do
    case "$*" in *"$name"=*) echo "line 0: Bad configuration option: $name" >&2; exit 255 ;; esac
  done
  for name in $(cat {dir}/unsupported 2>/dev/null); do
    case "$*" in *"$name"=*) echo "line 0: Unsupported option \"$name\"" >&2; exit 0 ;; esac
  done
  if [ -e {dir}/ask_fails ]; then
    case "$*" in *"$(cat {dir}/ask_fails)"*) cat {dir}/ask_says >&2; exit 255 ;; esac
  fi
  exit 0
fi
if [ "$1 $2" = "-O check" ]; then
  printf '%s\n' "$*" >> {dir}/checks
  if [ -e {dir}/hang_check ]; then exec sleep 30; fi
  if [ -e {dir}/alive ]; then exit 0; else exit 255; fi
fi
printf '%s\n' "$*" >> {dir}/log
printf '%s' "${{GITHUB_TOKEN-unset}}" > {dir}/token
case "$1" in
  -fNM)
    if [ -e {dir}/master ]; then . {dir}/master; fi
    : > {dir}/alive
    exit 0
    ;;
  -O) exit 0 ;;
esac
. {dir}/remote"#
            ),
        );
        fake.set_remote(remote);
        fake
    }

    fn set_remote(&self, shell: &str) {
        fs::write(self.dir.path().join("remote"), shell).unwrap();
    }

    fn set_unknown(&self, names: &[&str]) {
        fs::write(self.dir.path().join("unknown"), names.join(" ")).unwrap();
    }

    fn set_unsupported(&self, name: &str) {
        fs::write(self.dir.path().join("unsupported"), name).unwrap();
    }

    /// Asking about what holds `matching` fails, saying `says`.
    fn set_ask_failure(&self, matching: &str, says: &str) {
        fs::write(self.dir.path().join("ask_fails"), matching).unwrap();
        fs::write(self.dir.path().join("ask_says"), says).unwrap();
    }

    /// As `ControlPersist` does.
    fn expire_the_connection(&self) {
        fs::remove_file(self.dir.path().join("alive")).unwrap();
    }

    fn connections(&self) -> usize {
        self.log()
            .iter()
            .filter(|line| line.starts_with("-fNM "))
            .count()
    }

    fn set_master(&self, shell: &str) {
        fs::write(self.dir.path().join("master"), shell).unwrap();
    }

    fn open(&self) -> OpenSsh {
        self.open_with(Limits::default())
    }

    fn open_with(&self, limits: Limits) -> OpenSsh {
        OpenSsh::with_program(
            self.dir.path().join("ssh").as_os_str(),
            Destination::parse("user@host.example").unwrap(),
            None,
            limits,
        )
        .unwrap()
    }

    fn log(&self) -> Vec<String> {
        fs::read_to_string(self.dir.path().join("log"))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

fn control_path_of(log_line: &str) -> PathBuf {
    let path = log_line
        .split(' ')
        .find_map(|word| word.strip_prefix("ControlPath="))
        .unwrap();
    PathBuf::from(path)
}

fn control_dir(log_line: &str) -> PathBuf {
    control_path_of(log_line).parent().unwrap().to_owned()
}

#[test]
fn nothing_connects_until_something_is_asked() {
    let fake = Fake::new("");
    drop(fake.open());
    assert_eq!(fake.log(), Vec::<String>::new());
}

#[test]
fn one_connection_comes_first_and_is_closed_at_the_end() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();

    ssh.run("one", b"").unwrap();
    ssh.run("two", b"").unwrap();
    let dir = control_dir(&fake.log()[0]);
    assert!(dir.starts_with("/tmp"), "{}", dir.display());
    let mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode, 0o700);
    drop(ssh);

    let log = fake.log();
    assert_eq!(log.len(), 4, "{log:?}");
    assert!(log[0].starts_with("-fNM "), "{log:?}");
    assert!(log[1].ends_with(" one"), "{log:?}");
    assert!(log[2].ends_with(" two"), "{log:?}");
    assert!(log[3].starts_with("-O exit "), "{log:?}");
    assert!(log[3].contains("ControlMaster=no"), "{log:?}");
    assert!(log.iter().all(|line| line.contains(" -- host.example")));
    assert!(log[1].contains("ControlMaster=no"), "{log:?}");
    assert!(!log[0].contains("ControlMaster=no"), "{log:?}");
    assert!(!dir.exists());
}

/// A person at `y/N` for more than a minute: one more approval, and not one for each command.
#[test]
fn a_connection_that_has_ended_is_started_again_once() {
    let fake = Fake::new("exit 0");
    let said = Rc::new(RefCell::new(Vec::new()));
    let saying = Rc::clone(&said);
    let ssh = fake
        .open()
        .saying(move |text| saying.borrow_mut().push(text.to_owned()));

    ssh.run("one", b"").unwrap();
    assert_eq!(fake.connections(), 1);
    ssh.run("two", b"").unwrap();
    assert_eq!(fake.connections(), 1);

    fake.expire_the_connection();
    for command in ["three", "four", "five"] {
        ssh.run(command, b"").unwrap();
    }
    assert_eq!(ssh.run_privileged("six", false).unwrap(), 0);
    assert_eq!(fake.connections(), 2);

    // The privileged step can be the first to find it gone.
    fake.expire_the_connection();
    assert_eq!(ssh.run_privileged("seven", false).unwrap(), 0);
    assert_eq!(fake.connections(), 3);

    // Each said beforehand, for a key to touch or an agent to approve, which `ssh` won't say.
    let said = said.borrow();
    assert_eq!(said.len(), 3, "{said:?}");
    assert!(
        said.iter()
            .all(|line| line.contains("approve it if your key or agent asks"))
    );
    assert!(said.iter().all(|line| line.contains("user@host.example")));
    let checks = fs::read_to_string(fake.dir.path().join("checks")).unwrap();
    assert!(
        checks.lines().all(|line| line.contains("ControlMaster=no")),
        "{checks}"
    );
}

#[test]
fn a_connection_that_cannot_be_started_again_is_an_error() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();
    ssh.run("one", b"").unwrap();
    fake.expire_the_connection();
    fake.set_master("echo 'No route to host' >&2\nexit 255");

    let error = ssh.run("two", b"").unwrap_err();

    assert!(matches!(error, SshError::Connection(_)), "{error:?}");
    assert!(!fake.log().iter().any(|line| line.ends_with(" two")));
}

#[test]
fn github_token_is_not_passed_to_ssh() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();
    let command = ssh.command(Vec::new());
    assert!(
        command
            .get_envs()
            .any(|(name, value)| name == "GITHUB_TOKEN" && value.is_none())
    );
    ssh.run("the command", b"").unwrap();
    assert_eq!(
        fs::read_to_string(fake.dir.path().join("token")).unwrap(),
        "unset"
    );
    assert!(!fake.log().iter().any(|line| line.contains("GITHUB_TOKEN")));
}

#[test]
fn a_host_key_failure_says_what_to_do() {
    for (fake, stage) in [
        (Fake::new(""), "connect"),
        (
            Fake::new("echo 'Host key verification failed.' >&2\nexit 255"),
            "command",
        ),
    ] {
        if stage == "connect" {
            fake.set_master("echo 'Host key verification failed.' >&2\nexit 255");
        }
        let error = fake.open().run("the command", b"").unwrap_err();
        assert!(matches!(error, SshError::HostKey(_)), "{stage}: {error:?}");
        assert!(
            error.to_string().contains("connect once by hand"),
            "{error}"
        );
    }
}

#[test]
fn a_changed_host_key_shows_its_fingerprint_and_says_it_changed() {
    let fake = Fake::new("");
    let banner = "@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@\n".repeat(10);
    fake.set_master(&format!(
        "cat >&2 <<'SAID'\n{banner}@    WARNING: REMOTE HOST IDENTIFICATION HAS CHANGED!     @\nThe fingerprint for the ED25519 key sent by the remote host is\nSHA256:abcdefghijklmnopqrstuvwxyz.\nHost key verification failed.\nSAID\nexit 255"
    ));

    let error = fake.open().run("the command", b"").unwrap_err();

    assert!(matches!(error, SshError::HostKeyChanged(_)), "{error:?}");
    let text = error.to_string();
    assert!(text.contains("SHA256:abcdefghijklmnopqrstuvwxyz"), "{text}");
    assert!(text.contains("CHANGED"), "{text}");
    assert!(!text.contains("connect once by hand"), "{text}");
}

#[test]
fn a_failed_connection_is_told_from_a_failed_command() {
    let fake = Fake::new("");
    fake.set_master("echo 'No route to host' >&2\nexit 255");
    let error = fake.open().run("the command", b"").unwrap_err();
    assert!(matches!(error, SshError::Connection(_)), "{error:?}");
    assert!(error.to_string().contains("No route to host"), "{error}");
    // It never got as far as the command.
    assert_eq!(fake.log().len(), 1);

    let fake = Fake::new("echo 'Connection reset' >&2\nexit 255");
    let error = fake.open().run("the command", b"").unwrap_err();
    assert!(matches!(error, SshError::Connection(_)), "{error:?}");

    let fake = Fake::new("echo out; echo err >&2; exit 3");
    let output = fake.open().run("the command", b"").unwrap();
    assert_eq!(output.status, 3);
    assert_eq!(output.stdout, b"out\n");
    assert_eq!(output.stderr, b"err\n");
}

/// `ssh` being killed mustn't read as anything having worked: for `sudo -n true` that's a pass.
#[test]
fn a_command_stopped_by_a_signal_is_not_a_status() {
    let fake = Fake::new("kill -9 $$");
    let error = fake.open().run("the command", b"").unwrap_err();
    assert!(matches!(error, SshError::Connection(_)), "{error:?}");
}

#[test]
fn input_reaches_the_command() {
    let fake = Fake::new("cat");
    let output = fake.open().run("the command", b"what was sent").unwrap();
    assert_eq!(output.stdout, b"what was sent");
    assert!(!fake.log().iter().any(|line| line.contains("what was sent")));
}

/// More than a pipe holds, to a command that reads none of it.
#[test]
fn input_that_is_not_read_holds_nothing_up() {
    let fake = Fake::new("exit 0");
    let output = fake.open().run("x", &vec![b'x'; 4 * 1024 * 1024]).unwrap();
    assert_eq!(output.status, 0);
}

/// More output than a pipe holds before it has read any input, which it then wants all of.
#[test]
fn a_command_that_writes_before_it_reads_holds_nothing_up() {
    let fake = Fake::new("head -c 3145728 /dev/zero\ncat > /dev/null\nexit 0");
    let output = fake.open().run("x", &vec![b'x'; 4 * 1024 * 1024]).unwrap();
    assert_eq!(output.status, 0);
}

#[test]
fn output_is_capped_and_the_command_still_ends() {
    let fake = Fake::new(
        "head -c 3145728 /dev/zero || exit 9\nhead -c 3145728 /dev/zero >&2 || exit 9\nexit 0",
    );
    let output = fake.open().run("the command", b"").unwrap();
    assert_eq!(output.status, 0);
    assert_eq!(output.stdout.len(), 1024 * 1024);
    assert_eq!(output.stderr.len(), 1024 * 1024);
}

fn short(limit: Duration) -> Limits {
    Limits {
        connect: limit,
        command: limit,
        close: limit,
        unattended_script: limit,
    }
}

/// Whether the process with the pid in `file` is still there. Asks, and sends it nothing.
fn still_running(file: &Path) -> bool {
    let pid = fs::read_to_string(file).unwrap();
    Command::new("kill")
        .args(["-0", pid.trim()])
        .stderr(Stdio::null())
        .status()
        .unwrap()
        .success()
}

#[test]
fn a_command_that_hangs_is_stopped() {
    let fake = Fake::new("");
    let pid = fake.dir.path().join("pid");
    fake.set_remote(&format!("echo $$ > {}\nexec sleep 30", pid.display()));
    let start = Instant::now();
    let error = fake
        .open_with(short(Duration::from_secs(1)))
        .run("the command", b"")
        .unwrap_err();
    assert!(matches!(error, SshError::TimedOut(1)), "{error:?}");
    assert!(start.elapsed() < Duration::from_secs(20));
    // The limit is worth nothing if it only stops this from waiting.
    assert!(!still_running(&pid));
}

#[test]
fn a_connection_that_hangs_is_stopped() {
    let fake = Fake::new("");
    fake.set_master("exec sleep 30");
    let start = Instant::now();
    let error = fake
        .open_with(short(Duration::from_secs(1)))
        .run("the command", b"")
        .unwrap_err();
    assert!(matches!(error, SshError::TimedOut(1)), "{error:?}");
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// An upload's time goes by its size, or a slow link couldn't send a binary.
#[test]
fn a_large_input_has_longer() {
    let fake = Fake::new("sleep 2; cat > /dev/null");
    let output = fake
        .open_with(short(Duration::from_secs(1)))
        .run("the command", &vec![b'x'; 128 * 1024])
        .unwrap();
    assert_eq!(output.status, 0);
}

/// Something ssh started, such as a `ProxyCommand`, may keep its pipes open after it ends.
#[test]
fn a_child_holding_its_output_does_not_hold_up_the_result() {
    let fake = Fake::new("sleep 40 &\nexit 0");
    let start = Instant::now();
    let output = fake.open().run("the command", b"").unwrap();
    assert_eq!(output.status, 0);
    assert!(start.elapsed() < Duration::from_secs(20));
}

#[test]
fn the_privileged_step_goes_as_one_command_with_a_terminal_if_there_is_one() {
    for (interactive, tty) in [(true, "RequestTTY=force"), (false, "RequestTTY=no")] {
        let fake = Fake::new("exit 3");
        let ssh = fake.open();

        assert_eq!(ssh.run_privileged("the script", interactive).unwrap(), 3);

        let log = fake.log();
        assert!(log[0].starts_with("-fNM "), "{log:?}");
        assert!(log[1].contains(tty), "{log:?}");
        assert!(
            log[1].ends_with(&format!(
                " -- host.example {}",
                privileged_command("the script", interactive)
            )),
            "{log:?}"
        );
    }
}

#[test]
fn an_unattended_script_that_hangs_is_stopped() {
    let fake = Fake::new("exec sleep 30");
    let start = Instant::now();
    let error = fake
        .open_with(short(Duration::from_secs(1)))
        .run_privileged("the script", false)
        .unwrap_err();
    assert!(matches!(error, SshError::TimedOut(1)), "{error:?}");
    assert!(start.elapsed() < Duration::from_secs(20));
}

/// A person is there to answer `sudo`, for as long as they take.
#[test]
fn a_script_at_a_terminal_has_no_limit() {
    let fake = Fake::new("sleep 2; exit 7");
    let status = fake
        .open_with(short(Duration::from_secs(1)))
        .run_privileged("the script", true)
        .unwrap();
    assert_eq!(status, 7);
}

#[test]
fn a_lost_connection_in_the_privileged_step_is_not_a_status() {
    let fake = Fake::new("exit 255");
    let error = fake.open().run_privileged("the script", false).unwrap_err();
    assert!(matches!(error, SshError::Connection(_)), "{error:?}");

    let fake = Fake::new("kill -9 $$");
    let error = fake.open().run_privileged("the script", false).unwrap_err();
    assert!(matches!(error, SshError::Connection(_)), "{error:?}");
}
