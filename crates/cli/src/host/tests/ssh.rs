//! What `ssh` is given, what the real one makes of it offline, and what comes back from a fake on
//! `PATH`. Nothing here connects to anything.

use std::ffi::OsString;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::write_executable;
use crate::host::shell::privileged_command;
use crate::host::ssh::{Destination, Limits, OpenSsh, Remote, SshError, Tty, args, options};

const HOSTILE_CONFIG: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/src/host/tests/hostile_ssh_config"
);

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
        "the command",
    ));

    let separator = args.iter().position(|arg| arg == "--").unwrap();
    assert_eq!(args[separator + 1..], ["host.example", "the command"]);
    let before = &args[..separator];
    for option in options(Tty::Never) {
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

/// The list itself, as a new one wouldn't otherwise be noticed in a review, and the order matters
/// for its first.
#[test]
fn the_forced_options_are_these() {
    assert_eq!(
        options(Tty::Never),
        [
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
            "LogLevel=ERROR",
            "ConnectTimeout=30",
            "ServerAliveInterval=15",
            "ServerAliveCountMax=4",
            "ControlPersist=60",
            "RequestTTY=no",
        ]
    );
    assert_eq!(options(Tty::Force).last(), Some(&"RequestTTY=force"));
}

/// The real `ssh`, offline: `-G` says what it resolved, and connects to nothing.
#[test]
fn forced_options_hold_against_a_hostile_config() {
    let dest = Destination::parse("user@host.example").unwrap();
    for (tty, requesttty) in [(Tty::Never, "false"), (Tty::Force, "force")] {
        let args = args(
            &dest,
            Path::new("/tmp/ours"),
            Some(Path::new(HOSTILE_CONFIG)),
            tty,
            "true",
        );
        let ran = Command::new("ssh").arg("-G").args(&args).output().unwrap();
        let said = String::from_utf8(ran.stdout).unwrap();
        assert!(
            ran.status.success(),
            "{}",
            String::from_utf8_lossy(&ran.stderr)
        );
        let value = |key: &str| {
            said.lines()
                .find_map(|line| line.strip_prefix(&format!("{key} ")))
        };

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
            assert_eq!(value(key), Some(want), "{key}\n{said}");
        }
        // Not every build has it, and `IgnoreUnknown` lets those by.
        if let Some(found) = value("nohostauthenticationforproxycommand") {
            assert_eq!(found, "no");
        }
        for gone in [
            "localforward",
            "remoteforward",
            "dynamicforward",
            "remotecommand",
        ] {
            assert_eq!(value(gone), None, "{gone}\n{said}");
        }
    }
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
                r#"printf '%s\n' "$*" >> {dir}/log
printf '%s' "${{GITHUB_TOKEN-unset}}" > {dir}/token
case "$1" in
  -fNM)
    if [ -e {dir}/master ]; then . {dir}/master; fi
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

fn control_dir(log_line: &str) -> PathBuf {
    let path = log_line
        .split(' ')
        .find_map(|word| word.strip_prefix("ControlPath="))
        .unwrap();
    Path::new(path).parent().unwrap().to_owned()
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
    assert!(log.iter().all(|line| line.contains(" -- host.example")));
    assert!(log[1].contains("ControlMaster=no"), "{log:?}");
    assert!(!log[0].contains("ControlMaster=no"), "{log:?}");
    assert!(!dir.exists());
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

#[test]
fn a_command_that_hangs_is_stopped() {
    let fake = Fake::new("exec sleep 30");
    let start = Instant::now();
    let error = fake
        .open_with(short(Duration::from_secs(1)))
        .run("the command", b"")
        .unwrap_err();
    assert!(matches!(error, SshError::TimedOut(1)), "{error:?}");
    assert!(start.elapsed() < Duration::from_secs(20));
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
