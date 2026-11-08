//! The connection: which keys it takes, what a configuration can't do to it, and how many there
//! are, seen from the target's own log and from what really comes back.

use std::cell::RefCell;
use std::io::Write as _;
use std::os::unix::net::UnixListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use landfall_cli::host::install::InstallArgs;
use landfall_cli::host::ssh::{OpenSsh, Remote};

use crate::harness::{FixedSource, SlowYes, Target, install_through, wait_until};

/// A run that stops for its host key: exit 2, saying `words`, with nobody having logged in.
fn assert_refused_for_its_key(target: &Target, words: &str) {
    let logins = target.logins();
    let ran = target.install_captured(&target.args_with_no_code(), &FixedSource::real());
    assert_eq!(ran.status(), 2, "{}\n{}", ran.error_text(), ran.out);
    assert!(ran.error_text().contains(words), "{}", ran.error_text());
    assert_eq!(target.logins(), logins, "it got as far as logging in");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_unknown_host_key_is_refused() {
    let target = Target::start();
    std::fs::write(&target.known_hosts, "").unwrap();

    assert_refused_for_its_key(&target, "connect once by hand");

    assert_eq!(std::fs::read(&target.known_hosts).unwrap(), b"");
}

#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_changed_host_key_is_refused() {
    let target = Target::start();
    target.write_another_host_key();

    assert_refused_for_its_key(&target, "has CHANGED");
    assert_refused_for_its_key(&target, "SHA256:");

    // Whatever a config would have it shown as.
    target.write_ssh_config("FingerprintHash md5");
    assert_refused_for_its_key(&target, "SHA256:");
}

/// One test run per line, and none gets past an unknown key, whatever `-G` might say.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_config_that_turns_off_checking_is_still_refused() {
    let target = Target::start();
    std::fs::write(&target.known_hosts, "").unwrap();
    let port = target.port();
    for line in [
        "StrictHostKeyChecking no".to_owned(),
        "UserKnownHostsFile /dev/null".to_owned(),
        "NoHostAuthenticationForLocalhost yes".to_owned(),
        format!(
            "IgnoreUnknown NoHostAuthenticationForProxyCommand\nNoHostAuthenticationForProxyCommand yes\nProxyCommand nc 127.0.0.1 {port}"
        ),
        "LogLevel QUIET".to_owned(),
        "IgnoreUnknown ForkAfterAuthentication\nForkAfterAuthentication yes".to_owned(),
        "IgnoreUnknown StdinNull\nStdinNull yes".to_owned(),
        "ControlMaster yes".to_owned(),
        "IgnoreUnknown UseKeychain,SomeOptionFromTheFuture\nUseKeychain yes\nSomeOptionFromTheFuture yes".to_owned(),
    ] {
        target.write_ssh_config(&line);
        assert_refused_for_its_key(&target, "connect once by hand");
    }
}

/// What a real connection does with each: `-G` shows a setting, and not its effect. With
/// `ForkAfterAuthentication` every status read 0 while the command went on running.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_config_changes_no_status_or_stream() {
    let target = Target::start();
    for line in [
        "",
        "IgnoreUnknown ForkAfterAuthentication\nForkAfterAuthentication yes",
        "IgnoreUnknown StdinNull\nStdinNull yes",
        "IgnoreUnknown SessionType\nSessionType none",
        "ControlMaster yes",
        "ControlMaster auto",
        "IgnoreUnknown UseKeychain,SomeOptionFromTheFuture\nUseKeychain yes\nSomeOptionFromTheFuture yes",
    ] {
        target.write_ssh_config(line);
        let logins = target.logins();
        let ssh = target.remote_as("operator");

        let output = ssh.run("echo said; echo also >&2; exit 3", b"").unwrap();
        assert_eq!(output.status, 3, "{line}");
        assert_eq!(output.stdout, b"said\n", "{line}");
        assert_eq!(output.stderr, b"also\n", "{line}");

        let output = ssh.run("cat", b"what was sent").unwrap();
        assert_eq!(output.stdout, b"what was sent", "{line}");

        assert_eq!(ssh.run_privileged("exit 3", false).unwrap(), 3, "{line}");
        // It ran to its end, and wasn't left going while this went on.
        let done = "/tmp/done";
        target.sh_ok(&format!("rm -f {done}"));
        assert_eq!(
            ssh.run_privileged(&format!("sleep 1; touch {done}; exit 4"), false)
                .unwrap(),
            4,
            "{line}"
        );
        assert!(target.exists(done), "{line}");
        drop(ssh);

        // One login for all of that, the closing of it included.
        assert_eq!(
            target.logins(),
            logins + 1,
            "{line}\n{:#?}",
            target.login_log()
        );
    }
}

/// The `ssh` processes on this machine for this test's connection, by its own `ssh_config`.
fn masters_of(target: &Target) -> Vec<String> {
    let found = Command::new("pgrep")
        .arg("-f")
        .arg(format!("^ssh -fNM -F {}", target.ssh_config().display()))
        .output()
        .unwrap();
    String::from_utf8_lossy(&found.stdout)
        .lines()
        .map(str::to_owned)
        .collect()
}

/// The logins since the machine started: `want` as a rule, and never more than `at_most`. A command
/// whose master has gone in that instant logs in by itself, the residual the design accepts, so
/// that's a note in the log for anyone who wants to read it and not a failure of a required job.
/// Told apart by what was said: a master's login has a line, and a command's own doesn't.
#[track_caller]
fn assert_logins(target: &Target, want: usize, at_most: usize, said: &[String]) {
    let log = target.login_log();
    if log.len() != want {
        let _ = writeln!(
            std::io::stderr().lock(),
            "landfall-test-note: {} logins where {want} are usual, and {} lines said:\n{log:#?}\n{said:#?}\nmasters: {:?}",
            log.len(),
            said.len(),
            masters_of(target)
        );
    }
    assert!(
        log.len() >= want && log.len() <= at_most,
        "{} logins, and {want} to {at_most} should be:\n{log:#?}\n{said:#?}",
        log.len()
    );
}

/// What `OpenSsh` says to the operator, kept, for counting.
fn saying_kept(target: &Target) -> (OpenSsh, Rc<RefCell<Vec<String>>>) {
    let said = Rc::new(RefCell::new(Vec::new()));
    let kept = Rc::clone(&said);
    let ssh = target
        .remote_as("operator")
        .saying(move |text| kept.borrow_mut().push(text.to_owned()));
    (ssh, said)
}

fn signal(signal: &str, pid: &str) {
    let sent = Command::new("kill")
        .args([format!("-{signal}"), pid.to_owned()])
        .status()
        .unwrap();
    assert!(sent.success());
}

/// `kill -9` of the master, which is this test's own and leaves its socket file. One more login
/// for all that follows, said beforehand, and nothing logged in left behind.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_master_killed_leaves_nothing_behind() {
    let target = Target::start();
    let (ssh, said) = saying_kept(&target);
    assert_eq!(ssh.run("exit 3", b"").unwrap().status, 3);
    assert_eq!(target.logins(), 1);
    assert_eq!(said.borrow().len(), 1);
    let masters = masters_of(&target);
    assert_eq!(masters.len(), 1, "{masters:?}");
    signal("KILL", &masters[0]);

    for status in [4, 5, 6] {
        let command = format!("exit {status}");
        assert_eq!(ssh.run(&command, b"").unwrap().status, status);
    }
    assert_eq!(ssh.run_privileged("exit 7", false).unwrap(), 7);

    // Far from the nine of a master started over the old one's socket, which logs in twice for
    // each thing asked. A check in the instant the old one is dying is the next test.
    assert_logins(&target, 2, 2, &said.borrow());
    assert_eq!(said.borrow().len(), 2, "{:?}", said.borrow());
    assert!(said.borrow()[1].contains("approve it if your key or agent asks"));
    wait_until("one connection", || masters_of(&target).len() == 1);
    drop(ssh);
    wait_until("the connection to end", || masters_of(&target).is_empty());
}

/// The `-o ControlPath=` of the `ssh` with pid `pid`.
fn control_path_of(pid: &str) -> PathBuf {
    let ran = Command::new("ps")
        .args(["-o", "command=", "-p", pid])
        .output()
        .unwrap();
    let line = String::from_utf8(ran.stdout).unwrap();
    let path = line
        .split(' ')
        .find_map(|word| word.strip_prefix("ControlPath="))
        .unwrap_or_else(|| panic!("no ControlPath in {line:?}"));
    PathBuf::from(path)
}

/// Takes connections on `socket` and drops each unanswered, until dropped.
struct Unanswered {
    stop: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Unanswered {
    fn at(socket: &Path) -> Self {
        let listener = UnixListener::bind(socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        let thread = thread::spawn(move || {
            while !stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => drop(stream),
                    Err(_) => thread::sleep(Duration::from_millis(5)),
                }
            }
        });
        Self {
            stop,
            thread: Some(thread),
        }
    }
}

impl Drop for Unanswered {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// A master killed outright takes connections for an instant after the kill, and drops them
/// unanswered, which is when a check may come. Here a socket that does that stands in for it, for
/// the rest of the run: `ssh` would log in by itself for each check, which passed, and for each
/// command. One login more, said beforehand, and nothing else.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_master_dying_as_it_is_checked_costs_one_connection() {
    let target = Target::start();
    let (ssh, said) = saying_kept(&target);
    assert_eq!(ssh.run("exit 3", b"").unwrap().status, 3);
    let masters = masters_of(&target);
    assert_eq!(masters.len(), 1, "{masters:?}");
    let socket = control_path_of(&masters[0]);
    signal("KILL", &masters[0]);
    wait_until("the master to end", || masters_of(&target).is_empty());
    std::fs::remove_file(&socket).unwrap();
    let unanswered = Unanswered::at(&socket);

    for status in [4, 5, 6] {
        let command = format!("exit {status}");
        assert_eq!(ssh.run(&command, b"").unwrap().status, status);
    }
    assert_eq!(ssh.run_privileged("exit 7", false).unwrap(), 7);

    assert_logins(&target, 2, 2, &said.borrow());
    assert_eq!(said.borrow().len(), 2, "{:?}", said.borrow());
    wait_until("one connection", || masters_of(&target).len() == 1);
    drop(ssh);
    drop(unanswered);
    wait_until("the connection to end", || masters_of(&target).is_empty());
}

/// A master alive and not answering, which `-O check` waits on until its limit: the install goes
/// on over a new one. Asking it to exit waits out its limit too, and that client is killed, so
/// the old one goes by `ControlPersist`, 60 s after it can run again, which is most of this test.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_master_that_stalls_holds_nothing_up() {
    let target = Target::start();
    let (ssh, said) = saying_kept(&target);
    assert_eq!(ssh.run("exit 3", b"").unwrap().status, 3);
    let masters = masters_of(&target);
    assert_eq!(masters.len(), 1, "{masters:?}");
    let stalled = masters[0].clone();
    signal("STOP", &stalled);

    let start = Instant::now();
    let status = ssh.run("exit 4", b"").map(|output| output.status);
    let took = start.elapsed();
    // Before anything is asserted, so that a failure doesn't leave it stopped.
    signal("CONT", &stalled);

    assert_eq!(status.unwrap(), 4);
    assert!(took < Duration::from_secs(60), "{took:?}");
    assert_eq!(ssh.run("exit 5", b"").unwrap().status, 5);
    assert_logins(&target, 2, 3, &said.borrow());
    assert!(said.borrow().len() >= 2, "{:?}", said.borrow());
    drop(ssh);
    // The old one by `ControlPersist`, 60 s after `SIGCONT`, within the wait's 90.
    wait_until("both connections to end", || masters_of(&target).is_empty());
}

/// The connection goes when `ControlPersist` is up, with someone still reading the script at
/// `y/N`. What follows costs one more approval, and not one for each command.
#[test]
#[ignore = "needs Docker, LANDFALL_TEST_DIST and the image: see README.md"]
fn docker_a_slow_answer_costs_one_more_connection() {
    let target = Target::start();
    let args = InstallArgs {
        yes: false,
        ..target.args()
    };
    let (remote, said) = saying_kept(&target);
    let mut slow = SlowYes {
        pause: Duration::from_secs(70),
    };

    let ran = install_through(&args, &FixedSource::real(), &remote, &mut slow);

    ran.assert_ok();
    assert_eq!(target.unit_state(), "active");
    drop(remote);
    assert_logins(&target, 2, 3, &said.borrow());
}
