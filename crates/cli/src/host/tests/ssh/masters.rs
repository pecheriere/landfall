//! A connection that has gone, or won't answer: a new one never meets the old one's socket, and
//! none is left behind.

use std::fs;
use std::net::TcpListener;
use std::os::unix::net::UnixListener;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::TempDir;

use super::{Fake, control_path_of, real_known, short};
use crate::host::ssh::{Destination, Remote, control_args};

fn lines_starting(fake: &Fake, start: &str) -> Vec<String> {
    fake.log()
        .into_iter()
        .filter(|line| line.starts_with(start))
        .collect()
}

/// `ssh` finds a path that's taken, turns multiplexing off, and logs in all the same, with
/// nothing then to end it and every later command logging in by itself.
#[test]
fn a_new_connection_never_meets_the_old_ones_socket() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();
    ssh.run("one", b"").unwrap();
    fake.expire_the_connection();

    ssh.run("two", b"").unwrap();
    ssh.run("three", b"").unwrap();

    let masters = lines_starting(&fake, "-fNM ");
    assert_eq!(masters.len(), 2);
    let (first, second) = (control_path_of(&masters[0]), control_path_of(&masters[1]));
    assert_ne!(first, second);
    assert_eq!(first.parent(), second.parent());
    let log = fake.log();
    let of_command = |name: &str| {
        let line = log.iter().find(|line| line.ends_with(name)).unwrap();
        control_path_of(line)
    };
    assert_eq!(of_command(" one"), first);
    assert_eq!(of_command(" two"), second);
    assert_eq!(of_command(" three"), second);
}

/// It may only be stalled, and then it mustn't stay logged in beside the new one.
#[test]
fn every_connection_started_is_closed() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();
    ssh.run("one", b"").unwrap();
    fake.expire_the_connection();
    ssh.run("two", b"").unwrap();
    drop(ssh);

    let masters: Vec<_> = lines_starting(&fake, "-fNM ")
        .iter()
        .map(|line| control_path_of(line))
        .collect();
    let closed: Vec<_> = lines_starting(&fake, "-O exit ")
        .iter()
        .map(|line| control_path_of(line))
        .collect();
    assert_eq!(closed, masters);
}

#[test]
fn a_check_that_hangs_holds_nothing_up() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open_with(short(Duration::from_secs(1)));
    ssh.run("one", b"").unwrap();
    fs::write(fake.dir.path().join("hang_check"), "").unwrap();
    let start = Instant::now();

    ssh.run("two", b"").unwrap();

    assert!(start.elapsed() < Duration::from_secs(20));
    assert_eq!(lines_starting(&fake, "-fNM ").len(), 2);
}

/// Takes connections on a socket, and on a port of loopback, and drops each at once, counting
/// those on the port.
struct Dropping {
    port: u16,
    reached: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
    threads: Vec<thread::JoinHandle<()>>,
}

impl Dropping {
    fn start(socket: &Path) -> Self {
        let unix = UnixListener::bind(socket).unwrap();
        let tcp = TcpListener::bind("127.0.0.1:0").unwrap();
        unix.set_nonblocking(true).unwrap();
        tcp.set_nonblocking(true).unwrap();
        let port = tcp.local_addr().unwrap().port();
        let reached = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let (unix_stop, tcp_stop) = (Arc::clone(&stop), Arc::clone(&stop));
        let counted = Arc::clone(&reached);
        let threads = vec![
            thread::spawn(move || {
                while !unix_stop.load(Ordering::Relaxed) {
                    match unix.accept() {
                        Ok((stream, _)) => drop(stream),
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            }),
            thread::spawn(move || {
                while !tcp_stop.load(Ordering::Relaxed) {
                    match tcp.accept() {
                        Ok((stream, _)) => {
                            counted.fetch_add(1, Ordering::Relaxed);
                            drop(stream);
                        }
                        Err(_) => thread::sleep(Duration::from_millis(5)),
                    }
                }
            }),
        ];
        Self {
            port,
            reached,
            stop,
            threads,
        }
    }

    fn reached(&self) -> usize {
        self.reached.load(Ordering::Relaxed)
    }
}

impl Drop for Dropping {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for thread in self.threads.drain(..) {
            let _ = thread.join();
        }
    }
}

/// A master killed outright still takes connections for an instant, and drops them unanswered.
/// The real `ssh` then connects to the host by itself, for `-O` as for a command, and a check that
/// logged in there and ran a shell would pass. A configuration's jump is no way round that.
#[test]
fn asking_a_socket_that_answers_nothing_reaches_nothing_else() {
    let dir = TempDir::new().unwrap();
    let socket = dir.path().join("c.1");
    let dropping = Dropping::start(&socket);
    let dest = Destination::parse(&format!("ssh://user@127.0.0.1:{}", dropping.port)).unwrap();
    let plain = dir.path().join("plain");
    fs::write(&plain, "").unwrap();
    let jump = dir.path().join("jump");
    fs::write(
        &jump,
        format!("Host *\n  ProxyJump user@127.0.0.1:{}\n", dropping.port),
    )
    .unwrap();
    let known = real_known();

    for config in [&plain, &jump] {
        for operation in ["check", "exit"] {
            let ran = Command::new("ssh")
                .args(control_args(
                    operation,
                    &dest,
                    &socket,
                    Some(config),
                    &known,
                ))
                .stdin(Stdio::null())
                .output()
                .unwrap();

            let said = String::from_utf8_lossy(&ran.stderr);
            let what = format!("{operation} with {}: {said}", config.display());
            assert!(!ran.status.success(), "{what}");
            assert_eq!(dropping.reached(), 0, "{what}");
        }
    }
}
