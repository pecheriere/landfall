//! A connection that has gone, or won't answer: a new one never meets the old one's socket, and
//! none is left behind.

use std::fs;
use std::time::{Duration, Instant};

use super::{Fake, control_path_of, short};
use crate::host::ssh::Remote;

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
