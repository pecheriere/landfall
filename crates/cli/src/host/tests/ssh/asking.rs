//! What `ssh` is asked about what it has: any failure but not knowing an option is an error, as an
//! option left out on a build that has it would be `ForkAfterAuthentication`'s false exit 0 again.

use std::fs;
use std::time::{Duration, Instant};

use super::{Fake, options};
use crate::host::ssh::{Known, Remote, SshError, Tty};

/// Every option that not every build has.
const ALL: [&str; 6] = [
    "NoHostAuthenticationForProxyCommand=no",
    "ForkAfterAuthentication=no",
    "StdinNull=no",
    "SessionType=default",
    "ChannelTimeout=none",
    "GSSAPIDelegateCredentials=no",
];

fn asked(fake: &Fake) -> Known {
    Known::ask(fake.dir.path().join("ssh").as_os_str()).unwrap()
}

fn asked_lines(fake: &Fake) -> Vec<String> {
    fs::read_to_string(fake.dir.path().join("asked"))
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect()
}

#[test]
fn what_a_build_of_ssh_has_is_asked() {
    let fake = Fake::new("");
    let known = asked(&fake);
    for option in ALL {
        assert!(known.has(option), "{option}");
        assert!(options(Tty::Never, &known).contains(&option), "{option}");
    }
    // It's asked with no configuration of the operator's, and only offline.
    let lines = asked_lines(&fake);
    assert_eq!(lines.len(), ALL.len() + 1, "{lines:?}");
    assert_eq!(lines[0], "-G -F none -- x");
    assert!(lines.iter().all(|line| line.starts_with("-G -F none ")));
}

#[test]
fn an_option_is_only_left_out_when_ssh_says_it_has_not_got_it() {
    let fake = Fake::new("");
    fake.set_unknown(&["StdinNull", "ChannelTimeout"]);
    // Accepted, and said to do nothing, as a build without GSSAPI says on every call.
    fake.set_unsupported("GSSAPIDelegateCredentials");
    let known = asked(&fake);
    for option in ALL {
        let has = !["StdinNull", "ChannelTimeout", "GSSAPIDelegateCredentials"]
            .iter()
            .any(|name| option.starts_with(name));
        assert_eq!(known.has(option), has, "{option}");
        assert_eq!(
            options(Tty::Never, &known).contains(&option),
            has,
            "{option}"
        );
    }
}

#[test]
fn any_other_failure_of_ssh_is_an_error() {
    let fake = Fake::new("");
    fake.set_ask_failure("SessionType", "something else went wrong");
    let error = Known::ask(fake.dir.path().join("ssh").as_os_str()).unwrap_err();
    assert!(matches!(error, SshError::CannotAsk(_)), "{error:?}");
    assert!(error.to_string().contains("something else"), "{error}");

    let fake = Fake::new("");
    fake.set_ask_failure("-F none -- x", "ssh is broken");
    let error = Known::ask(fake.dir.path().join("ssh").as_os_str()).unwrap_err();
    assert!(matches!(error, SshError::CannotAsk(_)), "{error:?}");
}

#[test]
fn asking_that_hangs_is_stopped() {
    let fake = Fake::new("");
    fs::write(fake.dir.path().join("hang_ask"), "").unwrap();
    let start = Instant::now();
    let error = Known::ask_within(
        fake.dir.path().join("ssh").as_os_str(),
        Duration::from_secs(1),
    )
    .unwrap_err();
    assert!(matches!(error, SshError::TimedOut(1)), "{error:?}");
    assert!(start.elapsed() < Duration::from_secs(20));
}

#[test]
fn it_is_asked_once() {
    let fake = Fake::new("exit 0");
    let ssh = fake.open();
    ssh.run("one", b"").unwrap();
    let once = asked_lines(&fake).len();
    ssh.run("two", b"").unwrap();
    assert_eq!(asked_lines(&fake).len(), once);
}
