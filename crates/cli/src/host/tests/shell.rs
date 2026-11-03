//! Quoting, through a real `/bin/sh`.

use std::process::Command;

use crate::host::shell::{QUOTE_CHECK, quote, remote_command};

fn through_sh(command: &str) -> String {
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(command)
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout).unwrap()
}

const HOSTILE: [&str; 14] = [
    "",
    "plain",
    "two words",
    "it's",
    "''",
    "'; touch /nonexistent/landfall-pwned; '",
    "$(touch /nonexistent/landfall-pwned)",
    "`touch /nonexistent/landfall-pwned`",
    "$HOME ${HOME}",
    "a\nb\n",
    "back\\slash\\\\",
    "héllo wörld ✓",
    "-n",
    "--help",
];

#[test]
fn quote_survives_sh() {
    for text in HOSTILE {
        assert_eq!(
            through_sh(&format!("printf %s {}", quote(text))),
            text,
            "{text:?}"
        );
    }
}

#[test]
fn a_remote_command_runs_its_script_as_written() {
    for text in HOSTILE {
        let script = format!("printf %s {}", quote(text));
        assert_eq!(through_sh(&remote_command(&script)), text, "{text:?}");
    }
}

#[test]
fn a_remote_command_replaces_the_login_shell() {
    assert_eq!(remote_command("echo 'a'"), r"exec sh -c 'echo '\''a'\'''");
}

#[test]
fn the_quoting_check_holds_what_other_shells_read_differently() {
    for part in ["'", "\\", "\\\\", "\n"] {
        assert!(QUOTE_CHECK.contains(part), "{part:?}");
    }
    assert_eq!(
        through_sh(&format!("printf %s {}", quote(QUOTE_CHECK))),
        QUOTE_CHECK
    );
}
