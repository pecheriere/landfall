//! Quoting, through a real `/bin/sh`.

use std::fs;
use std::process::Command;

use tempfile::TempDir;

use super::write_executable;
use crate::host::shell::{QUOTE_CHECK, privileged_command, quote, remote_command};

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

/// Through a real `sh`, with a stub `id` and `sudo`, what the script's text ends up being.
fn run_privileged_command(uid: &str, interactive: bool, script: &str) -> (String, String) {
    let dir = TempDir::new().unwrap();
    let said = dir.path().join("sudo-args");
    write_executable(&dir.path().join("id"), &format!("echo {uid}"));
    write_executable(
        &dir.path().join("sudo"),
        &format!(
            "printf '%s|' \"$@\" > {said}\nwhile [ \"$1\" = -n ]; do shift; done\nexec \"$@\"",
            said = said.display()
        ),
    );
    let output = Command::new("/bin/sh")
        .arg("-c")
        .arg(privileged_command(script, interactive))
        .env("PATH", format!("{}:/usr/bin:/bin", dir.path().display()))
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    (
        String::from_utf8(output.stdout).unwrap(),
        fs::read_to_string(said).unwrap_or_default(),
    )
}

#[test]
fn a_privileged_command_goes_through_sudo_unless_root() {
    let script = "printf '%s' \"it's $((1 + 1))\"\n";

    let (ran, sudo) = run_privileged_command("1000", true, script);
    assert_eq!(ran, "it's 2");
    assert_eq!(sudo, format!("sh|-c|{script}|"));

    // With nobody to answer, it mustn't ask.
    let (ran, sudo) = run_privileged_command("1000", false, script);
    assert_eq!(ran, "it's 2");
    assert_eq!(sudo, format!("-n|sh|-c|{script}|"));

    for interactive in [true, false] {
        let (ran, sudo) = run_privileged_command("0", interactive, script);
        assert_eq!(ran, "it's 2");
        assert_eq!(sudo, "");
    }
}

#[test]
fn a_privileged_command_runs_any_script_as_written() {
    for text in HOSTILE {
        let script = format!("printf %s {}", quote(text));
        let (ran, _) = run_privileged_command("1000", false, &script);
        assert_eq!(ran, text, "{text:?}");
    }
}
