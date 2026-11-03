//! Reading a probe's output, and what it refuses.

use std::fmt::Write as _;

use landfall_core::controller_url::ControllerUrl;

use super::{Sandbox, stderr, stdout};
use crate::agent_release::Arch;
use crate::host::facts::{FactsError, HostFacts, Refusal, Warning, check, probe};
use crate::host::shell::QUOTE_CHECK;

const NOW: i64 = 1_800_000_000;

const DIRS: [&str; 2] = ["/srv/compose/app", "/srv/compose/other"];

fn hex(text: &str) -> String {
    text.bytes().fold(String::new(), |mut hex, byte| {
        write!(hex, "{byte:02x}").unwrap();
        hex
    })
}

/// What a host fit for an agent prints, as `(key, value)`.
fn good() -> Vec<(String, String)> {
    let quote_check = hex(QUOTE_CHECK);
    let clock = NOW.to_string();
    [
        ("os", "Linux"),
        ("machine", "x86_64"),
        ("kernel", "6.1.0-18-amd64"),
        ("uid", "1000"),
        ("has_sudo", "1"),
        ("has_systemctl", "1"),
        ("systemd_version", "252"),
        ("has_sha256sum", "1"),
        ("has_runuser", "1"),
        ("has_diff", "1"),
        ("docker_client", "24.0.7"),
        ("compose", "2.21.0"),
        ("docker_group", "1"),
        ("docker_service", "1"),
        ("ca_bundle", "1"),
        ("clock", clock.as_str()),
        ("agent_version", ""),
        ("agent_sha256", ""),
        ("unit_present", "0"),
        ("quote_check", quote_check.as_str()),
        ("dir_exists:0", "1"),
        ("dir_exists:1", "1"),
    ]
    .into_iter()
    .map(|(key, value)| (key.to_owned(), value.to_owned()))
    .collect()
}

fn output(rows: &[(String, String)]) -> String {
    let body = rows
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<Vec<_>>()
        .concat();
    format!("landfall-probe-begin\n{body}landfall-probe-end\n")
}

/// `good()` with `key` set to `value`.
fn with(key: &str, value: &str) -> HostFacts {
    let mut rows = good();
    let row = rows.iter_mut().find(|(k, _)| k == key).unwrap();
    value.clone_into(&mut row.1);
    HostFacts::parse(&output(&rows)).unwrap()
}

fn https() -> ControllerUrl {
    ControllerUrl::parse("https://controller.example", false).unwrap()
}

fn refusals(facts: &HostFacts) -> Vec<Refusal> {
    check(facts, NOW, &DIRS, &https()).unwrap_err()
}

#[test]
fn a_fit_host_passes_with_no_warning() {
    let facts = HostFacts::parse(&output(&good())).unwrap();
    assert_eq!(check(&facts, NOW, &DIRS, &https()), Ok(Vec::new()));
}

#[test]
fn probe_output_parses() {
    let sandbox = Sandbox::new();
    sandbox.stub(
        "uname",
        r#"case "$1" in -s) echo Linux ;; -m) echo aarch64 ;; -r) echo 6.6.1-rpi ;; esac"#,
    );
    sandbox.stub("id", "echo 1000");
    sandbox.stub("sudo", "exit 1");
    sandbox.stub("date", "echo 1800000000");
    sandbox.stub(
        "docker",
        r#"if [ "$1" = --version ]; then echo 'Docker version 24.0.7, build afdd53b'; else echo v2.21.0; fi"#,
    );
    sandbox.stub(
        "systemctl",
        r#"if [ "$1" = --version ]; then echo 'systemd 252 (252.22-1)'; echo '+PAM +AUDIT'; fi"#,
    );
    sandbox.stub("getent", "echo docker:x:999:");
    std::fs::create_dir_all(sandbox.path("/etc/ssl/certs")).unwrap();
    std::fs::write(sandbox.path("/etc/ssl/certs/ca-certificates.crt"), "").unwrap();
    std::fs::create_dir_all(sandbox.path("/tmp/app")).unwrap();
    std::fs::write(sandbox.path("/usr/local/bin/landfall-agent"), "").unwrap();
    super::write_executable(
        &sandbox.path("/usr/local/bin/landfall-agent"),
        "echo 'landfall-agent 1.2.3'",
    );
    std::fs::write(
        sandbox.path("/etc/systemd/system/landfall-agent.service"),
        "",
    )
    .unwrap();

    let dirs = ["/tmp/app", "/tmp/it's gone"];
    let ran = sandbox.run(&probe(&dirs));
    assert!(ran.status.success(), "{}", stderr(&ran));
    let facts = HostFacts::parse(&stdout(&ran)).unwrap();

    assert_eq!(facts.arch(), Some(Arch::Arm64));
    assert!(!facts.is_root());
    assert!(facts.unit_present());
    assert_eq!(facts.agent_version(), Some("landfall-agent 1.2.3"));
    assert_eq!(facts.agent_sha256().map(str::len), Some(64));
    assert!(facts.dir_exists(0));
    assert!(!facts.dir_exists(1));
    // The rest by what `check` makes of them: the second directory is all it minds.
    assert_eq!(
        check(&facts, NOW, &dirs, &https()),
        Err(vec![Refusal::MissingComposeDir(dirs[1].to_owned())])
    );
}

#[test]
fn the_probe_changes_nothing() {
    let sandbox = Sandbox::new();
    let ran = sandbox.run(&probe(&DIRS));
    assert!(ran.status.success(), "{}", stderr(&ran));
    assert!(
        !sandbox.log().contains("install"),
        "{log}",
        log = sandbox.log()
    );
    let text = probe(&DIRS);
    for word in ["rm ", "mv ", "useradd", "chmod", "chown", "sudo -"] {
        assert!(!text.contains(word), "{word}");
    }
}

#[test]
fn a_banner_around_the_probe_is_ignored() {
    let banner = "os=Windows\nWelcome \u{1b}[31mhome\u{1b}[0m\nnot a line of ours\n";
    let text = format!("{banner}{}Goodbye\nos=Darwin\n", output(&good()));
    let facts = HostFacts::parse(&text).unwrap();
    assert_eq!(check(&facts, NOW, &DIRS, &https()), Ok(Vec::new()));
}

#[test]
fn output_without_one_block_is_refused() {
    let block = output(&good());
    for text in [
        String::new(),
        "os=Linux\n".to_owned(),
        "landfall-probe-begin\nos=Linux\n".to_owned(),
        "os=Linux\nlandfall-probe-end\n".to_owned(),
        "landfall-probe-end\nlandfall-probe-begin\n".to_owned(),
        format!("{block}{block}"),
        format!("landfall-probe-begin\n{block}"),
    ] {
        assert_eq!(HostFacts::parse(&text), Err(FactsError::NoBlock), "{text}");
    }
}

#[test]
fn value_with_a_control_character_is_refused() {
    for bad in ["a\u{1b}[2Jb", "a\rb", "a\tb", "a\u{7f}b", "a\u{85}b"] {
        let text = format!("landfall-probe-begin\nos={bad}\nlandfall-probe-end\n");
        assert_eq!(
            HostFacts::parse(&text),
            Err(FactsError::ControlCharacter("os".to_owned())),
            "{bad:?}"
        );
    }
}

#[test]
fn oversized_output_is_refused() {
    let huge = format!("{}{}", "banner\n".repeat(10_000), output(&good()));
    assert_eq!(
        HostFacts::parse(&huge),
        Err(FactsError::TooLarge(64 * 1024))
    );

    let long = "x".repeat(257);
    let text = format!("landfall-probe-begin\nos={long}\nlandfall-probe-end\n");
    assert_eq!(
        HostFacts::parse(&text),
        Err(FactsError::ValueTooLong("os".to_owned(), 256))
    );
    let fits = "x".repeat(256);
    let text = format!("landfall-probe-begin\nos={fits}\nlandfall-probe-end\n");
    assert!(HostFacts::parse(&text).is_ok());
}

#[test]
fn unknown_keys_are_ignored_and_bad_lines_are_not() {
    let mut rows = good();
    rows.push(("from_the_future".to_owned(), "yes".to_owned()));
    let facts = HostFacts::parse(&output(&rows)).unwrap();
    assert_eq!(check(&facts, NOW, &DIRS, &https()), Ok(Vec::new()));

    assert_eq!(
        HostFacts::parse("landfall-probe-begin\nno equals sign\nlandfall-probe-end\n"),
        Err(FactsError::BadLine("no equals sign".to_owned()))
    );
    assert_eq!(
        HostFacts::parse("landfall-probe-begin\nos=Linux\nos=Darwin\nlandfall-probe-end\n"),
        Err(FactsError::Repeated("os".to_owned()))
    );
}

#[test]
fn each_refusal_is_named() {
    for (key, value, want) in [
        ("os", "Darwin", Refusal::NotLinux("Darwin".to_owned())),
        (
            "machine",
            "riscv64",
            Refusal::UnknownArch("riscv64".to_owned()),
        ),
        ("kernel", "5.7.0", Refusal::OldKernel("5.7.0".to_owned())),
        ("kernel", "", Refusal::OldKernel(String::new())),
        (
            "systemd_version",
            "234",
            Refusal::OldSystemd("234".to_owned()),
        ),
        ("has_systemctl", "0", Refusal::MissingTool("systemctl")),
        ("has_sha256sum", "0", Refusal::MissingTool("sha256sum")),
        ("has_runuser", "0", Refusal::MissingTool("runuser")),
        ("has_diff", "0", Refusal::MissingTool("diff")),
        ("quote_check", "6162", Refusal::QuoteCheck),
        ("quote_check", "", Refusal::QuoteCheck),
        ("docker_client", "", Refusal::NoDocker),
        (
            "docker_client",
            "19.03.1",
            Refusal::OldDocker("19.03.1".to_owned()),
        ),
        ("compose", "", Refusal::NoCompose(String::new())),
        ("compose", "1.29.2", Refusal::NoCompose("1.29.2".to_owned())),
        ("docker_group", "0", Refusal::NoDockerGroup),
        ("docker_service", "0", Refusal::NoDockerService),
        ("ca_bundle", "0", Refusal::NoCaBundle),
        (
            "dir_exists:1",
            "0",
            Refusal::MissingComposeDir(DIRS[1].to_owned()),
        ),
        ("has_sudo", "0", Refusal::NoPrivilege),
    ] {
        assert_eq!(refusals(&with(key, value)), vec![want], "{key}={value}");
    }
}

/// Each says what's wrong and what to do about it, which is the reason the variants exist.
#[test]
fn refusals_say_what_to_do() {
    for (refusal, words) in [
        (Refusal::QuoteCheck, "login shell"),
        (Refusal::NoDockerService, "snap"),
        (Refusal::NoCompose(String::new()), "docker-compose-plugin"),
        (Refusal::OldDocker("19.03".to_owned()), "upgrade Docker"),
        (Refusal::NoCaBundle, "ca-certificates"),
    ] {
        let text = refusal.to_string();
        assert!(text.contains(words), "{text}");
    }
}

#[test]
fn a_missing_key_is_refused_like_a_bad_one() {
    let mut rows = good();
    rows.retain(|(key, _)| key != "docker_group");
    let facts = HostFacts::parse(&output(&rows)).unwrap();
    assert_eq!(refusals(&facts), vec![Refusal::NoDockerGroup]);
}

#[test]
fn every_refusal_comes_at_once() {
    let mut rows = good();
    for row in &mut rows {
        if row.0 == "has_sudo" || row.0 == "docker_group" {
            "0".clone_into(&mut row.1);
        }
    }
    let facts = HostFacts::parse(&output(&rows)).unwrap();
    assert_eq!(
        refusals(&facts),
        vec![Refusal::NoDockerGroup, Refusal::NoPrivilege]
    );
}

#[test]
fn what_the_target_said_is_quoted_in_a_refusal() {
    let long = "x".repeat(200);
    let text = refusals(&with("os", &long))[0].to_string();
    assert!(text.len() < 150, "{text}");
}

#[test]
fn a_quoting_shell_that_differs_is_refused() {
    // What fish makes of the check: inside single quotes, `\'` is a quote and `\\` a backslash.
    let as_fish = QUOTE_CHECK.replace("\\\\", "\\");
    assert_ne!(as_fish, QUOTE_CHECK);
    let refused = refusals(&with("quote_check", &hex(&as_fish)));
    assert_eq!(refused, vec![Refusal::QuoteCheck]);
    assert!(refused[0].to_string().contains("login shell"));
}

#[test]
fn kernel_versions_compare_as_numbers() {
    for (kernel, passes) in [
        ("5.8", true),
        ("5.10", true),
        ("5.8.0-generic", true),
        ("6.1.0-18-amd64", true),
        ("10.0", true),
        ("5.7", false),
        ("5.7.19-generic", false),
        ("4.19.0", false),
        ("five", false),
        ("5", false),
    ] {
        let result = check(&with("kernel", kernel), NOW, &DIRS, &https());
        assert_eq!(result.is_ok(), passes, "{kernel}");
    }
}

#[test]
fn old_docker_is_refused() {
    for (client, passes) in [
        ("20.10.0", true),
        ("20.10", true),
        ("24.0.7", true),
        ("29.0.0-rc.1", true),
        ("20.9.9", false),
        ("19.03.15", false),
        ("seven", false),
    ] {
        let result = check(&with("docker_client", client), NOW, &DIRS, &https());
        assert_eq!(result.is_ok(), passes, "{client}");
    }
    for (compose, passes) in [
        ("2.0.0", true),
        ("v2.24.1", true),
        ("5.0.0", true),
        ("1.29.2", false),
        ("v1.29.2", false),
        ("nope", false),
    ] {
        let result = check(&with("compose", compose), NOW, &DIRS, &https());
        assert_eq!(result.is_ok(), passes, "{compose}");
    }
}

#[test]
fn systemd_versions_compare_as_numbers() {
    for (version, passes) in [
        ("235", true),
        ("1000", true),
        ("252.22", true),
        ("99", false),
    ] {
        let result = check(&with("systemd_version", version), NOW, &DIRS, &https());
        assert_eq!(result.is_ok(), passes, "{version}");
    }
}

#[test]
fn root_needs_no_sudo() {
    let mut rows = good();
    for row in &mut rows {
        if row.0 == "uid" || row.0 == "has_sudo" {
            "0".clone_into(&mut row.1);
        }
    }
    let facts = HostFacts::parse(&output(&rows)).unwrap();
    assert!(facts.is_root());
    assert_eq!(check(&facts, NOW, &DIRS, &https()), Ok(Vec::new()));
}

#[test]
fn only_an_https_controller_needs_a_ca_bundle() {
    let plain = ControllerUrl::parse("http://127.0.0.1:8080", true).unwrap();
    let facts = with("ca_bundle", "0");
    assert_eq!(check(&facts, NOW, &DIRS, &plain), Ok(Vec::new()));
}

#[test]
fn a_clock_more_than_a_minute_off_is_a_warning() {
    for (offset, want) in [
        (0, vec![]),
        (60, vec![]),
        (-60, vec![]),
        (61, vec![Warning::ClockOff(61)]),
        (-3600, vec![Warning::ClockOff(3600)]),
    ] {
        let clock = (NOW + offset).to_string();
        let result = check(&with("clock", &clock), NOW, &DIRS, &https());
        assert_eq!(result, Ok(want), "{offset}");
    }
    assert_eq!(
        check(&with("clock", "soon"), NOW, &DIRS, &https()),
        Ok(vec![Warning::ClockUnreadable("soon".to_owned())])
    );
}
