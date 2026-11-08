//! The command line's shape, and how a failure reads.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Write as _};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use clap::{CommandFactory, Parser};
use serde_json::json;
use thiserror::Error;

use super::{Chain, Cli, run, run_with};
use crate::settings::Env;

#[test]
fn command_line_is_well_formed() {
    Cli::command().debug_assert();
}

#[test]
fn verify_help_documents_exit_status_and_token() {
    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("verify")
        .unwrap()
        .render_long_help()
        .to_string();
    for line in [
        "0  the release is verified",
        "1  the release is refused",
        "2  the release could not be verified",
        "GITHUB_TOKEN",
    ] {
        assert!(help.contains(line), "{line:?} missing from:\n{help}");
    }
}

fn host_install_help() -> String {
    let mut command = Cli::command();
    command
        .find_subcommand_mut("host")
        .unwrap()
        .find_subcommand_mut("install")
        .unwrap()
        .render_long_help()
        .to_string()
}

#[test]
fn help_documents_the_exit_statuses() {
    let help = host_install_help();
    for line in [
        "0  the agent is installed",
        "1  refused or stopped",
        "2  could not try",
        "GITHUB_TOKEN",
    ] {
        assert!(help.contains(line), "{line:?} missing from:\n{help}");
    }
}

/// Every flag the task names, in its own spelling, and no flag for what a test sets.
#[test]
fn host_install_takes_what_it_should() {
    let cli = Cli::try_parse_from([
        "landfall",
        "host",
        "install",
        "user@host.example",
        "--host",
        "home-1",
        "--config",
        "fleet.toml",
        "--controller",
        "https://controller.example",
        "--allow-insecure-controller",
        "--code-file",
        "code",
        "--tag",
        "v1.2.3",
        "--dry-run",
        "--yes",
        "--replace-config",
        "--replace-unit",
        "--ssh-config",
        "ssh_config",
        "--cache-dir",
        "cache",
    ]);
    assert!(cli.is_ok(), "{:?}", cli.err());
    assert!(!host_install_help().contains("--timing"));
    assert!(!host_install_help().contains("stable"));

    for missing in ["--host", "--config", "--controller"] {
        let mut args = vec![
            "landfall",
            "host",
            "install",
            "user@host.example",
            "--host",
            "home-1",
            "--config",
            "fleet.toml",
            "--controller",
            "https://controller.example",
        ];
        let at = args.iter().position(|arg| arg == &missing).unwrap();
        args.drain(at..at + 2);
        let error = Cli::try_parse_from(args).err().unwrap();
        assert_eq!(error.exit_code(), 2, "{missing}");
    }
}

/// All the way through `run`, stopped by a destination before anything could connect.
#[test]
fn a_host_command_reaches_its_error_and_exit_status() {
    let cli = Cli::try_parse_from([
        "landfall",
        "host",
        "install",
        "a;b",
        "--host",
        "home-1",
        "--config",
        "fleet.toml",
        "--controller",
        "https://controller.example",
    ])
    .unwrap();
    assert_eq!(run(cli), 2);
}

#[test]
fn usage_errors_exit_2() {
    let error = Cli::try_parse_from(["landfall", "verify"]).err().unwrap();
    assert_eq!(error.exit_code(), 2);
}

#[derive(Debug, Error)]
#[error("outer")]
struct Outer(#[source] Inner);

#[derive(Debug, Error)]
#[error("inner")]
struct Inner;

#[test]
fn error_chain_names_every_cause() {
    assert_eq!(Chain(&Outer(Inner)).to_string(), "outer: inner");
}

/// The API flags are each API command's own, so `host install` keeps its `--controller`
/// without a clash, which `command_line_is_well_formed` would catch as a panic.
#[test]
fn api_flags_belong_to_each_api_command() {
    let parsed = Cli::try_parse_from([
        "landfall",
        "whoami",
        "--controller",
        "https://controller.example",
        "--allow-insecure-controller",
        "--token-file",
        "token",
        "--cli-config",
        "cli.toml",
        "--json",
    ]);
    assert!(parsed.is_ok(), "{:?}", parsed.err());
    assert!(Cli::try_parse_from(["landfall", "--json", "whoami"]).is_err());
    // No flag takes the token itself, so it never reaches argv.
    assert!(Cli::try_parse_from(["landfall", "whoami", "--token", "abc"]).is_err());

    let mut command = Cli::command();
    let help = command
        .find_subcommand_mut("whoami")
        .unwrap()
        .render_long_help()
        .to_string();
    for line in [
        "0  done",
        "1  the controller refused",
        "2  could not ask",
        "LANDFALL_TOKEN",
    ] {
        assert!(help.contains(line), "{line:?} missing from:\n{help}");
    }
}

struct FakeEnv(HashMap<&'static str, OsString>);

impl Env for FakeEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}

/// An environment with no configuration file and `LANDFALL_TOKEN` as given.
fn env(token: Option<&str>) -> FakeEnv {
    let mut vars = HashMap::from([("HOME", OsString::from("/nonexistent"))]);
    if let Some(token) = token {
        vars.insert("LANDFALL_TOKEN", token.into());
    }
    FakeEnv(vars)
}

/// A loopback server that answers one request with `status`, `content_type` and `body`,
/// and gives back the request's head.
fn answer_once(status: u16, content_type: &str, body: &str) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let response = format!(
        "HTTP/1.1 {status} X\r\ncontent-type: {content_type}\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream);
        let mut head = String::new();
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            head.push_str(&line);
        }
        reader.get_mut().write_all(response.as_bytes()).unwrap();
        head
    });
    (url, handle)
}

fn whoami(url: &str, extra: &[&str]) -> Cli {
    let mut args = vec![
        "landfall",
        "whoami",
        "--controller",
        url,
        "--allow-insecure-controller",
    ];
    args.extend_from_slice(extra);
    Cli::try_parse_from(args).unwrap()
}

#[test]
fn errors_are_escaped() {
    let title = "denied\x1b]0;x\x07 \u{202e}txt.exe\r\nforged line";
    let body = json!({"code": "forbidden", "title": title, "status": 403}).to_string();
    let (url, server) = answer_once(403, "application/problem+json", &body);
    let (mut out, mut err) = (Vec::new(), Vec::new());

    let status = run_with(whoami(&url, &[]), &env(Some("tok")), &mut out, &mut err);
    server.join().unwrap();

    assert_eq!(status, 1);
    assert_eq!(String::from_utf8(out).unwrap(), "");
    let err = String::from_utf8(err).unwrap();
    assert!(err.starts_with("landfall: "), "{err}");
    assert!(
        err.contains("denied\\u{1b}]0;x\\u{7} \\u{202e}txt.exe\\u{d}\\u{a}forged line"),
        "{err}"
    );
    for raw in ['\x1b', '\x07', '\u{202e}', '\r'] {
        assert!(!err.contains(raw), "{raw:?} in {err:?}");
    }
    assert_eq!(err.matches('\n').count(), 1, "one line: {err:?}");
}

#[test]
fn a_settings_error_exits_2_through_run_with() {
    let cli = Cli::try_parse_from([
        "landfall",
        "whoami",
        "--controller",
        "http://controller.example",
    ])
    .unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    assert_eq!(run_with(cli, &env(None), &mut out, &mut err), 2);
    let err = String::from_utf8(err).unwrap();
    assert!(err.contains("token"), "{err}");
}

#[test]
fn whoami_prints_who_and_what_they_may_do() {
    let body = json!({
        "principal": "operator",
        "via": "token",
        "grants": [{"deployment": "app/prod", "can": ["view", "request"]}],
        "approve_url": "https://landfall.example.com/approvals",
    })
    .to_string();
    let (url, server) = answer_once(200, "application/json", &body);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_with(whoami(&url, &[]), &env(Some("tok")), &mut out, &mut err);
    let head = server.join().unwrap();

    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(head.starts_with("GET /api/v1/me HTTP/1.1"), "{head}");
    assert!(
        head.to_ascii_lowercase()
            .contains("authorization: bearer tok"),
        "{head}"
    );
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "operator, by token\n\
         app/prod: view, request\n\
         approvers sign at https://landfall.example.com/approvals\n"
    );
}

#[test]
fn whoami_json_prints_the_body_as_received() {
    let body = r#"{"principal":"operator","via":"teleport","grants":[],"approve_url":null,"new":"\u009b"}"#;
    let (url, server) = answer_once(200, "application/json", body);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_with(whoami(&url, &["--json"]), &env(None), &mut out, &mut err);
    let head = server.join().unwrap();

    assert_eq!(status, 0, "{}", String::from_utf8_lossy(&err));
    assert!(
        !head.to_ascii_lowercase().contains("authorization"),
        "{head}"
    );
    let out = String::from_utf8(out).unwrap();
    assert!(out.contains("\"new\": \"\\u009b\""), "{out}");
    assert!(out.contains("\"via\": \"teleport\""), "{out}");
}
