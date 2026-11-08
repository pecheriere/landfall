//! The command line's shape, and how a failure reads.

use std::collections::HashMap;
use std::ffi::OsString;
use std::io::{BufRead as _, BufReader, Read as _, Write as _};
use std::net::TcpListener;
use std::thread::{self, JoinHandle};

use clap::{CommandFactory, Parser};
use serde_json::json;
use thiserror::Error;

use super::{Chain, Cli, run, run_with};
use crate::ask::tests::CALLS as ASK_CALLS;
use crate::read::tests::{CALLS, Call};
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
fn host_install_help_documents_the_exit_statuses() {
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
/// and gives back the request's head and body.
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
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line == "\r\n" || line.is_empty() {
                break;
            }
            if let Some((name, value)) = line.split_once(':')
                && name.eq_ignore_ascii_case("content-length")
            {
                length = value.trim().parse().unwrap();
            }
            head.push_str(&line);
        }
        // The body too, so that none is left unread when the connection closes.
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        head.push_str("\r\n");
        head.push_str(&String::from_utf8(body).unwrap());
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

/// The long help of a command, named by its words, such as `request deploy`.
fn help_of(name: &str) -> String {
    let mut command = Cli::command();
    let mut found = &mut command;
    for word in name.split(' ') {
        found = found
            .find_subcommand_mut(word)
            .unwrap_or_else(|| panic!("no command {name}"));
    }
    found.render_long_help().to_string()
}

/// Every API command's `--help` gives the exit statuses from the Rulings, and `status` says
/// how far it pages.
#[test]
fn help_documents_the_exit_statuses() {
    for name in [
        "whoami",
        "status",
        "history",
        "release",
        "releases",
        "why",
        "hosts",
        "audit",
        "approvals",
        "request deploy",
        "rollback",
        "cancel",
    ] {
        let help = help_of(name);
        for line in [
            "0  done",
            "1  the controller refused",
            "2  could not ask",
            "LANDFALL_TOKEN",
            "--json",
        ] {
            assert!(
                help.contains(line),
                "{name}: {line:?} missing from:\n{help}"
            );
        }
    }
    let help = help_of("status");
    assert!(help.contains("1,000 deployments or 20 pages"), "{help}");
    // Asking says that an approver signs on the page, and that rollback means it.
    for name in ["request deploy", "rollback"] {
        let help = help_of(name);
        assert!(help.contains("Agents can't approve"), "{name}: {help}");
    }
    assert!(help_of("rollback").contains("not_a_rollback"));
}

/// Each call a command makes is an operation of the checked-in document, with that method.
#[test]
fn every_cli_call_is_in_the_openapi_document() {
    let document: serde_json::Value =
        serde_json::from_str(include_str!("../../../../docs/api/openapi.json")).unwrap();
    let whoami: &[Call] = &[("GET", "/api/v1/me", "/api/v1/me")];
    let calls = CALLS
        .iter()
        .chain(ASK_CALLS)
        .map(|(line, calls)| (*line, *calls))
        .chain([("whoami", whoami)]);
    let mut seen = 0;
    for (line, calls) in calls {
        for (method, _, template) in calls {
            let operation = &document["paths"][template][method.to_ascii_lowercase()];
            assert!(
                operation["operationId"].is_string(),
                "{line}: {method} {template} is not in docs/api/openapi.json"
            );
            seen += 1;
        }
    }
    assert!(seen >= 14, "{seen}");
}

/// A megabyte of hostile text where the CLI wants something else gives one short line.
#[test]
fn a_parse_error_is_one_short_line() {
    let big = "\u{9b}A".repeat(1 << 19);
    let body = json!({"principal": "operator", "via": "token", "grants": big, "approve_url": null})
        .to_string();
    let (url, server) = answer_once(200, "application/json", &body);
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_with(whoami(&url, &[]), &env(None), &mut out, &mut err);
    server.join().unwrap();

    assert_eq!(status, 2);
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.len() < 200,
        "{} bytes: {}",
        err.len(),
        &err[..200.min(err.len())]
    );
    assert!(
        err.starts_with("landfall: the controller's answer is not one this CLI can read"),
        "{err}"
    );
    assert_eq!(err.matches('\n').count(), 1, "{err}");
}

/// `landfall rollback` through `run_with` and the real client: what goes on the wire, and an
/// older controller's refusal of the flag, escaped, with what it may mean.
#[test]
fn rollback_sends_the_flag_and_explains_an_older_controllers_refusal() {
    let title = "bad\x1b[2J\u{9b}31m\r\nforged";
    let body = json!({"code": "bad_request", "title": title, "status": 400}).to_string();
    let (url, server) = answer_once(400, "application/problem+json", &body);
    let cli = Cli::try_parse_from([
        "landfall",
        "rollback",
        "app/prod",
        "v1.1.0",
        "--controller",
        &url,
        "--allow-insecure-controller",
    ])
    .unwrap();
    let (mut out, mut err) = (Vec::new(), Vec::new());
    let status = run_with(cli, &env(Some("tok")), &mut out, &mut err);
    let request = server.join().unwrap();

    assert!(
        request.starts_with("POST /api/v1/deployments/app/prod/requests HTTP/1.1"),
        "{request}"
    );
    let lower = request.to_ascii_lowercase();
    assert!(
        lower.contains("content-type: application/json"),
        "{request}"
    );
    assert!(lower.contains("authorization: bearer tok"), "{request}");
    assert!(
        request.ends_with("\r\n\r\n{\"tag\":\"v1.1.0\",\"rollback\":true}"),
        "{request}"
    );

    assert_eq!(status, 1);
    assert_eq!(String::from_utf8(out).unwrap(), "");
    let err = String::from_utf8(err).unwrap();
    assert!(
        err.contains("may be because it is older than this landfall and doesn't know `rollback`"),
        "{err}"
    );
    assert!(
        err.contains("bad_request: bad\\u{1b}[2J\\u{9b}31m\\u{d}\\u{a}forged"),
        "{err}"
    );
    for raw in ['\x1b', '\u{9b}', '\r'] {
        assert!(!err.contains(raw), "{raw:?} in {err:?}");
    }
    assert_eq!(err.matches('\n').count(), 1, "one line: {err:?}");
}
