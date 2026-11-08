//! Asking: what each command sends, what it prints, and what a refusal reads as and exits
//! with. The table of which command line calls which operation is checked against the
//! document by `cli`'s tests too.

use clap::Parser;
use landfall_api::ProblemCode;
use serde_json::{Value, json};

use super::{AskCommand, run_with};
use crate::api_client::ApiError;
use crate::cli::{Chain, CliError};
use crate::read::tests::{Call, FakeApi, request};

/// Each command line, and the call it makes.
pub(crate) const CALLS: &[(&str, &[Call])] = &[
    (
        "request deploy app/prod v1.3.0",
        &[(
            "POST",
            "/api/v1/deployments/app/prod/requests",
            "/api/v1/deployments/{name}/{stage}/requests",
        )],
    ),
    (
        "rollback app/prod v1.1.0",
        &[(
            "POST",
            "/api/v1/deployments/app/prod/requests",
            "/api/v1/deployments/{name}/{stage}/requests",
        )],
    ),
    (
        "cancel 7",
        &[(
            "POST",
            "/api/v1/approvals/7/cancel",
            "/api/v1/approvals/{id}/cancel",
        )],
    ),
];

/// A command line of the asking commands, as `landfall` parses it.
#[derive(Debug, Parser)]
struct Line {
    #[command(subcommand)]
    command: AskCommand,
}

fn parse(line: &str) -> AskCommand {
    let args = std::iter::once("landfall").chain(line.split_whitespace());
    Line::try_parse_from(args).unwrap().command
}

/// Runs `line` against `api`, and gives what it printed.
fn run(line: &str, api: &FakeApi, json: bool) -> (Result<(), CliError>, String) {
    let command = parse(line);
    let mut out = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(run_with(&command, api, &mut out, json));
    (result, String::from_utf8(out).unwrap())
}

/// The request the controller answers with: open, on `app/prod`, for `tag`.
fn asked(tag: &str) -> Value {
    let mut view = request();
    view["intent"]["tag"] = json!(tag);
    view
}

/// An API that answers a request with `view` and a cancel as cancelled.
fn answering(view: Value) -> FakeApi {
    FakeApi::new(move |path, _| {
        Ok(match path {
            "/api/v1/deployments/app/prod/requests" => view.clone(),
            "/api/v1/approvals/7/cancel" => json!({"request": 7, "state": "cancelled"}),
            other => panic!("no answer for {other}"),
        })
    })
}

/// `error` and its sources, as `landfall` prints them, before escaping.
fn chain(error: &CliError) -> String {
    Chain(error).to_string()
}

fn refused(status: u16, code: ProblemCode, title: &str) -> ApiError {
    ApiError::Refused {
        status,
        code,
        title: title.to_owned(),
    }
}

#[test]
fn each_command_calls_its_operation() {
    for (line, want) in CALLS {
        let api = answering(asked("v1.3.0"));
        let (result, out) = run(line, &api, false);
        result.unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(!out.is_empty(), "{line} printed nothing");
        assert!(api.calls().is_empty(), "{line}: {:?}", api.calls());
        let posted: Vec<String> = api.posted().into_iter().map(|(path, _)| path).collect();
        let want: Vec<&str> = want.iter().map(|(_, path, _)| *path).collect();
        assert_eq!(posted, want, "{line}");
    }
}

#[test]
fn request_prints_where_to_approve() {
    let api = answering(asked("v1.3.0"));
    let (result, out) = run("request deploy app/prod v1.3.0", &api, false);
    result.unwrap();
    let nonce = "ab".repeat(32);
    assert_eq!(
        out,
        format!(
            "request 7 for app/prod on home-1: v1.3.0, awaiting_approval, asked by ci at \
             2023-11-14T22:16:40Z, until 2023-11-15T22:16:40Z\n  \
             commit 0123456789abcdef0123456789abcdef01234567\n  \
             digest sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n  \
             expects running nothing (a first deploy)\n  \
             nonce {nonce}\n\
             An approver signs this at https://landfall.example.com/approvals with their \
             passkey. Agents can't approve.\n"
        )
    );

    // With --json, the answer as received.
    let api = answering(asked("v1.3.0"));
    let (result, out) = run("request deploy app/prod v1.3.0", &api, true);
    result.unwrap();
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed, asked("v1.3.0"));
}

#[test]
fn request_deploy_sends_no_rollback_field() {
    let api = answering(asked("v1.3.0"));
    run("request deploy app/prod v1.3.0", &api, false)
        .0
        .unwrap();
    assert_eq!(
        api.posted(),
        [(
            "/api/v1/deployments/app/prod/requests".to_owned(),
            Some(r#"{"tag":"v1.3.0"}"#.to_owned())
        )]
    );
}

#[test]
fn rollback_sends_the_flag() {
    let api = answering(asked("v1.1.0"));
    let (result, out) = run("rollback app/prod v1.1.0", &api, false);
    result.unwrap();
    assert_eq!(
        api.posted(),
        [(
            "/api/v1/deployments/app/prod/requests".to_owned(),
            Some(r#"{"tag":"v1.1.0","rollback":true}"#.to_owned())
        )]
    );
    assert!(out.contains("app/prod on home-1: v1.1.0"), "{out}");
    assert!(out.contains("An approver signs this at"), "{out}");
}

#[test]
fn not_a_rollback_exits_1_with_its_code() {
    let title = "this release is not lower than what runs, so it is not a rollback";
    let api = FakeApi::new(move |_, _| Err(refused(409, ProblemCode::NotARollback, title)));
    let (result, out) = run("rollback app/prod v1.3.0", &api, false);
    let error = result.unwrap_err();
    assert_eq!(error.exit_code(), 1);
    assert!(
        matches!(
            &error,
            CliError::Api(ApiError::Refused {
                code: ProblemCode::NotARollback,
                ..
            })
        ),
        "{error:?}"
    );
    assert!(error.to_string().contains("not_a_rollback"), "{error}");
    assert!(error.to_string().contains(title), "{error}");
    assert_eq!(out, "");
    // Nothing more is asked.
    assert_eq!(api.calls(), Vec::new());
}

#[test]
fn request_open_exits_1_naming_the_open_request() {
    let title = "this deployment already has a request waiting for an approver";
    let api = FakeApi::new(move |path, _| match path {
        "/api/v1/deployments/app/prod/requests" => {
            Err(refused(409, ProblemCode::RequestOpen, title))
        }
        "/api/v1/approvals" => {
            // Another deployment's request comes first; the one on app/prod is named.
            let mut other = request();
            other["id"] = json!(9);
            other["intent"]["deployment"] = json!("app/staging");
            Ok(json!({"approvals": [other, request()]}))
        }
        other => panic!("no answer for {other}"),
    });
    let (result, out) = run("request deploy app/prod v1.3.0", &api, false);
    let error = result.unwrap_err();
    assert_eq!(error.exit_code(), 1);
    let text = chain(&error);
    assert!(
        text.starts_with(
            "request 7 already waits for an approver on app/prod: `landfall cancel 7` ends it"
        ),
        "{text}"
    );
    assert!(text.contains("request_open"), "{text}");
    assert!(text.contains(title), "{text}");
    assert_eq!(out, "");
    assert_eq!(api.calls().len(), 1);

    // One this principal can't see, or a list that can't be read, leaves the refusal as it is.
    for readable in [true, false] {
        let api = FakeApi::new(move |path, _| match path {
            "/api/v1/approvals" if readable => Ok(json!({"approvals": []})),
            "/api/v1/approvals" => Err(ApiError::TooLarge),
            _ => Err(refused(409, ProblemCode::RequestOpen, title)),
        });
        let error = run("request deploy app/prod v1.3.0", &api, false)
            .0
            .unwrap_err();
        assert_eq!(error.exit_code(), 1, "{readable}");
        assert!(
            matches!(
                &error,
                CliError::Api(ApiError::Refused {
                    code: ProblemCode::RequestOpen,
                    ..
                })
            ),
            "{readable}: {error:?}"
        );
    }
}

#[test]
fn cancel_calls_cancel() {
    let api = answering(asked("v1.3.0"));
    let (result, out) = run("cancel 7", &api, false);
    result.unwrap();
    assert_eq!(
        api.posted(),
        [("/api/v1/approvals/7/cancel".to_owned(), None)]
    );
    assert_eq!(out, "request 7: cancelled\n");

    let api = answering(asked("v1.3.0"));
    let (result, out) = run("cancel 7", &api, true);
    result.unwrap();
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed, json!({"request": 7, "state": "cancelled"}));

    // A request number is a positive number.
    for bad in ["cancel 0", "cancel -1", "cancel 7x"] {
        let args = std::iter::once("landfall").chain(bad.split_whitespace());
        assert!(Line::try_parse_from(args).is_err(), "{bad}");
    }
}

#[test]
fn no_approval_settings_says_nobody_can_approve() {
    let mut view = asked("v1.3.0");
    view["approve_url"] = Value::Null;
    let api = answering(view);
    let (result, out) = run("request deploy app/prod v1.3.0", &api, false);
    result.unwrap();
    assert!(
        out.ends_with("This controller has no [approval] settings, so nobody can approve yet.\n"),
        "{out}"
    );
    assert!(!out.contains("approver signs"), "{out}");
}

#[test]
fn a_bad_request_to_rollback_says_an_older_controller_may_not_know_the_flag() {
    let title = "the body is not a valid request";
    let api = FakeApi::new(move |_, _| Err(refused(400, ProblemCode::BadRequest, title)));
    let error = run("rollback app/prod v1.1.0", &api, false).0.unwrap_err();
    assert_eq!(error.exit_code(), 1);
    let text = chain(&error);
    assert!(
        text.contains("a controller older than this landfall may not know `rollback`"),
        "{text}"
    );
    assert!(text.contains("bad_request"), "{text}");
    assert!(text.contains(title), "{text}");

    // `request deploy` sends no flag, so nothing about one is said.
    let api = FakeApi::new(move |_, _| Err(refused(400, ProblemCode::BadRequest, title)));
    let error = run("request deploy app/prod v1.3.0", &api, false)
        .0
        .unwrap_err();
    assert!(
        matches!(error, CliError::Api(ApiError::Refused { .. })),
        "{error:?}"
    );
}

/// Hostile text as a field can hold it: an OSC title escape ended by BEL, a C1 CSI, a
/// carriage return, a bidi override, and a line feed to forge a line of output.
const HOSTILE: &str = "h\x1b]0;owned\x07\u{9b}2J\r\u{202e}\nFORGED";

/// [`HOSTILE`], as `safe` prints it.
const ESCAPED: &str = "h\\u{1b}]0;owned\\u{7}\\u{9b}2J\\u{d}\\u{202e}\\u{a}FORGED";

/// That nothing of [`HOSTILE`] is raw in `text`.
fn assert_no_raw(what: &str, text: &str) {
    for raw in ['\x1b', '\x07', '\r', '\u{9b}', '\u{202e}'] {
        assert!(!text.contains(raw), "{what}: {raw:?} in {text:?}");
    }
    assert!(
        !text
            .lines()
            .any(|line| line.trim_start().starts_with("FORGED")),
        "{what}: a forged line in:\n{text}"
    );
}

/// Every server string the asking commands print, seeded with [`HOSTILE`], in human output,
/// in `--json` and in a refusal's text, `approve_url` included.
#[test]
fn hostile_text_is_escaped_in_what_asking_prints() {
    let mut view = asked("v1.3.0");
    view["approve_url"] = json!(HOSTILE);
    view["intent"]["nonce"] = json!(HOSTILE);
    view["state"] = json!(HOSTILE);
    for line in ["request deploy app/prod v1.3.0", "rollback app/prod v1.3.0"] {
        let (result, out) = run(line, &answering(view.clone()), false);
        result.unwrap();
        assert_no_raw(line, &out);
        // The nonce; a state this CLI doesn't know reads `unknown`, and isn't said to be
        // signable, so the URL isn't printed.
        assert_eq!(out.matches(ESCAPED).count(), 1, "{line}: {out}");
        assert!(out.contains(", unknown,"), "{line}: {out}");

        let (result, out) = run(line, &answering(view.clone()), true);
        result.unwrap();
        assert_no_raw(line, &out);
        let printed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(printed["approve_url"], HOSTILE, "{line}");
    }
    // Where an approver signs, on an open request.
    let mut view = asked("v1.3.0");
    view["approve_url"] = json!(HOSTILE);
    let (result, out) = run("request deploy app/prod v1.3.0", &answering(view), false);
    result.unwrap();
    assert_no_raw("approve_url", &out);
    assert_eq!(out.matches(ESCAPED).count(), 1, "{out}");

    let api = FakeApi::new(|_, _| Ok(json!({"request": 7, "state": HOSTILE})));
    let (result, out) = run("cancel 7", &api, false);
    result.unwrap();
    assert_eq!(out, "request 7: unknown\n");
    let (result, out) = run("cancel 7", &api, true);
    result.unwrap();
    assert_no_raw("cancel --json", &out);

    // A refusal's title, through each way asking adds to one: `main` escapes the whole chain.
    let api = FakeApi::new(|path, _| match path {
        "/api/v1/approvals" => Ok(json!({"approvals": [request()]})),
        _ => Err(refused(409, ProblemCode::RequestOpen, HOSTILE)),
    });
    let error = run("request deploy app/prod v1.3.0", &api, false)
        .0
        .unwrap_err();
    let printed = crate::display::safe(&chain(&error)).into_owned();
    assert_no_raw("request_open", &printed);
    assert!(printed.contains(ESCAPED), "{printed}");
}
