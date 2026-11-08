//! What each command asks the API, how `status` pages, and what reaches the exit status.

use serde_json::{Value, json};

use super::{CALLS, FakeApi, fixture, request, run, summary};
use crate::api_client::ApiError;
use crate::cli::CliError;
use crate::read::MAX_BYTES;

/// A page of `count` deployments, and `next` as its cursor.
fn page(count: usize, next: Option<&str>) -> Value {
    let items: Vec<Value> = (0..count).map(|_| summary()).collect();
    json!({"items": items, "next_cursor": next})
}

fn cursor_of(query: &[(String, String)]) -> Option<String> {
    query
        .iter()
        .find(|(name, _)| name == "cursor")
        .map(|(_, value)| value.clone())
}

#[test]
fn status_pages_until_done() {
    let api = FakeApi::new(|_, query| {
        Ok(match cursor_of(query).as_deref() {
            None => page(2, Some("c1")),
            Some("c1") => page(1, None),
            Some(other) => panic!("unexpected cursor {other}"),
        })
    });
    let (result, out) = run(
        "status --host home-1 --repo example/app --needs-you",
        &api,
        false,
    );
    result.unwrap();

    let calls = api.calls();
    assert_eq!(calls.len(), 2);
    let first: Vec<(&str, &str)> = calls[0]
        .1
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_eq!(
        first,
        [
            ("host", "home-1"),
            ("repo", "example/app"),
            ("needs_you", "true"),
            ("limit", "100"),
        ]
    );
    assert_eq!(cursor_of(&calls[1].1).as_deref(), Some("c1"));
    assert_eq!(out.lines().count(), 3, "{out}");
    assert!(!out.contains("stopped"), "{out}");

    let (result, out) = run("status", &api, true);
    result.unwrap();
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed["items"].as_array().unwrap().len(), 3);
    assert!(printed.get("stopped").is_none(), "{out}");
}

#[test]
fn status_stops_at_1000_items_or_20_pages_and_says_so() {
    // Full pages of 100: the tenth brings 1,000, and paging stops though a cursor came.
    let api = FakeApi::new(|_, query| {
        let n = cursor_of(query).map_or(0, |c| c.parse::<u32>().unwrap());
        Ok(page(100, Some(&(n + 1).to_string())))
    });
    let (result, out) = run("status", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 10);
    assert_eq!(
        out.lines().filter(|l| l.starts_with("app/prod")).count(),
        1000
    );
    assert!(
        out.ends_with(
            "stopped at 1000 deployments: narrow it with --host, --repo or --needs-you\n"
        ),
        "{}",
        out.lines().last().unwrap()
    );

    // One page over the API's limit, and no cursor: what is dropped is still said.
    let api = FakeApi::new(|_, _| Ok(page(1001, None)));
    let (result, out) = run("status", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 1);
    assert_eq!(
        out.lines().filter(|l| l.starts_with("app/prod")).count(),
        1000
    );
    assert!(
        out.ends_with(
            "stopped at 1000 deployments: narrow it with --host, --repo or --needs-you\n"
        ),
        "{}",
        out.lines().last().unwrap()
    );

    // Short pages: 20 of them, and no more.
    let api = FakeApi::new(|_, query| {
        let n = cursor_of(query).map_or(0, |c| c.parse::<u32>().unwrap());
        Ok(page(3, Some(&(n + 1).to_string())))
    });
    let (result, out) = run("status", &api, true);
    result.unwrap();
    assert_eq!(api.calls().len(), 20);
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed["items"].as_array().unwrap().len(), 60);
    assert_eq!(
        printed["stopped"],
        "stopped after 20 pages: narrow it with --host, --repo or --needs-you"
    );
}

#[test]
fn a_repeated_cursor_stops_paging() {
    let api = FakeApi::new(|_, query| {
        Ok(match cursor_of(query).as_deref() {
            None | Some("b") => page(1, Some("a")),
            Some("a") => page(1, Some("b")),
            Some(other) => panic!("unexpected cursor {other}"),
        })
    });
    let (result, out) = run("status", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 3);
    assert!(
        out.ends_with("stopped: the controller sent a cursor it had already sent\n"),
        "{out}"
    );
}

#[test]
fn each_command_calls_its_operation() {
    for (line, want) in CALLS {
        let api = FakeApi::fixtures();
        let (result, out) = run(line, &api, false);
        result.unwrap_or_else(|e| panic!("{line}: {e}"));
        assert!(!out.is_empty(), "{line} printed nothing");
        let paths: Vec<String> = api.calls().into_iter().map(|(path, _)| path).collect();
        let want: Vec<&str> = want.iter().map(|(_, path, _)| *path).collect();
        assert_eq!(paths, want, "{line}");
        assert!(paths.len() <= 3, "{line}");
    }

    // The limits and filters each list takes.
    for (line, path, query) in [
        (
            "history app/prod --limit 5",
            "/api/v1/deployments/app/prod/deploys",
            vec![("limit", "5")],
        ),
        (
            "releases app/prod --limit 100",
            "/api/v1/deployments/app/prod/releases",
            vec![("limit", "100")],
        ),
        (
            "audit --deployment app/prod --host home-1 --kind deploy_queued --limit 1",
            "/api/v1/audit",
            vec![
                ("deployment", "app/prod"),
                ("host", "home-1"),
                ("kind", "deploy_queued"),
                ("limit", "1"),
            ],
        ),
    ] {
        let api = FakeApi::fixtures();
        run(line, &api, false).0.unwrap();
        let calls = api.calls();
        assert_eq!(calls.len(), 1, "{line}");
        assert_eq!(calls[0].0, path, "{line}");
        let sent: Vec<(&str, &str)> = calls[0]
            .1
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        assert_eq!(sent, query, "{line}");
    }

    // With nothing open, approvals doesn't ask who it is; with --json, it prints the list.
    let api = FakeApi::new(|path, _| {
        Ok(match path {
            "/api/v1/approvals" => json!({"approvals": []}),
            other => fixture(other),
        })
    });
    let (result, out) = run("approvals", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 1);
    assert_eq!(out, "nothing waits for an approver\n");
    let api = FakeApi::fixtures();
    run("approvals", &api, true).0.unwrap();
    assert_eq!(api.calls().len(), 1);
}

#[test]
fn approvals_say_where_an_approver_signs() {
    let api = FakeApi::fixtures();
    let (result, out) = run("approvals", &api, false);
    result.unwrap();
    assert!(
        out.contains(
            "An approver signs this at https://landfall.example.com/approvals with their passkey. Agents can't approve."
        ),
        "{out}"
    );
    assert!(
        out.contains("request 7 for app/prod on home-1: v1.3.0"),
        "{out}"
    );

    let api = FakeApi::new(|path, _| {
        let mut value = fixture(path);
        if path == "/api/v1/me" {
            value["approve_url"] = Value::Null;
        }
        Ok(value)
    });
    let (result, out) = run("approvals", &api, false);
    result.unwrap();
    assert!(
        out.contains("This controller has no [approval] settings, so nobody can approve yet."),
        "{out}"
    );
    // Only an open request is said to be signable; anything else asks nobody who it is.
    let api = FakeApi::new(|path, _| {
        Ok(match path {
            "/api/v1/approvals" => {
                let (mut approved, mut newer) = (request(), request());
                approved["state"] = json!("approved");
                newer["state"] = json!("teleporting");
                json!({"approvals": [approved, newer]})
            }
            other => fixture(other),
        })
    });
    let (result, out) = run("approvals", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 1);
    assert!(out.contains("v1.3.0, approved,"), "{out}");
    assert!(out.contains("v1.3.0, unknown,"), "{out}");
    assert!(!out.contains("approver signs"), "{out}");
    assert!(!out.contains("nobody can approve"), "{out}");
}

#[test]
fn refused_exits_1_and_unreachable_exits_2() {
    let api = FakeApi::new(|_, _| {
        Err(ApiError::Refused {
            status: 404,
            code: landfall_api::ProblemCode::NotFound,
            title: "no such deployment".to_owned(),
        })
    });
    let (result, out) = run("status app/prod", &api, false);
    let error = result.unwrap_err();
    assert!(matches!(error, CliError::Api(ApiError::Refused { .. })));
    assert_eq!(error.exit_code(), 1);
    assert_eq!(out, "");

    // A real client, to a loopback port nothing listens on.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let settings = crate::settings::Settings {
        controller: landfall_core::controller_url::ControllerUrl::parse(&url, true).unwrap(),
        token: None,
    };
    let client = crate::api_client::ApiClient::new(&settings).unwrap();
    let command = super::parse("why 12");
    let mut out = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let error = runtime
        .block_on(crate::read::run_with(&command, &client, &mut out, false))
        .unwrap_err();
    assert!(
        matches!(error, CliError::Api(ApiError::Network(_))),
        "{error:?}"
    );
    assert_eq!(error.exit_code(), 2);
}

#[test]
fn json_passes_new_fields_and_values_through() {
    let mut body = fixture("/api/v1/deployments/app/prod/releases/v1.3.0");
    body["release"]["status"] = json!("teleporting");
    body["from_the_future"] = json!({"nested": [1, "\u{9b}"]});
    let answer = body.clone();
    let api = FakeApi::new(move |_, _| Ok(answer.clone()));
    let (result, out) = run("release app/prod v1.3.0", &api, true);
    result.unwrap();
    assert!(!out.contains('\u{9b}'), "{out}");
    let printed: Value = serde_json::from_str(&out).unwrap();
    assert_eq!(printed, body);
}

/// A hostile controller's wide items, with a fresh cursor on every page: `status` stops at its
/// byte budget, says so, and holds no more than the bytes it counted.
#[test]
fn status_stops_at_the_byte_budget_and_holds_no_more() {
    let wide = |_: &str, query: &[(String, String)]| {
        let n = cursor_of(query).map_or(0, |c| c.parse::<u32>().unwrap());
        let mut item = summary();
        item["running"]["phase"] = json!("x".repeat(1 << 20));
        Ok(json!({
            "items": [item.clone(), item.clone(), item],
            "next_cursor": (n + 1).to_string(),
        }))
    };
    let stop = "stopped at 8 MiB of answers: narrow it with --host, --repo or --needs-you";

    // Pages of about 3 MiB: two are kept, and the third would pass 8 MiB.
    let api = FakeApi::new(wide);
    let (result, out) = run("status", &api, false);
    result.unwrap();
    assert_eq!(api.calls().len(), 3);
    assert_eq!(out.lines().filter(|l| l.starts_with("app/prod")).count(), 6);
    assert!(
        out.ends_with(&format!("{stop}\n")),
        "{}",
        out.lines().last().unwrap()
    );

    // Items are kept as the text received: what is printed is what was held, within budget.
    let api = FakeApi::new(wide);
    let (result, out) = run("status", &api, true);
    result.unwrap();
    assert_eq!(api.calls().len(), 3);
    let printed: Value = serde_json::from_str(&out).unwrap();
    let items = printed["items"].as_array().unwrap();
    assert_eq!(items.len(), 6);
    let held: usize = items.iter().map(|item| item.to_string().len()).sum();
    assert!(held > 6 << 20 && held <= MAX_BYTES, "{held}");
    assert_eq!(printed["stopped"], stop);
}
