//! The read commands: their fixtures, a fake API that records what it is asked, and the
//! table of which command line calls which operation, which `cli`'s tests check against the
//! document too.

use std::sync::Mutex;

use clap::Parser;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};

use super::{Api, ReadCommand, run_with};
use crate::api_client::ApiError;
use crate::cli::CliError;

mod commands;
mod render;

pub(crate) const DIGEST: &str =
    "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
pub(crate) const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";

/// A call: its method, the path sent, and the document's path for it, with its parameters as
/// `{…}`.
pub(crate) type Call = (&'static str, &'static str, &'static str);

/// A call the fake recorded: its path and query.
pub(crate) type Recorded = (String, Vec<(String, String)>);

/// Each command line, and the calls it makes in human output, in order.
pub(crate) const CALLS: &[(&str, &[Call])] = &[
    (
        "status",
        &[("GET", "/api/v1/deployments", "/api/v1/deployments")],
    ),
    (
        "status app/prod",
        &[(
            "GET",
            "/api/v1/deployments/app/prod",
            "/api/v1/deployments/{name}/{stage}",
        )],
    ),
    (
        "history app/prod",
        &[(
            "GET",
            "/api/v1/deployments/app/prod/deploys",
            "/api/v1/deployments/{name}/{stage}/deploys",
        )],
    ),
    (
        "release app/prod v1.3.0",
        &[(
            "GET",
            "/api/v1/deployments/app/prod/releases/v1.3.0",
            "/api/v1/deployments/{name}/{stage}/releases/{tag}",
        )],
    ),
    (
        "releases app/prod",
        &[(
            "GET",
            "/api/v1/deployments/app/prod/releases",
            "/api/v1/deployments/{name}/{stage}/releases",
        )],
    ),
    (
        "why 12",
        &[("GET", "/api/v1/deploys/12/why", "/api/v1/deploys/{id}/why")],
    ),
    ("hosts", &[("GET", "/api/v1/hosts", "/api/v1/hosts")]),
    (
        "hosts home-1",
        &[("GET", "/api/v1/hosts/home-1", "/api/v1/hosts/{host}")],
    ),
    ("audit", &[("GET", "/api/v1/audit", "/api/v1/audit")]),
    (
        "approvals",
        &[
            ("GET", "/api/v1/approvals", "/api/v1/approvals"),
            ("GET", "/api/v1/me", "/api/v1/me"),
        ],
    ),
];

/// A command line of the read commands, as `landfall` parses it.
#[derive(Debug, Parser)]
struct Line {
    #[command(subcommand)]
    command: ReadCommand,
}

pub(crate) fn parse(line: &str) -> ReadCommand {
    let args = std::iter::once("landfall").chain(line.split_whitespace());
    Line::try_parse_from(args).unwrap().command
}

/// `value` as `T`, read from its text, as the CLI reads an answer.
pub(crate) fn typed<T: DeserializeOwned>(value: &Value) -> T {
    serde_json::from_str(&value.to_string()).unwrap()
}

type Answer = Box<dyn Fn(&str, &[(String, String)]) -> Result<Value, ApiError> + Send + Sync>;

/// An API that answers from a function and records each call: its path and query.
pub(crate) struct FakeApi {
    answer: Answer,
    calls: Mutex<Vec<Recorded>>,
}

impl FakeApi {
    pub(crate) fn new(
        answer: impl Fn(&str, &[(String, String)]) -> Result<Value, ApiError> + Send + Sync + 'static,
    ) -> Self {
        Self {
            answer: Box::new(answer),
            calls: Mutex::new(Vec::new()),
        }
    }

    /// An API whose every answer is the fixture for the path asked.
    pub(crate) fn fixtures() -> Self {
        Self::new(|path, _| Ok(fixture(path)))
    }

    pub(crate) fn calls(&self) -> Vec<Recorded> {
        self.calls.lock().unwrap().clone()
    }
}

impl Api for FakeApi {
    fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> impl Future<Output = Result<String, ApiError>> + Send {
        let query: Vec<(String, String)> = query
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect();
        let answer = (self.answer)(path, &query);
        self.calls.lock().unwrap().push((path.to_owned(), query));
        std::future::ready(answer.map(|value| value.to_string()))
    }
}

/// Runs `line` against `api`, and gives what it printed.
pub(crate) fn run(line: &str, api: &FakeApi, json: bool) -> (Result<(), CliError>, String) {
    let command = parse(line);
    let mut out = Vec::new();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .unwrap();
    let result = runtime.block_on(run_with(&command, api, &mut out, json));
    (result, String::from_utf8(out).unwrap())
}

/// What the controller would answer at `path`, for `app/prod` on `home-1`.
pub(crate) fn fixture(path: &str) -> Value {
    match path {
        "/api/v1/deployments" | "/api/v1/deployments/app/prod/deploys" => {
            let item = if path.ends_with("deploys") {
                deploy()
            } else {
                summary()
            };
            json!({"items": [item], "next_cursor": null})
        }
        "/api/v1/deployments/app/prod" => deployment(),
        "/api/v1/deployments/app/prod/releases" => {
            json!({"items": [release()], "next_cursor": null})
        }
        "/api/v1/deployments/app/prod/releases/v1.3.0" => story(listed(2, 2)),
        "/api/v1/deploys/12/why" => why(),
        "/api/v1/hosts" => json!({"hosts": [host()]}),
        "/api/v1/hosts/home-1" => host(),
        "/api/v1/audit" => json!({"items": [audit()], "next_cursor": null}),
        "/api/v1/approvals" => json!({"approvals": [request()]}),
        "/api/v1/me" => json!({
            "principal": "ci",
            "via": "token",
            "grants": [{"deployment": "app/prod", "can": ["view", "request"]}],
            "approve_url": "https://landfall.example.com/approvals",
        }),
        other => panic!("no fixture for {other}"),
    }
}

pub(crate) fn summary() -> Value {
    json!({
        "id": "app/prod",
        "repo": "example/app",
        "host": "home-1",
        "running": {
            "tag": "v1.2.0",
            "digest": DIGEST,
            "phase": "idle",
            "busy": false,
            "drift": false,
            "config_drift": false,
            "healthy_secs": 600,
            "last_report": 1_700_000_000,
        },
        "latest": {"tag": "v1.3.0", "status": "awaiting_approval"},
        "open_request": 7,
        "needs_you": false,
    })
}

pub(crate) fn deployment() -> Value {
    json!({
        "summary": summary(),
        "rule": {"auto": "patch", "approve": "minor", "approvers": ["operator"], "prereleases": false},
        "promote_to": {"deployment": null, "unseen": true, "healthy_for_secs": 3600},
        "promoted_from": [{"deployment": "app/staging", "healthy_for_secs": 600}],
        "holds": [{"tag": "v1.3.0", "reason": "\"origin pending\"", "since": 1_700_000_000, "last_try": 1_700_000_100}],
        "holds_total": 3,
    })
}

pub(crate) fn deploy() -> Value {
    json!({
        "id": 12,
        "deployment": "app/prod",
        "host": "home-1",
        "tag": "v1.3.0",
        "digest": DIGEST,
        "commit": COMMIT,
        "state": "finished",
        "outcome": "rolled_back",
        "reason": "\"health check failed\"",
        "rollback_reason": null,
        "request": 7,
        "approved_by": "operator",
        "created_at": 1_700_000_000,
        "claimed_at": 1_700_000_010,
        "finished_at": 1_700_000_100,
        "steps": [
            {"position": 0, "name": "\"pull\"", "millis": 1200, "failure": null, "detail": null},
            {"position": 1, "name": "\"checks\"", "millis": 30_000, "failure": "\"web never healthy\"", "detail": null},
        ],
    })
}

pub(crate) fn release() -> Value {
    json!({
        "tag": "v1.3.0",
        "status": "awaiting_approval",
        "decision": "needs_approval",
        "first_seen_at": 1_700_000_000,
        "seen_at": 1_700_000_500,
    })
}

/// A listed range of `total` commits, of which `shown` are kept.
pub(crate) fn listed(shown: usize, total: u64) -> Value {
    let commits: Vec<Value> = (0..shown)
        .map(|n| json!({"sha": COMMIT, "summary": format!("\"change {n}\""), "author": "dev"}))
        .collect();
    json!({
        "source": "github",
        "verified": false,
        "state": "listed",
        "base": "v1.2.0",
        "total": total,
        "compare_url": "https://github.com/example/app/compare/a...b",
        "commits": commits,
    })
}

pub(crate) fn story(commits: Value) -> Value {
    let mut story = json!({
        "release": release(),
        "reasons": ["a request waits for an approver"],
        "next": {"kind": "approve", "detail": "an approver signs request 7"},
        "origin": {
            "commit": COMMIT,
            "digest": DIGEST,
            "signer": null,
            "san": "\"https://github.com/example/app/.github/workflows/release.yml@refs/tags/v1.3.0\"",
            "run_url": "\"https://github.com/example/app/actions/runs/1\"",
            "rekor_log_index": 42,
            "integrated_time": 1_700_000_000,
        },
        "commits": null,
        "requests": [{
            "id": 7,
            "state": "awaiting_approval",
            "requested_by": "ci",
            "approved_by": null,
            "created_at": 1_700_000_200,
            "closed_reason": null,
        }],
        "deploys": [{
            "id": 12,
            "state": "finished",
            "outcome": "rolled_back",
            "created_at": 1_700_000_000,
            "finished_at": 1_700_000_100,
        }],
    });
    story["commits"] = commits;
    story
}

pub(crate) fn why() -> Value {
    json!({
        "deploy": 12,
        "outcome": "rolled_back",
        "summary": "v1.3.0 failed on home-1 at step \"checks\" and rolled back to the previous version",
        "events": [
            {"at": 1_700_000_000, "what": "queued", "text": "queued for home-1"},
            {"at": null, "what": "step_failed", "text": "step \"checks\" failed: \"web never healthy\""},
        ],
        "next": {"kind": "request", "detail": "landfall request app/prod v1.3.0"},
    })
}

pub(crate) fn host() -> Value {
    json!({
        "id": "home-1",
        "enrolled_at": 1_690_000_000,
        "config_drift": false,
        "last_report": 1_700_000_000,
        "deployments": [summary()],
    })
}

pub(crate) fn audit() -> Value {
    json!({
        "seq": 41,
        "ts": 1_700_000_000,
        "kind": "deploy_queued",
        "deployment": "app/prod",
        "host": "home-1",
        "detail": {"tag": "v1.3.0", "deploy": 12},
    })
}

pub(crate) fn request() -> Value {
    json!({
        "id": 7,
        "host": "home-1",
        "intent": {
            "deployment": "app/prod",
            "tag": "v1.3.0",
            "commit": COMMIT,
            "digest": DIGEST,
            "expected_running": null,
            "nonce": "ab".repeat(32),
        },
        "challenge": "Y2hhbGxlbmdl",
        "state": "awaiting_approval",
        "requested_by": "ci",
        "created_at": 1_700_000_200,
        "expires_at": 1_700_086_600,
        "can_approve": false,
        "can_cancel": true,
    })
}
