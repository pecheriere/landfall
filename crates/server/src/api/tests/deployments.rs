//! Who am I, and the deployments a principal may see: `whoAmI`, `listDeployments` and
//! `getDeployment`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::SoftwareAuthenticator;
use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, HostId, PrincipalId};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};
use serde_json::{Value, json};

use super::grants::{assert_documented, documented, served_document};
use super::schemas::schema_of;
use super::{
    Answer, CANARY_VIEWER, Caller, FLEET_VIEWER, OUTSIDER, ROLES, WORLD_ORIGIN, World, answer,
    holder, verified, world_digest,
};
use crate::agent_api::{ApiState, Limits};
use crate::auth::{ApiToken, SessionToken};
use crate::store::{ManualClock, NewRequest, REQUEST_LIFETIME_SECS, Store};

const NOW: i64 = 1_800_000_000;

/// A deployment of `repo` on `host`, which only `approvers` may approve.
pub(super) fn deployment(
    id: &str,
    (repo, repo_id): (&str, u64),
    host: &str,
    approvers: &str,
) -> String {
    let dir = id.replace('/', "-");
    format!(
        r#"
[[deployment]]
id = "{id}"
repo = {{ name = "{repo}", id = {repo_id}, owner_id = 9 }}
host = "{host}"
compose = {{ dir = "/srv/{dir}", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = [{approvers}] }}
checks = ["container-healthy"]
"#
    )
}

pub(super) fn grant(principal: &str, deployments: &[&str], can: &[&str]) -> String {
    let list = |items: &[&str]| {
        items
            .iter()
            .map(|item| format!("\"{item}\""))
            .collect::<Vec<_>>()
            .join(", ")
    };
    format!(
        "\n[[grant]]\nprincipal = \"{principal}\"\ndeployments = [{}]\ncan = [{}]\n",
        list(deployments),
        list(can),
    )
}

/// The fleet's configuration, with `app/prod` on `prod_host`:
///
/// - `web/prod` on `home-2`, of `example/web`, then `app/staging` and `app/prod`, of
///   `example/app`: the file's order isn't the ids'.
/// - `operator` and `bystander` are approvers by key. `operator` may view and approve all
///   three. `bystander` may view all three and approve only `web/prod`, whose rule lists them.
/// - `viewer` may view all three. `mixed` may view `app/prod` and request on `app/staging`.
///   `gapped` may view `app/prod` and `web/prod`, and not `app/staging`, between them.
fn fleet_config(keys: &[(&str, &SoftwareAuthenticator)], prod_host: &str) -> String {
    let mut text = format!(
        "[approval]\nrp_id = \"landfall.example.com\"\norigin = \"{WORLD_ORIGIN}\"\n\n[approvers]\n"
    );
    text.extend(keys.iter().map(|(name, key)| {
        format!(
            "{name} = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
            URL_SAFE_NO_PAD.encode(key.credential_id()),
            URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
        )
    }));
    let all = ["web/prod", "app/staging", "app/prod"];
    text.push_str(&deployment(
        "web/prod",
        ("example/web", 2),
        "home-2",
        "\"operator\", \"bystander\"",
    ));
    text.push_str(&deployment(
        "app/staging",
        ("example/app", 1),
        "home-1",
        "\"operator\"",
    ));
    text.push_str(&deployment(
        "app/prod",
        ("example/app", 3),
        prod_host,
        "\"operator\"",
    ));
    text.push_str(&grant("operator", &all, &["view", "approve"]));
    text.push_str(&grant("bystander", &all, &["view"]));
    text.push_str(&grant("bystander", &["web/prod"], &["approve"]));
    text.push_str(&grant("viewer", &all, &["view"]));
    text.push_str(&grant("mixed", &["app/prod"], &["view"]));
    text.push_str(&grant("mixed", &["app/staging"], &["request"]));
    text.push_str(&grant("gapped", &["app/prod", "web/prod"], &["view"]));
    text
}

const FLEET_PRINCIPALS: [&str; 5] = ["operator", "bystander", "viewer", "mixed", "gapped"];

/// A controller of its own on the fleet's configuration, with a token and a session for each
/// principal. `app/prod` and `app/staging` have reported from `home-1`, and `app/staging` has
/// an open request for `v2.1.0`.
struct Fleet {
    app: Router,
    store: Store,
    clock: Arc<ManualClock>,
    keys: Vec<(&'static str, SoftwareAuthenticator)>,
    tokens: HashMap<String, ApiToken>,
    sessions: HashMap<String, SessionToken>,
    /// The open request's number.
    request: i64,
}

impl Fleet {
    async fn seed() -> Self {
        let keys = vec![
            ("operator", SoftwareAuthenticator::es256().unwrap()),
            ("bystander", SoftwareAuthenticator::es256().unwrap()),
        ];
        let config = Self::config_with(&keys, "home-1");
        let clock = ManualClock::at(NOW);
        let store = Store::open_in_memory()
            .await
            .unwrap()
            .with_clock(clock.clone());
        let running = |deployment: &str, tag: &str, fill| RunningState {
            deployment: deployment.parse().unwrap(),
            deployed: Some(DeployedRelease {
                tag: tag.parse().unwrap(),
                digest: world_digest(fill),
            }),
            drift: false,
            phase: Phase::Idle,
            busy: false,
        };
        store
            .record_host_state(
                &"home-1".parse().unwrap(),
                None,
                &[
                    &running("app/prod", "v1.2.0", '2'),
                    &running("app/staging", "v2.0.0", 'b'),
                ],
            )
            .await
            .unwrap();
        verified(&store, &config, "app/staging", "v2.1.0", 'c').await;
        let request = open_request(&store, "app/staging", "v2.1.0", 'c').await;
        let mut tokens = HashMap::new();
        let mut sessions = HashMap::new();
        for name in FLEET_PRINCIPALS {
            let (_, token) = store.create_token(&name.parse().unwrap()).await.unwrap();
            tokens.insert(name.to_owned(), token);
            sessions.insert(
                name.to_owned(),
                // Long enough to outlast a request.
                store
                    .begin_session_for_test(name, 2 * REQUEST_LIFETIME_SECS)
                    .await,
            );
        }
        let app = crate::router(ApiState::new(store.clone(), config, Limits::default()));
        Self {
            app,
            store,
            clock,
            keys,
            tokens,
            sessions,
            request,
        }
    }

    fn config_with(keys: &[(&'static str, SoftwareAuthenticator)], prod_host: &str) -> Config {
        let keys: Vec<(&str, &SoftwareAuthenticator)> =
            keys.iter().map(|(name, key)| (*name, key)).collect();
        landfall_approval::parse_config(fleet_config(&keys, prod_host).as_bytes()).unwrap()
    }

    /// The same store, served under a configuration that puts `app/prod` on `prod_host`.
    fn reconfigured(&self, prod_host: &str) -> Router {
        let config = Self::config_with(&self.keys, prod_host);
        crate::router(ApiState::new(self.store.clone(), config, Limits::default()))
    }

    async fn get(&self, path: &str, caller: Caller<'_>) -> Answer {
        self.get_from(&self.app, path, caller).await
    }

    async fn get_from(&self, app: &Router, path: &str, caller: Caller<'_>) -> Answer {
        let request = Request::builder().method(Method::GET).uri(path);
        let request = match caller {
            Caller::Nobody => request,
            Caller::Token(name) => request.header(
                header::AUTHORIZATION,
                format!("Bearer {}", self.tokens[name].reveal()),
            ),
            Caller::Session(name) => request.header(
                header::COOKIE,
                format!("__Host-landfall-session={}", self.sessions[name].reveal()),
            ),
        };
        answer(app, request.body(Body::empty()).unwrap()).await
    }
}

/// Records a request for `tag` on `deployment`, on `home-1`, as asking does.
pub(super) async fn open_request(store: &Store, deployment: &str, tag: &str, fill: char) -> i64 {
    let by: PrincipalId = "viewer".parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    let request = NewRequest {
        host: &host,
        intent: DeployIntent {
            deployment: deployment.parse().unwrap(),
            tag: tag.parse().unwrap(),
            commit: fill.to_string().repeat(40).parse().unwrap(),
            digest: world_digest(fill),
            expected_running: None,
            nonce: [3; 32],
        },
        requested_by: &by,
        audited_by: json!({ "principal": "viewer" }),
        is_rollback: false,
    };
    let mut tx = store.begin().await.unwrap();
    let stored = store.insert_request(&mut tx, &request).await.unwrap();
    tx.commit().await.unwrap();
    stored.id
}

/// The ids a page of deployments holds, and its cursor.
fn page(answer: &Answer) -> (Vec<String>, Option<String>) {
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    let ids = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .map(|item| item["id"].as_str().unwrap().to_owned())
        .collect();
    (ids, body["next_cursor"].as_str().map(ToOwned::to_owned))
}

/// That `body` is what the document says `operation` answers with 200.
fn assert_schema(doc: &Value, operation: &str, body: &Value) {
    let response = documented(doc, operation, StatusCode::OK).unwrap();
    let schema = &response["content"]["application/json"]["schema"];
    let validator = jsonschema::draft202012::new(&schema_of(doc, schema)).unwrap();
    let errors: Vec<String> = validator.iter_errors(body).map(|e| e.to_string()).collect();
    assert!(errors.is_empty(), "{operation}: {errors:#?}\n{body:#}");
}

#[tokio::test]
async fn me_names_the_principal_its_grants_and_where_to_approve() {
    let world = World::seed().await;
    let name = holder(&["view", "request"]);
    let answer = world
        .send(Method::GET, "/api/v1/me", Caller::Token(&name), None)
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(
        answer.json(),
        json!({
            "principal": name,
            "via": "token",
            "grants": [
                { "deployment": "app/prod", "can": ["view", "request"] },
                { "deployment": "app/staging", "can": ["view", "request"] },
            ],
            "approve_url": "https://landfall.example.com/approvals",
        })
    );
    let answer = world
        .send(
            Method::GET,
            "/api/v1/me",
            Caller::Session(FLEET_VIEWER),
            None,
        )
        .await;
    assert_eq!(
        answer.json(),
        json!({
            "principal": FLEET_VIEWER,
            "via": "session",
            "grants": [
                { "deployment": "app/beta", "can": ["view"] },
                { "deployment": "app/canary", "can": ["view"] },
            ],
            "approve_url": "https://landfall.example.com/approvals",
        })
    );
}

#[tokio::test]
async fn a_tokens_grants_never_list_approve() {
    let world = World::seed().await;
    let name = holder(&ROLES);
    let can = |answer: Answer| {
        let body = answer.json();
        let grants = body["grants"].as_array().unwrap().clone();
        assert_eq!(grants.len(), 2, "{body}");
        grants
            .iter()
            .map(|grant| grant["can"].clone())
            .collect::<Vec<_>>()
    };
    let token = world
        .send(Method::GET, "/api/v1/me", Caller::Token(&name), None)
        .await;
    for listed in can(token) {
        assert_eq!(listed, json!(["view", "request", "rollback"]));
    }
    let session = world
        .send(Method::GET, "/api/v1/me", Caller::Session(&name), None)
        .await;
    for listed in can(session) {
        assert_eq!(listed, json!(["view", "request", "approve", "rollback"]));
    }
    // A token of a principal whose only grant is `approve` still knows the deployments exist,
    // and may do nothing to them by it.
    let approver = holder(&["approve"]);
    let answer = world
        .send(Method::GET, "/api/v1/me", Caller::Token(&approver), None)
        .await;
    for listed in can(answer) {
        assert_eq!(listed, json!([]));
    }
}

#[tokio::test]
async fn list_holds_only_viewable_deployments() {
    let fleet = Fleet::seed().await;
    let answer = fleet
        .get("/api/v1/deployments", Caller::Token("mixed"))
        .await;
    assert_eq!(page(&answer), (vec!["app/prod".to_owned()], None));
    let answer = fleet
        .get("/api/v1/deployments", Caller::Token("viewer"))
        .await;
    let all = ["app/prod", "app/staging", "web/prod"].map(ToOwned::to_owned);
    assert_eq!(page(&answer), (all.to_vec(), None));
}

#[tokio::test]
async fn list_filters_by_host_repo_and_needs_you() {
    let doc = served_document().await;
    let fleet = Fleet::seed().await;
    let ids = |list: &[&str]| list.iter().map(|id| (*id).to_owned()).collect::<Vec<_>>();
    for (query, caller, want) in [
        (
            "?host=home-2",
            Caller::Token("operator"),
            ids(&["web/prod"]),
        ),
        (
            "?host=home-1",
            Caller::Token("operator"),
            ids(&["app/prod", "app/staging"]),
        ),
        (
            "?repo=example/app",
            Caller::Token("operator"),
            ids(&["app/prod", "app/staging"]),
        ),
        (
            "?repo=example/web",
            Caller::Token("operator"),
            ids(&["web/prod"]),
        ),
        (
            "?host=home-1&repo=example/web",
            Caller::Token("operator"),
            ids(&[]),
        ),
        ("?host=home-3", Caller::Token("operator"), ids(&[])),
        (
            "?needs_you=true",
            Caller::Session("operator"),
            ids(&["app/staging"]),
        ),
        (
            "?needs_you=false",
            Caller::Session("operator"),
            ids(&["app/prod", "web/prod"]),
        ),
        ("?needs_you=true", Caller::Token("operator"), ids(&[])),
        (
            "?needs_you=true&host=home-1&repo=example/app",
            Caller::Session("operator"),
            ids(&["app/staging"]),
        ),
    ] {
        let answer = fleet
            .get(&format!("/api/v1/deployments{query}"), caller)
            .await;
        assert_eq!(page(&answer), (want, None), "{query}, {caller:?}");
        assert_schema(&doc, "listDeployments", &answer.json());
    }
    for query in ["?host=Home_1", "?repo=nope", "?needs_you=maybe"] {
        let answer = fleet
            .get(
                &format!("/api/v1/deployments{query}"),
                Caller::Token("operator"),
            )
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{query}");
        assert_eq!(answer.code(), "bad_request");
        assert_documented(&doc, "listDeployments", query, &answer);
    }
}

#[tokio::test]
async fn needs_you_is_an_open_request_this_principal_can_approve() {
    let fleet = Fleet::seed().await;
    let staging = |answer: Answer| {
        let body = answer.json();
        let item = body["items"]
            .as_array()
            .unwrap()
            .iter()
            .find(|item| item["id"] == "app/staging")
            .unwrap()
            .clone();
        (item["open_request"].clone(), item["needs_you"].clone())
    };
    let open = json!(fleet.request);
    for (caller, needs_you) in [
        // An approver on its rule, in a session.
        (Caller::Session("operator"), true),
        // The same approver's token never approves.
        (Caller::Token("operator"), false),
        // An approver by key, who may approve another deployment and not this one.
        (Caller::Session("bystander"), false),
        // Who may only view.
        (Caller::Session("viewer"), false),
    ] {
        let answer = fleet.get("/api/v1/deployments", caller).await;
        assert_eq!(
            staging(answer),
            (open.clone(), json!(needs_you)),
            "{caller:?}"
        );
    }
    // `getDeployment` says the same.
    let answer = fleet
        .get(
            "/api/v1/deployments/app/staging",
            Caller::Session("operator"),
        )
        .await;
    let summary = &answer.json()["summary"];
    assert_eq!(summary["open_request"], open);
    assert_eq!(summary["needs_you"], true);
    // A request past its time waits for nobody, whether or not the watcher has ended it.
    fleet.clock.advance(REQUEST_LIFETIME_SECS);
    let answer = fleet
        .get("/api/v1/deployments", Caller::Session("operator"))
        .await;
    assert_eq!(staging(answer), (Value::Null, json!(false)));
}

#[tokio::test]
async fn list_pages_in_id_order() {
    let doc = served_document().await;
    let fleet = Fleet::seed().await;
    let path = "/api/v1/deployments";
    let answer = fleet
        .get(&format!("{path}?limit=2"), Caller::Token("viewer"))
        .await;
    let (first, cursor) = page(&answer);
    assert_eq!(first, ["app/prod", "app/staging"]);
    assert_schema(&doc, "listDeployments", &answer.json());
    let cursor = cursor.expect("a next page");
    let answer = fleet
        .get(
            &format!("{path}?limit=2&cursor={cursor}"),
            Caller::Token("viewer"),
        )
        .await;
    assert_eq!(page(&answer), (vec!["web/prod".to_owned()], None));
    // A page exactly as long as what is left is the last.
    let answer = fleet
        .get(&format!("{path}?limit=3"), Caller::Token("viewer"))
        .await;
    assert_eq!(page(&answer).1, None);
    // A page is never short of what this principal may see: `app/staging`, which they may
    // not, is left out before the page is cut.
    let answer = fleet
        .get(&format!("{path}?limit=1"), Caller::Token("gapped"))
        .await;
    let (first, cursor) = page(&answer);
    assert_eq!(first, ["app/prod"]);
    let answer = fleet
        .get(
            &format!("{path}?limit=1&cursor={}", cursor.unwrap()),
            Caller::Token("gapped"),
        )
        .await;
    assert_eq!(page(&answer), (vec!["web/prod".to_owned()], None));
    // Another list's cursor, and one that was changed, are refused.
    let releases = URL_SAFE_NO_PAD.encode("v1.releases.app/prod");
    for cursor in [releases.as_str(), "djEuZGVwbG95bWVudHMu", "%%"] {
        let answer = fleet
            .get(&format!("{path}?cursor={cursor}"), Caller::Token("viewer"))
            .await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{cursor}");
        assert_eq!(answer.code(), "bad_request");
        assert_documented(&doc, "listDeployments", cursor, &answer);
    }
}

#[tokio::test]
async fn limit_outside_1_to_100_is_refused() {
    let doc = served_document().await;
    let fleet = Fleet::seed().await;
    for limit in ["0", "101", "100000", "-1", "x", ""] {
        let path = format!("/api/v1/deployments?limit={limit}");
        let answer = fleet.get(&path, Caller::Token("viewer")).await;
        assert_eq!(answer.status, StatusCode::BAD_REQUEST, "{limit:?}");
        assert_eq!(answer.code(), "bad_request");
        assert_documented(&doc, "listDeployments", &path, &answer);
    }
    for (limit, count) in [("1", 1), ("100", 3)] {
        let path = format!("/api/v1/deployments?limit={limit}");
        let answer = fleet.get(&path, Caller::Token("viewer")).await;
        assert_eq!(page(&answer).0.len(), count, "{limit}");
    }
}

#[tokio::test]
async fn deployment_shows_rule_promotion_holds_and_running() {
    let doc = served_document().await;
    let world = World::seed().await;
    let canary: DeploymentId = "app/canary".parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    world
        .store
        .set_hold(
            (&canary, &host),
            Some(&"v3.1.0".parse().unwrap()),
            "the bundle could not be fetched",
            false,
        )
        .await
        .unwrap();
    world.clock.advance(10);
    world
        .store
        .set_hold((&canary, &host), None, "GitHub did not answer", true)
        .await
        .unwrap();
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/canary",
            Caller::Token(FLEET_VIEWER),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let body = answer.json();
    assert_schema(&doc, "getDeployment", &body);
    // Every holder of `approve`, as the World's rules list them.
    let approvers = body["rule"]["approvers"].clone();
    assert_eq!(approvers.as_array().unwrap().len(), 8, "{approvers}");
    assert!(
        approvers
            .as_array()
            .unwrap()
            .contains(&json!(holder(&["approve"]))),
        "{approvers}"
    );
    assert_eq!(
        body,
        json!({
            "summary": {
                "id": "app/canary",
                "repo": "example/app",
                "host": "home-1",
                "running": {
                    "tag": "v3.0.0",
                    "digest": world_digest('d'),
                    "phase": "idle",
                    "busy": false,
                    "drift": false,
                    "config_drift": false,
                    "healthy_secs": 0,
                    "last_report": NOW,
                },
                "latest": null,
                "open_request": null,
                "needs_you": false,
            },
            "rule": {
                "auto": "patch",
                "approve": "minor",
                "approvers": approvers,
                "prereleases": false,
            },
            "promote_to": { "deployment": "app/beta", "healthy_for_secs": 3600 },
            "promoted_from": [],
            "holds": [
                {
                    "tag": null,
                    "reason": "\"GitHub did not answer\"",
                    "since": NOW + 10,
                    "last_try": NOW + 10,
                },
                {
                    "tag": "v3.1.0",
                    "reason": "\"the bundle could not be fetched\"",
                    "since": NOW,
                    "last_try": NOW,
                },
            ],
            "holds_total": 2,
        })
    );
}

#[tokio::test]
async fn deployment_shows_where_its_releases_come_from() {
    let doc = served_document().await;
    let world = World::seed().await;
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/beta",
            Caller::Token(FLEET_VIEWER),
            None,
        )
        .await;
    let body = answer.json();
    assert_schema(&doc, "getDeployment", &body);
    assert_eq!(body["summary"]["running"], Value::Null);
    assert_eq!(body["promote_to"], Value::Null);
    assert_eq!(
        body["promoted_from"],
        json!([{ "deployment": "app/canary", "healthy_for_secs": 3600 }])
    );
    assert_eq!(body["holds"], json!([]));
    assert_eq!(body["holds_total"], 0);
}

#[tokio::test]
async fn holds_keep_the_newest_50_and_count_all() {
    let world = World::seed().await;
    let canary: DeploymentId = "app/canary".parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    for minor in 0..60 {
        let tag = format!("v3.{minor}.1").parse().unwrap();
        world
            .store
            .set_hold((&canary, &host), Some(&tag), "not yet", false)
            .await
            .unwrap();
        world.clock.advance(1);
    }
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/canary",
            Caller::Token(FLEET_VIEWER),
            None,
        )
        .await;
    let body = answer.json();
    assert_eq!(body["holds_total"], 60);
    let tags: Vec<&str> = body["holds"]
        .as_array()
        .unwrap()
        .iter()
        .map(|hold| hold["tag"].as_str().unwrap())
        .collect();
    let newest: Vec<String> = (10..60)
        .rev()
        .map(|minor| format!("v3.{minor}.1"))
        .collect();
    assert_eq!(tags, newest);
}

#[tokio::test]
async fn promotion_to_an_unseen_deployment_is_not_named() {
    let world = World::seed().await;
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/canary",
            Caller::Token(CANARY_VIEWER),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(
        answer.json()["promote_to"],
        json!({ "deployment": null, "unseen": true, "healthy_for_secs": 3600 })
    );
    let text = String::from_utf8(answer.body.clone()).unwrap();
    assert!(!text.contains("app/beta"), "{text}");
    for path in ["/api/v1/deployments", "/api/v1/me"] {
        let answer = world
            .send(Method::GET, path, Caller::Token(CANARY_VIEWER), None)
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{path}");
        let text = String::from_utf8(answer.body.clone()).unwrap();
        assert!(!text.contains("app/beta"), "{path}: {text}");
    }
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/beta",
            Caller::Token(CANARY_VIEWER),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_report_from_a_host_no_longer_paired_is_ignored() {
    let fleet = Fleet::seed().await;
    let path = "/api/v1/deployments/app/prod";
    let running = |answer: Answer| answer.json()["summary"]["running"].clone();
    let paired = fleet.get(path, Caller::Token("viewer")).await;
    assert_eq!(running(paired)["tag"], "v1.2.0");
    // `app/prod` moves to `home-2`, which hasn't reported it: what `home-1` said is not its.
    let moved = fleet.reconfigured("home-2");
    let answer = fleet.get_from(&moved, path, Caller::Token("viewer")).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    assert_eq!(running(answer), Value::Null);
    let answer = fleet
        .get_from(&moved, "/api/v1/deployments", Caller::Token("viewer"))
        .await;
    let body = answer.json();
    let prod = body["items"]
        .as_array()
        .unwrap()
        .iter()
        .find(|item| item["id"] == "app/prod")
        .unwrap()
        .clone();
    assert_eq!(prod["host"], "home-2");
    assert_eq!(prod["running"], Value::Null);
}

#[tokio::test]
async fn unseen_deployment_is_not_found_and_another_grant_is_forbidden() {
    let doc = served_document().await;
    let world = World::seed().await;
    let get = |path: &'static str, name: &'static str| {
        let world = &world;
        async move {
            world
                .send(Method::GET, path, Caller::Token(name), None)
                .await
        }
    };
    let missing = get("/api/v1/deployments/app/nowhere", OUTSIDER).await;
    assert_eq!(missing.status, StatusCode::NOT_FOUND);
    for path in [
        "/api/v1/deployments/app/prod",
        "/api/v1/deployments/app/canary",
        "/api/v1/deployments/App/prod",
        "/api/v1/deployments/app/prod%2F",
    ] {
        let answer = get(path, OUTSIDER).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(answer.body, missing.body, "{path}");
        assert_documented(&doc, "getDeployment", path, &answer);
    }
    let others = holder(&["request", "approve", "rollback"]);
    let answer = world
        .send(
            Method::GET,
            "/api/v1/deployments/app/prod",
            Caller::Token(&others),
            None,
        )
        .await;
    assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
    assert_eq!(answer.code(), "forbidden");
    assert_documented(&doc, "getDeployment", "another grant", &answer);
    let listed = world
        .send(
            Method::GET,
            "/api/v1/deployments",
            Caller::Token(&others),
            None,
        )
        .await;
    assert_eq!(page(&listed), (Vec::new(), None));
}
