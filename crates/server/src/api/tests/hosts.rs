//! The hosts, seen through the deployments on them: `listHosts` and `getHost`.

use std::sync::Arc;

use axum::Router;
use axum::http::{Method, StatusCode};
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};
use serde_json::Value;

use super::grants::{assert_documented, served_document};
use super::{Answer, Caller, Credentials, WORLD_ORIGIN, world_digest};
use crate::agent_api::{ApiState, Limits};
use crate::store::{ManualClock, Store};

/// When the fleet's clock starts.
pub(super) const NOW: i64 = 1_800_000_000;

/// When `home-1` enrolled.
const ENROLLED_AT: i64 = NOW - 1000;

/// Who may view `app/prod`, on `home-1`, and nothing else.
pub(super) const VIEWER: &str = "viewer";

/// Who may ask for a deploy of `app/prod`, and not view it.
pub(super) const ASKER: &str = "asker";

/// Who may view `app/edge`, on `home-2`, and nothing else.
pub(super) const EDGE_VIEWER: &str = "edge-viewer";

/// Who may view all three deployments.
pub(super) const FLEET_VIEWER: &str = "fleet-viewer";

const PRINCIPALS: [&str; 4] = [VIEWER, ASKER, EDGE_VIEWER, FLEET_VIEWER];

/// `app/prod` and `app/other` on `home-1`, and `app/edge` on `home-2`: a deployment has one
/// host.
fn hosts_config() -> String {
    let mut text = preamble();
    for (id, repo_id, host) in [
        ("app/prod", 1, "home-1"),
        ("app/other", 2, "home-1"),
        ("app/edge", 3, "home-2"),
    ] {
        text.push_str(&deployment(id, repo_id, host));
    }
    for (principal, deployments, can) in [
        (VIEWER, &["app/prod"][..], "view"),
        (ASKER, &["app/prod"][..], "request"),
        (EDGE_VIEWER, &["app/edge"][..], "view"),
        (
            FLEET_VIEWER,
            &["app/prod", "app/other", "app/edge"][..],
            "view",
        ),
    ] {
        text.push_str(&super::deployments::grant(principal, deployments, &[can]));
    }
    text
}

/// What every configuration of these tests begins with: `[approval]`, and `operator` as an
/// approver by key, who holds no grant.
pub(super) fn preamble() -> String {
    format!(
        r#"[approval]
rp_id = "landfall.example.com"
origin = "{WORLD_ORIGIN}"

[approvers]
operator = {{ credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }}
"#
    )
}

/// A deployment of `example/app` on `host`, which deploys patches by itself and which
/// `operator` approves.
pub(super) fn deployment(id: &str, repo_id: usize, host: &str) -> String {
    let dir = id.replace('/', "-");
    format!(
        r#"
[[deployment]]
id = "{id}"
repo = {{ name = "example/app", id = {repo_id}, owner_id = 9 }}
host = "{host}"
compose = {{ dir = "/srv/{dir}", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approvers = ["operator"] }}
checks = ["container-healthy"]
"#
    )
}

/// A controller on [`hosts_config`], with a token and a session for each principal. `home-1`
/// enrolled at [`ENROLLED_AT`]; `home-2` never has. No host has reported anything.
pub(super) struct Hosts {
    pub(super) app: Router,
    pub(super) store: Store,
    pub(super) clock: Arc<ManualClock>,
    credentials: Credentials,
}

impl Hosts {
    pub(super) async fn seed() -> Self {
        Self::seed_with(&hosts_config(), &PRINCIPALS).await
    }

    /// The same, on the configuration `text`, with credentials for `principals`.
    pub(super) async fn seed_with(text: &str, principals: &[&str]) -> Self {
        let config = landfall_approval::parse_config(text.as_bytes()).unwrap();
        let clock = ManualClock::at(NOW);
        let store = Store::open_in_memory()
            .await
            .unwrap()
            .with_clock(clock.clone());
        sqlx::query("INSERT INTO hosts (id, public_key, enrolled_at) VALUES ('home-1', ?, ?)")
            .bind([1_u8; 32].as_slice())
            .bind(ENROLLED_AT)
            .execute(store.pool())
            .await
            .unwrap();
        let credentials = Credentials::issue(&store, principals).await;
        let app = crate::router(ApiState::new(store.clone(), config, Limits::default()));
        Self {
            app,
            store,
            clock,
            credentials,
        }
    }

    /// What the router answers to a `GET` of `path` from `caller`.
    pub(super) async fn get(&self, path: &str, caller: Caller<'_>) -> Answer {
        self.credentials
            .send(&self.app, Method::GET, path, caller, None)
            .await
    }

    /// `home-1` reports `deployments` running `v1.2.0`, and its configuration's hash as
    /// `drifted` if given, now.
    pub(super) async fn report(&self, deployments: &[&str], drifted: Option<&[u8; 32]>) {
        let states: Vec<RunningState> = deployments
            .iter()
            .map(|deployment| RunningState {
                deployment: deployment.parse().unwrap(),
                deployed: Some(DeployedRelease {
                    tag: "v1.2.0".parse().unwrap(),
                    digest: world_digest('2'),
                }),
                drift: false,
                phase: Phase::Idle,
                busy: false,
            })
            .collect();
        let states: Vec<&RunningState> = states.iter().collect();
        self.store
            .record_host_state(&"home-1".parse().unwrap(), drifted, &states)
            .await
            .unwrap();
    }
}

/// The ids of a host's deployments.
fn deployment_ids(host: &Value) -> Vec<&str> {
    host["deployments"]
        .as_array()
        .unwrap()
        .iter()
        .map(|d| d["id"].as_str().unwrap())
        .collect()
}

/// The hosts `caller` is listed, each with its deployments' ids.
async fn listed(hosts: &Hosts, caller: Caller<'_>) -> Vec<(String, Vec<String>)> {
    let answer = hosts.get("/api/v1/hosts", caller).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    answer.json()["hosts"]
        .as_array()
        .unwrap()
        .iter()
        .map(|host| {
            let ids = deployment_ids(host).into_iter().map(ToOwned::to_owned);
            (host["id"].as_str().unwrap().to_owned(), ids.collect())
        })
        .collect()
}

fn owned(hosts: &[(&str, &[&str])]) -> Vec<(String, Vec<String>)> {
    hosts
        .iter()
        .map(|(id, deployments)| {
            let deployments = deployments.iter().map(|d| (*d).to_owned());
            ((*id).to_owned(), deployments.collect())
        })
        .collect()
}

#[tokio::test]
async fn hosts_show_only_viewable_deployments() {
    let hosts = Hosts::seed().await;
    let doc = served_document().await;
    for caller in [Caller::Token(VIEWER), Caller::Session(VIEWER)] {
        assert_eq!(
            listed(&hosts, caller).await,
            owned(&[("home-1", &["app/prod"])]),
            "{caller:?}"
        );
        let home_1 = hosts.get("/api/v1/hosts/home-1", caller).await;
        assert_eq!(home_1.status, StatusCode::OK, "{home_1:?}");
        assert_eq!(home_1.json()["id"], "home-1");
        assert_eq!(deployment_ids(&home_1.json()), ["app/prod"]);
        // `home-2` runs only `app/edge`, which this principal can't view: the same answer as
        // a host no deployment names, and as a path that isn't a host id.
        let nowhere = hosts.get("/api/v1/hosts/home-9", caller).await;
        assert_eq!(nowhere.status, StatusCode::NOT_FOUND);
        for path in ["/api/v1/hosts/home-2", "/api/v1/hosts/Not%20a%20host"] {
            let answer = hosts.get(path, caller).await;
            assert_eq!(answer.status, StatusCode::NOT_FOUND, "{path}");
            assert_eq!(answer.body, nowhere.body, "{path}");
            assert_documented(&doc, "getHost", path, &answer);
        }
    }
    assert_eq!(
        listed(&hosts, Caller::Token(FLEET_VIEWER)).await,
        owned(&[
            ("home-1", &["app/other", "app/prod"]),
            ("home-2", &["app/edge"]),
        ])
    );
    assert_eq!(
        listed(&hosts, Caller::Token(EDGE_VIEWER)).await,
        owned(&[("home-2", &["app/edge"])])
    );
}

#[tokio::test]
async fn host_with_only_another_grant_is_forbidden() {
    let hosts = Hosts::seed().await;
    let doc = served_document().await;
    for caller in [Caller::Token(ASKER), Caller::Session(ASKER)] {
        let answer = hosts.get("/api/v1/hosts/home-1", caller).await;
        assert_eq!(answer.status, StatusCode::FORBIDDEN, "{answer:?}");
        assert_eq!(answer.code(), "forbidden");
        assert_documented(&doc, "getHost", "another grant", &answer);
        // No grant at all on what runs on `home-2`.
        let answer = hosts.get("/api/v1/hosts/home-2", caller).await;
        assert_eq!(answer.status, StatusCode::NOT_FOUND);
        // A host is listed only for a deployment one may view.
        assert_eq!(listed(&hosts, caller).await, owned(&[]));
    }
}

#[tokio::test]
async fn host_never_enrolled_is_listed_without_enrolled_at() {
    let hosts = Hosts::seed().await;
    let answer = hosts
        .get("/api/v1/hosts/home-2", Caller::Token(EDGE_VIEWER))
        .await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    let home_2 = answer.json();
    assert_eq!(home_2["enrolled_at"], Value::Null);
    assert_eq!(home_2["config_drift"], false);
    assert_eq!(home_2["last_report"], Value::Null);
    assert_eq!(home_2["deployments"][0]["id"], "app/edge");
    assert_eq!(home_2["deployments"][0]["host"], "home-2");
    assert_eq!(home_2["deployments"][0]["running"], Value::Null);
    let list = hosts.get("/api/v1/hosts", Caller::Token(EDGE_VIEWER)).await;
    assert_eq!(list.json()["hosts"][0], home_2);
    // The one that did enrol says when.
    let home_1 = hosts
        .get("/api/v1/hosts/home-1", Caller::Token(VIEWER))
        .await;
    assert_eq!(home_1.json()["enrolled_at"], ENROLLED_AT);
}

/// `home-1`, as `caller` reads it.
async fn home_1(hosts: &Hosts, caller: Caller<'_>) -> Value {
    let answer = hosts.get("/api/v1/hosts/home-1", caller).await;
    assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
    answer.json()
}

#[tokio::test]
async fn host_shows_config_drift_and_last_report() {
    let hosts = Hosts::seed().await;
    let before = home_1(&hosts, Caller::Token(VIEWER)).await;
    assert_eq!(before["config_drift"], false);
    assert_eq!(before["last_report"], Value::Null);
    hosts.report(&["app/prod"], None).await;
    // A minute later, `home-1` says only how `app/other` is, with another configuration.
    hosts.clock.advance(60);
    hosts.report(&["app/other"], Some(&[7; 32])).await;
    let seen = home_1(&hosts, Caller::Token(VIEWER)).await;
    assert_eq!(seen["config_drift"], true);
    assert_eq!(seen["deployments"][0]["running"]["config_drift"], true);
    // What `home-1` last said about a deployment this principal may view, and not when it
    // last spoke of one they can't.
    assert_eq!(seen["last_report"], NOW);
    assert_eq!(seen["deployments"][0]["running"]["last_report"], NOW);
    let fleet = home_1(&hosts, Caller::Token(FLEET_VIEWER)).await;
    assert_eq!(fleet["last_report"], NOW + 60);
    // The host is the same in the list.
    let list = hosts.get("/api/v1/hosts", Caller::Token(VIEWER)).await;
    assert_eq!(list.json()["hosts"][0], seen);
}
