//! `/api/v1` through the controller's real router, on an in-memory store seeded through the
//! store's own functions.

mod deployments;
mod document;
mod grants;
mod query;
mod reads;
mod schemas;

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{DeployedRelease, Phase, RunningState};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::agent_api::{ApiState, Limits};
use crate::auth::{ApiToken, SessionToken};
use crate::store::{ManualClock, NewRequest, ReleaseDecision, Seen, Store};

/// `operator` may view `app/prod` and ask for its releases, and is its approver by key, with
/// no grant to approve.
const CONFIG: &str = r#"
[approval]
rp_id = "landfall.example.com"
origin = "https://landfall.example.com"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "home-1"
compose = { dir = "/srv/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { auto = "patch", approvers = ["operator"] }
checks = ["container-healthy"]

[[grant]]
principal = "operator"
deployments = ["app/prod"]
can = ["view", "request"]
"#;

/// An HTTP answer, read in full.
#[derive(Debug)]
pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

impl Answer {
    pub(super) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    /// A refusal's code.
    pub(super) fn code(&self) -> String {
        self.json()["code"].as_str().unwrap().to_owned()
    }
}

/// What `router` answers to `request`, read in full.
pub(super) async fn answer(router: &Router, request: Request<Body>) -> Answer {
    let answer = router.clone().oneshot(request).await.unwrap();
    let status = answer.status();
    let headers = answer.headers().clone();
    let body = axum::body::to_bytes(answer.into_body(), usize::MAX)
        .await
        .unwrap()
        .to_vec();
    Answer {
        status,
        headers,
        body,
    }
}

/// The controller's router on a store of its own.
pub(super) struct App {
    router: Router,
    store: Store,
    config: Config,
}

impl App {
    pub(super) async fn new() -> Self {
        let store = Store::open_in_memory().await.unwrap();
        let config = landfall_approval::parse_config(CONFIG.as_bytes()).unwrap();
        let state = ApiState::new(store.clone(), config.clone(), Limits::default());
        Self {
            router: crate::router(state),
            store,
            config,
        }
    }

    pub(super) async fn send(&self, request: Request<Body>) -> Answer {
        answer(&self.router, request).await
    }

    /// A `GET` of `path`, with this bearer token if any and this `Origin` if any.
    pub(super) async fn get(
        &self,
        path: &str,
        token: Option<&str>,
        origin: Option<&str>,
    ) -> Answer {
        let mut request = Request::builder().uri(path);
        if let Some(token) = token {
            request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        self.send(request.body(Body::empty()).unwrap()).await
    }

    /// A new API token for `principal`.
    pub(super) async fn token(&self, principal: &str) -> String {
        let (_, token) = self
            .store
            .create_token(&principal.parse().unwrap())
            .await
            .unwrap();
        token.reveal()
    }

    /// Opens a request by `operator` for `v1.3.0` on `app/prod`, over `v1.2.0`, as asking
    /// does once it has judged one.
    pub(super) async fn open_request(&self) {
        let deployment: DeploymentId = "app/prod".parse().unwrap();
        let host: HostId = "home-1".parse().unwrap();
        let tag: ReleaseTag = "v1.3.0".parse().unwrap();
        let commit = "3".repeat(40).parse().unwrap();
        let digest = format!("sha256:{}", "3".repeat(64)).parse().unwrap();
        let seen = Seen {
            tag_object: "object",
            config_hash: self.config.hash(),
            commit: Some(&commit),
            digest: Some(&digest),
            refused: false,
            detail: json!({}),
            origin: json!({}),
        };
        self.store
            .record_release(
                (&deployment, &host, &tag),
                ReleaseDecision::NeedsApproval,
                "a higher version that needs an approver",
                Some(&seen),
            )
            .await
            .unwrap();
        let operator: PrincipalId = "operator".parse().unwrap();
        let request = NewRequest {
            host: &host,
            intent: DeployIntent {
                deployment,
                tag,
                commit,
                digest,
                expected_running: Some(format!("sha256:{}", "2".repeat(64)).parse().unwrap()),
                nonce: [7; 32],
            },
            requested_by: &operator,
            audited_by: json!({ "principal": "operator" }),
            is_rollback: false,
        };
        let mut tx = self.store.begin().await.unwrap();
        self.store.insert_request(&mut tx, &request).await.unwrap();
        tx.commit().await.unwrap();
    }
}

/// The grants a principal may hold on a deployment, in the order a holder's name lists them.
pub(super) const ROLES: [&str; 4] = ["view", "request", "approve", "rollback"];

/// Who asked for the open request on `app/staging`, with `request` there and nothing else.
pub(super) const REQUESTER: &str = "requester";

/// Who holds `view` on `app/other`, and no grant on `app/prod` or `app/staging`.
pub(super) const OUTSIDER: &str = "outsider";

/// Who holds `view` on `app/canary`, and not on `app/beta`, which it promotes to.
pub(super) const CANARY_VIEWER: &str = "canary-viewer";

/// Who holds `view` on `app/canary` and `app/beta`.
pub(super) const FLEET_VIEWER: &str = "fleet-viewer";

const WORLD_ORIGIN: &str = "https://landfall.example.com";
const WORLD_RP_ID: &str = "landfall.example.com";

/// Who holds exactly these grants on `app/prod` and `app/staging`: their names in [`ROLES`]'
/// order, joined by `-`. `view-request-approve-rollback` holds every grant.
pub(super) fn holder(roles: &[&str]) -> String {
    ROLES
        .iter()
        .filter(|role| roles.contains(role))
        .copied()
        .collect::<Vec<_>>()
        .join("-")
}

/// Every set of grants but none.
fn grant_sets() -> Vec<Vec<&'static str>> {
    (1..16_u8)
        .map(|bits| {
            ROLES
                .iter()
                .enumerate()
                .filter(|(i, _)| bits & (1 << i) != 0)
                .map(|(_, role)| *role)
                .collect()
        })
        .collect()
}

fn world_digest(fill: char) -> ImageDigest {
    format!("sha256:{}", fill.to_string().repeat(64))
        .parse()
        .unwrap()
}

/// `app/prod`, `app/staging`, `app/other`, `app/canary` and `app/beta`, all on `home-1`,
/// with `app/canary` promoting to `app/beta` after an hour. Every holder of a set of grants
/// has it on `app/prod` and `app/staging`, and each holder of `approve` is an approver of
/// every deployment by key.
fn world_config(keys: &HashMap<String, SoftwareAuthenticator>) -> String {
    let mut approvers: Vec<&String> = keys.keys().collect();
    approvers.sort();
    let mut sections = vec![format!(
        "[approval]\nrp_id = \"{WORLD_RP_ID}\"\norigin = \"{WORLD_ORIGIN}\"\n\n[approvers]\n"
    )];
    sections.extend(approvers.iter().map(|name| {
        let key = &keys[*name];
        format!(
            "{name} = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
            URL_SAFE_NO_PAD.encode(key.credential_id()),
            URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
        )
    }));
    let listed = quoted_list(&approvers);
    let promotion = "promote_to = { deployment = \"app/beta\", healthy_for = \"1h\" }\n";
    sections.extend(
        [
            (1, "prod", ""),
            (2, "staging", ""),
            (3, "other", ""),
            (4, "canary", promotion),
            (4, "beta", ""),
        ]
        .map(|(repo, stage, extra)| {
            format!(
                r#"
[[deployment]]
id = "app/{stage}"
repo = {{ name = "example/app", id = {repo}, owner_id = 9 }}
host = "home-1"
compose = {{ dir = "/srv/{stage}", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = [{listed}] }}
checks = ["container-healthy"]
{extra}"#
            )
        }),
    );
    let grant = |principal: &str, deployments: &[&str], can: &[&str]| {
        format!(
            "\n[[grant]]\nprincipal = \"{principal}\"\ndeployments = [{}]\ncan = [{}]\n",
            quoted_list(deployments),
            quoted_list(can),
        )
    };
    sections.extend(
        grant_sets()
            .iter()
            .map(|roles| grant(&holder(roles), &["app/prod", "app/staging"], roles)),
    );
    sections.push(grant(REQUESTER, &["app/staging"], &["request"]));
    sections.push(grant(OUTSIDER, &["app/other"], &["view"]));
    sections.push(grant(CANARY_VIEWER, &["app/canary"], &["view"]));
    sections.push(grant(FLEET_VIEWER, &["app/canary", "app/beta"], &["view"]));
    sections.concat()
}

/// `"a", "b"`, for a TOML array.
fn quoted_list(items: &[impl std::fmt::Display]) -> String {
    items
        .iter()
        .map(|item| format!("\"{item}\""))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Who a request comes from, by the principal's name in the [`World`].
#[derive(Debug, Clone, Copy)]
pub(super) enum Caller<'a> {
    Nobody,
    Token(&'a str),
    /// A session, sending the configured `Origin`.
    Session(&'a str),
}

/// A controller in a known state, which only grants decide `requestDeploy` on `app/prod`:
///
/// - `app/prod` runs `v1.2.0`, and `v1.3.0` above it and `v1.1.0` below it are verified. It
///   has no open request and no promotion.
/// - `app/staging` runs `v2.0.0`, `v2.1.0` is verified, and [`REQUESTER`] has asked for it:
///   the open request `approveRequest` and `cancelRequest` act on.
/// - `app/other` has nothing, and [`OUTSIDER`] may view it.
/// - `app/canary` runs `v3.0.0` and promotes to `app/beta`, which has nothing. Neither is
///   `app/prod`, where a promotion would answer `requestDeploy` with `promotion_pending`.
///   [`CANARY_VIEWER`] may view `app/canary` alone, and [`FLEET_VIEWER`] both.
///
/// Every principal has a token and a session. Time stands still until a test moves `clock`.
pub(super) struct World {
    pub(super) app: Router,
    pub(super) state: ApiState,
    pub(super) store: Store,
    pub(super) clock: Arc<ManualClock>,
    pub(super) tokens: HashMap<String, ApiToken>,
    pub(super) sessions: HashMap<String, SessionToken>,
    keys: HashMap<String, SoftwareAuthenticator>,
    /// The open request on `app/staging`.
    pub(super) request: (i64, DeployIntent),
}

impl World {
    pub(super) async fn seed() -> Self {
        let keys: HashMap<String, SoftwareAuthenticator> = grant_sets()
            .iter()
            .filter(|roles| roles.contains(&"approve"))
            .map(|roles| (holder(roles), SoftwareAuthenticator::es256().unwrap()))
            .collect();
        let config = landfall_approval::parse_config(world_config(&keys).as_bytes()).unwrap();
        let clock = ManualClock::at(1_800_000_000);
        let store = Store::open_in_memory()
            .await
            .unwrap()
            .with_clock(clock.clone());
        let state = ApiState::new(store.clone(), config.clone(), Limits::default());
        for (deployment, tag, fill) in [
            ("app/prod", "v1.1.0", '1'),
            ("app/prod", "v1.3.0", '3'),
            ("app/staging", "v2.1.0", 'c'),
        ] {
            verified(&store, &config, deployment, tag, fill).await;
        }
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
        let (prod, staging, canary) = (
            running("app/prod", "v1.2.0", '2'),
            running("app/staging", "v2.0.0", 'b'),
            running("app/canary", "v3.0.0", 'd'),
        );
        store
            .record_host_state(
                &"home-1".parse().unwrap(),
                None,
                &[&prod, &staging, &canary],
            )
            .await
            .unwrap();
        let request = open_request(&store).await;
        let mut names: Vec<String> = grant_sets().iter().map(|roles| holder(roles)).collect();
        names.extend([REQUESTER, OUTSIDER, CANARY_VIEWER, FLEET_VIEWER].map(ToOwned::to_owned));
        let mut tokens = HashMap::new();
        let mut sessions = HashMap::new();
        for name in names {
            let (_, token) = store.create_token(&name.parse().unwrap()).await.unwrap();
            tokens.insert(name.clone(), token);
            sessions.insert(
                name.clone(),
                store.begin_session_for_test(&name, 3600).await,
            );
        }
        Self {
            app: crate::router(state.clone()),
            state,
            store,
            clock,
            tokens,
            sessions,
            keys,
            request,
        }
    }

    /// What the router answers.
    pub(super) async fn send(
        &self,
        method: Method,
        path: &str,
        caller: Caller<'_>,
        body: Option<String>,
    ) -> Answer {
        let mut request = Request::builder().method(method).uri(path);
        match caller {
            Caller::Nobody => {}
            Caller::Token(name) => {
                let token = self.tokens[name].reveal();
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            Caller::Session(name) => {
                let session = self.sessions[name].reveal();
                request = request
                    .header(header::COOKIE, format!("__Host-landfall-session={session}"))
                    .header(header::ORIGIN, WORLD_ORIGIN);
            }
        }
        if body.is_some() {
            request = request.header(header::CONTENT_TYPE, "application/json");
        }
        let body = body.map_or_else(Body::empty, Body::from);
        answer(&self.app, request.body(body).unwrap()).await
    }

    /// The body of an approval of the open request, signed by `name`'s passkey as the
    /// configured page would have it signed.
    pub(super) fn approval_by(&self, name: &str) -> String {
        let ceremony = Ceremony::new(WORLD_RP_ID, WORLD_ORIGIN, &self.request.1.challenge());
        let assertion = self.keys[name].assertion(&ceremony).unwrap();
        json!({
            "assertion": {
                "credential_id": URL_SAFE_NO_PAD.encode(&assertion.credential_id),
                "authenticator_data": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
                "client_data_json": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
                "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
            }
        })
        .to_string()
    }

    /// Every request and deploy, with its state: what a refusal must leave as it was.
    pub(super) async fn rows(&self) -> Vec<(String, i64, String)> {
        sqlx::query_as(
            "SELECT 'request', id, state FROM deploy_requests
             UNION ALL SELECT 'deploy', id, state FROM deploys ORDER BY 1, 2",
        )
        .fetch_all(self.store.pool())
        .await
        .unwrap()
    }
}

/// Records a release as the watcher does once it verified one.
async fn verified(store: &Store, config: &Config, deployment: &str, tag: &str, fill: char) {
    let commit = fill.to_string().repeat(40).parse().unwrap();
    let digest = world_digest(fill);
    let seen = Seen {
        tag_object: "object",
        config_hash: config.hash(),
        commit: Some(&commit),
        digest: Some(&digest),
        refused: false,
        detail: json!({}),
        origin: json!({}),
    };
    store
        .record_release(
            (
                &deployment.parse().unwrap(),
                &"home-1".parse().unwrap(),
                &tag.parse().unwrap(),
            ),
            ReleaseDecision::NeedsApproval,
            "a higher version that needs an approver",
            Some(&seen),
        )
        .await
        .unwrap();
}

/// [`REQUESTER`]'s request for `v2.1.0` on `app/staging`, over `v2.0.0`, as asking records
/// one it has judged.
async fn open_request(store: &Store) -> (i64, DeployIntent) {
    let requester: PrincipalId = REQUESTER.parse().unwrap();
    let host: HostId = "home-1".parse().unwrap();
    let intent = DeployIntent {
        deployment: "app/staging".parse().unwrap(),
        tag: "v2.1.0".parse().unwrap(),
        commit: "c".repeat(40).parse().unwrap(),
        digest: world_digest('c'),
        expected_running: Some(world_digest('b')),
        nonce: [9; 32],
    };
    let request = NewRequest {
        host: &host,
        intent: intent.clone(),
        requested_by: &requester,
        audited_by: json!({ "principal": REQUESTER }),
        is_rollback: false,
    };
    let mut tx = store.begin().await.unwrap();
    let stored = store.insert_request(&mut tx, &request).await.unwrap();
    tx.commit().await.unwrap();
    (stored.id, intent)
}
