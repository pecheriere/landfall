//! `/api/v1` through the controller's real router, on an in-memory store seeded through the
//! store's own functions.

mod document;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode, header};
use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, HostId, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::agent_api::{ApiState, Limits};
use crate::store::{NewRequest, ReleaseDecision, Seen, Store};

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
        let answer = self.router.clone().oneshot(request).await.unwrap();
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
