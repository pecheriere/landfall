//! The human API through its real router, with software passkeys.

mod approving;
mod auditing;
mod budget;
mod cancelling;
mod concurrent;
mod credentials;
mod grants;
mod hostile;
mod promotion;
mod requesting;
mod staleness;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use landfall_core::config::Config;
use landfall_core::ids::{HostId, ImageDigest, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{
    DeployedRelease, PROBLEM_CONTENT_TYPE, Phase, Problem, RunningState,
};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::agent_api::{ApiState, Limits};
use crate::auth::Via;
use crate::store::{ManualClock, ReleaseDecision, Seen, Store};

pub(super) const RP_ID: &str = "landfall.example";
pub(super) const ORIGIN: &str = "https://landfall.example";
pub(super) const PROD: &str = "app/prod";
pub(super) const OTHER: &str = "other/prod";
pub(super) const HOST: &str = "host-a";
pub(super) const APPROVALS: &str = "/api/v1/approvals";
pub(super) const PROD_REQUESTS: &str = "/api/v1/deployments/app/prod/requests";

pub(super) fn digest(fill: char) -> ImageDigest {
    format!("sha256:{}", fill.to_string().repeat(64))
        .parse()
        .unwrap()
}

fn approver_line(name: &str, key: &SoftwareAuthenticator) -> String {
    format!(
        "{name} = {{ credential_id = \"{}\", public_key = \"{}\" }}\n",
        URL_SAFE_NO_PAD.encode(key.credential_id()),
        URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
    )
}

/// `alice`, `bob` and `zoe` are approvers on `app/prod`'s rule. `alice` may ask, approve and
/// see; `bob` only approve; `carol` only ask; `dave` only see; `erin` only roll back. `zoe`
/// has no grant on it, and neither does `otto`, whose grants are on `other/prod`.
pub(super) fn config_text(keys: &Keys, extra: &str) -> String {
    format!(
        r#"
[approval]
rp_id = "{RP_ID}"
origin = "{ORIGIN}"

[approvers]
{}{}{}
[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1, owner_id = 2 }}
host = "host-a"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = ["alice", "bob", "zoe"] }}
checks = ["container-healthy"]

[[deployment]]
id = "other/prod"
repo = {{ name = "example/other", id = 3, owner_id = 2 }}
host = "host-b"
compose = {{ dir = "/srv/other", service = "other" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ approvers = ["zoe"] }}
checks = ["container-healthy"]

[[grant]]
principal = "alice"
deployments = ["app/prod"]
can = ["view", "request", "approve"]

[[grant]]
principal = "bob"
deployments = ["app/prod"]
can = ["approve"]

[[grant]]
principal = "carol"
deployments = ["app/prod"]
can = ["request"]

[[grant]]
principal = "dave"
deployments = ["app/prod"]
can = ["view"]

[[grant]]
principal = "erin"
deployments = ["app/prod"]
can = ["rollback"]

[[grant]]
principal = "otto"
deployments = ["other/prod"]
can = ["view", "request"]

[[grant]]
principal = "zoe"
deployments = ["other/prod"]
can = ["approve"]
{extra}
"#,
        approver_line("alice", &keys.alice),
        approver_line("bob", &keys.bob),
        approver_line("zoe", &keys.zoe),
    )
}

/// The passkeys of the approvers.
pub(super) struct Keys {
    pub(super) alice: SoftwareAuthenticator,
    pub(super) bob: SoftwareAuthenticator,
    pub(super) zoe: SoftwareAuthenticator,
}

impl Keys {
    fn new() -> Self {
        Self {
            alice: SoftwareAuthenticator::es256().unwrap(),
            bob: SoftwareAuthenticator::eddsa().unwrap(),
            zoe: SoftwareAuthenticator::es256().unwrap(),
        }
    }
}

/// An HTTP answer, read in full.
#[derive(Debug)]
pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

impl Answer {
    /// The stable code of a problem, having checked its shape.
    pub(super) fn code(&self) -> String {
        assert_eq!(
            self.headers[header::CONTENT_TYPE],
            PROBLEM_CONTENT_TYPE,
            "{self:?}"
        );
        let problem: Problem = serde_json::from_slice(&self.body).unwrap();
        assert_eq!(problem.status, self.status.as_u16());
        problem.code
    }

    pub(super) fn json(&self) -> Value {
        serde_json::from_slice(&self.body).unwrap()
    }

    pub(super) fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// Who a request says it comes from.
#[derive(Debug, Clone)]
pub(super) enum Caller {
    Nobody,
    Token(String),
    /// A session, sending the configured `Origin`.
    Session(String),
    /// A session, sending this `Origin`, or none.
    SessionFrom(String, Option<String>),
}

pub(super) struct Harness {
    pub(super) app: Router,
    pub(super) store: Store,
    pub(super) clock: Arc<ManualClock>,
    pub(super) keys: Keys,
    pub(super) config: Config,
    pub(super) limits: Limits,
}

impl Harness {
    pub(super) async fn new() -> Self {
        Self::on(Store::open_in_memory().await.unwrap(), "")
    }

    /// With more configuration after the rest, and `store` under it.
    pub(super) fn on(store: Store, extra: &str) -> Self {
        let keys = Keys::new();
        let clock = ManualClock::at(1_800_000_000);
        let store = store.with_clock(clock.clone());
        let config = landfall_approval::parse_config(config_text(&keys, extra).as_bytes()).unwrap();
        let limits = Limits::default();
        let state = ApiState::new(store.clone(), config.clone(), limits);
        Self {
            app: crate::router(state),
            store,
            clock,
            keys,
            config,
            limits,
        }
    }

    pub(super) async fn send(&self, request: Request<Body>) -> Answer {
        let answer = self.app.clone().oneshot(request).await.unwrap();
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

    pub(super) async fn call(
        &self,
        method: Method,
        path: &str,
        caller: &Caller,
        body: Vec<u8>,
    ) -> Answer {
        let mut request = Request::builder().method(method).uri(path);
        match caller {
            Caller::Nobody => {}
            Caller::Token(token) => {
                request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
            }
            Caller::Session(session) => {
                request = request
                    .header(header::COOKIE, format!("__Host-landfall-session={session}"))
                    .header(header::ORIGIN, ORIGIN);
            }
            Caller::SessionFrom(session, origin) => {
                request =
                    request.header(header::COOKIE, format!("__Host-landfall-session={session}"));
                if let Some(origin) = origin {
                    request = request.header(header::ORIGIN, origin);
                }
            }
        }
        self.send(request.body(Body::from(body)).unwrap()).await
    }

    pub(super) async fn post(&self, path: &str, caller: &Caller, body: &Value) -> Answer {
        self.call(
            Method::POST,
            path,
            caller,
            serde_json::to_vec(body).unwrap(),
        )
        .await
    }

    pub(super) async fn list(&self, caller: &Caller) -> Answer {
        self.call(Method::GET, APPROVALS, caller, Vec::new()).await
    }

    pub(super) async fn token(&self, name: &str) -> Caller {
        let (_, token) = self
            .store
            .create_token(&name.parse().unwrap())
            .await
            .unwrap();
        Caller::Token(token.reveal())
    }

    pub(super) async fn session(&self, name: &str) -> Caller {
        let session = self.store.begin_session_for_test(name, 3600).await;
        Caller::Session(session.reveal_for_test())
    }

    /// Records a release as the watcher does when it verified one.
    pub(super) async fn verified(&self, deployment: &str, on: &str, tag: &str, fill: char) {
        let commit = fill.to_string().repeat(40).parse().unwrap();
        let digest = digest(fill);
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
                (
                    &deployment.parse().unwrap(),
                    &on.parse::<HostId>().unwrap(),
                    &tag.parse::<ReleaseTag>().unwrap(),
                ),
                ReleaseDecision::NeedsApproval,
                "a higher version that needs an approver",
                Some(&seen),
            )
            .await
            .unwrap();
    }

    /// What `host-a` says it runs of `app/prod`, in a poll's transaction.
    pub(super) async fn reports(&self, running: Option<(&str, char)>) {
        self.reports_state(running, false, Phase::Idle, false).await;
    }

    pub(super) async fn reports_state(
        &self,
        running: Option<(&str, char)>,
        drift: bool,
        phase: Phase,
        busy: bool,
    ) {
        let state = RunningState {
            deployment: PROD.parse().unwrap(),
            deployed: running.map(|(tag, fill)| DeployedRelease {
                tag: tag.parse().unwrap(),
                digest: digest(fill),
            }),
            drift,
            phase,
            busy,
        };
        self.store
            .record_host_state(&HOST.parse().unwrap(), None, &[&state])
            .await
            .unwrap();
    }

    /// `app/prod` runs `v1.0.0` (digest of `0`s), and `v1.1.0` (of `1`s) is verified.
    pub(super) async fn ready(&self) {
        self.reports(Some(("v1.0.0", '0'))).await;
        self.verified(PROD, HOST, "v1.1.0", '1').await;
    }

    pub(super) async fn ask(&self, caller: &Caller, tag: &str) -> Answer {
        self.post(PROD_REQUESTS, caller, &json!({ "tag": tag }))
            .await
    }

    /// Opens a request for `v1.1.0` as `alice`, and gives its number and intent.
    pub(super) async fn opened(&self) -> (i64, DeployIntent) {
        self.ready().await;
        let caller = self.token("alice").await;
        let answer = self.ask(&caller, "v1.1.0").await;
        assert_eq!(answer.status, StatusCode::CREATED, "{answer:?}");
        request_of(&answer.json())
    }

    pub(super) async fn approve(
        &self,
        id: i64,
        caller: &Caller,
        key: &SoftwareAuthenticator,
        intent: &DeployIntent,
    ) -> Answer {
        self.post(
            &format!("{APPROVALS}/{id}"),
            caller,
            &assertion_body(key, intent),
        )
        .await
    }

    /// The kinds in the audit log so far, oldest first.
    pub(super) async fn audit_kinds(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT kind FROM audit_events ORDER BY seq")
            .fetch_all(self.store.pool())
            .await
            .unwrap()
    }

    /// The details of every audit row of this kind, oldest first.
    pub(super) async fn audited(&self, kind: &str) -> Vec<Value> {
        let details: Vec<String> =
            sqlx::query_scalar("SELECT detail FROM audit_events WHERE kind = ? ORDER BY seq")
                .bind(kind)
                .fetch_all(self.store.pool())
                .await
                .unwrap();
        details
            .iter()
            .map(|detail| serde_json::from_str(detail).unwrap())
            .collect()
    }

    pub(super) async fn count_deploys(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM deploys")
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }

    pub(super) async fn request_state(&self, id: i64) -> String {
        sqlx::query_scalar("SELECT state FROM deploy_requests WHERE id = ?")
            .bind(id)
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }
}

/// A request's number and intent from its JSON.
pub(super) fn request_of(view: &Value) -> (i64, DeployIntent) {
    (
        view["id"].as_i64().unwrap(),
        serde_json::from_value(view["intent"].clone()).unwrap(),
    )
}

/// An honest ceremony over `intent`, as the configured page would run it.
pub(super) fn ceremony(intent: &DeployIntent) -> Ceremony {
    Ceremony::new(RP_ID, ORIGIN, &intent.challenge())
}

/// The body of an approval, from this ceremony.
pub(super) fn body_of(key: &SoftwareAuthenticator, ceremony: &Ceremony) -> Value {
    let assertion = key.assertion(ceremony).unwrap();
    json!({
        "assertion": {
            "credential_id": URL_SAFE_NO_PAD.encode(&assertion.credential_id),
            "authenticator_data": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            "client_data_json": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
            "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
        }
    })
}

/// The body of an approval by `key` of `intent`.
pub(super) fn assertion_body(key: &SoftwareAuthenticator, intent: &DeployIntent) -> Value {
    body_of(key, &ceremony(intent))
}

pub(super) fn principal(name: &str, via: Via) -> crate::auth::Principal {
    crate::auth::Principal::for_test(name, via)
}
