//! The agent API through its real router, on an in-memory store.

mod enrol;
mod report;
mod signing;
mod work;

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use landfall_core::config;
use landfall_core::ids::HostId;
use landfall_core::protocol::{
    self, DeployId, DeployReportBody, EnrolRequest, HOST_HEADER, NONCE_HEADER, Nonce,
    NonceResponse, PROBLEM_CONTENT_TYPE, Problem, ReportedOutcome, RunningState, SIGNATURE_HEADER,
    SigningKey, WorkRequest, WorkResponse,
};
use serde::Serialize;
use sqlx::Row as _;
use tower::ServiceExt as _;

use super::{ApiState, Limits, router};
use crate::store::{ManualClock, NewDeploy, Store};

pub(super) const WORK: &str = "/agent/v1/work";
pub(super) const REPORT: &str = "/agent/v1/report";
pub(super) const ENROL: &str = "/agent/v1/enrol";
pub(super) const NONCE: &str = "/agent/v1/nonce";

/// `app/prod` runs on `host-a` and `other/prod` on `host-b`.
const CONFIG: &str = r#"
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "host-a"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = ["container-healthy"]

[[deployment]]
id = "other/prod"
repo = { name = "example/other", id = 1235, owner_id = 5678 }
host = "host-b"
compose = { dir = "/srv/compose/other", service = "other" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = ["container-healthy"]
"#;

/// Limits for tests: a short long poll, and no rate limit in the way.
pub(super) fn test_limits() -> Limits {
    Limits {
        long_poll: Duration::from_millis(100),
        source_rate_per_second: 100_000,
        source_burst: 100_000,
        ..Limits::default()
    }
}

pub(super) fn signing_key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

pub(super) fn host(name: &str) -> HostId {
    name.parse().unwrap()
}

/// A problem's status and code, having checked its shape.
pub(super) fn problem(answer: &Answer) -> (StatusCode, String) {
    assert_eq!(
        answer.headers["content-type"], PROBLEM_CONTENT_TYPE,
        "{answer:?}"
    );
    let problem: Problem = serde_json::from_slice(&answer.body).unwrap();
    assert_eq!(problem.status, answer.status.as_u16());
    (answer.status, problem.code)
}

/// An HTTP answer, read in full.
#[derive(Debug)]
pub(super) struct Answer {
    pub(super) status: StatusCode,
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

impl Answer {
    pub(super) fn code(&self) -> String {
        problem(self).1
    }

    pub(super) fn work(&self) -> WorkResponse {
        assert_eq!(self.status, StatusCode::OK, "{self:?}");
        serde_json::from_slice(&self.body).unwrap()
    }
}

pub(super) struct Harness {
    pub(super) app: Router,
    pub(super) state: ApiState,
    pub(super) store: Store,
    pub(super) clock: Arc<ManualClock>,
    pub(super) config_hash: [u8; 32],
}

impl Harness {
    pub(super) async fn new() -> Self {
        Self::with_limits(test_limits()).await
    }

    pub(super) async fn with_limits(limits: Limits) -> Self {
        let clock = ManualClock::at(1_800_000_000);
        let store = Store::open_in_memory()
            .await
            .unwrap()
            .with_clock(clock.clone());
        let config = config::parse(CONFIG.as_bytes()).unwrap();
        let config_hash: [u8; 32] = hex::decode(config.hash()).unwrap().try_into().unwrap();
        let state = ApiState::new(store.clone(), config, limits);
        Self {
            app: router(state.clone()),
            state,
            store,
            clock,
            config_hash,
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

    pub(super) async fn post_json<T: Serialize>(&self, path: &str, body: &T) -> Answer {
        let request = Request::builder()
            .method(Method::POST)
            .uri(path)
            .body(Body::from(serde_json::to_vec(body).unwrap()))
            .unwrap();
        self.send(request).await
    }

    pub(super) async fn enrol_with(
        &self,
        name: &str,
        key: &SigningKey,
        code: protocol::EnrolCode,
    ) -> Answer {
        let request = EnrolRequest {
            code,
            host: host(name),
            public_key: key.verifying_key(),
        };
        self.post_json(ENROL, &request).await
    }

    /// Issues a code as the operator would and returns it as the wire has it.
    pub(super) async fn code(&self, name: &str, replace: bool) -> protocol::EnrolCode {
        let code = self
            .store
            .issue_enrol_code(&host(name), replace)
            .await
            .unwrap();
        code.reveal().parse().unwrap()
    }

    /// Enrols `name` with the key from `seed`.
    pub(super) async fn enrolled(&self, name: &str, seed: u8) -> SigningKey {
        let key = signing_key(seed);
        let code = self.code(name, false).await;
        let answer = self.enrol_with(name, &key, code).await;
        assert_eq!(answer.status, StatusCode::NO_CONTENT, "{answer:?}");
        key
    }

    pub(super) async fn nonce(&self) -> Nonce {
        let answer = self.get_nonce().await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        serde_json::from_slice::<NonceResponse>(&answer.body)
            .unwrap()
            .nonce
    }

    pub(super) async fn get_nonce(&self) -> Answer {
        self.get_nonce_from("192.0.2.1:1000".parse().unwrap()).await
    }

    pub(super) async fn get_nonce_from(&self, source: SocketAddr) -> Answer {
        let mut request = Request::builder().uri(NONCE).body(Body::empty()).unwrap();
        request.extensions_mut().insert(ConnectInfo(source));
        self.send(request).await
    }

    /// Signs and sends a POST with a fresh nonce.
    pub(super) async fn signed_post<T: Serialize>(
        &self,
        name: &str,
        key: &SigningKey,
        path: &str,
        body: &T,
    ) -> Answer {
        let nonce = self.nonce().await;
        let body = serde_json::to_vec(body).unwrap();
        self.send(signed_request(name, key, path, path, &nonce, body))
            .await
    }

    pub(super) async fn work(
        &self,
        name: &str,
        key: &SigningKey,
        running: Vec<RunningState>,
    ) -> Answer {
        let request = WorkRequest {
            config_hash: self.config_hash,
            running,
        };
        self.signed_post(name, key, WORK, &request).await
    }

    pub(super) async fn report(
        &self,
        name: &str,
        key: &SigningKey,
        body: &DeployReportBody,
    ) -> Answer {
        self.signed_post(name, key, REPORT, body).await
    }

    /// Queues a deploy and wakes the agents, as the watcher does.
    pub(super) async fn queue(&self, deployment: &str, on: &str, tag: &str) -> DeployId {
        let mut tx = self.store.begin().await.unwrap();
        sqlx::query(
            "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
             VALUES (?, ?, 'auto', 'patch', 0)",
        )
        .bind(deployment)
        .bind(tag)
        .execute(&mut *tx)
        .await
        .unwrap();
        let deploy = NewDeploy {
            deployment: deployment.parse().unwrap(),
            host: host(on),
            tag: tag.parse().unwrap(),
            digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
            commit: "a".repeat(40).parse().unwrap(),
        };
        let id = self.store.queue_deploy(&mut tx, &deploy).await.unwrap();
        tx.commit().await.unwrap();
        self.store.wake_agents();
        id
    }

    /// The kinds in the audit log so far, oldest first.
    pub(super) async fn audit_kinds(&self) -> Vec<String> {
        sqlx::query_scalar("SELECT kind FROM audit_events ORDER BY seq")
            .fetch_all(self.store.pool())
            .await
            .unwrap()
    }

    /// The most recent audit row's detail.
    pub(super) async fn last_audit_detail(&self) -> serde_json::Value {
        let row = sqlx::query("SELECT detail FROM audit_events ORDER BY seq DESC LIMIT 1")
            .fetch_one(self.store.pool())
            .await
            .unwrap();
        serde_json::from_str(&row.get::<String, _>("detail")).unwrap()
    }

    /// The most recent `config_drift` row's detail.
    pub(super) async fn last_config_drift(&self) -> serde_json::Value {
        let detail: String = sqlx::query_scalar(
            "SELECT detail FROM audit_events WHERE kind = 'config_drift' ORDER BY seq DESC LIMIT 1",
        )
        .fetch_one(self.store.pool())
        .await
        .unwrap();
        serde_json::from_str(&detail).unwrap()
    }

    pub(super) async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }
}

/// A request to `sent_path`, with a signature made over `signed_path`.
pub(super) fn signed_request(
    name: &str,
    key: &SigningKey,
    signed_path: &str,
    sent_path: &str,
    nonce: &Nonce,
    body: Vec<u8>,
) -> Request<Body> {
    let signature = protocol::sign(key, &host(name), "POST", signed_path, nonce, &body);
    Request::builder()
        .method(Method::POST)
        .uri(sent_path)
        .header(HOST_HEADER, name)
        .header(NONCE_HEADER, nonce.to_string())
        .header(SIGNATURE_HEADER, signature.to_string())
        .body(Body::from(body))
        .unwrap()
}

pub(super) fn deployed_report(id: DeployId) -> DeployReportBody {
    DeployReportBody {
        deploy_id: id,
        outcome: ReportedOutcome::Deployed {},
        steps: Vec::new(),
    }
}
