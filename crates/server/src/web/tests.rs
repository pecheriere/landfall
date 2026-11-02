//! The ceremonies through the real router, with software passkeys.

mod approving;
mod flood;
mod origin;
mod pages;
mod registration;
mod sessions;
mod sign_in;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Assertion, Ceremony, SoftwareAuthenticator};
use serde_json::{Value, json};
use tower::ServiceExt as _;

use crate::agent_api::{ApiState, Limits};
use crate::store::{ManualClock, Store};

pub(super) const RP_ID: &str = "landfall.example";
pub(super) const ORIGIN: &str = "https://landfall.example";
pub(super) const COOKIE_NAME: &str = "__Host-landfall-session";

pub(super) const REGISTER_BEGIN: &str = "/passkeys/register/begin";
pub(super) const REGISTER_FINISH: &str = "/passkeys/register/finish";
pub(super) const SIGN_IN_BEGIN: &str = "/sign-in/begin";
pub(super) const SIGN_IN_FINISH: &str = "/sign-in/finish";
pub(super) const SIGN_OUT: &str = "/sign-out";

pub(super) fn b64(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(super) fn from_b64(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

/// `alice` is an approver who may approve and ask. `gina` may see and ask and has no key in
/// the file. Anyone else is unknown to it.
pub(super) fn config_text(alice: &SoftwareAuthenticator) -> String {
    format!(
        r#"
[approval]
rp_id = "{RP_ID}"
origin = "{ORIGIN}"

[approvers]
alice = {{ credential_id = "{}", public_key = "{}" }}

[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1, owner_id = 2 }}
host = "host-a"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = ["alice"] }}
checks = ["container-healthy"]

[[grant]]
principal = "alice"
deployments = ["app/prod"]
can = ["view", "request", "approve"]

[[grant]]
principal = "gina"
deployments = ["app/prod"]
can = ["view", "request"]
"#,
        b64(alice.credential_id()),
        b64(alice.key().unwrap().as_bytes()),
    )
}

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

    pub(super) fn code(&self) -> String {
        self.json()["code"].as_str().unwrap().to_owned()
    }

    /// The session token this answer sets.
    pub(super) fn session(&self) -> String {
        let cookie = self.headers[header::SET_COOKIE].to_str().unwrap();
        let (pair, _) = cookie.split_once(';').unwrap();
        pair.strip_prefix(COOKIE_NAME)
            .and_then(|rest| rest.strip_prefix('='))
            .unwrap()
            .to_owned()
    }
}

pub(super) struct Harness {
    pub(super) app: Router,
    pub(super) store: Store,
    pub(super) clock: Arc<ManualClock>,
    pub(super) state: ApiState,
    pub(super) alice: SoftwareAuthenticator,
}

impl Harness {
    pub(super) async fn new() -> Self {
        Self::with_limits(Limits::default()).await
    }

    pub(super) async fn with_limits(limits: Limits) -> Self {
        let alice = SoftwareAuthenticator::es256().unwrap();
        let text = config_text(&alice);
        Self::on(Store::open_in_memory().await.unwrap(), &text, limits, alice)
    }

    /// With this configuration over `store`, and the clock at its usual start.
    pub(super) fn on(
        store: Store,
        config: &str,
        limits: Limits,
        alice: SoftwareAuthenticator,
    ) -> Self {
        let clock = ManualClock::at(1_800_000_000);
        let store = store.with_clock(clock.clone());
        let config = landfall_approval::parse_config(config.as_bytes()).unwrap();
        let state = ApiState::new(store.clone(), config, limits);
        Self {
            app: crate::router(state.clone()),
            state,
            store,
            clock,
            alice,
        }
    }

    /// The same database under another configuration, as a restart would have it.
    pub(super) fn reloaded(&self, config: &str) -> Router {
        let config = landfall_approval::parse_config(config.as_bytes()).unwrap();
        crate::router(ApiState::new(self.store.clone(), config, Limits::default()))
    }

    pub(super) async fn send(&self, request: Request<Body>) -> Answer {
        answer_of(&self.app, request).await
    }

    /// A POST from the configured origin, with this cookie if any.
    pub(super) async fn post(&self, path: &str, cookie: Option<&str>, body: &Value) -> Answer {
        answer_of(&self.app, post_request(path, Some(ORIGIN), cookie, body)).await
    }

    pub(super) async fn get(&self, path: &str) -> Answer {
        self.send(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
    }

    /// A new invite's code for `name`.
    pub(super) async fn invite(&self, name: &str) -> String {
        self.store
            .issue_passkey_invite(&name.parse().unwrap())
            .await
            .unwrap()
            .reveal()
    }

    /// What `begin` gave a registration to sign.
    pub(super) async fn begin_registration(&self, code: &str) -> Vec<u8> {
        let answer = self
            .post(REGISTER_BEGIN, None, &json!({ "code": code }))
            .await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        challenge_of(&answer)
    }

    /// Runs a whole registration with `key`.
    pub(super) async fn register(&self, code: &str, key: &SoftwareAuthenticator) -> Answer {
        let challenge = self.begin_registration(code).await;
        self.post(
            REGISTER_FINISH,
            None,
            &attestation_body(code, key, &Ceremony::new(RP_ID, ORIGIN, &challenge)),
        )
        .await
    }

    /// What `begin` gave a sign-in to sign.
    pub(super) async fn begin_sign_in(&self) -> Vec<u8> {
        let answer = self.post(SIGN_IN_BEGIN, None, &json!({})).await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        challenge_of(&answer)
    }

    /// Runs a whole sign-in with `key`, and gives the answer to its finish.
    pub(super) async fn try_sign_in(&self, key: &SoftwareAuthenticator) -> Answer {
        let challenge = self.begin_sign_in().await;
        self.post(SIGN_IN_FINISH, None, &sign_in_body(key, &challenge))
            .await
    }

    /// Signs in with `key`, which has to work, and gives the cookie's value.
    pub(super) async fn signed_in(&self, key: &SoftwareAuthenticator) -> String {
        let answer = self.try_sign_in(key).await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        answer.session()
    }

    /// `name` holds a passkey of their own, registered through the page.
    pub(super) async fn registered(&self, name: &str) -> SoftwareAuthenticator {
        let key = SoftwareAuthenticator::es256().unwrap();
        let code = self.invite(name).await;
        let answer = self.register(&code, &key).await;
        assert_eq!(answer.status, StatusCode::OK, "{answer:?}");
        key
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

    pub(super) async fn count(&self, table: &str) -> i64 {
        sqlx::query_scalar(sqlx::AssertSqlSafe(format!("SELECT count(*) FROM {table}")))
            .fetch_one(self.store.pool())
            .await
            .unwrap()
    }
}

pub(super) async fn answer_of(app: &Router, request: Request<Body>) -> Answer {
    let answer = app.clone().oneshot(request).await.unwrap();
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

/// A POST with this `Origin`, if any, and this cookie, if any.
pub(super) fn post_request(
    path: &str,
    origin: Option<&str>,
    cookie: Option<&str>,
    body: &Value,
) -> Request<Body> {
    let mut request = Request::builder().method(Method::POST).uri(path);
    if let Some(origin) = origin {
        request = request.header(header::ORIGIN, origin);
    }
    if let Some(cookie) = cookie {
        request = request.header(header::COOKIE, format!("{COOKIE_NAME}={cookie}"));
    }
    request
        .body(Body::from(serde_json::to_vec(body).unwrap()))
        .unwrap()
}

/// The raw challenge in the options a `begin` gave.
pub(super) fn challenge_of(answer: &Answer) -> Vec<u8> {
    from_b64(answer.json()["publicKey"]["challenge"].as_str().unwrap())
}

pub(super) fn assertion_text(assertion: &Assertion) -> Value {
    json!({
        "credential_id": b64(&assertion.credential_id),
        "authenticator_data": b64(&assertion.authenticator_data),
        "client_data_json": b64(&assertion.client_data_json),
        "signature": b64(&assertion.signature),
    })
}

/// The body of a sign-in's finish, from this ceremony.
pub(super) fn sign_in_ceremony_body(
    key: &SoftwareAuthenticator,
    challenge: &[u8],
    ceremony: &Ceremony,
) -> Value {
    json!({
        "challenge": b64(challenge),
        "assertion": assertion_text(&key.assertion(ceremony).unwrap()),
    })
}

/// The body of an honest sign-in's finish.
pub(super) fn sign_in_body(key: &SoftwareAuthenticator, challenge: &[u8]) -> Value {
    sign_in_ceremony_body(key, challenge, &Ceremony::new(RP_ID, ORIGIN, challenge))
}

/// The body of a registration's finish, from this ceremony.
pub(super) fn attestation_body(
    code: &str,
    key: &SoftwareAuthenticator,
    ceremony: &Ceremony,
) -> Value {
    let attestation = key.attestation(ceremony);
    json!({
        "code": code,
        "attestation_object": b64(&attestation.attestation_object),
        "client_data_json": b64(&attestation.client_data_json),
    })
}
