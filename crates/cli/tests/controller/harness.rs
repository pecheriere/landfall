//! A real controller in the test's runtime, and `landfall` run against it through
//! `cli::run_with`.
//!
//! The controller is `landfall_server::serve::run` over `landfall_server::router`, on
//! `127.0.0.1:0`, with its store in a temporary directory. What the watcher and a host would
//! have said is written through the store's own functions, as the server's own tests do: no
//! agent, no GitHub. The operator's session is a real one: an invite from the store, then
//! registration and sign-in over HTTP, through the controller's own pages' routes, with a
//! software passkey signing for the configured origin.

use std::ffi::OsString;
use std::sync::Mutex;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use clap::Parser as _;
use landfall_api::RequestView;
use landfall_approval::{Ceremony, SoftwareAuthenticator};
use landfall_cli::cli::{self, Cli};
use landfall_cli::settings::Env;
use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::protocol::{DeployReportBody, DeployedRelease, Phase, RunningState};
use landfall_server::agent_api::{ApiState, Limits};
use landfall_server::report::BoundedReport;
use landfall_server::serve::{self, ServeOptions};
use landfall_server::store::{ReleaseDecision, Seen, Store};
use reqwest::header::{CONTENT_TYPE, COOKIE, ORIGIN, SET_COOKIE};
use reqwest::{RequestBuilder, Response};
use serde_json::{Value, json};
use tempfile::TempDir;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

/// Where the approval page is, as `[approval]` names it.
pub const APPROVAL_ORIGIN: &str = "https://landfall.example.com";
const RP_ID: &str = "landfall.example.com";
const SESSION_COOKIE: &str = "__Host-landfall-session";

/// What runs on `home-1` when a test starts.
pub const RUNNING: &str = "v1.2.0";
/// The release above it, which waits for someone to ask.
pub const WAITING: &str = "v1.3.0";

/// `app/prod` on `home-1`: a minor needs an approver, and `operator` is the one, by the key
/// `key` is. `ci` may see, ask and roll back; `reader` may only see. The operator may see and
/// approve.
fn config_text(key: &SoftwareAuthenticator) -> String {
    format!(
        r#"
[approval]
rp_id = "{RP_ID}"
origin = "{APPROVAL_ORIGIN}"

[approvers]
operator = {{ credential_id = "{}", public_key = "{}" }}

[[deployment]]
id = "app/prod"
repo = {{ name = "example/app", id = 1, owner_id = 2 }}
host = "home-1"
compose = {{ dir = "/srv/app", service = "app" }}
origin = {{ workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }}
rule = {{ auto = "patch", approve = "minor", approvers = ["operator"] }}
checks = ["container-healthy"]

[[grant]]
principal = "operator"
deployments = ["app/prod"]
can = ["view", "approve"]

[[grant]]
principal = "ci"
deployments = ["app/prod"]
can = ["view", "request", "rollback"]

[[grant]]
principal = "reader"
deployments = ["app/prod"]
can = ["view"]
"#,
        URL_SAFE_NO_PAD.encode(key.credential_id()),
        URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
    )
}

/// The digest a tag's image has here: one character per release, repeated.
fn digest_of(tag: &str) -> ImageDigest {
    format!("sha256:{}", fill_of(tag).to_string().repeat(64))
        .parse()
        .unwrap()
}

/// The character a release's commit and digest are made of: its minor version.
fn fill_of(tag: &str) -> char {
    tag.split('.').nth(1).unwrap().chars().next().unwrap()
}

/// What `landfall` printed and how it ended.
#[derive(Debug)]
pub struct Ran {
    pub status: u8,
    pub out: String,
    pub err: String,
}

/// The environment `landfall` sees: the token, and nothing else, so no configuration file of
/// the machine running the tests is read.
#[derive(Debug)]
struct TokenOnly(Option<String>);

impl Env for TokenOnly {
    fn var_os(&self, name: &str) -> Option<OsString> {
        (name == "LANDFALL_TOKEN")
            .then(|| self.0.clone().map(OsString::from))
            .flatten()
    }
}

/// A controller, serving until this is dropped.
pub struct Controller {
    store: Store,
    url: String,
    config: Config,
    key: SoftwareAuthenticator,
    ci: (i64, String),
    reader: String,
    http: reqwest::Client,
    /// The accept loop, until it is found to have ended.
    serving: Mutex<Option<JoinHandle<usize>>>,
    _stop: oneshot::Sender<()>,
    _dir: TempDir,
}

impl Controller {
    /// A controller where `home-1` runs [`RUNNING`] and [`WAITING`] is verified and needs a
    /// request, with a token for `ci` and one for `reader`.
    pub async fn start() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = SoftwareAuthenticator::es256().unwrap();
        let config = landfall_approval::parse_config(config_text(&key).as_bytes()).unwrap();
        let store = Store::open(&dir.path().join("controller.db"))
            .await
            .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let app = landfall_server::router(ApiState::new(
            store.clone(),
            config.clone(),
            Limits::default(),
        ));
        let (stop, stopped) = oneshot::channel::<()>();
        let serving = tokio::spawn(serve::run(
            listener,
            app,
            ServeOptions::default(),
            async move {
                // Dropping the sender stops it as well as sending would.
                let _ = stopped.await;
            },
        ));
        let ci = store.create_token(&principal("ci")).await.unwrap();
        let (_, reader) = store.create_token(&principal("reader")).await.unwrap();
        let controller = Self {
            store,
            url,
            config,
            key,
            ci: (ci.0, ci.1.reveal()),
            reader: reader.reveal(),
            http: reqwest::Client::builder().no_proxy().build().unwrap(),
            serving: Mutex::new(Some(serving)),
            _stop: stop,
            _dir: dir,
        };
        controller.verified(WAITING).await;
        controller.runs(RUNNING).await;
        controller
    }

    /// `ci`'s token.
    pub fn ci(&self) -> &str {
        &self.ci.1
    }

    /// `reader`'s token.
    pub fn reader(&self) -> &str {
        &self.reader
    }

    /// Revokes `ci`'s token, as `landfall-server token revoke` does.
    pub async fn revoke_ci(&self) {
        assert!(self.store.revoke_token(self.ci.0).await.unwrap());
    }

    /// Records `tag` as the watcher does once it verified it and its rule wants an approver.
    async fn verified(&self, tag: &str) {
        let commit = fill_of(tag).to_string().repeat(40).parse().unwrap();
        let digest = digest_of(tag);
        let origin = json!({
            "tag": tag,
            "tag_object": "object",
            "commit": commit,
            "digest": digest,
            "signer": null,
            "san": format!(
                "\"https://github.com/example/app/.github/workflows/release.yml@refs/tags/{tag}\""
            ),
            "run_url": "\"https://github.com/example/app/actions/runs/7\"",
            "rekor_log_index": 42,
            "integrated_time": 1_799_999_000,
        });
        let seen = Seen {
            tag_object: "object",
            config_hash: self.config.hash(),
            commit: Some(&commit),
            digest: Some(&digest),
            refused: false,
            detail: json!({}),
            origin,
        };
        self.store
            .record_release(
                (&deployment(), &host(), &tag.parse::<ReleaseTag>().unwrap()),
                ReleaseDecision::NeedsApproval,
                "a higher version that needs an approver",
                Some(&seen),
            )
            .await
            .unwrap();
    }

    /// `home-1` says it runs `tag` on `app/prod`, idle, as its poll does.
    async fn runs(&self, tag: &str) {
        let running = RunningState {
            deployment: deployment(),
            deployed: Some(DeployedRelease {
                tag: tag.parse().unwrap(),
                digest: digest_of(tag),
            }),
            drift: false,
            phase: Phase::Idle,
            busy: false,
        };
        self.store
            .record_host_state(&host(), None, &[&running])
            .await
            .unwrap();
    }

    /// `home-1` claims the queued deploy `id` and reports that it rolled back, as its agent
    /// would.
    pub async fn rolled_back(&self, id: u64, tag: &str) {
        let work = self.store.next_work(&host()).await.unwrap().work.unwrap();
        assert_eq!(work.deploy_id.0, id);
        let report: DeployReportBody = serde_json::from_value(json!({
            "deploy_id": id,
            "deployment": "app/prod",
            "tag": tag,
            "digest": digest_of(tag),
            "outcome": { "kind": "rolled_back", "reason": "check container-healthy failed" },
            "steps": [
                { "name": "pull", "millis": 1200, "failure": null },
                { "name": "checks", "millis": 3000, "failure": "container-healthy failed" },
            ],
        }))
        .unwrap();
        self.store
            .finish_deploy(&host(), &BoundedReport::new(&report))
            .await
            .unwrap();
    }

    /// Runs `landfall <args>` against this controller, over loopback, with `token` in
    /// `LANDFALL_TOKEN` if any. Its runtime is its own, on a thread of its own, as a process's
    /// would be.
    pub async fn landfall(&self, token: Option<&str>, args: &[&str]) -> Ran {
        let mut command_line = vec!["landfall".to_owned()];
        command_line.extend(args.iter().map(|&arg| arg.to_owned()));
        command_line.extend([
            "--controller".to_owned(),
            self.url.clone(),
            "--allow-insecure-controller".to_owned(),
        ]);
        let env = TokenOnly(token.map(ToOwned::to_owned));
        let ran = tokio::task::spawn_blocking(move || {
            let cli = Cli::try_parse_from(command_line).unwrap();
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let status = cli::run_with(cli, &env, &mut out, &mut err);
            Ran {
                status,
                out: String::from_utf8(out).unwrap(),
                err: String::from_utf8(err).unwrap(),
            }
        })
        .await
        .unwrap();
        self.still_serving().await;
        ran
    }

    /// Panics with how the accept loop ended, if it has. It serves until this is dropped, so
    /// one that ended failed, and that is what a test should say rather than the connection
    /// errors that follow.
    async fn still_serving(&self) {
        let ended = {
            let mut serving = self.serving.lock().unwrap();
            if serving.as_ref().is_some_and(JoinHandle::is_finished) {
                serving.take()
            } else {
                None
            }
        };
        if let Some(serving) = ended {
            match serving.await {
                Ok(left) => panic!("the controller stopped serving, with {left} connections left"),
                Err(error) => panic!("the controller's accept loop failed: {error}"),
            }
        }
    }

    /// Sends `request` straight over HTTP.
    async fn send(&self, request: RequestBuilder) -> Response {
        let answer = request.send().await;
        self.still_serving().await;
        answer.unwrap()
    }

    /// The status and problem of `answer`.
    async fn problem(answer: Response) -> (u16, Value) {
        let status = answer.status().as_u16();
        (status, answer.json().await.unwrap())
    }

    /// The status and problem code of a `GET` of `path` with `token`, straight over HTTP.
    pub async fn problem_code(&self, token: &str, path: &str) -> (u16, String) {
        let request = self
            .http
            .get(format!("{}{path}", self.url))
            .bearer_auth(token);
        let (status, problem) = Self::problem(self.send(request).await).await;
        (status, problem["code"].as_str().unwrap().to_owned())
    }

    /// The status and problem of a `POST` of `body`, as it is, to `path` with `token`,
    /// straight over HTTP.
    pub async fn refusal_of_post(&self, token: &str, path: &str, body: &str) -> (u16, Value) {
        let request = self
            .http
            .post(format!("{}{path}", self.url))
            .bearer_auth(token)
            .header(CONTENT_TYPE, "application/json")
            .body(body.to_owned());
        Self::problem(self.send(request).await).await
    }

    /// A POST from the approval page, with the operator's session if any.
    async fn post(&self, path: &str, session: Option<&str>, body: &Value) -> Response {
        let mut request = self
            .http
            .post(format!("{}{path}", self.url))
            .header(ORIGIN, APPROVAL_ORIGIN)
            .json(body);
        if let Some(session) = session {
            request = request.header(COOKIE, format!("{SESSION_COOKIE}={session}"));
        }
        let answer = self.send(request).await;
        assert!(answer.status().is_success(), "{path}: {answer:?}");
        answer
    }

    /// The `publicKey.challenge` of a ceremony's `begin`, decoded, from its answer's body.
    fn challenge_of(body: &Value) -> Vec<u8> {
        decoded(body["publicKey"]["challenge"].as_str().unwrap())
    }

    /// The operator registers the key `[approvers]` holds for them from an invite, and signs
    /// in with it, as the controller's pages do. Gives the session.
    pub async fn operator_signs_in(&self) -> String {
        let code = self
            .store
            .issue_passkey_invite(&principal("operator"))
            .await
            .unwrap()
            .reveal();
        let begun: Value = self
            .post("/passkeys/register/begin", None, &json!({ "code": code }))
            .await
            .json()
            .await
            .unwrap();
        let attestation = self.key.attestation(&ceremony(&Self::challenge_of(&begun)));
        let shown: Value = self
            .post(
                "/passkeys/register/finish",
                None,
                &json!({
                    "code": code,
                    "attestation_object": URL_SAFE_NO_PAD.encode(&attestation.attestation_object),
                    "client_data_json": URL_SAFE_NO_PAD.encode(&attestation.client_data_json),
                }),
            )
            .await
            .json()
            .await
            .unwrap();
        assert_eq!(shown["principal"], "operator");

        let begun: Value = self
            .post("/sign-in/begin", None, &json!({}))
            .await
            .json()
            .await
            .unwrap();
        let challenge = Self::challenge_of(&begun);
        let body = json!({
            "challenge": URL_SAFE_NO_PAD.encode(&challenge),
            "assertion": self.assertion(&challenge),
        });
        let signed_in = self.post("/sign-in/finish", None, &body).await;
        let cookie = signed_in.headers()[SET_COOKIE].to_str().unwrap();
        let (pair, _) = cookie.split_once(';').unwrap();
        pair.strip_prefix(&format!("{SESSION_COOKIE}="))
            .unwrap()
            .to_owned()
    }

    /// The operator taps their passkey on `request` and sends it with `session`, as the
    /// approval page does. Gives the deploy it queued.
    pub async fn operator_approves(&self, session: &str, request: &RequestView) -> u64 {
        let body = json!({ "assertion": self.assertion(&decoded(&request.challenge)) });
        let path = format!("/api/v1/approvals/{}", request.id);
        let approved: Value = self
            .post(&path, Some(session), &body)
            .await
            .json()
            .await
            .unwrap();
        approved["deploy_id"].as_u64().unwrap()
    }

    /// The operator's assertion over `challenge`, as a page sends it.
    fn assertion(&self, challenge: &[u8]) -> Value {
        let assertion = self.key.assertion(&ceremony(challenge)).unwrap();
        json!({
            "credential_id": URL_SAFE_NO_PAD.encode(&assertion.credential_id),
            "authenticator_data": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
            "client_data_json": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
            "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
        })
    }
}

/// A browser on the configured origin, running a ceremony over `challenge`.
fn ceremony(challenge: &[u8]) -> Ceremony {
    Ceremony::new(RP_ID, APPROVAL_ORIGIN, challenge)
}

fn decoded(text: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(text).unwrap()
}

fn deployment() -> DeploymentId {
    "app/prod".parse().unwrap()
}

fn host() -> HostId {
    "home-1".parse().unwrap()
}

fn principal(name: &str) -> PrincipalId {
    name.parse().unwrap()
}
