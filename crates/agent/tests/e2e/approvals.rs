//! Approvals, from a person's tap to what the host did about it: the real controller over
//! real HTTP, the agent's real daemon, and `SoftwareAuthenticator` for the passkey. The
//! desk here is what a browser's script does, and every call goes through the controller's
//! real routes, so what reaches a host is what a page would have got there.
//!
//! The tests that have the controller lie write to its database directly, as someone who
//! holds that machine could. The host's answer to them is the point.

mod first_deploy;
mod forged;
mod manual_rollback;
mod on_docker;
mod restored;
mod retried;
mod stale;
mod upgrade;

use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use landfall_approval::{Assertion, Ceremony, SoftwareAuthenticator};
use reqwest::header::{COOKIE, ORIGIN, SET_COOKIE};
use serde_json::{Value, json};
use sqlx::sqlite::SqliteConnectOptions;
use sqlx::{Connection as _, Row as _, SqliteConnection};

use crate::harness::{DeployRow, Fleet, FleetOptions};
use crate::world::digest_of;

pub const RP_ID: &str = "landfall.example";
pub const ORIGIN_URL: &str = "https://landfall.example";
const SESSION: &str = "__Host-landfall-session";

/// Patches go by themselves, minors take an approval, and anything else is manual.
const RULE: &str = "rule = { auto = \"patch\", approve = \"minor\", approvers = [\"operator\"] }";
/// `operator` is the person, and `ci` a program that may ask, and may do no more.
const GRANTS: &str = "\n[[grant]]\nprincipal = \"operator\"\ndeployments = [\"app/prod\"]\n\
    can = [\"view\", \"request\", \"approve\", \"rollback\"]\n\n\
    [[grant]]\nprincipal = \"ci\"\ndeployments = [\"app/prod\"]\ncan = [\"request\"]\n";

/// What `key` comes to under `[approvers]`, as the registration page shows it.
pub fn approver_line(key: &SoftwareAuthenticator) -> String {
    format!(
        "operator = {{ credential_id = \"{}\", public_key = \"{}\" }}",
        URL_SAFE_NO_PAD.encode(key.credential_id()),
        URL_SAFE_NO_PAD.encode(key.key().unwrap().as_bytes()),
    )
}

/// A fleet whose rule and grants are the ones above, with `key` as its approver's.
pub fn options_for(key: &SoftwareAuthenticator) -> FleetOptions {
    FleetOptions {
        approver: approver_line(key),
        ..options_with_no_key_yet()
    }
}

/// The same, before anyone has registered: `operator` has some other key on file.
pub fn options_with_no_key_yet() -> FleetOptions {
    FleetOptions {
        rule: RULE.to_owned(),
        grants: GRANTS.to_owned(),
        ..FleetOptions::default()
    }
}

/// An assertion as a page sends it, each field in base64url.
pub fn assertion_text(assertion: &Assertion) -> Value {
    json!({
        "credential_id": URL_SAFE_NO_PAD.encode(&assertion.credential_id),
        "authenticator_data": URL_SAFE_NO_PAD.encode(&assertion.authenticator_data),
        "client_data_json": URL_SAFE_NO_PAD.encode(&assertion.client_data_json),
        "signature": URL_SAFE_NO_PAD.encode(&assertion.signature),
    })
}

/// A ceremony as a browser on the configured origin runs it, over a challenge as the
/// controller gives it.
pub fn ceremony(challenge: &str) -> Ceremony {
    Ceremony::new(
        RP_ID,
        ORIGIN_URL,
        &URL_SAFE_NO_PAD.decode(challenge).unwrap(),
    )
}

/// `key`'s tap on this request.
pub fn tap(key: &SoftwareAuthenticator, request: &Value) -> Value {
    let challenge = request["challenge"].as_str().unwrap();
    assertion_text(&key.assertion(&ceremony(challenge)).unwrap())
}

/// One HTTP answer.
#[derive(Debug)]
pub struct Answer {
    pub status: u16,
    pub body: Value,
    set_cookie: Option<String>,
}

impl Answer {
    /// The stable code of a problem.
    pub fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

/// What a person and a program do, over HTTP.
#[derive(Debug)]
pub struct Desk {
    url: String,
    client: reqwest::Client,
    pub key: SoftwareAuthenticator,
    /// `ci`'s token, from a real `token create`.
    token: String,
    /// The person's session, from a real sign-in.
    session: String,
}

/// How a call says who it is from.
#[derive(Debug, Clone, Copy)]
enum Caller<'a> {
    Nobody,
    Token(&'a str),
    Session(&'a str),
}

async fn post(
    client: &reqwest::Client,
    url: String,
    caller: Caller<'_>,
    body: Option<&Value>,
) -> Answer {
    let mut request = client.post(url).header(ORIGIN, ORIGIN_URL);
    match caller {
        Caller::Nobody => {}
        Caller::Token(token) => request = request.bearer_auth(token),
        Caller::Session(session) => {
            request = request.header(COOKIE, format!("{SESSION}={session}"));
        }
    }
    if let Some(body) = body {
        request = request.body(serde_json::to_vec(body).unwrap());
    }
    let answer = request.send().await.unwrap();
    let status = answer.status().as_u16();
    let set_cookie = answer
        .headers()
        .get(SET_COOKIE)
        .map(|value| value.to_str().unwrap().to_owned());
    let bytes = answer.bytes().await.unwrap();
    Answer {
        status,
        body: serde_json::from_slice(&bytes).unwrap_or(Value::Null),
        set_cookie,
    }
}

fn http_client() -> reqwest::Client {
    reqwest::Client::builder().no_proxy().build().unwrap()
}

/// A person with `key` signs in, as the sign-in page does.
async fn sign_in(client: &reqwest::Client, url: &str, key: &SoftwareAuthenticator) -> String {
    let begun = post(client, format!("{url}/sign-in/begin"), Caller::Nobody, None).await;
    assert_eq!(begun.status, 200, "{begun:?}");
    let challenge = begun.body["publicKey"]["challenge"].as_str().unwrap();
    let assertion = key.assertion(&ceremony(challenge)).unwrap();
    let body = json!({ "challenge": challenge, "assertion": assertion_text(&assertion) });
    let done = post(
        client,
        format!("{url}/sign-in/finish"),
        Caller::Nobody,
        Some(&body),
    )
    .await;
    assert_eq!(done.status, 200, "{done:?}");
    assert_eq!(done.body["principal"], "operator");
    let cookie = done.set_cookie.unwrap();
    let value = cookie.split(';').next().unwrap();
    value
        .strip_prefix(&format!("{SESSION}="))
        .unwrap()
        .to_owned()
}

/// A real `passkey-invite`, and `key` registering from its link, as the page does. Gives what
/// the page shows.
pub async fn register(fleet: &Fleet, key: &SoftwareAuthenticator) -> Value {
    let args = [
        "passkey-invite",
        "--principal",
        "operator",
        "--config",
        fleet.config_path.to_str().unwrap(),
        "--db",
        fleet.db.to_str().unwrap(),
    ];
    let (status, link) = fleet.server_command(args.map(str::to_owned).to_vec());
    assert_eq!(status, 0, "{link}");
    let (page, code) = link.split_once('#').unwrap();
    assert_eq!(page, format!("{ORIGIN_URL}/passkeys/register"));
    let client = http_client();
    let url = fleet.url();
    let body = json!({ "code": code });
    let begun = post(
        &client,
        format!("{url}/passkeys/register/begin"),
        Caller::Nobody,
        Some(&body),
    )
    .await;
    assert_eq!(begun.status, 200, "{begun:?}");
    assert_eq!(begun.body["publicKey"]["rp"]["id"], RP_ID);
    let challenge = begun.body["publicKey"]["challenge"].as_str().unwrap();
    let attestation = key.attestation(&ceremony(challenge));
    let body = json!({
        "code": code,
        "attestation_object": URL_SAFE_NO_PAD.encode(&attestation.attestation_object),
        "client_data_json": URL_SAFE_NO_PAD.encode(&attestation.client_data_json),
    });
    let done = post(
        &client,
        format!("{url}/passkeys/register/finish"),
        Caller::Nobody,
        Some(&body),
    )
    .await;
    assert_eq!(done.status, 200, "{done:?}");
    done.body
}

/// What the operator's pull request does: this line, for the one `operator` had.
pub fn copy_into_the_config(fleet: &Fleet, line: &str) {
    let text = fs::read_to_string(&fleet.config_path).unwrap();
    let start = text.find("operator = {").unwrap();
    let end = start + text[start..].find('\n').unwrap();
    let replaced = format!("{}{line}{}", &text[..start], &text[end..]);
    fs::write(&fleet.config_path, replaced).unwrap();
}

impl Desk {
    /// The person signed in and the program holding its token. The controller must be up.
    pub async fn open(fleet: &Fleet, key: SoftwareAuthenticator) -> Self {
        let args = [
            "token",
            "create",
            "--principal",
            "ci",
            "--config",
            fleet.config_path.to_str().unwrap(),
            "--db",
            fleet.db.to_str().unwrap(),
        ];
        let (status, line) = fleet.server_command(args.map(str::to_owned).to_vec());
        assert_eq!(status, 0, "{line}");
        let made: Value = serde_json::from_str(&line).unwrap();
        let client = http_client();
        let url = fleet.url();
        let session = sign_in(&client, &url, &key).await;
        Self {
            token: made["token"].as_str().unwrap().to_owned(),
            url,
            client,
            key,
            session,
        }
    }

    fn requests_url(&self) -> String {
        format!("{}/api/v1/deployments/app/prod/requests", self.url)
    }

    /// The program asks for `tag`.
    pub async fn try_ask(&self, tag: &str) -> Answer {
        let body = json!({ "tag": tag });
        post(
            &self.client,
            self.requests_url(),
            Caller::Token(&self.token),
            Some(&body),
        )
        .await
    }

    /// The program asks for `tag`, and may: gives the request.
    pub async fn ask(&self, tag: &str) -> Value {
        let answer = self.try_ask(tag).await;
        assert_eq!(answer.status, 201, "{answer:?}");
        answer.body
    }

    /// The person asks for `tag`, and may: gives the request.
    pub async fn ask_in_person(&self, tag: &str) -> Value {
        let body = json!({ "tag": tag });
        let answer = post(
            &self.client,
            self.requests_url(),
            Caller::Session(&self.session),
            Some(&body),
        )
        .await;
        assert_eq!(answer.status, 201, "{answer:?}");
        answer.body
    }

    /// The person sends `assertion` as their approval of `request`.
    pub async fn try_approve_with(&self, request: &Value, assertion: &Value) -> Answer {
        let id = &request["id"];
        post(
            &self.client,
            format!("{}/api/v1/approvals/{id}", self.url),
            Caller::Session(&self.session),
            Some(&json!({ "assertion": assertion })),
        )
        .await
    }

    /// The person taps and sends the approval of `request`.
    pub async fn try_approve(&self, request: &Value) -> Answer {
        self.try_approve_with(request, &tap(&self.key, request))
            .await
    }

    /// The person approves `request`, and it goes through: gives the new deploy's number.
    pub async fn approve(&self, request: &Value) -> i64 {
        let answer = self.try_approve(request).await;
        assert_eq!(answer.status, 200, "{answer:?}");
        answer.body["deploy_id"].as_i64().unwrap()
    }

    /// The program sends a good assertion of the person's, as its own approval.
    pub async fn try_approve_as_the_program(&self, request: &Value) -> Answer {
        let id = &request["id"];
        post(
            &self.client,
            format!("{}/api/v1/approvals/{id}", self.url),
            Caller::Token(&self.token),
            Some(&json!({ "assertion": tap(&self.key, request) })),
        )
        .await
    }
}

/// A connection that can write: what someone who holds the controller's machine has.
pub async fn lying_connection(fleet: &Fleet) -> SqliteConnection {
    let options = SqliteConnectOptions::new()
        .filename(&fleet.db)
        .foreign_keys(true);
    SqliteConnection::connect_with(&options).await.unwrap()
}

/// Waits until `tag` can be asked for: the watcher has decided on it, the host has said
/// what it runs and that it is idle, and nothing else is on its way.
pub async fn wait_askable(fleet: &Fleet, tag: &str) {
    fleet
        .wait_until(&format!("{tag} ready to be asked for"), async || {
            let decided = fleet
                .audit()
                .await
                .iter()
                .any(|row| row.kind == "rule_decision" && row.detail["tag"] == tag);
            let mut connection = fleet.connection().await;
            let idle = sqlx::query(
                "SELECT phase = 'idle' AND busy = 0 AND drift = 0 AS idle FROM running_states",
            )
            .fetch_optional(&mut connection)
            .await
            .unwrap()
            .is_some_and(|row| row.get::<bool, _>("idle"));
            let active: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM deploys WHERE state != 'finished'")
                    .fetch_one(&mut connection)
                    .await
                    .unwrap();
            decided && idle && active == 0
        })
        .await;
}

/// Waits for the deploy under this number to be reported, and gives it.
pub async fn wait_deploy(fleet: &Fleet, id: i64) -> DeployRow {
    fleet
        .wait_until(&format!("deploy {id} finished"), async || {
            fleet
                .deploys()
                .await
                .iter()
                .any(|deploy| deploy.id == id && deploy.state == "finished")
        })
        .await;
    let deploys = fleet.deploys().await;
    deploys.into_iter().find(|deploy| deploy.id == id).unwrap()
}

/// The lines of the host's nonce log. No file is none spent.
pub fn nonces_spent(fleet: &Fleet) -> Vec<String> {
    let log = fleet.state_dir.join("approval-nonces.log");
    fs::read_to_string(log)
        .map(|text| text.lines().map(str::to_owned).collect())
        .unwrap_or_default()
}

/// Whether this is what runs on the host, by the digest.
pub fn runs(fleet: &Fleet, tag: &str) -> bool {
    fleet
        .world
        .image()
        .is_some_and(|image| image.ends_with(digest_of(tag).as_ref()))
}

/// What a nonce in the audit log says about this request.
pub async fn nonce_approved(fleet: &Fleet, deploy_id: i64) -> String {
    let rows = fleet.audit().await;
    let row = rows
        .iter()
        .find(|row| row.kind == "request_approved" && row.detail["deploy_id"] == deploy_id)
        .unwrap();
    row.detail["nonce"].as_str().unwrap().to_owned()
}

/// The refusal of a deploy, as the audit log has it: its reason.
pub async fn refusal_reason(fleet: &Fleet, deploy_id: i64) -> String {
    let rows = fleet.audit().await;
    let row = rows
        .iter()
        .find(|row| row.kind == "deploy_refused" && row.detail["deploy_id"] == deploy_id)
        .unwrap_or_else(|| panic!("no deploy_refused for {deploy_id}: {rows:#?}"));
    assert_eq!(row.detail["outcome"], "refused");
    row.detail["reason"].as_str().unwrap().to_owned()
}

/// How many critical `controller_work_refused` lines of this deploy are in the host's journal,
/// each with `reason` in it.
pub fn journalled_critical(fleet: &Fleet, deploy_id: i64, reason: &str) -> usize {
    let number = format!("\"deploy_id\":{deploy_id},");
    fleet
        .log("agent")
        .lines()
        .filter(|line| {
            line.starts_with("<2>{\"event\":\"controller_work_refused\"")
                && line.contains(&number)
                && line.contains(reason)
        })
        .count()
}

/// A real `backup` while the controller runs. Gives where it is.
pub fn backup(fleet: &Fleet, name: &str) -> PathBuf {
    let dest = fleet.db.with_file_name(name);
    let args = [
        "backup",
        "--db",
        fleet.db.to_str().unwrap(),
        dest.to_str().unwrap(),
    ];
    let (status, line) = fleet.server_command(args.map(str::to_owned).to_vec());
    assert_eq!(status, 0, "{line}");
    dest
}

/// The steps of "Backing up and restoring" in the operations guide: with the controller and
/// the agents stopped.
pub fn restore(fleet: &Fleet, backup: &Path) {
    for extra in ["controller.db-wal", "controller.db-shm"] {
        let _ = fs::remove_file(fleet.db.with_file_name(extra));
    }
    fs::copy(backup, &fleet.db).unwrap();
}
