//! `token create`, `token revoke` and `passkey-invite`, through the command line.

use std::path::{Path, PathBuf};

use clap::Parser as _;
use serde_json::Value;
use sqlx::Row as _;

use super::super::{Cli, CliError, EXIT_OK, EXIT_TAMPERED, execute};
use crate::auth::ApiToken;
use crate::store::Store;

const CONFIG: &str = r#"
[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1, owner_id = 2 }
host = "host-a"
compose = { dir = "/srv/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signed_tags = false }
rule = { approvers = ["operator"] }
checks = ["container-healthy"]

[[grant]]
principal = "ci"
deployments = ["app/prod"]
can = ["request"]
"#;

struct Files {
    _dir: tempfile::TempDir,
    db: PathBuf,
    config: PathBuf,
}

impl Files {
    async fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let db = dir.path().join("controller.db");
        let config = dir.path().join("fleet.toml");
        std::fs::write(&config, CONFIG).unwrap();
        Store::open(&db).await.unwrap().close().await;
        Self {
            _dir: dir,
            db,
            config,
        }
    }

    fn path(path: &Path) -> &str {
        path.to_str().unwrap()
    }

    async fn run(&self, args: &[&str]) -> (Result<u8, CliError>, String) {
        let db = Self::path(&self.db);
        let config = Self::path(&self.config);
        let mut line = vec!["landfall-server"];
        for arg in args {
            line.push(match *arg {
                "DB" => db,
                "CONFIG" => config,
                other => other,
            });
        }
        let mut out = Vec::new();
        let result = execute(Cli::try_parse_from(line).unwrap(), &mut out).await;
        (result, String::from_utf8(out).unwrap())
    }

    async fn create(&self, principal: &str) -> (Result<u8, CliError>, String) {
        self.run(&[
            "token",
            "create",
            "--principal",
            principal,
            "--config",
            "CONFIG",
            "--db",
            "DB",
        ])
        .await
    }
}

#[tokio::test]
async fn a_token_is_printed_once_and_revoked_by_its_id() {
    let files = Files::new().await;
    let (result, out) = files.create("ci").await;
    assert_eq!(result.unwrap(), EXIT_OK);
    let printed: Value = serde_json::from_str(out.trim()).unwrap();
    let token = printed["token"].as_str().unwrap();
    let id = printed["id"].as_i64().unwrap();
    assert_eq!(printed["principal"], "ci");
    let parsed = ApiToken::parse(token).unwrap();

    let store = Store::open_existing(&files.db).await.unwrap();
    let row = sqlx::query("SELECT token_hash FROM api_tokens")
        .fetch_one(store.pool())
        .await
        .unwrap();
    let stored: Vec<u8> = row.get("token_hash");
    assert_eq!(stored, parsed.hash());
    assert!(store.token_holder(&parsed).await.unwrap().is_some());
    let rows = store.audit_rows(None, 10).await.unwrap();
    assert!(rows.iter().all(|row| !row.detail.contains(token)));

    let id = id.to_string();
    let revoke = ["token", "revoke", "--id", id.as_str(), "--db", "DB"];
    let (result, out) = files.run(&revoke).await;
    assert_eq!(result.unwrap(), EXIT_OK);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap()["already_revoked"],
        false
    );
    assert!(store.token_holder(&parsed).await.unwrap().is_none());
    let (result, out) = files.run(&revoke).await;
    assert_eq!(result.unwrap(), EXIT_OK);
    assert_eq!(
        serde_json::from_str::<Value>(out.trim()).unwrap()["already_revoked"],
        true
    );

    let (result, _) = files
        .run(&["token", "revoke", "--id", "999", "--db", "DB"])
        .await;
    assert!(result.unwrap_err().to_string().contains("no API token"));

    // The log with these in it still verifies, and a backup of it.
    let (result, _) = files.run(&["audit", "verify", "--db", "DB"]).await;
    assert_eq!(result.unwrap(), EXIT_OK);
    let (result, _) = files
        .run(&["audit", "verify", "--at", "1", "--db", "DB"])
        .await;
    assert_eq!(result.unwrap(), EXIT_OK);
    let (result, _) = files
        .run(&["audit", "verify", "--at", "99", "--db", "DB"])
        .await;
    assert_eq!(result.unwrap(), EXIT_TAMPERED);
    let backup = files.db.with_extension("bak");
    let (result, _) = files
        .run(&["backup", "--db", "DB", backup.to_str().unwrap()])
        .await;
    assert_eq!(result.unwrap(), EXIT_OK);
    let copy = Store::open_read_only(&backup).await.unwrap();
    assert!(copy.token_holder(&parsed).await.unwrap().is_none());
}

#[tokio::test]
async fn a_token_is_only_made_for_a_principal_the_configuration_names() {
    let files = Files::new().await;
    let (result, out) = files.create("nobody").await;
    let error = result.unwrap_err();
    assert!(matches!(error, CliError::UnknownPrincipal(_)), "{error}");
    assert!(error.to_string().contains("nobody"), "{error}");
    assert_eq!(out, "");
    // An approver with no grant is named, and gets a token that can do nothing.
    let (result, _) = files.create("operator").await;
    assert_eq!(result.unwrap(), EXIT_OK);
}

#[tokio::test]
async fn a_passkey_invite_prints_a_link_and_keeps_a_hash() {
    let files = Files::new().await;
    let invite = [
        "passkey-invite",
        "--principal",
        "new-person",
        "--config",
        "CONFIG",
        "--db",
        "DB",
    ];
    let (result, out) = files.run(&invite).await;
    assert_eq!(result.unwrap(), EXIT_OK);
    let code = out
        .trim()
        .strip_prefix("https://landfall.example/passkeys/register#")
        .unwrap_or_else(|| panic!("{out}"))
        .to_owned();
    assert_eq!(code.len(), 64);

    let store = Store::open_existing(&files.db).await.unwrap();
    let row = sqlx::query("SELECT code_hash, principal, expires_at FROM passkey_invites")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(row.get::<String, _>("principal"), "new-person");
    let stored: Vec<u8> = row.get("code_hash");
    assert_ne!(hex::encode(&stored), code);
    let now = store.now().unwrap();
    let expires: i64 = row.get("expires_at");
    assert!((now + 3590..=now + 3600).contains(&expires), "{expires}");
    let rows = store.audit_rows(None, 10).await.unwrap();
    assert!(rows.iter().all(|row| !row.detail.contains(&code)));
    assert_eq!(rows.last().unwrap().kind, "passkey_invite_issued");

    // Another for the same person replaces it.
    let (result, again) = files.run(&invite).await;
    assert_eq!(result.unwrap(), EXIT_OK);
    assert_ne!(again, out);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM passkey_invites")
        .fetch_one(store.pool())
        .await
        .unwrap();
    assert_eq!(count, 1);
}

#[tokio::test]
async fn a_passkey_invite_refuses_a_configuration_without_approval_settings() {
    let files = Files::new().await;
    std::fs::write(&files.config, "").unwrap();
    let (result, out) = files
        .run(&[
            "passkey-invite",
            "--principal",
            "someone",
            "--config",
            "CONFIG",
            "--db",
            "DB",
        ])
        .await;
    assert!(matches!(result, Err(CliError::NoApprovalSettings)));
    assert_eq!(out, "");
}

#[tokio::test]
async fn these_need_a_database_that_is_there() {
    let files = Files::new().await;
    let missing = files.db.with_extension("missing");
    let line = [
        "landfall-server",
        "token",
        "revoke",
        "--id",
        "1",
        "--db",
        missing.to_str().unwrap(),
    ];
    let mut out = Vec::new();
    let result = execute(Cli::try_parse_from(line).unwrap(), &mut out).await;
    assert!(matches!(result, Err(CliError::NoDatabase { .. })));
}
