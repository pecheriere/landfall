use clap::{CommandFactory as _, Parser as _};

use landfall_core::config::ConfigError;

use super::{
    Cli, CliError, Command, DeploymentId, EXIT_OK, EXIT_TAMPERED, HostId, OsString, Path, PathBuf,
    ServeArgs, ServeOptions, Store, execute, github_token, load_config, release_fetcher,
    trust_cache_dir,
};

#[test]
fn a_key_the_verifier_would_refuse_is_refused_at_load() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("fleet.toml");
    std::fs::write(
        &path,
        "[approvers]\noperator = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }\n",
    )
    .unwrap();
    let err = load_config(&path).unwrap_err();
    assert!(
        matches!(
            &err,
            CliError::Config { source: ConfigError::InvalidApprover { approver, .. }, .. }
                if approver.to_string() == "operator"
        ),
        "{err}"
    );
}

#[test]
fn command_line_is_well_formed() {
    Cli::command().debug_assert();
}

fn parsed_serve_options(extra: &[&str]) -> Result<ServeOptions, clap::Error> {
    let base = [
        "landfall-server",
        "serve",
        "--config",
        "c.toml",
        "--db",
        "x.db",
        "--listen",
        "127.0.0.1:0",
    ];
    let cli = Cli::try_parse_from(base.iter().chain(extra))?;
    let Command::Serve(args) = cli.command else {
        panic!("not serve");
    };
    Ok(args.serve_options())
}

#[test]
fn connection_caps_can_be_set_and_default_to_the_servers_own() {
    assert_eq!(parsed_serve_options(&[]).unwrap(), ServeOptions::default());
    let options = parsed_serve_options(&[
        "--max-connections",
        "2048",
        "--max-connections-per-source",
        "512",
    ])
    .unwrap();
    assert_eq!(options.max_connections, 2048);
    assert_eq!(options.max_connections_per_source, 512);
}

#[test]
fn a_connection_cap_of_zero_is_refused() {
    for flag in ["--max-connections", "--max-connections-per-source"] {
        assert!(parsed_serve_options(&[flag, "0"]).is_err(), "{flag}");
    }
}

#[test]
fn help_documents_the_exit_status() {
    let help = Cli::command().render_long_help().to_string();
    assert!(help.contains("Exit status:"), "{help}");
}

#[test]
fn a_hostile_host_id_is_a_usage_error() {
    let parsed = Cli::try_parse_from([
        "landfall-server",
        "enrol-code",
        "--host",
        "HOST\n",
        "--db",
        "x.db",
    ]);
    assert!(parsed.is_err());
}

fn parse(args: &[&str]) -> Cli {
    Cli::try_parse_from(args).unwrap()
}

#[tokio::test]
async fn enrol_code_prints_only_the_code_and_audit_verify_sees_it() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("controller.db");
    Store::open(&db).await.unwrap().close().await;
    let db = db.to_str().unwrap();

    let mut out = Vec::new();
    let enrol = parse(&[
        "landfall-server",
        "enrol-code",
        "--host",
        "host-a",
        "--db",
        db,
    ]);
    assert_eq!(execute(enrol, &mut out).await.unwrap(), EXIT_OK);
    let printed = String::from_utf8(out).unwrap();
    let code = printed.strip_suffix('\n').unwrap();
    assert!(
        hex::decode(code).is_ok_and(|bytes| bytes.len() == 32),
        "{printed}"
    );

    let mut out = Vec::new();
    let verify = parse(&["landfall-server", "audit", "verify", "--db", db]);
    assert_eq!(execute(verify, &mut out).await.unwrap(), EXIT_OK);
    let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(printed["rows"], 1);
    assert_eq!(printed["empty"], false);
    assert_eq!(printed["first_bad"], serde_json::Value::Null);
    assert_eq!(printed["head_seq"], 1);
    assert_eq!(printed["head_hash"].as_str().unwrap().len(), 64);
}

/// What the printed head is for: saved now, compared after the log has
/// grown, and after it has been rolled back to before the saved row.
#[tokio::test]
async fn audit_verify_at_compares_a_saved_head_with_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let db = path.to_str().unwrap();
    let older = dir.path().join("older.db");
    let store = Store::open(&path).await.unwrap();
    let issue = async |host: &str| {
        let host: HostId = host.parse().unwrap();
        store.issue_enrol_code(&host, false).await.unwrap();
    };
    let verify = async |db: &str, at: &[&str]| {
        let mut args = vec!["landfall-server", "audit", "verify", "--db", db];
        args.extend_from_slice(at);
        let mut out = Vec::new();
        let code = execute(parse(&args), &mut out).await.unwrap();
        (
            code,
            serde_json::from_slice::<serde_json::Value>(&out).unwrap(),
        )
    };
    issue("host-a").await;
    store.checkpoint_for_test().await;
    std::fs::copy(&path, &older).unwrap();
    issue("host-b").await;

    let (code, saved) = verify(db, &[]).await;
    assert_eq!(code, EXIT_OK);
    assert_eq!(saved["head_seq"], 2);
    assert!(saved.get("at_seq").is_none(), "{saved}");
    issue("host-c").await;

    // The log has grown: the head moved, and the saved row is still there.
    let (code, later) = verify(db, &["--at", "2"]).await;
    assert_eq!(code, EXIT_OK);
    assert_eq!(later["head_seq"], 3);
    assert_ne!(later["head_hash"], saved["head_hash"]);
    assert_eq!(later["at_seq"], 2);
    assert_eq!(later["at_hash"], saved["head_hash"]);

    // An old backup verifies clean, but no longer holds the saved row.
    let (code, restored) = verify(older.to_str().unwrap(), &["--at", "2"]).await;
    assert_eq!(code, EXIT_TAMPERED);
    assert_eq!(restored["first_bad"], serde_json::Value::Null);
    assert_eq!(restored["at_seq"], 2);
    assert_eq!(restored["at_hash"], serde_json::Value::Null);
}

#[tokio::test]
async fn audit_verify_says_when_the_log_is_empty() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    Store::open(&path).await.unwrap().close().await;

    let mut out = Vec::new();
    let verify = parse(&[
        "landfall-server",
        "audit",
        "verify",
        "--db",
        path.to_str().unwrap(),
    ]);
    assert_eq!(execute(verify, &mut out).await.unwrap(), EXIT_OK);
    assert_eq!(
        String::from_utf8(out).unwrap(),
        "{\"empty\":true,\"first_bad\":null,\"head_hash\":null,\"head_seq\":null,\"rows\":0}\n"
    );
}

#[tokio::test]
async fn enrol_code_refuses_a_missing_database_and_says_to_start_serve() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typo.db");
    let mut out = Vec::new();
    let enrol = parse(&[
        "landfall-server",
        "enrol-code",
        "--host",
        "host-a",
        "--db",
        path.to_str().unwrap(),
    ]);
    let error = execute(enrol, &mut out).await.unwrap_err();
    assert!(error.to_string().contains("run `serve` once"), "{error}");
    assert_eq!(out, b"");
    assert!(!path.exists());
}

#[tokio::test]
async fn audit_verify_exits_nonzero_on_a_tampered_log() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let db = path.to_str().unwrap();
    let store = Store::open(&path).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store.issue_enrol_code(&host, false).await.unwrap();
    store.tamper_for_test().await;

    let mut out = Vec::new();
    let verify = parse(&["landfall-server", "audit", "verify", "--db", db]);
    assert_eq!(execute(verify, &mut out).await.unwrap(), EXIT_TAMPERED);
    let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(printed["rows"], 1);
    assert_eq!(printed["first_bad"], 1);
}

/// Runs `audit show` with `extra` and gives what it printed, row by row.
async fn shown_rows(db: &str, extra: &[&str]) -> Vec<serde_json::Value> {
    let mut args = vec!["landfall-server", "audit", "show", "--db", db];
    args.extend_from_slice(extra);
    let mut out = Vec::new();
    assert_eq!(execute(parse(&args), &mut out).await.unwrap(), EXIT_OK);
    String::from_utf8(out)
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

#[tokio::test]
async fn audit_show_prints_the_newest_rows_as_json_lines_and_writes_nothing() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let db = path.to_str().unwrap();
    let store = Store::open(&path).await.unwrap();
    for host in ["host-a", "host-b", "host-c"] {
        let host: HostId = host.parse().unwrap();
        store.issue_enrol_code(&host, false).await.unwrap();
    }
    let id: DeploymentId = "app/prod".parse().unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store
        .set_hold((&id, &host), None, "held\nfor a reason", false)
        .await
        .unwrap();
    store.close().await;
    let before = std::fs::read(&path).unwrap();

    let all = shown_rows(db, &[]).await;
    assert_eq!(all.len(), 4);
    assert_eq!(all[0]["seq"], 1);
    assert_eq!(all[0]["kind"], "enrol_code_issued");
    assert_eq!(all[0]["host"], "host-a");
    assert_eq!(all[3]["kind"], "release_held");
    assert_eq!(all[3]["deployment"], "app/prod");
    assert!(
        all[3]["detail"]["reason"]
            .as_str()
            .unwrap()
            .contains("for a reason")
    );

    let newest = shown_rows(db, &["--limit", "2"]).await;
    assert_eq!(
        newest.iter().map(|row| &row["seq"]).collect::<Vec<_>>(),
        [3, 4],
        "the newest, oldest first"
    );
    let held = shown_rows(db, &["--deployment", "app/prod"]).await;
    assert_eq!(held.len(), 1);
    assert_eq!(held[0]["seq"], 4);
    let none: [serde_json::Value; 0] = [];
    assert_eq!(shown_rows(db, &["--deployment", "app/none"]).await, none);
    assert_eq!(std::fs::read(&path).unwrap(), before, "read only");

    assert!(
        Cli::try_parse_from([
            "landfall-server",
            "audit",
            "show",
            "--db",
            db,
            "--limit",
            "0"
        ])
        .is_err()
    );
}

#[tokio::test]
async fn audit_show_of_a_tampered_row_shows_what_is_there() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store.issue_enrol_code(&host, false).await.unwrap();
    sqlx::query("DROP TRIGGER audit_events_no_update")
        .execute(store.pool())
        .await
        .unwrap();
    sqlx::query("UPDATE audit_events SET detail = CAST(x'6e6f7420ff6a736f6e' AS TEXT)")
        .execute(store.pool())
        .await
        .unwrap();
    store.close().await;
    let rows = shown_rows(path.to_str().unwrap(), &[]).await;
    assert_eq!(rows[0]["detail"], "not \u{fffd}json");
}

#[tokio::test]
async fn audit_show_escapes_what_a_terminal_would_act_on_and_it_reads_back_the_same() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store.issue_enrol_code(&host, false).await.unwrap();
    sqlx::query("DROP TRIGGER audit_events_no_update")
        .execute(store.pool())
        .await
        .unwrap();
    let hostile =
        "del\u{7f} c1\u{80}\u{85}\u{9f} rlo\u{202e} lri\u{2066} alm\u{61c} ls\u{2028} ok é";
    sqlx::query("UPDATE audit_events SET detail = ?")
        .bind(serde_json::json!({ "reason": hostile }).to_string())
        .execute(store.pool())
        .await
        .unwrap();
    store.close().await;

    let mut out = Vec::new();
    let show = parse(&[
        "landfall-server",
        "audit",
        "show",
        "--db",
        path.to_str().unwrap(),
    ]);
    assert_eq!(execute(show, &mut out).await.unwrap(), EXIT_OK);
    let printed = String::from_utf8(out).unwrap();

    for raw in [
        '\u{7f}', '\u{80}', '\u{85}', '\u{9f}', '\u{202e}', '\u{2066}', '\u{61c}', '\u{2028}',
    ] {
        assert!(!printed.contains(raw), "{raw:?} in {printed}");
    }
    assert!(printed.contains("\\u202e"), "{printed}");
    assert!(printed.contains('é'), "ordinary text stays as it is");
    let read: serde_json::Value = serde_json::from_str(&printed).unwrap();
    assert_eq!(read["detail"]["reason"], hostile);
}

/// The useful part of a reason is often at the end: well past the short form, an audit
/// row and what `audit show` prints still have it.
#[tokio::test]
async fn audit_show_prints_holds_and_decisions_up_to_their_longer_bound() {
    use crate::store::ReleaseDecision;

    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    let (id, host): (DeploymentId, HostId) =
        ("app/prod".parse().unwrap(), "host-a".parse().unwrap());
    let tag = "v1.2.3".parse().unwrap();
    let kept = format!("{}the end", "x".repeat(249));
    let reason = format!("{kept}; and past the bound");
    store
        .set_hold((&id, &host), Some(&tag), &reason, false)
        .await
        .unwrap();
    store
        .record_release((&id, &host, &tag), ReleaseDecision::Manual, &reason, None)
        .await
        .unwrap();
    store.close().await;

    let rows = shown_rows(path.to_str().unwrap(), &[]).await;
    assert_eq!(rows.len(), 2);
    for row in rows {
        let shown = row["detail"]["reason"].as_str().unwrap().to_owned();
        assert_eq!(shown, format!("{kept:?}..."), "{}", row["kind"]);
    }
}

#[tokio::test]
async fn a_backup_refuses_what_is_there_and_leaves_nothing_of_a_failure() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store.issue_enrol_code(&host, false).await.unwrap();

    let dest = dir.path().join("backup.db");
    let args = |dest: &Path| {
        parse(&[
            "landfall-server",
            "backup",
            "--db",
            path.to_str().unwrap(),
            dest.to_str().unwrap(),
        ])
    };
    let mut out = Vec::new();
    assert_eq!(execute(args(&dest), &mut out).await.unwrap(), EXIT_OK);
    let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(printed["rows"], 1);
    assert_eq!(printed["first_bad"], serde_json::Value::Null);

    // Whatever is there, a backup, a file, an empty file or a link to one.
    let before = std::fs::read(&dest).unwrap();
    let error = execute(args(&dest), &mut Vec::new()).await.unwrap_err();
    assert!(matches!(error, CliError::BackupFile { .. }), "{error}");
    assert_eq!(std::fs::read(&dest).unwrap(), before);
    let empty = dir.path().join("empty");
    std::fs::write(&empty, "").unwrap();
    assert!(execute(args(&empty), &mut Vec::new()).await.is_err());
    assert_eq!(std::fs::read(&empty).unwrap(), b"");
    let link = dir.path().join("link");
    let aimed = dir.path().join("aimed");
    std::os::unix::fs::symlink(&aimed, &link).unwrap();
    assert!(execute(args(&link), &mut Vec::new()).await.is_err());
    assert!(!aimed.exists());

    // No source, and nothing is made.
    let nothing = dir.path().join("nothing.db");
    let missing = parse(&[
        "landfall-server",
        "backup",
        "--db",
        dir.path().join("typo.db").to_str().unwrap(),
        nothing.to_str().unwrap(),
    ]);
    assert!(execute(missing, &mut Vec::new()).await.is_err());
    assert!(!nothing.exists());
    assert!(!dir.path().join("typo.db").exists());
}

#[tokio::test]
async fn a_backup_of_a_tampered_log_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let store = Store::open(&path).await.unwrap();
    let host: HostId = "host-a".parse().unwrap();
    store.issue_enrol_code(&host, false).await.unwrap();
    store.tamper_for_test().await;
    let dest = dir.path().join("backup.db");
    let args = parse(&[
        "landfall-server",
        "backup",
        "--db",
        path.to_str().unwrap(),
        dest.to_str().unwrap(),
    ]);
    let mut out = Vec::new();
    assert_eq!(execute(args, &mut out).await.unwrap(), EXIT_TAMPERED);
    let printed: serde_json::Value = serde_json::from_slice(&out).unwrap();
    assert_eq!(printed["first_bad"], 1);
}

#[tokio::test]
async fn audit_verify_of_a_missing_database_could_not_run() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("typo.db");
    let verify = parse(&[
        "landfall-server",
        "audit",
        "verify",
        "--db",
        path.to_str().unwrap(),
    ]);
    assert!(execute(verify, &mut Vec::new()).await.is_err());
    assert!(!path.exists());
}

#[test]
fn the_github_token_is_optional_but_must_be_usable() {
    assert_eq!(github_token(None).unwrap(), None);
    assert_eq!(github_token(Some(OsString::new())).unwrap(), None);
    assert_eq!(
        github_token(Some("t".into())).unwrap().as_deref(),
        Some("t")
    );
    let not_utf8 = std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]);
    assert!(matches!(
        github_token(Some(not_utf8)),
        Err(CliError::GitHubToken)
    ));
    assert!(matches!(
        release_fetcher(Some("bad\ntoken")),
        Err(CliError::GitHubToken)
    ));
}

#[test]
fn the_trust_cache_defaults_to_beside_the_database_and_is_private() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("controller.db");
    let args = |cache: Option<PathBuf>| ServeArgs {
        config: "c".into(),
        db: db.clone(),
        listen: "127.0.0.1:0".parse().unwrap(),
        trust_cache: cache,
        max_connections: 1,
        max_connections_per_source: 1,
    };

    let default = trust_cache_dir(&args(None)).unwrap();
    assert_eq!(default, dir.path().join("controller.db.tuf"));
    let mode = std::fs::metadata(&default).unwrap();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode.permissions()) & 0o077,
        0
    );

    let named = dir.path().join("a/b");
    assert_eq!(trust_cache_dir(&args(Some(named.clone()))).unwrap(), named);
    assert!(named.is_dir());
}

#[tokio::test]
async fn serve_refuses_a_missing_configuration_before_touching_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let config = dir.path().join("missing.toml");
    let serve = parse(&[
        "landfall-server",
        "serve",
        "--config",
        config.to_str().unwrap(),
        "--db",
        path.to_str().unwrap(),
        "--listen",
        "127.0.0.1:0",
    ]);
    let error = execute(serve, &mut Vec::new()).await.unwrap_err();
    assert!(matches!(error, CliError::ReadConfig { .. }), "{error}");
    assert!(!path.exists());
}
