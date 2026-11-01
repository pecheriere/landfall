//! The command line behind the `landfall-server` binary. Results go to stdout
//! and failures to stderr, with the exit status saying which: 0 success, 1 the
//! audit log failed verification, 2 could not run (usage included, which is
//! clap's own status).

use std::io::{self, Write};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use clap::{Args, Parser, Subcommand};
use landfall_core::config::{self, Config, ConfigError};
use landfall_core::ids::HostId;
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};

use crate::store::{Store, StoreError};

/// The command succeeded.
pub const EXIT_OK: u8 = 0;
/// `audit verify` ran and the log is not intact.
pub const EXIT_TAMPERED: u8 = 1;
/// The command could not run: usage, configuration, database or network.
pub const EXIT_COULD_NOT_RUN: u8 = 2;

const EXIT_STATUS: &str = "\
Exit status:
  0  success
  1  audit verify ran and the audit log is not intact
  2  could not run: usage, configuration, database or network";

/// Watches releases, verifies their origin and coordinates deploys.
#[derive(Debug, Parser)]
#[command(name = "landfall-server", version, about, after_help = EXIT_STATUS)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Run the controller.
    Serve(ServeArgs),
    /// Print a one-time code that lets one host enrol its key, valid for an
    /// hour. Any earlier code for that host stops working.
    EnrolCode(EnrolCodeArgs),
    /// Work with the audit log.
    Audit {
        #[command(subcommand)]
        command: AuditCommand,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Walk the hash chain without writing to the database, and print as JSON
    /// the row count, the first bad row and the head: the last row's `seq` and
    /// `hash`. The chain alone cannot show rows cut from the end or an old
    /// backup restored: keep the printed head elsewhere, and check later that
    /// the log still holds that row with that hash.
    Verify(AuditVerifyArgs),
}

#[derive(Debug, Args)]
struct ServeArgs {
    /// The fleet configuration file, read once at start-up.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The database file, created if it is missing.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
    /// The address to serve plain HTTP on: a tailnet address or one behind a
    /// TLS-terminating proxy.
    #[arg(long, value_name = "ADDR")]
    listen: SocketAddr,
}

#[derive(Debug, Args)]
struct EnrolCodeArgs {
    /// The host the code is for.
    #[arg(long, value_name = "ID")]
    host: HostId,
    /// Allow replacing the key of a host that is already enrolled. Recorded in
    /// the audit log.
    #[arg(long)]
    replace: bool,
    /// The database file `serve` uses, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
}

#[derive(Debug, Args)]
struct AuditVerifyArgs {
    /// The database file, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
}

/// Why a command could not run.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum CliError {
    /// The configuration file could not be read.
    #[error("cannot read configuration {}: {source}", .path.display())]
    ReadConfig {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The configuration file is not valid.
    #[error("configuration {}: {source}", .path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        source: ConfigError,
    },
    /// The store failed.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// `enrol-code` needs the database `serve` uses, and could not open it.
    #[error("cannot open database {}: {source}; run `serve` once first to create it, or check the path", .path.display())]
    NoDatabase {
        /// The file.
        path: PathBuf,
        /// The failure.
        source: StoreError,
    },
    /// The listen address could not be bound or served.
    #[error("cannot serve on {addr}: {source}")]
    Serve {
        /// The address.
        addr: SocketAddr,
        /// The underlying error.
        source: io::Error,
    },
    /// The signal handlers could not be installed.
    #[error("cannot watch for signals: {0}")]
    Signals(#[source] io::Error),
    /// The async runtime could not start.
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    /// The result could not be written to stdout.
    #[error("cannot write the result: {0}")]
    Output(#[source] io::Error),
}

fn load_config(path: &Path) -> Result<Config, CliError> {
    let bytes = std::fs::read(path).map_err(|source| CliError::ReadConfig {
        path: path.to_owned(),
        source,
    })?;
    config::parse(&bytes).map_err(|source| CliError::Config {
        path: path.to_owned(),
        source,
    })
}

async fn serve(args: ServeArgs) -> Result<u8, CliError> {
    load_config(&args.config)?;
    let store = Store::open(&args.db).await?;
    let serve_error = |source| CliError::Serve {
        addr: args.listen,
        source,
    };
    let listener = TcpListener::bind(args.listen).await.map_err(serve_error)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(CliError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(CliError::Signals)?;
    axum::serve(listener, crate::router(store))
        .with_graceful_shutdown(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
        })
        .await
        .map_err(serve_error)?;
    Ok(EXIT_OK)
}

async fn enrol_code(args: EnrolCodeArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = Store::open_existing(&args.db)
        .await
        .map_err(|source| CliError::NoDatabase {
            path: args.db.clone(),
            source,
        })?;
    let code = store.issue_enrol_code(&args.host, args.replace).await?;
    writeln!(out, "{}", code.reveal()).map_err(CliError::Output)?;
    Ok(EXIT_OK)
}

async fn audit_verify(args: AuditVerifyArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = Store::open_read_only(&args.db).await?;
    let report = store.verify_audit().await?;
    let line = json!({
        "rows": report.rows,
        "empty": report.rows == 0,
        "first_bad": report.first_bad,
        "head_seq": report.head_seq,
        "head_hash": report.head_hash,
    });
    writeln!(out, "{line}").map_err(CliError::Output)?;
    Ok(if report.first_bad.is_some() {
        EXIT_TAMPERED
    } else {
        EXIT_OK
    })
}

async fn execute(cli: Cli, out: &mut impl Write) -> Result<u8, CliError> {
    match cli.command {
        Command::Serve(args) => serve(args).await,
        Command::EnrolCode(args) => enrol_code(args, out).await,
        Command::Audit {
            command: AuditCommand::Verify(args),
        } => audit_verify(args, out).await,
    }
}

/// Runs a parsed command line and gives the process's exit status.
#[must_use]
pub fn run(cli: Cli) -> u8 {
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)
        .and_then(|runtime| runtime.block_on(execute(cli, &mut io::stdout())));
    match result {
        Ok(code) => code,
        Err(error) => {
            // Nothing is left to tell if stderr itself is gone.
            drop(writeln!(io::stderr(), "landfall-server: {error}"));
            EXIT_COULD_NOT_RUN
        }
    }
}

#[cfg(test)]
mod tests {
    use clap::CommandFactory as _;

    use super::*;

    #[test]
    fn command_line_is_well_formed() {
        Cli::command().debug_assert();
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
}
