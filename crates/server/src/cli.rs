//! The command line behind the `landfall-server` binary. Results go to stdout
//! and failures to stderr, with the exit status saying which: 0 success, 1 the
//! audit log failed verification, 2 could not run (usage included, which is
//! clap's own status).

use std::ffi::OsString;
use std::fs::{DirBuilder, OpenOptions};
use std::future::Future;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clap::{Args, Parser, Subcommand};
use landfall_core::config::{self, Config, ConfigError};
use landfall_core::ids::{DeploymentId, HostId};
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

use crate::agent_api::{ApiState, Limits};
use crate::audit::AuditReport;
use crate::serve::ServeOptions;
use crate::store::{Store, StoreError};
use crate::watcher::{self, LiveSource, ReleaseSource};

/// How long stopping waits for the database's last connection to close.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The command succeeded.
pub const EXIT_OK: u8 = 0;
/// `audit verify` ran and the log is not intact, or has no row at `--at`.
pub const EXIT_TAMPERED: u8 = 1;
/// The command could not run: usage, configuration, database or network.
pub const EXIT_COULD_NOT_RUN: u8 = 2;

const EXIT_STATUS: &str = "\
Exit status:
  0  success
  1  audit verify ran and the audit log is not intact, or has no row at --at
  2 could not run: usage, configuration, database or network";

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
    /// Write a whole copy of the database to a new file, private to this user, while
    /// `serve` runs or not, verify the copy's audit log, and print the same JSON as
    /// `audit verify` does for it. A copy of the database file alone is no backup: a
    /// running controller's latest changes are in the file beside it.
    Backup(BackupArgs),
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Walk the hash chain without writing to the database, and print as JSON
    /// the row count, the first bad row and the head: the last row's `seq` and
    /// `hash`. The chain alone cannot show rows cut from the end or an old
    /// backup restored: keep the printed head elsewhere, and check later with
    /// `--at` that the log still holds that row with that hash.
    Verify(AuditVerifyArgs),
    /// Print the newest rows of the audit log as JSON lines, oldest first, without
    /// writing to the database: what was decided and held, and why. This reads the
    /// log and does not check it, which is what `verify` is for.
    Show(AuditShowArgs),
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
    /// The directory of the Sigstore trust root's TUF cache, created if it is
    /// missing. Defaults to `<db>.tuf`, beside the database. Releases are verified
    /// against this: with none that verifies, the watcher verifies nothing and
    /// records why. `GITHUB_TOKEN`, when set and not empty, is sent to the GitHub
    /// API only, for its higher rate limit.
    #[arg(long, value_name = "DIR")]
    trust_cache: Option<PathBuf>,
    /// How many connections are served at once. More wait to be accepted.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = ServeOptions::default().max_connections,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    max_connections: u32,
    /// How many of those one source address may hold; more are closed at once and
    /// logged. Behind a proxy all clients are one source, so raise this to fit the
    /// fleet there, and know that any client of that proxy can then use it up.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = ServeOptions::default().max_connections_per_source,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    max_connections_per_source: u32,
}

impl ServeArgs {
    fn serve_options(&self) -> ServeOptions {
        ServeOptions {
            max_connections: self.max_connections,
            max_connections_per_source: self.max_connections_per_source,
            ..ServeOptions::default()
        }
    }
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
    /// Also print the `hash` of the row at this `seq`, to compare with a head
    /// kept from earlier. A log with no such row exits 1.
    #[arg(long, value_name = "SEQ")]
    at: Option<i64>,
}

#[derive(Debug, Args)]
struct AuditShowArgs {
    /// The database file, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
    /// Only the rows about this deployment.
    #[arg(long, value_name = "ID")]
    deployment: Option<DeploymentId>,
    /// How many rows, the newest.
    #[arg(
        long,
        value_name = "COUNT",
        default_value_t = 100,
        value_parser = clap::value_parser!(u32).range(1..),
    )]
    limit: u32,
}

#[derive(Debug, Args)]
struct BackupArgs {
    /// The database file, which must exist.
    #[arg(long, value_name = "FILE")]
    db: PathBuf,
    /// The file to write, which must not exist.
    #[arg(value_name = "DEST")]
    dest: PathBuf,
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
    /// `GITHUB_TOKEN` is set but cannot be used. The value is never shown.
    #[error("GITHUB_TOKEN is set but is not valid UTF-8 text or not a valid HTTP header value")]
    GitHubToken,
    /// The trust cache directory could not be created.
    #[error("cannot create the trust cache {}: {source}", .path.display())]
    TrustCache {
        /// The directory.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
    /// The HTTP client for releases could not be set up.
    #[error("cannot set up fetching releases: {0}")]
    Fetcher(#[source] FetchError),
    /// The signal handlers could not be installed.
    #[error("cannot watch for signals: {0}")]
    Signals(#[source] io::Error),
    /// The async runtime could not start.
    #[error("cannot start the async runtime: {0}")]
    Runtime(#[source] io::Error),
    /// The result could not be written to stdout.
    #[error("cannot write the result: {0}")]
    Output(#[source] io::Error),
    /// The backup's file could not be created or completed. An existing one is
    /// refused, and left as it is.
    #[error("backup {}: {source}", .path.display())]
    BackupFile {
        /// The file.
        path: PathBuf,
        /// The underlying error.
        source: io::Error,
    },
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

/// The GitHub token in `GITHUB_TOKEN`'s value: `None` when unset or empty.
fn github_token(value: Option<OsString>) -> Result<Option<String>, CliError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => value
            .into_string()
            .map(Some)
            .map_err(|_| CliError::GitHubToken),
    }
}

/// The fetcher for GitHub and the registry. `token` goes to GitHub only.
fn release_fetcher(token: Option<&str>) -> Result<Fetcher, CliError> {
    let fetcher =
        Fetcher::new(Endpoints::public().map_err(CliError::Fetcher)?).map_err(CliError::Fetcher)?;
    match token {
        None => Ok(fetcher),
        Some(token) => fetcher
            .with_github_token(token)
            .map_err(|_| CliError::GitHubToken),
    }
}

/// The trust cache's directory, made if it is missing, private to this user.
fn trust_cache_dir(args: &ServeArgs) -> Result<PathBuf, CliError> {
    let path = args.trust_cache.clone().unwrap_or_else(|| {
        let mut path = args.db.clone().into_os_string();
        path.push(".tuf");
        PathBuf::from(path)
    });
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&path)
        .map_err(|source| CliError::TrustCache {
            path: path.clone(),
            source,
        })?;
    Ok(path)
}

async fn serve(args: ServeArgs) -> Result<u8, CliError> {
    let config = load_config(&args.config)?;
    let token = github_token(std::env::var_os("GITHUB_TOKEN"))?;
    let fetcher = release_fetcher(token.as_deref())?;
    let source = |args: &ServeArgs, watched: Arc<Config>| {
        let cache_dir = trust_cache_dir(args)?;
        Ok(Arc::new(LiveSource::new(fetcher, watched, cache_dir)))
    };
    serve_watching(args, config, source, watcher::TICK_INTERVAL).await
}

/// Serves `config`, with the watcher looking at what `source` makes every
/// `interval`. It is made once the database is open.
async fn serve_watching<S: ReleaseSource>(
    args: ServeArgs,
    config: Config,
    source: impl FnOnce(&ServeArgs, Arc<Config>) -> Result<Arc<S>, CliError>,
    interval: Duration,
) -> Result<u8, CliError> {
    let store = Store::open(&args.db).await?;
    let watched = Arc::new(config.clone());
    let source = source(&args, Arc::clone(&watched))?;
    let serve_error = |source| CliError::Serve {
        addr: args.listen,
        source,
    };
    let listener = TcpListener::bind(args.listen).await.map_err(serve_error)?;
    let mut terminate = signal(SignalKind::terminate()).map_err(CliError::Signals)?;
    let mut interrupt = signal(SignalKind::interrupt()).map_err(CliError::Signals)?;

    let (stop_watcher, stop_watching) = watch::channel(false);
    let watching = tokio::spawn(watcher::run(
        store.clone(),
        watched,
        source,
        interval,
        stop_watching,
    ));

    let closing = store.clone();
    let state = ApiState::new(store, config, Limits::default());
    let app = crate::router(state.clone());
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        state.begin_shutdown();
        stop_watcher.send_replace(true);
    };
    crate::serve::run(listener, app, args.serve_options(), shutdown).await;
    // Told to stop as the serving began to, it lets go at once. If the watcher
    // had already stopped, that was a panic and it was logged by the runtime.
    drop(watching.await);
    // So that the main file holds everything. A request still running past the
    // drain has its connection for a while yet, and stopping does not wait for that:
    // the next start reads what is left in the write-ahead log.
    if tokio::time::timeout(CLOSE_TIMEOUT, closing.close())
        .await
        .is_err()
    {
        crate::agent_api::log("the database did not close in time; it stays whole, with its -wal");
    }
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
    store.close().await;
    writeln!(out, "{}", code.reveal()).map_err(CliError::Output)?;
    Ok(EXIT_OK)
}

/// The JSON of `audit verify`, for the log `store` holds.
fn verified_line(report: &AuditReport) -> serde_json::Value {
    json!({
        "rows": report.rows,
        "empty": report.rows == 0,
        "first_bad": report.first_bad,
        "head_seq": report.head_seq,
        "head_hash": report.head_hash,
    })
}

async fn backup(args: BackupArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let dest_error = |source| CliError::BackupFile {
        path: args.dest.clone(),
        source,
    };
    // Read-only, so that it asks nothing of a controller that is running. First, so
    // that a mistyped source leaves no file behind.
    let source = Store::open_read_only(&args.db).await?;
    let dest = args.dest.to_str().ok_or_else(|| {
        dest_error(io::Error::new(
            io::ErrorKind::InvalidInput,
            "the path is not valid UTF-8",
        ))
    })?;
    // Made here rather than by `SQLite`, to refuse what is there, whatever it holds
    // and without following a link, and to be private from the start.
    let file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&args.dest)
        .map_err(dest_error)?;
    let copied = source.vacuum_into(dest).await;
    source.close().await;
    if let Err(error) = copied {
        // What was left is unfinished, and is this command's own.
        drop(std::fs::remove_file(&args.dest));
        return Err(error.into());
    }
    file.sync_all().map_err(dest_error)?;
    let dir = args.dest.parent().filter(|dir| !dir.as_os_str().is_empty());
    std::fs::File::open(dir.unwrap_or_else(|| Path::new(".")))
        .and_then(|dir| dir.sync_all())
        .map_err(dest_error)?;
    let copy = Store::open_read_only(&args.dest).await?;
    let report = copy.verify_audit().await;
    copy.close().await;
    let report = report?;
    writeln!(out, "{}", verified_line(&report)).map_err(CliError::Output)?;
    Ok(if report.first_bad.is_some() {
        EXIT_TAMPERED
    } else {
        EXIT_OK
    })
}

async fn audit_show(args: AuditShowArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = Store::open_read_only(&args.db).await?;
    let rows = store
        .audit_rows(args.deployment.as_ref(), args.limit)
        .await?;
    for row in rows {
        // A detail that isn't JSON is a tampered row: shown as the text it is.
        let detail = serde_json::from_str::<serde_json::Value>(&row.detail)
            .unwrap_or(serde_json::Value::String(row.detail));
        let line = json!({
            "seq": row.seq,
            "ts": row.ts,
            "kind": row.kind,
            "deployment": row.deployment,
            "host": row.host,
            "detail": detail,
        });
        writeln!(out, "{line}").map_err(CliError::Output)?;
    }
    Ok(EXIT_OK)
}

async fn audit_verify(args: AuditVerifyArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = Store::open_read_only(&args.db).await?;
    let report = store.verify_audit().await?;
    let mut line = verified_line(&report);
    let mut row_missing = false;
    if let Some(seq) = args.at {
        let hash = store.audit_hash_at(seq).await?;
        row_missing = hash.is_none();
        line["at_seq"] = json!(seq);
        line["at_hash"] = json!(hash);
    }
    writeln!(out, "{line}").map_err(CliError::Output)?;
    Ok(if report.first_bad.is_some() || row_missing {
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
        Command::Audit {
            command: AuditCommand::Show(args),
        } => audit_show(args, out).await,
        Command::Backup(args) => backup(args, out).await,
    }
}

/// Runs a parsed command line and gives the process's exit status.
#[must_use]
pub fn run(cli: Cli) -> u8 {
    on_a_runtime(execute(cli, &mut io::stdout()))
}

/// [`run`], with `serve` watching `source` every `interval`, for the end-to-end
/// tests: no test repository signs real releases. Nothing on the command line
/// leads here.
#[must_use]
pub fn run_watching<S: ReleaseSource>(cli: Cli, source: Arc<S>, interval: Duration) -> u8 {
    match cli.command {
        Command::Serve(args) => on_a_runtime(async move {
            let config = load_config(&args.config)?;
            serve_watching(args, config, |_, _| Ok(source), interval).await
        }),
        command => run(Cli { command }),
    }
}

fn on_a_runtime(work: impl Future<Output = Result<u8, CliError>>) -> u8 {
    let result = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .map_err(CliError::Runtime)
        .and_then(|runtime| runtime.block_on(work));
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
        assert!(
            shown_rows(db, &["--deployment", "app/none"])
                .await
                .is_empty()
        );
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
}
