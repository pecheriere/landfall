//! The command line behind the `landfall-server` binary. Results go to stdout
//! and failures to stderr, with the exit status saying which: 0 success, 1 the
//! audit log, or a backup's, failed verification, 2 could not run (usage included,
//! which is clap's own status).

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
use landfall_core::config::{Config, ConfigError};
use landfall_core::ids::{DeploymentId, HostId, PrincipalId};
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use serde_json::json;
use tokio::net::TcpListener;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

use self::tokens::{PasskeyInviteArgs, TokenCommand};
use crate::agent_api::{ApiState, Limits};
use crate::audit::AuditReport;
use crate::auth::{flush_dropped, keep_flushing};
use crate::serve::ServeOptions;
use crate::store::{Store, StoreError};
use crate::watcher::{self, LiveSource, ReleaseSource};

mod tokens;

/// How long stopping waits for the database's last connection to close.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(5);

/// The command succeeded.
pub const EXIT_OK: u8 = 0;
/// `audit verify` or `backup` ran and the log is not intact, or has no row at `--at`.
pub const EXIT_TAMPERED: u8 = 1;
/// The command could not run: usage, configuration, database or network.
pub const EXIT_COULD_NOT_RUN: u8 = 2;

const EXIT_STATUS: &str = "\
Exit status:
  0  success
  1  audit verify or backup ran and the audit log is not intact, or has no row at --at
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
    /// Make and revoke API tokens.
    Token {
        #[command(subcommand)]
        command: TokenCommand,
    },
    /// Print a one-time link, valid for an hour, for someone to register a passkey on.
    /// Any earlier link for them stops working.
    PasskeyInvite(PasskeyInviteArgs),
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
    /// A command that needs the database `serve` uses could not open it.
    #[error("cannot open database {}: {source}; run `serve` once first to create it, or check the path", .path.display())]
    NoDatabase {
        /// The file.
        path: PathBuf,
        /// The failure.
        source: StoreError,
    },
    /// The database's schema is older than this program's: `serve` brings it up to date.
    #[error("database {} is older than this program; run `serve` from this version once to upgrade it, then try again", .path.display())]
    OutOfDate {
        /// The file.
        path: PathBuf,
    },
    /// `token create` was given a principal the configuration doesn't name: a token for
    /// them would not work.
    #[error("the configuration has no principal {0}: no grant and not in [approvers]")]
    UnknownPrincipal(PrincipalId),
    /// `passkey-invite` needs the origin in `[approval]`, which a configuration with no
    /// deployments can leave out.
    #[error("the configuration has no [approval], so there is no page to invite anyone to")]
    NoApprovalSettings,
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
    landfall_approval::parse_config(&bytes).map_err(|source| CliError::Config {
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
    let drain = ServeOptions::default().drain_timeout;
    serve_watching(args, config, source, watcher::TICK_INTERVAL, drain).await
}

/// Serves `config`, with the watcher looking at what `source` makes every
/// `interval`. It is made once the database is open.
async fn serve_watching<S: ReleaseSource>(
    args: ServeArgs,
    config: Config,
    source: impl FnOnce(&ServeArgs, Arc<Config>) -> Result<Arc<S>, CliError>,
    interval: Duration,
    drain_timeout: Duration,
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
    // Says the real port, if it was asked for port 0, and that signals are heard from here on.
    let listening = listener.local_addr().map_err(serve_error)?;
    crate::agent_api::log(&format!("listening on {listening}"));

    let (stop_watcher, stop_watching) = watch::channel(false);
    let stop_flushing = stop_watching.clone();
    let watching = tokio::spawn(watcher::run(
        store.clone(),
        watched,
        source,
        interval,
        stop_watching,
    ));

    let closing = store.clone();
    let state = ApiState::new(store, config, Limits::default());
    let draining = state.clone();
    let app = crate::router(state.clone());
    let flushing = tokio::spawn(keep_flushing(state.clone(), interval, stop_flushing));
    let shutdown = async move {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = interrupt.recv() => {}
        }
        state.begin_shutdown();
        stop_watcher.send_replace(true);
    };
    let options = ServeOptions {
        drain_timeout,
        ..args.serve_options()
    };
    crate::serve::run(listener, app, options, shutdown).await;
    // Told to stop as the serving began to, it lets go at once. If the watcher
    // had already stopped, that was a panic and it was logged by the runtime.
    drop(watching.await);
    drop(flushing.await);
    // It stopped as the draining began, and a request finishing since may have counted something.
    // No request is running now, so nothing can count anything after this.
    flush_dropped(&draining).await;
    crate::web::tend(&draining).await;
    // So that the main file holds everything. If it can't in time, the next start reads what is
    // left in the write-ahead log.
    if tokio::time::timeout(CLOSE_TIMEOUT, closing.close())
        .await
        .is_err()
    {
        crate::agent_api::log("the database did not close in time; it stays whole, with its -wal");
    }
    Ok(EXIT_OK)
}

/// The database `serve` uses, which must exist.
async fn opened(db: &Path) -> Result<Store, CliError> {
    Store::open_existing(db)
        .await
        .map_err(|source| CliError::NoDatabase {
            path: db.to_owned(),
            source,
        })
}

async fn enrol_code(args: EnrolCodeArgs, out: &mut impl Write) -> Result<u8, CliError> {
    let store = opened(&args.db).await?;
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
        writeln!(out, "{}", safe_to_print(&line.to_string())).map_err(CliError::Output)?;
    }
    Ok(EXIT_OK)
}

/// A line of JSON with what JSON leaves as it is, and a terminal doesn't, escaped: the
/// delete and C1 controls, and what reorders text or breaks a line unseen. They can
/// only be inside strings, where the escape reads back as the same character.
fn safe_to_print(line: &str) -> String {
    let mut safe = String::with_capacity(line.len());
    for character in line.chars() {
        if matches!(
            character,
            '\u{7f}'..='\u{9f}'
                | '\u{61c}'
                | '\u{200e}'
                | '\u{200f}'
                | '\u{2028}'..='\u{202e}'
                | '\u{2066}'..='\u{2069}'
                | '\u{feff}'
        ) {
            // Writing to a String cannot fail.
            let _ = std::fmt::Write::write_fmt(
                &mut safe,
                format_args!("\\u{:04x}", u32::from(character)),
            );
        } else {
            safe.push(character);
        }
    }
    safe
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
        Command::Token { command } => tokens::token(command, out).await,
        Command::PasskeyInvite(args) => tokens::passkey_invite(args, out).await,
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
    let drain = ServeOptions::default().drain_timeout;
    run_watching_draining(cli, source, interval, drain)
}

/// [`run_watching`], giving requests in flight `drain_timeout` when it stops, for a test holding
/// one of them open, which on a loaded machine can take longer than a real drain allows.
#[must_use]
pub fn run_watching_draining<S: ReleaseSource>(
    cli: Cli,
    source: Arc<S>,
    interval: Duration,
    drain_timeout: Duration,
) -> u8 {
    match cli.command {
        Command::Serve(args) => on_a_runtime(async move {
            let config = load_config(&args.config)?;
            serve_watching(args, config, |_, _| Ok(source), interval, drain_timeout).await
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
mod tests;
