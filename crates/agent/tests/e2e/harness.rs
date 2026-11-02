//! The fleet of a test: its files, its processes, and what can be read of them.

use std::fs::{self, DirBuilder, File};
use std::io::Write as _;
use std::net::{Ipv4Addr, TcpListener};
use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::{Duration, Instant};

use clap::Parser as _;
use landfall_agent::checks::CheckOptions;
use landfall_agent::client::ControllerUrl;
use landfall_agent::compose::OVERRIDE_FILE;
use landfall_agent::daemon;
use landfall_agent::deploy::{self, DeployPlan, EngineOptions, Outcome};
use landfall_agent::docker::{Docker, DockerCli};
use landfall_agent::state::{DeploymentState, StateDir};
use landfall_core::config::{Config, parse};
use rustix::process::{Pid, Signal, kill_process};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::sqlite::{SqliteConnectOptions, SqliteRow};
use sqlx::{Connection as _, Row as _, SqliteConnection};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpStream;

use crate::world::{FileSource, FileVerifier, Release, SimDocker, World, origin};

/// The variable that tells this binary which process it is to be.
pub const CHILD_SPEC: &str = "LANDFALL_E2E_CHILD";
pub const AGENT_BINARY: &str = env!("CARGO_BIN_EXE_landfall-agent");
pub const HOST: &str = "home-1";
pub const DEPLOYMENT: &str = "app/prod";
const REPO: &str = "example/app";
const CHECK_COMMAND: &str = "checks = [{ command = [\"true\"] }]";
/// A stuck wait in a test ends here, with what the processes said.
const PATIENCE: Duration = Duration::from_mins(1);
/// How often a watcher in a test looks for releases.
const WATCH_EVERY: Duration = Duration::from_millis(100);

/// What the engine's timing comes to in a test: it takes its time on a host.
pub fn quick_engine() -> EngineOptions {
    EngineOptions {
        checks: CheckOptions {
            interval: Duration::from_millis(50),
            deadline: Duration::from_secs(3),
            http_timeout: Duration::from_secs(1),
            settle: Duration::from_millis(100),
        },
        ..EngineOptions::default()
    }
}

/// Which process a [`Spec`] makes this binary.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Role {
    /// `landfall_server::cli::run`, as the binary's `main` calls it.
    ServerCli,
    /// The same, with the watcher reading the world.
    ServerWatching,
    /// The daemon, with [`SimDocker`] and the world's verifier.
    AgentSim,
    /// The daemon, with the real Docker and the world's verifier.
    AgentDocker,
}

#[derive(Debug, Serialize, Deserialize)]
struct Spec {
    role: Role,
    world: PathBuf,
    repo: String,
    args: Vec<String>,
}

fn agent_exit(result: Result<(), daemon::DaemonError>) -> u8 {
    match result {
        Ok(()) => 0,
        Err(error) => {
            writeln!(std::io::stderr(), "agent could not start: {error}").unwrap();
            2
        }
    }
}

/// `run` for the daemon with `docker`: `args` are config, URL, host and state dir.
fn run_agent<D: Docker>(args: &[String], world: &World, docker: &D) -> u8 {
    let [config, url, host, state] = args else {
        panic!("{args:?}");
    };
    let url = ControllerUrl::parse(url, true).unwrap();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    let verifier = |_| Ok(FileVerifier(world.clone()));
    let result = runtime.block_on(Box::pin(daemon::run_with(
        Path::new(config),
        url,
        &host.parse().unwrap(),
        Path::new(state),
        docker,
        verifier,
        quick_engine(),
    )));
    runtime.shutdown_timeout(Duration::from_secs(5));
    agent_exit(result)
}

/// Becomes the process `spec` says. Gives its exit status.
pub fn run_child(spec: &str) -> u8 {
    use landfall_server::cli::{self, Cli};
    let spec: Spec = serde_json::from_str(spec).unwrap();
    let world = World(spec.world);
    let server_cli = || {
        let name = "landfall-server".to_owned();
        Cli::parse_from(std::iter::once(name).chain(spec.args.iter().cloned()))
    };
    match spec.role {
        Role::ServerCli => cli::run(server_cli()),
        Role::ServerWatching => {
            let source = Arc::new(FileSource {
                world,
                repo: spec.repo,
            });
            cli::run_watching(server_cli(), source, WATCH_EVERY)
        }
        Role::AgentSim => run_agent(&spec.args, &world, &SimDocker(world.clone())),
        Role::AgentDocker => run_agent(&spec.args, &world, &DockerCli::new()),
    }
}

/// A process of a test, killed if the test ends before it has.
#[derive(Debug)]
pub struct Process {
    name: &'static str,
    child: Child,
    log: PathBuf,
}

impl Process {
    pub fn signal(&self, signal: Signal) {
        let pid = i32::try_from(self.child.id()).ok().and_then(Pid::from_raw);
        kill_process(pid.unwrap(), signal).unwrap();
    }

    /// Whether it is still running.
    pub fn running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    /// Waits for it to end, and gives its exit status.
    pub async fn exit_status(&mut self) -> i32 {
        let started = Instant::now();
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status.code().unwrap_or(-1);
            }
            assert!(
                started.elapsed() < PATIENCE,
                "{} did not exit:\n{}",
                self.name,
                read_log(&self.log)
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// SIGTERM, which it must end by, at once, with status 0.
    pub async fn stop(&mut self) {
        self.signal(Signal::TERM);
        let status = self.exit_status().await;
        assert_eq!(
            status,
            0,
            "{} on SIGTERM:\n{}",
            self.name,
            read_log(&self.log)
        );
    }

    /// SIGKILL: it ends with no chance to do anything about it.
    pub async fn kill(&mut self) {
        self.signal(Signal::KILL);
        self.exit_status().await;
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn read_log(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

/// One row of `deploys`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeployRow {
    pub id: i64,
    pub tag: String,
    pub state: String,
    pub outcome: Option<String>,
}

/// One row of the audit log.
#[derive(Debug, Clone)]
pub struct AuditRow {
    pub kind: String,
    pub detail: Value,
}

/// What `audit verify` said.
#[derive(Debug)]
pub struct Verified {
    pub status: i32,
    pub printed: Value,
}

/// How a fleet is put together, where a test wants other than the plain one.
#[derive(Debug)]
pub struct FleetOptions {
    /// The repository, and the part of a deployment's table after it.
    pub repo: String,
    pub repo_ids: (u64, u64),
    /// The deployment's origin, as configuration.
    pub origin: String,
    pub checks: String,
    /// The compose directory, if not one of the fleet's own.
    pub compose: Option<PathBuf>,
}

impl Default for FleetOptions {
    fn default() -> Self {
        Self {
            repo: REPO.to_owned(),
            repo_ids: (1, 2),
            origin: "origin = { workflow = \".github/workflows/release.yml\", tags = \"v*\", signed_tags = false }".to_owned(),
            checks: CHECK_COMMAND.to_owned(),
            compose: None,
        }
    }
}

/// A controller and one host, in a directory of their own.
#[derive(Debug)]
pub struct Fleet {
    _dir: tempfile::TempDir,
    pub world: World,
    pub db: PathBuf,
    pub config_path: PathBuf,
    pub config: Config,
    pub compose: PathBuf,
    pub state_dir: PathBuf,
    root: PathBuf,
    repo: String,
    port: u16,
}

impl Fleet {
    pub fn new() -> Self {
        Self::with(FleetOptions::default())
    }

    pub fn with(options: FleetOptions) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path().canonicalize().unwrap();
        let world = World(root.join("world"));
        fs::create_dir(&world.0).unwrap();
        let state_dir = root.join("state");
        DirBuilder::new().mode(0o700).create(&state_dir).unwrap();
        let compose = options.compose.clone().unwrap_or_else(|| {
            let compose = root.join("compose");
            fs::create_dir(&compose).unwrap();
            fs::write(compose.join("compose.yaml"), "services:\n  app: {}\n").unwrap();
            fs::write(
                compose.join(".env"),
                format!("COMPOSE_FILE=compose.yaml:{OVERRIDE_FILE}\n"),
            )
            .unwrap();
            compose
        });
        let text = format!(
            "[approvers]\noperator = {{ credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }}\n\
             [[deployment]]\nid = \"{DEPLOYMENT}\"\n\
             repo = {{ name = \"{repo}\", id = {repo_id}, owner_id = {owner_id} }}\n\
             host = \"{HOST}\"\ncompose = {{ dir = {compose:?}, service = \"app\" }}\n\
             {origin}\nrule = {{ auto = \"patch\", approvers = [\"operator\"] }}\n{checks}\n",
            repo = options.repo,
            repo_id = options.repo_ids.0,
            owner_id = options.repo_ids.1,
            compose = compose.to_str().unwrap(),
            origin = options.origin,
            checks = options.checks,
        );
        let config_path = root.join("fleet.toml");
        fs::write(&config_path, &text).unwrap();
        let config = parse(text.as_bytes()).unwrap();
        let port = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        Self {
            world,
            db: root.join("controller.db"),
            config_path,
            config,
            compose,
            state_dir,
            root,
            repo: options.repo,
            port,
            _dir: dir,
        }
    }

    pub fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.port)
    }

    fn log_of(&self, name: &str) -> PathBuf {
        self.root.join(format!("{name}.log"))
    }

    /// What a process of this name has written to stderr, restarts included.
    pub fn log(&self, name: &str) -> String {
        read_log(&self.log_of(name))
    }

    /// This binary, about to become `role`.
    fn child(&self, role: Role, args: Vec<String>) -> Command {
        let spec = Spec {
            role,
            world: self.world.0.clone(),
            repo: self.repo.clone(),
            args,
        };
        let mut command = Command::new(std::env::current_exe().unwrap());
        command
            .args(["--exact", "child_process", "--ignored", "--nocapture"])
            .args(["--test-threads=1", "-q"])
            .env(CHILD_SPEC, serde_json::to_string(&spec).unwrap())
            .stdin(Stdio::null());
        command
    }

    fn spawn(&self, name: &'static str, mut command: Command) -> Process {
        let log = self.log_of(name);
        let file = File::options()
            .create(true)
            .append(true)
            .open(&log)
            .unwrap();
        let child = command
            .stdout(file.try_clone().unwrap())
            .stderr(file)
            .spawn()
            .unwrap();
        Process { name, child, log }
    }

    fn serve_args(&self) -> Vec<String> {
        [
            "serve",
            "--config",
            self.config_path.to_str().unwrap(),
            "--db",
            self.db.to_str().unwrap(),
            "--listen",
            &format!("127.0.0.1:{}", self.port),
        ]
        .map(str::to_owned)
        .to_vec()
    }

    /// Starts the controller, with its watcher reading the world, and waits for it
    /// to answer.
    pub async fn controller(&self) -> Process {
        let command = self.child(Role::ServerWatching, self.serve_args());
        let mut process = self.spawn("controller", command);
        self.wait_for_health(&mut process).await;
        process
    }

    /// Starts the controller as its binary would: `extra` are more arguments.
    pub async fn real_controller(&self, extra: &[&str]) -> Process {
        let mut args = self.serve_args();
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        let mut process = self.spawn("controller", self.child(Role::ServerCli, args));
        self.wait_for_health(&mut process).await;
        process
    }

    async fn wait_for_health(&self, process: &mut Process) {
        let started = Instant::now();
        while !healthy(self.port).await {
            assert!(
                process.running(),
                "the controller ended:\n{}",
                self.log("controller")
            );
            assert!(
                started.elapsed() < PATIENCE,
                "the controller never answered:\n{}",
                self.log("controller")
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Runs `landfall-server` to its end, and gives its status and the last line it
    /// wrote to stdout: before that, the test harness says it is running one test.
    pub fn server_command(&self, args: Vec<String>) -> (i32, String) {
        let output = self.child(Role::ServerCli, args).output().unwrap();
        let stdout = String::from_utf8(output.stdout).unwrap();
        let last = stdout.lines().last().unwrap_or_default().to_owned();
        (output.status.code().unwrap_or(-1), last)
    }

    /// All that a `landfall-server` command that must succeed wrote to stdout.
    pub fn server_output(&self, args: Vec<String>) -> String {
        let output = self.child(Role::ServerCli, args).output().unwrap();
        assert!(output.status.success(), "{output:?}");
        String::from_utf8(output.stdout).unwrap()
    }

    /// A real `serve` that is expected to end by itself. Gives its status.
    pub fn serve_to_its_end(&self, extra: &[&str]) -> i32 {
        let mut args = self.serve_args();
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        self.server_command(args).0
    }

    /// A code from a real `enrol-code`, in a file for `enrol`.
    pub fn enrol_code(&self) -> PathBuf {
        let args = [
            "enrol-code",
            "--host",
            HOST,
            "--db",
            self.db.to_str().unwrap(),
        ];
        let (status, code) = self.server_command(args.map(str::to_owned).to_vec());
        assert_eq!(status, 0, "{code}");
        let path = self.root.join("code");
        fs::write(&path, format!("{code}\n")).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        path
    }

    /// The real `landfall-agent enrol` with `code_file`. Gives its exit status.
    pub fn run_enrol(&self, code_file: &Path) -> i32 {
        let output = Command::new(AGENT_BINARY)
            .args(["enrol", "--allow-insecure-controller", "--host", HOST])
            .arg("--controller")
            .arg(self.url())
            .arg("--code-file")
            .arg(code_file)
            .arg("--state-dir")
            .arg(&self.state_dir)
            .output()
            .unwrap();
        output.status.code().unwrap_or(-1)
    }

    /// Enrols the host, for real, with a new code.
    pub fn enrol(&self) {
        let code = self.enrol_code();
        assert_eq!(self.run_enrol(&code), 0);
        fs::remove_file(code).unwrap();
    }

    fn agent_args(&self) -> Vec<String> {
        vec![
            self.config_path.to_str().unwrap().to_owned(),
            self.url(),
            HOST.to_owned(),
            self.state_dir.to_str().unwrap().to_owned(),
        ]
    }

    /// Starts the daemon, on the simulated Docker.
    pub fn agent(&self) -> Process {
        self.spawn("agent", self.child(Role::AgentSim, self.agent_args()))
    }

    /// Starts the daemon, on the real Docker.
    pub fn agent_on_docker(&self) -> Process {
        self.spawn("agent", self.child(Role::AgentDocker, self.agent_args()))
    }

    /// Starts the real `landfall-agent run`, with `path` first on its `PATH`.
    pub fn real_agent(&self, path: Option<&Path>) -> Process {
        let mut command = Command::new(AGENT_BINARY);
        command
            .args(["run", "--allow-insecure-controller", "--host", HOST])
            .arg("--config")
            .arg(&self.config_path)
            .arg("--controller")
            .arg(self.url())
            .arg("--state-dir")
            .arg(&self.state_dir);
        if let Some(path) = path {
            let inherited = std::env::var_os("PATH").unwrap_or_default();
            let mut paths = vec![path.to_owned()];
            paths.extend(std::env::split_paths(&inherited));
            command.env("PATH", std::env::join_paths(paths).unwrap());
        }
        self.spawn("agent", command)
    }

    pub fn deployment_state(&self) -> DeploymentState {
        StateDir::open(&self.state_dir)
            .unwrap()
            .deployment(&DEPLOYMENT.parse().unwrap())
            .unwrap()
    }

    /// The first deploy, which an operator asks for: it is what later ones go from.
    pub async fn seed_on<D: Docker>(&self, docker: &D, release: &Release) {
        let deployment = &self.config.deployments()[0];
        let version = deployment.origin().tags().parse_tag(&release.tag).unwrap();
        let plan = DeployPlan::from_verified(deployment, &release.tag, version, &origin(release));
        let report = Box::pin(deploy::run(
            docker,
            &self.deployment_state(),
            deployment,
            &self.compose,
            &plan,
            &quick_engine(),
        ))
        .await
        .unwrap();
        assert_eq!(report.outcome, Outcome::Deployed, "{report:?}");
    }

    /// [`seed_on`](Self::seed_on) the simulated Docker.
    pub async fn seed(&self, tag: &str) {
        let release = self.world.publish(tag);
        self.seed_on(&SimDocker(self.world.clone()), &release).await;
    }

    async fn connection(&self) -> SqliteConnection {
        let options = SqliteConnectOptions::new()
            .filename(&self.db)
            .read_only(true);
        SqliteConnection::connect_with(&options).await.unwrap()
    }

    pub async fn deploys(&self) -> Vec<DeployRow> {
        let mut connection = self.connection().await;
        let rows: Vec<SqliteRow> =
            sqlx::query("SELECT id, tag, state, outcome FROM deploys ORDER BY id")
                .fetch_all(&mut connection)
                .await
                .unwrap();
        rows.iter()
            .map(|row| DeployRow {
                id: row.get("id"),
                tag: row.get("tag"),
                state: row.get("state"),
                outcome: row.get("outcome"),
            })
            .collect()
    }

    /// The release the host last said is running, if it has said.
    pub async fn running_tag(&self) -> Option<Option<String>> {
        let mut connection = self.connection().await;
        sqlx::query_scalar("SELECT tag FROM running_states WHERE deployment = ?")
            .bind(DEPLOYMENT)
            .fetch_optional(&mut connection)
            .await
            .unwrap()
    }

    pub async fn audit(&self) -> Vec<AuditRow> {
        let mut connection = self.connection().await;
        let rows: Vec<SqliteRow> =
            sqlx::query("SELECT kind, detail FROM audit_events ORDER BY seq")
                .fetch_all(&mut connection)
                .await
                .unwrap();
        rows.iter()
            .map(|row| AuditRow {
                kind: row.get("kind"),
                detail: serde_json::from_str(row.get("detail")).unwrap(),
            })
            .collect()
    }

    /// A real `audit verify`, with `--at` if given.
    pub fn audit_verify(&self, at: Option<i64>) -> Verified {
        self.audit_verify_of(&self.db, at)
    }

    /// [`audit_verify`](Self::audit_verify) of the database at `db`.
    pub fn audit_verify_of(&self, db: &Path, at: Option<i64>) -> Verified {
        let mut args = ["audit", "verify", "--db", db.to_str().unwrap()]
            .map(str::to_owned)
            .to_vec();
        if let Some(at) = at {
            args.extend(["--at".to_owned(), at.to_string()]);
        }
        let (status, line) = self.server_command(args);
        Verified {
            status,
            printed: serde_json::from_str(&line).unwrap(),
        }
    }

    /// Waits until `done` says so, or fails the test with what the processes said.
    pub async fn wait_until(&self, what: &str, done: impl AsyncFnMut() -> bool) {
        self.wait_for(PATIENCE, what, done).await;
    }

    /// [`wait_until`](Self::wait_until), for as long as `patience`.
    pub async fn wait_for(
        &self,
        patience: Duration,
        what: &str,
        mut done: impl AsyncFnMut() -> bool,
    ) {
        let started = Instant::now();
        while !done().await {
            assert!(
                started.elapsed() < patience,
                "never: {what}\n--- controller:\n{}\n--- agent:\n{}",
                self.log("controller"),
                self.log("agent"),
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    }

    /// Waits for the host to say this is what runs.
    pub async fn wait_running(&self, tag: &str) {
        self.wait_until(&format!("{tag} running"), async || {
            self.running_tag().await.flatten().as_deref() == Some(tag)
        })
        .await;
    }

    /// Waits for the deploy of `tag` to have been reported, and gives it.
    pub async fn wait_finished(&self, tag: &str) -> DeployRow {
        self.wait_until(&format!("{tag} finished"), async || {
            self.deploys()
                .await
                .iter()
                .any(|deploy| deploy.tag == tag && deploy.state == "finished")
        })
        .await;
        let deploys = self.deploys().await;
        deploys
            .into_iter()
            .rfind(|deploy| deploy.tag == tag)
            .unwrap()
    }

    /// Waits for the agent to have reached a held `up`.
    pub async fn wait_at_up(&self) {
        self.wait_until("a deploy reaching its up", async || self.world.at_up())
            .await;
    }

    /// How many of the agent's journal lines say `event`.
    pub fn journalled(&self, event: &str) -> usize {
        let needle = format!("\"event\":\"{event}\"");
        self.log("agent").matches(&needle).count()
    }

    /// Gives the watcher time for several looks, for a test that something does not
    /// happen. How many it gets is not exact: a look is what each wait is for.
    pub async fn let_the_watcher_look(&self) {
        tokio::time::sleep(WATCH_EVERY * 10).await;
    }
}

/// Whether `GET /healthz` says 200.
async fn healthy(port: u16) -> bool {
    let Ok(mut stream) = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await else {
        return false;
    };
    let request = b"GET /healthz HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return false;
    }
    let mut answer = Vec::new();
    stream.read_to_end(&mut answer).await.is_ok() && answer.starts_with(b"HTTP/1.1 200")
}
