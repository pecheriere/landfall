//! The driver that runs the `docker` binary.

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use jiff::Timestamp;
use landfall_core::config::LOG_PATTERN_LIMIT;
use tokio::process::Command;

use super::parse::{
    parse_config, parse_container, parse_inspect, parse_project_name, parse_service_containers,
};
use super::process::{
    Captured, ReadError, kill_group, not_a_flag, read_capped, read_tail, shown_argv, spawn,
};
use super::scan::scan;
use super::{
    ContainerId, ContainerInfo, Docker, DockerError, INSPECT_FORMAT, OUTPUT_CAP, SCRUBBED_ENV,
    SERVICE_CONTAINER_FORMAT, STDERR_TAIL, ServiceConfig, ServiceContainer,
};

/// [`Docker`] on the `docker` command-line client.
#[derive(Debug, Clone)]
pub struct DockerCli {
    binary: PathBuf,
    /// Timeout of quick calls (config, ps, inspect, exec). Default 60 s.
    pub timeout: Duration,
    /// Timeout of calls that move data (pull, up, stop). Default 600 s.
    pub long_timeout: Duration,
}

impl Default for DockerCli {
    fn default() -> Self {
        Self::with_binary("docker")
    }
}

impl DockerCli {
    /// The client found as `docker` on the agent's `PATH`.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// The client at `binary`, which is a path or a name looked up on
    /// `PATH`. Tests point this at a stub script.
    #[must_use]
    pub fn with_binary(binary: impl Into<PathBuf>) -> Self {
        Self {
            binary: binary.into(),
            timeout: Duration::from_secs(60),
            long_timeout: Duration::from_secs(600),
        }
    }

    pub(super) fn command(&self, dir: Option<&Path>) -> Command {
        let mut cmd = Command::new(&self.binary);
        for var in SCRUBBED_ENV {
            cmd.env_remove(var);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true)
            .process_group(0);
        if let Some(dir) = dir {
            cmd.current_dir(dir);
        }
        cmd
    }

    fn compose(&self, dir: &Path, args: &[&str]) -> Command {
        let mut cmd = self.command(Some(dir));
        cmd.arg("compose").args(args);
        cmd
    }

    /// Runs `cmd` to completion within `limit`, with output capped, killing
    /// it on any error.
    async fn capture(
        label: &'static str,
        mut cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let mut child = spawn(label, &mut cmd)?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let work = async {
            let (out, err) = tokio::try_join!(
                read_capped(stdout, OUTPUT_CAP),
                read_tail(stderr, STDERR_TAIL)
            )?;
            let status = child.wait().await.map_err(ReadError::Io)?;
            Ok::<_, ReadError>(Captured {
                status,
                stdout: out,
                stderr_tail: err,
            })
        };
        let result = tokio::time::timeout(limit, work).await;
        let error = match result {
            Ok(Ok(captured)) => return Ok(captured),
            Ok(Err(ReadError::TooMuch)) => DockerError::TooMuchOutput {
                command: label,
                cap: OUTPUT_CAP,
            },
            Ok(Err(ReadError::Io(source))) => DockerError::Io {
                command: label,
                source,
            },
            Err(_) => DockerError::Timeout {
                command: label,
                after: limit,
            },
        };
        kill_group(label, &mut child).await?;
        Err(error)
    }

    /// [`capture`](Self::capture) for a `docker compose` subcommand: it loads
    /// the stack's `.env` and compose files and prints their parse errors,
    /// quoting values, so a failure reports its exit status only.
    async fn run_compose(
        label: &'static str,
        cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let argv = format!("{} in the compose directory", shown_argv(&cmd));
        let captured = Self::capture(label, cmd, limit).await?;
        if captured.status.success() {
            Ok(captured)
        } else {
            Err(DockerError::FailedQuietly {
                command: label,
                status: captured.status.to_string(),
                argv,
            })
        }
    }

    /// The compose project's name in `dir`. Commands given it don't load the
    /// project: compose refuses one where the service has no image, which is
    /// the state before a first deploy and the one a failed first deploy goes
    /// back to, possibly with its container still running.
    async fn project_name(&self, label: &'static str, dir: &Path) -> Result<String, DockerError> {
        let config = self.compose(dir, &["config", "--no-consistency", "--format", "json"]);
        let captured = Self::run_compose(label, config, self.timeout).await?;
        let project = parse_project_name(&captured.stdout)?;
        not_a_flag(label, &project)?;
        Ok(project)
    }

    /// `docker ps` for the running containers of `service` that `selector`
    /// picks. By the labels compose gives its containers, not through compose,
    /// which would refuse a service without an image, the state before a first
    /// deploy. `oneoff` leaves out the containers of `compose run`.
    fn ps_command(&self, selector: OsString, service: &str) -> Command {
        let mut cmd = self.command(None);
        cmd.args(["ps", "--quiet", "--no-trunc", "--filter"])
            .arg(selector)
            .arg("--filter")
            .arg(format!("label=com.docker.compose.service={service}"))
            .args(["--filter", "label=com.docker.compose.oneoff=False"]);
        cmd
    }

    /// [`capture`](Self::capture), failing on a non-zero exit with the
    /// quoted tail of stderr.
    async fn run(
        label: &'static str,
        cmd: Command,
        limit: Duration,
    ) -> Result<Captured, DockerError> {
        let captured = Self::capture(label, cmd, limit).await?;
        if captured.status.success() {
            Ok(captured)
        } else {
            Err(DockerError::Failed {
                command: label,
                status: captured.status.to_string(),
                stderr: String::from_utf8_lossy(&captured.stderr_tail).into_owned(),
            })
        }
    }
}

impl Docker for DockerCli {
    async fn pull(&self, image: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker pull";
        not_a_flag(LABEL, image)?;
        let mut cmd = self.command(None);
        cmd.args(["pull", "--", image]);
        Self::run(LABEL, cmd, self.long_timeout).await.map(drop)
    }

    async fn compose_service(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        const LABEL: &str = "docker compose config";
        // Without `--no-consistency`, compose refuses a service that has no
        // image yet, which is what a first deploy starts from (design 7.1).
        let cmd = self.compose(dir, &["config", "--no-consistency", "--format", "json"]);
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_config(&captured.stdout, service)
    }

    async fn compose_service_checked(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<ServiceConfig, DockerError> {
        const LABEL: &str = "docker compose config";
        let cmd = self.compose(dir, &["config", "--format", "json"]);
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_config(&captured.stdout, service)
    }

    async fn compose_up(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker compose up";
        not_a_flag(LABEL, service)?;
        let cmd = self.compose(dir, &["up", "-d", "--no-deps", "--", service]);
        Self::run_compose(LABEL, cmd, self.long_timeout)
            .await
            .map(drop)
    }

    async fn compose_stop(&self, dir: &Path, service: &str) -> Result<(), DockerError> {
        const LABEL: &str = "docker compose stop";
        not_a_flag(LABEL, service)?;
        let project = self.project_name(LABEL, dir).await?;
        let cmd = self.compose(dir, &["-p", &project, "stop", "--", service]);
        Self::run_compose(LABEL, cmd, self.long_timeout)
            .await
            .map(drop)
    }

    async fn container(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Option<ContainerId>, DockerError> {
        const LABEL: &str = "docker ps";
        not_a_flag(LABEL, service)?;
        let project = self.project_name(LABEL, dir).await?;
        let selector = format!("label=com.docker.compose.project={project}");
        let cmd = self.ps_command(selector.into(), service);
        // The project's name is interpolated: stderr could repeat it.
        let captured = Self::run_compose(LABEL, cmd, self.timeout).await?;
        parse_container(&captured.stdout)
    }

    async fn container_at(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Option<ContainerId>, DockerError> {
        const LABEL: &str = "docker ps";
        not_a_flag(LABEL, service)?;
        let mut selector = OsString::from("label=com.docker.compose.project.working_dir=");
        selector.push(dir);
        let cmd = self.ps_command(selector, service);
        let captured = Self::run(LABEL, cmd, self.timeout).await?;
        parse_container(&captured.stdout)
    }

    async fn inspect(&self, id: &ContainerId) -> Result<ContainerInfo, DockerError> {
        const LABEL: &str = "docker inspect";
        let mut cmd = self.command(None);
        cmd.args(["inspect", "--type", "container", "--format", INSPECT_FORMAT])
            .arg("--")
            .arg(id.as_ref());
        let captured = Self::run(LABEL, cmd, self.timeout).await?;
        parse_inspect(&captured.stdout)
    }

    async fn service_containers(
        &self,
        dir: &Path,
        service: &str,
    ) -> Result<Vec<ServiceContainer>, DockerError> {
        const LABEL: &str = "docker ps";
        not_a_flag(LABEL, service)?;
        let project = self.project_name(LABEL, dir).await?;
        let mut cmd = self.command(None);
        cmd.args(["ps", "--all", "--no-trunc", "--filter"])
            .arg(format!("label=com.docker.compose.service={service}"))
            .args(["--filter", "label=com.docker.compose.oneoff=False"])
            .args(["--format", SERVICE_CONTAINER_FORMAT]);
        let captured = Self::run(LABEL, cmd, self.timeout).await?;
        parse_service_containers(&captured.stdout, &project)
    }

    async fn exec(&self, id: &ContainerId, argv: &[String]) -> Result<bool, DockerError> {
        const LABEL: &str = "docker exec";
        if argv.is_empty() {
            return Err(DockerError::BadArgument {
                command: LABEL,
                reason: "empty command",
            });
        }
        // After the container id Docker reads no more flags of its own, so
        // an argument starting with '-' belongs to the command.
        let mut cmd = self.command(None);
        cmd.args(["exec", "--", id.as_ref()])
            .args(argv)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = spawn(LABEL, &mut cmd)?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(status)) => Ok(status.success()),
            Ok(Err(source)) => {
                kill_group(LABEL, &mut child).await?;
                Err(DockerError::Io {
                    command: LABEL,
                    source,
                })
            }
            Err(_) => {
                kill_group(LABEL, &mut child).await?;
                Err(DockerError::Timeout {
                    command: LABEL,
                    after: self.timeout,
                })
            }
        }
    }

    async fn logs_contain(
        &self,
        id: &ContainerId,
        since: Timestamp,
        until: Timestamp,
        needle: &str,
    ) -> Result<bool, DockerError> {
        const LABEL: &str = "docker logs";
        if needle.is_empty() || needle.len() > LOG_PATTERN_LIMIT || needle.contains('\n') {
            return Err(DockerError::BadArgument {
                command: LABEL,
                reason: "needle must be 1 to 4096 bytes on a single line",
            });
        }
        let out_of_range = |_| DockerError::BadArgument {
            command: LABEL,
            reason: "time out of range",
        };
        let since = Timestamp::from_second(since.as_second()).map_err(out_of_range)?;
        // Rounded up: a line in the last fraction of the window counts.
        let until_second = until.as_second() + i64::from(until.subsec_nanosecond() > 0);
        let until = Timestamp::from_second(until_second).map_err(out_of_range)?;
        let mut cmd = self.command(None);
        cmd.args([
            "logs",
            "--since",
            &since.to_string(),
            "--until",
            &until.to_string(),
            "--",
        ])
        .arg(id.as_ref());
        let argv = shown_argv(&cmd);
        let mut child = spawn(LABEL, &mut cmd)?;
        let (stdout, stderr) = (child.stdout.take(), child.stderr.take());
        let needle = needle.as_bytes();
        let work = async {
            // The container's stdout and stderr are both its log: the first
            // match in either wins, and a stream that ends only hands over
            // to the other.
            let out = scan(stdout, needle);
            let err = scan(stderr, needle);
            tokio::pin!(out, err);
            let (mut out_done, mut err_done) = (false, false);
            while !(out_done && err_done) {
                tokio::select! {
                    r = &mut out, if !out_done => {
                        if r? { return Ok::<_, io::Error>(true); }
                        out_done = true;
                    }
                    r = &mut err, if !err_done => {
                        if r? { return Ok(true); }
                        err_done = true;
                    }
                }
            }
            Ok(false)
        };
        let result = tokio::time::timeout(self.timeout, work).await;
        let error = match result {
            Ok(Ok(true)) => {
                kill_group(LABEL, &mut child).await?;
                return Ok(true);
            }
            Ok(Ok(false)) => {
                let status = tokio::time::timeout(self.timeout, child.wait()).await;
                return match status {
                    Ok(Ok(status)) if status.success() => Ok(false),
                    Ok(Ok(status)) => Err(DockerError::FailedQuietly {
                        command: LABEL,
                        status: status.to_string(),
                        argv,
                    }),
                    Ok(Err(source)) => Err(DockerError::Io {
                        command: LABEL,
                        source,
                    }),
                    Err(_) => {
                        kill_group(LABEL, &mut child).await?;
                        Err(DockerError::Timeout {
                            command: LABEL,
                            after: self.timeout,
                        })
                    }
                };
            }
            Ok(Err(source)) => DockerError::Io {
                command: LABEL,
                source,
            },
            Err(_) => DockerError::Timeout {
                command: LABEL,
                after: self.timeout,
            },
        };
        kill_group(LABEL, &mut child).await?;
        Err(error)
    }
}
