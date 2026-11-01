//! Post-deploy checks.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use landfall_core::config::Check;
use tokio::time::Instant;

use crate::docker::{ContainerId, ContainerInfo, Docker};

/// Timing of a run of checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOptions {
    /// Pause between rounds.
    pub interval: Duration,
    /// How long to keep trying.
    pub deadline: Duration,
    /// Timeout of one HTTP probe.
    pub http_timeout: Duration,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            deadline: Duration::from_secs(180),
            http_timeout: Duration::from_secs(5),
        }
    }
}

/// What one check took.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckReport {
    /// The check's description.
    pub check: String,
    /// How many times it was evaluated.
    pub attempts: u32,
    /// Time spent evaluating it.
    pub elapsed: Duration,
}

/// Every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckSummary {
    /// One report per check, in configuration order.
    pub checks: Vec<CheckReport>,
}

/// A check failed for good.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{check}: {reason}")]
pub struct CheckFailure {
    /// The check, e.g. `checks[1] http /health on app`.
    pub check: String,
    /// Why it failed.
    pub reason: String,
}

/// The longest piece of container- or server-supplied text a reason quotes.
const QUOTE_LIMIT: usize = 200;

/// Runs `checks` against the service's container until they all pass in one
/// round or `options.deadline` passes.
///
/// A round looks up the container, inspects it once, then evaluates the
/// observing checks (`container_healthy`, `http`, `command`) in order,
/// stopping at the first that fails. Only when all of them pass in the same
/// round do the `no_log_match` checks run: each waits until its window
/// (from the container's start) has closed, then scans the logs, and a match
/// is final. A container that is missing or cannot be inspected is retried
/// like any failing check.
///
/// # Errors
///
/// The last failure, once it cannot be retried (a service that can never pass,
/// a network the container is not on, a log match) or the deadline has passed.
pub async fn run_checks<D: Docker>(
    docker: &D,
    dir: &Path,
    service: &str,
    checks: &[Check],
    options: &CheckOptions,
) -> Result<CheckSummary, CheckFailure> {
    let client = if checks.iter().any(|c| matches!(c, Check::Http { .. })) {
        Some(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(options.http_timeout)
                .build()
                .map_err(|e| CheckFailure {
                    check: "http client".to_owned(),
                    reason: quote(&e.without_url().to_string()),
                })?,
        )
    } else {
        None
    };
    let run = Run {
        docker,
        dir,
        service,
        checks,
        client: client.as_ref(),
    };
    let mut reports: Vec<CheckReport> = checks
        .iter()
        .enumerate()
        .map(|(i, c)| CheckReport {
            check: describe(i, c),
            attempts: 0,
            elapsed: Duration::ZERO,
        })
        .collect();
    let start = Instant::now();
    loop {
        match run.round(&mut reports).await {
            Ok(()) => return Ok(CheckSummary { checks: reports }),
            Err(Verdict::Fatal(failure)) => return Err(failure),
            Err(Verdict::Retry(failure)) => {
                let remaining = options.deadline.saturating_sub(start.elapsed());
                if remaining.is_zero() {
                    return Err(failure);
                }
                tokio::time::sleep(options.interval.max(MIN_INTERVAL).min(remaining)).await;
            }
        }
    }
}

fn retry(check: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Retry(CheckFailure {
        check: check.into(),
        reason: reason.into(),
    })
}

/// A zero interval would spin; this is the floor.
const MIN_INTERVAL: Duration = Duration::from_millis(1);

/// Why a check did not pass.
enum Verdict {
    /// Worth another round.
    Retry(CheckFailure),
    /// Another round cannot change it.
    Fatal(CheckFailure),
}

struct Run<'a, D> {
    docker: &'a D,
    dir: &'a Path,
    service: &'a str,
    checks: &'a [Check],
    client: Option<&'a reqwest::Client>,
}

impl<D: Docker> Run<'_, D> {
    async fn round(&self, reports: &mut [CheckReport]) -> Result<(), Verdict> {
        let id = match self.docker.container(self.dir, self.service).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                return Err(retry(
                    "container",
                    format!("service {} has no container", quote(self.service)),
                ));
            }
            Err(e) => return Err(retry("container", quote(&e.to_string()))),
        };
        let info = self
            .docker
            .inspect(&id)
            .await
            .map_err(|e| retry("container", quote(&e.to_string())))?;

        for (i, check) in self.checks.iter().enumerate() {
            if matches!(check, Check::NoLogMatch { .. }) {
                continue;
            }
            let report = &mut reports[i];
            report.attempts += 1;
            let started = Instant::now();
            let result = self.observe(&report.check, check, &id, &info).await;
            report.elapsed += started.elapsed();
            result?;
        }
        for (i, check) in self.checks.iter().enumerate() {
            let Check::NoLogMatch {
                pattern,
                within_secs,
            } = check
            else {
                continue;
            };
            let report = &mut reports[i];
            report.attempts += 1;
            let started = Instant::now();
            let result = self
                .log_window(&report.check, pattern, *within_secs, &id, &info)
                .await;
            report.elapsed += started.elapsed();
            result?;
        }
        Ok(())
    }

    async fn observe(
        &self,
        name: &str,
        check: &Check,
        id: &ContainerId,
        info: &ContainerInfo,
    ) -> Result<(), Verdict> {
        match check {
            Check::ContainerHealthy => match info.health.as_deref() {
                Some("healthy") => Ok(()),
                Some(other) => Err(retry(name, format!("health is {}", quote(other)))),
                None => Err(Verdict::Fatal(CheckFailure {
                    check: name.to_owned(),
                    reason: "the container has no healthcheck, so it can never be healthy"
                        .to_owned(),
                })),
            },
            Check::Http {
                path,
                network,
                port,
                expect,
            } => self.probe(name, info, path, network, *port, *expect).await,
            Check::Command { argv } => match self.docker.exec(id, argv).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(retry(name, "exited with a non-zero status")),
                Err(e) => Err(retry(name, quote(&e.to_string()))),
            },
            Check::NoLogMatch { .. } => Ok(()),
        }
    }

    async fn probe(
        &self,
        name: &str,
        info: &ContainerInfo,
        path: &str,
        network: &str,
        port: u16,
        expect: u16,
    ) -> Result<(), Verdict> {
        let fatal = |reason: String| {
            Verdict::Fatal(CheckFailure {
                check: name.to_owned(),
                reason,
            })
        };
        let Some(address) = info.networks.get(network) else {
            return Err(fatal(format!(
                "the container is not attached to network {network}"
            )));
        };
        let Some(ip) = address else {
            return Err(fatal(format!(
                "the container has no address on network {network}"
            )));
        };
        let url = probe_url(*ip, port, path).map_err(fatal)?;
        let Some(client) = self.client else {
            return Err(fatal("no HTTP client".to_owned()));
        };
        match client.get(url).send().await {
            Ok(response) if response.status().as_u16() == expect => Ok(()),
            Ok(response) => Err(retry(
                name,
                format!("expected {expect}, got {}", response.status().as_u16()),
            )),
            Err(e) => Err(retry(name, quote(&e.without_url().to_string()))),
        }
    }

    async fn log_window(
        &self,
        name: &str,
        pattern: &str,
        within_secs: u32,
        id: &ContainerId,
        info: &ContainerInfo,
    ) -> Result<(), Verdict> {
        let fatal = |reason: String| {
            Verdict::Fatal(CheckFailure {
                check: name.to_owned(),
                reason,
            })
        };
        let closes = info
            .started_at
            .checked_add(SignedDuration::from_secs(i64::from(within_secs)))
            .map_err(|_| fatal("the observation window is out of range".to_owned()))?;
        // The window is measured on the wall clock; a clock that already
        // passed it means no wait.
        let remaining =
            Duration::try_from(closes.duration_since(Timestamp::now())).unwrap_or(Duration::ZERO);
        tokio::time::sleep(remaining).await;
        match self.docker.logs_contain(id, info.started_at, pattern).await {
            Ok(false) => Ok(()),
            Ok(true) => Err(fatal(format!(
                "the logs match {} within {within_secs} s of the start",
                quote(pattern)
            ))),
            Err(e) => Err(retry(name, quote(&e.to_string()))),
        }
    }
}

/// `http://<ip>:<port><path>`; IPv6 addresses get their brackets.
fn probe_url(ip: IpAddr, port: u16, path: &str) -> Result<reqwest::Url, String> {
    let text = format!("http://{}{path}", SocketAddr::new(ip, port));
    reqwest::Url::parse(&text)
        .map_err(|_| format!("the path {} is not a valid URL path", quote(path)))
}

fn describe(index: usize, check: &Check) -> String {
    match check {
        Check::ContainerHealthy => format!("checks[{index}] container_healthy"),
        Check::Http { path, network, .. } => {
            format!("checks[{index}] http {} on {network}", clip(path))
        }
        Check::Command { argv } => format!(
            "checks[{index}] command {}",
            quote(argv.first().map_or("", String::as_str))
        ),
        Check::NoLogMatch { pattern, .. } => {
            format!("checks[{index}] no_log_match {}", quote(pattern))
        }
    }
}

/// `text` cut to [`QUOTE_LIMIT`] characters.
fn clip(text: &str) -> String {
    let mut out: String = text.chars().take(QUOTE_LIMIT).collect();
    if out.len() < text.len() {
        out.push_str("...");
    }
    out
}

/// `text` truncated and double-quoted with escapes, so nothing a container
/// or a server said can pass for the agent's own words or break a line.
fn quote(text: &str) -> String {
    format!("{:?}", clip(text))
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::Mutex;

    use jiff::Timestamp;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::time::Instant;

    use super::*;
    use crate::testing::{Call, FakeDocker, running};

    const LOCALHOST: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    fn dir() -> &'static Path {
        Path::new("/srv/compose/app")
    }

    fn short() -> CheckOptions {
        CheckOptions {
            interval: Duration::from_millis(10),
            deadline: Duration::from_millis(150),
            http_timeout: Duration::from_millis(500),
        }
    }

    fn http(port: u16, expect: u16) -> Check {
        Check::Http {
            path: "/health".to_owned(),
            network: "app".to_owned(),
            port,
            expect,
        }
    }

    fn inspects(docker: &FakeDocker) -> usize {
        docker.count(|c| matches!(c, Call::Inspect(_)))
    }

    /// A local server answering every request with `response`; the request
    /// lines it saw are collected.
    async fn serve(response: &'static str) -> (u16, Arc<Mutex<Vec<String>>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let seen = Arc::new(Mutex::new(Vec::new()));
        let log = Arc::clone(&seen);
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let log = Arc::clone(&log);
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 4096];
                    let n = socket.read(&mut buf).await.unwrap_or(0);
                    let text = String::from_utf8_lossy(&buf[..n]).into_owned();
                    log.lock()
                        .unwrap()
                        .push(text.lines().next().unwrap_or_default().to_owned());
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        (port, seen)
    }

    #[tokio::test(start_paused = true)]
    async fn healthy_container_passes() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(summary.checks.len(), 1);
        assert_eq!(summary.checks[0].attempts, 1);
    }

    #[tokio::test(start_paused = true)]
    async fn no_healthcheck_fails_at_once() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[]))]);
        let start = Instant::now();
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[0] container_healthy");
        assert!(failure.reason.contains("no healthcheck"), "{failure}");
        assert_eq!(inspects(&docker), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn starting_then_healthy_passes() {
        let docker = FakeDocker::new();
        docker.script_inspect([
            Ok(running(Some("starting"), &[])),
            Ok(running(Some("unhealthy"), &[])),
            Ok(running(Some("healthy"), &[])),
        ]);
        let options = CheckOptions::default();
        let start = Instant::now();
        let summary = run_checks(&docker, dir(), "app", &[Check::ContainerHealthy], &options)
            .await
            .unwrap();
        assert_eq!(summary.checks[0].attempts, 3);
        assert_eq!(start.elapsed(), options.interval * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn container_that_goes_away_is_retried() {
        let docker = FakeDocker::new();
        docker.script_container([
            Ok(None),
            Err("gone"),
            Ok(Some(crate::testing::container_id())),
        ]);
        docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
        run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(inspects(&docker), 1);
    }

    #[tokio::test]
    async fn http_matching_status_passes() {
        let (port, seen) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("healthy"), &[("app", Some(LOCALHOST))]))]);
        run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy, http(port, 200)],
            &short(),
        )
        .await
        .unwrap();
        assert_eq!(seen.lock().unwrap().as_slice(), ["GET /health HTTP/1.1"]);
    }

    #[tokio::test]
    async fn http_wrong_status_fails_naming_it() {
        let (port, _) =
            serve("HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\n\r\n").await;
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("healthy"), &[("app", Some(LOCALHOST))]))]);
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy, http(port, 200)],
            &short(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[1] http /health on app");
        assert_eq!(failure.reason, "expected 200, got 503");
        assert!(inspects(&docker) > 1, "a failing probe is retried");
    }

    #[tokio::test]
    async fn http_does_not_follow_redirects() {
        let (port, seen) = serve(
            "HTTP/1.1 302 Found\r\nlocation: http://127.0.0.1:1/elsewhere\r\ncontent-length: 0\r\n\r\n",
        )
        .await;
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[("app", Some(LOCALHOST))]))]);
        let failure = run_checks(&docker, dir(), "app", &[http(port, 200)], &short())
            .await
            .unwrap_err();
        assert_eq!(failure.reason, "expected 200, got 302");
        let seen = seen.lock().unwrap();
        assert!(!seen.is_empty());
        assert!(seen.iter().all(|line| line == "GET /health HTTP/1.1"));
    }

    #[tokio::test(start_paused = true)]
    async fn http_network_not_attached_fails_at_once() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[("other", Some(LOCALHOST))]))]);
        let start = Instant::now();
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[http(8080, 200)],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[0] http /health on app");
        assert!(
            failure.reason.contains("not attached to network app"),
            "{failure}"
        );
        assert_eq!(inspects(&docker), 1);
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn http_network_without_address_fails_at_once() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[("app", None)]))]);
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[http(8080, 200)],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(
            failure.reason.contains("no address on network app"),
            "{failure}"
        );
        assert_eq!(inspects(&docker), 1);
    }

    #[test]
    fn ipv6_addresses_are_bracketed() {
        let ip: IpAddr = "fd00::2".parse().unwrap();
        assert_eq!(
            probe_url(ip, 8080, "/health").unwrap().as_str(),
            "http://[fd00::2]:8080/health"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn command_exit_nonzero_retries_then_fails() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[]))]);
        docker.script_exec([Ok(false)]);
        let argv = vec!["/bin/check".to_owned(), "--now".to_owned()];
        let options = CheckOptions {
            interval: Duration::from_secs(10),
            deadline: Duration::from_secs(30),
            http_timeout: Duration::from_secs(1),
        };
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[Check::Command { argv: argv.clone() }],
            &options,
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[0] command \"/bin/check\"");
        assert_eq!(failure.reason, "exited with a non-zero status");
        let execs = docker.count(|c| matches!(c, Call::Exec { argv: a, .. } if *a == argv));
        assert_eq!(execs, 4, "at 0 s, 10 s, 20 s and 30 s");
    }

    #[tokio::test(start_paused = true)]
    async fn command_that_passes_after_retries_is_reported() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[]))]);
        docker.script_exec([Err("busy"), Ok(false), Ok(true)]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[Check::Command {
                argv: vec!["true".to_owned()],
            }],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(summary.checks[0].attempts, 3);
    }

    #[tokio::test(start_paused = true)]
    async fn log_match_fails_after_window() {
        let docker = FakeDocker::new();
        let info = running(Some("healthy"), &[]);
        let started = info.started_at;
        docker.script_inspect([Ok(info)]);
        docker.script_logs_contain([Ok(true)]);
        let start = Instant::now();
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[
                Check::ContainerHealthy,
                Check::NoLogMatch {
                    pattern: "panic".to_owned(),
                    within_secs: 20,
                },
            ],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[1] no_log_match \"panic\"");
        assert!(failure.reason.contains("within 20 s"), "{failure}");
        assert!(
            start.elapsed() >= Duration::from_secs(19),
            "{:?}",
            start.elapsed()
        );
        assert!(docker.calls().contains(&Call::LogsContain {
            id: crate::testing::container_id(),
            since: started,
            needle: "panic".to_owned(),
        }));
    }

    #[tokio::test(start_paused = true)]
    async fn quiet_log_window_passes() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("healthy"), &[]))]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[
                Check::ContainerHealthy,
                Check::NoLogMatch {
                    pattern: "panic".to_owned(),
                    within_secs: 5,
                },
            ],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert!(summary.checks[1].elapsed >= Duration::from_secs(4));
    }

    #[tokio::test(start_paused = true)]
    async fn log_window_already_elapsed_does_not_wait() {
        let docker = FakeDocker::new();
        let mut info = running(Some("healthy"), &[]);
        info.started_at = Timestamp::now()
            .checked_sub(jiff::SignedDuration::from_secs(600))
            .unwrap();
        docker.script_inspect([Ok(info)]);
        let start = Instant::now();
        run_checks(
            &docker,
            dir(),
            "app",
            &[
                Check::ContainerHealthy,
                Check::NoLogMatch {
                    pattern: "panic".to_owned(),
                    within_secs: 30,
                },
            ],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    #[tokio::test(start_paused = true)]
    async fn log_window_waits_for_the_observing_checks() {
        let docker = FakeDocker::new();
        docker.script_inspect([
            Ok(running(Some("starting"), &[])),
            Ok(running(Some("healthy"), &[])),
        ]);
        run_checks(
            &docker,
            dir(),
            "app",
            &[
                Check::NoLogMatch {
                    pattern: "panic".to_owned(),
                    within_secs: 1,
                },
                Check::ContainerHealthy,
            ],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        let calls = docker.calls();
        let logs = calls
            .iter()
            .filter(|c| matches!(c, Call::LogsContain { .. }))
            .count();
        assert_eq!(logs, 1, "scanned once, after the service was healthy");
    }

    #[tokio::test(start_paused = true)]
    async fn all_observing_checks_must_pass_in_one_round() {
        let docker = FakeDocker::new();
        docker.script_inspect([
            Ok(running(Some("healthy"), &[])),
            Ok(running(Some("unhealthy"), &[])),
            Ok(running(Some("healthy"), &[])),
        ]);
        docker.script_exec([Ok(false), Ok(true)]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[
                Check::ContainerHealthy,
                Check::Command {
                    argv: vec!["probe".to_owned()],
                },
            ],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(
            summary.checks[0].attempts, 3,
            "health re-checked every round"
        );
        assert_eq!(
            summary.checks[1].attempts, 2,
            "skipped in the round health failed"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn deadline_is_respected() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("starting"), &[]))]);
        let options = CheckOptions {
            interval: Duration::from_secs(10),
            deadline: Duration::from_secs(25),
            http_timeout: Duration::from_secs(1),
        };
        let start = Instant::now();
        let failure = run_checks(&docker, dir(), "app", &[Check::ContainerHealthy], &options)
            .await
            .unwrap_err();
        assert_eq!(failure.reason, "health is \"starting\"");
        assert_eq!(start.elapsed(), Duration::from_secs(25));
        assert_eq!(
            inspects(&docker),
            4,
            "at 0 s, 10 s, 20 s and a last try at 25 s"
        );
    }
}
