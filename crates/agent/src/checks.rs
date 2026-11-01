//! Post-deploy checks.
//!
//! These checks decide whether a release is kept, so a false pass is the worst
//! way they can fail. `http` and `command` look at one instant, and a service
//! that crash-loops passes between crashes, so passing once is not enough: see
//! [`run_checks`].

use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use jiff::{SignedDuration, Timestamp};
use landfall_core::config::Check;
use tokio::time::Instant;

use crate::docker::{ContainerId, ContainerInfo, Docker, DockerError};

/// Timing of a run of checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckOptions {
    /// Pause between rounds.
    pub interval: Duration,
    /// How long to keep trying. No blocked call outlasts it. The one thing
    /// outside it is the wait for a `no_log_match` window, which is the
    /// user's setting and may be longer: such a wait moves the deadline out,
    /// by at most the longest `within_secs` of the run in total (configuration
    /// caps that at 3600 s), so a crash loop cannot wait for window after
    /// window.
    pub deadline: Duration,
    /// Timeout of one HTTP probe.
    pub http_timeout: Duration,
    /// Wait between the first passing round and the second one that confirms
    /// it. Every successful run takes at least this long, and it is inside
    /// the deadline: a first pass this close to the deadline fails.
    pub settle: Duration,
}

impl Default for CheckOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(5),
            deadline: Duration::from_secs(180),
            http_timeout: Duration::from_secs(5),
            settle: Duration::from_secs(10),
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
    /// The image reference of the container that passed, as last inspected.
    pub image: String,
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

/// Runs `checks` against the service's container until they have passed in
/// two rounds on one run of the container, or `options.deadline` passes.
///
/// A round looks up the container, inspects it once and requires it to be
/// running, then evaluates the observing checks (`container_healthy`, `http`,
/// `command`) in order, stopping at the first that fails. Only when all of
/// them pass in the same round do the `no_log_match` checks run: each waits
/// until its window (from the container's start) has closed, then scans the
/// logs from the earliest start seen in this run to the window's end, so a
/// panic before a restart counts, and a match is final. The round then looks
/// at the container again: it must be the same one, running, from the same
/// start, with the same addresses for `http` checks.
///
/// After the first passing round, the run waits `options.settle` and requires
/// a second passing round on the same container and start. Any change, or a
/// failure in that round, starts over. A container that is missing, cannot be
/// inspected or is not running is retried like any failing check.
///
/// # Errors
///
/// The last failure, once it cannot be retried (a service that can never pass,
/// a network the container is not on, a log match, an argument the driver
/// refuses) or the deadline has passed.
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
        http_timeout: options.http_timeout,
    };
    let mut progress = Progress {
        reports: checks
            .iter()
            .enumerate()
            .map(|(i, c)| CheckReport {
                check: describe(i, c),
                attempts: 0,
                elapsed: Duration::ZERO,
            })
            .collect(),
        earliest: None,
        budget: Budget::new(options.deadline, checks),
    };
    // The run of the container the last passing round saw, if the round after
    // it is the one that may confirm it.
    let mut settling: Option<Incarnation> = None;
    let mut last_failure: Option<CheckFailure> = None;
    loop {
        match run.round(&mut progress).await {
            Ok(passed) => {
                let previous = settling.take();
                if previous.as_ref() == Some(&passed.incarnation) {
                    return Ok(CheckSummary {
                        checks: progress.reports,
                        image: passed.image,
                    });
                }
                last_failure = None;
                if progress.budget.remaining() <= options.settle {
                    return Err(too_late_to_settle(previous.is_some(), options.settle));
                }
                settling = Some(passed.incarnation);
                tokio::time::sleep(options.settle).await;
            }
            Err(Verdict::Fatal(failure)) => return Err(failure),
            // A cut-off call says less than what the rounds before it found.
            Err(Verdict::OutOfTime(failure)) => return Err(last_failure.unwrap_or(failure)),
            Err(Verdict::Retry(failure)) => {
                settling = None;
                let remaining = progress.budget.remaining();
                tokio::time::sleep(options.interval.max(MIN_INTERVAL).min(remaining)).await;
                if progress.budget.remaining().is_zero() {
                    return Err(failure);
                }
                last_failure = Some(failure);
            }
        }
    }
}

fn too_late_to_settle(restarted: bool, settle: Duration) -> CheckFailure {
    let reason = if restarted {
        format!(
            "the container keeps restarting: it did not stay up for {settle:?} before the deadline"
        )
    } else {
        format!(
            "the checks passed, but too close to the deadline to wait {settle:?} and confirm it"
        )
    };
    CheckFailure {
        check: "container".to_owned(),
        reason,
    }
}

fn retry(check: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Retry(CheckFailure {
        check: check.into(),
        reason: reason.into(),
    })
}

fn fatal(check: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Fatal(CheckFailure {
        check: check.into(),
        reason: reason.into(),
    })
}

/// A failed Docker call: worth retrying, unless the driver refused the
/// argument, which it will do again.
fn docker_failure(check: &str, error: &DockerError) -> Verdict {
    let reason = quote(&error.to_string());
    if matches!(error, DockerError::BadArgument { .. }) {
        fatal(check, reason)
    } else {
        retry(check, reason)
    }
}

/// A zero interval would spin; this is the floor.
const MIN_INTERVAL: Duration = Duration::from_millis(1);

/// Why a check did not pass.
enum Verdict {
    /// Worth another round.
    Retry(CheckFailure),
    /// Another round cannot change it.
    Fatal(CheckFailure),
    /// The deadline passed during a call.
    OutOfTime(CheckFailure),
}

/// When the run ends.
struct Budget {
    ends: Instant,
    /// How much further log windows may still move `ends`.
    window_credit: Duration,
}

impl Budget {
    fn new(deadline: Duration, checks: &[Check]) -> Self {
        let longest_window = checks
            .iter()
            .filter_map(|c| match c {
                Check::NoLogMatch { within_secs, .. } => Some(*within_secs),
                _ => None,
            })
            .max()
            .unwrap_or(0);
        Self {
            ends: Instant::now() + deadline,
            window_credit: Duration::from_secs(u64::from(longest_window)),
        }
    }

    fn remaining(&self) -> Duration {
        self.ends.saturating_duration_since(Instant::now())
    }

    /// Moves the end out by a log window's `wait`, as far as the credit goes;
    /// whether the wait fits before the end.
    fn make_room(&mut self, wait: Duration) -> bool {
        let moved = wait.min(self.window_credit);
        self.ends += moved;
        self.window_credit -= moved;
        wait < self.remaining()
    }
}

/// Runs a call that may block, for as long as the budget allows. Dropping it
/// kills any Docker process behind it.
async fn bounded<T>(
    budget: &Budget,
    check: &str,
    work: impl Future<Output = Result<T, Verdict>>,
) -> Result<T, Verdict> {
    tokio::time::timeout(budget.remaining(), work)
        .await
        .unwrap_or_else(|_| {
            Err(Verdict::OutOfTime(CheckFailure {
                check: check.to_owned(),
                reason: "no answer before the deadline".to_owned(),
            }))
        })
}

/// One start of one container.
#[derive(PartialEq, Eq)]
struct Incarnation {
    id: ContainerId,
    started_at: Timestamp,
}

/// A passing round.
struct Passed {
    incarnation: Incarnation,
    image: String,
}

/// A running container, as seen at one moment.
struct Look {
    id: ContainerId,
    info: ContainerInfo,
}

/// What rounds pass on to each other.
struct Progress {
    reports: Vec<CheckReport>,
    /// The earliest start seen; the logs since then are all from this run.
    earliest: Option<Timestamp>,
    budget: Budget,
}

struct Run<'a, D> {
    docker: &'a D,
    dir: &'a Path,
    service: &'a str,
    checks: &'a [Check],
    client: Option<&'a reqwest::Client>,
    http_timeout: Duration,
}

impl<D: Docker> Run<'_, D> {
    async fn round(&self, progress: &mut Progress) -> Result<Passed, Verdict> {
        let first = self.look(progress).await?;

        for (i, check) in self.checks.iter().enumerate() {
            if matches!(check, Check::NoLogMatch { .. }) {
                continue;
            }
            let report = &mut progress.reports[i];
            report.attempts += 1;
            let started = Instant::now();
            let result = bounded(
                &progress.budget,
                &report.check,
                self.observe(&report.check, check, &first),
            )
            .await;
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
            let since = progress
                .earliest
                .map_or(first.info.started_at, |e| e.min(first.info.started_at));
            let report = &mut progress.reports[i];
            report.attempts += 1;
            let started = Instant::now();
            let result = self
                .log_window(
                    &report.check,
                    pattern,
                    *within_secs,
                    &first,
                    since,
                    &mut progress.budget,
                )
                .await;
            report.elapsed += started.elapsed();
            result?;
        }

        // Everything above looked at the container as it was at the start of
        // the round, and a log window can be long.
        let last = self.look(progress).await?;
        if last.id != first.id {
            return Err(retry("container", "replaced during the checks"));
        }
        if last.info.started_at != first.info.started_at {
            return Err(retry("container", "restarted during the checks"));
        }
        for (check, report) in self.checks.iter().zip(&progress.reports) {
            if let Check::Http { network, .. } = check
                && last.info.networks.get(network) != first.info.networks.get(network)
            {
                return Err(retry(
                    &report.check,
                    format!("the address on network {network} changed during the checks"),
                ));
            }
        }
        Ok(Passed {
            incarnation: Incarnation {
                id: last.id,
                started_at: last.info.started_at,
            },
            image: last.info.image,
        })
    }

    /// Finds and inspects the container, which must be running.
    async fn look(&self, progress: &mut Progress) -> Result<Look, Verdict> {
        let id = bounded(&progress.budget, "container", async {
            match self.docker.container(self.dir, self.service).await {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(retry(
                    "container",
                    format!("service {} has no container", quote(self.service)),
                )),
                Err(e) => Err(docker_failure("container", &e)),
            }
        })
        .await?;
        let info = bounded(&progress.budget, "container", async {
            self.docker
                .inspect(&id)
                .await
                .map_err(|e| docker_failure("container", &e))
        })
        .await?;
        // One that never started has no meaningful start time.
        if info.status != "created" {
            progress.earliest = Some(
                progress
                    .earliest
                    .map_or(info.started_at, |e| e.min(info.started_at)),
            );
        }
        if info.status != "running" {
            return Err(retry(
                "container",
                format!("status is {}", quote(&info.status)),
            ));
        }
        Ok(Look { id, info })
    }

    async fn observe(&self, name: &str, check: &Check, look: &Look) -> Result<(), Verdict> {
        match check {
            Check::ContainerHealthy => match look.info.health.as_deref() {
                Some("healthy") => Ok(()),
                Some(other) => Err(retry(name, format!("health is {}", quote(other)))),
                None => Err(fatal(
                    name,
                    "the container has no healthcheck, so it can never be healthy",
                )),
            },
            Check::Http {
                path,
                network,
                port,
                expect,
            } => {
                self.probe(name, &look.info, path, network, *port, *expect)
                    .await
            }
            Check::Command { argv } => match self.docker.exec(&look.id, argv).await {
                Ok(true) => Ok(()),
                Ok(false) => Err(retry(name, "exited with a non-zero status")),
                Err(e) => Err(docker_failure(name, &e)),
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
        let Some(address) = info.networks.get(network) else {
            return Err(fatal(
                name,
                format!("the container is not attached to network {network}"),
            ));
        };
        let Some(ip) = address else {
            return Err(fatal(
                name,
                format!("the container has no address on network {network}"),
            ));
        };
        let url = probe_url(*ip, port, path).map_err(|reason| fatal(name, reason))?;
        let Some(client) = self.client else {
            return Err(fatal(name, "no HTTP client"));
        };
        match client.get(url).send().await {
            Ok(response) if response.status().as_u16() == expect => Ok(()),
            Ok(response) => Err(retry(
                name,
                format!("expected {expect}, got {}", response.status().as_u16()),
            )),
            Err(e) if e.is_timeout() => Err(retry(
                name,
                format!("no answer within {:?}", self.http_timeout),
            )),
            Err(e) if e.is_connect() => Err(retry(
                name,
                format!(
                    "cannot connect to {}: not listening yet, or the host cannot reach network {network} (a firewall?)",
                    SocketAddr::new(*ip, port)
                ),
            )),
            Err(e) => Err(retry(name, quote(&e.without_url().to_string()))),
        }
    }

    async fn log_window(
        &self,
        name: &str,
        pattern: &str,
        within_secs: u32,
        look: &Look,
        since: Timestamp,
        budget: &mut Budget,
    ) -> Result<(), Verdict> {
        let closes = look
            .info
            .started_at
            .checked_add(SignedDuration::from_secs(i64::from(within_secs)))
            .map_err(|_| fatal(name, "the observation window is out of range"))?;
        // The window is measured on the wall clock; a clock that already
        // passed it means no wait.
        let wait =
            Duration::try_from(closes.duration_since(Timestamp::now())).unwrap_or(Duration::ZERO);
        if !budget.make_room(wait) {
            return Err(retry(name, "the window closes after the deadline"));
        }
        tokio::time::sleep(wait).await;
        let found = bounded(budget, name, async {
            self.docker
                .logs_contain(&look.id, since, closes, pattern)
                .await
                .map_err(|e| docker_failure(name, &e))
        })
        .await?;
        if found {
            Err(fatal(
                name,
                format!(
                    "the logs match {} within {within_secs} s of the start",
                    quote(pattern)
                ),
            ))
        } else {
            Ok(())
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
            deadline: Duration::from_millis(500),
            http_timeout: Duration::from_millis(400),
            settle: Duration::from_millis(10),
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
        assert_eq!(summary.checks[0].attempts, 2, "a pass and its confirmation");
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
        assert_eq!(summary.checks[0].attempts, 4);
        assert_eq!(start.elapsed(), options.interval * 2 + options.settle);
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
        assert_eq!(inspects(&docker), 4, "two looks in each of two rounds");
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
        assert_eq!(
            seen.lock().unwrap().as_slice(),
            ["GET /health HTTP/1.1", "GET /health HTTP/1.1"]
        );
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
            ..CheckOptions::default()
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
        assert_eq!(execs, 3, "at 0 s, 10 s and 20 s");
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
        assert_eq!(summary.checks[0].attempts, 4);
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
            until: started.checked_add(SignedDuration::from_secs(20)).unwrap(),
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
        let options = CheckOptions::default();
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
            &options,
        )
        .await
        .unwrap();
        assert_eq!(start.elapsed(), options.settle, "only the settle time");
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
        assert_eq!(logs, 2, "scanned in the two rounds where it was healthy");
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
            summary.checks[0].attempts, 4,
            "health re-checked every round"
        );
        assert_eq!(
            summary.checks[1].attempts, 3,
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
            ..CheckOptions::default()
        };
        let start = Instant::now();
        let failure = run_checks(&docker, dir(), "app", &[Check::ContainerHealthy], &options)
            .await
            .unwrap_err();
        assert_eq!(failure.reason, "health is \"starting\"");
        assert_eq!(start.elapsed(), Duration::from_secs(25));
        assert_eq!(inspects(&docker), 3, "at 0 s, 10 s and 20 s");
    }

    /// `info` from a start `secs` later.
    fn restarted(info: &ContainerInfo, secs: i64) -> ContainerInfo {
        let mut later = info.clone();
        later.started_at = info
            .started_at
            .checked_add(SignedDuration::from_secs(secs))
            .unwrap();
        later
    }

    fn command() -> Check {
        Check::Command {
            argv: vec!["/bin/check".to_owned()],
        }
    }

    fn no_log_match(within_secs: u32) -> Check {
        Check::NoLogMatch {
            pattern: "panic".to_owned(),
            within_secs,
        }
    }

    #[tokio::test(start_paused = true)]
    async fn container_that_exits_during_a_log_window_fails() {
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        let mut exited = up.clone();
        exited.status = "exited".to_owned();
        docker.script_inspect([Ok(up), Ok(exited)]);
        docker.script_exec([Ok(true)]);
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[command(), no_log_match(5)],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "container");
        assert_eq!(failure.reason, "status is \"exited\"");
    }

    #[tokio::test(start_paused = true)]
    async fn restart_during_a_log_window_is_seen_and_the_earlier_logs_count() {
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        let again = restarted(&up, 3);
        docker.script_inspect([Ok(up.clone()), Ok(again.clone())]);
        docker.script_exec([Ok(true)]);
        // Nothing in the first incarnation's scan, then the panic turns up.
        docker.script_logs_contain([Ok(false), Ok(true)]);
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[command(), no_log_match(5)],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.check, "checks[1] no_log_match \"panic\"");
        let scans: Vec<(Timestamp, Timestamp)> = docker
            .calls()
            .into_iter()
            .filter_map(|c| match c {
                Call::LogsContain { since, until, .. } => Some((since, until)),
                _ => None,
            })
            .collect();
        let five = SignedDuration::from_secs(5);
        assert_eq!(
            scans,
            [
                (up.started_at, up.started_at.checked_add(five).unwrap()),
                (up.started_at, again.started_at.checked_add(five).unwrap()),
            ],
            "from the earliest start to the end of the current window"
        );
    }

    #[tokio::test(start_paused = true)]
    async fn a_start_seen_only_in_a_failed_round_still_counts_for_the_logs() {
        let docker = FakeDocker::new();
        let up = running(Some("starting"), &[]);
        let mut again = restarted(&up, 3);
        again.health = Some("healthy".to_owned());
        docker.script_inspect([Ok(up.clone()), Ok(again)]);
        run_checks(
            &docker,
            dir(),
            "app",
            &[Check::ContainerHealthy, no_log_match(1)],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        for call in docker.calls() {
            if let Call::LogsContain { since, .. } = call {
                assert_eq!(since, up.started_at);
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn replaced_container_starts_over() {
        let docker = FakeDocker::new();
        let other: ContainerId = "ba9876543210".parse().unwrap();
        docker.script_container([
            Ok(Some(crate::testing::container_id())),
            Ok(Some(other.clone())),
        ]);
        docker.script_inspect([Ok(running(None, &[]))]);
        docker.script_exec([Ok(true)]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[command()],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(summary.checks[0].attempts, 3, "one wasted, then two on it");
    }

    #[tokio::test]
    async fn address_that_changes_during_a_round_is_retried() {
        let (port, seen) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let docker = FakeDocker::new();
        let up = running(None, &[("app", Some(LOCALHOST))]);
        let mut moved = up.clone();
        moved.networks.insert("app".to_owned(), None);
        docker.script_inspect([Ok(up.clone()), Ok(moved), Ok(up)]);
        let summary = run_checks(&docker, dir(), "app", &[http(port, 200)], &short())
            .await
            .unwrap();
        assert_eq!(summary.checks[0].attempts, 3);
        assert_eq!(seen.lock().unwrap().len(), 3);
    }

    #[tokio::test(start_paused = true)]
    async fn crash_loop_fails_even_without_a_log_window() {
        // Each start lasts for one whole round, which passes, and is gone
        // after the settle time.
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        docker.script_inspect((0..200).flat_map(|i| {
            let start = restarted(&up, i);
            [Ok(start.clone()), Ok(start)]
        }));
        docker.script_exec([Ok(true)]);
        let options = CheckOptions::default();
        let start = Instant::now();
        let failure = run_checks(&docker, dir(), "app", &[command()], &options)
            .await
            .unwrap_err();
        assert!(failure.reason.contains("keeps restarting"), "{failure}");
        assert!(start.elapsed() <= options.deadline, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn settling_starts_over_when_the_start_changes() {
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        let again = restarted(&up, 12);
        docker.script_inspect([Ok(up.clone()), Ok(up), Ok(again)]);
        docker.script_exec([Ok(true)]);
        let options = CheckOptions::default();
        let start = Instant::now();
        let summary = run_checks(&docker, dir(), "app", &[command()], &options)
            .await
            .unwrap();
        assert_eq!(summary.checks[0].attempts, 3);
        assert_eq!(start.elapsed(), options.settle * 2);
    }

    #[tokio::test(start_paused = true)]
    async fn settling_starts_over_when_the_second_round_fails() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[]))]);
        docker.script_exec([Ok(true), Ok(false), Ok(true)]);
        let options = CheckOptions::default();
        let start = Instant::now();
        let summary = run_checks(&docker, dir(), "app", &[command()], &options)
            .await
            .unwrap();
        assert_eq!(summary.checks[0].attempts, 4);
        assert_eq!(start.elapsed(), options.settle * 2 + options.interval);
    }

    #[tokio::test(start_paused = true)]
    async fn first_pass_too_close_to_the_deadline_fails() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[]))]);
        docker.script_exec([Ok(true)]);
        let options = CheckOptions {
            deadline: Duration::from_secs(10),
            ..CheckOptions::default()
        };
        let failure = run_checks(&docker, dir(), "app", &[command()], &options)
            .await
            .unwrap_err();
        assert!(failure.reason.contains("too close"), "{failure}");
    }

    #[tokio::test(start_paused = true)]
    async fn summary_has_the_image_of_the_final_round() {
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        let mut swapped = up.clone();
        swapped.image = "ghcr.io/example/app@sha256:11".to_owned();
        docker.script_inspect([Ok(up), Ok(swapped)]);
        docker.script_exec([Ok(true)]);
        let summary = run_checks(
            &docker,
            dir(),
            "app",
            &[command()],
            &CheckOptions::default(),
        )
        .await
        .unwrap();
        assert_eq!(summary.image, "ghcr.io/example/app@sha256:11");
    }

    #[tokio::test(start_paused = true)]
    async fn a_blocked_call_ends_at_the_deadline_naming_the_check() {
        let docker = FakeDocker::new();
        docker.hang_when(|c| matches!(c, Call::Exec { .. }));
        docker.script_inspect([Ok(running(None, &[]))]);
        let options = CheckOptions {
            deadline: Duration::from_secs(30),
            ..CheckOptions::default()
        };
        let start = Instant::now();
        let failure = run_checks(&docker, dir(), "app", &[command()], &options)
            .await
            .unwrap_err();
        assert_eq!(start.elapsed(), options.deadline);
        assert_eq!(failure.check, "checks[0] command \"/bin/check\"");
        assert_eq!(failure.reason, "no answer before the deadline");
    }

    #[tokio::test(start_paused = true)]
    async fn a_call_cut_off_by_the_deadline_keeps_the_earlier_failure() {
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(Some("starting"), &[]))]);
        let seen = Arc::new(Mutex::new(0));
        let inspected = Arc::clone(&seen);
        docker.on_call(move |c| {
            if matches!(c, Call::Inspect(_)) {
                *inspected.lock().unwrap() += 1;
            }
        });
        let hang = Arc::clone(&seen);
        docker.hang_when(move |c| matches!(c, Call::Inspect(_)) && *hang.lock().unwrap() >= 2);
        let options = CheckOptions {
            deadline: Duration::from_secs(30),
            ..CheckOptions::default()
        };
        let start = Instant::now();
        let failure = run_checks(&docker, dir(), "app", &[Check::ContainerHealthy], &options)
            .await
            .unwrap_err();
        assert_eq!(start.elapsed(), options.deadline);
        assert_eq!(failure.reason, "health is \"starting\"");
    }

    /// In real time: the second round must find the window closed, and paused
    /// time would not move the wall clock the window is measured on.
    #[tokio::test]
    async fn a_log_window_longer_than_the_deadline_can_pass() {
        let docker = FakeDocker::new();
        let mut info = running(None, &[]);
        info.started_at = info
            .started_at
            .checked_sub(SignedDuration::from_secs(299))
            .unwrap();
        docker.script_inspect([Ok(info)]);
        docker.script_exec([Ok(true)]);
        let options = CheckOptions {
            deadline: Duration::from_millis(500),
            ..short()
        };
        let start = Instant::now();
        run_checks(
            &docker,
            dir(),
            "app",
            &[command(), no_log_match(300)],
            &options,
        )
        .await
        .unwrap();
        assert!(start.elapsed() > options.deadline, "{:?}", start.elapsed());
    }

    #[tokio::test(start_paused = true)]
    async fn a_crash_loop_cannot_wait_for_window_after_window() {
        let docker = FakeDocker::new();
        let up = running(None, &[]);
        docker.script_inspect((0..200).map(|i| Ok(restarted(&up, i))));
        docker.script_exec([Ok(true)]);
        let options = CheckOptions {
            deadline: Duration::from_secs(30),
            ..CheckOptions::default()
        };
        let start = Instant::now();
        run_checks(
            &docker,
            dir(),
            "app",
            &[command(), no_log_match(100)],
            &options,
        )
        .await
        .unwrap_err();
        assert!(
            start.elapsed() <= options.deadline + Duration::from_secs(100),
            "{:?}",
            start.elapsed()
        );
    }

    #[tokio::test]
    async fn http_on_a_container_not_running_yet_is_retried() {
        let (port, _) = serve("HTTP/1.1 200 OK\r\ncontent-length: 0\r\n\r\n").await;
        let docker = FakeDocker::new();
        // What Docker reports for a restarting container: the network with no
        // address.
        let mut restarting = running(None, &[("app", None)]);
        restarting.status = "restarting".to_owned();
        docker.script_inspect([
            Ok(restarting),
            Ok(running(None, &[("app", Some(LOCALHOST))])),
        ]);
        run_checks(&docker, dir(), "app", &[http(port, 200)], &short())
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn status_that_never_becomes_running_fails_naming_it() {
        let docker = FakeDocker::new();
        let mut info = running(None, &[("app", None)]);
        info.status = "restarting\nFAKE".to_owned();
        docker.script_inspect([Ok(info)]);
        let failure = run_checks(
            &docker,
            dir(),
            "app",
            &[http(8080, 200)],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert_eq!(failure.reason, "status is \"restarting\\nFAKE\"");
    }

    #[tokio::test]
    async fn refused_connection_says_so() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[("app", Some(LOCALHOST))]))]);
        let failure = run_checks(&docker, dir(), "app", &[http(port, 200)], &short())
            .await
            .unwrap_err();
        assert!(failure.reason.contains("cannot connect"), "{failure}");
        assert!(failure.reason.contains("firewall"), "{failure}");
    }

    #[tokio::test]
    async fn silent_server_says_it_timed_out() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let docker = FakeDocker::new();
        docker.script_inspect([Ok(running(None, &[("app", Some(LOCALHOST))]))]);
        let options = CheckOptions {
            http_timeout: Duration::from_millis(50),
            deadline: Duration::from_millis(200),
            ..short()
        };
        let failure = run_checks(&docker, dir(), "app", &[http(port, 200)], &options)
            .await
            .unwrap_err();
        assert!(failure.reason.contains("no answer within"), "{failure}");
        drop(listener);
    }

    #[tokio::test(start_paused = true)]
    async fn an_argument_the_driver_refuses_fails_at_once() {
        // The real driver, which refuses this before it runs anything.
        let docker = crate::docker::DockerCli::with_binary("/nonexistent/docker");
        let start = Instant::now();
        let failure = run_checks(
            &docker,
            dir(),
            "--help",
            &[Check::ContainerHealthy],
            &CheckOptions::default(),
        )
        .await
        .unwrap_err();
        assert!(failure.reason.contains("refused argument"), "{failure}");
        assert_eq!(start.elapsed(), Duration::ZERO);
    }

    /// Against a real Docker daemon: `cargo test -p landfall-agent --locked
    /// -- --ignored docker`. These use `command` checks, because a Docker
    /// bridge network cannot be reached from every host that runs them.
    mod real {
        use super::*;
        use crate::docker::DockerCli;
        use crate::testing::{ComposeProject, TEST_IMAGE};

        /// A project with a service `app` running `script`.
        async fn project(cli: &DockerCli, restart: &str, script: &str) -> ComposeProject {
            let services = format!(
                "  app:\n    image: {TEST_IMAGE}\n    restart: '{restart}'\n    command: [sh, -c, '{script}']\n    stop_grace_period: 1s\n"
            );
            let project = ComposeProject::new(cli, &services).await;
            cli.compose_up(project.path(), "app").await.unwrap();
            project
        }

        fn alive() -> Check {
            Check::Command {
                argv: vec!["true".to_owned()],
            }
        }

        fn options(deadline: u64, settle: u64) -> CheckOptions {
            CheckOptions {
                interval: Duration::from_millis(200),
                deadline: Duration::from_secs(deadline),
                http_timeout: Duration::from_secs(1),
                settle: Duration::from_secs(settle),
            }
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_healthy_container_passes() {
            let cli = DockerCli::new();
            let project = project(&cli, "no", "sleep 300").await;
            let summary = run_checks(
                &cli,
                project.path(),
                "app",
                &[alive(), no_log_match(2)],
                &options(30, 2),
            )
            .await
            .unwrap();
            assert_eq!(summary.image, TEST_IMAGE);
            assert_eq!(summary.checks[0].attempts, 2);
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_container_that_exits_inside_the_window_fails() {
            let cli = DockerCli::new();
            let project = project(&cli, "no", "sleep 2").await;
            let failure = run_checks(
                &cli,
                project.path(),
                "app",
                &[alive(), no_log_match(5)],
                &options(10, 1),
            )
            .await
            .unwrap_err();
            assert_eq!(failure.check, "container", "{failure}");
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_crash_loop_inside_the_window_fails() {
            let cli = DockerCli::new();
            let project = project(&cli, "always", "sleep 2; exit 1").await;
            run_checks(
                &cli,
                project.path(),
                "app",
                &[alive(), no_log_match(4)],
                &options(20, 1),
            )
            .await
            .unwrap_err();
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_crash_loop_without_a_log_window_fails() {
            let cli = DockerCli::new();
            let project = project(&cli, "always", "sleep 2; exit 1").await;
            run_checks(&cli, project.path(), "app", &[alive()], &options(20, 4))
                .await
                .unwrap_err();
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_panic_before_a_restart_counts() {
            let cli = DockerCli::new();
            // Panics once, on its first start, then stays up: the file
            // survives a restart of the container.
            let script = "if [ -e /tmp/seen ]; then sleep 300; fi; touch /tmp/seen; sleep 3; echo panic; exit 1";
            let project = project(&cli, "always", script).await;
            let failure = run_checks(
                &cli,
                project.path(),
                "app",
                &[alive(), no_log_match(6)],
                &options(30, 1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                failure.check, "checks[1] no_log_match \"panic\"",
                "{failure}"
            );
        }

        #[tokio::test]
        #[ignore = "docker: runs in ci.yml"]
        async fn docker_line_in_the_window_fails_and_a_later_one_does_not() {
            let cli = DockerCli::new();
            let inside = project(&cli, "no", "sleep 1; echo panic; sleep 300").await;
            let failure = run_checks(
                &cli,
                inside.path(),
                "app",
                &[alive(), no_log_match(3)],
                &options(30, 1),
            )
            .await
            .unwrap_err();
            assert_eq!(
                failure.check, "checks[1] no_log_match \"panic\"",
                "{failure}"
            );

            // Logged before the second round scans, but after the window.
            let later = project(&cli, "no", "sleep 5; echo panic; sleep 300").await;
            run_checks(
                &cli,
                later.path(),
                "app",
                &[alive(), no_log_match(2)],
                &options(30, 6),
            )
            .await
            .unwrap();
        }
    }
}
