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

#[cfg(test)]
mod tests;

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
    /// What each check took up to then, in configuration order. Empty when no
    /// run began.
    pub checks: Vec<CheckReport>,
}

impl CheckFailure {
    fn new(check: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            check: check.into(),
            reason: reason.into(),
            checks: Vec::new(),
        }
    }
}

/// The longest piece of container- or server-supplied text a reason quotes.
const QUOTE_LIMIT: usize = 200;

/// Runs `checks` against the service's container until they have passed in
/// two rounds on one run of the container, or `options.deadline` passes.
/// `since` is the caller's time just before it brought the service up (with
/// `up`, or a restart where there is none).
///
/// A round looks up the container, inspects it once and requires it to be
/// running, then evaluates the observing checks (`container_healthy`, `http`,
/// `command`) in order, stopping at the first that fails. Only when all of
/// them pass in the same round do the `no_log_match` checks run: each waits
/// until its window has closed, then scans the logs from `since` to the
/// window's end, and a match is final. The window runs for `within_secs` from
/// the container's current start or from `since`, whichever is later, so a
/// container that `up` left untouched is observed for all of it, and no scan
/// is empty because its window closed before `since`. A panic before a restart
/// counts even if nothing here saw that start, while what a reused container
/// logged before `since` does not. The logs of a container
/// that was replaced are not scanned. The round then looks at the container
/// again: it must be the same one, running, from the same
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
    since: Timestamp,
    options: &CheckOptions,
) -> Result<CheckSummary, CheckFailure> {
    let client = if checks.iter().any(|c| matches!(c, Check::Http { .. })) {
        Some(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none())
                .timeout(options.http_timeout)
                .build()
                .map_err(|e| {
                    CheckFailure::new("http client", quote(&e.without_url().to_string()))
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
        since,
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
        budget: Budget::new(options.deadline, checks),
    };
    match rounds(&run, &mut progress, options).await {
        Ok(image) => Ok(CheckSummary {
            checks: progress.reports,
            image,
        }),
        Err(failure) => Err(CheckFailure {
            checks: progress.reports,
            ..failure
        }),
    }
}

/// Rounds until two have passed on one run of the container, as [`run_checks`]
/// says, or one has failed for good. Returns the image the last one saw.
async fn rounds<D: Docker>(
    run: &Run<'_, D>,
    progress: &mut Progress,
    options: &CheckOptions,
) -> Result<String, CheckFailure> {
    // The run of the container the last passing round saw, if the round after
    // it is the one that may confirm it.
    let mut settling: Option<Incarnation> = None;
    let mut last_failure: Option<CheckFailure> = None;
    loop {
        match run.round(progress).await {
            Ok(passed) => {
                let previous = settling.take();
                if previous.as_ref() == Some(&passed.incarnation) {
                    return Ok(passed.image);
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
    CheckFailure::new("container", reason)
}

fn retry(check: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Retry(CheckFailure::new(check, reason))
}

fn fatal(check: impl Into<String>, reason: impl Into<String>) -> Verdict {
    Verdict::Fatal(CheckFailure::new(check, reason))
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
            Err(Verdict::OutOfTime(CheckFailure::new(
                check,
                "no answer before the deadline",
            )))
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
    budget: Budget,
}

struct Run<'a, D> {
    docker: &'a D,
    dir: &'a Path,
    service: &'a str,
    checks: &'a [Check],
    client: Option<&'a reqwest::Client>,
    since: Timestamp,
    http_timeout: Duration,
}

impl<D: Docker> Run<'_, D> {
    async fn round(&self, progress: &mut Progress) -> Result<Passed, Verdict> {
        let first = self.look(&progress.budget).await?;

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
            let report = &mut progress.reports[i];
            report.attempts += 1;
            let started = Instant::now();
            let result = self
                .log_window(
                    &report.check,
                    pattern,
                    *within_secs,
                    &first,
                    &mut progress.budget,
                )
                .await;
            report.elapsed += started.elapsed();
            result?;
        }

        // Everything above looked at the container as it was at the start of
        // the round, and a log window can be long.
        let last = self.look(&progress.budget).await?;
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
    async fn look(&self, budget: &Budget) -> Result<Look, Verdict> {
        let id = bounded(budget, "container", async {
            match self.docker.container(self.dir, self.service).await {
                Ok(Some(id)) => Ok(id),
                Ok(None) => Err(retry(
                    "container",
                    format!("service {} has no running container", quote(self.service)),
                )),
                Err(e) => Err(docker_failure("container", &e)),
            }
        })
        .await?;
        let info = bounded(budget, "container", async {
            self.docker
                .inspect(&id)
                .await
                .map_err(|e| docker_failure("container", &e))
        })
        .await?;
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
        budget: &mut Budget,
    ) -> Result<(), Verdict> {
        let closes = look
            .info
            .started_at
            .max(self.since)
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
                .logs_contain(&look.id, self.since, closes, pattern)
                .await
                .map_err(|e| docker_failure(name, &e))
        })
        .await?;
        if found {
            Err(fatal(
                name,
                format!(
                    "the logs match {} within {within_secs} s of the service coming up",
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
pub(crate) fn quote(text: &str) -> String {
    format!("{:?}", clip(text))
}
