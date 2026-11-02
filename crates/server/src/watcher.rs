//! The release watcher: what is new in each configured repository, whether it
//! verifies, what its rule allows, and whether its host can take it now.
//!
//! No database transaction is held across the network: what is read, is read
//! first; each result is recorded on its own; and what a deploy depends on is read
//! again in the transaction that queues it.
//!
//! Each decision is recorded once with its reason. A release's origin is verified
//! once, and again only when its inputs change: the git object its tag names, or
//! the configuration. What its rule says follows the running version, so that is
//! looked at each tick and recorded when it changes. A failure that may pass is a
//! hold: recorded once with its reason, and tried again later.
//!
//! The controller only asks. The host verifies everything again and makes its own
//! decision, so nothing here is what stops a bad release from running. It is what
//! keeps the host from being asked: a claimed deploy blocks its host until it is
//! reported, so only what the host can take is queued. A host that answers not now
//! is asked again after a wait that grows with each answer; one that refuses is not
//! asked again.

mod backoff;
mod source;
mod ticking;

use std::collections::HashMap;
use std::future::Future;
use std::time::Duration;

use landfall_core::config::{Config, Deployment};
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag, RepoName};
use landfall_core::protocol::DeployId;
use landfall_core::release::{RunCandidate, select_release_run};
use landfall_core::rule::{Decision, Refusal, decide};
use landfall_core::text::{quoted, shown};
use landfall_origin::fetch::{FetchError, ListedTag, RateLimitReset};
use landfall_origin::release::{ReleaseError, ReleaseOrigin};
use semver::Version;
use serde_json::{Value, json};

pub use self::backoff::WatcherState;
pub use self::source::LiveSource;
pub use self::ticking::{run, tick};
use crate::report::MAX_STORED_TEXT_CHARS;
use crate::store::{
    Hold, NewDeploy, ReleaseDecision, Seen, Store, StoreError, StoredRelease, WatchView,
    WatchedRunning,
};

/// How often the watcher looks.
pub const TICK_INTERVAL: Duration = Duration::from_mins(5);

/// How long one repository may take in a tick. What was done by then stays done,
/// and the rest waits for the next tick.
pub const REPO_DEADLINE: Duration = Duration::from_mins(10);

/// Repositories worked on at once, so that a slow one does not hold up the rest.
const REPOS_AT_ONCE: usize = 4;

/// Releases of a deployment verified in one tick, newest first. A repository seen
/// for the first time has its whole history to get through, and this spreads that
/// over ticks.
const VERIFICATIONS_PER_TICK: usize = 16;

/// A failure that may pass is tried every tick for this long, seconds...
const EAGER_RETRY_SECS: i64 = 60 * 60;
/// ...and after that this often, seconds: an old tag that was released before the
/// project attested its images will never have a bundle.
const SLOW_RETRY_SECS: i64 = 60 * 60;
/// How often a failure is tried on a tag below the running version, seconds: only an
/// operator could want it, so it is not worth a place in the rate limit.
const BELOW_RUNNING_RETRY_SECS: i64 = 24 * 60 * 60;

/// A deploy that never touched the service may go ahead later, up to this many
/// tries for one release.
const NOTHING_CHANGED_TRIES: i64 = 3;

/// The longest wait before asking a host again after it said not now, seconds. Long
/// against the hour a host can take over one try, for which its other deployments
/// wait: a release that will never verify takes a small part of the host's time.
const DEFERRED_COOLDOWN_MAX_SECS: i64 = 6 * 60 * 60;

const HOST_DEFERRED: &str =
    "its host said not now, for the reason in its last deploy_finished; asked again after a wait";
const BEHIND_DEFERRED: &str =
    "lower releases wait behind a higher one that its host said not now to";
const NOT_REPORTED: &str = "its host has not reported this deployment yet";
const RUNNING_TAG_UNREADABLE: &str = "the running tag does not match the deployment's tag pattern";
const RATE_LIMITED: &str = "rate limited: waiting for the limit to lift";
const DRIFTED: &str = "the running state differs from what the agent deployed";
const CONFIG_DRIFTED: &str = "its host's configuration differs from the controller's";
const INTERRUPTED: &str = "an interrupted deploy on its host waits for recovery";

/// Where releases come from. The real one is [`LiveSource`].
pub trait ReleaseSource: Send + Sync + 'static {
    /// Called before each tick. An error fails it closed: nothing is verified,
    /// and every deployment is held with this reason.
    fn prepare(&self) -> impl Future<Output = Result<(), String>> + Send;

    /// The tags of `deployment`'s repository, of its pattern or not.
    fn tags(
        &self,
        deployment: &DeploymentId,
    ) -> impl Future<Output = Result<Vec<ListedTag>, ReleaseError>> + Send;

    /// Verifies the release's origin, for no host in particular.
    fn verify(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, ReleaseError>> + Send;

    /// Every digest validly attested for the release, on its verified `commit`.
    /// `version_digest`, the one verified for it, is looked at whatever is remembered
    /// about it.
    fn attested_digests(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        commit: &CommitSha,
        version_digest: &ImageDigest,
    ) -> impl Future<Output = Result<Vec<RunCandidate>, ReleaseError>> + Send;
}

/// What one tick did.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TickSummary {
    /// Releases verified.
    pub verified: usize,
    /// Releases left for a later tick, over what one tick verifies.
    pub deferred: usize,
    /// Decisions recorded.
    pub decisions: usize,
    /// Deploys queued.
    pub queued: Vec<DeployId>,
    /// Holds newly recorded.
    pub held: usize,
    /// Deployments not looked at because their repository is waiting.
    pub backed_off: usize,
    /// Repositories whose work ended in an error, a panic or its deadline.
    pub failed: usize,
}

impl TickSummary {
    fn add(&mut self, other: Self) {
        self.verified += other.verified;
        self.deferred += other.deferred;
        self.decisions += other.decisions;
        self.queued.extend(other.queued);
        self.held += other.held;
        self.backed_off += other.backed_off;
        self.failed += other.failed;
    }
}

/// Why the rest of a repository's work waits.
#[derive(Debug, Clone, Copy)]
enum Stop {
    RateLimited(RateLimitReset),
    Outage,
}

/// An error's whole chain, for a reason. Built of hostile text in part, and the
/// store quotes and bounds it.
fn describe(error: &ReleaseError) -> String {
    let mut text = error.to_string();
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        text.push_str(": ");
        text.push_str(&cause.to_string());
        source = cause.source();
    }
    text
}

/// What to do about a failure to get a release's material.
enum Failure {
    /// Stop asking this repository for a while.
    Stop(Stop, String),
    /// The release itself is refused.
    Refuse(String),
    /// Only this release waits, and whether it is slow to try again.
    Hold(String, bool),
}

fn classify(error: &ReleaseError) -> Failure {
    match error.fetch_error() {
        Some(FetchError::RateLimited { reset, .. }) => {
            Failure::Stop(Stop::RateLimited(*reset), RATE_LIMITED.to_owned())
        }
        Some(FetchError::Request { .. } | FetchError::Status { .. }) => {
            Failure::Stop(Stop::Outage, describe(error))
        }
        _ if error.is_refusal() => Failure::Refuse(describe(error)),
        _ => Failure::Hold(describe(error), error.is_slow_to_retry()),
    }
}

/// How long after the `count`th time a host said not now to ask it again, seconds:
/// `start`, doubling each time, up to [`DEFERRED_COOLDOWN_MAX_SECS`]. There is no last
/// try: the cause may pass at any time, and only the host can tell.
fn deferred_cooldown(start: i64, count: i64) -> i64 {
    let doublings = u32::try_from(count.saturating_sub(1)).unwrap_or(u32::MAX);
    2_i64
        .checked_pow(doublings)
        .and_then(|factor| factor.checked_mul(start))
        .map_or(DEFERRED_COOLDOWN_MAX_SECS, |wait| {
            wait.min(DEFERRED_COOLDOWN_MAX_SECS)
        })
}

/// Where a verified release came from, its text put through `bound`.
fn origin_value(listed: &ListedTag, origin: &ReleaseOrigin, bound: fn(&str) -> String) -> Value {
    let attestation = &origin.attestation;
    json!({
        "tag": listed.tag,
        "tag_object": listed.object,
        "commit": origin.commit,
        "digest": attestation.digest,
        "signer": origin.tag.as_ref().map(|signed| &signed.signer),
        "san": bound(&attestation.san),
        "run_url": bound(&attestation.run_url),
        "rekor_log_index": attestation.rekor_log_index,
        "integrated_time": attestation.integrated_time,
    })
}

/// A long form of text, for the tables.
fn long(text: &str) -> String {
    quoted(text, MAX_STORED_TEXT_CHARS)
}

/// A release whose origin is settled.
struct Settled {
    commit: CommitSha,
    digest: ImageDigest,
    /// Set if it was verified in this tick, so that its digests were just
    /// enumerated: its origin's short form and long form, to record.
    fresh: Option<(Value, Value)>,
}

/// Whether a host can take a deploy now.
enum HostReadiness {
    Ready,
    /// Not now, for a passing reason nobody need hear about.
    Occupied,
    /// Not until something changes, and this is what.
    Held(&'static str),
}

/// A release its rule makes automatic.
struct AutoRelease {
    version: Version,
    listed: ListedTag,
    settled: Settled,
}

/// What became of a look at a release's origin.
enum Looked {
    Settled(Settled),
    /// Recorded as refused.
    Refused,
    /// Waits, held.
    Held,
    Stopped(Stop),
}

/// Whether what enumerating found makes one release: one run and attempt, with the
/// version tag's digest among its digests.
fn one_run(
    repo: &RepoName,
    version_digest: &ImageDigest,
    candidates: &[RunCandidate],
) -> Result<(), ReleaseError> {
    select_release_run(repo, candidates, version_digest)
        .map(drop)
        .map_err(ReleaseError::Runs)
}

/// Watching one deployment for one tick.
struct DeploymentWatch<'a, S> {
    store: &'a Store,
    config: &'a Config,
    source: &'a S,
    d: &'a Deployment,
    view: WatchView,
    running: WatchedRunning,
    running_version: Option<Version>,
    holds: HashMap<String, Hold>,
    stored: HashMap<String, StoredRelease>,
    budget: usize,
    /// The wait after a host's first "not now", seconds.
    cooldown_start: i64,
    /// The highest release its host has put off and that waits to be asked again.
    highest_deferred: Option<Version>,
    summary: TickSummary,
}

impl<S: ReleaseSource> DeploymentWatch<'_, S> {
    fn key(&self) -> (&DeploymentId, &landfall_core::ids::HostId) {
        (self.d.id(), self.d.host())
    }

    async fn hold_tag(
        &mut self,
        tag: &ReleaseTag,
        reason: &str,
        slow: bool,
    ) -> Result<(), StoreError> {
        let known = self.holds.get(tag.as_ref()).is_some_and(|h| h.says(reason));
        self.store
            .set_hold(self.key(), Some(tag), reason, slow)
            .await?;
        if !known {
            self.summary.held += 1;
        }
        Ok(())
    }

    /// Records a decision, unless it is what is already recorded and there is no
    /// new look at the release to record with it.
    async fn record(
        &mut self,
        tag: &ReleaseTag,
        decision: ReleaseDecision,
        reason: &str,
        seen: Option<&Seen<'_>>,
    ) -> Result<(), StoreError> {
        let known = self
            .stored
            .get(tag.as_ref())
            .is_some_and(|stored| stored.says(decision, reason));
        if known && seen.is_none() {
            return Ok(());
        }
        let (deployment, host) = self.key();
        self.store
            .record_release((deployment, host, tag), decision, reason, seen)
            .await?;
        if !known {
            self.summary.decisions += 1;
        }
        Ok(())
    }

    /// Whether a release on hold is due another try: every tick for a while, then
    /// slowly; slowly from the start if the hold says so; hardly ever if it is below
    /// the running version.
    fn retry_due(&self, hold: &Hold, version: &Version, now: i64) -> bool {
        let below_running = self.running_version.as_ref().is_some_and(|r| version < r);
        let wait = if below_running {
            BELOW_RUNNING_RETRY_SECS
        } else if hold.slow || now.saturating_sub(hold.since) >= EAGER_RETRY_SECS {
            SLOW_RETRY_SECS
        } else {
            0
        };
        now.saturating_sub(hold.last_try) >= wait
    }

    /// Records a release as refused by verification, for as long as its inputs stay
    /// the same. A digest it had before stays recorded.
    async fn record_refusal(
        &mut self,
        listed: &ListedTag,
        commit: Option<&CommitSha>,
        reason: &str,
    ) -> Result<(), StoreError> {
        let origin = json!({
            "tag": listed.tag,
            "tag_object": listed.object,
            "commit": commit,
            "refused": long(reason),
        });
        let detail = json!({
            "tag": listed.tag,
            "tag_object": listed.object,
            "commit": commit,
            "refused": shown(reason),
        });
        let config = self.config;
        let seen = Seen {
            tag_object: &listed.object,
            config_hash: config.hash(),
            commit,
            digest: None,
            refused: true,
            detail,
            origin,
        };
        self.record(&listed.tag, ReleaseDecision::Refused, reason, Some(&seen))
            .await
    }

    /// What is known of a release's origin, verifying it if its inputs changed.
    async fn look_at_origin(
        &mut self,
        version: &Version,
        listed: &ListedTag,
    ) -> Result<Looked, StoreError> {
        let config_hash = self.config.hash();
        if let Some(row) = self
            .stored
            .get(listed.tag.as_ref())
            .filter(|row| row.has_inputs(&listed.object, config_hash))
        {
            return Ok(match (&row.commit, &row.digest, row.origin_refused) {
                (Some(commit), Some(digest), false) => Looked::Settled(Settled {
                    commit: commit.clone(),
                    digest: digest.clone(),
                    fresh: None,
                }),
                _ => Looked::Refused,
            });
        }
        if !version.pre.is_empty() && !self.d.rule().prereleases() {
            self.record_refusal(listed, None, refusal_reason(Refusal::Prerelease))
                .await?;
            return Ok(Looked::Refused);
        }
        let now = self.store.now()?;
        if let Some(hold) = self.holds.get(listed.tag.as_ref())
            && !self.retry_due(hold, version, now)
        {
            return Ok(Looked::Held);
        }
        if self.budget == 0 {
            self.summary.deferred += 1;
            return Ok(Looked::Held);
        }
        self.budget -= 1;
        self.verify(listed).await
    }

    /// Verifies a release and enumerates its digests.
    async fn verify(&mut self, listed: &ListedTag) -> Result<Looked, StoreError> {
        let id = self.d.id();
        let origin = match self.source.verify(id, &listed.tag).await {
            Ok(origin) => origin,
            Err(error) => return self.failed(listed, None, &error).await,
        };
        self.summary.verified += 1;
        let digest = &origin.attestation.digest;
        let candidates = match self
            .source
            .attested_digests(id, &listed.tag, &origin.commit, digest)
            .await
        {
            Ok(candidates) => candidates,
            Err(error) => return self.failed(listed, Some(&origin.commit), &error).await,
        };
        if let Err(error) = one_run(self.d.repo().name(), digest, &candidates) {
            return self.failed(listed, Some(&origin.commit), &error).await;
        }
        Ok(Looked::Settled(Settled {
            commit: origin.commit.clone(),
            digest: digest.clone(),
            fresh: Some((
                origin_value(listed, &origin, shown),
                origin_value(listed, &origin, long),
            )),
        }))
    }

    /// Records a failure as what it is.
    async fn failed(
        &mut self,
        listed: &ListedTag,
        commit: Option<&CommitSha>,
        error: &ReleaseError,
    ) -> Result<Looked, StoreError> {
        match classify(error) {
            Failure::Stop(stop, reason) => {
                self.hold_tag(&listed.tag, &reason, false).await?;
                Ok(Looked::Stopped(stop))
            }
            Failure::Refuse(reason) => {
                self.record_refusal(listed, commit, &reason).await?;
                Ok(Looked::Refused)
            }
            Failure::Hold(reason, slow) => {
                self.hold_tag(&listed.tag, &reason, slow).await?;
                Ok(Looked::Held)
            }
        }
    }

    /// Why a release this deployment's rule would allow is not to be queued, from
    /// what became of it here before. What is final comes first: a host's "not now"
    /// only ever makes it wait, and never ends it.
    fn history_says_no(
        &self,
        tag: &ReleaseTag,
        digest: &ImageDigest,
        now: i64,
    ) -> Option<(ReleaseDecision, &'static str)> {
        let finished = self
            .view
            .finished
            .iter()
            .filter(|f| f.tag == tag.as_ref() && f.digest == digest.as_ref());
        let refused = |reason| Some((ReleaseDecision::Refused, reason));
        let mut deferred = None;
        for deploy in finished {
            match deploy.outcome.as_str() {
                "nothing_changed" if deploy.count < NOTHING_CHANGED_TRIES => {}
                "nothing_changed" => return refused("its deploys kept stopping before they began"),
                "deferred" => deferred = Some(deploy),
                "rolled_back" => return refused("it already rolled back on its host"),
                "refused" => return refused("its host refused it"),
                "deployed" => return refused("it was deployed before and is not running now"),
                _ => return refused("its deploy failed on its host"),
            }
        }
        deferred
            .filter(|deploy| {
                now.saturating_sub(deploy.last_finished_at)
                    < deferred_cooldown(self.cooldown_start, deploy.count)
            })
            .map(|_| (ReleaseDecision::Deferred, HOST_DEFERRED))
    }

    /// What the rule, the release's history and promotion allow.
    async fn decision(
        &self,
        version: &Version,
        tag: &ReleaseTag,
        digest: &ImageDigest,
    ) -> Result<(ReleaseDecision, String), StoreError> {
        let (decision, reason) = match decide(self.d.rule(), self.running_version.as_ref(), version)
        {
            Decision::Auto => (
                ReleaseDecision::Auto,
                "a higher version within the rule's automatic level",
            ),
            Decision::NeedsApproval => (
                ReleaseDecision::NeedsApproval,
                "a higher version that needs an approver",
            ),
            Decision::Manual => {
                let reason = match &self.running_version {
                    None => "nothing has been deployed yet: a first deploy needs an operator",
                    Some(running) if version < running => {
                        "lower than the running version: a downgrade needs an operator"
                    }
                    Some(_) => "beyond the rule's levels: it needs an operator",
                };
                return Ok((ReleaseDecision::Manual, reason.to_owned()));
            }
            Decision::Refused(refusal) => {
                return Ok((ReleaseDecision::Refused, refusal_reason(refusal).to_owned()));
            }
        };
        if let Some((no, why)) = self.history_says_no(tag, digest, self.store.now()?) {
            return Ok((no, why.to_owned()));
        }
        if let Some(source) =
            promotion_waits_for(self.store, self.config, self.d.id(), tag, digest).await?
        {
            let reason = format!(
                "waits for promotion: not yet reported healthy for long enough on {source}, or \
                 it has gone quiet (enforced by the controller only)"
            );
            return Ok((ReleaseDecision::Manual, reason));
        }
        Ok((decision, reason.to_owned()))
    }

    /// Whether this release has failed before and has not been settled since, and
    /// so waits for what has never been tried.
    fn is_retry(&self, listed: &ListedTag) -> bool {
        self.holds.contains_key(listed.tag.as_ref())
            && !self
                .stored
                .get(listed.tag.as_ref())
                .is_some_and(|row| row.has_inputs(&listed.object, self.config.hash()))
    }

    /// Goes through the deployment's releases, newest first, those never tried before
    /// those that failed, so that tags that keep failing cannot starve a release
    /// below them. Gives the ones its rule makes automatic, highest first, and what
    /// stopped the look, if anything. What was settled before a stop still counts: a
    /// rate limit met among old tags does not hold up a new release.
    async fn go_through(
        &mut self,
        releases: &[(Version, ListedTag)],
    ) -> Result<(Vec<AutoRelease>, Option<Stop>), StoreError> {
        let (retries, first_looks): (Vec<_>, Vec<_>) = releases
            .iter()
            .partition(|(_, listed)| self.is_retry(listed));
        let mut autos = Vec::new();
        let mut stopped = None;
        for (version, listed) in first_looks.into_iter().chain(retries) {
            let settled = match self.look_at_origin(version, listed).await? {
                Looked::Settled(settled) => settled,
                Looked::Refused | Looked::Held => continue,
                Looked::Stopped(stop) => {
                    stopped = Some(stop);
                    break;
                }
            };
            let (decision, reason) = self.decision(version, &listed.tag, &settled.digest).await?;
            let config = self.config;
            let seen = settled.fresh.as_ref().map(|(detail, origin)| Seen {
                tag_object: &listed.object,
                config_hash: config.hash(),
                commit: Some(&settled.commit),
                digest: Some(&settled.digest),
                refused: false,
                detail: detail.clone(),
                origin: origin.clone(),
            });
            self.record(&listed.tag, decision, &reason, seen.as_ref())
                .await?;
            if decision == ReleaseDecision::Deferred
                && self.highest_deferred.as_ref().is_none_or(|v| version > v)
            {
                self.highest_deferred = Some(version.clone());
            }
            if decision == ReleaseDecision::Auto {
                autos.push(AutoRelease {
                    version: version.clone(),
                    listed: listed.clone(),
                    settled,
                });
            }
        }
        autos.sort_by(|a, b| b.version.cmp(&a.version));
        Ok((autos, stopped))
    }

    /// Whether the host can take a deploy now.
    fn host_readiness(&self) -> HostReadiness {
        if self.view.active_deploy || self.running.busy && !self.running.drift {
            HostReadiness::Occupied
        } else if self.running.drift {
            HostReadiness::Held(DRIFTED)
        } else if self.view.config_drifted {
            HostReadiness::Held(CONFIG_DRIFTED)
        } else if self.running.phase != "idle" && !self.running.busy {
            HostReadiness::Held(INTERRUPTED)
        } else {
            HostReadiness::Ready
        }
    }

    /// Whether `auto` may go: one verified in an earlier tick has its digests
    /// enumerated again, since a second run may have come since, unless it is on
    /// hold and not yet due another try. Gives whether it may, and what stopped it.
    async fn still_one_run(
        &mut self,
        auto: &AutoRelease,
    ) -> Result<(bool, Option<Stop>), StoreError> {
        let AutoRelease {
            version,
            listed,
            settled,
        } = auto;
        if settled.fresh.is_some() {
            return Ok((true, None));
        }
        let hold = self.holds.get(listed.tag.as_ref());
        let was_waiting = hold.is_some();
        let now = self.store.now()?;
        if hold.is_some_and(|hold| !self.retry_due(hold, version, now)) {
            return Ok((false, None));
        }
        let enumerated = self
            .source
            .attested_digests(self.d.id(), &listed.tag, &settled.commit, &settled.digest)
            .await
            .and_then(|candidates| one_run(self.d.repo().name(), &settled.digest, &candidates));
        match enumerated {
            Ok(()) => {
                if was_waiting {
                    self.store
                        .clear_hold(self.d.id(), Some(&listed.tag))
                        .await?;
                }
                Ok((true, None))
            }
            Err(error) => match self.failed(listed, Some(&settled.commit), &error).await? {
                Looked::Stopped(stop) => Ok((false, Some(stop))),
                Looked::Settled(_) | Looked::Refused | Looked::Held => Ok((false, None)),
            },
        }
    }

    /// Queues the highest of `autos` that can go. One refused or on hold is skipped,
    /// and is not queued. None lower than a release its host has only put off goes: it
    /// is still on its way, and each lower one could otherwise take its own turn at
    /// holding the host. Gives what to hold the deployment for, and what stopped it.
    async fn queue_highest(
        &mut self,
        mut autos: Vec<AutoRelease>,
    ) -> Result<(Option<&'static str>, Option<Stop>), StoreError> {
        if autos.is_empty() {
            return Ok((None, None));
        }
        if let Some(deferred) = &self.highest_deferred {
            autos.retain(|auto| auto.version > *deferred);
            if autos.is_empty() {
                return Ok((Some(BEHIND_DEFERRED), None));
            }
        }
        match self.host_readiness() {
            HostReadiness::Ready => {}
            HostReadiness::Occupied => return Ok((None, None)),
            HostReadiness::Held(reason) => return Ok((Some(reason), None)),
        }
        for auto in autos {
            let (may_go, stop) = self.still_one_run(&auto).await?;
            if stop.is_some() {
                return Ok((None, stop));
            }
            if !may_go {
                continue;
            }
            let deploy = NewDeploy {
                deployment: self.d.id().clone(),
                host: self.d.host().clone(),
                tag: auto.listed.tag,
                digest: auto.settled.digest,
                commit: auto.settled.commit,
            };
            if let Some(id) = self
                .store
                .queue_if_unchanged(&deploy, &self.running)
                .await?
            {
                self.summary.queued.push(id);
            }
            break;
        }
        Ok((None, None))
    }
}

/// The deployment the promotion of `tag` to `target` still waits for, if any: every
/// deployment that promotes to it must have had it healthy for long enough. Enforced by
/// the controller only.
pub(crate) async fn promotion_waits_for<'a>(
    store: &Store,
    config: &'a Config,
    target: &DeploymentId,
    tag: &ReleaseTag,
    digest: &ImageDigest,
) -> Result<Option<&'a DeploymentId>, StoreError> {
    for source in config.deployments() {
        let Some(promotion) = source.promote_to() else {
            continue;
        };
        if promotion.deployment() == target
            && !store
                .healthy_for(
                    (source.id(), source.host()),
                    tag,
                    digest,
                    promotion.healthy_for_secs(),
                )
                .await?
        {
            return Ok(Some(source.id()));
        }
    }
    Ok(None)
}

/// The reason for a refusal by the rule.
fn refusal_reason(refusal: Refusal) -> &'static str {
    match refusal {
        Refusal::Prerelease => "a pre-release, and the rule does not opt in",
        Refusal::AlreadyRunning => "already running",
    }
}

/// Makes the hold on the whole deployment say `reason`, or nothing.
async fn settle_whole_hold(
    store: &Store,
    d: &Deployment,
    whole: Option<&Hold>,
    reason: Option<&str>,
    summary: &mut TickSummary,
) -> Result<(), StoreError> {
    match (reason, whole) {
        (None, None) => {}
        (None, Some(_)) => store.clear_hold(d.id(), None).await?,
        (Some(reason), whole) => {
            if !whole.is_some_and(|hold| hold.says(reason)) {
                summary.held += 1;
            }
            store
                .set_hold((d.id(), d.host()), None, reason, false)
                .await?;
        }
    }
    Ok(())
}

/// One tick of one deployment. Gives what it did and what stops its repository.
async fn watch_deployment<S: ReleaseSource>(
    store: &Store,
    config: &Config,
    source: &S,
    d: &Deployment,
    cooldown_start: i64,
) -> Result<(TickSummary, Option<Stop>), StoreError> {
    let mut summary = TickSummary::default();
    let id = d.id();
    let view = store.watch_view(id, d.host()).await?;
    let (holds, whole) = store.holds_of(id).await?;
    let whole = whole.as_ref();
    let Some(running) = view.running.clone() else {
        settle_whole_hold(store, d, whole, Some(NOT_REPORTED), &mut summary).await?;
        return Ok((summary, None));
    };
    let running_version = match &running.tag {
        None => None,
        Some(tag) => {
            if let Ok(version) = d.origin().tags().parse_tag(tag) {
                Some(version)
            } else {
                settle_whole_hold(store, d, whole, Some(RUNNING_TAG_UNREADABLE), &mut summary)
                    .await?;
                return Ok((summary, None));
            }
        }
    };
    let listed = match source.tags(id).await {
        Ok(listed) => listed,
        Err(error) => {
            let (stop, reason) = match classify(&error) {
                Failure::Stop(stop, reason) => (stop, reason),
                Failure::Refuse(reason) | Failure::Hold(reason, _) => (Stop::Outage, reason),
            };
            settle_whole_hold(store, d, whole, Some(&reason), &mut summary).await?;
            return Ok((summary, Some(stop)));
        }
    };
    let mut releases: Vec<(Version, ListedTag)> = listed
        .into_iter()
        .filter_map(|listed| {
            let version = d.origin().tags().parse_tag(&listed.tag).ok()?;
            Some((version, listed))
        })
        .collect();
    releases.sort_by(|a, b| b.0.cmp(&a.0));

    let mut watch = DeploymentWatch {
        store,
        config,
        source,
        d,
        view,
        running,
        running_version,
        holds,
        stored: store.releases_of(id).await?,
        budget: VERIFICATIONS_PER_TICK,
        cooldown_start,
        highest_deferred: None,
        summary,
    };
    let (autos, stopped) = watch.go_through(&releases).await?;
    let (hold, stop) = watch.queue_highest(autos).await?;
    let stop = stopped.or(stop);
    let mut summary = watch.summary;
    // A stop that came with a reason left it on the tag it was looking at. The
    // deployment's own hold is about the deployment.
    settle_whole_hold(store, d, whole, hold, &mut summary).await?;
    Ok((summary, stop))
}

#[cfg(test)]
mod tests;
