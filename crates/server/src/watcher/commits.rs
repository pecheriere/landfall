//! The commits between verified releases, fetched from GitHub after each tick's
//! verifications and within a budget of GitHub's requests.
//!
//! An approver reads a release's commits to decide, so a list never passes for more
//! than it is: a range is fetched whole within one tick or not stored, keeps its
//! newest [`KEPT_COMMITS`] and GitHub's total, and says when it is too large to list
//! or its base isn't an ancestor of its head. Verification has GitHub first: this
//! runs only once a tick's verifications are done, makes at most 12 requests a tick
//! with a token and 3 without, and stops while GitHub's count of requests left is
//! below a floor, or at the first 403 or 429, which it logs once, with the repository and
//! when commits go on, so that a refusal that never lifts isn't silent. A failure is
//! recorded as `unavailable`
//! and tried again after [`COMMIT_RETRY_SECS`]; it holds and refuses nothing, and
//! writes no audit row, since nothing is decided here. A list whose pages don't hold
//! what GitHub's total says they should is a failure, not a list. The whole pass has
//! [`COMMITS_DEADLINE`], and none while GitHub has the watcher waiting for its limit.
//! Below the floor, or refused, commits wait for GitHub's window to end, across ticks:
//! until its `x-ratelimit-reset`, or an hour when it doesn't say.

use std::time::Duration;

use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, ReleaseTag, RepoName, TagPattern};
use landfall_core::text::quoted;
use landfall_origin::fetch::{
    COMPARE_PER_PAGE, ComparePage, CompareStatus, FetchError, KEPT_COMMITS, ListedCommit,
    RateLimitReset,
};
use landfall_origin::release::ReleaseError;
use semver::Version;

use super::backoff::WatcherState;
use super::{ReleaseSource, describe};
use crate::store::{NewRange, RangeState, Store, WantedRange};

/// How long after a range was unavailable it is tried again, seconds.
pub(crate) const COMMIT_RETRY_SECS: i64 = 60 * 60;

/// How long the commits of one tick may take, after its verifications and before the
/// tick ends. The next tick waits for this one, so this is time taken from verification:
/// a minute is a fifth of the five-minute [`super::TICK_INTERVAL`]. GitHub answers a
/// compare page in about a second, so a minute fits a tick's 12 requests many times
/// over, and only a slow or stalling GitHub reaches it. Each request alone may take up
/// to the fetcher's 30 s. A range cut short by it isn't stored, since a range is stored
/// only once whole, and the next tick asks for it again.
pub(crate) const COMMITS_DEADLINE: Duration = Duration::from_mins(1);

/// The most requests one range can need: its first page and the last two.
const REQUESTS_PER_RANGE: u8 = 3;

// The newest `KEPT_COMMITS` fit in the last two pages.
const _: () = assert!(KEPT_COMMITS <= COMPARE_PER_PAGE as usize);

/// The most characters of a failure in its log line.
const FAILURE_SHOWN_CHARS: usize = 256;

/// What one tick may ask of GitHub for commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct GitHubBudget {
    /// Requests left this tick.
    requests_left: u8,
    /// The fewest requests GitHub may have left for this to go on asking.
    floor: u32,
}

impl GitHubBudget {
    /// The budget of a tick: 12 requests while GitHub has at least 1,000 left with a
    /// token, and 3, one range, while it has at least 30 without, of its 60 an hour.
    #[must_use]
    pub(crate) fn for_tick(has_token: bool) -> Self {
        if has_token {
            Self {
                requests_left: 12,
                floor: 1_000,
            }
        } else {
            Self {
                requests_left: 3,
                floor: 30,
            }
        }
    }

    /// Whether `requests` more fit in what is left.
    fn covers(self, requests: u8) -> bool {
        self.requests_left >= requests
    }

    fn spend(&mut self) {
        self.requests_left = self.requests_left.saturating_sub(1);
    }

    /// Whether GitHub's count of requests left is below the floor.
    fn is_low(self, rate_remaining: Option<u32>) -> bool {
        rate_remaining.is_some_and(|left| left < self.floor)
    }
}

/// The pages holding the newest [`KEPT_COMMITS`] of a comparison of `total` commits,
/// in GitHub's order, oldest first: page 1 for a comparison of one page, else the last
/// two pages.
#[must_use]
pub(crate) fn pages_for_newest(total: u64) -> Vec<u32> {
    let per_page = u64::from(COMPARE_PER_PAGE);
    if total <= per_page {
        return vec![1];
    }
    let last = u32::try_from(total.div_ceil(per_page)).unwrap_or(u32::MAX);
    vec![last - 1, last]
}

/// Settled releases of one deployment in version order, lowest first, each tag read
/// by the pattern once, with whatever else `X` the caller keeps of each. A tag the
/// pattern doesn't read is left out: it is never a base. The one place that says where
/// a range to a release starts: [`Self::base_of`], for every release at once in
/// [`Store::ranges_wanted`] as for one release's story.
pub(crate) struct SettledByVersion<X> {
    sorted: Vec<(Version, ReleaseTag, CommitSha, X)>,
}

impl<X> SettledByVersion<X> {
    /// `settled` in version order, by `pattern`.
    pub(crate) fn new(
        pattern: &TagPattern,
        settled: impl IntoIterator<Item = (ReleaseTag, CommitSha, X)>,
    ) -> Self {
        let mut sorted: Vec<_> = settled
            .into_iter()
            .filter_map(|(tag, commit, extra)| {
                Some((pattern.parse_tag(&tag).ok()?, tag, commit, extra))
            })
            .collect();
        sorted.sort_by(|a, b| a.0.cmp(&b.0));
        Self { sorted }
    }

    /// Each release, lowest version first.
    pub(crate) fn iter(&self) -> impl Iterator<Item = &(Version, ReleaseTag, CommitSha, X)> {
        self.sorted.iter()
    }

    /// Where a range to the release at `version` starts: the highest settled release
    /// below it, where a pre-release is below its release, as semantic versioning says.
    /// `None` when there is none, and the release is the first. A binary search.
    pub(crate) fn base_of(&self, version: &Version) -> Option<(&ReleaseTag, &CommitSha)> {
        let below = self.sorted.partition_point(|(v, ..)| v < version);
        below
            .checked_sub(1)
            .and_then(|index| self.sorted.get(index))
            .map(|(_, tag, commit, _)| (tag, commit))
    }
}

/// What one tick's commits ask of GitHub, and what they learn of its limit.
struct Asking<'a> {
    budget: GitHubBudget,
    state: &'a WatcherState,
    now: i64,
    /// Where the pass's lines go: the controller's log.
    log: &'a (dyn Fn(&str) + Sync),
}

impl Asking<'_> {
    /// Whether a page that left GitHub `rate_remaining` requests is below the floor; if
    /// so, commits wait for `rate_reset`, or an hour without one.
    fn is_low(&self, rate_remaining: Option<u32>, rate_reset: Option<i64>) -> bool {
        let low = self.budget.is_low(rate_remaining);
        if low {
            let until = rate_reset.unwrap_or(self.now.saturating_add(COMMIT_RETRY_SECS));
            self.state.pause_commits(until, self.now);
        }
        low
    }

    /// Commits wait as long as GitHub's refusal of a compare in `repo` with `status` says,
    /// or an hour when it doesn't, and the log says so: the repository, the status and
    /// when commits go on, and nothing of the request, which could name a credential.
    fn refused(&self, error: &ReleaseError, repo: &RepoName, status: u16) {
        let until = match error.fetch_error() {
            Some(FetchError::RateLimited {
                reset: RateLimitReset::At(at),
                ..
            }) => at.as_second(),
            Some(FetchError::RateLimited {
                reset: RateLimitReset::After(seconds),
                ..
            }) => self
                .now
                .saturating_add(i64::try_from(*seconds).unwrap_or(i64::MAX)),
            _ => self.now.saturating_add(COMMIT_RETRY_SECS),
        };
        let until = self.state.pause_commits(until, self.now);
        (self.log)(&paused_line(repo, status, until));
    }
}

/// What came of asking for one page.
enum Asked {
    Page(ComparePage),
    /// GitHub refused for its limit: nothing more until it lifts.
    Stop,
    Failed(ReleaseError),
}

/// What came of fetching one range.
enum Fetched {
    /// All its pages came back.
    Whole {
        state: RangeState,
        total: Option<u64>,
        commits: Vec<ListedCommit>,
    },
    /// The tick stopped before it was whole: nothing of it is kept.
    Stopped,
    /// It could not be fetched, or its pages didn't hold what GitHub's total says, for
    /// this reason, hostile text in part.
    Failed(String),
}

/// The status of a 403 or a 429 from GitHub, with the rate-limit headers or without.
fn refusal_for_limit(error: &ReleaseError) -> Option<u16> {
    match error.fetch_error()? {
        FetchError::RateLimited { status, .. }
        | FetchError::Status {
            status: status @ (403 | 429),
            ..
        } => Some(*status),
        _ => None,
    }
}

/// The line logged when GitHub's refusal of a compare in `repo` pauses commits until
/// `until`, in Unix seconds.
fn paused_line(repo: &RepoName, status: u16, until: i64) -> String {
    format!(
        "watcher: commits: GitHub answered {status} to a compare in {repo}: no commits are \
         fetched until {until} (Unix seconds)"
    )
}

async fn ask<S: ReleaseSource>(
    source: &S,
    range: &WantedRange,
    page: u32,
    asking: &mut Asking<'_>,
) -> Asked {
    asking.budget.spend();
    match source
        .compare_page(&range.deployment, &range.base, &range.head, page)
        .await
    {
        Ok(answer) => Asked::Page(answer),
        Err(error) => match refusal_for_limit(&error) {
            Some(status) => {
                asking.refused(&error, &range.repo, status);
                Asked::Stop
            }
            None => Asked::Failed(error),
        },
    }
}

fn whole(state: RangeState) -> Fetched {
    Fetched::Whole {
        state,
        total: None,
        commits: Vec::new(),
    }
}

/// Fetches `range` whole, and says whether the tick should stop after it.
async fn fetch_range<S: ReleaseSource>(
    source: &S,
    range: &WantedRange,
    asking: &mut Asking<'_>,
) -> (Fetched, bool) {
    let (status, total, first, rate_remaining, rate_reset) =
        match ask(source, range, 1, asking).await {
            Asked::Page(ComparePage::Listed {
                status,
                total,
                commits,
                rate_remaining,
                rate_reset,
            }) => (status, total, commits, rate_remaining, rate_reset),
            Asked::Page(ComparePage::TooLarge) => return (whole(RangeState::TooLarge), false),
            Asked::Stop => return (Fetched::Stopped, true),
            Asked::Failed(error) => return (Fetched::Failed(describe(&error)), false),
        };
    let mut stop = asking.is_low(rate_remaining, rate_reset);
    if matches!(status, CompareStatus::Behind | CompareStatus::Diverged) {
        return (whole(RangeState::BaseNotFound), stop);
    }
    let pages = pages_for_newest(total);
    // What the pages asked for must hold: every commit from the first one on.
    let skipped = u64::from(pages[0] - 1) * u64::from(COMPARE_PER_PAGE);
    let expected = total.saturating_sub(skipped);
    let mut first = Some(first);
    let mut listed = Vec::new();
    for page in pages {
        if page == 1 {
            listed.extend(first.take().unwrap_or_default());
            continue;
        }
        if stop {
            return (Fetched::Stopped, true);
        }
        match ask(source, range, page, asking).await {
            Asked::Page(ComparePage::Listed {
                commits,
                rate_remaining,
                rate_reset,
                ..
            }) => {
                listed.extend(commits);
                stop = asking.is_low(rate_remaining, rate_reset);
            }
            Asked::Page(ComparePage::TooLarge) => return (whole(RangeState::TooLarge), false),
            Asked::Stop => return (Fetched::Stopped, true),
            Asked::Failed(error) => return (Fetched::Failed(describe(&error)), false),
        }
    }
    if u64::try_from(listed.len()).ok() != Some(expected) {
        let reason = format!(
            "GitHub counts {total} commits, and its pages held {} where {expected} were due",
            listed.len()
        );
        return (Fetched::Failed(reason), stop);
    }
    let newest = listed.len().saturating_sub(KEPT_COMMITS);
    let mut kept = listed.split_off(newest);
    kept.reverse();
    let fetched = Fetched::Whole {
        state: RangeState::Listed,
        total: Some(total),
        commits: kept,
    };
    (fetched, stop)
}

/// Fetches the ranges the releases settled under `config` want, newest first, within
/// this tick's budget, and stores each whole one, or each failure as unavailable, its
/// lines going to `log`. The count of ranges stored, unavailable ones included.
pub(crate) async fn after_tick<S: ReleaseSource>(
    store: &Store,
    source: &S,
    config: &Config,
    state: &WatcherState,
    now: i64,
    log: &(dyn Fn(&str) + Sync),
) -> usize {
    // What GitHub said of its limit in an earlier tick still holds: no request is sent
    // to learn it again.
    if state.commits_paused(now) {
        return 0;
    }
    let mut asking = Asking {
        budget: GitHubBudget::for_tick(source.has_github_token()),
        state,
        now,
        log,
    };
    let wanted = match store.ranges_wanted(config, config.hash(), now).await {
        Ok(wanted) => wanted,
        Err(error) => {
            log(&format!("watcher: commits: {error}"));
            return 0;
        }
    };
    let mut stored = 0;
    for range in &wanted {
        if !asking.budget.covers(REQUESTS_PER_RANGE) {
            break;
        }
        let (fetched, stop) = fetch_range(source, range, &mut asking).await;
        let (state, total, commits) = match fetched {
            Fetched::Whole {
                state,
                total,
                commits,
            } => (state, total, commits),
            Fetched::Stopped => break,
            Fetched::Failed(reason) => {
                // Logged when it first fails, not on each try after.
                if !range.retry {
                    log(&format!(
                        "watcher: {}: commits of {} {}...{}: unavailable: {}",
                        range.deployment,
                        range.tag,
                        range.base,
                        range.head,
                        quoted(&reason, FAILURE_SHOWN_CHARS)
                    ));
                }
                (RangeState::Unavailable, None, Vec::new())
            }
        };
        let new = NewRange {
            state,
            total,
            commits: &commits,
        };
        match store
            .record_commit_range(&range.repo, &range.base, &range.head, &new)
            .await
        {
            Ok(()) => stored += 1,
            Err(error) => log(&format!("watcher: commits: {error}")),
        }
        if stop {
            break;
        }
    }
    stored
}
