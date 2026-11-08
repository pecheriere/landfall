//! How long each repository waits after a failure or a rate limit.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use landfall_origin::fetch::RateLimitReset;

use super::commits::COMMITS_DEADLINE;
use super::{REPO_DEADLINE, TICK_INTERVAL};

/// The first wait after a failure, seconds; it doubles with each one after.
pub(super) const BACKOFF_START_SECS: i64 = 5 * 60;
/// The longest wait after failures, seconds.
pub(super) const BACKOFF_MAX_SECS: i64 = 60 * 60;
/// The longest wait a server can ask for, seconds. Its word on when a limit lifts
/// is hostile too, and must not silence a repository for good.
pub(super) const RATE_LIMIT_MAX_SECS: i64 = 24 * 60 * 60;

#[derive(Debug, Clone, Copy)]
struct Backoff {
    until: i64,
    failures: u32,
    /// Whether it waits for a server's rate limit, rather than after failures.
    rate_limited: bool,
}

/// What the watcher keeps between ticks: how long each repository waits, by its
/// numeric id. In memory only: after a restart a repository is simply asked again.
#[derive(Debug)]
pub struct WatcherState {
    backoffs: Mutex<HashMap<u64, Backoff>>,
    /// Whose turn it is to go first in each repository, as a count of looks.
    turns: Mutex<HashMap<u64, usize>>,
    /// Until when no commits are asked of GitHub, in Unix seconds: its window's reset,
    /// once it had fewer requests left than the floor or refused one. Kept across ticks,
    /// so a new tick's budget doesn't spend a request to learn it again.
    commits_paused_until: Mutex<i64>,
    pub(super) repo_deadline: Duration,
    /// How long a tick's commits may take.
    pub(super) commits_deadline: Duration,
    /// The wait after a host's first "not now", seconds: one look's worth.
    pub(super) cooldown_start: i64,
}

impl Default for WatcherState {
    fn default() -> Self {
        Self::looking_every(TICK_INTERVAL)
    }
}

impl WatcherState {
    /// The default state but for how long a repository may take, for a test.
    #[cfg(test)]
    pub(super) fn with_deadline(repo_deadline: Duration) -> Self {
        Self {
            repo_deadline,
            ..Self::default()
        }
    }

    /// The default state but for how long a tick's commits may take, for a test.
    #[cfg(test)]
    pub(super) fn with_commits_deadline(commits_deadline: Duration) -> Self {
        Self {
            commits_deadline,
            ..Self::default()
        }
    }

    /// The state of a watcher that looks every `interval`.
    pub(super) fn looking_every(interval: Duration) -> Self {
        Self {
            backoffs: Mutex::default(),
            turns: Mutex::default(),
            commits_paused_until: Mutex::new(i64::MIN),
            repo_deadline: REPO_DEADLINE,
            commits_deadline: COMMITS_DEADLINE,
            cooldown_start: i64::try_from(interval.as_secs()).unwrap_or(i64::MAX),
        }
    }

    /// The count of looks at `repo` before this one.
    pub(super) fn next_turn(&self, repo: u64) -> usize {
        // Each step leaves the map valid, so a panic elsewhere changes nothing.
        let mut turns = self.turns.lock().unwrap_or_else(PoisonError::into_inner);
        let turn = turns.entry(repo).or_insert(0);
        let this = *turn;
        *turn = turn.wrapping_add(1);
        this
    }

    fn locked(&self) -> MutexGuard<'_, HashMap<u64, Backoff>> {
        // Each step leaves the map valid, so a panic elsewhere changes nothing.
        self.backoffs.lock().unwrap_or_else(PoisonError::into_inner)
    }

    pub(super) fn is_waiting(&self, repo: u64, now: i64) -> bool {
        self.locked().get(&repo).is_some_and(|b| now < b.until)
    }

    /// Whether any repository waits for a server's rate limit now. The commits between
    /// releases are not asked for then: GitHub's requests go to verification first, and
    /// one limit on the controller's address or token is likely the same for both.
    pub(super) fn any_rate_limited(&self, now: i64) -> bool {
        self.locked()
            .values()
            .any(|b| b.rate_limited && now < b.until)
    }

    pub(super) fn succeeded(&self, repo: u64) {
        self.locked().remove(&repo);
    }

    /// Whether commits wait for GitHub's rate-limit window to end.
    pub(super) fn commits_paused(&self, now: i64) -> bool {
        now < *self
            .commits_paused_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Commits wait until `until`, as far as a server's word is believable: at least a
    /// second and at most [`RATE_LIMIT_MAX_SECS`] from `now`. A later pause already set
    /// stands. Returns when they wait until now.
    pub(super) fn pause_commits(&self, until: i64, now: i64) -> i64 {
        let until = until.clamp(
            now.saturating_add(1),
            now.saturating_add(RATE_LIMIT_MAX_SECS),
        );
        let mut paused = self
            .commits_paused_until
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        *paused = (*paused).max(until);
        *paused
    }

    /// The repository waits longer the more often it fails in a row.
    pub(super) fn failed(&self, repo: u64, now: i64) {
        let mut backoffs = self.locked();
        let failures = backoffs.get(&repo).map_or(0, |b| b.failures) + 1;
        let wait = 2_i64
            .checked_pow(failures - 1)
            .and_then(|factor| factor.checked_mul(BACKOFF_START_SECS))
            .map_or(BACKOFF_MAX_SECS, |wait| wait.min(BACKOFF_MAX_SECS));
        backoffs.insert(
            repo,
            Backoff {
                until: now.saturating_add(wait),
                failures,
                rate_limited: false,
            },
        );
    }

    /// The repository waits until the limit lifts, as far as the server's word is
    /// believable.
    pub(super) fn rate_limited(&self, repo: u64, reset: RateLimitReset, now: i64) {
        let until = match reset {
            RateLimitReset::At(at) => at.as_second(),
            RateLimitReset::After(seconds) => {
                now.saturating_add(i64::try_from(seconds).unwrap_or(RATE_LIMIT_MAX_SECS))
            }
            RateLimitReset::Unknown => {
                self.failed(repo, now);
                if let Some(backoff) = self.locked().get_mut(&repo) {
                    backoff.rate_limited = true;
                }
                return;
            }
        };
        let until = until.clamp(
            now.saturating_add(1),
            now.saturating_add(RATE_LIMIT_MAX_SECS),
        );
        let mut backoffs = self.locked();
        let failures = backoffs.get(&repo).map_or(0, |b| b.failures);
        backoffs.insert(
            repo,
            Backoff {
                until,
                failures,
                rate_limited: true,
            },
        );
    }
}
