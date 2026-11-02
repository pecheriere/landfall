//! How long each repository waits after a failure or a rate limit.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use landfall_origin::fetch::RateLimitReset;

use super::REPO_DEADLINE;

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
}

/// What the watcher keeps between ticks: how long each repository waits, by its
/// numeric id. In memory only: after a restart a repository is simply asked again.
#[derive(Debug)]
pub struct WatcherState {
    backoffs: Mutex<HashMap<u64, Backoff>>,
    /// Whose turn it is to go first in each repository, as a count of looks.
    turns: Mutex<HashMap<u64, usize>>,
    pub(super) repo_deadline: Duration,
}

impl Default for WatcherState {
    fn default() -> Self {
        Self::with_deadline(REPO_DEADLINE)
    }
}

impl WatcherState {
    pub(super) fn with_deadline(repo_deadline: Duration) -> Self {
        Self {
            backoffs: Mutex::default(),
            turns: Mutex::default(),
            repo_deadline,
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

    pub(super) fn succeeded(&self, repo: u64) {
        self.locked().remove(&repo);
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
            RateLimitReset::Unknown => return self.failed(repo, now),
        };
        let until = until.clamp(
            now.saturating_add(1),
            now.saturating_add(RATE_LIMIT_MAX_SECS),
        );
        let mut backoffs = self.locked();
        let failures = backoffs.get(&repo).map_or(0, |b| b.failures);
        backoffs.insert(repo, Backoff { until, failures });
    }
}
