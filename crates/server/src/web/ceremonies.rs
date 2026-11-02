//! Challenges under way and failures not yet written down, all in memory.
//!
//! A challenge lives five minutes and a restart costs a person one more tap, so nothing here
//! needs the database, and a flood of `begin` costs it nothing.
//!
//! **Sign-in** challenges can be asked for by anyone. They are random, kept only as a SHA-256 and
//! found by that, with a queue in order of expiry beside them, which is what the hard limit
//! counts. A full table refuses the new one rather than dropping an old one, so nobody can push
//! out someone else's challenge, and refusing looks only at the head of the queue. Taking one
//! removes it, so it works once, whether what came with it verifies or not. Its place in the queue
//! stays until its time is up, which keeps the queue bounded however fast they come and go.
//!
//! **Registration** challenges take a good invite's code, and there is one for each invite: a
//! new `begin` replaces only that invite's own. So that table is as small as the invites are few,
//! and one invite's challenge can't finish another's.
//!
//! The two are apart, so a challenge can't cross from one ceremony to the other.
//!
//! **Failures** are counted by principal, kind and reason, so that one reason can't overwrite
//! another: most of all, a signature that verified by a key that may not sign in, which says
//! someone holds a registered key, stays apart from any number of bad signatures sent after it.

use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;

use landfall_core::ids::PrincipalId;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::agent_api::{Limits, RateLimiter, source_key};
use crate::audit::{AuditEvent, EventKind};

/// How long a challenge may wait for its answer, in seconds: five minutes.
pub(super) const CHALLENGE_LIFETIME_SECS: i64 = 5 * 60;

/// How many different sources one count names. It says how many more there were.
const MAX_SOURCES_NAMED: usize = 8;

/// What failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum FailureKind {
    /// A registration with a good code.
    Registration,
    /// A sign-in naming a principal's credential, whose signature didn't verify.
    SignIn,
    /// A sign-in whose signature did verify, by a key that may not sign in.
    SignInBarred,
    /// A session's state change from another origin.
    BadOrigin,
}

/// So many failures against one principal for one reason, not yet in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    principal: PrincipalId,
    kind: FailureKind,
    /// The controller's own text.
    reason: &'static str,
    attempts: u64,
    first_seen: i64,
    /// Who from, as far as [`MAX_SOURCES_NAMED`].
    sources: BTreeSet<IpAddr>,
    /// How many attempts came from a source there was no room to name. A count put back after it
    /// couldn't be written has lost how many came from each of its sources, so what doesn't fit
    /// then counts as one each: this can be low in that case, never high.
    from_others: u64,
}

impl Failure {
    /// Its audit row. Nothing a sender wrote is in it.
    pub(crate) fn event(&self) -> AuditEvent {
        let mut detail = json!({
            "principal": self.principal,
            "attempts": self.attempts,
            "reason": self.reason,
            "first_seen": self.first_seen,
            "sources": self.sources,
            "from_others": self.from_others,
        });
        if self.kind == FailureKind::BadOrigin {
            detail["by"] = json!({ "principal": self.principal, "via": "session" });
        }
        AuditEvent {
            kind: match self.kind {
                FailureKind::Registration => EventKind::RegistrationRefused,
                FailureKind::SignIn => EventKind::SignInRefused,
                FailureKind::SignInBarred => EventKind::SignInBarredKey,
                FailureKind::BadOrigin => EventKind::AccessRefused,
            },
            deployment: None,
            host: None,
            detail,
        }
    }

    /// Takes in another count of the same thing.
    fn absorb(&mut self, other: Self) {
        self.attempts = self.attempts.saturating_add(other.attempts);
        self.first_seen = self.first_seen.min(other.first_seen);
        self.from_others = self.from_others.saturating_add(other.from_others);
        for source in other.sources {
            if self.sources.contains(&source) {
                continue;
            }
            if self.sources.len() < MAX_SOURCES_NAMED {
                self.sources.insert(source);
            } else {
                self.from_others = self.from_others.saturating_add(1);
            }
        }
    }
}

/// A registration waiting for its answer.
#[derive(Debug)]
struct Registering {
    challenge: [u8; 32],
    expires_at: i64,
}

/// There is no room for another sign-in challenge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct Full;

/// All of it.
#[derive(Debug)]
pub(crate) struct Ceremonies {
    limiter: RateLimiter,
    /// When each challenge's time is up, by the SHA-256 of the challenge.
    sign_ins: HashMap<[u8; 32], i64>,
    /// Every challenge not yet past its time, used or not, oldest first.
    sign_in_queue: VecDeque<(i64, [u8; 32])>,
    max_sign_ins: usize,
    /// By the SHA-256 of the invite's code.
    registrations: HashMap<[u8; 32], Registering>,
    /// A principal only gets here by the configuration, an invite or a session, and the reasons
    /// are this program's own: nobody else's failures are counted.
    failures: HashMap<(PrincipalId, FailureKind, &'static str), Failure>,
}

impl Ceremonies {
    pub(crate) fn new(limits: &Limits) -> Self {
        Self {
            limiter: RateLimiter::new(
                limits.ceremony_rate_per_second,
                limits.ceremony_burst,
                limits.max_sources,
            ),
            sign_ins: HashMap::new(),
            sign_in_queue: VecDeque::new(),
            max_sign_ins: limits.max_sign_in_challenges,
            registrations: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    /// Whether `source` may make a request now, taking a token if it may.
    pub(super) fn allow(&mut self, source: IpAddr, now: i64) -> bool {
        self.limiter.allow_key(source_key(source), now)
    }

    /// Lets go of sign-in challenges past their time. Each is looked at once more than it is
    /// let go of, so this and a refusal cost the same however full the table is.
    fn reclaim_sign_ins(&mut self, now: i64) {
        while let Some((expires_at, hash)) = self.sign_in_queue.front().copied() {
            if expires_at > now {
                break;
            }
            self.sign_in_queue.pop_front();
            self.sign_ins.remove(&hash);
        }
    }

    /// Remembers a sign-in challenge.
    pub(super) fn open_sign_in(&mut self, challenge: &[u8], now: i64) -> Result<(), Full> {
        self.reclaim_sign_ins(now);
        if self.sign_in_queue.len() >= self.max_sign_ins {
            return Err(Full);
        }
        let hash: [u8; 32] = Sha256::digest(challenge).into();
        let expires_at = now.saturating_add(CHALLENGE_LIFETIME_SECS);
        self.sign_ins.insert(hash, expires_at);
        self.sign_in_queue.push_back((expires_at, hash));
        Ok(())
    }

    /// Whether this was an outstanding sign-in challenge. It isn't one any more.
    pub(super) fn take_sign_in(&mut self, challenge: &[u8], now: i64) -> bool {
        let hash: [u8; 32] = Sha256::digest(challenge).into();
        self.sign_ins
            .remove(&hash)
            .is_some_and(|expires_at| expires_at > now)
    }

    /// Remembers a registration's challenge, in place of any that invite had.
    pub(super) fn open_registration(&mut self, invite: [u8; 32], challenge: [u8; 32], now: i64) {
        self.registrations.insert(
            invite,
            Registering {
                challenge,
                expires_at: now.saturating_add(CHALLENGE_LIFETIME_SECS),
            },
        );
    }

    /// Whether this invite has a challenge in time, leaving it there.
    pub(super) fn has_registration(&self, invite: &[u8; 32], now: i64) -> bool {
        self.registrations
            .get(invite)
            .is_some_and(|registering| registering.expires_at > now)
    }

    /// This invite's challenge, if it has one in time. It doesn't have it any more.
    pub(super) fn take_registration(&mut self, invite: &[u8; 32], now: i64) -> Option<[u8; 32]> {
        self.registrations
            .remove(invite)
            .filter(|registering| registering.expires_at > now)
            .map(|registering| registering.challenge)
    }

    /// Counts a failure against `principal`.
    pub(crate) fn count_failure(
        &mut self,
        principal: &PrincipalId,
        kind: FailureKind,
        reason: &'static str,
        source: IpAddr,
        now: i64,
    ) {
        self.keep_failure(Failure {
            principal: principal.clone(),
            kind,
            reason,
            attempts: 1,
            first_seen: now,
            sources: BTreeSet::from([source]),
            from_others: 0,
        });
    }

    /// Adds to the count, as one that couldn't be written down yet.
    pub(crate) fn keep_failure(&mut self, failure: Failure) {
        let key = (failure.principal.clone(), failure.kind, failure.reason);
        match self.failures.get_mut(&key) {
            Some(counted) => counted.absorb(failure),
            None => {
                self.failures.insert(key, failure);
            }
        }
    }

    /// Takes every count there is, to write down.
    pub(crate) fn take_failures(&mut self) -> Vec<Failure> {
        self.failures.drain().map(|(_, failure)| failure).collect()
    }

    /// Lets go of what's past its time.
    pub(crate) fn forget_expired(&mut self, now: i64) {
        self.reclaim_sign_ins(now);
        self.registrations
            .retain(|_, registering| registering.expires_at > now);
    }

    /// How many sign-in places and registration challenges are held, for a test.
    #[cfg(test)]
    pub(crate) fn held(&self) -> (usize, usize) {
        (self.sign_in_queue.len(), self.registrations.len())
    }
}
