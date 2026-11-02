//! Challenges under way and failures not yet written down, all in memory.
//!
//! A challenge lives five minutes and a restart costs a person one more tap, so nothing here
//! needs the database, and a flood of `begin` costs it nothing.
//!
//! **Sign-in** challenges can be asked for by anyone. They are random, kept only as a SHA-256 and
//! found by that, in a table with a hard limit, and a full table refuses the new one rather than
//! dropping an old one: nobody can push out someone else's challenge. Taking one removes it, so
//! it works once, whether what came with it verifies or not.
//!
//! **Registration** challenges take a good invite's code, and there is one for each invite: a
//! new `begin` replaces only that invite's own. So that table is as small as the invites are few,
//! and one invite's challenge can't finish another's.
//!
//! The two are apart, so a challenge can't cross from one ceremony to the other.

use std::collections::HashMap;
use std::net::IpAddr;

use landfall_core::ids::PrincipalId;
use serde_json::json;
use sha2::{Digest as _, Sha256};

use crate::agent_api::{Limits, RateLimiter, source_key};
use crate::audit::{AuditEvent, EventKind};

/// How long a challenge may wait for its answer, in seconds: five minutes.
pub(super) const CHALLENGE_LIFETIME_SECS: i64 = 5 * 60;

/// Which ceremony failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum Ceremony {
    Registration,
    SignIn,
}

/// So many failures against one principal, not yet in the log.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Failure {
    principal: PrincipalId,
    ceremony: Ceremony,
    attempts: u64,
    /// The controller's own text, for the last of them.
    reason: &'static str,
}

impl Failure {
    /// Its audit row. Nothing a sender wrote is in it.
    pub(crate) fn event(&self) -> AuditEvent {
        AuditEvent {
            kind: match self.ceremony {
                Ceremony::Registration => EventKind::RegistrationRefused,
                Ceremony::SignIn => EventKind::SignInRefused,
            },
            deployment: None,
            host: None,
            detail: json!({
                "principal": self.principal,
                "attempts": self.attempts,
                "reason": self.reason,
            }),
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
    max_sign_ins: usize,
    /// By the SHA-256 of the invite's code.
    registrations: HashMap<[u8; 32], Registering>,
    /// One for each principal and ceremony, and a principal only gets here by the configuration
    /// or an invite: nobody else's failures are counted.
    failures: HashMap<(PrincipalId, Ceremony), Failure>,
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
            max_sign_ins: limits.max_sign_in_challenges,
            registrations: HashMap::new(),
            failures: HashMap::new(),
        }
    }

    /// Whether `source` may make a request now, taking a token if it may.
    pub(super) fn allow(&mut self, source: IpAddr, now: i64) -> bool {
        self.limiter.allow_key(source_key(source), now)
    }

    /// Remembers a sign-in challenge. It looks for room only when it needs some, as that walks
    /// the table.
    pub(super) fn open_sign_in(&mut self, challenge: &[u8], now: i64) -> Result<(), Full> {
        if self.sign_ins.len() >= self.max_sign_ins {
            self.sign_ins.retain(|_, expires_at| *expires_at > now);
            if self.sign_ins.len() >= self.max_sign_ins {
                return Err(Full);
            }
        }
        self.sign_ins.insert(
            Sha256::digest(challenge).into(),
            now.saturating_add(CHALLENGE_LIFETIME_SECS),
        );
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

    /// This invite's challenge, if it has one in time. It doesn't have it any more.
    pub(super) fn take_registration(&mut self, invite: &[u8; 32], now: i64) -> Option<[u8; 32]> {
        self.registrations
            .remove(invite)
            .filter(|registering| registering.expires_at > now)
            .map(|registering| registering.challenge)
    }

    /// Counts a failure against `principal`.
    pub(super) fn count_failure(
        &mut self,
        principal: &PrincipalId,
        ceremony: Ceremony,
        reason: &'static str,
    ) {
        self.keep_failure(Failure {
            principal: principal.clone(),
            ceremony,
            attempts: 1,
            reason,
        });
    }

    /// Adds to the count, as one that couldn't be written down yet.
    pub(crate) fn keep_failure(&mut self, failure: Failure) {
        let key = (failure.principal.clone(), failure.ceremony);
        self.failures
            .entry(key)
            .and_modify(|counted| {
                counted.attempts = counted.attempts.saturating_add(failure.attempts);
                counted.reason = failure.reason;
            })
            .or_insert(failure);
    }

    /// Takes every count there is, to write down.
    pub(crate) fn take_failures(&mut self) -> Vec<Failure> {
        self.failures.drain().map(|(_, failure)| failure).collect()
    }

    /// Lets go of what's past its time.
    pub(crate) fn forget_expired(&mut self, now: i64) {
        self.sign_ins.retain(|_, expires_at| *expires_at > now);
        self.registrations
            .retain(|_, registering| registering.expires_at > now);
    }
}
