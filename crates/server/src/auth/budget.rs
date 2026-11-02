//! How many state changes a credential may ask for: a bound on the audit rows and the write
//! transactions one can cause, however it is used.
//!
//! Refusals to someone who proved who they are go in the audit log, so without this one
//! stolen token with no grant at all can write a row per request, each a `BEGIN IMMEDIATE`
//! that agents' writes wait behind. Only what isn't safe costs anything: a read writes
//! nothing, and a page polling for what waits must never run out.
//!
//! Each [`Spender`] has its own bucket, so that a stolen credential can exhaust only itself:
//!
//! - **A session,** by its token's hash. A stolen cookie can't stop its owner's other sessions,
//!   their sign-in, or their sign-out, which is never charged. A session takes a passkey to get,
//!   and a principal keeps a bounded number, so those bound what sessions can cost.
//! - **A principal's tokens,** all as one.
//! - **A principal's sign-ins:** paid only after a passkey signed, so nobody without one can
//!   spend it. It bounds the `signed_in` rows a key can write.
//!
//! So the table is bounded by the configuration: only a principal it names gets this far, and the
//! entry of a session goes when the session does. A bad `Origin` costs nothing and isn't here at
//! all: it is refused first, and counted with failed ceremonies, in [`crate::web`]. The limits are
//! in [`Limits`](crate::agent_api::Limits), with why they are what they are.
//!
//! Going over writes nothing. The count is kept here, and whichever comes first writes it to
//! the log: the next call within the budget, the flush each watcher interval, or stopping.
//! So nothing is lost in silence, even if the spender goes quiet. A principal's tokens' count
//! names no token, as another of them may be the one to write it. It lives in memory: a crash
//! loses a count not yet written, and a restart gives every budget back.

use std::collections::HashMap;
use std::time::Duration;

use landfall_core::ids::PrincipalId;
use serde_json::json;
use tokio::sync::watch;

use crate::agent_api::{ApiState, RateLimiter, log};
use crate::audit::{AuditEvent, EventKind};

/// How many sessions one principal keeps. Signing in anew past this ends the oldest, so a
/// passkey signing in over and over can't grow the table of sessions, or this one.
pub(crate) const MAX_SESSIONS_PER_PRINCIPAL: i64 = 16;

/// Whose budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) enum Spender {
    /// One session, by its token's hash.
    Session {
        /// The hash.
        hash: [u8; 32],
        /// Whose it is, for the count's audit row.
        principal: PrincipalId,
    },
    /// All of a principal's tokens.
    Tokens(PrincipalId),
    /// A principal's sign-ins, each with a verified assertion.
    SignIns(PrincipalId),
}

impl Spender {
    fn principal(&self) -> &PrincipalId {
        match self {
            Self::Session { principal, .. }
            | Self::Tokens(principal)
            | Self::SignIns(principal) => principal,
        }
    }

    fn via(&self) -> &'static str {
        match self {
            Self::Session { .. } => "session",
            Self::Tokens(_) => "token",
            Self::SignIns(_) => "sign_in",
        }
    }
}

/// What a call's cost came to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Spent {
    /// Over budget: refuse it, and write nothing.
    Over,
    /// Within it, and this many calls were refused since the last one that was.
    Within {
        /// The count now taken from the table, for the caller to write down.
        dropped: u64,
    },
}

/// Every budget.
#[derive(Debug)]
pub(crate) struct Budget {
    limiter: RateLimiter<Spender>,
    dropped: HashMap<Spender, u64>,
}

impl Budget {
    /// Budgets for at most `principals` principals: for each, its tokens, its sign-ins and as
    /// many sessions as it may keep.
    pub(crate) fn new(rate_per_second: u32, burst: u32, principals: usize) -> Self {
        let each = MAX_SESSIONS_PER_PRINCIPAL.saturating_add(2);
        Self {
            limiter: RateLimiter::new(
                rate_per_second,
                burst,
                principals.saturating_mul(usize::try_from(each).unwrap_or(usize::MAX)),
            ),
            dropped: HashMap::new(),
        }
    }

    /// Takes the cost of one call, at `now`.
    pub(crate) fn spend(&mut self, spender: &Spender, now: i64) -> Spent {
        if self.limiter.allow_key(spender.clone(), now) {
            Spent::Within {
                dropped: self.dropped.remove(spender).unwrap_or(0),
            }
        } else {
            let dropped = self.dropped.entry(spender.clone()).or_insert(0);
            *dropped = dropped.saturating_add(1);
            Spent::Over
        }
    }

    /// Lets go of the budgets of sessions that ended. A count not yet written stays, for the next
    /// flush.
    pub(crate) fn forget_sessions(&mut self, ended: &[[u8; 32]]) {
        if ended.is_empty() {
            return;
        }
        self.limiter.forget_where(
            |spender| matches!(spender, Spender::Session { hash, .. } if ended.contains(hash)),
        );
    }

    /// Puts back a count that couldn't be written down.
    pub(crate) fn keep_dropped(&mut self, spender: Spender, count: u64) {
        let dropped = self.dropped.entry(spender).or_insert(0);
        *dropped = dropped.saturating_add(count);
    }

    /// Takes every count there is, to write down.
    pub(crate) fn take_dropped(&mut self) -> Vec<(Spender, u64)> {
        self.dropped.drain().collect()
    }
}

/// The audit row of a count.
pub(crate) fn throttled_event(spender: &Spender, dropped: u64) -> AuditEvent {
    AuditEvent {
        kind: EventKind::AccessThrottled,
        deployment: None,
        host: None,
        detail: json!({
            "by": { "principal": spender.principal(), "via": spender.via() },
            "dropped": dropped,
        }),
    }
}

/// Writes down every count, and keeps any it can't for next time.
pub(crate) async fn flush_dropped(state: &ApiState) {
    for (spender, dropped) in state.take_dropped() {
        let event = throttled_event(&spender, dropped);
        if let Err(error) = state.store().record(&event).await {
            log(&format!("API: writing down dropped calls: {error}"));
            state.keep_dropped(spender, dropped);
        }
    }
}

/// Writes down every count each `every`, and once more when `stop` says so.
pub(crate) async fn keep_flushing(
    state: ApiState,
    every: Duration,
    mut stop: watch::Receiver<bool>,
) {
    loop {
        tokio::select! {
            () = tokio::time::sleep(every) => {
                flush_dropped(&state).await;
                crate::web::tend(&state).await;
            }
            () = until_stopped(&mut stop) => {
                flush_dropped(&state).await;
                crate::web::tend(&state).await;
                return;
            }
        }
    }
}

/// Ends when `stop` says so, or when nobody is left to say it.
async fn until_stopped(stop: &mut watch::Receiver<bool>) {
    drop(stop.wait_for(|stop| *stop).await);
}

#[cfg(test)]
mod tests {
    use super::{Budget, Spender, Spent};
    use landfall_core::ids::PrincipalId;

    fn id(name: &str) -> PrincipalId {
        name.parse().unwrap()
    }

    fn tokens(name: &str) -> Spender {
        Spender::Tokens(id(name))
    }

    fn session(hash: u8, name: &str) -> Spender {
        Spender::Session {
            hash: [hash; 32],
            principal: id(name),
        }
    }

    #[test]
    fn it_counts_what_it_refuses_and_hands_the_count_over_once() {
        let mut budget = Budget::new(1, 2, 4);
        let alice = tokens("alice");
        assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, 100), Spent::Over);
        assert_eq!(budget.spend(&alice, 100), Spent::Over);
        assert_eq!(budget.spend(&alice, 101), Spent::Within { dropped: 2 });
        assert_eq!(budget.spend(&alice, 102), Spent::Within { dropped: 0 });
    }

    #[test]
    fn sessions_tokens_and_sign_ins_spend_apart() {
        let mut budget = Budget::new(1, 1, 4);
        let spenders = [
            tokens("alice"),
            session(1, "alice"),
            session(2, "alice"),
            Spender::SignIns(id("alice")),
        ];
        for spender in &spenders {
            assert_eq!(budget.spend(spender, 100), Spent::Within { dropped: 0 });
            assert_eq!(budget.spend(spender, 100), Spent::Over);
        }
    }

    #[test]
    fn a_count_put_back_comes_round_again() {
        let mut budget = Budget::new(1, 1, 4);
        let alice = tokens("alice");
        budget.keep_dropped(alice.clone(), 5);
        assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 5 });
    }

    #[test]
    fn a_session_that_ended_leaves_its_count_and_no_entry() {
        let mut budget = Budget::new(1, 1, 4);
        let (gone, kept) = (session(1, "alice"), session(2, "alice"));
        budget.spend(&gone, 100);
        budget.spend(&gone, 100);
        budget.spend(&kept, 100);
        budget.forget_sessions(&[[1; 32]]);
        // Its bucket is new, and its count goes to whoever writes it.
        assert_eq!(budget.take_dropped(), vec![(gone.clone(), 1)]);
        assert_eq!(budget.spend(&gone, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&kept, 100), Spent::Over);
    }

    #[test]
    fn as_many_sessions_as_a_principal_may_keep_all_have_a_budget() {
        let mut budget = Budget::new(1, 2, 1);
        for hash in 0..16 {
            assert_eq!(
                budget.spend(&session(hash, "alice"), 100),
                Spent::Within { dropped: 0 },
                "{hash}"
            );
        }
        for spender in [tokens("alice"), Spender::SignIns(id("alice"))] {
            assert_eq!(budget.spend(&spender, 100), Spent::Within { dropped: 0 });
        }
    }
}
