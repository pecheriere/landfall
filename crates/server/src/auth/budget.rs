//! How much a credential may ask of the controller: a bound on the audit rows and the write
//! transactions one can cause, and on the queries, however it is used.
//!
//! Refusals to someone who proved who they are go in the audit log, so without this one
//! stolen token with no grant at all can write a row per request, each a `BEGIN IMMEDIATE`
//! that agents' writes wait behind. So each state change costs one from a bucket. A read
//! writes nothing, but each is a query, and the API can list a long history: so reads cost
//! one from a bucket of their own, far larger and quicker to refill, which state changes never
//! touch. A page polling for what waits, and an agent reading before it asks, can't run out of
//! state changes by reading, nor of reads by asking.
//!
//! Each [`Spender`] has its own bucket of each, so that a stolen credential can exhaust only
//! itself:
//!
//! - **A session,** by its token's hash. A stolen cookie can't stop its owner's other sessions,
//!   their sign-in, or their sign-out, which is never charged. A session takes a passkey to get,
//!   and a principal keeps a bounded number, so those bound what sessions can cost.
//! - **A principal's tokens,** all as one.
//! - **A principal's sign-ins:** paid only after a passkey signed, so nobody without one can
//!   spend it. It refills far more slowly than the rest, because each sign-in is a new session
//!   with whole new buckets: this is what bounds how many of those a key can have.
//!
//! So the tables are bounded by the configuration: only a principal it names gets this far, and
//! the entries of a session go when the session does. A session's call from elsewhere costs
//! nothing and isn't here at all: a state change with a bad `Origin`, or a read that
//! `Sec-Fetch-Site` says another site sent. It is refused first, and counted with failed
//! ceremonies, in [`crate::web`]. The limits are in [`Limits`](crate::agent_api::Limits), with
//! why they are what they are.
//!
//! Going over writes nothing. The count is kept here, reads' apart from state changes', and
//! whichever comes first writes it to the log: the next call of the same kind within the budget,
//! the flush each watcher interval, or stopping. So nothing is lost in silence, even if the
//! spender goes quiet or the call writing it is cut off, as it goes back unless it was written. A
//! principal's tokens' count names no token, as another of them may be the one to write it. It
//! lives in memory: a crash loses a count not yet written, and a restart gives every budget back.

use std::collections::HashMap;
use std::time::Duration;

use landfall_core::ids::PrincipalId;
use serde_json::json;
use tokio::sync::watch;

use crate::agent_api::{ApiState, Limits, RateLimiter};
use crate::audit::{AuditEvent, EventKind};
use crate::logger::log;

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

/// A principal's allowance of sign-ins, which refill in whole minutes rather than each second.
#[derive(Debug, Clone, Copy)]
struct SignIns {
    tokens: u32,
    /// When `tokens` last gained one, or was full.
    at: i64,
}

/// A count of calls refused for their budget, to write down.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Dropped {
    /// Whose.
    pub(crate) spender: Spender,
    /// Whether they were reads, rather than state changes.
    pub(crate) reads: bool,
    /// How many.
    pub(crate) count: u64,
}

/// Every budget.
#[derive(Debug)]
pub(crate) struct Budget {
    /// Sessions' and tokens' state changes.
    limiter: RateLimiter<Spender>,
    /// Sessions' and tokens' reads.
    reads: RateLimiter<Spender>,
    /// One for each principal who has signed in, so at most one each that the file names.
    sign_ins: HashMap<PrincipalId, SignIns>,
    sign_in_burst: u32,
    sign_in_refill_secs: i64,
    dropped: HashMap<Spender, u64>,
    dropped_reads: HashMap<Spender, u64>,
}

impl Budget {
    /// Budgets for at most `principals` principals: for each, its tokens and as many sessions as
    /// it may keep, for state changes and for reads, and its sign-ins apart.
    pub(crate) fn new(limits: &Limits, principals: usize) -> Self {
        let each = MAX_SESSIONS_PER_PRINCIPAL.saturating_add(1);
        let spenders = principals.saturating_mul(usize::try_from(each).unwrap_or(usize::MAX));
        Self {
            limiter: RateLimiter::new(
                limits.principal_rate_per_second,
                limits.principal_burst,
                spenders,
            ),
            reads: RateLimiter::new(limits.read_rate_per_second, limits.read_burst, spenders),
            sign_ins: HashMap::new(),
            sign_in_burst: limits.sign_in_burst,
            sign_in_refill_secs: i64::from(limits.sign_in_refill_secs).max(1),
            dropped: HashMap::new(),
            dropped_reads: HashMap::new(),
        }
    }

    /// Whether `principal` may sign in now, taking a token if so. Time that has earned no whole
    /// token yet isn't lost, and a clock stepped backwards gives nothing and takes nothing away.
    fn allow_sign_in(&mut self, principal: &PrincipalId, now: i64) -> bool {
        let burst = self.sign_in_burst;
        let refill = self.sign_in_refill_secs;
        let bucket = self.sign_ins.entry(principal.clone()).or_insert(SignIns {
            tokens: burst,
            at: now,
        });
        let earned = now.saturating_sub(bucket.at).max(0) / refill;
        bucket.tokens = bucket
            .tokens
            .saturating_add(u32::try_from(earned).unwrap_or(u32::MAX))
            .min(burst);
        bucket.at = if bucket.tokens == burst || now < bucket.at {
            now
        } else {
            bucket.at.saturating_add(earned.saturating_mul(refill))
        };
        match bucket.tokens.checked_sub(1) {
            Some(left) => {
                bucket.tokens = left;
                true
            }
            None => false,
        }
    }

    /// How long until `principal`'s next sign-in comes, in seconds, for one just refused: at least
    /// one, and at most a whole refill.
    pub(crate) fn sign_in_wait(&self, principal: &PrincipalId, now: i64) -> u32 {
        let refill = self.sign_in_refill_secs;
        let wait = self.sign_ins.get(principal).map_or(refill, |bucket| {
            bucket.at.saturating_add(refill).saturating_sub(now)
        });
        u32::try_from(wait.clamp(1, refill)).unwrap_or(u32::MAX)
    }

    /// Takes the cost of one state change or sign-in, at `now`.
    pub(crate) fn spend(&mut self, spender: &Spender, now: i64) -> Spent {
        let allowed = match spender {
            Spender::SignIns(principal) => self.allow_sign_in(principal, now),
            other => self.limiter.allow_key(other.clone(), now),
        };
        counted(&mut self.dropped, spender, allowed)
    }

    /// Takes the cost of one read, at `now`, from the spender's bucket for reads. A session's or
    /// tokens' only: a sign-in is no read.
    pub(crate) fn spend_read(&mut self, spender: &Spender, now: i64) -> Spent {
        let allowed = self.reads.allow_key(spender.clone(), now);
        counted(&mut self.dropped_reads, spender, allowed)
    }

    /// Lets go of the budgets of sessions that ended. A count not yet written stays, for the next
    /// flush.
    pub(crate) fn forget_sessions(&mut self, ended: &[[u8; 32]]) {
        if ended.is_empty() {
            return;
        }
        let gone = |spender: &Spender| matches!(spender, Spender::Session { hash, .. } if ended.contains(hash));
        self.limiter.forget_where(gone);
        self.reads.forget_where(gone);
    }

    /// How many sessions have a budget, for a test: of state changes, and of reads.
    #[cfg(test)]
    pub(crate) fn session_budgets(&self) -> (usize, usize) {
        let session = |spender: &Spender| matches!(spender, Spender::Session { .. });
        (
            self.limiter.count_where(session),
            self.reads.count_where(session),
        )
    }

    /// Puts back a count that couldn't be written down.
    pub(crate) fn keep_dropped(&mut self, dropped: Dropped) {
        let counts = if dropped.reads {
            &mut self.dropped_reads
        } else {
            &mut self.dropped
        };
        let count = counts.entry(dropped.spender).or_insert(0);
        *count = count.saturating_add(dropped.count);
    }

    /// Takes every count there is, to write down.
    pub(crate) fn take_dropped(&mut self) -> Vec<Dropped> {
        let changes = self.dropped.drain().map(|(spender, count)| Dropped {
            spender,
            reads: false,
            count,
        });
        let reads = self.dropped_reads.drain().map(|(spender, count)| Dropped {
            spender,
            reads: true,
            count,
        });
        changes.chain(reads).collect()
    }
}

/// What came of a call in `counts`: a call within the budget takes the spender's count, to write
/// down, and one over it adds to the count.
fn counted(counts: &mut HashMap<Spender, u64>, spender: &Spender, allowed: bool) -> Spent {
    if allowed {
        Spent::Within {
            dropped: counts.remove(spender).unwrap_or(0),
        }
    } else {
        let dropped = counts.entry(spender.clone()).or_insert(0);
        *dropped = dropped.saturating_add(1);
        Spent::Over
    }
}

/// The audit row of a count: of reads if `reads`, and of state changes or sign-ins otherwise.
pub(crate) fn throttled_event(spender: &Spender, dropped: u64, reads: bool) -> AuditEvent {
    let mut detail = json!({
        "by": { "principal": spender.principal(), "via": spender.via() },
        "dropped": dropped,
    });
    if reads {
        detail["reads"] = json!(true);
    }
    AuditEvent {
        kind: EventKind::AccessThrottled,
        deployment: None,
        host: None,
        detail,
    }
}

/// Writes down every count, and keeps any it can't for next time.
pub(crate) async fn flush_dropped(state: &ApiState) {
    for dropped in state.take_dropped() {
        let event = throttled_event(&dropped.spender, dropped.count, dropped.reads);
        if let Err(error) = state.store().record(&event).await {
            log(&format!("API: writing down dropped calls: {error}"));
            state.keep_dropped(dropped);
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
    use super::{Budget, Dropped, Spender, Spent, throttled_event};
    use crate::agent_api::Limits;
    use landfall_core::ids::PrincipalId;

    /// Budgets where sessions, tokens and sign-ins all have this burst.
    fn budget_of(rate_per_second: u32, burst: u32, principals: usize) -> Budget {
        let limits = Limits {
            principal_rate_per_second: rate_per_second,
            principal_burst: burst,
            sign_in_burst: burst,
            ..Limits::default()
        };
        Budget::new(&limits, principals)
    }

    #[test]
    fn sign_ins_have_a_burst_of_ten_and_one_more_each_five_minutes() {
        let limits = Limits::default();
        assert_eq!(
            (limits.sign_in_burst, limits.sign_in_refill_secs),
            (10, 300)
        );
        let mut budget = Budget::new(&limits, 1);
        let alice = Spender::SignIns(id("alice"));
        for _ in 0..10 {
            assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 0 });
        }
        assert_eq!(budget.spend(&alice, 100), Spent::Over);
        // A refused one pushes the next no further away.
        assert_eq!(budget.spend(&alice, 399), Spent::Over);
        assert_eq!(budget.spend(&alice, 400), Spent::Within { dropped: 2 });
        assert_eq!(budget.spend(&alice, 400), Spent::Over);
        // Time short of a token isn't lost: 450 seconds is one, and 150 towards the next.
        assert_eq!(budget.spend(&alice, 850), Spent::Within { dropped: 1 });
        assert_eq!(budget.spend(&alice, 850), Spent::Over);
        assert_eq!(budget.spend(&alice, 1000), Spent::Within { dropped: 1 });
        // Never more than the burst, however long it has been.
        for _ in 0..10 {
            assert_eq!(
                budget.spend(&alice, 1_000_000),
                Spent::Within { dropped: 0 }
            );
        }
        assert_eq!(budget.spend(&alice, 1_000_000), Spent::Over);
        // A clock stepped backwards gives nothing, and the next token comes a refill from there.
        assert_eq!(budget.spend(&alice, 500), Spent::Over);
        assert_eq!(budget.spend(&alice, 799), Spent::Over);
        assert_eq!(budget.spend(&alice, 800), Spent::Within { dropped: 3 });
    }

    #[test]
    fn a_full_allowance_of_sign_ins_banks_no_time() {
        let mut budget = Budget::new(&Limits::default(), 1);
        let alice = Spender::SignIns(id("alice"));
        budget.spend(&alice, 0);
        // Back to full long ago, and then ten in a moment.
        for _ in 0..10 {
            assert_eq!(budget.spend(&alice, 100_000), Spent::Within { dropped: 0 });
        }
        assert_eq!(budget.spend(&alice, 100_000), Spent::Over);
        assert_eq!(budget.spend(&alice, 100_299), Spent::Over);
    }

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
        let mut budget = budget_of(1, 2, 4);
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
        let mut budget = budget_of(1, 1, 4);
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
    fn reads_and_state_changes_spend_and_count_apart() {
        let limits = Limits {
            principal_burst: 1,
            read_burst: 2,
            ..Limits::default()
        };
        let mut budget = Budget::new(&limits, 4);
        let alice = tokens("alice");
        assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, 100), Spent::Over);
        // State changes spent, reads whole.
        assert_eq!(budget.spend_read(&alice, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend_read(&alice, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend_read(&alice, 100), Spent::Over);
        assert_eq!(budget.spend_read(&alice, 100), Spent::Over);
        let mut counts = budget.take_dropped();
        counts.sort_by_key(|dropped| dropped.reads);
        assert_eq!(
            counts,
            vec![
                Dropped {
                    spender: alice.clone(),
                    reads: false,
                    count: 1
                },
                Dropped {
                    spender: alice.clone(),
                    reads: true,
                    count: 2
                },
            ]
        );
        // Each kind's count goes back to its own.
        for dropped in counts {
            budget.keep_dropped(dropped);
        }
        assert_eq!(budget.spend_read(&alice, 101), Spent::Within { dropped: 2 });
        assert_eq!(budget.spend(&alice, 101), Spent::Within { dropped: 1 });
    }

    #[test]
    fn only_a_count_of_reads_says_reads() {
        let alice = tokens("alice");
        assert_eq!(throttled_event(&alice, 3, true).detail["reads"], true);
        let changes = throttled_event(&alice, 3, false).detail;
        assert_eq!(changes.get("reads"), None, "{changes}");
    }

    #[test]
    fn a_count_put_back_comes_round_again() {
        let mut budget = budget_of(1, 1, 4);
        let alice = tokens("alice");
        budget.keep_dropped(Dropped {
            spender: alice.clone(),
            reads: false,
            count: 5,
        });
        assert_eq!(budget.spend(&alice, 100), Spent::Within { dropped: 5 });
    }

    #[test]
    fn a_session_that_ended_leaves_its_count_and_no_entry() {
        let mut budget = budget_of(1, 1, 4);
        let (gone, kept) = (session(1, "alice"), session(2, "alice"));
        budget.spend(&gone, 100);
        budget.spend(&gone, 100);
        budget.spend(&kept, 100);
        budget.spend_read(&gone, 100);
        assert_eq!(budget.session_budgets(), (2, 1));
        budget.forget_sessions(&[[1; 32]]);
        assert_eq!(budget.session_budgets(), (1, 0));
        // Its bucket is new, and its count goes to whoever writes it.
        let count = Dropped {
            spender: gone.clone(),
            reads: false,
            count: 1,
        };
        assert_eq!(budget.take_dropped(), vec![count]);
        assert_eq!(budget.spend(&gone, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&kept, 100), Spent::Over);
    }

    #[test]
    fn as_many_sessions_as_a_principal_may_keep_all_have_a_budget() {
        let mut budget = budget_of(1, 2, 1);
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
