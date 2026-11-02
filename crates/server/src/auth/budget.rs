//! How many state changes a principal may ask for: a bound on the audit rows and the
//! write transactions one credential can cause, however it is used.
//!
//! Refusals to someone who proved who they are go in the audit log, so without this one
//! stolen token with no grant at all can write a row per request, each a `BEGIN IMMEDIATE`
//! that agents' writes wait behind. Only what isn't safe costs anything: a read writes
//! nothing, and a page polling for what waits must never run out.
//!
//! A person's session and a principal's tokens have a budget each, so that a stolen token
//! can't keep the person from approving. There are two buckets for each principal the
//! configuration names, and credentials of anyone else never get this far, so the table is
//! bounded by the configuration. The limits are in
//! [`Limits`](crate::agent_api::Limits), with why they are what they are.
//!
//! Going over writes nothing. The count is kept here, and the next call within the budget
//! writes it to the log first, so that nothing is lost in silence. It lives in memory: a
//! restart loses a count not yet written, and gives every budget back.

use std::collections::HashMap;

use landfall_core::ids::PrincipalId;

use crate::agent_api::RateLimiter;

/// Whose budget.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct Spender {
    principal: PrincipalId,
    human: bool,
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

/// Every principal's budget.
#[derive(Debug)]
pub(crate) struct Budget {
    limiter: RateLimiter<Spender>,
    dropped: HashMap<Spender, u64>,
}

impl Budget {
    /// Budgets for at most `principals` principals.
    pub(crate) fn new(rate_per_second: u32, burst: u32, principals: usize) -> Self {
        Self {
            limiter: RateLimiter::new(rate_per_second, burst, principals.saturating_mul(2)),
            dropped: HashMap::new(),
        }
    }

    /// Takes the cost of one call, at `now`.
    pub(crate) fn spend(&mut self, principal: &PrincipalId, human: bool, now: i64) -> Spent {
        let spender = Spender {
            principal: principal.clone(),
            human,
        };
        if self.limiter.allow_key(spender.clone(), now) {
            Spent::Within {
                dropped: self.dropped.remove(&spender).unwrap_or(0),
            }
        } else {
            let dropped = self.dropped.entry(spender).or_insert(0);
            *dropped = dropped.saturating_add(1);
            Spent::Over
        }
    }

    /// Puts back a count that couldn't be written down.
    pub(crate) fn keep_dropped(&mut self, principal: &PrincipalId, human: bool, count: u64) {
        let spender = Spender {
            principal: principal.clone(),
            human,
        };
        let dropped = self.dropped.entry(spender).or_insert(0);
        *dropped = dropped.saturating_add(count);
    }
}

#[cfg(test)]
mod tests {
    use super::{Budget, Spent};
    use landfall_core::ids::PrincipalId;

    fn id(name: &str) -> PrincipalId {
        name.parse().unwrap()
    }

    #[test]
    fn it_counts_what_it_refuses_and_hands_the_count_over_once() {
        let mut budget = Budget::new(1, 2, 4);
        let alice = id("alice");
        assert_eq!(budget.spend(&alice, false, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, false, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, false, 100), Spent::Over);
        assert_eq!(budget.spend(&alice, false, 100), Spent::Over);
        assert_eq!(budget.spend(&alice, false, 101), Spent::Within { dropped: 2 });
        assert_eq!(budget.spend(&alice, false, 102), Spent::Within { dropped: 0 });
    }

    #[test]
    fn a_session_and_a_token_of_one_principal_spend_apart() {
        let mut budget = Budget::new(1, 1, 4);
        let alice = id("alice");
        assert_eq!(budget.spend(&alice, false, 100), Spent::Within { dropped: 0 });
        assert_eq!(budget.spend(&alice, false, 100), Spent::Over);
        assert_eq!(budget.spend(&alice, true, 100), Spent::Within { dropped: 0 });
    }

    #[test]
    fn a_count_put_back_comes_round_again() {
        let mut budget = Budget::new(1, 1, 4);
        let alice = id("alice");
        budget.keep_dropped(&alice, false, 5);
        assert_eq!(budget.spend(&alice, false, 100), Spent::Within { dropped: 5 });
    }
}
