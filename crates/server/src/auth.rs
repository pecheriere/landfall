//! Who is asking, and what they may do.
//!
//! `Principal` is how a handler learns who is asking: an extractor, the only thing that
//! can make one. `can` is the one place that says what a principal may do. It denies by
//! default and goes by the configuration on every call, so a grant taken out of the file
//! is gone when the controller next loads it, and `approve` is for people, whatever the
//! file says.
//!
//! Tokens and session tokens are 32 random bytes from the operating system, kept only as
//! a SHA-256 and looked up by that hash, so a comparison says nothing about the secret.
//! They never reach a log, an error or the audit log, and [`Debug`](std::fmt::Debug) on
//! them is redacted.
//!
//! No credentials and bad ones get the same answer, whether a token is malformed,
//! unknown, revoked or belongs to a principal the configuration no longer names. Someone
//! authenticated with no grant at all on a deployment gets the same 404 as for one that
//! doesn't exist, so that the API doesn't say which exist; with some other grant on it,
//! they can see it anyway and get a 403.

mod budget;
mod grants;
mod principal;
mod problem;
mod token;

#[cfg(test)]
pub(crate) use self::budget::flush_dropped;
pub(crate) use self::budget::{Budget, Spent, keep_flushing};
pub(crate) use self::grants::{can, named_in_config, sees};
pub(crate) use self::principal::Principal;
#[cfg(test)]
pub(crate) use self::principal::Via;
pub(crate) use self::problem::HumanProblem;
pub use self::token::{ApiToken, PasskeyInvite, SessionToken};
