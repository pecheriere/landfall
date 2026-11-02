//! The API agents call: enrol once, then fetch nonces and sign every request.
//!
//! Everything an agent sends is hostile. Bodies are capped before they are
//! parsed, every request has a deadline, identity comes from the signature and
//! never from a body, and a host only ever sees and reports on its own deploys.
//! Errors are `application/problem+json` with stable codes; no error repeats
//! anything the client sent.
//!
//! `GET /agent/v1/nonce` and `POST /agent/v1/enrol` are unauthenticated, so they
//! are rate-limited per source. The source is the peer of the TCP connection, and
//! a forwarding header counts only from a peer the configuration says is a proxy
//! (`client_source`), as anyone could set one. Behind a proxy not listed there,
//! all agents share one allowance, so the defaults leave room for a fleet.
//!
//! A refusal that a signer or the holder of a valid code can be held to is in the
//! audit log. One that could come from anyone goes to a capped stderr log, since
//! auditing it would let anyone fill the audit log.
//!
//! Agent and controller are upgraded together in v0: unknown fields and enum
//! values in a request are refused, so a newer agent's new outcome or phase gets
//! `bad_request` from an older controller.

mod client_source;
mod handlers;
mod problem;
mod rate_limit;
mod refusal_log;
mod signed;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::Extensions;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use landfall_core::config::Config;
use landfall_core::ids::{HostId, PrincipalId};
use tokio::sync::{oneshot, watch};

use self::client_source::ClientSource;
pub(crate) use self::client_source::{note_client_source, source_of};
pub(crate) use self::handlers::json;
pub(crate) use self::problem::{ApiProblem, log, problem_response};
pub(crate) use self::rate_limit::{RateLimiter, source_key};
pub(crate) use self::refusal_log::RefusalLog;
pub(crate) use self::signed::read_body;
use crate::auth::{Budget, Spender, Spent};
use crate::store::Store;
use crate::web::Ceremonies;

/// The API's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// How long `work` holds a request that has nothing to hand out.
    pub long_poll: Duration,
    /// How long a client has to send its request body.
    pub body_timeout: Duration,
    /// How long any request may take in all, so at least `long_poll` and
    /// `body_timeout` together.
    pub request_timeout: Duration,
    /// How many unexpired nonces may be outstanding. A full table refuses
    /// rather than grows.
    pub max_outstanding_nonces: u64,
    /// Unauthenticated requests one source may make each second, sustained.
    pub source_rate_per_second: u32,
    /// Unauthenticated requests one source may make at once.
    pub source_burst: u32,
    /// How many sources are remembered for rate limiting. When all of them are
    /// recently active, a new source is refused rather than the table growing.
    pub max_sources: usize,
    /// State changes one credential may ask for each second, sustained, on the human API: each
    /// session on its own, and a principal's tokens as one. It is what a credential gone wrong
    /// can cost for as long as it lasts: one write transaction a second beside the agents'. A
    /// hostile caller's worst rows are one to two KiB, and superseding a request writes two a
    /// call, so that is some 80 to 170 MB of audit log a day, for each credential, until it is
    /// revoked. A principal keeps sixteen sessions, so sixteen times that, plus the burst of each
    /// new one: a sign-in is a whole new bucket, which [`sign_in_burst`](Self::sign_in_burst) and
    /// [`sign_in_refill_secs`](Self::sign_in_refill_secs) bound.
    pub principal_rate_per_second: u32,
    /// State changes one credential may ask for at once. A person signs a few approvals an
    /// hour, and a script asks for at most one release per deployment and then waits, as a
    /// deployment holds one open request: this leaves room for that across a large fleet, with
    /// retries, and refills in two minutes.
    pub principal_burst: u32,
    /// Sign-ins one principal may make at once, each after a signature verified. A person signs
    /// in a few times a day. Each one makes a new session with a whole burst above, so this and
    /// the next are what a passkey in the wrong hands can buy with: 120 state changes for each.
    pub sign_in_burst: u32,
    /// How long, in seconds, a principal waits for one more sign-in once those are spent.
    pub sign_in_refill_secs: u32,
    /// Beginnings of registration and sign-in, and failed finishes, one source may make each
    /// second, sustained. They have a bucket of their own, so that a flood of them leaves agents
    /// their nonces. A finish with a live challenge isn't charged. Behind a proxy, one source is
    /// everyone unless `[server] trusted_proxies` says who it is forwarding for.
    pub ceremony_rate_per_second: u32,
    /// How many of those one source may make at once.
    pub ceremony_burst: u32,
    /// How many sign-in challenges may be outstanding, in memory, each holding its place until
    /// its time is up. A full table refuses the new and keeps those it has. Far more than the rate
    /// above lets one source hold for the five minutes one lasts, so it takes many sources to
    /// fill, and 32-byte keys make it a few MiB.
    pub max_sign_in_challenges: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            long_poll: Duration::from_secs(30),
            body_timeout: Duration::from_secs(10),
            request_timeout: Duration::from_secs(45),
            // 32-byte rows, so a few MiB at most.
            max_outstanding_nonces: 65_536,
            source_rate_per_second: 10,
            source_burst: 100,
            max_sources: 4096,
            principal_rate_per_second: 1,
            principal_burst: 120,
            sign_in_burst: 10,
            sign_in_refill_secs: 300,
            ceremony_rate_per_second: 2,
            ceremony_burst: 30,
            max_sign_in_challenges: 65_536,
        }
    }
}

/// What the agent API's handlers share. Cloning shares it.
#[derive(Debug, Clone)]
pub struct ApiState {
    store: Store,
    config: Arc<Config>,
    limits: Limits,
    limiter: Arc<Mutex<RateLimiter>>,
    budget: Arc<Mutex<Budget>>,
    ceremonies: Arc<Mutex<Ceremonies>>,
    refusals: Arc<RefusalLog>,
    /// What ends each host's current long poll. One entry per host that ever
    /// signed a `work` request, so bounded by the enrolled hosts.
    polls: Arc<Mutex<HashMap<HostId, oneshot::Sender<()>>>>,
    shutdown: watch::Sender<bool>,
}

impl ApiState {
    /// The state for an API over `store`, answering by `config`, which was read
    /// once at start-up.
    #[must_use]
    pub fn new(store: Store, config: Config, limits: Limits) -> Self {
        // Every principal the configuration can name, at most: it never changes while running.
        let principals = config
            .grants()
            .len()
            .saturating_add(config.approvers().len());
        Self {
            budget: Arc::new(Mutex::new(Budget::new(&limits, principals))),
            ceremonies: Arc::new(Mutex::new(Ceremonies::new(&limits))),
            store,
            config: Arc::new(config),
            limits,
            limiter: Arc::new(Mutex::new(RateLimiter::new(
                limits.source_rate_per_second,
                limits.source_burst,
                limits.max_sources,
            ))),
            refusals: Arc::new(RefusalLog::default()),
            polls: Arc::new(Mutex::new(HashMap::new())),
            shutdown: watch::channel(false).0,
        }
    }

    /// Writes a refusal to the capped log, with who it is from: the connection's peer, or who a
    /// trusted proxy says it is forwarding for. `what` is the controller's own text.
    pub(crate) fn note_refusal(&self, extensions: &Extensions, what: &str) {
        let source = extensions.get::<ClientSource>().map_or_else(
            || "an unknown source".to_owned(),
            |source| source.0.to_string(),
        );
        // Without a clock the line is not worth failing the refusal for.
        if let Ok(now) = self.store.now() {
            self.refusals
                .note(now, &format!("refused {what} from {source}"));
        }
    }

    /// Makes this the host's only long poll: the previous one, if any, ends.
    /// The receiver resolves when a later one takes over.
    fn take_over_poll(&self, host: &HostId) -> oneshot::Receiver<()> {
        let (ours, superseded) = oneshot::channel();
        let previous = self
            .polls
            .lock()
            // Holds only channel ends, valid at every step.
            .unwrap_or_else(PoisonError::into_inner)
            .insert(host.clone(), ours);
        if let Some(previous) = previous {
            // It may have finished already, which is fine.
            let _ = previous.send(());
        }
        superseded
    }

    /// The store.
    #[must_use]
    pub fn store(&self) -> &Store {
        &self.store
    }

    /// The configuration, as it was read at start-up.
    pub(crate) fn config(&self) -> &Config {
        &self.config
    }

    /// The API's limits.
    pub(crate) fn limits(&self) -> Limits {
        self.limits
    }

    /// Registration's and sign-in's challenges and counts. Never held across an `await`.
    pub(crate) fn ceremonies(&self) -> MutexGuard<'_, Ceremonies> {
        self.ceremonies
            .lock()
            // Maps and counts, valid at every step.
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// How long until `principal` has another sign-in, in seconds.
    pub(crate) fn sign_in_wait(&self, principal: &PrincipalId, now: i64) -> u32 {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .sign_in_wait(principal, now)
    }

    /// Takes the cost of one state change from a budget.
    pub(crate) fn spend_budget(&self, spender: &Spender, now: i64) -> Spent {
        self.budget
            .lock()
            // Counts, valid at every step.
            .unwrap_or_else(PoisonError::into_inner)
            .spend(spender, now)
    }

    /// Lets go of the budgets of sessions that ended.
    pub(crate) fn forget_sessions(&self, ended: &[[u8; 32]]) {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .forget_sessions(ended);
    }

    /// How many sessions have a budget, for a test.
    #[cfg(test)]
    pub(crate) fn session_budgets(&self) -> usize {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .session_budgets()
    }

    /// Takes every count of dropped calls there is, to write down.
    pub(crate) fn take_dropped(&self) -> Vec<(Spender, u64)> {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .take_dropped()
    }

    /// Puts back a count of dropped calls that couldn't be written down.
    pub(crate) fn keep_dropped(&self, spender: Spender, count: u64) {
        self.budget
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .keep_dropped(spender, count);
    }

    /// Ends every long poll now, with whatever it has, and makes later ones
    /// answer at once: the server is stopping and should not wait them out.
    pub fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
    }
}

/// Answers a request that passes `limit` with a problem. Dropping the handler
/// rolls back any transaction it had open.
pub(crate) async fn deadline(
    State(limit): State<Duration>,
    request: Request,
    next: Next,
) -> Response {
    match tokio::time::timeout(limit, next.run(request)).await {
        Ok(response) => response,
        Err(_) => ApiProblem::SlowRequest.into_response(),
    }
}

/// The agent API's routes.
pub fn router(state: ApiState) -> Router {
    let limit = state.limits.request_timeout;
    Router::new()
        .route("/agent/v1/enrol", post(handlers::enrol))
        .route("/agent/v1/nonce", get(handlers::nonce))
        .route("/agent/v1/work", post(handlers::work))
        .route("/agent/v1/report", post(handlers::report))
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(limit, deadline))
        .layer(middleware::from_fn_with_state(state, note_client_source))
}
