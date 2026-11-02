//! The API agents call: enrol once, then fetch nonces and sign every request.
//!
//! Everything an agent sends is hostile. Bodies are capped before they are
//! parsed, every request has a deadline, identity comes from the signature and
//! never from a body, and a host only ever sees and reports on its own deploys.
//! Errors are `application/problem+json` with stable codes; no error repeats
//! anything the client sent.
//!
//! `GET /agent/v1/nonce` and `POST /agent/v1/enrol` are unauthenticated, so they
//! are rate-limited per source. The source is the peer of the TCP connection,
//! never a forwarding header, which anyone could set: behind a proxy all agents
//! share one allowance, so the defaults leave room for a fleet.
//!
//! A refusal that a signer or the holder of a valid code can be held to is in the
//! audit log. One that could come from anyone goes to a capped stderr log, since
//! auditing it would let anyone fill the audit log.
//!
//! Agent and controller are upgraded together in v0: unknown fields and enum
//! values in a request are refused, so a newer agent's new outcome or phase gets
//! `bad_request` from an older controller.

mod handlers;
mod problem;
mod rate_limit;
mod refusal_log;
mod signed;
#[cfg(test)]
mod tests;

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use axum::Router;
use axum::extract::{ConnectInfo, Request, State};
use axum::http::Extensions;
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use landfall_core::config::Config;
use landfall_core::ids::HostId;
use tokio::sync::{oneshot, watch};

use self::problem::ApiProblem;
pub(crate) use self::problem::log;
use self::rate_limit::RateLimiter;
pub(crate) use self::rate_limit::source_key;
pub(crate) use self::refusal_log::RefusalLog;
use crate::store::Store;

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
        Self {
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

    /// Writes a refusal nobody can be held to to the capped log, with the
    /// connection's source. `what` is the controller's own text.
    fn note_refusal(&self, extensions: &Extensions, what: &str) {
        let source = extensions.get::<ConnectInfo<SocketAddr>>().map_or_else(
            || "an unknown source".to_owned(),
            |peer| peer.0.ip().to_string(),
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

    /// Ends every long poll now, with whatever it has, and makes later ones
    /// answer at once: the server is stopping and should not wait them out.
    pub fn begin_shutdown(&self) {
        self.shutdown.send_replace(true);
    }
}

/// Answers a request that passes `limit` with a problem. Dropping the handler
/// rolls back any transaction it had open.
async fn deadline(State(limit): State<Duration>, request: Request, next: Next) -> Response {
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
        .with_state(state)
        .layer(middleware::from_fn_with_state(limit, deadline))
}
