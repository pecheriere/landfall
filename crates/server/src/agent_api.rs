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

mod handlers;
mod problem;
mod rate_limit;
mod signed;
#[cfg(test)]
mod tests;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse as _, Response};
use axum::routing::{get, post};
use landfall_core::config::Config;
use tokio::sync::watch;

use self::problem::ApiProblem;
pub(crate) use self::problem::log;
use self::rate_limit::RateLimiter;
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
            shutdown: watch::channel(false).0,
        }
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
