//! The browser's side: registering a passkey, signing in, and the approvals page.
//!
//! The pages are static files with one script, built into the binary, which fetch JSON and
//! put what comes back in the page as text. So nothing a hostile tag or name holds can become
//! markup, and the strict policy on every answer (see [`headers`]) has nothing to make an
//! exception for. The design language comes later: these are the pages it restyles.
//!
//! These routes run before anyone has proved who they are, so everything here is hostile.
//! Every `POST` that takes no [`Principal`](crate::auth::Principal) goes through [`admit`]
//! first, for what stops it before anything is read or written:
//!
//! - **The configuration has `[approval]`.** One that loads without it gets a clear refusal.
//! - **The exact `Origin`.** The `Principal` extractor makes this check for a session's state
//!   changes, and there is no session yet here. Without it a page on another site could sign
//!   its visitor in as itself, or spend their allowance.
//!
//! **The source's allowance** is a bucket of its own, as agents must not lose their nonces to
//! this. Each `begin` pays first. A `finish` pays only if it turns out bad: one with a live
//! challenge and a good answer never does, so a real tap isn't wasted by someone else's flood.
//!
//! Anyone can send these, so a refusal costs little. Over the allowance or with a full table it
//! is a `429` or a `503` and writes nothing. A wrong invite or an unknown credential goes to the
//! capped log. A failure that can be attributed to a principal goes there too, and is counted in
//! memory and written by [`tend`] each watcher interval, as one row per principal, kind and
//! reason, so what anyone can make the audit log hold is bounded by the configuration and the
//! clock. That also means a request that names a real principal does no more work than one that
//! doesn't. A crash loses a count not yet written, as with [`Budget`](crate::auth::Budget). A
//! session's state change from another origin is counted the same way.
//!
//! No `GET` changes anything here, which is what the extractor's check relies on.

mod ceremonies;
mod headers;
mod pages;
mod registration;
mod sign_in;
#[cfg(test)]
mod tests;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::request::Parts;
use axum::middleware;
use axum::routing::{get, post};
use landfall_core::config::Approval;
use landfall_core::ids::PrincipalId;
use serde::de::DeserializeOwned;

pub(crate) use self::ceremonies::{Ceremonies, FailureKind};
pub(crate) use self::headers::security_headers;
use crate::agent_api::{
    ApiProblem, ApiState, deadline, log, note_client_source, read_body, source_of,
};
use crate::auth::{HumanProblem, origin_matches};

/// What a ceremony's answer says about being kept.
const NO_STORE: [(header::HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];

/// Runs before everything else on a route with no principal yet. Gives the relying party.
fn admit<'a>(state: &'a ApiState, parts: &Parts) -> Result<&'a Approval, HumanProblem> {
    let Some(settings) = state.config().approval() else {
        return Err(HumanProblem::ApprovalsNotConfigured);
    };
    if !origin_matches(&parts.headers, state.config()) {
        state.note_refusal(&parts.extensions, "a ceremony from another origin");
        return Err(HumanProblem::BadOrigin);
    }
    Ok(settings)
}

/// Takes a token from the source's allowance.
fn charge(state: &ApiState, parts: &Parts) -> Result<(), HumanProblem> {
    let source = source_of(&parts.extensions);
    let now = state.store().now()?;
    if state.ceremonies().allow(source, now) {
        Ok(())
    } else {
        state.note_refusal(&parts.extensions, "a ceremony over its source's allowance");
        Err(ApiProblem::RateLimited.into())
    }
}

/// The answer to a bad `finish`, which pays for itself: `problem`, or the `429` if it can't.
fn charged(state: &ApiState, parts: &Parts, problem: HumanProblem) -> HumanProblem {
    charge(state, parts).err().unwrap_or(problem)
}

/// The note of a failure against a principal: the capped log now, and the count for the audit
/// log. Without a clock the log line still goes, and the refusal stands.
fn count_failure(
    state: &ApiState,
    parts: &Parts,
    principal: &PrincipalId,
    kind: FailureKind,
    reason: &'static str,
) {
    state.note_refusal(&parts.extensions, &format!("{reason}, for {principal}"));
    match state.store().now() {
        Ok(now) => state.ceremonies().count_failure(
            principal,
            kind,
            reason,
            source_of(&parts.extensions),
            now,
        ),
        Err(error) => log(&format!("web: {error}")),
    }
}

/// Reads and parses a body within `limit`.
async fn parsed<T: DeserializeOwned>(
    state: &ApiState,
    body: Body,
    limit: usize,
) -> Result<T, HumanProblem> {
    let bytes = read_body(body, limit, state.limits().body_timeout).await?;
    serde_json::from_slice(&bytes).map_err(|_| ApiProblem::BadRequest.into())
}

/// The upkeep each watcher interval: writes down the failures counted since the last time,
/// keeping any it can't, and clears out what's past its time.
pub(crate) async fn tend(state: &ApiState) {
    let store = state.store();
    let now = match store.now() {
        Ok(now) => now,
        Err(error) => {
            log(&format!("web: {error}"));
            return;
        }
    };
    state.ceremonies().forget_expired(now);
    let counted = state.ceremonies().take_failures();
    for failure in counted {
        if let Err(error) = store.record(&failure.event()).await {
            log(&format!("web: writing down failed ceremonies: {error}"));
            state.ceremonies().keep_failure(failure);
        }
    }
    match store.settle_ceremonies().await {
        Ok(ended) => state.forget_sessions(&ended),
        Err(error) => log(&format!(
            "web: clearing out sessions past their time: {error}"
        )),
    }
}

/// The routes.
pub(crate) fn router(state: ApiState) -> Router {
    let limit = state.limits().request_timeout;
    Router::new()
        .route("/passkeys/register", get(pages::register))
        .route("/passkeys/register/begin", post(registration::begin))
        .route("/passkeys/register/finish", post(registration::finish))
        .route("/sign-in", get(pages::sign_in))
        .route("/sign-in/begin", post(sign_in::begin))
        .route("/sign-in/finish", post(sign_in::finish))
        .route("/sign-out", post(sign_in::sign_out))
        .route("/approvals", get(pages::approvals))
        .route("/static/landfall.js", get(pages::script))
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(limit, deadline))
        .layer(middleware::from_fn_with_state(state, note_client_source))
}

async fn method_not_allowed() -> HumanProblem {
    HumanProblem::MethodNotAllowed
}
