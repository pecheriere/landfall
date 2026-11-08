//! Who is asking: an extractor over a token or a session.
//!
//! A [`Principal`] can only come out of this extractor, and this extractor makes the
//! exact-`Origin` check on any state change that came with a session, and the `Sec-Fetch-Site`
//! check on any read that did. So a handler that takes a principal can't forget either check,
//! and a route that doesn't take one has nobody to act for. A token needs neither: a browser
//! never attaches one by itself. Then it takes the call's cost from the credential's budget: a
//! state change's from one, and a read's from another. Sessions are begun by sign-in, in its own
//! module; this only reads them.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{Extensions, HeaderMap, HeaderName, Method, header};
use landfall_core::config::Config;
use landfall_core::ids::PrincipalId;
use serde_json::{Value, json};

use super::budget::{Dropped, Spender, Spent, throttled_event};
use super::grants::named_in_config;
use super::problem::HumanProblem;
use super::token::{ApiToken, SessionToken};
use crate::agent_api::{ApiState, source_of};
use crate::web::FailureKind;

/// The session cookie. `__Host-` makes a browser refuse it unless it is `Secure`, from
/// this very host, with no `Domain` and `Path=/`.
pub(crate) const SESSION_COOKIE: &str = "__Host-landfall-session";

/// Which site a browser says sent a request: `same-origin`, `same-site`, `cross-site`, or `none`
/// for one a person started.
const SEC_FETCH_SITE: HeaderName = HeaderName::from_static("sec-fetch-site");

/// How a principal proved who it is. This is what tells the kinds apart.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Via {
    /// A person's session, from a passkey.
    Session,
    /// An API token, by its id.
    Token(i64),
}

/// Someone who proved who they are. Private fields: only the extractor makes one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Principal {
    id: PrincipalId,
    via: Via,
}

impl Principal {
    /// Who.
    pub(crate) fn id(&self) -> &PrincipalId {
        &self.id
    }

    /// Whether a person is asking, by a passkey's session. Nothing else is.
    pub(crate) fn is_human(&self) -> bool {
        matches!(self.via, Via::Session)
    }

    /// Who, as an audit row names them. Holds no secret: a token only by its id.
    pub(crate) fn audited(&self) -> Value {
        match self.via {
            Via::Session => json!({ "principal": self.id, "via": "session" }),
            Via::Token(token) => json!({ "principal": self.id, "via": "token", "token": token }),
        }
    }

    /// A principal with no request, for a test of grants.
    #[cfg(test)]
    pub(crate) fn for_test(name: &str, via: Via) -> Self {
        Self {
            id: name.parse().unwrap(),
            via,
        }
    }
}

/// A count taken from the table to be written down. It goes back when dropped unless it was, which
/// covers a write that fails and a handler dropped while waiting for one: by a deadline, a client
/// that left or stopping. So a count can't be lost that way. If the handler is dropped just as the
/// write commits, the count is written twice, which says more calls were refused than were.
struct CountBeingWritten<'a> {
    state: &'a ApiState,
    spender: &'a Spender,
    dropped: u64,
    written: bool,
}

impl Drop for CountBeingWritten<'_> {
    fn drop(&mut self) {
        if !self.written {
            self.state.keep_dropped(Dropped {
                spender: self.spender.clone(),
                reads: false,
                count: self.dropped,
            });
        }
    }
}

/// Takes the cost of a state change from a budget. Over it, the call is refused before it can
/// write anything. The first call back within it writes down how many were, or is refused
/// itself and keeps the count. Call this only for someone who has proved who they are: anyone
/// else could spend a person's budget by naming them.
pub(crate) async fn spend_budget(
    state: &ApiState,
    extensions: &Extensions,
    spender: &Spender,
) -> Result<(), HumanProblem> {
    let now = state.store().now()?;
    match state.spend_budget(spender, now) {
        Spent::Over => {
            state.note_refusal(extensions, "a call over its budget");
            Err(match spender {
                Spender::SignIns(principal) => HumanProblem::SignInsSpent {
                    retry_after_secs: state.sign_in_wait(principal, now),
                },
                _ => HumanProblem::OverBudget,
            })
        }
        Spent::Within { dropped } => write_down(state, spender, dropped).await,
    }
}

/// The same for a read, from the budget for reads: over it, the read is refused. A read writes
/// nothing either way: how many were refused waits for the flush, so a read can't fail on that.
fn spend_read_budget(
    state: &ApiState,
    extensions: &Extensions,
    spender: &Spender,
) -> Result<(), HumanProblem> {
    if state.spend_read_budget(spender, state.store().now()?) {
        Ok(())
    } else {
        state.note_refusal(extensions, "a read over its budget");
        Err(HumanProblem::ReadsOverBudget)
    }
}

/// Writes down a count of state changes taken from the table, or puts it back if that fails.
async fn write_down(state: &ApiState, spender: &Spender, dropped: u64) -> Result<(), HumanProblem> {
    if dropped == 0 {
        return Ok(());
    }
    let mut count = CountBeingWritten {
        state,
        spender,
        dropped,
        written: false,
    };
    let event = throttled_event(spender, dropped, false);
    state.store().record(&event).await?;
    count.written = true;
    Ok(())
}

/// What a request presents.
enum Credential {
    Token(ApiToken),
    Session(SessionToken),
}

/// The value of the session cookie: `Ok(None)` for no such cookie. A header that isn't
/// text, and a cookie sent twice, are `Err`: the two readers of a header can't disagree.
fn session_cookie(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let mut found = None;
    for value in headers.get_all(header::COOKIE) {
        for pair in value.to_str().map_err(drop)?.split(';') {
            if let Some((name, value)) = pair.trim().split_once('=')
                && name == SESSION_COOKIE
                && found.replace(value).is_some()
            {
                return Err(());
            }
        }
    }
    Ok(found)
}

/// The session a request's cookie carries, if it carries one that can be read.
pub(crate) fn session_of(headers: &HeaderMap) -> Option<SessionToken> {
    SessionToken::parse(session_cookie(headers).ok()??)
}

/// The token in the value of an `Authorization` header.
fn bearer(value: &str) -> Option<ApiToken> {
    let (scheme, token) = value.split_once(' ')?;
    scheme
        .eq_ignore_ascii_case("bearer")
        .then(|| ApiToken::parse(token))
        .flatten()
}

/// The one credential a request presents, if it presents one that can be read. Both
/// together are refused, so that nothing has to choose between two people.
fn presented(headers: &HeaderMap) -> Option<Credential> {
    let mut authorization = headers.get_all(header::AUTHORIZATION).iter();
    let (value, repeated) = (authorization.next(), authorization.next());
    if repeated.is_some() {
        return None;
    }
    match (value, session_cookie(headers).ok()?) {
        (Some(value), None) => bearer(value.to_str().ok()?).map(Credential::Token),
        (None, Some(cookie)) => SessionToken::parse(cookie).map(Credential::Session),
        (Some(_), Some(_)) | (None, None) => None,
    }
}

/// Whether the method can't change anything, by what every route here does with it.
fn is_safe(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// Whether the request's one `Origin` is exactly the configured origin. A configuration
/// with none has no page to be at, so nothing matches it.
pub(crate) fn origin_matches(headers: &HeaderMap, config: &Config) -> bool {
    let Some(settings) = config.approval() else {
        return false;
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    match (origins.next(), origins.next()) {
        (Some(origin), None) => origin.as_bytes() == settings.origin().as_bytes(),
        _ => false,
    }
}

/// Whether a session's read may have come from the controller's own pages: its one
/// `Sec-Fetch-Site` says `same-origin`, or `none` for one a person started, or it has none, as
/// from a client that isn't a browser. Sent twice, or as anything else, it didn't.
fn read_from_own_pages(headers: &HeaderMap) -> bool {
    let mut sites = headers.get_all(SEC_FETCH_SITE).iter();
    match (sites.next(), sites.next()) {
        (None, _) => true,
        (Some(site), None) => matches!(site.as_bytes(), b"same-origin" | b"none"),
        (Some(_), Some(_)) => false,
    }
}

/// Who a request's credential says it is, with a session's token if that's what it is, and with
/// a session's call checked for where it came from: by its `Origin` for a state change, and by
/// `Sec-Fetch-Site` for a read. That comes before any budget: a page on a sibling subdomain can
/// send a person's cookie, as `SameSite` doesn't stop it, and that must cost them nothing. It
/// writes no row either, only a count.
async fn identified(
    parts: &Parts,
    state: &ApiState,
) -> Result<(Principal, Option<SessionToken>), HumanProblem> {
    let store = state.store();
    let found = match presented(&parts.headers) {
        None => None,
        Some(Credential::Token(token)) => store
            .token_holder(&token)
            .await?
            .map(|(id, principal)| (principal, Via::Token(id), None)),
        Some(Credential::Session(session)) => store
            .session_holder(&session)
            .await?
            .map(|principal| (principal, Via::Session, Some(session))),
    };
    let Some((id, via, session)) =
        found.filter(|(principal, _, _)| named_in_config(state.config(), principal))
    else {
        // Anyone can send these, so they go to the capped log and not the audit log.
        state.note_refusal(
            &parts.extensions,
            "an API request with no valid credentials",
        );
        return Err(HumanProblem::Unauthenticated);
    };
    let principal = Principal { id, via };
    if principal.is_human() {
        let refused = if is_safe(&parts.method) {
            (!read_from_own_pages(&parts.headers))
                .then_some("a read with a session, sent by another site")
        } else {
            (!origin_matches(&parts.headers, state.config()))
                .then_some("a state change with a session, not from the configured origin")
        };
        if let Some(reason) = refused {
            count_bad_origin(state, parts, &principal.id, reason)?;
            return Err(HumanProblem::BadOrigin);
        }
    }
    Ok((principal, session))
}

/// Counts a session's call from elsewhere, for `reason`. It goes in the capped log now and the
/// audit log as a count, by [`tend`](crate::web::tend).
fn count_bad_origin(
    state: &ApiState,
    parts: &Parts,
    principal: &PrincipalId,
    reason: &'static str,
) -> Result<(), HumanProblem> {
    state.note_refusal(&parts.extensions, &format!("{reason}, for {principal}"));
    let source = source_of(&parts.extensions);
    let now = state.store().now()?;
    state
        .ceremonies()
        .count_failure(principal, FailureKind::BadOrigin, reason, source, now);
    Ok(())
}

impl FromRequestParts<ApiState> for Principal {
    type Rejection = HumanProblem;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, HumanProblem> {
        let (principal, session) = identified(parts, state).await?;
        let spender = match session {
            Some(session) => Spender::Session {
                hash: session.hash(),
                principal: principal.id.clone(),
            },
            None => Spender::Tokens(principal.id.clone()),
        };
        if is_safe(&parts.method) {
            spend_read_budget(state, &parts.extensions, &spender)?;
        } else {
            spend_budget(state, &parts.extensions, &spender).await?;
        }
        Ok(principal)
    }
}

/// Who is asking to sign out, and the session to end, if it is a session that asks. Its `Origin`
/// was checked, and that is all: ending a session is never refused by a budget, so that someone
/// who sees their cookie is being used up can always end it. It can't write much, since it ends
/// what it would need to come again. A token has nothing to end, and pays as usual to be told.
#[derive(Debug)]
pub(crate) struct Leaving {
    pub(crate) principal: Principal,
    pub(crate) session: Option<SessionToken>,
}

impl FromRequestParts<ApiState> for Leaving {
    type Rejection = HumanProblem;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, HumanProblem> {
        let (principal, session) = identified(parts, state).await?;
        if session.is_none() {
            let spender = Spender::Tokens(principal.id.clone());
            spend_budget(state, &parts.extensions, &spender).await?;
        }
        Ok(Self { principal, session })
    }
}
