//! Who is asking: an extractor over a token or a session.
//!
//! A [`Principal`] can only come out of this extractor, and this extractor makes the
//! exact-`Origin` check on any state change that came with a session. So a handler that
//! takes a principal can't forget the check, and a route that doesn't take one has nobody
//! to act for. A token needs no such check: a browser never attaches one by itself.
//! Sessions are begun by sign-in, in its own module; this only reads them.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use axum::http::{HeaderMap, Method, header};
use landfall_core::config::Config;
use landfall_core::ids::PrincipalId;
use serde_json::{Value, json};

use super::budget::Spent;
use super::grants::named_in_config;
use super::problem::HumanProblem;
use super::token::{ApiToken, SessionToken};
use crate::agent_api::ApiState;
use crate::audit::{AuditEvent, EventKind};

/// The session cookie. `__Host-` makes a browser refuse it unless it is `Secure`, from
/// this very host, with no `Domain` and `Path=/`.
const SESSION_COOKIE: &str = "__Host-landfall-session";

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

    /// Takes the cost of a state change from this principal's budget. Over it, the call is
    /// refused before it can write anything. The first call back within it writes down how
    /// many were, or is refused itself and keeps the count.
    async fn spend_budget(&self, parts: &Parts, state: &ApiState) -> Result<(), HumanProblem> {
        let store = state.store();
        let human = self.is_human();
        match state.spend_budget(&self.id, human, store.now()?) {
            Spent::Over => {
                state.note_refusal(&parts.extensions, "an API call over its principal's budget");
                Err(HumanProblem::OverBudget)
            }
            Spent::Within { dropped: 0 } => Ok(()),
            Spent::Within { dropped } => {
                let event = AuditEvent {
                    kind: EventKind::AccessThrottled,
                    deployment: None,
                    host: None,
                    detail: json!({ "by": self.audited(), "dropped": dropped }),
                };
                if let Err(error) = store.record(&event).await {
                    state.keep_dropped(&self.id, human, dropped);
                    return Err(error.into());
                }
                Ok(())
            }
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
fn origin_matches(headers: &HeaderMap, config: &Config) -> bool {
    let Some(settings) = config.approval() else {
        return false;
    };
    let mut origins = headers.get_all(header::ORIGIN).iter();
    match (origins.next(), origins.next()) {
        (Some(origin), None) => origin.as_bytes() == settings.origin().as_bytes(),
        _ => false,
    }
}

impl FromRequestParts<ApiState> for Principal {
    type Rejection = HumanProblem;

    async fn from_request_parts(parts: &mut Parts, state: &ApiState) -> Result<Self, HumanProblem> {
        let store = state.store();
        let found = match presented(&parts.headers) {
            None => None,
            Some(Credential::Token(token)) => store
                .token_holder(&token)
                .await?
                .map(|(id, principal)| (principal, Via::Token(id))),
            Some(Credential::Session(session)) => store
                .session_holder(&session)
                .await?
                .map(|principal| (principal, Via::Session)),
        };
        let Some((id, via)) =
            found.filter(|(principal, _)| named_in_config(state.config(), principal))
        else {
            // Anyone can send these, so they go to the capped log and not the audit log.
            state.note_refusal(
                &parts.extensions,
                "an API request with no valid credentials",
            );
            return Err(HumanProblem::Unauthenticated);
        };
        let principal = Self { id, via };
        if is_safe(&parts.method) {
            return Ok(principal);
        }
        principal.spend_budget(parts, state).await?;
        if principal.is_human() && !origin_matches(&parts.headers, state.config()) {
            let event = AuditEvent {
                kind: EventKind::AccessRefused,
                deployment: None,
                host: None,
                detail: json!({
                    "by": principal.audited(),
                    "reason": "a state change with a session, not from the configured origin",
                }),
            };
            store.record(&event).await?;
            return Err(HumanProblem::BadOrigin);
        }
        Ok(principal)
    }
}
