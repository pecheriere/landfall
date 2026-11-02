//! Error answers: `application/problem+json` with the codes in
//! [`landfall_core::protocol::ProblemCode`].

use std::io::{self, Write as _};

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use landfall_core::protocol::{PROBLEM_CONTENT_TYPE, Problem, ProblemCode};

use crate::store::StoreError;

/// How long to tell a client to wait when the controller is refusing for load,
/// in seconds.
const RETRY_AFTER_SECS: &str = "5";

/// Writes a line to the controller's log. Callers pass only validated values or
/// the controller's own messages, never an agent's text unquoted.
pub(crate) fn log(line: &str) {
    // Nothing is left to tell if stderr itself is gone.
    drop(writeln!(io::stderr(), "landfall-server: {line}"));
}

/// Every way the API refuses a request. No variant carries anything the client
/// sent, so no answer can repeat it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ApiProblem {
    /// A signature header is missing, repeated or malformed.
    Unsigned,
    /// The nonce is unknown, used or expired: fetch another.
    BadNonce,
    /// The host is unknown or the signature does not verify. One code for both,
    /// reached in the same order with the body read first and a signature checked
    /// either way, against a fixed key for an unknown host, so that neither the
    /// answer nor the time it takes says which hosts exist.
    BadSignature,
    /// The enrolment code is unknown, used, expired or for another host.
    InvalidCode,
    /// The host has a key and the code does not allow replacing it.
    AlreadyEnrolled,
    /// Another host has this public key.
    KeyInUse,
    /// The body is not the request this endpoint takes.
    BadRequest,
    /// The body is over the limit.
    BodyTooLarge,
    /// The request took too long.
    SlowRequest,
    /// This source is asking too often.
    RateLimited,
    /// Too many nonces are outstanding.
    NoncesExhausted,
    /// The database is busy with another writer.
    Busy,
    /// The host has no such deploy.
    UnknownDeploy,
    /// The deploy was never handed to this host.
    NotClaimed,
    /// The controller failed. The details are in its log and not in the answer.
    Internal,
}

impl ApiProblem {
    /// The stable code, for an audit row.
    pub(crate) fn code(self) -> &'static str {
        self.parts().1.as_str()
    }

    fn parts(self) -> (StatusCode, ProblemCode, &'static str) {
        match self {
            Self::Unsigned => (
                StatusCode::UNAUTHORIZED,
                ProblemCode::Unsigned,
                "the request's signature headers are missing or malformed",
            ),
            Self::BadNonce => (
                StatusCode::UNAUTHORIZED,
                ProblemCode::BadNonce,
                "the nonce is unknown, used or expired",
            ),
            Self::BadSignature => (
                StatusCode::UNAUTHORIZED,
                ProblemCode::BadSignature,
                "the request's signature does not verify",
            ),
            Self::InvalidCode => (
                StatusCode::FORBIDDEN,
                ProblemCode::InvalidCode,
                "the enrolment code is not valid for this host",
            ),
            Self::AlreadyEnrolled => (
                StatusCode::CONFLICT,
                ProblemCode::AlreadyEnrolled,
                "the host has a key, and this code does not allow replacing it",
            ),
            Self::KeyInUse => (
                StatusCode::CONFLICT,
                ProblemCode::KeyInUse,
                "this public key is enrolled to another host",
            ),
            Self::BadRequest => (
                StatusCode::BAD_REQUEST,
                ProblemCode::BadRequest,
                "the body is not a valid request",
            ),
            Self::BodyTooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                ProblemCode::BodyTooLarge,
                "the body is over the limit",
            ),
            Self::SlowRequest => (
                StatusCode::REQUEST_TIMEOUT,
                ProblemCode::SlowRequest,
                "the request took too long",
            ),
            Self::RateLimited => (
                StatusCode::TOO_MANY_REQUESTS,
                ProblemCode::RateLimited,
                "too many requests from this source",
            ),
            Self::NoncesExhausted => (
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemCode::NoncesExhausted,
                "too many nonces are outstanding",
            ),
            Self::Busy => (
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemCode::Busy,
                "the database is busy",
            ),
            Self::UnknownDeploy => (
                StatusCode::NOT_FOUND,
                ProblemCode::UnknownDeploy,
                "this host has no such deploy",
            ),
            Self::NotClaimed => (
                StatusCode::CONFLICT,
                ProblemCode::NotClaimed,
                "this deploy was never handed out",
            ),
            Self::Internal => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ProblemCode::Internal,
                "the controller failed",
            ),
        }
    }
}

/// An `application/problem+json` answer.
pub(crate) fn problem_response(status: StatusCode, code: &str, title: &str) -> Response {
    let problem = Problem {
        code: code.to_owned(),
        title: title.to_owned(),
        status: status.as_u16(),
    };
    // Strings and an integer: serialising this cannot fail, and if it ever
    // did, an empty body with the right status is still a refusal.
    let body = serde_json::to_vec(&problem).unwrap_or_default();
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(PROBLEM_CONTENT_TYPE),
    );
    response
}

impl IntoResponse for ApiProblem {
    fn into_response(self) -> Response {
        let (status, code, title) = self.parts();
        let mut response = problem_response(status, code.as_str(), title);
        let headers = response.headers_mut();
        if matches!(self, Self::RateLimited | Self::NoncesExhausted | Self::Busy) {
            headers.insert(
                header::RETRY_AFTER,
                HeaderValue::from_static(RETRY_AFTER_SECS),
            );
        }
        response
    }
}

impl From<StoreError> for ApiProblem {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::InvalidCode => Self::InvalidCode,
            StoreError::AlreadyEnrolled(_) => Self::AlreadyEnrolled,
            StoreError::KeyInUse => Self::KeyInUse,
            StoreError::NonceTableFull => Self::NoncesExhausted,
            StoreError::UnknownDeploy => Self::UnknownDeploy,
            StoreError::NotClaimed => Self::NotClaimed,
            busy if busy.is_busy() => Self::Busy,
            other => {
                log(&format!("API: {other}"));
                Self::Internal
            }
        }
    }
}
