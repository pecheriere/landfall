//! Error answers: `application/problem+json` with the codes in [`ProblemCode`]. Every code
//! the agent API sends is one the agent reads by [`landfall_core::protocol::ProblemCode`], as
//! `every_problem_code_is_in_the_schema` holds.

use axum::body::Body;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use landfall_api::{Problem, ProblemCode};
use landfall_core::protocol::PROBLEM_CONTENT_TYPE;

use crate::logger::log;
use crate::store::StoreError;

/// How long to tell a client to wait when the controller is refusing for load,
/// in seconds.
const RETRY_AFTER_SECS: &str = "5";

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
    pub(crate) fn code(self) -> ProblemCode {
        self.parts().1
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
pub(crate) fn problem_response(status: StatusCode, code: ProblemCode, title: &str) -> Response {
    let problem = Problem {
        code,
        title: title.to_owned(),
        status: status.as_u16(),
    };
    // A known code, a string and an integer: serialising this cannot fail, and
    // if it ever did, an empty body with the right status is still a refusal.
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
        let mut response = problem_response(status, code, title);
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
