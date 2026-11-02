//! Refusals of the human API, as `application/problem+json`. No variant carries anything
//! the client sent, or anything internal, so no answer can repeat it.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};

use crate::agent_api::{ApiProblem, problem_response};
use crate::store::StoreError;

/// Every way the human API refuses a request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum HumanProblem {
    /// No credentials, or ones that aren't good: the same answer for every way of that.
    Unauthenticated,
    /// A state change with a session, not from the configured origin.
    BadOrigin,
    /// The principal may see this and may not do that to it.
    Forbidden,
    /// No such thing, as far as this principal may know.
    NotFound,
    /// This path doesn't take this method.
    MethodNotAllowed,
    /// The deployment already has a request waiting for an approver.
    RequestOpen,
    /// The deployment has a deploy queued or running.
    DeploymentBusy,
    /// Its host hasn't reported it, or can't take a deploy as it stands.
    HostNotReady,
    /// The controller has no verified record of this release.
    ReleaseNotVerified,
    /// The rule refuses this release, and an approval wouldn't change that.
    ReleaseRefused,
    /// Promotion from another deployment hasn't finished.
    PromotionPending,
    /// The running release moved since the request was made: ask again.
    RequestStale,
    /// The request waited too long: ask again.
    RequestExpired,
    /// The request was already approved.
    RequestClosed,
    /// The assertion isn't one by this principal for this request's intent.
    AssertionRefused,
    /// The configuration has no `[approval]`.
    ApprovalsNotConfigured,
    /// A problem both APIs have.
    Shared(ApiProblem),
}

impl HumanProblem {
    /// The answer's status, stable code and text for people. `None` for a shared one,
    /// which knows its own.
    fn parts(self) -> Option<(StatusCode, &'static str, &'static str)> {
        let conflict = StatusCode::CONFLICT;
        Some(match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                "unauthenticated",
                "valid credentials are required",
            ),
            Self::BadOrigin => (
                StatusCode::FORBIDDEN,
                "bad_origin",
                "this request did not come from the controller's own origin",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                "forbidden",
                "no grant allows this here",
            ),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found", "there is no such thing"),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "this path does not take this method",
            ),
            Self::RequestOpen => (
                conflict,
                "request_open",
                "this deployment already has a request waiting for an approver",
            ),
            Self::DeploymentBusy => (
                conflict,
                "deployment_busy",
                "this deployment has a deploy queued or running; try again when it ends",
            ),
            Self::HostNotReady => (
                conflict,
                "host_not_ready",
                "this deployment's host has not reported it, or cannot take a deploy now",
            ),
            Self::ReleaseNotVerified => (
                conflict,
                "release_not_verified",
                "the controller has no verified record of this release for this configuration",
            ),
            Self::ReleaseRefused => (
                conflict,
                "release_refused",
                "the deployment's rule refuses this release, and an approval would not change it",
            ),
            Self::PromotionPending => (
                conflict,
                "promotion_pending",
                "this release has not been healthy for long enough where it is promoted from",
            ),
            Self::RequestStale => (
                conflict,
                "request_stale",
                "what is running changed since this request was made; ask again for a new one",
            ),
            Self::RequestExpired => (
                conflict,
                "request_expired",
                "this request waited too long; ask again for a new one",
            ),
            Self::RequestClosed => (
                conflict,
                "request_closed",
                "this request was already approved",
            ),
            Self::AssertionRefused => (
                StatusCode::FORBIDDEN,
                "assertion_refused",
                "this assertion is not one by you for this request",
            ),
            Self::ApprovalsNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                "approvals_not_configured",
                "the configuration has no [approval] settings",
            ),
            Self::Shared(_) => return None,
        })
    }

    /// The stable code, for an audit row.
    pub(crate) fn code(self) -> &'static str {
        match self {
            Self::Shared(shared) => shared.code(),
            other => other.parts().map_or("", |(_, code, _)| code),
        }
    }
}

impl IntoResponse for HumanProblem {
    fn into_response(self) -> Response {
        if let Self::Shared(shared) = self {
            return shared.into_response();
        }
        let Some((status, code, title)) = self.parts() else {
            return ApiProblem::Internal.into_response();
        };
        let mut response = problem_response(status, code, title);
        if self == Self::Unauthenticated {
            response
                .headers_mut()
                .insert(header::WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

impl From<ApiProblem> for HumanProblem {
    fn from(problem: ApiProblem) -> Self {
        Self::Shared(problem)
    }
}

impl From<StoreError> for HumanProblem {
    fn from(error: StoreError) -> Self {
        Self::Shared(error.into())
    }
}
