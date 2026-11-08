//! Refusals of the human API, as `application/problem+json`. No variant carries anything
//! the client sent, or anything internal, so no answer can repeat it.

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use landfall_api::ProblemCode;

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
    /// The request was cancelled: ask again.
    RequestCancelled,
    /// The request's own row can't be read.
    RequestUnreadable,
    /// The assertion isn't one by this principal for this request's intent.
    AssertionRefused,
    /// The configuration has no `[approval]`.
    ApprovalsNotConfigured,
    /// This credential has asked for too many state changes.
    OverBudget,
    /// This credential has made too many reads.
    ReadsOverBudget,
    /// An audit page over more deployments and hosts than one query reads.
    AuditTooWide,
    /// An invite's code that is wrong, used or expired: the same answer for every way of that.
    InviteRefused,
    /// A registration with a good code whose ceremony didn't check out.
    RegistrationRefused,
    /// A sign-in that didn't work: the same answer for every way of that, so that it says
    /// nothing about who exists or which credentials are known.
    SignInRefused,
    /// Too many ceremonies are under way to begin another.
    CeremoniesBusy,
    /// A passkey that verified, for a principal with no sign-ins left for now.
    SignInsSpent {
        /// How long until the next one, in seconds.
        retry_after_secs: u32,
    },
    /// A problem both APIs have.
    Shared(ApiProblem),
}

impl HumanProblem {
    /// The answer's status, stable code and text for people. `None` for a shared one,
    /// which knows its own.
    fn parts(self) -> Option<(StatusCode, ProblemCode, &'static str)> {
        let conflict = StatusCode::CONFLICT;
        Some(match self {
            Self::Unauthenticated => (
                StatusCode::UNAUTHORIZED,
                ProblemCode::Unauthenticated,
                "valid credentials are required",
            ),
            Self::BadOrigin => (
                StatusCode::FORBIDDEN,
                ProblemCode::BadOrigin,
                "this request did not come from the controller's own origin",
            ),
            Self::Forbidden => (
                StatusCode::FORBIDDEN,
                ProblemCode::Forbidden,
                "no grant allows this here",
            ),
            Self::NotFound => (
                StatusCode::NOT_FOUND,
                ProblemCode::NotFound,
                "there is no such thing",
            ),
            Self::MethodNotAllowed => (
                StatusCode::METHOD_NOT_ALLOWED,
                ProblemCode::MethodNotAllowed,
                "this path does not take this method",
            ),
            Self::RequestOpen => (
                conflict,
                ProblemCode::RequestOpen,
                "this deployment already has a request waiting for an approver",
            ),
            Self::DeploymentBusy => (
                conflict,
                ProblemCode::DeploymentBusy,
                "this deployment has a deploy queued or running; try again when it ends",
            ),
            Self::HostNotReady => (
                conflict,
                ProblemCode::HostNotReady,
                "this deployment's host has not reported it, or cannot take a deploy now",
            ),
            Self::ReleaseNotVerified => (
                conflict,
                ProblemCode::ReleaseNotVerified,
                "the controller has no verified record of this release for this configuration",
            ),
            Self::ReleaseRefused => (
                conflict,
                ProblemCode::ReleaseRefused,
                "the deployment's rule refuses this release, and an approval would not change it",
            ),
            Self::PromotionPending => (
                conflict,
                ProblemCode::PromotionPending,
                "this release has not been healthy for long enough where it is promoted from",
            ),
            Self::RequestStale => (
                conflict,
                ProblemCode::RequestStale,
                "what is running changed since this request was made; ask again for a new one",
            ),
            Self::RequestExpired => (
                conflict,
                ProblemCode::RequestExpired,
                "this request waited too long; ask again for a new one",
            ),
            Self::RequestClosed => (
                conflict,
                ProblemCode::RequestClosed,
                "this request was already approved",
            ),
            Self::RequestCancelled => (
                conflict,
                ProblemCode::RequestCancelled,
                "this request was cancelled; ask again for a new one",
            ),
            Self::RequestUnreadable => (
                StatusCode::INTERNAL_SERVER_ERROR,
                ProblemCode::RequestUnreadable,
                "the controller cannot read this request; its log names the row, and it ends by \
                 itself when its time is up",
            ),
            Self::AssertionRefused => (
                StatusCode::FORBIDDEN,
                ProblemCode::AssertionRefused,
                "this assertion is not one by you for this request",
            ),
            Self::ApprovalsNotConfigured
            | Self::OverBudget
            | Self::ReadsOverBudget
            | Self::AuditTooWide
            | Self::InviteRefused
            | Self::RegistrationRefused
            | Self::SignInRefused
            | Self::CeremoniesBusy
            | Self::SignInsSpent { .. }
            | Self::Shared(_) => return self.ceremony_parts(),
        })
    }

    /// The same, for what registering and signing in refuse, approving too when nothing is
    /// configured for it, for budgets, and for the bound on an audit page. `None` for anything
    /// else.
    fn ceremony_parts(self) -> Option<(StatusCode, ProblemCode, &'static str)> {
        Some(match self {
            Self::ApprovalsNotConfigured => (
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemCode::ApprovalsNotConfigured,
                "the configuration has no [approval] settings",
            ),
            Self::OverBudget => (
                StatusCode::TOO_MANY_REQUESTS,
                ProblemCode::RateLimited,
                "too many state changes by this principal",
            ),
            Self::ReadsOverBudget => (
                StatusCode::TOO_MANY_REQUESTS,
                ProblemCode::RateLimited,
                "too many reads by this credential",
            ),
            Self::AuditTooWide => (
                StatusCode::BAD_REQUEST,
                ProblemCode::BadRequest,
                "this audit page would read too many deployments and hosts at once; filter it by \
                 deployment or host",
            ),
            Self::InviteRefused => (
                StatusCode::FORBIDDEN,
                ProblemCode::InviteRefused,
                "this link is not valid; ask for a new one",
            ),
            Self::RegistrationRefused => (
                StatusCode::BAD_REQUEST,
                ProblemCode::RegistrationRefused,
                "this passkey could not be registered; try again from the link",
            ),
            Self::SignInRefused => (
                StatusCode::FORBIDDEN,
                ProblemCode::SignInRefused,
                "this passkey cannot sign in here, or the attempt took too long; try again",
            ),
            Self::CeremoniesBusy => (
                StatusCode::SERVICE_UNAVAILABLE,
                ProblemCode::CeremoniesBusy,
                "too many sign-ins are under way; try again shortly",
            ),
            Self::SignInsSpent { .. } => (
                StatusCode::TOO_MANY_REQUESTS,
                ProblemCode::RateLimited,
                "too many sign-ins for this person; try again in a few minutes",
            ),
            _ => return None,
        })
    }

    /// The stable code, for an audit row. A variant with no parts of its own answers as
    /// `internal`, and so does its code.
    pub(crate) fn code(self) -> ProblemCode {
        match self {
            Self::Shared(shared) => shared.code(),
            other => other
                .parts()
                .map_or(ProblemCode::Internal, |(_, code, _)| code),
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
        if matches!(self, Self::OverBudget | Self::CeremoniesBusy) {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("5"));
        }
        // Reads refill many a second, so the next comes within one.
        if self == Self::ReadsOverBudget {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from_static("1"));
        }
        if let Self::SignInsSpent { retry_after_secs } = self {
            response
                .headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(retry_after_secs));
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
