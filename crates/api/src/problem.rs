//! Refusals: `application/problem+json` (RFC 9457), each with a stable code.

use serde::{Deserialize, Serialize};

/// A refusal, as every `/api/v1` answer that isn't a success has it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Problem {
    /// What a client should act on: it never changes its meaning.
    pub code: ProblemCode,
    /// For people, and may change. Hostile in a client: escape it before showing it.
    pub title: String,
    /// The HTTP status.
    pub status: u16,
}

/// The stable codes of a `Problem`. A code never changes its meaning, and new ones are only
/// added.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ProblemCode {
    /// No credentials, or ones that aren't good.
    Unauthenticated,
    /// A state change with a session, not from the controller's own origin.
    BadOrigin,
    /// The principal may see this and may not do that to it.
    Forbidden,
    /// No such thing, as far as this principal may know.
    NotFound,
    /// This path doesn't take this method.
    MethodNotAllowed,
    /// The deployment already has a request waiting for an approver.
    RequestOpen,
    /// A request meant as a rollback for a tag that isn't lower than what runs, or when
    /// nothing runs or what runs isn't a version.
    NotARollback,
    /// The deployment has a deploy queued or running.
    DeploymentBusy,
    /// Its host hasn't reported it, or can't take a deploy as it stands.
    HostNotReady,
    /// The controller has no verified record of this release for this configuration.
    ReleaseNotVerified,
    /// The rule refuses this release, and an approval wouldn't change that.
    ReleaseRefused,
    /// Promotion from another deployment hasn't finished.
    PromotionPending,
    /// What runs changed since the request was made: ask again.
    RequestStale,
    /// The request waited too long: ask again.
    RequestExpired,
    /// The request was already approved.
    RequestClosed,
    /// The request was cancelled: ask again.
    RequestCancelled,
    /// The controller can't read the request's own record.
    RequestUnreadable,
    /// The assertion isn't one by this principal for this request.
    AssertionRefused,
    /// The configuration has no `[approval]`.
    ApprovalsNotConfigured,
    /// Too many requests: wait for `Retry-After`.
    RateLimited,
    /// An invite's code that is wrong, used or expired.
    InviteRefused,
    /// A registration whose ceremony didn't check out.
    RegistrationRefused,
    /// A sign-in that didn't work.
    SignInRefused,
    /// Too many ceremonies are under way to begin another.
    CeremoniesBusy,
    /// A host's signature headers are missing or malformed.
    Unsigned,
    /// A host's nonce is unknown, used or expired.
    BadNonce,
    /// A host's signature doesn't verify.
    BadSignature,
    /// An enrolment code that isn't valid for this host.
    InvalidCode,
    /// The host has a key, and the code doesn't allow replacing it.
    AlreadyEnrolled,
    /// Another host has this public key.
    KeyInUse,
    /// The body isn't the request this endpoint takes.
    BadRequest,
    /// The body is over the limit.
    BodyTooLarge,
    /// The request took too long.
    SlowRequest,
    /// Too many nonces are outstanding.
    NoncesExhausted,
    /// The database is busy with another writer.
    Busy,
    /// The host has no such deploy.
    UnknownDeploy,
    /// The deploy was never handed to this host.
    NotClaimed,
    /// The controller failed. Its log has the details.
    Internal,
    /// A code from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}
