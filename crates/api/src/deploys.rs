//! A deploy, the steps its host reported, and why it ended as it did.

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use serde::{Deserialize, Serialize};

use crate::{DeployState, NextAction, Outcome, RawJson};

/// One step a host reported of a deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct StepView {
    /// Where it comes in the deploy, from 0.
    pub position: u32,
    /// What was done, as the host named it, quoted. Hostile: escape it before showing it.
    #[cfg_attr(feature = "openapi", schema(example = "\"pull\""))]
    pub name: String,
    /// How long it took, in milliseconds.
    pub millis: i64,
    /// Why it failed, quoted, or `null` if it did what it should. Hostile: escape it before
    /// showing it.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub failure: Option<String>,
    /// More about the step, as the controller stored it, bounded, or `null`: for checks,
    /// `{"kind": "checks", "checks": [{"check", "attempts", "millis"}]}`, each check's name
    /// quoted; for a backup, `{"kind": "backup", "files", "directories", "symlinks",
    /// "bytes"}`. A newer controller may add kinds.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<Object>, required = true)
    )]
    pub detail: Option<RawJson>,
}

/// A deploy: a release sent to its deployment's host, and what the host said of it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeployView {
    /// The deploy's number.
    pub id: i64,
    /// The deployment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "app/prod"))]
    pub deployment: DeploymentId,
    /// The host it was sent to, or `null` when the reader may not see that host: a host is
    /// seen through a deployment on it now that the reader may view, as `getHost` shows it.
    /// A deploy made before its deployment moved can have been sent to a host it no longer is
    /// on.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "home-1")
    )]
    pub host: Option<HostId>,
    /// The release's tag.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "v1.3.0"))]
    pub tag: ReleaseTag,
    /// The image digest sent.
    #[cfg_attr(
        feature = "openapi",
        schema(
            value_type = String,
            example = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    )]
    pub digest: ImageDigest,
    /// The release commit.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = String, example = "0123456789abcdef0123456789abcdef01234567")
    )]
    pub commit: CommitSha,
    /// Where it stands.
    pub state: DeployState,
    /// How it went, `null` until it finished. `null` with `state` `finished` is an outcome
    /// this controller can't read, recorded by a newer one.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub outcome: Option<Outcome>,
    /// Why, as its host said, quoted, or `null`. Hostile: escape it before showing it.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub reason: Option<String>,
    /// Why going back failed, as its host said, quoted, or `null`. Hostile: escape it before
    /// showing it.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub rollback_reason: Option<String>,
    /// The number of the request it came from, or `null` for one the controller queued by
    /// itself.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub request: Option<i64>,
    /// Who signed that request, or `null`.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "operator")
    )]
    pub approved_by: Option<PrincipalId>,
    /// When it was queued, in seconds since the Unix epoch.
    pub created_at: i64,
    /// When its host took it, in seconds since the Unix epoch, or `null`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub claimed_at: Option<i64>,
    /// When its host said how it went, in seconds since the Unix epoch, or `null`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub finished_at: Option<i64>,
    /// The steps its host reported, in order: at most 32.
    pub steps: Vec<StepView>,
}

/// What kind of thing happened to a deploy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum WhyKind {
    /// Someone asked for it.
    Requested,
    /// An approver signed the request.
    Approved,
    /// The controller queued it for its host.
    Queued,
    /// Its host took it.
    Claimed,
    /// Its host did a step of it.
    Step,
    /// A step of it failed.
    StepFailed,
    /// It failed, and its host went back to what ran before.
    RolledBack,
    /// It failed, and so did going back.
    RollbackFailed,
    /// Its host refused it.
    HostRefused,
    /// Its host said not now.
    Deferred,
    /// It ended otherwise: it runs, it changed nothing, or it failed with nothing to go back
    /// to.
    Finished,
    /// A kind from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// One thing that happened to a deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct WhyEvent {
    /// When, in seconds since the Unix epoch, or `null` when that isn't recorded, as for a
    /// step.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub at: Option<i64>,
    /// What kind of thing it was.
    pub what: WhyKind,
    /// The controller's words for it, with the host's text quoted in them. Escape it before
    /// showing it.
    pub text: String,
}

/// Why a deploy ended as it did, or where it stands if it hasn't.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Why {
    /// The deploy's number.
    pub deploy: i64,
    /// How it went, `null` until it finished. `null` once finished is an outcome this
    /// controller can't read, recorded by a newer one.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub outcome: Option<Outcome>,
    /// One sentence to act on, with the host's text quoted in it. Escape it before showing it.
    #[cfg_attr(
        feature = "openapi",
        schema(
            example = "v1.3.0 failed on home-1 at step \"checks\" and rolled back to the \
                       previous version; it won't be retried automatically"
        )
    )]
    pub summary: String,
    /// What happened, in time order: the request and its approval, if any, then the queue,
    /// the host taking it, each step, and the outcome.
    pub events: Vec<WhyEvent>,
    /// What to do next, if anything.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub next: Option<NextAction>,
}
