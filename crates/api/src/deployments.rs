//! Who is asking, and the deployments they may see.

use std::fmt;

use landfall_core::ids::{DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag, RepoName};
use serde::{Deserialize, Serialize};

/// How a principal proved who they are.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// An API token, which never approves.
    Token,
    /// A passkey's session on the controller's own pages.
    Session,
    /// A way from a newer controller than this client knows. No controller sends it, and the
    /// schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// What a grant lets a principal do to a deployment.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Permission {
    /// See it.
    View,
    /// Ask for a deploy of a higher release, or its first.
    Request,
    /// Sign a request, with a passkey, in a session.
    Approve,
    /// Ask for a deploy of a lower release.
    Rollback,
    /// A permission from a newer controller than this client knows. No controller sends it,
    /// and the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// What a principal may do to one deployment, now, by this credential.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct GrantView {
    /// The deployment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "app/prod"))]
    pub deployment: DeploymentId,
    /// What this credential may do to it: a token never lists `approve`.
    pub can: Vec<Permission>,
}

/// Who is asking.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct MeView {
    /// The principal.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "operator"))]
    pub principal: PrincipalId,
    /// How they proved it.
    pub via: Via,
    /// Each deployment they hold a grant on, by id.
    pub grants: Vec<GrantView>,
    /// Where an approver signs a request with a passkey: the configured `[approval]` origin
    /// and `/approvals`, or `null` without one.
    #[cfg_attr(
        feature = "openapi",
        schema(
            value_type = Option<String>,
            required = true,
            example = "https://landfall.example.com/approvals"
        )
    )]
    pub approve_url: Option<String>,
}

/// Where a release stands on a deployment. The first that applies, in this order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum ReleaseStatus {
    /// Its host runs it.
    Running,
    /// A deploy of it is queued or claimed.
    Deploying,
    /// A request for it waits for an approver.
    AwaitingApproval,
    /// Verification or the rule refused it.
    Refused,
    /// Something holds it, or the whole deployment, undecided.
    Held,
    /// A higher release runs.
    Superseded,
    /// Its last deploy failed, and it isn't tried again by itself.
    Failed,
    /// Its host refused it.
    HostRefused,
    /// Its host said not now.
    Deferred,
    /// It waits for a promotion to finish.
    PromotionPending,
    /// It deploys only when someone asks.
    NeedsRequest,
    /// It deploys by itself, and nothing known stands in the way.
    Waiting,
    /// A status from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A release, by its tag and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReleaseBrief {
    /// The tag.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "v1.3.0"))]
    pub tag: ReleaseTag,
    /// Where it stands.
    pub status: ReleaseStatus,
}

/// What a deployment's host last said about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RunningView {
    /// The release deployed, `null` if none ever was.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "v1.2.0")
    )]
    pub tag: Option<ReleaseTag>,
    /// Its digest.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, required = true))]
    pub digest: Option<ImageDigest>,
    /// The agent's phase, such as `idle`.
    #[cfg_attr(feature = "openapi", schema(example = "idle"))]
    pub phase: String,
    /// Whether the agent is running a deploy.
    pub busy: bool,
    /// Whether what runs differs from what the agent deployed.
    pub drift: bool,
    /// Whether the host's configuration differs from the controller's.
    pub config_drift: bool,
    /// How long this release has been observed healthy, in seconds, as of `last_report`;
    /// `null` while nothing runs or it has drifted.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub healthy_secs: Option<i64>,
    /// When the host last said anything about it, in seconds since the Unix epoch.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub last_report: Option<i64>,
}

/// A deployment in a list.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeploymentSummary {
    /// The deployment.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "app/prod"))]
    pub id: DeploymentId,
    /// Its source repository.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "example/app"))]
    pub repo: RepoName,
    /// The host it runs on.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "home-1"))]
    pub host: HostId,
    /// What its host last said, `null` if it hasn't reported it.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub running: Option<RunningView>,
    /// Its newest release, `null` when none is known.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub latest: Option<ReleaseBrief>,
    /// The number of its request waiting for an approver, if any.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub open_request: Option<i64>,
    /// Whether that request is one this principal could sign. A token never approves, so
    /// this is always `false` for one.
    pub needs_you: bool,
}

/// A deployment named in another's view, if this principal may view it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeploymentRef {
    /// One this principal may view.
    Seen(DeploymentId),
    /// One they may not, never named.
    Unseen,
}

impl fmt::Display for DeploymentRef {
    /// The deployment's id, or what a reason says of one this principal can't view.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Seen(id) => write!(f, "{id}"),
            Self::Unseen => f.write_str("a deployment you can't view"),
        }
    }
}

/// Another deployment, named in this one's view: its id, or `null` with `unseen` for one this
/// principal can't view, which is never named.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[cfg_attr(feature = "openapi", schema(as = DeploymentRef))]
struct DeploymentRefWire {
    /// The deployment, or `null` for one this principal can't view.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "app/beta")
    )]
    deployment: Option<DeploymentId>,
    /// `true` when `deployment` is `null` because this principal can't view it; left out
    /// otherwise.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    unseen: bool,
}

impl From<DeploymentRefWire> for DeploymentRef {
    fn from(wire: DeploymentRefWire) -> Self {
        wire.deployment.map_or(Self::Unseen, Self::Seen)
    }
}

impl From<&DeploymentRef> for DeploymentRefWire {
    fn from(reference: &DeploymentRef) -> Self {
        match reference {
            DeploymentRef::Seen(id) => Self {
                deployment: Some(id.clone()),
                unseen: false,
            },
            DeploymentRef::Unseen => Self {
                deployment: None,
                unseen: true,
            },
        }
    }
}

impl Serialize for DeploymentRef {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        DeploymentRefWire::from(self).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DeploymentRef {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        DeploymentRefWire::deserialize(deserializer).map(Self::from)
    }
}

/// When a deployment's releases go on to another, or came from one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct PromotionView {
    /// The other deployment.
    #[serde(flatten)]
    #[cfg_attr(feature = "openapi", schema(value_type = DeploymentRefWire))]
    pub deployment: DeploymentRef,
    /// How long a release must be healthy on the deployment promoted from, in seconds.
    pub healthy_for_secs: u64,
}

/// When a deployment's releases deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RuleView {
    /// Without a human up to this bump: `patch`, `minor` or `any`, or `null` for never.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "patch")
    )]
    pub auto: Option<String>,
    /// With an approver up to this bump: `patch`, `minor` or `any`, or `null` for never.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "minor")
    )]
    pub approve: Option<String>,
    /// Who may sign a request.
    #[cfg_attr(feature = "openapi", schema(value_type = Vec<String>, example = json!(["operator"])))]
    pub approvers: Vec<PrincipalId>,
    /// Whether prereleases are eligible.
    pub prerelease: bool,
}

/// Why something is still undecided.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HoldView {
    /// The release held, or `null` for the whole deployment.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "v1.3.0")
    )]
    pub tag: Option<ReleaseTag>,
    /// Why, as the controller recorded it, quoted. Hostile: escape it before showing it.
    pub reason: String,
    /// When this reason began to stand, in seconds since the Unix epoch.
    pub since: i64,
    /// When it was last tried, in seconds since the Unix epoch.
    pub last_try: i64,
}

/// One deployment, in full.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeploymentView {
    /// What a list shows of it.
    pub summary: DeploymentSummary,
    /// When its releases deploy.
    pub rule: RuleView,
    /// Where its releases go on to, if anywhere.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub promote_to: Option<PromotionView>,
    /// Each deployment whose releases come on to this one.
    pub promoted_from: Vec<PromotionView>,
    /// What holds it or its releases undecided, the newest 50.
    pub holds: Vec<HoldView>,
    /// How many holds there are in all.
    pub holds_total: u32,
}
