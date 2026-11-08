//! A deployment's releases, and the story of one: where it stands and why, where it came
//! from, the commits it brings, and what was asked and deployed of it.

use landfall_core::ids::{CommitSha, ImageDigest, PrincipalId, ReleaseTag};
use serde::{Deserialize, Serialize};

use crate::{ReleaseStatus, RequestState};

/// What the controller's watcher last recorded of a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    /// A deploy without a human, if its host can take one.
    Auto,
    /// A deploy once an approver signs a request for it.
    NeedsApproval,
    /// A deploy only when someone asks for it.
    Manual,
    /// No deploy by itself: verification, the rule or what became of its deploys refused it.
    Refused,
    /// Its host said not now, and it is asked again after a wait.
    Deferred,
    /// A decision from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A release of a deployment, and where it stands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReleaseView {
    /// The tag.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "v1.3.0"))]
    pub tag: ReleaseTag,
    /// Where it stands now.
    pub status: ReleaseStatus,
    /// What the watcher last recorded of it.
    pub decision: Decision,
    /// When the controller first recorded it, in seconds since the Unix epoch.
    pub first_seen_at: i64,
    /// When it was last verified, in seconds since the Unix epoch.
    pub seen_at: i64,
}

/// What a person or agent can do next about a release.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum NextKind {
    /// Ask for a deploy of it.
    Request,
    /// Ask for a rollback to it.
    Rollback,
    /// An approver signs the request for it.
    Approve,
    /// Nothing to do but wait.
    Wait,
    /// Its host's configuration needs a person.
    FixHost,
    /// Its host may be left in a bad state: a person looks at it.
    Recover,
    /// Nothing anyone needs to do.
    None,
    /// A kind from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// The one thing to do next about a release.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct NextAction {
    /// What kind of thing it is.
    pub kind: NextKind,
    /// The controller's own words for it, such as the command to run.
    #[cfg_attr(
        feature = "openapi",
        schema(example = "ask for a deploy of v1.3.0 with `landfall request`")
    )]
    pub detail: String,
}

/// Where a verified release came from, as the controller verified it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct OriginView {
    /// The release commit.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = String, example = "0123456789abcdef0123456789abcdef01234567")
    )]
    pub commit: CommitSha,
    /// The image digest its build attested.
    #[cfg_attr(
        feature = "openapi",
        schema(
            value_type = String,
            example = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    )]
    pub digest: ImageDigest,
    /// Who signed its tag, `null` when the deployment doesn't require signed tags.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "operator")
    )]
    pub signer: Option<PrincipalId>,
    /// The workflow identity in the attestation's certificate, quoted. Hostile: escape it
    /// before showing it.
    pub san: String,
    /// The run that built it, quoted. Hostile: escape it before showing it.
    pub run_url: String,
    /// Its attestation's index in the transparency log, if it has one.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<u64>, required = true))]
    pub rekor_log_index: Option<u64>,
    /// When the transparency log took it, in seconds since the Unix epoch, if it did.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub integrated_time: Option<i64>,
}

/// Where a release's commits come from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CommitSource {
    /// GitHub's compare of the release below and this one.
    Github,
    /// A source from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// What is known of a release's commits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum CommitsState {
    /// Listed: all of them when `total` is their count, else the newest 100 of `total`.
    Listed,
    /// Too many for GitHub to list: read them at `compare_url`. Unknown, not empty.
    TooLarge,
    /// The release below isn't an ancestor of this one: the history was rewritten between
    /// them. Unknown, not empty.
    BaseNotFound,
    /// No verified release is below this one: it is the first.
    First,
    /// Not fetched yet. Unknown, not empty.
    NotYet,
    /// GitHub couldn't be asked, and it is tried again later. Unknown, not empty.
    Unavailable,
    /// Never fetched: the release isn't verified under this configuration, or was recorded
    /// before the controller compared commits. Unknown, not empty.
    NotRecorded,
    /// A state from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// One commit, as GitHub lists it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CommitView {
    /// Its id.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = String, example = "0123456789abcdef0123456789abcdef01234567")
    )]
    pub sha: CommitSha,
    /// The first line of its message, quoted and cut at 200 characters. Hostile: escape it
    /// before showing it.
    pub summary: String,
    /// The login GitHub attributes it to by its email, which nothing verifies, or `null`.
    #[cfg_attr(feature = "openapi", schema(required = true, example = "octocat"))]
    pub author: Option<String>,
}

/// The schema of [`CommitsView::verified`]: `false`, always.
#[cfg(feature = "openapi")]
fn always_false() -> utoipa::openapi::Object {
    use utoipa::openapi::extensions::Extensions;
    use utoipa::openapi::schema::{ObjectBuilder, Type};
    // utoipa has no `const`, so it is added as a keyword of its own: the key isn't prefixed
    // with `x-` when the map is built from its items.
    let mut schema = ObjectBuilder::new()
        .schema_type(Type::Boolean)
        .description(Some(
            "Always `false`: GitHub's list is shown as GitHub gave it, and only the release \
             commit itself is verified.",
        ))
        .build();
    schema.extensions = Some(Extensions::from_iter([("const", false)]));
    schema
}

/// The commits a release brings over the verified release below it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct CommitsView {
    /// Where the list comes from.
    pub source: CommitSource,
    /// Always `false`: GitHub's list is shown as GitHub gave it, and only the release commit
    /// itself is verified.
    #[cfg_attr(feature = "openapi", schema(schema_with = always_false))]
    pub verified: bool,
    /// What is known of them. Only `listed` carries commits; every other state but `first`
    /// means unknown, not none.
    pub state: CommitsState,
    /// The verified release below this one, where the list starts, `null` for none.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "v1.2.0")
    )]
    pub base: Option<ReleaseTag>,
    /// How many commits GitHub counts between them, for a listed range: more than `commits`
    /// holds when only the newest 100 are kept.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<u64>, required = true))]
    pub total: Option<u64>,
    /// GitHub's page comparing the two, whenever there is a base.
    #[cfg_attr(
        feature = "openapi",
        schema(
            value_type = Option<String>,
            required = true,
            example = "https://github.com/example/app/compare/0123456789abcdef0123456789abcdef01234567...89abcdef0123456789abcdef0123456789abcdef"
        )
    )]
    pub compare_url: Option<String>,
    /// The commits, newest first: the newest 100 at most.
    pub commits: Vec<CommitView>,
}

/// A request for a release, in its story.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestBrief {
    /// The request's number.
    pub id: i64,
    /// Where it stands.
    pub state: RequestState,
    /// Who asked.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "ci"))]
    pub requested_by: PrincipalId,
    /// Who signed it, `null` unless it was approved.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "operator")
    )]
    pub approved_by: Option<PrincipalId>,
    /// When it was asked, in seconds since the Unix epoch.
    pub created_at: i64,
    /// Why it was closed unsigned, in the controller's words, or `null`.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub closed_reason: Option<String>,
}

/// Where a deploy stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum DeployState {
    /// Waiting for its host to take it.
    Queued,
    /// Its host took it and is running it.
    Claimed,
    /// Its host said how it went.
    Finished,
    /// A state from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// How a finished deploy went, as its host said.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// It runs.
    Deployed,
    /// It failed its checks, and the host went back to what ran before.
    RolledBack,
    /// It stopped before anything changed.
    NothingChanged,
    /// It failed, with nothing to go back to.
    FailedNoPrevious,
    /// It failed, and so did going back.
    RollbackFailed,
    /// The host refused it.
    Refused,
    /// The host said not now.
    Deferred,
    /// An outcome from a newer controller than this client knows. No controller sends it,
    /// and the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A deploy of a release, in its story.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct DeployBrief {
    /// The deploy's number.
    pub id: i64,
    /// Where it stands.
    pub state: DeployState,
    /// How it went, `null` until it finished. `null` with `state` `finished` is an outcome
    /// this controller can't read, recorded by a newer one.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub outcome: Option<Outcome>,
    /// When it was queued, in seconds since the Unix epoch.
    pub created_at: i64,
    /// When it finished, in seconds since the Unix epoch, or `null`.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub finished_at: Option<i64>,
}

/// One release, and why it stands where it does.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ReleaseStory {
    /// The release.
    pub release: ReleaseView,
    /// Why it stands where it does, in order: the controller's words, with hostile text
    /// quoted in them. Escape them before showing them.
    pub reasons: Vec<String>,
    /// What to do next, if anything.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub next: Option<NextAction>,
    /// Where it came from, `null` unless it verified.
    #[cfg_attr(feature = "openapi", schema(required = true))]
    pub origin: Option<OriginView>,
    /// The commits it brings.
    pub commits: CommitsView,
    /// The newest 20 requests for it, newest first.
    pub requests: Vec<RequestBrief>,
    /// The newest 20 deploys of it, newest first.
    pub deploys: Vec<DeployBrief>,
}
