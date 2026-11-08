//! The audit log, as far as a principal may see it.

use landfall_core::ids::{DeploymentId, HostId};
use serde::{Deserialize, Serialize};

/// One row of the audit log. There is no hash: checking the chain is
/// `landfall-server audit verify`'s job, on the controller.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct AuditEntry {
    /// Its place in the log. Numbers are shared by the whole log, so a gap between two rows
    /// is rows this principal can't see.
    pub seq: i64,
    /// When it was written, in seconds since the Unix epoch.
    pub ts: i64,
    /// What it records, such as `deploy_queued`. A newer controller may add kinds. A name this
    /// controller doesn't know, which only someone editing the database writes, is quoted.
    #[cfg_attr(feature = "openapi", schema(example = "deploy_queued"))]
    pub kind: String,
    /// The deployment it is about, or `null` for a row about a host alone.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "app/prod")
    )]
    pub deployment: Option<DeploymentId>,
    /// The host it is about, or `null`: also `null` for a host this principal can't see, as
    /// `getHost` decides.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = Option<String>, required = true, example = "home-1")
    )]
    pub host: Option<HostId>,
    /// The particulars: the fields its kind shows, as the controller recorded them, and
    /// nothing else of what it recorded. A deployment named in it is shown as one this
    /// principal can't view would be, a host they can't see as `null`, and a reason that could
    /// name either is said again in the rule's words, or left out. A kind with nothing to show
    /// has `{}`. A row whose detail isn't a JSON object, which only someone editing the database
    /// makes, reads `{"unreadable": "..."}`, with its first 256 characters quoted. Text from
    /// hosts and GitHub is in here: escape it before showing it.
    #[cfg_attr(feature = "openapi", schema(value_type = Object))]
    pub detail: serde_json::Value,
}
