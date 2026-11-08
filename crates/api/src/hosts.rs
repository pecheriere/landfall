//! The hosts, as far as a principal may see them: through the deployments on each.

use landfall_core::ids::HostId;
use serde::{Deserialize, Serialize};

use crate::DeploymentSummary;

/// A host, with the deployments on it that this principal may view, and only those.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HostView {
    /// The host.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "home-1"))]
    pub id: HostId,
    /// When it enrolled its key, in seconds since the Unix epoch, or `null` if it never has.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub enrolled_at: Option<i64>,
    /// Whether its configuration differs from the controller's.
    pub config_drift: bool,
    /// When it last said anything about one of the deployments listed here, in seconds since
    /// the Unix epoch, or `null` if it hasn't.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<i64>, required = true))]
    pub last_report: Option<i64>,
    /// The deployments on it that this principal may view, by id. The configuration says
    /// which deployment runs on which host.
    pub deployments: Vec<DeploymentSummary>,
}

/// The hosts this principal may see: those the configuration puts a deployment on that they
/// may view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct HostsView {
    /// The hosts, by id.
    pub hosts: Vec<HostView>,
}
