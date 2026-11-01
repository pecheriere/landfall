//! Release facts shared by the controller, the agent and origin verification.

use serde::{Deserialize, Serialize};

/// An image platform, as an OCI image index or Docker manifest list
/// declares it for one of its manifests.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system, for example `linux`.
    pub os: String,
    /// CPU architecture, for example `arm64`.
    pub architecture: String,
    /// CPU variant, for example `v7` for `arm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}
