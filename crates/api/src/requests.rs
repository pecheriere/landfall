//! Asking for a deploy, approving one and cancelling one.

use landfall_core::ids::{CommitSha, DeploymentId, HostId, ImageDigest, PrincipalId, ReleaseTag};
use landfall_core::intent::DeployIntent;
use landfall_core::protocol::{AssertionText, DeployId};
use serde::{Deserialize, Serialize};

/// Exactly what an approver signs, with the same JSON as the intent a host checks.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct IntentView {
    /// The deployment that would change.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "app/prod"))]
    pub deployment: DeploymentId,
    /// The release tag it would run.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "v1.3.0"))]
    pub tag: ReleaseTag,
    /// The commit the tag points at, as verified.
    #[cfg_attr(
        feature = "openapi",
        schema(value_type = String, example = "0123456789abcdef0123456789abcdef01234567")
    )]
    pub commit: CommitSha,
    /// The image digest it would run, as verified.
    #[cfg_attr(
        feature = "openapi",
        schema(
            value_type = String,
            example = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        )
    )]
    pub digest: ImageDigest,
    /// The digest the host must be running when it deploys, `null` for a first deploy.
    #[cfg_attr(feature = "openapi", schema(value_type = Option<String>, required = true))]
    pub expected_running: Option<ImageDigest>,
    /// The one-time value that makes an approval unrepeatable: 64 lowercase hex digits.
    #[cfg_attr(feature = "openapi", schema(pattern = "^[0-9a-f]{64}$"))]
    pub nonce: String,
}

impl From<&DeployIntent> for IntentView {
    fn from(intent: &DeployIntent) -> Self {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let nonce = intent
            .nonce
            .iter()
            .flat_map(|byte| [HEX[usize::from(byte >> 4)], HEX[usize::from(byte & 0xf)]])
            .map(char::from)
            .collect();
        Self {
            deployment: intent.deployment.clone(),
            tag: intent.tag.clone(),
            commit: intent.commit.clone(),
            digest: intent.digest.clone(),
            expected_running: intent.expected_running.clone(),
            nonce,
        }
    }
}

/// Where a request stands. Values are added as answers come to carry them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(rename_all = "snake_case")]
pub enum RequestState {
    /// Waiting for an approver to sign it.
    AwaitingApproval,
    /// Cancelled before anyone signed it.
    Cancelled,
    /// A state from a newer controller than this client knows. No controller sends it, and
    /// the schema leaves it out.
    #[serde(other, skip_serializing)]
    Unknown,
}

/// A request, as a principal may see it, with what a passkey signs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct RequestView {
    /// The request's number.
    pub id: i64,
    /// The host it would deploy on.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "home-1"))]
    pub host: HostId,
    /// What an approver signs.
    pub intent: IntentView,
    /// The intent's `WebAuthn` challenge, in base64url without padding.
    pub challenge: String,
    /// Where it stands.
    pub state: RequestState,
    /// Who asked for it.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "operator"))]
    pub requested_by: PrincipalId,
    /// When it was asked for, in seconds since the Unix epoch.
    pub created_at: i64,
    /// When it ends unless signed, in seconds since the Unix epoch.
    pub expires_at: i64,
    /// Whether this principal could sign it.
    pub can_approve: bool,
    /// Whether this principal could cancel it.
    pub can_cancel: bool,
}

/// What waits for an approver, as far as this principal may see.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct ApprovalsView {
    /// The open requests, at most one for each deployment.
    pub approvals: Vec<RequestView>,
}

/// A request for a deploy: a tag, and nothing the controller would take on trust.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct NewRequest {
    /// The release to deploy.
    #[cfg_attr(feature = "openapi", schema(value_type = String, example = "v1.3.0"))]
    pub tag: ReleaseTag,
}

/// An approval: a passkey's assertion over the request's challenge.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct NewApproval {
    /// The assertion, as the browser gave it.
    pub assertion: AssertionBody,
}

/// A `WebAuthn` assertion, each field in base64url without padding.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
#[serde(deny_unknown_fields)]
pub struct AssertionBody {
    /// The credential that signed.
    pub credential_id: String,
    /// The authenticator's data, as signed.
    pub authenticator_data: String,
    /// The browser's client data, as hashed into the signature.
    pub client_data_json: String,
    /// The signature.
    pub signature: String,
}

impl From<AssertionBody> for AssertionText {
    fn from(body: AssertionBody) -> Self {
        Self {
            credential_id: body.credential_id,
            authenticator_data: body.authenticator_data,
            client_data_json: body.client_data_json,
            signature: body.signature,
        }
    }
}

/// A request that was approved, and the deploy it became.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Approved {
    /// The request's number.
    pub request: i64,
    /// The deploy queued for its host.
    #[cfg_attr(feature = "openapi", schema(value_type = u64))]
    pub deploy_id: DeployId,
}

/// A request that was cancelled.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]
pub struct Cancelled {
    /// The request's number.
    pub request: i64,
    /// Where it stands now: `cancelled`.
    pub state: RequestState,
}
