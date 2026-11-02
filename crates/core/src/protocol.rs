//! The agent protocol: wire types and request signing.
//!
//! The agent connects out to the controller and signs every request with its
//! Ed25519 key. A request carries three headers, [`HOST_HEADER`],
//! [`NONCE_HEADER`] and [`SIGNATURE_HEADER`]. The nonce is single-use and
//! issued by the controller, so a host without a clock can still sign. The
//! signature covers [`signing_bytes`]: the host id, the method, the path, the
//! nonce and a hash of the body. The host header only selects which key to
//! check; because the host id is signed too, a signature made for one host
//! never verifies for another.
//!
//! The path is signed exactly as sent, so when the request has a query
//! string it is part of what is signed: `/p?a=1` does not verify against `/p`.
//!
//! This is a wire contract between controller and agent: [`signing_bytes`]
//! and the JSON shapes never change without bumping the domain tag.
//!
//! Everything an agent or a controller sends is hostile to the other side:
//! free text in these types ([`HeldBack::reason`], [`ReportedOutcome`]'s
//! reasons, [`ReportedStep`]) must be quoted and truncated with
//! [`crate::text::shown`] before it reaches a log or an error, and bounded
//! before it is stored.

use std::fmt;
use std::str::FromStr;

use ed25519_dalek::{Signature, Signer};
pub use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::hex;
use crate::ids::{CommitSha, DeploymentId, HostId, ImageDigest, ReleaseTag};

#[cfg(test)]
mod tests;

/// Header naming the host that signed the request.
pub const HOST_HEADER: &str = "Landfall-Host";

/// Header carrying the single-use [`Nonce`] the request was signed under.
pub const NONCE_HEADER: &str = "Landfall-Nonce";

/// Header carrying the [`RequestSignature`], 128 hex digits.
pub const SIGNATURE_HEADER: &str = "Landfall-Signature";

/// Domain-separation tag of the signed bytes.
const DOMAIN: &[u8] = b"landfall-agent-v1";

/// Text that is not the expected number of lowercase hex digits.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("{what} must be exactly {digits} lowercase hex digits")]
#[non_exhaustive]
pub struct HexError {
    what: &'static str,
    digits: usize,
}

/// A fixed-size byte string written as lowercase hex in text and JSON.
macro_rules! hex_bytes {
    ($(#[$meta:meta])* $name:ident, $len:literal, $what:literal) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq)]
        pub struct $name([u8; $len]);

        impl $name {
            /// Wraps raw bytes.
            #[must_use]
            pub const fn from_bytes(bytes: [u8; $len]) -> Self {
                Self(bytes)
            }

            /// The raw bytes.
            #[must_use]
            pub const fn as_bytes(&self) -> &[u8; $len] {
                &self.0
            }
        }

        impl FromStr for $name {
            type Err = HexError;

            fn from_str(text: &str) -> Result<Self, HexError> {
                hex::decode(text).map(Self).ok_or(HexError {
                    what: $what,
                    digits: $len * 2,
                })
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&hex::encode(&self.0))
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
                s.collect_str(self)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                String::deserialize(d)?
                    .parse()
                    .map_err(serde::de::Error::custom)
            }
        }
    };
}

hex_bytes!(
    /// A single-use value issued by the controller: 32 random bytes, hex on
    /// the wire. Core takes it as a value and draws no randomness.
    Nonce, 32, "nonce"
);

hex_bytes!(
    /// An Ed25519 signature over [`signing_bytes`], hex on the wire.
    RequestSignature, 64, "signature"
);

impl fmt::Debug for Nonce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Nonce({self})")
    }
}

impl fmt::Debug for RequestSignature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "RequestSignature({self})")
    }
}

/// Why a signature was not accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum SignatureError {
    /// The signature does not match this key, host, method, path, nonce and
    /// body.
    #[error("request signature does not verify")]
    Invalid,
}

/// Appends `field` as an 8-byte big-endian length followed by its bytes.
///
/// The host id is bounded by its type but the method and path are chosen by
/// the sender, so the length is a full `u64`. A `usize` is never wider than
/// 64 bits, so the conversion cannot fail and no length is truncated.
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let len = u64::try_from(field.len()).unwrap_or(u64::MAX);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(field);
}

/// The bytes a request signature covers: the ASCII bytes `landfall-agent-v1`
/// as a field, then `host`, `method`, `path`, the nonce's 32 raw bytes and the
/// 32-byte SHA-256 of `body`, each as a field. A field is an 8-byte
/// big-endian length and its bytes, so no value, newline or otherwise, can
/// shift bytes into a neighbouring field.
///
/// `method` and `path` are taken exactly as sent: the verifier must pass the
/// request's own method and raw path including the query string if there is
/// one, not a normalised form.
#[must_use]
pub fn signing_bytes(
    host: &HostId,
    method: &str,
    path: &str,
    nonce: &Nonce,
    body: &[u8],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + method.len() + path.len() + 160);
    push_field(&mut out, DOMAIN);
    push_field(&mut out, host.as_ref().as_bytes());
    push_field(&mut out, method.as_bytes());
    push_field(&mut out, path.as_bytes());
    push_field(&mut out, nonce.as_bytes());
    push_field(&mut out, &Sha256::digest(body));
    out
}

/// Signs a request.
#[must_use]
pub fn sign(
    key: &SigningKey,
    host: &HostId,
    method: &str,
    path: &str,
    nonce: &Nonce,
    body: &[u8],
) -> RequestSignature {
    let signature = key.sign(&signing_bytes(host, method, path, nonce, body));
    RequestSignature(signature.to_bytes())
}

/// Checks a request signature. Uses strict verification, which also refuses
/// weak (small-order) keys and the malleable encodings plain Ed25519 accepts.
///
/// # Errors
///
/// [`SignatureError::Invalid`] if `signature` is not `key`'s signature over
/// exactly this host, method, path, nonce and body.
pub fn verify(
    key: &VerifyingKey,
    signature: &RequestSignature,
    host: &HostId,
    method: &str,
    path: &str,
    nonce: &Nonce,
    body: &[u8],
) -> Result<(), SignatureError> {
    key.verify_strict(
        &signing_bytes(host, method, path, nonce, body),
        &Signature::from_bytes(signature.as_bytes()),
    )
    .map_err(|_| SignatureError::Invalid)
}

/// Serde adapter: a 32-byte value as exactly 64 lowercase hex digits.
mod hash_hex {
    use super::{Deserialize, Deserializer, Serializer, hex};

    pub(super) fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(&text)
            .ok_or_else(|| serde::de::Error::custom("expected 64 lowercase hex digits"))
    }
}

/// Serde adapter: an Ed25519 public key as 64 lowercase hex digits. A weak
/// (small-order) key is refused: it would verify signatures nobody made.
mod key_hex {
    use super::{Deserialize, Deserializer, Serializer, VerifyingKey, hex};

    pub(super) fn serialize<S: Serializer>(key: &VerifyingKey, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(key.as_bytes()))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<VerifyingKey, D::Error> {
        let text = String::deserialize(d)?;
        let bytes: [u8; 32] = hex::decode(&text).ok_or_else(|| {
            serde::de::Error::custom("public key must be 64 lowercase hex digits")
        })?;
        let key = VerifyingKey::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("not a valid Ed25519 public key"))?;
        if key.is_weak() {
            return Err(serde::de::Error::custom("weak Ed25519 public key"));
        }
        Ok(key)
    }
}

/// A one-time enrolment code: 32 random bytes, 64 lowercase hex digits in
/// text and JSON. Its `Debug` is redacted and it has no equality: the
/// controller stores only its SHA-256 and compares hashes.
#[derive(Clone)]
pub struct EnrolCode([u8; 32]);

impl EnrolCode {
    /// Wraps the code's raw bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The raw bytes. Callers must not log them.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The code as the operator is given it: 64 lowercase hex digits. Callers
    /// must not log it.
    #[must_use]
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
}

impl FromStr for EnrolCode {
    type Err = HexError;

    fn from_str(text: &str) -> Result<Self, HexError> {
        hex::decode(text).map(Self).ok_or(HexError {
            what: "enrolment code",
            digits: 64,
        })
    }
}

impl fmt::Debug for EnrolCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrolCode(<redacted>)")
    }
}

impl Serialize for EnrolCode {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_hex())
    }
}

impl<'de> Deserialize<'de> for EnrolCode {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// `POST /agent/v1/enrol`: the host's public key and the code that binds it
/// to one host id.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    /// The one-time code from `enrol-code`.
    pub code: EnrolCode,
    /// The host the code was issued for.
    pub host: HostId,
    /// The key the host will sign with, 64 hex digits. A weak key does not
    /// parse.
    #[serde(with = "key_hex")]
    pub public_key: VerifyingKey,
}

/// `GET /agent/v1/nonce`: a nonce to sign the next request under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NonceResponse {
    /// The nonce: single-use, and valid for 5 minutes by the controller's clock.
    pub nonce: Nonce,
}

/// The most bytes the controller reads of a request body. A larger one is
/// refused before it is parsed. This is the only size limit on a report, so the
/// agent trims a report to fit before sending it: refused for its size, it would
/// never get through.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The content type of a [`Problem`].
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// An error answer from the controller (RFC 9457).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    /// Stable, machine-readable, and what a client should act on: see
    /// [`ProblemCode::parse`]. Hostile in the agent: quote and bound it with
    /// [`crate::text::shown`] before showing it.
    pub code: String,
    /// For people; may change. Hostile in the agent like `code`.
    pub title: String,
    /// The HTTP status.
    pub status: u16,
}

/// What a client should do about a [`Problem`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Disposition {
    /// Try again later, with a fresh nonce: the refusal is about now, and not
    /// about the request.
    Retry,
    /// The same request will be refused every time. Retrying cannot help.
    Final,
}

/// The stable codes in a [`Problem`]. They are a wire contract: a code never
/// changes its meaning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum ProblemCode {
    /// A signature header is missing, repeated or malformed.
    Unsigned,
    /// The nonce is unknown, used or expired: fetch another.
    BadNonce,
    /// The host is unknown or the signature does not verify.
    BadSignature,
    /// The enrolment code is unknown, used, expired or for another host.
    InvalidCode,
    /// The host has a key and the code does not allow replacing it.
    AlreadyEnrolled,
    /// Another host has this public key.
    KeyInUse,
    /// The body is not the request this endpoint takes.
    BadRequest,
    /// The body is over [`MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The request took too long.
    SlowRequest,
    /// This source is asking too often.
    RateLimited,
    /// Too many nonces are outstanding.
    NoncesExhausted,
    /// The database is busy with another writer.
    Busy,
    /// The host has no such deploy.
    UnknownDeploy,
    /// The deploy was never handed to this host.
    NotClaimed,
    /// The controller failed.
    Internal,
}

impl ProblemCode {
    /// The code as the wire has it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsigned => "unsigned",
            Self::BadNonce => "bad_nonce",
            Self::BadSignature => "bad_signature",
            Self::InvalidCode => "invalid_code",
            Self::AlreadyEnrolled => "already_enrolled",
            Self::KeyInUse => "key_in_use",
            Self::BadRequest => "bad_request",
            Self::BodyTooLarge => "body_too_large",
            Self::SlowRequest => "slow_request",
            Self::RateLimited => "rate_limited",
            Self::NoncesExhausted => "nonces_exhausted",
            Self::Busy => "busy",
            Self::UnknownDeploy => "unknown_deploy",
            Self::NotClaimed => "not_claimed",
            Self::Internal => "internal",
        }
    }

    /// The code named by `text`, or `None` for one this build does not know.
    /// Agent and controller are upgraded together, so that means the answer did
    /// not come from a controller: treat it as [`Disposition::Retry`].
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Unsigned,
            Self::BadNonce,
            Self::BadSignature,
            Self::InvalidCode,
            Self::AlreadyEnrolled,
            Self::KeyInUse,
            Self::BadRequest,
            Self::BodyTooLarge,
            Self::SlowRequest,
            Self::RateLimited,
            Self::NoncesExhausted,
            Self::Busy,
            Self::UnknownDeploy,
            Self::NotClaimed,
            Self::Internal,
        ]
        .into_iter()
        .find(|code| code.as_str() == text)
    }

    /// What a client should do about this code.
    #[must_use]
    pub const fn disposition(self) -> Disposition {
        match self {
            Self::BadNonce
            | Self::SlowRequest
            | Self::RateLimited
            | Self::NoncesExhausted
            | Self::Busy
            | Self::Internal => Disposition::Retry,
            Self::Unsigned
            | Self::BadSignature
            | Self::InvalidCode
            | Self::AlreadyEnrolled
            | Self::KeyInUse
            | Self::BadRequest
            | Self::BodyTooLarge
            | Self::UnknownDeploy
            | Self::NotClaimed => Disposition::Final,
        }
    }
}

/// A controller-assigned deploy identifier. Reports are idempotent by it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct DeployId(pub u64);

impl fmt::Display for DeployId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Where a deployment's in-progress marker stands on the host. These are the
/// agent's own marker phases, plus [`Self::Idle`] for no marker.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Phase {
    /// No marker: nothing is in progress or waiting to be recovered.
    Idle,
    /// Checking the project and pulling the image; no service has been
    /// touched.
    Preflight,
    /// Going forward; the service may have been touched.
    Deploying,
    /// Going back after a failure.
    RollingBack,
    /// Going back, and the backup is restored in full; the previous version
    /// is still to be started and checked.
    Restored,
    /// Back, and checked; only the marker is left to remove.
    RolledBack,
}

/// The release a host last deployed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployedRelease {
    /// The release tag.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
}

/// One deployment as the host sees it. A request lists every deployment the
/// host has, always.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningState {
    /// The deployment.
    pub deployment: DeploymentId,
    /// What the host last deployed. The key must be present: `null` means the
    /// deployment has never been deployed, which is not the same as a first
    /// deploy that is in progress or blocked (see `phase`).
    #[serde(deserialize_with = "Option::deserialize")]
    pub deployed: Option<DeployedRelease>,
    /// Whether the running container differs from what the agent deployed.
    pub drift: bool,
    /// Where the in-progress marker stands.
    pub phase: Phase,
    /// Whether the agent is running that deploy right now. With a `phase`
    /// other than idle, `false` means the deploy was interrupted and waits
    /// for recovery.
    pub busy: bool,
}

/// `POST /agent/v1/work`: ask for work, stating the config and the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRequest {
    /// SHA-256 of the agent's configuration, 64 hex digits.
    #[serde(with = "hash_hex")]
    pub config_hash: [u8; 32],
    /// Every deployment of the host.
    pub running: Vec<RunningState>,
}

/// One release the controller asks the host to deploy. The host decides for
/// itself whether it may.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployWork {
    /// The controller's id for this deploy.
    pub deploy_id: DeployId,
    /// The deployment to change.
    pub deployment: DeploymentId,
    /// The release tag.
    pub tag: ReleaseTag,
    /// The image digest to run.
    pub digest: ImageDigest,
    /// The commit the tag points at.
    pub commit: CommitSha,
}

/// A deployment the controller is not deploying to, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeldBack {
    /// The deployment.
    pub deployment: DeploymentId,
    /// Why, in the controller's words. Hostile in the agent: quote and bound
    /// it with [`crate::text::shown`] before showing it.
    pub reason: String,
}

/// The answer to a [`WorkRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkResponse {
    /// The next deploy, if there is one. The key must be present: `null`
    /// means no work, and an omitted key is an error, so a truncated payload
    /// is never read as "nothing to do".
    #[serde(deserialize_with = "Option::deserialize")]
    pub work: Option<DeployWork>,
    /// Deployments that have a release waiting but are not being deployed to.
    pub held_back: Vec<HeldBack>,
}

/// How a deploy that started, or a request that was refused, ended, as the
/// agent reports it. Every reason is the agent's own text and hostile to the
/// controller: quote and bound it with [`crate::text::shown`], and bound it
/// before storing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReportedOutcome {
    /// The release is running and passed its checks.
    Deployed {},
    /// The deploy failed; the previous version is back.
    RolledBack {
        /// Why the deploy failed.
        reason: String,
    },
    /// The deploy was interrupted before it touched the service.
    NothingChanged {
        /// Why the deploy did not go ahead.
        reason: String,
    },
    /// The deploy failed and there is no previous version to start.
    FailedNoPrevious {
        /// Why the deploy failed.
        reason: String,
    },
    /// The deploy and its rollback both failed; deploys stay blocked.
    RollbackFailed {
        /// Why the deploy failed.
        reason: String,
        /// Why the rollback failed.
        rollback_reason: String,
    },
    /// The host refused the controller's request for good, without starting it:
    /// its rule does not allow it, verification failed on it, or it is on the
    /// host's record of failures. This is the signal of a controller asking for
    /// something the host doesn't allow: treat it as an alert.
    Refused {
        /// Why the host refused.
        reason: String,
    },
    /// Not now: the host did not start it, for a cause that may pass (a deploy
    /// that did not finish, drift, what it could not read, its clock behind the
    /// release, a wait for verification past its bound). The controller may ask
    /// again later, and the host judges it again then.
    Deferred {
        /// Why not now.
        reason: String,
    },
}

/// What one post-deploy check took.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedCheck {
    /// The check's description; hostile text.
    pub check: String,
    /// How many times it was evaluated.
    pub attempts: u32,
    /// Time spent evaluating it, in milliseconds.
    pub millis: u64,
}

/// More about a step, for the steps that have more to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReportedDetail {
    /// A run of the post-deploy checks. Their number is not limited here: the
    /// configuration does not limit it, and refusing the report would leave the
    /// deploy unfinished. The controller bounds what it stores.
    Checks {
        /// One per check, in configuration order.
        checks: Vec<ReportedCheck>,
    },
    /// A backup that completed.
    Backup {
        /// Regular files copied.
        files: u64,
        /// Directories copied.
        directories: u64,
        /// Symlinks copied.
        symlinks: u64,
        /// Bytes of file content copied.
        bytes: u64,
    },
}

/// One step of a deploy, as the agent reports it. Its text is hostile to the
/// controller: quote and bound it with [`crate::text::shown`] and bound it
/// before storing it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedStep {
    /// What was done.
    pub name: String,
    /// How long it took.
    pub millis: u64,
    /// Why it failed; `null` if it did what it should. The key must be
    /// present, so a truncated step is never read as a success.
    #[serde(deserialize_with = "Option::deserialize")]
    pub failure: Option<String>,
    /// More about the step, when it has more to say; omitted otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ReportedDetail>,
}

/// `POST /agent/v1/report`: the record of a finished deploy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployReportBody {
    /// The deploy being reported.
    pub deploy_id: DeployId,
    /// The deployment it was of. With `tag` and `digest` this says what ended: a
    /// controller restored from a backup hands out numbers again, and a number alone
    /// can't tell a late report from the deploy now under it.
    pub deployment: DeploymentId,
    /// The release it was of.
    pub tag: ReleaseTag,
    /// That release's image digest.
    pub digest: ImageDigest,
    /// How it ended.
    pub outcome: ReportedOutcome,
    /// Every step, in order.
    pub steps: Vec<ReportedStep>,
}
