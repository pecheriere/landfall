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
/// refused before it is parsed, so an agent must keep what it sends under this,
/// reports included: a refused report would be retried forever.
pub const MAX_BODY_BYTES: usize = 1024 * 1024;

/// The content type of a [`Problem`].
pub const PROBLEM_CONTENT_TYPE: &str = "application/problem+json";

/// An error answer from the controller (RFC 9457).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Problem {
    /// Stable, machine-readable, and what a client should act on. Hostile in
    /// the agent: quote and bound it with [`crate::text::shown`] before showing
    /// it.
    pub code: String,
    /// For people; may change. Hostile in the agent like `code`.
    pub title: String,
    /// The HTTP status.
    pub status: u16,
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
    /// The host refused the controller's request without starting it, because
    /// its own configuration or state does not allow it. This is the signal
    /// of a controller asking for something the host doesn't allow (a release
    /// its rule does not make automatic, a downgrade): treat it as an alert.
    Refused {
        /// Why the host refused.
        reason: String,
    },
}

/// The most checks one [`ReportedDetail::Checks`] may list.
pub const MAX_REPORTED_CHECKS: usize = 64;

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

/// Serde adapter: a list of at most [`MAX_REPORTED_CHECKS`] checks.
mod bounded_checks {
    use super::{Deserialize, Deserializer, MAX_REPORTED_CHECKS, ReportedCheck};

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(
        d: D,
    ) -> Result<Vec<ReportedCheck>, D::Error> {
        let checks = Vec::<ReportedCheck>::deserialize(d)?;
        if checks.len() > MAX_REPORTED_CHECKS {
            return Err(serde::de::Error::custom("too many checks"));
        }
        Ok(checks)
    }
}

/// More about a step, for the steps that have more to say.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReportedDetail {
    /// A run of the post-deploy checks, at most [`MAX_REPORTED_CHECKS`].
    Checks {
        /// One per check, in configuration order.
        #[serde(deserialize_with = "bounded_checks::deserialize")]
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
    /// How it ended.
    pub outcome: ReportedOutcome,
    /// Every step, in order.
    pub steps: Vec<ReportedStep>,
}

#[cfg(test)]
mod tests {
    use serde_json::{Value, json};
    use sha2::{Digest, Sha256};

    use super::{
        DeployId, DeployReportBody, DeployWork, DeployedRelease, EnrolCode, EnrolRequest, HeldBack,
        MAX_REPORTED_CHECKS, Nonce, NonceResponse, Phase, Problem, ReportedCheck, ReportedDetail,
        ReportedOutcome, ReportedStep, RequestSignature, RunningState, SignatureError, SigningKey,
        VerifyingKey, WorkRequest, WorkResponse, sign, signing_bytes, verify,
    };
    use crate::hex;
    use crate::ids::HostId;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(byte: u8) -> Nonce {
        Nonce::from_bytes([byte; 32])
    }

    fn host(name: &str) -> HostId {
        name.parse().unwrap()
    }

    fn identity_key_bytes() -> [u8; 32] {
        let mut bytes = [0_u8; 32];
        bytes[0] = 1;
        bytes
    }

    #[test]
    fn signature_covers_host_method_path_nonce_and_body() {
        let k = key(1);
        let h = host("host-a");
        let sig = sign(&k, &h, "POST", "/agent/v1/work", &nonce(2), b"{}");
        let public = k.verifying_key();
        assert_eq!(
            verify(
                &public,
                &sig,
                &h,
                "POST",
                "/agent/v1/work",
                &nonce(2),
                b"{}"
            ),
            Ok(())
        );
        let other = host("host-b");
        let cases: [(&HostId, &str, &str, Nonce, &[u8]); 6] = [
            (&other, "POST", "/agent/v1/work", nonce(2), b"{}"),
            (&h, "GET", "/agent/v1/work", nonce(2), b"{}"),
            (&h, "POST", "/agent/v1/report", nonce(2), b"{}"),
            (&h, "POST", "/agent/v1/work?a=1", nonce(2), b"{}"),
            (&h, "POST", "/agent/v1/work", nonce(3), b"{}"),
            (&h, "POST", "/agent/v1/work", nonce(2), b"{ }"),
        ];
        for (host, method, path, n, body) in cases {
            assert_eq!(
                verify(&public, &sig, host, method, path, &n, body),
                Err(SignatureError::Invalid),
                "{host} {method} {path} {n} {body:?}"
            );
        }
    }

    #[test]
    fn signing_bytes_has_a_pinned_layout() {
        let mut expected = Vec::new();
        let mut field = |bytes: &[u8]| {
            expected.extend_from_slice(&u64::try_from(bytes.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(bytes);
        };
        field(b"landfall-agent-v1");
        field(b"host-a");
        field(b"POST");
        field(b"/agent/v1/work");
        field(&[7; 32]);
        field(&Sha256::digest(b"body"));
        assert_eq!(
            signing_bytes(
                &host("host-a"),
                "POST",
                "/agent/v1/work",
                &nonce(7),
                b"body"
            ),
            expected
        );
    }

    #[test]
    fn signing_bytes_cannot_be_confused_across_fields() {
        let h = host("host-a");
        let n = nonce(9);
        let body = b"x";
        let mut seen = vec![signing_bytes(&h, "GET", "/a", &n, body)];
        // Newlines, and text that looks like the neighbouring field, moved
        // across every boundary.
        let attempts = [
            ("GET\n/a", ""),
            ("GET", "/a\n"),
            ("GET\n", "/a"),
            ("GET", "/a\n/b"),
            ("", "GET\n/a"),
            ("GET/a", ""),
        ];
        for (method, path) in attempts {
            let bytes = signing_bytes(&h, method, path, &n, body);
            assert!(!seen.contains(&bytes), "{method:?} {path:?}");
            seen.push(bytes);
        }
        // A path that spells out the nonce and body hash cannot stand in for
        // the real fields.
        let forged_path = format!("/a\n{n}\n{}", hex::encode(&Sha256::digest(body)));
        let bytes = signing_bytes(&h, "GET", &forged_path, &nonce(0), b"");
        assert!(!seen.contains(&bytes));
        // Nor can the host id and the method trade bytes.
        let bytes = signing_bytes(&host("host-ag"), "ET", "/a", &n, body);
        assert!(!seen.contains(&bytes));
    }

    #[test]
    fn signature_from_another_key_is_refused() {
        let h = host("h");
        let sig = sign(&key(1), &h, "GET", "/p", &nonce(1), b"");
        assert_eq!(
            verify(
                &key(2).verifying_key(),
                &sig,
                &h,
                "GET",
                "/p",
                &nonce(1),
                b""
            ),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn a_weak_key_with_a_trivial_signature_is_refused() {
        // The identity point as key and as R, with s = 0, satisfies the plain
        // Ed25519 equation for every message. Strict verification refuses it.
        let weak = VerifyingKey::from_bytes(&identity_key_bytes()).unwrap();
        assert!(weak.is_weak());
        let mut raw = [0_u8; 64];
        raw[..32].copy_from_slice(&identity_key_bytes());
        let sig = RequestSignature::from_bytes(raw);
        assert_eq!(
            verify(&weak, &sig, &host("h"), "GET", "/p", &nonce(1), b""),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn a_non_canonical_scalar_is_refused() {
        // s + L is the same scalar modulo the group order, so a lax verifier
        // accepts a second encoding of every signature.
        const L: [u8; 32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x10,
        ];
        let k = key(3);
        let h = host("h");
        let sig = sign(&k, &h, "GET", "/p", &nonce(1), b"");
        let public = k.verifying_key();
        assert_eq!(
            verify(&public, &sig, &h, "GET", "/p", &nonce(1), b""),
            Ok(())
        );

        let mut raw = *sig.as_bytes();
        let mut carry = 0_u16;
        for (s, l) in raw[32..].iter_mut().zip(L) {
            let sum = u16::from(*s) + u16::from(l) + carry;
            *s = u8::try_from(sum & 0xff).unwrap();
            carry = sum >> 8;
        }
        assert_eq!(carry, 0);
        assert_eq!(
            verify(
                &public,
                &RequestSignature::from_bytes(raw),
                &h,
                "GET",
                "/p",
                &nonce(1),
                b""
            ),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn signature_and_nonce_round_trip_through_their_text_form() {
        let sig = sign(&key(1), &host("h"), "GET", "/p", &nonce(1), b"");
        let text = sig.to_string();
        assert_eq!(text.len(), 128);
        assert_eq!(text.parse::<RequestSignature>(), Ok(sig));
        assert_eq!(nonce(0xab).to_string(), "ab".repeat(32));
        assert_eq!("ab".repeat(32).parse::<Nonce>(), Ok(nonce(0xab)));
        for bad in [
            "",
            "AB",
            &"ab".repeat(31),
            &"ab".repeat(33),
            &"zz".repeat(32),
        ] {
            assert!(bad.parse::<Nonce>().is_err(), "{bad:?}");
        }
        assert!("ab".repeat(63).parse::<RequestSignature>().is_err());
    }

    fn code() -> EnrolCode {
        EnrolCode::from_bytes([0x5e; 32])
    }

    #[test]
    fn debug_of_secrets_is_redacted() {
        let req = EnrolRequest {
            code: code(),
            host: host("host-1"),
            public_key: key(1).verifying_key(),
        };
        for text in [format!("{:?}", code()), format!("{req:?}")] {
            assert!(!text.contains("5e5e") && !text.contains("94, 94"), "{text}");
        }
        // The signing key's own Debug must not print the seed either.
        let seed_hex = hex::encode(&[0x42; 32]);
        let dbg = format!("{:?}", key(0x42));
        assert!(!dbg.contains(&seed_hex) && !dbg.contains("66, 66"), "{dbg}");
    }

    fn running_state() -> RunningState {
        RunningState {
            deployment: "app/prod".parse().unwrap(),
            deployed: Some(DeployedRelease {
                tag: "v1.2.4".parse().unwrap(),
                digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            }),
            drift: false,
            phase: Phase::Idle,
            busy: false,
        }
    }

    fn work_request() -> WorkRequest {
        WorkRequest {
            config_hash: [5; 32],
            running: vec![running_state()],
        }
    }

    fn work_response() -> WorkResponse {
        WorkResponse {
            work: Some(DeployWork {
                deploy_id: DeployId(7),
                deployment: "app/prod".parse().unwrap(),
                tag: "v1.2.5".parse().unwrap(),
                digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
                commit: "a".repeat(40).parse().unwrap(),
            }),
            held_back: vec![HeldBack {
                deployment: "app/stage".parse().unwrap(),
                reason: "config hash differs".to_owned(),
            }],
        }
    }

    fn step(failure: Option<&str>, detail: Option<ReportedDetail>) -> ReportedStep {
        ReportedStep {
            name: "checks".to_owned(),
            millis: 9000,
            failure: failure.map(str::to_owned),
            detail,
        }
    }

    fn report() -> DeployReportBody {
        DeployReportBody {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::RolledBack {
                reason: "health check failed".to_owned(),
            },
            steps: vec![
                step(
                    None,
                    Some(ReportedDetail::Backup {
                        files: 3,
                        directories: 2,
                        symlinks: 1,
                        bytes: 4096,
                    }),
                ),
                step(
                    Some("unhealthy"),
                    Some(ReportedDetail::Checks {
                        checks: vec![ReportedCheck {
                            check: "http 200".to_owned(),
                            attempts: 3,
                            millis: 1500,
                        }],
                    }),
                ),
            ],
        }
    }

    fn enrol() -> EnrolRequest {
        EnrolRequest {
            code: code(),
            host: host("host-1"),
            public_key: key(1).verifying_key(),
        }
    }

    fn all_outcomes() -> Vec<(ReportedOutcome, Value)> {
        let r = || "why".to_owned();
        vec![
            (ReportedOutcome::Deployed {}, json!({"kind": "deployed"})),
            (
                ReportedOutcome::RolledBack { reason: r() },
                json!({"kind": "rolled_back", "reason": "why"}),
            ),
            (
                ReportedOutcome::NothingChanged { reason: r() },
                json!({"kind": "nothing_changed", "reason": "why"}),
            ),
            (
                ReportedOutcome::FailedNoPrevious { reason: r() },
                json!({"kind": "failed_no_previous", "reason": "why"}),
            ),
            (
                ReportedOutcome::RollbackFailed {
                    reason: r(),
                    rollback_reason: "again".to_owned(),
                },
                json!({"kind": "rollback_failed", "reason": "why", "rollback_reason": "again"}),
            ),
            (
                ReportedOutcome::Refused { reason: r() },
                json!({"kind": "refused", "reason": "why"}),
            ),
        ]
    }

    #[test]
    fn round_trips_through_json() {
        fn check<T>(value: &T)
        where
            T: serde::Serialize + serde::de::DeserializeOwned + PartialEq + std::fmt::Debug,
        {
            let json = serde_json::to_string(value).unwrap();
            assert_eq!(&serde_json::from_str::<T>(&json).unwrap(), value, "{json}");
        }
        check(&work_request());
        check(&work_response());
        check(&WorkResponse {
            work: None,
            held_back: Vec::new(),
        });
        check(&report());
        for (outcome, _) in all_outcomes() {
            check(&outcome);
        }
        check(&step(None, None));
        check(&NonceResponse { nonce: nonce(1) });
        check(&Problem {
            code: "bad_nonce".to_owned(),
            title: "the nonce is unknown, used or expired".to_owned(),
            status: 401,
        });

        // EnrolRequest has no equality (its code is a secret): compare the
        // wire form after a round trip.
        let wire = serde_json::to_value(enrol()).unwrap();
        let back: EnrolRequest = serde_json::from_value(wire.clone()).unwrap();
        assert_eq!(serde_json::to_value(back).unwrap(), wire);
        assert_eq!(wire["code"], "5e".repeat(32));
        assert_eq!(
            wire["public_key"],
            hex::encode(key(1).verifying_key().as_bytes())
        );

        let json = serde_json::to_value(work_request()).unwrap();
        assert_eq!(json["config_hash"], "05".repeat(32));
    }

    #[test]
    fn wire_strings_are_pinned() {
        for (outcome, want) in all_outcomes() {
            assert_eq!(serde_json::to_value(&outcome).unwrap(), want);
        }
        for (phase, want) in [
            (Phase::Idle, "idle"),
            (Phase::Preflight, "preflight"),
            (Phase::Deploying, "deploying"),
            (Phase::RollingBack, "rolling_back"),
            (Phase::Restored, "restored"),
            (Phase::RolledBack, "rolled_back"),
        ] {
            assert_eq!(serde_json::to_value(phase).unwrap(), want);
        }
        let checks = ReportedDetail::Checks { checks: Vec::new() };
        assert_eq!(
            serde_json::to_value(checks).unwrap(),
            json!({"kind": "checks", "checks": []})
        );
        assert_eq!(
            serde_json::to_value(step(None, None)).unwrap(),
            json!({"name": "checks", "millis": 9000, "failure": null})
        );
    }

    #[test]
    fn a_blocked_first_deploy_differs_from_never_deployed() {
        let never = RunningState {
            deployed: None,
            ..running_state()
        };
        let blocked = RunningState {
            deployed: None,
            phase: Phase::Preflight,
            busy: false,
            ..running_state()
        };
        assert_ne!(never, blocked);
        for state in [&never, &blocked] {
            let wire = serde_json::to_value(state).unwrap();
            assert!(wire["deployed"].is_null());
            assert_eq!(
                &serde_json::from_value::<RunningState>(wire).unwrap(),
                state
            );
        }
        // The key may not be omitted.
        let mut wire = serde_json::to_value(&blocked).unwrap();
        wire.as_object_mut().unwrap().remove("deployed");
        assert!(serde_json::from_value::<RunningState>(wire).is_err());
    }

    #[test]
    fn null_keys_must_be_present() {
        let mut wire = serde_json::to_value(WorkResponse {
            work: None,
            held_back: Vec::new(),
        })
        .unwrap();
        assert!(wire["work"].is_null());
        wire.as_object_mut().unwrap().remove("work");
        assert!(serde_json::from_value::<WorkResponse>(wire).is_err());

        let mut wire = serde_json::to_value(step(None, None)).unwrap();
        assert!(wire["failure"].is_null());
        wire.as_object_mut().unwrap().remove("failure");
        assert!(serde_json::from_value::<ReportedStep>(wire).is_err());
    }

    #[test]
    fn unknown_fields_are_refused() {
        fn refuses<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) {
            let mut v = serde_json::to_value(value).unwrap();
            v.as_object_mut()
                .unwrap()
                .insert("extra".to_owned(), Value::Null);
            assert!(serde_json::from_value::<T>(v).is_err());
        }
        refuses(&work_request());
        refuses(&work_response());
        refuses(&report());
        refuses(&enrol());
        for (outcome, _) in all_outcomes() {
            refuses(&outcome);
        }

        // And in nested values.
        let mut v = serde_json::to_value(work_response()).unwrap();
        v["work"]["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<WorkResponse>(v).is_err());
        let mut v = serde_json::to_value(work_request()).unwrap();
        v["running"][0]["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<WorkRequest>(v).is_err());
        let mut v = serde_json::to_value(work_request()).unwrap();
        v["running"][0]["deployed"]["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<WorkRequest>(v).is_err());
        let mut v = serde_json::to_value(report()).unwrap();
        v["steps"][0]["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
        let mut v = serde_json::to_value(report()).unwrap();
        v["steps"][0]["detail"]["extra"] = Value::Bool(true);
        assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
    }

    #[test]
    fn hostile_values_are_refused() {
        let mut v = serde_json::to_value(work_response()).unwrap();
        v["work"]["tag"] = Value::String("v1\n".to_owned());
        assert!(serde_json::from_value::<WorkResponse>(v).is_err());
        let mut v = serde_json::to_value(work_request()).unwrap();
        v["config_hash"] = Value::String("05".repeat(31));
        assert!(serde_json::from_value::<WorkRequest>(v).is_err());
        let mut v = serde_json::to_value(enrol()).unwrap();
        v["public_key"] = Value::String("00".repeat(31));
        assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
        let mut v = serde_json::to_value(enrol()).unwrap();
        v["code"] = Value::String("5E".repeat(32));
        assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
        let mut v = serde_json::to_value(enrol()).unwrap();
        v["code"] = Value::String("x".to_owned());
        assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
    }

    #[test]
    fn a_weak_enrolment_key_is_refused() {
        let mut v = serde_json::to_value(enrol()).unwrap();
        v["public_key"] = Value::String(hex::encode(&identity_key_bytes()));
        assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
    }

    #[test]
    fn too_many_checks_are_refused() {
        let check = ReportedCheck {
            check: "c".to_owned(),
            attempts: 1,
            millis: 1,
        };
        for (count, ok) in [
            (MAX_REPORTED_CHECKS, true),
            (MAX_REPORTED_CHECKS + 1, false),
        ] {
            let detail = ReportedDetail::Checks {
                checks: vec![check.clone(); count],
            };
            let wire = serde_json::to_value(&detail).unwrap();
            assert_eq!(serde_json::from_value::<ReportedDetail>(wire).is_ok(), ok);
        }
    }
}
