//! The agent protocol: wire types and request signing.
//!
//! The agent connects out to the controller and signs every request with its
//! Ed25519 key. A request carries three headers, [`HOST_HEADER`],
//! [`NONCE_HEADER`] and [`SIGNATURE_HEADER`]. The nonce is single-use and
//! issued by the controller, so a host without a clock can still sign. The
//! signature covers [`signing_bytes`]: the method, the path, the nonce and a
//! hash of the body.
//!
//! This is a wire contract between controller and agent: [`signing_bytes`]
//! and the JSON shapes never change without bumping the domain tag.

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
    /// The signature does not match this key, method, path, nonce and body.
    #[error("request signature does not verify")]
    Invalid,
}

/// Appends `field` as an 8-byte big-endian length followed by its bytes.
///
/// Unlike [`crate::intent`], the method and path are chosen by the sender and
/// not bounded by a type, so the length is a full `u64`: it can never be
/// truncated, and no field can run into the next.
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u64).to_be_bytes());
    out.extend_from_slice(field);
}

/// The bytes a request signature covers: the ASCII bytes `landfall-agent-v1`
/// as a field, then `method`, `path`, the nonce's 32 raw bytes and the 32-byte
/// SHA-256 of `body`, each as a field. A field is an 8-byte big-endian length
/// and its bytes, so no value, newline or otherwise, can shift bytes into a
/// neighbouring field.
///
/// `method` and `path` are taken exactly as sent: the verifier must pass the
/// request's own method and raw path (and query, if any), not a normalised
/// form.
#[must_use]
pub fn signing_bytes(method: &str, path: &str, nonce: &Nonce, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(DOMAIN.len() + method.len() + path.len() + 128);
    push_field(&mut out, DOMAIN);
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
    method: &str,
    path: &str,
    nonce: &Nonce,
    body: &[u8],
) -> RequestSignature {
    let signature = key.sign(&signing_bytes(method, path, nonce, body));
    RequestSignature(signature.to_bytes())
}

/// Checks a request signature. Uses strict verification, which also refuses
/// the malleable encodings plain Ed25519 accepts.
///
/// # Errors
///
/// [`SignatureError::Invalid`] if `signature` is not `key`'s signature over
/// exactly this method, path, nonce and body.
pub fn verify(
    key: &VerifyingKey,
    signature: &RequestSignature,
    method: &str,
    path: &str,
    nonce: &Nonce,
    body: &[u8],
) -> Result<(), SignatureError> {
    key.verify_strict(
        &signing_bytes(method, path, nonce, body),
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

/// Serde adapter: an Ed25519 public key as 64 lowercase hex digits.
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
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| serde::de::Error::custom("not a valid Ed25519 public key"))
    }
}

/// A one-time enrolment code. Its `Debug` is redacted; the controller stores
/// only its hash.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EnrolCode(String);

impl EnrolCode {
    /// Wraps the code as the operator typed or read it.
    #[must_use]
    pub const fn new(code: String) -> Self {
        Self(code)
    }

    /// The code itself. Callers must not log it.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnrolCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EnrolCode(<redacted>)")
    }
}

/// `POST /agent/v1/enrol`: the host's public key and the code that binds it
/// to one host id.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnrolRequest {
    /// The one-time code from `enrol-code`.
    pub code: EnrolCode,
    /// The host the code was issued for.
    pub host: HostId,
    /// The key the host will sign with, 64 hex digits.
    #[serde(with = "key_hex")]
    pub public_key: VerifyingKey,
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

/// What the agent is doing with one deployment right now.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum Phase {
    /// Nothing in progress.
    Idle,
    /// A deploy is running.
    Deploying,
    /// A failed rollback or an unfinished deploy blocks further deploys until
    /// recovery.
    Blocked,
}

/// One deployment as the host sees it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunningState {
    /// The deployment.
    pub deployment: DeploymentId,
    /// The release the host last deployed.
    pub tag: ReleaseTag,
    /// Its image digest.
    pub digest: ImageDigest,
    /// Whether the running container differs from what the agent deployed.
    pub drift: bool,
    /// What the agent is doing with it.
    pub phase: Phase,
}

/// `POST /agent/v1/work`: ask for work, stating the config and the state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkRequest {
    /// SHA-256 of the agent's configuration, 64 hex digits.
    #[serde(with = "hash_hex")]
    pub config_hash: [u8; 32],
    /// The state of each of the host's deployments.
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
    /// it before showing it.
    pub reason: String,
}

/// The answer to a [`WorkRequest`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WorkResponse {
    /// The next deploy, if there is one.
    pub work: Option<DeployWork>,
    /// Deployments that have a release waiting but are not being deployed to.
    pub held_back: Vec<HeldBack>,
}

/// How a deploy that started ended, as the agent reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
#[non_exhaustive]
pub enum ReportedOutcome {
    /// The release is running and passed its checks.
    Deployed,
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
}

/// One step of a deploy, as the agent reports it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReportedStep {
    /// What was done.
    pub name: String,
    /// How long it took.
    pub millis: u64,
    /// Why it failed; `None` if it did what it should.
    pub failure: Option<String>,
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
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn nonce(byte: u8) -> Nonce {
        Nonce::from_bytes([byte; 32])
    }

    #[test]
    fn signature_covers_method_path_nonce_and_body() {
        let k = key(1);
        let sig = sign(&k, "POST", "/agent/v1/work", &nonce(2), b"{}");
        let public = k.verifying_key();
        assert_eq!(
            verify(&public, &sig, "POST", "/agent/v1/work", &nonce(2), b"{}"),
            Ok(())
        );
        let cases: [(&str, &str, Nonce, &[u8]); 4] = [
            ("GET", "/agent/v1/work", nonce(2), b"{}"),
            ("POST", "/agent/v1/report", nonce(2), b"{}"),
            ("POST", "/agent/v1/work", nonce(3), b"{}"),
            ("POST", "/agent/v1/work", nonce(2), b"{ }"),
        ];
        for (method, path, n, body) in cases {
            assert_eq!(
                verify(&public, &sig, method, path, &n, body),
                Err(SignatureError::Invalid),
                "{method} {path} {n} {body:?}"
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
        field(b"POST");
        field(b"/agent/v1/work");
        field(&[7; 32]);
        field(&Sha256::digest(b"body"));
        assert_eq!(
            signing_bytes("POST", "/agent/v1/work", &nonce(7), b"body"),
            expected
        );
    }

    #[test]
    fn signing_bytes_cannot_be_confused_across_fields() {
        let n = nonce(9);
        let body = b"x";
        let mut seen = vec![signing_bytes("GET", "/a", &n, body)];
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
            let bytes = signing_bytes(method, path, &n, body);
            assert!(!seen.contains(&bytes), "{method:?} {path:?}");
            seen.push(bytes);
        }
        // A path that spells out the nonce and body hash cannot stand in for
        // the real fields.
        let forged_path = format!("/a\n{n}\n{}", crate::hex::encode(&Sha256::digest(body)));
        let bytes = signing_bytes("GET", &forged_path, &nonce(0), b"");
        assert!(!seen.contains(&bytes));
    }

    #[test]
    fn signature_from_another_key_is_refused() {
        let sig = sign(&key(1), "GET", "/p", &nonce(1), b"");
        assert_eq!(
            verify(&key(2).verifying_key(), &sig, "GET", "/p", &nonce(1), b""),
            Err(SignatureError::Invalid)
        );
    }

    #[test]
    fn signature_and_nonce_round_trip_through_their_text_form() {
        let sig = sign(&key(1), "GET", "/p", &nonce(1), b"");
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

    #[test]
    fn debug_of_secrets_is_redacted() {
        let code = EnrolCode::new("s3cret-code".to_owned());
        assert!(!format!("{code:?}").contains("s3cret"));
        let req = EnrolRequest {
            code,
            host: "host-1".parse().unwrap(),
            public_key: key(1).verifying_key(),
        };
        assert!(!format!("{req:?}").contains("s3cret"));
        // The signing key's own Debug must not print the seed either.
        let seed_hex = crate::hex::encode(&[0x42; 32]);
        let dbg = format!("{:?}", key(0x42));
        assert!(!dbg.contains(&seed_hex) && !dbg.contains("66, 66"), "{dbg}");
    }

    fn work_request() -> WorkRequest {
        WorkRequest {
            config_hash: [5; 32],
            running: vec![RunningState {
                deployment: "app/prod".parse().unwrap(),
                tag: "v1.2.4".parse().unwrap(),
                digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
                drift: false,
                phase: Phase::Idle,
            }],
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

    fn report() -> DeployReportBody {
        DeployReportBody {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::RolledBack {
                reason: "health check failed".to_owned(),
            },
            steps: vec![
                ReportedStep {
                    name: "pull".to_owned(),
                    millis: 120,
                    failure: None,
                },
                ReportedStep {
                    name: "checks".to_owned(),
                    millis: 9000,
                    failure: Some("unhealthy".to_owned()),
                },
            ],
        }
    }

    fn enrol() -> EnrolRequest {
        EnrolRequest {
            code: EnrolCode::new("code".to_owned()),
            host: "host-1".parse().unwrap(),
            public_key: key(1).verifying_key(),
        }
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
        check(&ReportedOutcome::Deployed);
        check(&enrol());

        let json = serde_json::to_value(work_request()).unwrap();
        assert_eq!(json["config_hash"], "05".repeat(32));
        let json = serde_json::to_value(enrol()).unwrap();
        assert_eq!(
            json["public_key"],
            crate::hex::encode(key(1).verifying_key().as_bytes())
        );
        assert_eq!(json["code"], "code");
    }

    #[test]
    fn unknown_fields_are_refused() {
        fn refuses<T: serde::Serialize + serde::de::DeserializeOwned>(value: &T) {
            let mut v = serde_json::to_value(value).unwrap();
            v.as_object_mut()
                .unwrap()
                .insert("extra".to_owned(), serde_json::Value::Null);
            assert!(serde_json::from_value::<T>(v).is_err());
        }
        refuses(&work_request());
        refuses(&work_response());
        refuses(&report());
        refuses(&enrol());

        // And in nested values.
        let mut v = serde_json::to_value(work_response()).unwrap();
        v["work"]["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<WorkResponse>(v).is_err());
        let mut v = serde_json::to_value(work_request()).unwrap();
        v["running"][0]["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<WorkRequest>(v).is_err());
        let mut v = serde_json::to_value(report()).unwrap();
        v["steps"][0]["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
        let mut v = serde_json::to_value(report()).unwrap();
        v["outcome"]["extra"] = serde_json::Value::Bool(true);
        assert!(serde_json::from_value::<DeployReportBody>(v).is_err());
    }

    #[test]
    fn hostile_values_are_refused() {
        let mut v = serde_json::to_value(work_response()).unwrap();
        v["work"]["tag"] = serde_json::Value::String("v1\n".to_owned());
        assert!(serde_json::from_value::<WorkResponse>(v).is_err());
        let mut v = serde_json::to_value(work_request()).unwrap();
        v["config_hash"] = serde_json::Value::String("05".repeat(31));
        assert!(serde_json::from_value::<WorkRequest>(v).is_err());
        let mut v = serde_json::to_value(enrol()).unwrap();
        v["public_key"] = serde_json::Value::String("00".repeat(31));
        assert!(serde_json::from_value::<EnrolRequest>(v).is_err());
    }
}
