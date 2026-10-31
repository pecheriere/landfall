//! Deploy intents and the approval challenge derived from them.
//!
//! A passkey signs [`DeployIntent::challenge`]. The controller computes it to
//! ask for the approval and each host agent recomputes it from the intent it
//! is about to execute, so the encoding below is a wire contract: it must
//! agree byte for byte on both sides and is never changed without bumping the
//! domain-separation prefix.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use crate::hex;
use crate::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};

/// Domain-separation prefix of the canonical encoding.
const DOMAIN: &[u8] = b"landfall-deploy-intent-v1";

/// Everything an approver authorises: which deployment moves to which image,
/// from which running image, under a one-time nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeployIntent {
    /// The deployment being changed.
    pub deployment: DeploymentId,
    /// The release tag being deployed.
    pub tag: ReleaseTag,
    /// The commit the tag points at.
    pub commit: CommitSha,
    /// The image content digest to run.
    pub digest: ImageDigest,
    /// The digest the host must be running now; `None` (JSON `null`) for a
    /// first deploy. The key must be present: an omitted key is an error, so
    /// a truncated payload can never silently become a first deploy.
    #[serde(deserialize_with = "Option::deserialize")]
    pub expected_running: Option<ImageDigest>,
    /// One-time value that makes this approval unrepeatable; 64 hex digits
    /// on the wire.
    #[serde(with = "nonce_hex")]
    pub nonce: [u8; 32],
}

/// Serde adapter: a 32-byte nonce as exactly 64 lowercase hex digits.
mod nonce_hex {
    use super::{Deserialize, Deserializer, Serializer, hex};

    pub(super) fn serialize<S: Serializer>(nonce: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(nonce))
    }

    pub(super) fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let text = String::deserialize(d)?;
        hex::decode(&text)
            .ok_or_else(|| serde::de::Error::custom("nonce must be 64 lowercase hex digits"))
    }
}

/// Appends `field` as a 4-byte big-endian length followed by its bytes.
///
/// Every field of a [`DeployIntent`] is bounded by its type: identifiers and
/// digests by their validated grammar, the tag by [`ReleaseTag`] (at most 128
/// bytes) and the nonce by its array length. The longest is therefore far
/// below `u32::MAX`, so the low four bytes of the length are the whole length
/// and nothing is truncated.
fn push_field(out: &mut Vec<u8>, field: &[u8]) {
    let [.., a, b, c, d] = field.len().to_be_bytes();
    out.extend_from_slice(&[a, b, c, d]);
    out.extend_from_slice(field);
}

impl DeployIntent {
    /// The domain-separated, length-prefixed encoding that is hashed into
    /// the challenge: the ASCII bytes `landfall-deploy-intent-v1`, then, for
    /// `deployment`, `tag`, `commit`, `digest`, `expected_running` and
    /// `nonce` in that order, a 4-byte big-endian length and the field's
    /// bytes. Text fields are UTF-8, `expected_running` is empty when
    /// `None`, and the nonce is its 32 raw bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = DOMAIN.to_vec();
        push_field(&mut out, self.deployment.as_ref().as_bytes());
        push_field(&mut out, self.tag.as_ref().as_bytes());
        push_field(&mut out, self.commit.as_ref().as_bytes());
        push_field(&mut out, self.digest.as_ref().as_bytes());
        push_field(
            &mut out,
            self.expected_running
                .as_ref()
                .map_or(&[][..], |d| d.as_ref().as_bytes()),
        );
        push_field(&mut out, &self.nonce);
        out
    }

    /// The `WebAuthn` challenge: SHA-256 of [`canonical_bytes`](Self::canonical_bytes).
    #[must_use]
    pub fn challenge(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn intent() -> DeployIntent {
        DeployIntent {
            deployment: "app/prod".parse().unwrap(),
            tag: "v1.2.4".parse().unwrap(),
            commit: "a".repeat(40).parse().unwrap(),
            digest: format!("sha256:{}", "b".repeat(64)).parse().unwrap(),
            expected_running: Some(format!("sha256:{}", "c".repeat(64)).parse().unwrap()),
            nonce: [7; 32],
        }
    }

    #[test]
    fn challenge_is_stable() {
        let mut expected = b"landfall-deploy-intent-v1".to_vec();
        let mut field = |bytes: &[u8]| {
            expected.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
            expected.extend_from_slice(bytes);
        };
        field(b"app/prod");
        field(b"v1.2.4");
        field("a".repeat(40).as_bytes());
        field(format!("sha256:{}", "b".repeat(64)).as_bytes());
        field(format!("sha256:{}", "c".repeat(64)).as_bytes());
        field(&[7; 32]);

        let i = intent();
        assert_eq!(i.canonical_bytes(), expected);
        let want: [u8; 32] = Sha256::digest(&expected).into();
        assert_eq!(i.challenge(), want);
        // Pinned once from the encoding above; a change here breaks every
        // agent and controller pair.
        assert_eq!(hex::encode(&i.challenge()), PINNED);
    }

    const PINNED: &str = "1450185144696e3becd3230aa9a78d5931a1d52155686619ba6f2f5518f60180";

    #[test]
    fn distinct_intents_never_share_a_challenge() {
        let base = intent();
        let mut variants = Vec::new();
        let mut v = base.clone();
        v.deployment = "app/stage".parse().unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.tag = "v1.2.5".parse().unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.commit = "d".repeat(40).parse().unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.digest = format!("sha256:{}", "d".repeat(64)).parse().unwrap();
        variants.push(v);
        let mut v = base.clone();
        v.expected_running = None;
        variants.push(v);
        let mut v = base.clone();
        v.expected_running = Some(format!("sha256:{}", "d".repeat(64)).parse().unwrap());
        variants.push(v);
        let mut v = base.clone();
        v.nonce = [8; 32];
        variants.push(v);
        for tag in ["v1.2.4-rc.1", "v1.2.4+1", "app/prodv1.2.4", "v1.2", "x"] {
            let mut v = base.clone();
            v.tag = tag.parse().unwrap();
            variants.push(v);
        }

        let mut seen = vec![base.challenge()];
        for v in &variants {
            let c = v.challenge();
            assert!(!seen.contains(&c), "collision for {v:?}");
            seen.push(c);
        }
    }

    #[test]
    fn shifting_the_deployment_tag_boundary_changes_the_challenge() {
        // Without length prefixes these two would concatenate to the same
        // bytes: "app/prod" + "v1.2.4" and "app/pro" + "dv1.2.4".
        let base = intent();
        let shifted = DeployIntent {
            deployment: "app/pro".parse().unwrap(),
            tag: "dv1.2.4".parse().unwrap(),
            ..base.clone()
        };
        assert_ne!(base.challenge(), shifted.challenge());
    }

    #[test]
    fn intent_round_trips_through_json() {
        for i in [
            intent(),
            DeployIntent {
                expected_running: None,
                ..intent()
            },
        ] {
            let json = serde_json::to_string(&i).unwrap();
            assert!(json.contains(&"07".repeat(32)), "{json}");
            assert_eq!(serde_json::from_str::<DeployIntent>(&json).unwrap(), i);
        }
    }

    #[test]
    fn expected_running_must_be_present_even_when_null() {
        let mut v = serde_json::to_value(intent()).unwrap();
        v["expected_running"] = serde_json::Value::Null;
        let parsed: DeployIntent = serde_json::from_value(v.clone()).unwrap();
        assert_eq!(parsed.expected_running, None);
        v.as_object_mut().unwrap().remove("expected_running");
        assert!(serde_json::from_value::<DeployIntent>(v).is_err());
    }

    #[test]
    fn hostile_tags_do_not_deserialise() {
        let mut v = serde_json::to_value(intent()).unwrap();
        for bad in ["v1\n", "v1\"", "v1\u{202e}"] {
            v["tag"] = serde_json::Value::String(bad.to_owned());
            assert!(serde_json::from_value::<DeployIntent>(v.clone()).is_err());
        }
    }

    #[test]
    fn malformed_nonces_are_refused() {
        let good = serde_json::to_value(intent()).unwrap();
        for bad in [
            "07".repeat(31),
            "07".repeat(33),
            "0G".repeat(32),
            "07".to_uppercase().repeat(32).replace("07", "AB"),
            String::new(),
        ] {
            let mut v = good.clone();
            v["nonce"] = serde_json::Value::String(bad.clone());
            assert!(
                serde_json::from_value::<DeployIntent>(v).is_err(),
                "{bad:?} should be refused"
            );
        }
    }
}
