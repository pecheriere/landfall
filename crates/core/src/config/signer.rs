//! Tag-signing keys from `[signers]`.

use ed25519_dalek::VerifyingKey;
use ssh_key::{Algorithm, HashAlg, PublicKey};

use super::shown_in_config;

/// A trusted tag-signing key: an `ssh-ed25519` public key in OpenSSH format,
/// as written in a `.pub` file. Only ed25519 is supported, so a key of any
/// other type is a configuration error rather than a key that silently never
/// matches. The trailing comment is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerKey {
    key: PublicKey,
}

impl SignerKey {
    /// Parses one signer's key.
    ///
    /// # Errors
    ///
    /// The reason it is refused, without the signer's name, which the caller adds:
    /// not an `ssh-ed25519` key, bytes that are not exactly what such a key encodes to, or
    /// 32 bytes that are not a good key. `verify_tag` verifies with plain `verify`, so for
    /// a key of small order anyone could forge a tag: it, and another spelling of a point
    /// or of the key, must not load.
    pub fn parse(text: &str) -> Result<Self, String> {
        let key_type = text.split_whitespace().next().unwrap_or_default();
        if key_type != "ssh-ed25519" {
            return Err(format!(
                "key type {} is not supported; use an ssh-ed25519 public key (the contents of a .pub file)",
                shown_in_config(key_type)
            ));
        }
        let mut key = PublicKey::from_openssh(text.trim()).map_err(|e| {
            format!(
                "not a valid OpenSSH public key: {}",
                shown_in_config(&e.to_string())
            )
        })?;
        let Some(ed25519) = key.key_data().ed25519() else {
            return Err(format!(
                "key type {} is not supported; use an ssh-ed25519 public key",
                shown_in_config(Algorithm::as_str(&key.algorithm()))
            ));
        };
        key_fault(&ed25519.0).map_or(Ok(()), Err)?;
        key.set_comment("");
        // The parser reads a nested key's 32 bytes and never checks that its length
        // said 32, so what it read is checked against what that key encodes to.
        let encoded = key
            .to_openssh()
            .map_err(|e| format!("cannot encode the key: {}", shown_in_config(&e.to_string())))?;
        if encoded.split_whitespace().nth(1) != text.split_whitespace().nth(1) {
            return Err(
                "the key's bytes are not the one encoding of an ssh-ed25519 key".to_owned(),
            );
        }
        Ok(Self { key })
    }

    /// The key's fingerprint as `ssh-keygen -l` prints it: `SHA256:<base64>`.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        self.key.fingerprint(HashAlg::Sha256).to_string()
    }

    /// The parsed key, for signature verification.
    pub(crate) fn public_key(&self) -> &PublicKey {
        &self.key
    }
}

/// What is wrong with 32 bytes as an Ed25519 public key, if anything: it refuses what
/// `release_preflight.py`'s `key_fault` refuses, though one key may be told a different
/// reason. Decompressing accepts a y beyond the field's prime and a sign on x = 0, each
/// another spelling of a point, so only compressing it again shows those.
fn key_fault(bytes: &[u8; 32]) -> Option<String> {
    let Ok(point) = VerifyingKey::from_bytes(bytes) else {
        return Some("the key is not a point on the curve".to_owned());
    };
    if point.to_edwards().compress().as_bytes() != bytes {
        return Some("the key is not a canonical encoding of its point".to_owned());
    }
    point.is_weak().then(|| {
        "the key is a point of small order, for which anyone can forge a signature".to_owned()
    })
}
