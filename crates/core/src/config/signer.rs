//! Tag-signing keys from `[signers]`.

use ssh_key::{Algorithm, HashAlg, PublicKey};

use crate::text::shown;

/// A trusted tag-signing key: an `ssh-ed25519` public key in OpenSSH format,
/// as written in a `.pub` file. Only ed25519 is supported, so a key of any
/// other type is a configuration error rather than a key that silently never
/// matches. The trailing comment is ignored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignerKey {
    key: PublicKey,
}

impl SignerKey {
    /// Parses one `[signers]` value; the error is the reason, without the
    /// signer's name, which the caller adds.
    pub(crate) fn parse(text: &str) -> Result<Self, String> {
        let key_type = text.split_whitespace().next().unwrap_or_default();
        if key_type != "ssh-ed25519" {
            return Err(format!(
                "key type {} is not supported; use an ssh-ed25519 public key (the contents of a .pub file)",
                shown(key_type)
            ));
        }
        let mut key = PublicKey::from_openssh(text.trim())
            .map_err(|e| format!("not a valid OpenSSH public key: {e}"))?;
        if key.algorithm() != Algorithm::Ed25519 {
            return Err(format!(
                "key type {} is not supported; use an ssh-ed25519 public key",
                key.algorithm()
            ));
        }
        key.set_comment("");
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
