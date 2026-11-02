//! A software authenticator for tests, with knobs to break every field.
//!
//! Behind the `test-support` feature: it holds private keys in memory, signs
//! whatever it is told to, and has no place in a production build.

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::error::Unspecified;
use aws_lc_rs::rand::{SecureRandom, SystemRandom};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair};

use crate::assertion::Assertion;
use crate::authenticator_data::{FLAG_AT, FLAG_UP, FLAG_UV};
use crate::cose::{CoseError, CoseKey, encode_eddsa, encode_es256};
use crate::registration::encode_attestation_object;
use crate::wire;

/// A software authenticator couldn't do what it was asked.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SoftwareError {
    /// The key couldn't be generated, or couldn't sign.
    #[error("software authenticator: {0}")]
    Crypto(#[from] Unspecified),
    /// The generated key didn't parse, which would be a bug in this crate.
    #[error(transparent)]
    Key(#[from] CoseError),
}

enum Signer {
    Es256(EcdsaKeyPair),
    EdDsa(Ed25519KeyPair),
}

/// One ceremony's inputs. [`Ceremony::new`] gives an honest one; change a field to
/// break exactly that field, and the result is still properly signed unless
/// [`signed_message`](Self::signed_message) says otherwise.
#[derive(Debug, Clone)]
pub struct Ceremony {
    /// The RP ID hashed into the authenticator data.
    pub rp_id: String,
    /// `origin` in the client data.
    pub origin: String,
    /// The challenge, base64url in the client data.
    pub challenge: Vec<u8>,
    /// `type` in the client data; `None` for the one the ceremony uses.
    pub kind: Option<String>,
    /// `crossOrigin` in the client data; `None` leaves it out.
    pub cross_origin: Option<bool>,
    /// The authenticator data's flags; `None` for UP and UV, and AT on a
    /// registration.
    pub flags: Option<u8>,
    /// `signCount`.
    pub sign_count: u32,
    /// Appended to the authenticator data, whatever the flags declare.
    pub trailing: Vec<u8>,
    /// Replaces the credential id the assertion names.
    pub credential_id: Option<Vec<u8>>,
    /// Replaces the whole client data.
    pub client_data_json: Option<Vec<u8>>,
    /// Replaces the whole authenticator data of an assertion.
    pub authenticator_data: Option<Vec<u8>>,
    /// Signs this instead of what was generated.
    pub signed_message: Option<Vec<u8>>,
    /// The attestation format.
    pub format: String,
    /// The encoded attestation statement.
    pub statement: Vec<u8>,
    /// Replaces the COSE key in the attested credential data.
    pub attested_key: Option<Vec<u8>>,
}

impl Ceremony {
    /// An honest ceremony for this relying party and challenge.
    #[must_use]
    pub fn new(rp_id: &str, origin: &str, challenge: &[u8]) -> Self {
        Self {
            rp_id: rp_id.to_owned(),
            origin: origin.to_owned(),
            challenge: challenge.to_vec(),
            kind: None,
            cross_origin: None,
            flags: None,
            sign_count: 0,
            trailing: Vec::new(),
            credential_id: None,
            client_data_json: None,
            authenticator_data: None,
            signed_message: None,
            format: "none".to_owned(),
            statement: vec![0xa0],
            attested_key: None,
        }
    }

    fn client_data(&self, default_kind: &str) -> Vec<u8> {
        if let Some(raw) = &self.client_data_json {
            return raw.clone();
        }
        let quote = |text: &str| serde_json::Value::from(text).to_string();
        let cross_origin = self
            .cross_origin
            .map_or(String::new(), |value| format!(",\"crossOrigin\":{value}"));
        format!(
            "{{\"type\":{},\"challenge\":{},\"origin\":{}{cross_origin}}}",
            quote(self.kind.as_deref().unwrap_or(default_kind)),
            quote(&wire::encode(&self.challenge)),
            quote(&self.origin),
        )
        .into_bytes()
    }

    fn fixed_data(&self, default_flags: u8) -> Vec<u8> {
        let mut data = digest(&SHA256, self.rp_id.as_bytes()).as_ref().to_vec();
        data.push(self.flags.unwrap_or(default_flags));
        data.extend_from_slice(&self.sign_count.to_be_bytes());
        data
    }
}

/// An attestation as a browser hands it over.
#[derive(Debug, Clone)]
pub struct Attestation {
    /// `attestationObject`.
    pub attestation_object: Vec<u8>,
    /// `clientDataJSON`.
    pub client_data_json: Vec<u8>,
}

/// A credential held in memory.
pub struct SoftwareAuthenticator {
    signer: Signer,
    credential_id: Vec<u8>,
    key: Vec<u8>,
}

impl std::fmt::Debug for SoftwareAuthenticator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareAuthenticator")
            .field("credential_id", &wire::encode(&self.credential_id))
            .finish_non_exhaustive()
    }
}

impl SoftwareAuthenticator {
    /// A new ES256 credential.
    ///
    /// # Errors
    ///
    /// When key generation fails.
    pub fn es256() -> Result<Self, SoftwareError> {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING)?;
        let point = pair.public_key().as_ref();
        let key = encode_es256(
            point.get(1..33).unwrap_or_default(),
            point.get(33..).unwrap_or_default(),
        );
        Self::with(Signer::Es256(pair), key)
    }

    /// A new `EdDSA` credential.
    ///
    /// # Errors
    ///
    /// When key generation fails.
    pub fn eddsa() -> Result<Self, SoftwareError> {
        let pair = Ed25519KeyPair::generate()?;
        let key = encode_eddsa(pair.public_key().as_ref());
        Self::with(Signer::EdDsa(pair), key)
    }

    fn with(signer: Signer, key: Vec<u8>) -> Result<Self, SoftwareError> {
        let mut credential_id = vec![0; 32];
        SystemRandom::new().fill(&mut credential_id)?;
        Ok(Self {
            signer,
            credential_id,
            key,
        })
    }

    /// The credential's id.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// The credential's public key, as the host's configuration would hold it.
    ///
    /// # Errors
    ///
    /// Never for a key from this type's constructors, short of a bug in this crate.
    pub fn key(&self) -> Result<CoseKey, SoftwareError> {
        Ok(CoseKey::parse(&self.key)?)
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, SoftwareError> {
        Ok(match &self.signer {
            Signer::Es256(pair) => pair.sign(&SystemRandom::new(), message)?.as_ref().to_vec(),
            Signer::EdDsa(pair) => pair.sign(message).as_ref().to_vec(),
        })
    }

    /// An assertion, as `navigator.credentials.get()` gives it.
    ///
    /// # Errors
    ///
    /// When signing fails.
    pub fn assertion(&self, ceremony: &Ceremony) -> Result<Assertion, SoftwareError> {
        let client_data_json = ceremony.client_data("webauthn.get");
        let authenticator_data = ceremony.authenticator_data.clone().unwrap_or_else(|| {
            let mut data = ceremony.fixed_data(FLAG_UP | FLAG_UV);
            data.extend_from_slice(&ceremony.trailing);
            data
        });
        let mut message = authenticator_data.clone();
        message.extend_from_slice(digest(&SHA256, &client_data_json).as_ref());
        let signature = self.sign(ceremony.signed_message.as_deref().unwrap_or(&message))?;
        Ok(Assertion {
            credential_id: ceremony
                .credential_id
                .clone()
                .unwrap_or_else(|| self.credential_id.clone()),
            authenticator_data,
            client_data_json,
            signature,
        })
    }

    /// An attestation, as `navigator.credentials.create()` gives it. Nothing signs
    /// a `none` attestation.
    #[must_use]
    pub fn attestation(&self, ceremony: &Ceremony) -> Attestation {
        let id = ceremony
            .credential_id
            .as_ref()
            .unwrap_or(&self.credential_id);
        let mut data = ceremony.fixed_data(FLAG_UP | FLAG_UV | FLAG_AT);
        data.extend_from_slice(&[0; 16]);
        let [.., high, low] = id.len().to_be_bytes();
        data.extend_from_slice(&[high, low]);
        data.extend_from_slice(id);
        data.extend_from_slice(ceremony.attested_key.as_ref().unwrap_or(&self.key));
        data.extend_from_slice(&ceremony.trailing);
        Attestation {
            attestation_object: encode_attestation_object(
                &ceremony.format,
                &ceremony.statement,
                &data,
            ),
            client_data_json: ceremony.client_data("webauthn.create"),
        }
    }
}
