//! COSE public keys (RFC 9053), ES256 and `EdDSA` only.
//!
//! `WebAuthn` 6.5.1 says a credential key has `alg`, the parameters its key type
//! requires, and no other optional parameter, in the CTAP2 canonical CBOR form. So
//! exactly two shapes exist, and each key has one encoding, which is what its
//! fingerprint is taken over. [`CoseKey::parse`], which config load uses, takes that
//! encoding and nothing else. Only registration normalises, and only the encoding: a
//! key with another parameter or a repeated label is refused there too.

use std::fmt;

use aws_lc_rs::digest::{SHA256, digest};
use aws_lc_rs::signature::{ECDSA_P256_SHA256_ASN1, ED25519, ParsedPublicKey};
use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use ed25519_dalek::VerifyingKey;
use minicbor::Decoder;
use minicbor::data::Type;

const LABEL_KTY: i64 = 1;
const LABEL_ALG: i64 = 3;
const LABEL_CRV: i64 = -1;
const LABEL_X: i64 = -2;
const LABEL_Y: i64 = -3;

const ALG_ES256: i64 = -7;
const ALG_EDDSA: i64 = -8;
const KTY_OKP: i64 = 1;
const KTY_EC2: i64 = 2;
const CRV_P256: i64 = 1;
const CRV_ED25519: i64 = 6;

const COORDINATE_LEN: usize = 32;
/// More than any key has. Bounds the scan for duplicate labels.
const MAX_PARAMETERS: u64 = 16;

/// A signature algorithm an approver's key can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Algorithm {
    /// ECDSA with SHA-256 over P-256, COSE algorithm -7.
    Es256,
    /// Ed25519, COSE algorithm -8.
    EdDsa,
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Es256 => "ES256",
            Self::EdDsa => "EdDSA",
        })
    }
}

/// Why a COSE key was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum CoseError {
    /// Not a CBOR map of integer labels.
    #[error("COSE key is malformed: {0}")]
    Malformed(String),
    /// A label appears twice.
    #[error("COSE key has label {0} twice")]
    DuplicateLabel(i64),
    /// A required parameter is absent.
    #[error("COSE key has no {0}")]
    MissingParameter(&'static str),
    /// A parameter `WebAuthn` 6.5.1 doesn't allow in a credential key, such as a
    /// private key.
    #[error("COSE key has unexpected label {0}")]
    UnexpectedParameter(i64),
    /// The algorithm is neither ES256 (-7) nor `EdDSA` (-8).
    #[error("COSE algorithm {0} is not supported: use ES256 (-7) or EdDSA (-8)")]
    UnsupportedAlgorithm(i64),
    /// The key type doesn't go with the algorithm.
    #[error("COSE key type: expected {expected}, found {found}")]
    KeyType {
        /// The key type the algorithm uses.
        expected: i64,
        /// The key type in the key.
        found: i64,
    },
    /// The curve doesn't go with the algorithm.
    #[error("COSE curve: expected {expected}, found {found}")]
    Curve {
        /// The curve the algorithm uses.
        expected: i64,
        /// The curve in the key.
        found: i64,
    },
    /// A coordinate isn't 32 bytes.
    #[error("COSE key {name}: expected {COORDINATE_LEN} bytes, found {found}")]
    CoordinateLength {
        /// `x` or `y`.
        name: &'static str,
        /// The length in the key.
        found: usize,
    },
    /// `y` is a sign bit: the point is compressed.
    #[error("COSE key has a compressed point, an uncompressed one is required")]
    CompressedPoint,
    /// The bytes are not a point on the curve.
    #[error("COSE key is not a point on its curve")]
    NotOnCurve,
    /// An Ed25519 point of small order, for which signatures can be forged.
    #[error("COSE key is a point of small order")]
    WeakKey,
    /// An Ed25519 point written with a `y` beyond the field's prime: the same point
    /// has a shorter spelling, so the same key would have two fingerprints.
    #[error("COSE key is not the canonical encoding of its point")]
    NonCanonicalPoint,
    /// The right values, not in the CTAP2 canonical encoding.
    #[error("COSE key is not in the canonical encoding")]
    NotCanonical,
    /// Bytes follow the key.
    #[error("{0} bytes follow the COSE key")]
    TrailingBytes(usize),
}

/// A validated public key, as it would be read from the configuration.
#[derive(Debug, Clone)]
pub struct CoseKey {
    algorithm: Algorithm,
    /// The canonical encoding, whatever this key was read from.
    encoded: Vec<u8>,
    parsed: ParsedPublicKey,
}

impl PartialEq for CoseKey {
    fn eq(&self, other: &Self) -> bool {
        self.encoded == other.encoded
    }
}

impl Eq for CoseKey {}

impl CoseKey {
    /// Parses and validates a key: the whole of `bytes`, in the canonical encoding,
    /// on its curve.
    ///
    /// # Errors
    ///
    /// Everything the module's docs say doesn't exist, as a [`CoseError`].
    pub fn parse(bytes: &[u8]) -> Result<Self, CoseError> {
        let (key, end) = Self::normalise_prefix(bytes)?;
        if bytes.get(..end) != Some(key.as_bytes()) {
            return Err(CoseError::NotCanonical);
        }
        match bytes.len() - end {
            0 => Ok(key),
            found => Err(CoseError::TrailingBytes(found)),
        }
    }

    /// Reads the key at the start of `bytes`, however it's encoded, and says where it
    /// ends: in attested credential data, nothing else marks that. The key that comes
    /// out holds the canonical encoding.
    pub(crate) fn normalise_prefix(bytes: &[u8]) -> Result<(Self, usize), CoseError> {
        let params = Parameters::scan(bytes)?;
        let (algorithm, encoded, parsed) = match params.int(LABEL_ALG, "alg")? {
            ALG_ES256 => es256(&params)?,
            ALG_EDDSA => eddsa(&params)?,
            other => return Err(CoseError::UnsupportedAlgorithm(other)),
        };
        let key = Self {
            algorithm,
            encoded,
            parsed,
        };
        Ok((key, params.end))
    }

    /// The key's algorithm.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.algorithm
    }

    /// The key's canonical encoding: what's stored, shown and put in a configuration.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }

    /// What a person compares: `SHA256:` and the unpadded base64 of the hash of the
    /// canonical encoding, the form `ssh-keygen -l` prints for the signer keys.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let hash = digest(&SHA256, &self.encoded);
        format!("SHA256:{}", STANDARD_NO_PAD.encode(hash.as_ref()))
    }

    /// Verifies `signature` over `message`. An ES256 signature is ASN.1 DER.
    pub(crate) fn verify_signature(&self, message: &[u8], signature: &[u8]) -> bool {
        self.parsed.verify_sig(message, signature).is_ok()
    }
}

/// The encoding of an ES256 key: `{1: 2, 3: -7, -1: 1, -2: x, -3: y}`.
pub(crate) fn encode_es256(x: &[u8], y: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20];
    out.extend_from_slice(x);
    out.extend_from_slice(&[0x22, 0x58, 0x20]);
    out.extend_from_slice(y);
    out
}

/// The encoding of an `EdDSA` key: `{1: 1, 3: -8, -1: 6, -2: x}`.
pub(crate) fn encode_eddsa(x: &[u8]) -> Vec<u8> {
    let mut out = vec![0xa4, 0x01, 0x01, 0x03, 0x27, 0x20, 0x06, 0x21, 0x58, 0x20];
    out.extend_from_slice(x);
    out
}

type Validated = (Algorithm, Vec<u8>, ParsedPublicKey);

fn es256(params: &Parameters<'_>) -> Result<Validated, CoseError> {
    params.only(&[LABEL_KTY, LABEL_ALG, LABEL_CRV, LABEL_X, LABEL_Y])?;
    params.key_type_and_curve(KTY_EC2, CRV_P256)?;
    let x = params.coordinate(LABEL_X, "x")?;
    let y = params.coordinate(LABEL_Y, "y")?;
    let mut point = vec![0x04];
    point.extend_from_slice(x);
    point.extend_from_slice(y);
    let parsed =
        ParsedPublicKey::new(&ECDSA_P256_SHA256_ASN1, &point).map_err(|_| CoseError::NotOnCurve)?;
    Ok((Algorithm::Es256, encode_es256(x, y), parsed))
}

fn eddsa(params: &Parameters<'_>) -> Result<Validated, CoseError> {
    params.only(&[LABEL_KTY, LABEL_ALG, LABEL_CRV, LABEL_X])?;
    params.key_type_and_curve(KTY_OKP, CRV_ED25519)?;
    let x = params.coordinate(LABEL_X, "x")?;
    // aws-lc takes any 32 bytes as an Ed25519 key, and verifying is where a bad one
    // would show. For a small-order key, signatures can be forged by anyone.
    let bytes: &[u8; COORDINATE_LEN] = x.try_into().map_err(|_| CoseError::NotOnCurve)?;
    let point = VerifyingKey::from_bytes(bytes).map_err(|_| CoseError::NotOnCurve)?;
    if point.is_weak() {
        return Err(CoseError::WeakKey);
    }
    // Decompressing accepts a y beyond the field's prime, which is another spelling of
    // the point at y - p.
    if point.to_edwards().compress().as_bytes() != bytes {
        return Err(CoseError::NonCanonicalPoint);
    }
    let parsed = ParsedPublicKey::new(&ED25519, x).map_err(|_| CoseError::NotOnCurve)?;
    Ok((Algorithm::EdDsa, encode_eddsa(x), parsed))
}

/// The labels of a key's map and where each value starts, so that the algorithm
/// can be read first: an RSA key's `-1` is bytes, not a curve, and the error that
/// helps is the one naming the algorithm.
struct Parameters<'a> {
    bytes: &'a [u8],
    entries: Vec<(i64, usize)>,
    end: usize,
}

fn decoded<T>(result: Result<T, minicbor::decode::Error>) -> Result<T, CoseError> {
    result.map_err(|e| CoseError::Malformed(e.to_string()))
}

impl<'a> Parameters<'a> {
    fn scan(bytes: &'a [u8]) -> Result<Self, CoseError> {
        let mut d = Decoder::new(bytes);
        let Some(count) = decoded(d.map())? else {
            return Err(CoseError::NotCanonical);
        };
        if count > MAX_PARAMETERS {
            return Err(CoseError::Malformed(format!("{count} parameters")));
        }
        let mut entries = Vec::new();
        for _ in 0..count {
            let label = decoded(d.i64())?;
            if entries.iter().any(|(seen, _)| *seen == label) {
                return Err(CoseError::DuplicateLabel(label));
            }
            entries.push((label, d.position()));
            decoded(d.skip())?;
        }
        let end = d.position();
        Ok(Self {
            bytes,
            entries,
            end,
        })
    }

    fn only(&self, allowed: &[i64]) -> Result<(), CoseError> {
        match self.entries.iter().find(|(l, _)| !allowed.contains(l)) {
            Some((label, _)) => Err(CoseError::UnexpectedParameter(*label)),
            None => Ok(()),
        }
    }

    fn value(&self, label: i64, name: &'static str) -> Result<Decoder<'a>, CoseError> {
        let (_, position) = self
            .entries
            .iter()
            .find(|(l, _)| *l == label)
            .ok_or(CoseError::MissingParameter(name))?;
        let mut d = Decoder::new(self.bytes);
        d.set_position(*position);
        Ok(d)
    }

    fn int(&self, label: i64, name: &'static str) -> Result<i64, CoseError> {
        decoded(self.value(label, name)?.i64())
    }

    fn key_type_and_curve(&self, kty: i64, crv: i64) -> Result<(), CoseError> {
        let found = self.int(LABEL_KTY, "kty")?;
        if found != kty {
            return Err(CoseError::KeyType {
                expected: kty,
                found,
            });
        }
        let found = self.int(LABEL_CRV, "crv")?;
        if found != crv {
            return Err(CoseError::Curve {
                expected: crv,
                found,
            });
        }
        Ok(())
    }

    fn coordinate(&self, label: i64, name: &'static str) -> Result<&'a [u8], CoseError> {
        let mut d = self.value(label, name)?;
        if decoded(d.datatype())? == Type::Bool {
            return Err(CoseError::CompressedPoint);
        }
        let bytes = decoded(d.bytes())?;
        if bytes.len() != COORDINATE_LEN {
            return Err(CoseError::CoordinateLength {
                name,
                found: bytes.len(),
            });
        }
        Ok(bytes)
    }
}
