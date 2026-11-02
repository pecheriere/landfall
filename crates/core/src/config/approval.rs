//! `[approval]` and the keys of `[approvers]`.
//!
//! The verifier compares the origin byte for byte against what a browser sends, and the
//! RP ID's hash against what the authenticator signed. So an origin in any form but the
//! one a browser writes, or an RP ID that isn't its hostname, would load and then refuse
//! every approval. They're refused here instead, not normalised: the file says exactly
//! what's compared.
//!
//! This crate has no COSE parser, because checking a key takes the cryptographic library
//! the verifier uses and this crate stays free of it. [`parse`](super::parse) takes the
//! verifier's check as a required argument, so a caller can't forget it.
//! `landfall_approval::parse_config` is how every binary supplies it.

use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use super::ConfigError;
use crate::ids::PrincipalId;

/// The longest credential id `WebAuthn` 7.1 lets a relying party accept, in bytes.
pub const MAX_CREDENTIAL_ID_LEN: usize = 1023;

/// The longest DNS name, in the bytes a name is written with.
const MAX_HOST_LEN: usize = 253;
/// The longest label of a DNS name.
const MAX_LABEL_LEN: usize = 63;
/// A browser leaves the default port out of an origin.
const DEFAULT_HTTPS_PORT: u16 = 443;

/// Decides whether the decoded bytes of an approver's `public_key` are a key the verifier
/// can use, and says why not. The error is shown with the approver's name, and must not
/// repeat the key.
pub type KeyCheck = fn(&[u8]) -> Result<(), String>;

/// The relying party every approval is checked against.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approval {
    /// The RP ID: the hostname of `origin`.
    rp_id: String,
    /// The origin, exactly as a browser writes it.
    origin: String,
}

impl Approval {
    /// Validates the settings; see the module's docs for why nothing is normalised.
    pub(super) fn new(rp_id: String, origin: String) -> Result<Self, ConfigError> {
        let host = origin_host(&origin).map_err(|reason| ConfigError::InvalidApprovalOrigin {
            origin: origin.clone(),
            reason,
        })?;
        if rp_id != host {
            return Err(ConfigError::RpIdNotOriginHost {
                rp_id,
                host: host.to_owned(),
            });
        }
        Ok(Self { rp_id, origin })
    }

    /// The RP ID: the hostname of [`origin`](Self::origin), nothing broader.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }

    /// The origin, exactly as a browser writes it: `https://`, a lower-case hostname, and
    /// a port only if it isn't 443.
    #[must_use]
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

/// A passkey approver, as read from the local configuration: the only place a host takes
/// an approver's key from.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Approver {
    /// `WebAuthn` credential id.
    credential_id: Vec<u8>,
    /// COSE public key, in its canonical encoding.
    public_key: Vec<u8>,
}

impl Approver {
    /// Decodes and checks one `[approvers]` entry.
    pub(super) fn parse(
        name: &PrincipalId,
        credential_id: &str,
        public_key: &str,
        check: KeyCheck,
    ) -> Result<Self, ConfigError> {
        let refused = |reason: String| ConfigError::InvalidApprover {
            approver: name.clone(),
            reason,
        };
        // The decoder refuses padding and set trailing bits, so bytes have one spelling.
        let credential_id = URL_SAFE_NO_PAD
            .decode(credential_id)
            .map_err(|_| refused("credential_id is not unpadded base64url".to_owned()))?;
        if credential_id.is_empty() || credential_id.len() > MAX_CREDENTIAL_ID_LEN {
            return Err(refused(format!(
                "credential_id is {} bytes, 1 to {MAX_CREDENTIAL_ID_LEN} are allowed",
                credential_id.len()
            )));
        }
        let public_key = URL_SAFE_NO_PAD
            .decode(public_key)
            .map_err(|_| refused("public_key is not unpadded base64url".to_owned()))?;
        check(&public_key).map_err(refused)?;
        Ok(Self {
            credential_id,
            public_key,
        })
    }

    /// `WebAuthn` credential id.
    #[must_use]
    pub fn credential_id(&self) -> &[u8] {
        &self.credential_id
    }

    /// COSE public key, in its canonical encoding, which `landfall_approval::CoseKey`
    /// parses.
    #[must_use]
    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }
}

/// Refuses a credential id or a key held by two names: an approval is by one person, and
/// the host could not tell which.
pub(super) fn check_distinct(
    approvers: &BTreeMap<PrincipalId, Approver>,
) -> Result<(), ConfigError> {
    let mut ids = HashMap::new();
    let mut keys = HashMap::new();
    for (name, approver) in approvers {
        if let Some(first) = ids.insert(approver.credential_id(), name) {
            return Err(ConfigError::DuplicateCredentialId {
                first: first.clone(),
                second: name.clone(),
            });
        }
        if let Some(first) = keys.insert(approver.public_key(), name) {
            return Err(ConfigError::DuplicateApproverKey {
                first: first.clone(),
                second: name.clone(),
            });
        }
    }
    Ok(())
}

/// The hostname of an origin in the only form a browser writes: `https://`, the host in
/// lower case, a port only if it isn't the default, and nothing after that.
fn origin_host(origin: &str) -> Result<&str, &'static str> {
    let rest = origin
        .strip_prefix("https://")
        .ok_or("must start with \"https://\", in lower case")?;
    if rest.contains(['/', '?', '#', '\\']) {
        return Err("must have no path, query or fragment, not even a trailing '/'");
    }
    if rest.contains('@') {
        return Err("must have no user name or password");
    }
    if rest.starts_with('[') {
        return Err("must have a domain name as its host, not an IP address");
    }
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, Some(port)),
        None => (rest, None),
    };
    if let Some(port) = port {
        check_port(port)?;
    }
    check_host(host)?;
    Ok(host)
}

/// A port as a browser writes one: digits, no leading zero, never the default.
fn check_port(port: &str) -> Result<(), &'static str> {
    let bad = "must have a port from 1 to 65535 in plain digits, if it has one";
    if port.starts_with('0') || !port.bytes().all(|b| b.is_ascii_digit()) {
        return Err(bad);
    }
    match port.parse::<u16>() {
        Ok(DEFAULT_HTTPS_PORT) => Err("must leave out port 443, as a browser does"),
        Ok(_) => Ok(()),
        Err(_) => Err(bad),
    }
}

/// A lower-case DNS name in ASCII. `WebAuthn` 13.4.9 takes an RP ID to be a domain, so an
/// address is refused, which the URL standard takes any name ending in a number to be.
fn check_host(host: &str) -> Result<(), &'static str> {
    let bad = "must have a lower-case domain name as its host: labels of a-z, 0-9 and '-', \
               at most 63 bytes each and 253 in all, in xn-- form if it isn't ASCII";
    if host.len() > MAX_HOST_LEN {
        return Err(bad);
    }
    let mut last = "";
    for label in host.split('.') {
        let bytes = label.as_bytes();
        if bytes.is_empty()
            || bytes.len() > MAX_LABEL_LEN
            || bytes.first() == Some(&b'-')
            || bytes.last() == Some(&b'-')
            || !bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
        {
            return Err(bad);
        }
        last = label;
    }
    let is_number = last.bytes().all(|b| b.is_ascii_digit())
        || last
            .strip_prefix("0x")
            .is_some_and(|hex| hex.bytes().all(|b| b.is_ascii_hexdigit()));
    if is_number {
        return Err("must have a domain name as its host, not an IP address");
    }
    Ok(())
}
