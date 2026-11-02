//! The secrets a person or a program holds: shown once, stored as a SHA-256.

use std::fmt;

use sha2::{Digest as _, Sha256};

/// What every API token starts with, so that a secret scanner can tell one.
const TOKEN_PREFIX: &str = "lf_";

/// 32 random bytes with no equality, and no `Debug` that prints them.
struct Secret([u8; 32]);

impl Secret {
    fn random() -> Result<Self, getrandom::Error> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// Exactly 64 lowercase hex digits, so that a secret has one spelling. A longer or
    /// stranger value, binary included, is `None`, with nothing done with it first.
    fn parse(text: &str) -> Option<Self> {
        let lowercase_hex = |b: u8| b.is_ascii_digit() || (b'a'..=b'f').contains(&b);
        if text.len() != 64 || !text.bytes().all(lowercase_hex) {
            return None;
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(text, &mut bytes).ok()?;
        Some(Self(bytes))
    }

    fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.0).into()
    }
}

/// An API token. Only its SHA-256 is stored.
pub struct ApiToken(Secret);

impl ApiToken {
    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        Secret::random().map(Self)
    }

    /// The token as it is sent, from an `Authorization` header: `None` for anything that
    /// isn't exactly the form [`reveal`](Self::reveal) gives.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Secret::parse(text.strip_prefix(TOKEN_PREFIX)?).map(Self)
    }

    /// The token as its holder uses it. Show it once: nothing can give it again.
    #[must_use]
    pub fn reveal(&self) -> String {
        format!("{TOKEN_PREFIX}{}", hex::encode(self.0.0))
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        self.0.hash()
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken(<redacted>)")
    }
}

/// What a signed-in browser holds. Only its SHA-256 is stored.
pub struct SessionToken(Secret);

impl SessionToken {
    /// The token as a cookie carries it: 64 lowercase hex digits, and `None` otherwise.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Secret::parse(text).map(Self)
    }

    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        Secret::random().map(Self)
    }

    /// The cookie's value. It goes in that one `Set-Cookie`, and nowhere else.
    pub(crate) fn reveal(&self) -> String {
        hex::encode(self.0.0)
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        self.0.hash()
    }
}

impl fmt::Debug for SessionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SessionToken(<redacted>)")
    }
}

/// A one-time link's code, to register a passkey. Only its SHA-256 is stored.
pub struct PasskeyInvite(Secret);

impl PasskeyInvite {
    pub(crate) fn random() -> Result<Self, getrandom::Error> {
        Secret::random().map(Self)
    }

    /// The code as the page sends it: 64 lowercase hex digits, and `None` otherwise.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Secret::parse(text).map(Self)
    }

    /// The code as the link carries it: 64 hex digits.
    #[must_use]
    pub fn reveal(&self) -> String {
        hex::encode(self.0.0)
    }

    pub(crate) fn hash(&self) -> [u8; 32] {
        self.0.hash()
    }
}

impl fmt::Debug for PasskeyInvite {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasskeyInvite(<redacted>)")
    }
}

#[cfg(test)]
mod tests {
    use super::{ApiToken, PasskeyInvite, SessionToken};

    #[test]
    fn a_token_reads_back_as_itself_and_its_debug_says_nothing() {
        let token = ApiToken::random().unwrap();
        let text = token.reveal();
        assert_eq!(ApiToken::parse(&text).unwrap().hash(), token.hash());
        let digits = text.strip_prefix("lf_").unwrap();
        for debug in [
            format!("{token:?}"),
            format!("{:?}", PasskeyInvite::random().unwrap()),
            format!("{:?}", SessionToken::parse(digits).unwrap()),
        ] {
            assert!(debug.contains("redacted"), "{debug}");
            assert!(!debug.contains(digits), "{debug}");
        }
    }

    #[test]
    fn only_one_spelling_of_a_token_parses() {
        let good = ApiToken::random().unwrap().reveal();
        let digits = good.strip_prefix("lf_").unwrap();
        for bad in [
            String::new(),
            "lf_".to_owned(),
            digits.to_owned(),
            good.to_uppercase(),
            format!("lf_{}", "AB".repeat(32)),
            format!("{good}0"),
            good[..good.len() - 1].to_owned(),
            format!("lf_{}", "é".repeat(32)),
            format!("lf_{}", "g".repeat(64)),
            "lf_".repeat(100_000),
        ] {
            assert!(ApiToken::parse(&bad).is_none(), "{bad}");
        }
    }
}
