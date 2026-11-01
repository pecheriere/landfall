//! Release facts shared by the controller, the agent and origin verification,
//! and the pure rules over them: exactly one image digest per release, and
//! the host's platform present in the image.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::ImageDigest;

/// An image platform, as an OCI image index or Docker manifest list
/// declares it for one of its manifests.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Platform {
    /// Operating system, for example `linux`.
    pub os: String,
    /// CPU architecture, for example `arm64`.
    pub architecture: String,
    /// CPU variant, for example `v7` for `arm`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,
}

/// Shown as `os/architecture` or `os/architecture/variant`, the form
/// [`Platform::from_str`] reads.
impl fmt::Display for Platform {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.os, self.architecture)?;
        if let Some(variant) = &self.variant {
            write!(f, "/{variant}")?;
        }
        Ok(())
    }
}

/// A platform text that is not `os/architecture[/variant]`.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error(
    "invalid platform {0:?}: expected os/architecture or os/architecture/variant, \
     each part 1 to 32 bytes of [a-z0-9_-], for example linux/arm64"
)]
pub struct PlatformParseError(pub String);

impl FromStr for Platform {
    type Err = PlatformParseError;

    /// Reads `os/architecture` or `os/architecture/variant`, for example
    /// `linux/arm64` or `linux/arm/v7`.
    fn from_str(s: &str) -> Result<Self, PlatformParseError> {
        let valid = |part: &str| {
            (1..=32).contains(&part.len())
                && part.bytes().all(|b| {
                    b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-')
                })
        };
        let refuse = || PlatformParseError(s.to_owned());
        let parts: Vec<&str> = s.split('/').collect();
        if !parts.iter().all(|part| valid(part)) {
            return Err(refuse());
        }
        match parts.as_slice() {
            [os, architecture] => Ok(Self {
                os: (*os).to_owned(),
                architecture: (*architecture).to_owned(),
                variant: None,
            }),
            [os, architecture, variant] => Ok(Self {
                os: (*os).to_owned(),
                architecture: (*architecture).to_owned(),
                variant: Some((*variant).to_owned()),
            }),
            _ => Err(refuse()),
        }
    }
}

/// Why no single digest could be chosen for a release.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum DigestRuleError {
    /// No attested digest was found for the release.
    #[error("no attested image digest was found for the release")]
    None,
    /// Several distinct attested digests exist for the release, for example
    /// after a re-run release workflow.
    #[error(
        "the release has {} attested image digests ({}); exactly one is allowed",
        .digests.len(),
        Joined(.digests)
    )]
    Several {
        /// The distinct digests, in the order first seen.
        digests: Vec<ImageDigest>,
    },
}

/// Why the image cannot run on the host.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PlatformError {
    /// The index has no manifest for the wanted platform.
    #[error("the image has no {want} platform; it has {}", Joined(.available))]
    Missing {
        /// The platform asked for.
        want: Platform,
        /// The platforms the index lists.
        available: Vec<Platform>,
    },
}

/// Displays a list as `a, b, c`, or `none` when it is empty.
struct Joined<'a, T>(&'a [T]);

impl<T: fmt::Display> fmt::Display for Joined<'_, T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.is_empty() {
            return f.write_str("none");
        }
        for (index, item) in self.0.iter().enumerate() {
            if index > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{item}")?;
        }
        Ok(())
    }
}

/// The release's one image digest: the candidates must name exactly one
/// distinct digest. The same digest listed several times counts once.
///
/// # Errors
///
/// [`DigestRuleError::None`] for no candidate, [`DigestRuleError::Several`]
/// for more than one distinct digest.
pub fn select_release_digest(candidates: &[ImageDigest]) -> Result<&ImageDigest, DigestRuleError> {
    let mut distinct: Vec<&ImageDigest> = Vec::new();
    for candidate in candidates {
        if !distinct.contains(&candidate) {
            distinct.push(candidate);
        }
    }
    match distinct.as_slice() {
        [] => Err(DigestRuleError::None),
        [one] => Ok(one),
        several => Err(DigestRuleError::Several {
            digests: several.iter().map(|d| (*d).clone()).collect(),
        }),
    }
}

/// Requires `want` among `platforms`. Operating system and architecture must
/// be equal; the variant must be equal when `want` names one, and is not
/// compared when it does not.
///
/// # Errors
///
/// [`PlatformError::Missing`] naming the wanted and the available platforms.
pub fn require_platform(platforms: &[Platform], want: &Platform) -> Result<(), PlatformError> {
    let found = platforms.iter().any(|p| {
        p.os == want.os
            && p.architecture == want.architecture
            && want
                .variant
                .as_ref()
                .is_none_or(|v| p.variant.as_ref() == Some(v))
    });
    if found {
        Ok(())
    } else {
        Err(PlatformError::Missing {
            want: want.clone(),
            available: platforms.to_vec(),
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::ids::ImageDigest;

    use super::{
        DigestRuleError, Platform, PlatformError, require_platform, select_release_digest,
    };

    fn digest(byte: &str) -> ImageDigest {
        format!("sha256:{}", byte.repeat(64)).parse().unwrap()
    }

    fn platform(text: &str) -> Platform {
        text.parse().unwrap()
    }

    #[test]
    fn one_digest_is_selected() {
        let candidates = [digest("a")];
        assert_eq!(select_release_digest(&candidates), Ok(&digest("a")));
    }

    #[test]
    fn several_digests_are_refused() {
        let candidates = [digest("a"), digest("b"), digest("a")];
        assert_eq!(
            select_release_digest(&candidates),
            Err(DigestRuleError::Several {
                digests: vec![digest("a"), digest("b")],
            })
        );
    }

    #[test]
    fn same_digest_twice_counts_once() {
        let candidates = [digest("a"), digest("a")];
        assert_eq!(select_release_digest(&candidates), Ok(&digest("a")));
    }

    #[test]
    fn no_digest_is_refused() {
        assert_eq!(select_release_digest(&[]), Err(DigestRuleError::None));
    }

    #[test]
    fn missing_platform_is_refused() {
        let platforms = [platform("linux/amd64"), platform("linux/arm/v7")];
        let want = platform("linux/arm64");
        let error = require_platform(&platforms, &want).unwrap_err();
        assert_eq!(
            error,
            PlatformError::Missing {
                want,
                available: platforms.to_vec(),
            }
        );
        assert_eq!(
            error.to_string(),
            "the image has no linux/arm64 platform; it has linux/amd64, linux/arm/v7"
        );
    }

    #[test]
    fn variant_must_match_when_asked() {
        let platforms = [platform("linux/arm/v7"), platform("linux/arm64/v8")];
        assert!(require_platform(&platforms, &platform("linux/arm/v7")).is_ok());
        assert!(require_platform(&platforms, &platform("linux/arm/v6")).is_err());
        // No variant asked: any variant of the architecture will do.
        assert!(require_platform(&platforms, &platform("linux/arm")).is_ok());
        assert!(require_platform(&platforms, &platform("linux/arm64")).is_ok());
        // A variant asked of an entry that declares none does not match.
        let plain = [platform("linux/arm64")];
        assert!(require_platform(&plain, &platform("linux/arm64/v8")).is_err());
    }

    #[test]
    fn platform_text_round_trips_and_is_validated() {
        for text in ["linux/arm64", "linux/arm/v7", "windows/amd64"] {
            assert_eq!(platform(text).to_string(), text);
        }
        for text in [
            "",
            "linux",
            "linux/",
            "/arm64",
            "linux/arm/v7/x",
            "Linux/arm64",
            "linux/arm 64",
        ] {
            assert!(text.parse::<Platform>().is_err(), "{text:?}");
        }
    }
}
