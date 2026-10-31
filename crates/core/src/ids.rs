//! Validated identifiers.
//!
//! Every type here is a newtype over a string that is checked once, when it
//! is parsed. Deserialisation goes through [`FromStr`], so an invalid value in
//! a configuration file or an API payload is an error at the point it enters
//! the system. The checks are byte-level and hand-written: no regex engine.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use thiserror::Error;

/// A rejected identifier, carrying the text that was refused.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum IdError {
    /// Not `<name>/<stage>` with each part `[a-z0-9][a-z0-9-]{0,62}`.
    #[error("invalid deployment id {0:?}: expected <name>/<stage>, each [a-z0-9][a-z0-9-]{{0,62}}")]
    Deployment(String),
    /// Not `[a-z0-9][a-z0-9-]{0,62}`.
    #[error("invalid host id {0:?}: expected [a-z0-9][a-z0-9-]{{0,62}}")]
    Host(String),
    /// Not `[a-z0-9][a-z0-9-]{0,62}`.
    #[error("invalid principal id {0:?}: expected [a-z0-9][a-z0-9-]{{0,62}}")]
    Principal(String),
    /// Not a GitHub `<owner>/<repo>` name.
    #[error("invalid repository name {0:?}: expected <owner>/<repo> with GitHub naming rules")]
    Repo(String),
    /// Not `sha256:` followed by 64 lowercase hex digits.
    #[error("invalid image digest {0:?}: expected sha256: followed by 64 lowercase hex digits")]
    Digest(String),
    /// Not 40 lowercase hex digits.
    #[error("invalid commit sha {0:?}: expected 40 lowercase hex digits")]
    Commit(String),
    /// Not `<prefix>*` with prefix `[A-Za-z0-9._/-]{0,32}`.
    #[error("invalid tag pattern {0:?}: expected <prefix>*, prefix [A-Za-z0-9._/-]{{0,32}}")]
    TagPattern(String),
}

/// A tag that does not match its pattern or is not strict semver.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("tag {tag:?} refused: {reason}")]
pub struct TagError {
    /// The tag that was refused.
    pub tag: String,
    /// Why it was refused.
    pub reason: &'static str,
}

/// Implements the traits shared by every identifier newtype.
macro_rules! id_type {
    ($(#[$meta:meta])* $name:ident, $variant:ident, $valid:path) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl FromStr for $name {
            type Err = IdError;

            fn from_str(s: &str) -> Result<Self, IdError> {
                if $valid(s) {
                    Ok(Self(s.to_owned()))
                } else {
                    Err(IdError::$variant(s.to_owned()))
                }
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                text.parse().map_err(serde::de::Error::custom)
            }
        }
    };
}

/// `[a-z0-9][a-z0-9-]{0,62}`.
fn is_label(s: &str) -> bool {
    let bytes = s.as_bytes();
    (1..=63).contains(&bytes.len())
        && (bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit())
        && bytes[1..]
            .iter()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-')
}

fn is_deployment(s: &str) -> bool {
    s.split_once('/')
        .is_some_and(|(name, stage)| is_label(name) && is_label(stage))
}

fn is_repo(s: &str) -> bool {
    s.split_once('/').is_some_and(|(owner, repo)| {
        (1..=39).contains(&owner.len())
            && owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            && (1..=100).contains(&repo.len())
            && repo != "."
            && repo != ".."
            && repo
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    })
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

fn is_digest(s: &str) -> bool {
    s.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && is_lower_hex(hex))
}

fn is_commit(s: &str) -> bool {
    s.len() == 40 && is_lower_hex(s)
}

id_type!(
    /// A deployment: `<name>/<stage>`, each part `[a-z0-9][a-z0-9-]{0,62}`.
    DeploymentId,
    Deployment,
    is_deployment
);
id_type!(
    /// A target host: `[a-z0-9][a-z0-9-]{0,62}`.
    HostId,
    Host,
    is_label
);
id_type!(
    /// A person or agent that can approve: `[a-z0-9][a-z0-9-]{0,62}`.
    PrincipalId,
    Principal,
    is_label
);
id_type!(
    /// A GitHub repository, `<owner>/<repo>`.
    RepoName,
    Repo,
    is_repo
);
id_type!(
    /// An image content digest: `sha256:` and 64 lowercase hex digits.
    ImageDigest,
    Digest,
    is_digest
);
id_type!(
    /// A git commit: 40 lowercase hex digits.
    CommitSha,
    Commit,
    is_commit
);

/// Which tags count as releases: `"<prefix>*"`, for example `"v*"`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TagPattern {
    prefix: String,
}

impl TagPattern {
    /// Extracts the version from `tag`: strips the literal prefix, parses
    /// strict semver and refuses build metadata.
    ///
    /// # Errors
    ///
    /// Returns [`TagError`] when the prefix is missing, the rest is not
    /// strict semver (`MAJOR.MINOR.PATCH`, no leading zeros) or the version
    /// carries build metadata.
    pub fn parse_tag(&self, tag: &str) -> Result<semver::Version, TagError> {
        let refuse = |reason| TagError {
            tag: tag.to_owned(),
            reason,
        };
        let rest = tag
            .strip_prefix(&self.prefix)
            .ok_or_else(|| refuse("does not start with the pattern prefix"))?;
        let version = semver::Version::parse(rest)
            .map_err(|_| refuse("not a strict semantic version after the prefix"))?;
        if version.build.is_empty() {
            Ok(version)
        } else {
            Err(refuse("build metadata (+...) is not allowed"))
        }
    }
}

impl FromStr for TagPattern {
    type Err = IdError;

    fn from_str(s: &str) -> Result<Self, IdError> {
        s.strip_suffix('*')
            .filter(|prefix| {
                prefix.len() <= 32
                    && prefix.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'/' | b'-')
                    })
            })
            .map(|prefix| Self {
                prefix: prefix.to_owned(),
            })
            .ok_or_else(|| IdError::TagPattern(s.to_owned()))
    }
}

impl fmt::Display for TagPattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}*", self.prefix)
    }
}

impl Serialize for TagPattern {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for TagPattern {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use semver::{Prerelease, Version};
    use serde::Deserialize;

    use super::*;

    #[test]
    fn ids_accept_valid_values() {
        assert!("app/prod".parse::<DeploymentId>().is_ok());
        assert!("home-1".parse::<HostId>().is_ok());
        assert!("maintainer".parse::<PrincipalId>().is_ok());
        assert!("example/app".parse::<RepoName>().is_ok());
        assert!(
            format!("sha256:{}", "a".repeat(64))
                .parse::<ImageDigest>()
                .is_ok()
        );
        assert!(
            "0123456789abcdef0123456789abcdef01234567"
                .parse::<CommitSha>()
                .is_ok()
        );
        assert!("v*".parse::<TagPattern>().is_ok());
        assert!("*".parse::<TagPattern>().is_ok());
    }

    #[test]
    fn ids_reject_invalid_values() {
        for bad in [
            "app",
            "App/prod",
            "app/prod/x",
            "-app/prod",
            "app/",
            "/prod",
        ] {
            assert!(bad.parse::<DeploymentId>().is_err(), "{bad}");
        }
        let too_long = "a".repeat(64);
        assert!(format!("{too_long}/prod").parse::<DeploymentId>().is_err());
        assert!("Home".parse::<HostId>().is_err());
        assert!("".parse::<PrincipalId>().is_err());
        for bad in [
            "example",
            "example/..",
            "example/.",
            "ex ample/app",
            "/app",
            "example/",
        ] {
            assert!(bad.parse::<RepoName>().is_err(), "{bad}");
        }
        assert!(
            format!("sha256:{}", "A".repeat(64))
                .parse::<ImageDigest>()
                .is_err()
        );
        assert!(
            format!("sha512:{}", "a".repeat(64))
                .parse::<ImageDigest>()
                .is_err()
        );
        assert!(
            format!("sha256:{}", "a".repeat(63))
                .parse::<ImageDigest>()
                .is_err()
        );
        assert!("a".repeat(39).parse::<CommitSha>().is_err());
        assert!("A".repeat(40).parse::<CommitSha>().is_err());
        for bad in ["v", "v**", "v*x", "v 1*", "*v"] {
            assert!(bad.parse::<TagPattern>().is_err(), "{bad}");
        }
        assert!(
            format!("{}*", "v".repeat(33))
                .parse::<TagPattern>()
                .is_err()
        );
    }

    #[test]
    fn ids_round_trip_through_display() {
        let id: DeploymentId = "app/prod".parse().unwrap();
        assert_eq!(id.to_string(), "app/prod");
        assert_eq!(id.as_ref(), "app/prod");
    }

    #[test]
    fn tags_parse_with_their_prefix() {
        let pattern: TagPattern = "v*".parse().unwrap();
        assert_eq!(pattern.parse_tag("v1.2.3").unwrap(), Version::new(1, 2, 3));
        let rc = pattern.parse_tag("v1.3.0-rc.1").unwrap();
        assert_eq!(rc.pre, Prerelease::new("rc.1").unwrap());
        let bare: TagPattern = "*".parse().unwrap();
        assert_eq!(bare.parse_tag("1.2.3").unwrap(), Version::new(1, 2, 3));
    }

    #[test]
    fn tags_that_only_look_like_versions_are_rejected() {
        let pattern: TagPattern = "v*".parse().unwrap();
        for bad in ["v1.2", "v01.2.3", "1.2.3", "v1.2.3+build", "release-1.2.3"] {
            assert!(pattern.parse_tag(bad).is_err(), "{bad}");
        }
        let err = pattern.parse_tag("v1.2.3+build").unwrap_err();
        assert!(err.reason.contains("build metadata"), "{err}");
    }

    #[test]
    fn invalid_ids_fail_deserialisation() {
        #[derive(Debug, Deserialize)]
        struct Wrapper {
            id: DeploymentId,
        }
        assert!(toml::from_str::<Wrapper>("id = \"App\"").is_err());
        let ok = toml::from_str::<Wrapper>("id = \"app/prod\"").unwrap();
        assert_eq!(ok.id.as_ref(), "app/prod");
    }
}
