//! Release facts shared by the controller, the agent and origin verification,
//! and the pure rules over them: one digest for the host to check, one run of the
//! release workflow per release, and the host's platform present in the image.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::ids::{ImageDigest, RepoName};
use crate::text::shown;

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

/// One run of a release workflow: the run and its attempt, as the Run Invocation
/// URI of a Fulcio certificate names them. Attempt 2 of a run is a re-run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ReleaseRun {
    /// The run id.
    pub run: u64,
    /// The attempt, from 1.
    pub attempt: u64,
}

impl fmt::Display for ReleaseRun {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "run {} attempt {}", self.run, self.attempt)
    }
}

/// A digest validly attested for a release, and the run that attested it, as the
/// verified certificate says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunCandidate {
    /// The digest.
    pub digest: ImageDigest,
    /// The certificate's Run Invocation URI.
    pub run_url: String,
}

/// Why a release's attested digests do not make one release.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum RunRuleError {
    /// A verified certificate names its run in a form this does not read, so the
    /// run is unknown and could be another one.
    #[error("the certificate for {digest} names its run as {url}, not a run and attempt")]
    BadRunUrl {
        /// The digest.
        digest: ImageDigest,
        /// The URI, quoted and bounded.
        url: String,
    },
    /// Several runs, or attempts of one run, attested the release: it was re-run.
    #[error(
        "the release was attested by {} workflow runs ({}); exactly one run and attempt is allowed",
        .runs.len(),
        Joined(.runs)
    )]
    SeveralRuns {
        /// The distinct runs, sorted.
        runs: Vec<ReleaseRun>,
    },
    /// The digest the version tag resolves to is not among the attested ones.
    #[error("the version tag's digest {digest} is not among the release's attested digests")]
    VersionDigestOutside {
        /// The digest the version tag resolves to.
        digest: ImageDigest,
    },
}

/// One number of a run URI: decimal digits only, no leading zero, not zero.
fn run_number(text: &str) -> Option<u64> {
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse().ok()
}

/// Reads a Run Invocation URI of `repo`, strictly
/// `https://github.com/<repo>/actions/runs/<id>/attempts/<n>`. The repository name
/// is compared ASCII case-insensitively, as GitHub treats it.
#[must_use]
pub fn parse_run_url(repo: &RepoName, url: &str) -> Option<ReleaseRun> {
    let rest = url.strip_prefix("https://github.com/")?;
    let (named, rest) = rest.split_at_checked(repo.as_ref().len())?;
    if !named.eq_ignore_ascii_case(repo.as_ref()) {
        return None;
    }
    let (run, attempt) = rest
        .strip_prefix("/actions/runs/")?
        .split_once("/attempts/")?;
    Some(ReleaseRun {
        run: run_number(run)?,
        attempt: run_number(attempt)?,
    })
}

/// The one run that made a release. Every candidate must come from one run and
/// attempt, so that several digests from it are image variants of one release,
/// while a second run or attempt is a re-run, which is refused. `version_digest`,
/// which the version tag resolves to, must be among the candidates.
///
/// # Errors
///
/// [`RunRuleError::BadRunUrl`] for a URI that is not a run and attempt of `repo`,
/// [`RunRuleError::SeveralRuns`] for more than one,
/// [`RunRuleError::VersionDigestOutside`] for a version digest not among them.
pub fn select_release_run(
    repo: &RepoName,
    candidates: &[RunCandidate],
    version_digest: &ImageDigest,
) -> Result<ReleaseRun, RunRuleError> {
    let mut runs = Vec::with_capacity(candidates.len());
    for candidate in candidates {
        let run =
            parse_run_url(repo, &candidate.run_url).ok_or_else(|| RunRuleError::BadRunUrl {
                digest: candidate.digest.clone(),
                url: shown(&candidate.run_url),
            })?;
        runs.push(run);
    }
    runs.sort_unstable();
    runs.dedup();
    if let [_, _, ..] = runs.as_slice() {
        return Err(RunRuleError::SeveralRuns { runs });
    }
    let outside = || RunRuleError::VersionDigestOutside {
        digest: version_digest.clone(),
    };
    if !candidates.iter().any(|c| c.digest == *version_digest) {
        return Err(outside());
    }
    runs.first().copied().ok_or_else(outside)
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
        DigestRuleError, Platform, PlatformError, ReleaseRun, RunCandidate, RunRuleError,
        parse_run_url, require_platform, select_release_digest, select_release_run,
    };

    fn digest(byte: &str) -> ImageDigest {
        format!("sha256:{}", byte.repeat(64)).parse().unwrap()
    }

    const RUN_1: &str = "https://github.com/example/app/actions/runs/1/attempts/1";

    fn candidate(byte: &str, run_url: &str) -> RunCandidate {
        RunCandidate {
            digest: digest(byte),
            run_url: run_url.to_owned(),
        }
    }

    fn run(run: u64, attempt: u64) -> ReleaseRun {
        ReleaseRun { run, attempt }
    }

    #[test]
    fn the_run_rule_counts_runs_not_digests() {
        let attempt_2 = "https://github.com/example/app/actions/runs/1/attempts/2";
        let run_2 = "https://github.com/example/app/actions/runs/2/attempts/1";
        let several = |runs| Err(RunRuleError::SeveralRuns { runs });
        let outside = |byte| {
            Err(RunRuleError::VersionDigestOutside {
                digest: digest(byte),
            })
        };
        let cases = [
            (
                "one digest",
                vec![candidate("a", RUN_1)],
                "a",
                Ok(run(1, 1)),
            ),
            (
                "variants of one run",
                vec![candidate("a", RUN_1), candidate("b", RUN_1)],
                "a",
                Ok(run(1, 1)),
            ),
            (
                "the other variant is the version's",
                vec![candidate("a", RUN_1), candidate("b", RUN_1)],
                "b",
                Ok(run(1, 1)),
            ),
            (
                "attempt 2 of the same run",
                vec![candidate("a", RUN_1), candidate("b", attempt_2)],
                "a",
                several(vec![run(1, 1), run(1, 2)]),
            ),
            (
                "only attempt 2 is fine",
                vec![candidate("a", attempt_2)],
                "a",
                Ok(run(1, 2)),
            ),
            (
                "two runs",
                vec![candidate("b", run_2), candidate("a", RUN_1)],
                "a",
                several(vec![run(1, 1), run(2, 1)]),
            ),
            (
                "the version's digest outside",
                vec![candidate("a", RUN_1)],
                "c",
                outside("c"),
            ),
            ("nothing attested", Vec::new(), "c", outside("c")),
        ];
        let repo = "example/app".parse().unwrap();
        for (name, candidates, version, expected) in cases {
            assert_eq!(
                select_release_run(&repo, &candidates, &digest(version)),
                expected,
                "{name}"
            );
        }
    }

    #[test]
    fn a_refusal_names_both_runs() {
        let repo = "example/app".parse().unwrap();
        let candidates = [
            candidate("a", RUN_1),
            candidate(
                "b",
                "https://github.com/example/app/actions/runs/1/attempts/2",
            ),
        ];
        let error = select_release_run(&repo, &candidates, &digest("a")).unwrap_err();
        let text = error.to_string();
        assert!(text.contains("run 1 attempt 1, run 1 attempt 2"), "{text}");
    }

    #[test]
    fn a_run_url_that_is_not_that_shape_fails_closed() {
        let repo = "example/app".parse().unwrap();
        for url in [
            "",
            "https://github.com/example/app/actions/runs/1",
            "https://github.com/example/app/actions/runs/1/attempts/",
            "https://github.com/example/app/actions/runs//attempts/1",
            "https://github.com/example/app/actions/runs/1/attempts/1/",
            "https://github.com/example/app/actions/runs/1/attempts/1?x=1",
            "https://github.com/example/app/actions/runs/1/attempts/1#x",
            "https://github.com/example/app/actions/runs/01/attempts/1",
            "https://github.com/example/app/actions/runs/1/attempts/0",
            "https://github.com/example/app/actions/runs/+1/attempts/1",
            "https://github.com/example/app/actions/runs/x/attempts/1",
            "https://github.com/example/app/actions/runs/99999999999999999999/attempts/1",
            "http://github.com/example/app/actions/runs/1/attempts/1",
            "https://github.com.evil.test/example/app/actions/runs/1/attempts/1",
            "https://github.com/other/app/actions/runs/1/attempts/1",
            "https://github.com/example/app/actions/runs/1/attempts/1\n",
        ] {
            assert_eq!(parse_run_url(&repo, url), None, "{url:?}");
            let candidates = [candidate("a", RUN_1), candidate("b", url)];
            let error = select_release_run(&repo, &candidates, &digest("a")).unwrap_err();
            assert!(
                matches!(error, RunRuleError::BadRunUrl { .. }),
                "{url:?}: {error:?}"
            );
        }
    }

    #[test]
    fn a_hostile_run_url_is_quoted_and_bounded_in_the_error() {
        let repo = "example/app".parse().unwrap();
        let hostile = format!("evil\n{}", "x".repeat(10_000));
        let candidates = [candidate("a", &hostile)];
        let text = select_release_run(&repo, &candidates, &digest("a"))
            .unwrap_err()
            .to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.len() < 400, "{}", text.len());
    }

    #[test]
    fn the_repository_name_is_compared_as_github_treats_it() {
        let repo = "Example/App".parse().unwrap();
        assert_eq!(parse_run_url(&repo, RUN_1), Some(run(1, 1)));
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
