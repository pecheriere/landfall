//! Every digest validly attested for one release, and the run that attested it
//! (design section 5.2, step 4, whose rule is
//! [`landfall_core::release::select_release_run`]).
//!
//! The registry lists a referrer tag for every digest with something attached,
//! whichever release it belongs to. Each is checked against this release's
//! identity, and only a bundle that verifies counts. So a candidate that cannot
//! verify cannot block a release, and is ignored. A candidate whose material
//! could not be read at all is different: it might have verified, so the whole
//! answer is an error and is asked for again later.
//!
//! A repository with `n` releases lists `n` digests for each of its `n` releases,
//! so what is learned about a digest is kept: a verified result for good, since a
//! bundle cannot stop having verified, and anything else for
//! [`RULED_OUT_LIFETIME`], since what is attached to a digest can change. A
//! certificate names the one ref it was issued for, so a bundle already seen to
//! name another release's ref need not be fetched again for each release.

use std::collections::HashMap;
use std::sync::{Mutex, PoisonError};
use std::time::{Duration, Instant};

use futures_util::{StreamExt as _, stream};
use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::release::RunCandidate;
use reqwest::header::HeaderValue;

use crate::attestation::{AttestationError, Expected};
use crate::fetch::{FetchError, Fetcher};
use crate::release::{ReleaseError, image_name, verify_bundle_off_runtime};
use crate::trust::TrustRoot;

/// How long a candidate that did not verify stays ruled out.
pub const RULED_OUT_LIFETIME: Duration = Duration::from_hours(1);

/// How long a candidate with nothing to verify, or whose material was junk, is left
/// alone. Short, since a good answer may be on its way, and there because every look
/// at one costs requests, for each of up to some thousands of tags.
pub const UNATTESTED_LIFETIME: Duration = Duration::from_mins(15);

/// Entries kept in each map of a [`CandidateCache`]. Past this it starts again,
/// which costs only requests: only a registry listing far more digests than any
/// real project has gets there.
const MAX_CACHE_ENTRIES: usize = 100_000;

/// Candidates looked at together. A real image lists hundreds, each a few requests,
/// which one after the other take minutes.
const CANDIDATES_AT_ONCE: usize = 8;

/// The certificate claim that names a bundle's ref.
const REF_CLAIM: &str = "source_repository_ref";
/// The claims checked before the ref, which hold for no release if they fail.
const CLAIMS_BEFORE_REF: [&str; 3] = [
    "issuer",
    "source_repository_identifier",
    "source_repository_owner_identifier",
];

/// One verified result: this digest verified for this release of this deployment.
type VerifiedKey = (DeploymentId, ImageDigest, ReleaseTag, CommitSha);

/// A digest that did not verify.
#[derive(Debug)]
struct RuledOut {
    until: Instant,
    /// The one ref it may still verify for; `None` when it verifies for none.
    except_ref: Option<String>,
}

#[derive(Debug, Default)]
struct CacheEntries {
    /// With the run its certificate names.
    verified: HashMap<VerifiedKey, String>,
    ruled_out: HashMap<(DeploymentId, ImageDigest), RuledOut>,
}

/// What is known about candidates, kept between calls.
#[derive(Debug)]
pub struct CandidateCache {
    ruled_out_lifetime: Duration,
    unattested_lifetime: Duration,
    entries: Mutex<CacheEntries>,
}

impl Default for CandidateCache {
    fn default() -> Self {
        Self::with_lifetimes(RULED_OUT_LIFETIME, UNATTESTED_LIFETIME)
    }
}

impl CandidateCache {
    fn with_lifetimes(ruled_out_lifetime: Duration, unattested_lifetime: Duration) -> Self {
        Self {
            ruled_out_lifetime,
            unattested_lifetime,
            entries: Mutex::default(),
        }
    }

    fn locked(&self) -> std::sync::MutexGuard<'_, CacheEntries> {
        // Every step leaves the maps valid, so a panic elsewhere changes nothing.
        self.entries.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn verified_run(&self, key: &VerifiedKey) -> Option<String> {
        self.locked().verified.get(key).cloned()
    }

    fn is_ruled_out(&self, key: &(DeploymentId, ImageDigest), git_ref: &str) -> bool {
        self.locked().ruled_out.get(key).is_some_and(|ruled_out| {
            Instant::now() < ruled_out.until && ruled_out.except_ref.as_deref() != Some(git_ref)
        })
    }

    fn keep_verified(&self, key: VerifiedKey, run_url: String) {
        let mut entries = self.locked();
        if entries.verified.len() >= MAX_CACHE_ENTRIES {
            entries.verified.clear();
        }
        entries.verified.insert(key, run_url);
    }

    fn keep_ruled_out(
        &self,
        key: (DeploymentId, ImageDigest),
        except_ref: Option<String>,
        lifetime: Duration,
    ) {
        let mut entries = self.locked();
        if entries.ruled_out.len() >= MAX_CACHE_ENTRIES {
            entries.ruled_out.clear();
        }
        entries.ruled_out.insert(
            key,
            RuledOut {
                until: Instant::now() + lifetime,
                except_ref,
            },
        );
    }
}

/// A candidate that does not count, and why. The reason is built from hostile
/// material: quote and bound it before showing it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IgnoredCandidate {
    /// The digest.
    pub digest: ImageDigest,
    /// Why it does not count.
    pub reason: String,
}

/// The answer for one release.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AttestedDigests {
    /// Every digest validly attested for the release, with the run that attested
    /// it, sorted by digest.
    pub verified: Vec<RunCandidate>,
    /// The candidates looked at this time that do not count. One already known
    /// not to count is not looked at, so it is not repeated here.
    pub ignored: Vec<IgnoredCandidate>,
}

/// Every digest validly attested for release `tag` of `deployment`, on `commit`.
/// `version_digest`, which was just verified for it, is always looked at whatever is
/// remembered about it. One pull token serves the whole look.
///
/// # Errors
///
/// [`ReleaseError::UnknownDeployment`] for a deployment not in the configuration;
/// [`ReleaseError::Listing`] when the list of referrer tags, or the material of
/// one candidate, could not be read, or the list is too long to read.
pub async fn attested_digests(
    fetcher: &Fetcher,
    root: &TrustRoot,
    config: &Config,
    (deployment, tag, commit, version_digest): (
        &DeploymentId,
        &ReleaseTag,
        &CommitSha,
        &ImageDigest,
    ),
    cache: &CandidateCache,
) -> Result<AttestedDigests, ReleaseError> {
    let d = config
        .deployment(deployment)
        .ok_or_else(|| ReleaseError::UnknownDeployment(deployment.clone()))?;
    let image = image_name(d.repo().name());
    let token = fetcher
        .pull_token(&image)
        .await
        .map_err(ReleaseError::Listing)?;
    let candidates = fetcher
        .list_referrer_digests_with(&image, &token)
        .await
        .map_err(ReleaseError::Listing)?;
    let expected = Expected {
        repo: d.repo().name(),
        repo_id: d.repo().id(),
        owner_id: d.repo().owner_id(),
        workflow: d.origin().workflow(),
        tag,
        commit,
    };
    let git_ref = format!("refs/tags/{tag}");

    let verified_key = |digest: &ImageDigest| {
        (
            deployment.clone(),
            digest.clone(),
            tag.clone(),
            commit.clone(),
        )
    };
    let mut answer = AttestedDigests::default();
    let mut unknown = Vec::new();
    for digest in candidates {
        if let Some(run_url) = cache.verified_run(&verified_key(&digest)) {
            answer.verified.push(RunCandidate { digest, run_url });
        } else if digest == *version_digest
            || !cache.is_ruled_out(&(deployment.clone(), digest.clone()), &git_ref)
        {
            unknown.push(digest);
        }
    }

    // An error leaves at once, and what was learned so far stays learned.
    let (image, expected, token) = (&image, &expected, &token);
    let mut checks = stream::iter(unknown)
        .map(|digest| async move {
            let checked = check_candidate(fetcher, root, (image, token), &digest, expected).await;
            (digest, checked)
        })
        .buffer_unordered(CANDIDATES_AT_ONCE);
    while let Some((digest, checked)) = checks.next().await {
        match checked? {
            Candidate::Verified(run_url) => {
                cache.keep_verified(verified_key(&digest), run_url.clone());
                answer.verified.push(RunCandidate { digest, run_url });
            }
            Candidate::Unattested(reason) => {
                cache.keep_ruled_out(
                    (deployment.clone(), digest.clone()),
                    None,
                    cache.unattested_lifetime,
                );
                answer.ignored.push(IgnoredCandidate { digest, reason });
            }
            Candidate::RuledOut { reason, except_ref } => {
                // A bundle naming another release's ref is what most of the list
                // is, and says nothing about this release.
                let of_another_release = except_ref.as_ref().is_some_and(|r| *r != git_ref);
                cache.keep_ruled_out(
                    (deployment.clone(), digest.clone()),
                    except_ref,
                    cache.ruled_out_lifetime,
                );
                if !of_another_release {
                    answer.ignored.push(IgnoredCandidate { digest, reason });
                }
            }
        }
    }
    answer.verified.sort_by(|a, b| a.digest.cmp(&b.digest));
    Ok(answer)
}

/// What one candidate turned out to be.
enum Candidate {
    /// With the Run Invocation URI of its certificate.
    Verified(String),
    /// Nothing is attached yet, or what was served was junk, and something better
    /// may be soon.
    Unattested(String),
    /// A verification result: its bundle was read and does not verify.
    RuledOut {
        reason: String,
        except_ref: Option<String>,
    },
}

async fn check_candidate(
    fetcher: &Fetcher,
    root: &TrustRoot,
    (image, token): (&str, &HeaderValue),
    digest: &ImageDigest,
    expected: &Expected<'_>,
) -> Result<Candidate, ReleaseError> {
    let bundle = match fetcher.bundle_with(image, digest, token).await {
        Ok(bundle) => bundle,
        Err(error @ (FetchError::NotFound { .. } | FetchError::Bundles { count: 0, .. })) => {
            return Ok(Candidate::Unattested(error.to_string()));
        }
        Err(error) if error.is_unavailable() => return Err(ReleaseError::Listing(error)),
        // Junk from the registry says nothing about the digest.
        Err(error) => return Ok(Candidate::Unattested(error.to_string())),
    };
    match verify_bundle_off_runtime(bundle, digest, root, expected).await? {
        Ok(attestation) => Ok(Candidate::Verified(attestation.run_url)),
        Err(error @ AttestationError::Bundle(_)) => Ok(Candidate::Unattested(error.to_string())),
        Err(error) => {
            let except_ref = match &error {
                AttestationError::Identity { field, found, .. } if *field == REF_CLAIM => {
                    Some(found.clone())
                }
                AttestationError::Identity { field, .. } if !CLAIMS_BEFORE_REF.contains(field) => {
                    // The ref was this release's, and something after it was not.
                    Some(format!("refs/tags/{}", expected.tag))
                }
                _ => None,
            };
            Ok(Candidate::RuledOut {
                reason: error.to_string(),
                except_ref,
            })
        }
    }
}

#[cfg(test)]
mod tests;
