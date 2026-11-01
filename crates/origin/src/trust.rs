//! The Sigstore trust root, built through TUF.
//!
//! The public-good `root.json` is embedded in the binary and is the only
//! trust anchor: every metadata file the repository serves, and every file
//! in the cache, is verified against it. [`Refresh::Online`] updates the
//! cache from the repository; [`Refresh::Offline`] makes no request and
//! re-verifies the cache, so a missing, tampered or expired cache is an
//! error and never a fallback to older or embedded material.
//!
//! The result is a [`TrustRoot`], which only [`load_trusted_root`] makes:
//! every bundle is verified against a root that came through TUF.

use std::path::Path;
use std::time::Duration;

use jiff::Timestamp;
use sigstore_verify::trust_root::reqwest::Client;
use sigstore_verify::trust_root::{TrustedRoot, TufBootstrap, TufConfig};
use thiserror::Error;

/// The public-good Sigstore TUF repository.
const TUF_URL: &str = "https://tuf-repo-cdn.sigstore.dev";

/// The embedded trust anchor; provenance in `assets/README.md`.
const ROOT_JSON: &[u8] = include_bytes!("../assets/sigstore-root.json");

/// Connect timeout for every request to the repository.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total timeout for every request to the repository.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Whether the trust root may be refreshed from the network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refresh {
    /// Update the cache from the TUF repository, then build the root.
    Online,
    /// Make no request: re-verify the cache and build the root from it.
    Offline,
}

/// The Sigstore trust root bundles are verified against: the Fulcio
/// certificate authorities, Rekor logs and certificate transparency logs of
/// the public-good instance. Only [`load_trusted_root`] makes one in
/// production code.
#[derive(Debug, Clone)]
pub struct TrustRoot(TrustedRoot);

impl TrustRoot {
    /// The root for the Sigstore verifier.
    pub(crate) fn inner(&self) -> &TrustedRoot {
        &self.0
    }

    /// A root parsed from a `trusted_root.json` snapshot, without TUF. Test
    /// builds only, for fixtures verified offline.
    #[cfg(test)]
    pub(crate) fn from_json(json: &str) -> Self {
        Self(TrustedRoot::from_json(json).unwrap())
    }
}

/// Why the trust root could not be built.
#[derive(Debug, Error)]
pub enum TrustError {
    /// The cache directory is unusable, or the cache is missing or invalid.
    #[error("TUF cache: {0}")]
    Cache(String),
    /// Verified TUF metadata has passed its expiry time.
    #[error("TUF metadata has expired: {0}")]
    Expired(String),
    /// The repository could not be fetched or its metadata did not verify.
    #[error("TUF fetch: {0}")]
    Fetch(String),
}

/// Builds the Sigstore trust root with `cache_dir` as the TUF cache.
///
/// `cache_dir` must already exist and be a directory; it is never created.
/// The cache is untrusted input: everything read from it is re-verified
/// against the embedded root. Even [`Refresh::Offline`] may write to
/// `cache_dir`: newer root versions it verified on the way from the embedded
/// root are stored there. It makes no network request.
///
/// # Errors
///
/// [`TrustError::Cache`] when `cache_dir` is not an existing directory, or
/// (offline) the cache is missing or invalid; [`TrustError::Expired`] when
/// the metadata is past its expiry; [`TrustError::Fetch`] when an online
/// refresh fails.
pub async fn load_trusted_root(
    cache_dir: &Path,
    refresh: Refresh,
) -> Result<TrustRoot, TrustError> {
    load_trusted_root_at(cache_dir, refresh, Timestamp::now()).await
}

/// [`load_trusted_root`] with TUF metadata expiry evaluated at `now`, so
/// tests do not depend on the calendar.
async fn load_trusted_root_at(
    cache_dir: &Path,
    refresh: Refresh,
    now: Timestamp,
) -> Result<TrustRoot, TrustError> {
    let meta = std::fs::metadata(cache_dir)
        .map_err(|e| TrustError::Cache(format!("{}: {e}", cache_dir.display())))?;
    if !meta.is_dir() {
        return Err(TrustError::Cache(format!(
            "{} is not a directory",
            cache_dir.display()
        )));
    }

    let client = Client::builder()
        .connect_timeout(CONNECT_TIMEOUT)
        .timeout(REQUEST_TIMEOUT)
        .https_only(true)
        .build()
        .map_err(|e| TrustError::Fetch(format!("HTTP client: {e}")))?;
    let mut config = TufConfig::custom(TUF_URL, TufBootstrap::trusted(ROOT_JSON))
        .with_cache_dir(cache_dir.to_path_buf())
        .with_http_client(client);
    if refresh == Refresh::Offline {
        config = config.offline();
    }

    TrustedRoot::from_tuf_at(config, now)
        .await
        .map(TrustRoot)
        .map_err(|e| {
            let message = e.to_string();
            // The TUF client reports failures as text only; this is its message
            // for metadata past its expiry (sigstore-tuf `Error::Expired`).
            if message.contains(" metadata expired at ") {
                TrustError::Expired(message)
            } else if refresh == Refresh::Offline {
                TrustError::Cache(message)
            } else {
                TrustError::Fetch(message)
            }
        })
}

#[cfg(test)]
mod tests {
    use landfall_core::ids::{CommitSha, ImageDigest, ReleaseTag, RepoName};

    use jiff::{SignedDuration, Timestamp};

    use super::{Refresh, TrustError, load_trusted_root, load_trusted_root_at};
    use crate::attestation::{Expected, verify_bundle};

    const BUNDLE: &[u8] = include_bytes!("../tests/fixtures/attestation/bundle.json");
    const INDEX_DIGEST: &str = include_str!("../tests/fixtures/attestation/index-digest.txt");

    /// Well before the embedded root expires, so the tests never depend on
    /// the calendar.
    fn fixed_now() -> Timestamp {
        "2026-11-01T00:00:00Z".parse().unwrap()
    }

    /// The error, for an assertion message; a trust root is not printed.
    fn outcome(result: &Result<super::TrustRoot, TrustError>) -> String {
        match result {
            Ok(_) => "a trust root".to_owned(),
            Err(error) => error.to_string(),
        }
    }

    #[tokio::test]
    async fn offline_with_empty_cache_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_trusted_root_at(dir.path(), Refresh::Offline, fixed_now()).await;
        assert!(
            matches!(result, Err(TrustError::Cache(_))),
            "{}",
            outcome(&result)
        );
    }

    #[tokio::test]
    async fn cache_dir_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        for refresh in [Refresh::Online, Refresh::Offline] {
            let result = load_trusted_root(&missing, refresh).await;
            assert!(
                matches!(result, Err(TrustError::Cache(_))),
                "{}",
                outcome(&result)
            );
        }
        assert!(!missing.exists(), "the cache directory was created");
    }

    #[tokio::test]
    async fn cache_dir_must_be_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let result = load_trusted_root_at(&file, Refresh::Offline, fixed_now()).await;
        assert!(
            matches!(result, Err(TrustError::Cache(_))),
            "{}",
            outcome(&result)
        );
    }

    #[tokio::test]
    #[ignore = "network: runs nightly in advisories.yml"]
    async fn live_refresh_then_offline() {
        let dir = tempfile::tempdir().unwrap();
        let online = load_trusted_root(dir.path(), Refresh::Online)
            .await
            .unwrap();
        let offline = load_trusted_root(dir.path(), Refresh::Offline)
            .await
            .unwrap();
        // The timestamp metadata lives 7 days: a month on, the cache is stale.
        let later = Timestamp::now()
            .checked_add(SignedDuration::from_hours(30 * 24))
            .unwrap();
        let stale = load_trusted_root_at(dir.path(), Refresh::Offline, later).await;
        assert!(
            matches!(stale, Err(TrustError::Expired(_))),
            "{}",
            outcome(&stale)
        );

        let repo: RepoName = "dani-garcia/vaultwarden".parse().unwrap();
        let tag: ReleaseTag = "1.37.4".parse().unwrap();
        let commit: CommitSha = "7c188967e7a467b19b2757bc3326f9cf3ccae327".parse().unwrap();
        let expected = Expected {
            repo: &repo,
            repo_id: 121_898_717,
            owner_id: 725_423,
            workflow: ".github/workflows/release.yml",
            tag: &tag,
            commit: &commit,
        };
        let digest: ImageDigest = INDEX_DIGEST.trim().parse().unwrap();
        for root in [&online, &offline] {
            verify_bundle(BUNDLE, &digest, root, &expected).unwrap();
        }
    }
}
