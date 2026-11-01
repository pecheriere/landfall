//! The Sigstore trust root, built through TUF.
//!
//! The public-good `root.json` is embedded in the binary and is the only
//! trust anchor: every metadata file the repository serves, and every file
//! in the cache, is verified against it. [`Refresh::Online`] updates the
//! cache from the repository; [`Refresh::Offline`] makes no request and
//! re-verifies the cache, so a missing, tampered or expired cache is an
//! error and never a fallback to older or embedded material.

use std::path::Path;
use std::time::Duration;

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
/// against the embedded root.
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
) -> Result<TrustedRoot, TrustError> {
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

    TrustedRoot::from_tuf(config).await.map_err(|e| {
        let message = e.to_string();
        // The TUF client reports failures as text only.
        if message.contains("expired") {
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

    use super::{Refresh, TrustError, load_trusted_root};
    use crate::attestation::{Expected, verify_bundle};

    const BUNDLE: &[u8] = include_bytes!("../tests/fixtures/attestation/bundle.json");
    const INDEX_DIGEST: &str = include_str!("../tests/fixtures/attestation/index-digest.txt");

    #[tokio::test]
    async fn offline_with_empty_cache_fails_closed() {
        let dir = tempfile::tempdir().unwrap();
        let result = load_trusted_root(dir.path(), Refresh::Offline).await;
        assert!(matches!(result, Err(TrustError::Cache(_))), "{result:?}");
    }

    #[tokio::test]
    async fn cache_dir_must_exist() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent");
        for refresh in [Refresh::Online, Refresh::Offline] {
            let result = load_trusted_root(&missing, refresh).await;
            assert!(matches!(result, Err(TrustError::Cache(_))), "{result:?}");
        }
        assert!(!missing.exists(), "the cache directory was created");
    }

    #[tokio::test]
    async fn cache_dir_must_be_a_directory() {
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("file");
        std::fs::write(&file, b"x").unwrap();
        let result = load_trusted_root(&file, Refresh::Offline).await;
        assert!(matches!(result, Err(TrustError::Cache(_))), "{result:?}");
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
