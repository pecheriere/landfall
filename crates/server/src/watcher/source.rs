//! The real [`ReleaseSource`]: GitHub, the registry and the Sigstore trust root.
//!
//! The trust root is read through TUF, from its cache on disk, and refreshed over
//! the network at most once a day. It fails closed: when neither gives a root that
//! verifies, nothing is verified.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use landfall_core::config::Config;
use landfall_core::ids::{CommitSha, DeploymentId, ImageDigest, ReleaseTag};
use landfall_core::text::shown;
use landfall_origin::candidates::{CandidateCache, attested_digests};
use landfall_origin::fetch::{Fetcher, ListedTag};
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release_origin};
use landfall_origin::trust::{Refresh, TrustRoot, load_trusted_root};
use tokio::sync::Mutex;

use super::ReleaseSource;
use crate::agent_api::log;

/// The longest the trust root goes without a refresh.
const REFRESH_EVERY: Duration = Duration::from_hours(24);

/// How soon a refresh that failed is tried again, the cache being still good.
const REFRESH_RETRY: Duration = Duration::from_hours(1);

/// In the cache directory, written when a refresh succeeds: its modification time
/// says when, also across a restart. Tampering with it can only move the next
/// refresh, since every load verifies the metadata and its expiry.
const REFRESH_STAMP: &str = "landfall-refreshed";

#[derive(Debug, Default)]
struct TrustState {
    root: Option<Arc<TrustRoot>>,
    reload_at: Option<Instant>,
}

/// How long ago the last refresh was, if that can be told. A time in the future
/// cannot.
fn stamp_age(cache_dir: &Path) -> Option<Duration> {
    fs::metadata(cache_dir.join(REFRESH_STAMP))
        .and_then(|meta| meta.modified())
        .ok()?
        .elapsed()
        .ok()
}

/// Whether a refresh is due, given how long ago the last one was.
fn refresh_due(age: Option<Duration>) -> bool {
    age.is_none_or(|age| age >= REFRESH_EVERY)
}

/// Reads releases over the network.
#[derive(Debug)]
pub struct LiveSource {
    fetcher: Fetcher,
    config: Arc<Config>,
    cache_dir: PathBuf,
    trust: Mutex<TrustState>,
    candidates: CandidateCache,
}

impl LiveSource {
    /// A source that fetches with `fetcher`, for the deployments in `config`, with
    /// `cache_dir` as the TUF cache. Nothing is read until the first tick.
    #[must_use]
    pub fn new(fetcher: Fetcher, config: Arc<Config>, cache_dir: PathBuf) -> Self {
        Self {
            fetcher,
            config,
            cache_dir,
            trust: Mutex::default(),
            candidates: CandidateCache::default(),
        }
    }

    async fn root(&self) -> Result<Arc<TrustRoot>, ReleaseError> {
        self.trust
            .lock()
            .await
            .root
            .clone()
            .ok_or(ReleaseError::NoTrustRoot)
    }
}

impl ReleaseSource for LiveSource {
    async fn prepare(&self) -> Result<(), String> {
        let mut trust = self.trust.lock().await;
        if trust.root.is_some() && trust.reload_at.is_some_and(|at| Instant::now() < at) {
            return Ok(());
        }
        let age = stamp_age(&self.cache_dir);
        let mut good_for = age.map_or(REFRESH_RETRY, |age| REFRESH_EVERY.saturating_sub(age));
        if refresh_due(age) {
            match load_trusted_root(&self.cache_dir, Refresh::Online).await {
                Ok(root) => {
                    let now = format!("{:?}\n", std::time::SystemTime::now());
                    if let Err(error) = fs::write(self.cache_dir.join(REFRESH_STAMP), now) {
                        log(&format!("watcher: cannot note the TUF refresh: {error}"));
                    }
                    trust.root = Some(Arc::new(root));
                    trust.reload_at = Some(Instant::now() + REFRESH_EVERY);
                    return Ok(());
                }
                Err(error) => {
                    log(&format!(
                        "watcher: cannot refresh the Sigstore trust root: {}",
                        shown(&error.to_string())
                    ));
                    good_for = REFRESH_RETRY;
                }
            }
        }
        match load_trusted_root(&self.cache_dir, Refresh::Offline).await {
            Ok(root) => {
                trust.root = Some(Arc::new(root));
                trust.reload_at = Some(Instant::now() + good_for);
                Ok(())
            }
            Err(error) => {
                trust.root = None;
                Err(format!("the Sigstore trust root is unavailable: {error}"))
            }
        }
    }

    async fn tags(&self, deployment: &DeploymentId) -> Result<Vec<ListedTag>, ReleaseError> {
        let d = self
            .config
            .deployment(deployment)
            .ok_or_else(|| ReleaseError::UnknownDeployment(deployment.clone()))?;
        self.fetcher
            .list_release_tags(d.repo().name())
            .await
            .map_err(ReleaseError::Listing)
    }

    async fn verify(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<ReleaseOrigin, ReleaseError> {
        let root = self.root().await?;
        verify_release_origin(&self.fetcher, &root, &self.config, deployment, tag).await
    }

    async fn attested_digests(
        &self,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
        commit: &CommitSha,
    ) -> Result<Vec<ImageDigest>, ReleaseError> {
        let root = self.root().await?;
        let answer = attested_digests(
            &self.fetcher,
            &root,
            &self.config,
            (deployment, tag, commit),
            &self.candidates,
        )
        .await?;
        for ignored in answer.ignored {
            log(&format!(
                "watcher: {deployment}: candidate {} of {tag} does not count: {}",
                ignored.digest,
                shown(&ignored.reason)
            ));
        }
        Ok(answer.verified)
    }
}

#[cfg(test)]
mod tests {
    use landfall_origin::fetch::Endpoints;

    use super::*;

    const CONFIG: &str = r#"
[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }
"#;

    fn source(cache_dir: PathBuf) -> LiveSource {
        LiveSource::new(
            Fetcher::new(Endpoints::public().unwrap()).unwrap(),
            Arc::new(landfall_core::config::parse(CONFIG.as_bytes()).unwrap()),
            cache_dir,
        )
    }

    #[test]
    fn a_refresh_is_due_only_once_a_day() {
        assert!(refresh_due(None));
        assert!(!refresh_due(Some(Duration::ZERO)));
        assert!(!refresh_due(Some(Duration::from_secs(24 * 60 * 60 - 1))));
        assert!(refresh_due(Some(REFRESH_EVERY)));
    }

    #[test]
    fn a_stamp_says_how_long_ago_and_a_missing_one_says_nothing() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(stamp_age(dir.path()), None);
        fs::write(dir.path().join(REFRESH_STAMP), "x").unwrap();
        assert!(stamp_age(dir.path()).is_some_and(|age| age < REFRESH_EVERY));
    }

    #[tokio::test]
    async fn with_no_usable_cache_it_fails_closed_and_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let live = source(dir.path().join("absent"));
        let reason = live.prepare().await.unwrap_err();
        assert!(reason.contains("trust root is unavailable"), "{reason}");
        assert!(!dir.path().join("absent").exists());
        assert!(matches!(live.root().await, Err(ReleaseError::NoTrustRoot)));
    }

    #[tokio::test]
    async fn a_refresh_not_yet_due_touches_nothing_but_the_cache() {
        // Stamped just now, with an empty cache: no refresh is tried, so the
        // reading fails on the cache at once, with no network.
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join(REFRESH_STAMP), "x").unwrap();
        let reason = source(dir.path().to_owned()).prepare().await.unwrap_err();
        assert!(reason.contains("TUF cache"), "{reason}");
    }

    #[tokio::test]
    #[ignore = "network: the real Sigstore TUF repository"]
    async fn live_refreshes_once_then_reads_its_cache() {
        let dir = tempfile::tempdir().unwrap();
        source(dir.path().to_owned()).prepare().await.unwrap();
        assert!(stamp_age(dir.path()).is_some());
        // A new process, just as well: the stamp keeps it off the network.
        let again = source(dir.path().to_owned());
        again.prepare().await.unwrap();
        assert!(again.root().await.is_ok());
    }
}
