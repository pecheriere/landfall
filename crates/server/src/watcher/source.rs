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
use landfall_core::release::RunCandidate;
use landfall_core::text::shown;
use landfall_origin::candidates::{CandidateCache, attested_digests};
use landfall_origin::fetch::{Fetcher, ListedTag};
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release_origin};
use landfall_origin::trust::{Refresh, TrustRoot, load_trusted_root};
use tokio::sync::Mutex;

use super::ReleaseSource;
use crate::logger::log;

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

/// [`stamp_age`] on a blocking thread: the disk may be slow, and the runtime's
/// threads have others to serve.
async fn stamp_age_off_runtime(cache_dir: &Path) -> Option<Duration> {
    let cache_dir = cache_dir.to_owned();
    tokio::task::spawn_blocking(move || stamp_age(&cache_dir))
        .await
        .ok()
        .flatten()
}

/// Notes on a blocking thread that a refresh succeeded just now.
async fn write_stamp_off_runtime(cache_dir: &Path) {
    let stamp = cache_dir.join(REFRESH_STAMP);
    let written = tokio::task::spawn_blocking(move || {
        fs::write(stamp, format!("{:?}\n", std::time::SystemTime::now()))
    })
    .await;
    match written {
        Ok(Ok(())) => {}
        Ok(Err(error)) => log(&format!("watcher: cannot note the TUF refresh: {error}")),
        Err(error) => log(&format!("watcher: cannot note the TUF refresh: {error}")),
    }
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
        let age = stamp_age_off_runtime(&self.cache_dir).await;
        let mut good_for = age.map_or(REFRESH_RETRY, |age| REFRESH_EVERY.saturating_sub(age));
        if refresh_due(age) {
            match load_trusted_root(&self.cache_dir, Refresh::Online).await {
                Ok(root) => {
                    write_stamp_off_runtime(&self.cache_dir).await;
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
        version_digest: &ImageDigest,
    ) -> Result<Vec<RunCandidate>, ReleaseError> {
        let root = self.root().await?;
        let answer = attested_digests(
            &self.fetcher,
            &root,
            &self.config,
            (deployment, tag, commit, version_digest),
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

    use super::{
        Arc, DeploymentId, Duration, Fetcher, LiveSource, PathBuf, REFRESH_EVERY, REFRESH_STAMP,
        ReleaseError, ReleaseSource as _, fs, refresh_due, stamp_age,
    };

    const CONFIG: &str = r#"
[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }
"#;

    fn source(cache_dir: PathBuf) -> LiveSource {
        LiveSource::new(
            Fetcher::new(Endpoints::public().unwrap()).unwrap(),
            Arc::new(landfall_approval::parse_config(CONFIG.as_bytes()).unwrap()),
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

    /// One deployment of the attestation fixture's project, unsigned, with its real
    /// ids and a patch rule.
    const LIVE_CONFIG: &str = r#"
[approval]
rp_id = "landfall.example"
origin = "https://landfall.example"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "pAEBAycgBiFYINdamAGCsQq31Uv-08lkBzoO4XLz2qYjJa8CGmj3B1Ea" }

[[deployment]]
id = "app/prod"
repo = { name = "dani-garcia/vaultwarden", id = 121898717, owner_id = 725423 }
host = "host-a"
compose = { dir = "/srv/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "*", signed_tags = false }
rule = { auto = "patch", approvers = ["operator"] }
checks = ["container-healthy"]
"#;

    /// Real GitHub, GHCR and Sigstore: a real release with two image variants from
    /// one run gets decided, and a deploy of the highest patch of its line queued.
    /// It may take more than a tick, so that newer releases than this one, each
    /// verified first, do not fail it as they appear.
    #[tokio::test]
    #[ignore = "network: GitHub, GHCR and the Sigstore TUF repository"]
    async fn live_a_tick_decides_a_real_release() {
        use landfall_core::protocol::{DeployedRelease, Phase, RunningState};

        use crate::store::{ReleaseDecision, Store};
        use crate::watcher::{WatcherState, tick};

        const DIGEST: &str =
            "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055";
        let dir = tempfile::tempdir().unwrap();
        let config = Arc::new(landfall_approval::parse_config(LIVE_CONFIG.as_bytes()).unwrap());
        let mut fetcher = Fetcher::new(Endpoints::public().unwrap()).unwrap();
        if let Some(token) = std::env::var("GITHUB_TOKEN").ok().filter(|t| !t.is_empty()) {
            fetcher = fetcher.with_github_token(&token).unwrap();
        }
        let live = Arc::new(LiveSource::new(
            fetcher,
            Arc::clone(&config),
            dir.path().to_owned(),
        ));
        let store = Store::open_in_memory().await.unwrap();
        let deployment: DeploymentId = "app/prod".parse().unwrap();
        let running = RunningState {
            deployment: deployment.clone(),
            deployed: Some(DeployedRelease {
                tag: "1.37.3".parse().unwrap(),
                digest: format!("sha256:{}", "a".repeat(64)).parse().unwrap(),
            }),
            drift: false,
            phase: Phase::Idle,
            busy: false,
        };
        let host = "host-a".parse().unwrap();
        store
            .record_host_state(&host, None, &[&running])
            .await
            .unwrap();
        let state = Arc::new(WatcherState::default());

        let mut queued = Vec::new();
        for _ in 0..10 {
            let summary = tick(&store, &config, &live, &state).await;
            assert_eq!(summary.failed, 0, "{summary:?}");
            assert_eq!(summary.backed_off, 0, "{summary:?}");
            queued.extend(summary.queued);
            if store
                .releases_of(&deployment)
                .await
                .unwrap()
                .contains_key("1.37.4")
            {
                break;
            }
        }

        let releases = store.releases_of(&deployment).await.unwrap();
        let release = &releases["1.37.4"];
        assert_eq!(release.decision, ReleaseDecision::Auto, "{release:?}");
        assert_eq!(release.digest.as_ref().unwrap().as_ref(), DIGEST);
        assert_eq!(queued.len(), 1, "{queued:?}");
        assert_eq!(store.verify_audit().await.unwrap().first_bad, None);
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
