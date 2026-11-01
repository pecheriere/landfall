//! Verifying a release on this host, with this host's own trust root.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::release::Platform;
use landfall_origin::fetch::{Endpoints, Fetcher};
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release};
use landfall_origin::trust::{Refresh, TrustRoot, load_trusted_root};

use super::DaemonError;
use crate::client::error_chain;

/// How often the trust root is brought up to date, when a release needs it.
const TRUST_ROOT_EVERY: Duration = Duration::from_hours(24);

/// Why a release could not be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyFailure {
    /// The release was refused: a check failed on material that was obtained.
    Refused(String),
    /// The material could not be obtained, which may work on a later try.
    Unavailable(String),
}

impl From<ReleaseError> for VerifyFailure {
    fn from(error: ReleaseError) -> Self {
        if error.is_refusal() {
            Self::Refused(error_chain(&error))
        } else {
            Self::Unavailable(error_chain(&error))
        }
    }
}

/// Verifies a release on this host. [`OriginVerifier`] is the real one.
pub trait Verifier: Send + Sync {
    /// Where release `tag` of `deployment` came from, by this host's trust.
    fn verify(
        &self,
        config: &Config,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> impl Future<Output = Result<ReleaseOrigin, VerifyFailure>> + Send;
}

/// [`verify_release`] with the trust root in the state directory.
pub struct OriginVerifier {
    fetcher: Fetcher,
    platform: Platform,
    cache_dir: PathBuf,
    root: tokio::sync::Mutex<Option<(TrustRoot, Instant)>>,
}

impl OriginVerifier {
    /// A verifier for this host's platform, with its trust root cached in
    /// `cache_dir`, which must exist.
    ///
    /// # Errors
    ///
    /// [`DaemonError`] if the platform has no image or the client can't be built.
    pub fn new(cache_dir: PathBuf) -> Result<Self, DaemonError> {
        Ok(Self {
            fetcher: Fetcher::new(Endpoints::public().map_err(DaemonError::Fetcher)?)
                .map_err(DaemonError::Fetcher)?,
            platform: host_platform(std::env::consts::OS, std::env::consts::ARCH)?,
            cache_dir,
            root: tokio::sync::Mutex::new(None),
        })
    }

    /// The trust root, brought up to date if it is a day old. If the update
    /// can't be fetched the cache is read again, which refuses metadata past
    /// its expiry, and the update is tried at the next release.
    async fn root(&self) -> Result<TrustRoot, VerifyFailure> {
        let mut held = self.root.lock().await;
        if let Some((root, refreshed)) = held.as_ref()
            && refreshed.elapsed() < TRUST_ROOT_EVERY
        {
            return Ok(root.clone());
        }
        match load_trusted_root(&self.cache_dir, Refresh::Online).await {
            Ok(root) => {
                *held = Some((root.clone(), Instant::now()));
                Ok(root)
            }
            Err(online) => load_trusted_root(&self.cache_dir, Refresh::Offline)
                .await
                .map_err(|offline| {
                    VerifyFailure::Unavailable(format!("trust root: {online}; {offline}"))
                }),
        }
    }
}

impl Verifier for OriginVerifier {
    async fn verify(
        &self,
        config: &Config,
        deployment: &DeploymentId,
        tag: &ReleaseTag,
    ) -> Result<ReleaseOrigin, VerifyFailure> {
        let root = self.root().await?;
        Box::pin(verify_release(
            &self.fetcher,
            &root,
            config,
            deployment,
            tag,
            &self.platform,
        ))
        .await
        .map_err(VerifyFailure::from)
    }
}

/// The OCI platform of a Linux host with this `std::env::consts::ARCH`.
fn host_platform(os: &'static str, arch: &'static str) -> Result<Platform, DaemonError> {
    let architecture = match (os, arch) {
        ("linux", "aarch64") => "arm64",
        ("linux", "x86_64") => "amd64",
        _ => return Err(DaemonError::Platform { os, arch }),
    };
    Ok(Platform {
        os: "linux".to_owned(),
        architecture: architecture.to_owned(),
        variant: None,
    })
}

#[cfg(test)]
mod tests {
    use landfall_origin::release::ReleaseError;

    use super::{VerifyFailure, host_platform};

    #[test]
    fn what_was_not_refused_can_still_be_retried() {
        let unknown = ReleaseError::UnknownDeployment("app/prod".parse().unwrap());
        assert!(matches!(
            VerifyFailure::from(unknown),
            VerifyFailure::Unavailable(_)
        ));
        let pattern = ReleaseError::TagPattern(landfall_core::ids::TagError {
            tag: "x".to_owned(),
            reason: "no",
        });
        let VerifyFailure::Refused(text) = VerifyFailure::from(pattern) else {
            panic!("a failed check is a refusal");
        };
        assert!(
            text.contains("tag pattern") && text.contains("no"),
            "{text}"
        );
    }

    #[test]
    fn the_platform_uses_oci_architecture_names() {
        assert_eq!(
            host_platform("linux", "aarch64").unwrap().architecture,
            "arm64"
        );
        assert_eq!(
            host_platform("linux", "x86_64").unwrap().architecture,
            "amd64"
        );
        assert!(host_platform("macos", "aarch64").is_err());
    }
}
