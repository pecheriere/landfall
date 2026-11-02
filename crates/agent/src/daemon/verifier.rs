//! Verifying a release on this host, with this host's own trust root.

use std::ffi::OsString;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use landfall_core::config::Config;
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::release::Platform;
use landfall_origin::attestation::AttestationError;
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release};
use landfall_origin::trust::{Refresh, TrustRoot, load_trusted_root};
use serde::Serialize;

use super::DaemonError;
use crate::client::error_chain;
use crate::journal::{self, Priority};

/// How often the trust root is brought up to date, when a release needs it.
const TRUST_ROOT_EVERY: Duration = Duration::from_hours(24);

/// Why a release could not be verified.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum VerifyFailure {
    /// The release was refused: a check failed on material that was obtained.
    Refused(String),
    /// The registry or GitHub answered that the material isn't there: a release
    /// still being published, or one that was yanked. Waited for, but not for
    /// ever.
    Missing(String),
    /// The material could not be obtained, or was not what it should be, as in a
    /// network failure, a rate limit or a wrong answer, which may work on a later
    /// try. Waited for, but not for ever.
    Unavailable(String),
    /// This host's clock is behind the transparency log's time for the release. A
    /// host may have no battery for its clock, and this says nothing of the release.
    ClockBehind(String),
}

impl From<ReleaseError> for VerifyFailure {
    fn from(error: ReleaseError) -> Self {
        if matches!(
            &error,
            ReleaseError::Attestation(AttestationError::ClockBehind(_))
        ) {
            return Self::ClockBehind(error_chain(&error));
        }
        let missing = matches!(
            &error,
            ReleaseError::TagObject(fetch)
                | ReleaseError::TagCommit(fetch)
                | ReleaseError::Index(fetch)
                | ReleaseError::Bundle(fetch)
                if matches!(fetch, FetchError::NotFound { .. } | FetchError::Bundles { count: 0, .. })
        );
        if error.is_refusal() {
            Self::Refused(error_chain(&error))
        } else if missing {
            Self::Missing(error_chain(&error))
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

/// The fetcher for GitHub and the registry, with `token`, the value of
/// `GITHUB_TOKEN`, for GitHub only: hosts behind one address share the limit on
/// anonymous requests. Unset or empty is no token. A value that can't be used is an
/// error, which doesn't repeat it.
fn release_fetcher(token: Option<OsString>) -> Result<Fetcher, DaemonError> {
    let fetcher = Fetcher::new(Endpoints::public().map_err(DaemonError::Fetcher)?)
        .map_err(DaemonError::Fetcher)?;
    match token {
        Some(token) if !token.is_empty() => {
            let token = token.into_string().map_err(|_| DaemonError::GitHubToken)?;
            fetcher
                .with_github_token(&token)
                .map_err(|_| DaemonError::GitHubToken)
        }
        _ => Ok(fetcher),
    }
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
        let platform = host_platform(std::env::consts::OS, std::env::consts::ARCH)?;
        Self::for_platform(cache_dir, platform)
    }

    fn for_platform(cache_dir: PathBuf, platform: Platform) -> Result<Self, DaemonError> {
        Ok(Self {
            fetcher: release_fetcher(std::env::var_os("GITHUB_TOKEN"))?,
            platform,
            cache_dir,
            root: tokio::sync::Mutex::new(None),
        })
    }

    /// The trust root, brought up to date if it is a day old. If the update
    /// can't be fetched the cache is read again, which refuses metadata past
    /// its expiry, the journal is told, and the update is tried at the next
    /// release.
    async fn root(&self) -> Result<TrustRoot, VerifyFailure> {
        #[derive(Serialize)]
        struct NotRefreshed {
            event: &'static str,
            error: String,
        }
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
            Err(online) => {
                let cached = load_trusted_root(&self.cache_dir, Refresh::Offline)
                    .await
                    .map_err(|offline| {
                        VerifyFailure::Unavailable(format!("trust root: {online}; {offline}"))
                    })?;
                journal::emit(
                    Priority::Warning,
                    &NotRefreshed {
                        event: "trust_root_not_refreshed",
                        error: online.to_string(),
                    },
                );
                Ok(cached)
            }
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
    use landfall_core::config;
    use landfall_origin::attestation::AttestationError;
    use landfall_origin::fetch::FetchError;
    use landfall_origin::release::ReleaseError;

    use std::ffi::OsString;

    use super::{
        DaemonError, OriginVerifier, Verifier, VerifyFailure, host_platform, release_fetcher,
    };

    #[test]
    fn what_is_not_there_is_told_from_what_cant_be_reached() {
        let digest = format!("sha256:{}", "a".repeat(64)).parse().unwrap();
        let not_found = || FetchError::NotFound {
            url: "https://registry.example/x".to_owned(),
        };
        for error in [
            ReleaseError::TagObject(not_found()),
            ReleaseError::TagCommit(not_found()),
            ReleaseError::Index(not_found()),
            ReleaseError::Bundle(not_found()),
            ReleaseError::Bundle(FetchError::Bundles { digest, count: 0 }),
        ] {
            let failure = VerifyFailure::from(error);
            assert!(matches!(failure, VerifyFailure::Missing(_)), "{failure:?}");
        }
    }

    /// The attestation fixture's release of `crates/origin`, through the real
    /// GitHub API, GHCR and Sigstore TUF repository: what the agent's `run` uses.
    #[tokio::test]
    #[ignore = "network: run by hand"]
    async fn live_origin_verifier_verifies_the_fixture_release() {
        let text = r#"
[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "dani-garcia/vaultwarden", id = 121898717, owner_id = 725423 }
host = "host-1"
compose = { dir = "/srv/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "*", signed_tags = false }
rule = { approvers = ["operator"] }
checks = ["container-healthy"]
"#;
        let config = config::parse(text.as_bytes()).unwrap();
        let cache = tempfile::tempdir().unwrap();
        let verifier =
            OriginVerifier::for_platform(cache.path().to_owned(), "linux/amd64".parse().unwrap())
                .unwrap();

        let origin = verifier
            .verify(
                &config,
                &"app/prod".parse().unwrap(),
                &"1.37.4".parse().unwrap(),
            )
            .await
            .unwrap();

        assert_eq!(
            origin.commit.as_ref(),
            "7c188967e7a467b19b2757bc3326f9cf3ccae327"
        );
        assert_eq!(
            origin.attestation.digest.as_ref(),
            "sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055"
        );
    }

    #[test]
    fn the_github_token_is_optional_but_must_be_usable_and_is_not_repeated() {
        assert!(release_fetcher(None).is_ok());
        assert!(release_fetcher(Some(OsString::new())).is_ok());
        assert!(release_fetcher(Some("a-token".into())).is_ok());
        let not_utf8 = std::os::unix::ffi::OsStringExt::from_vec(vec![0xff]);
        for bad in [not_utf8, OsString::from("secret\ntoken")] {
            let Err(error) = release_fetcher(Some(bad)) else {
                panic!("a token that can't be sent is an error");
            };
            assert!(matches!(error, DaemonError::GitHubToken), "{error}");
            assert!(!error.to_string().contains("secret"), "{error}");
        }
    }

    #[test]
    fn a_clock_behind_the_log_is_its_own_class_and_no_refusal() {
        let error = ReleaseError::Attestation(AttestationError::ClockBehind(
            "integrated time is in the future".to_owned(),
        ));
        let VerifyFailure::ClockBehind(text) = VerifyFailure::from(error) else {
            panic!("a clock is not a verdict on a release");
        };
        assert!(text.contains("in the future"), "{text}");
        // A bundle that doesn't verify stays what it is.
        let refused = ReleaseError::Attestation(AttestationError::Signature("no".to_owned()));
        assert!(matches!(
            VerifyFailure::from(refused),
            VerifyFailure::Refused(_)
        ));
    }

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
