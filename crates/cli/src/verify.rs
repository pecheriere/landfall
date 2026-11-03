//! `landfall verify`: verify one release of one deployment end to end, as a
//! host would before deploying it, and print where it came from.

use std::path::{Path, PathBuf};

use clap::Args;
use landfall_core::config::{Config, ConfigError};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::release::Platform;
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release};
use landfall_origin::trust::Refresh;
use thiserror::Error;

use crate::access::{AccessError, public_fetcher, trust_root};

/// Arguments of `landfall verify`.
#[derive(Debug, Args)]
pub struct VerifyArgs {
    /// The fleet configuration file.
    #[arg(long, value_name = "FILE")]
    config: PathBuf,
    /// The deployment, `<name>/<stage>`.
    #[arg(long, value_name = "ID")]
    deployment: DeploymentId,
    /// The release tag.
    #[arg(long)]
    tag: ReleaseTag,
    /// The platform the image must serve, `os/architecture[/variant]`.
    /// Defaults to this machine's on Linux; required elsewhere.
    #[arg(long, value_name = "PLATFORM")]
    platform: Option<Platform>,
    /// The Sigstore TUF cache directory; it must exist. Defaults to
    /// `$XDG_CACHE_HOME/landfall/tuf` (or `~/.cache/landfall/tuf`), created
    /// when missing.
    #[arg(long, value_name = "DIR")]
    cache_dir: Option<PathBuf>,
    /// Do not refresh the Sigstore trust root: use the cache as it is, and
    /// fail if it is missing or expired. Tags, indexes and bundles are still
    /// fetched.
    #[arg(long)]
    offline: bool,
}

/// Why `landfall verify` could not verify the release, or refused it.
#[derive(Debug, Error)]
pub enum VerifyError {
    /// The configuration file could not be read.
    #[error("cannot read configuration {}", .path.display())]
    ReadConfig {
        /// The file.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The configuration file is invalid.
    #[error("configuration {} is invalid", .path.display())]
    Config {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        #[source]
        source: Box<ConfigError>,
    },
    /// No `--platform` was given and this machine has no default.
    #[error(
        "no default platform on {os}/{arch}: images are matched against a Linux host's \
         platform; pass --platform, for example --platform linux/arm64"
    )]
    NoDefaultPlatform {
        /// `std::env::consts::OS`.
        os: &'static str,
        /// `std::env::consts::ARCH`.
        arch: &'static str,
    },
    /// The trust root or the fetcher could not be had.
    #[error(transparent)]
    Access(#[from] AccessError),
    /// The release was refused, or its material could not be fetched.
    #[error(
        "release {tag} of {deployment} {}",
        if source.is_refusal() { "is refused" } else { "could not be verified" }
    )]
    Release {
        /// The deployment.
        deployment: DeploymentId,
        /// The tag.
        tag: ReleaseTag,
        /// The step that failed.
        #[source]
        source: Box<ReleaseError>,
    },
}

impl VerifyError {
    /// The process exit status: 1 when the release was refused (a
    /// verification check failed), 2 when it could not be verified
    /// (configuration, usage, network, rate limit, trust root).
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Release { source, .. } if source.is_refusal() => EXIT_REFUSED,
            _ => EXIT_UNVERIFIED,
        }
    }
}

/// Exit status of a refused release.
pub const EXIT_REFUSED: u8 = 1;
/// Exit status when the release could not be verified.
pub const EXIT_UNVERIFIED: u8 = 2;

fn load_config(path: &Path) -> Result<Config, VerifyError> {
    let bytes = std::fs::read(path).map_err(|source| VerifyError::ReadConfig {
        path: path.to_owned(),
        source,
    })?;
    landfall_approval::parse_config(&bytes).map_err(|source| VerifyError::Config {
        path: path.to_owned(),
        source: Box::new(source),
    })
}

/// Runs `landfall verify`. A non-empty `GITHUB_TOKEN` in the environment is
/// sent to the GitHub API (never to the registry) for its higher rate limit.
///
/// # Errors
///
/// A [`VerifyError`]; [`VerifyError::Release`] when the release is refused
/// or its material could not be fetched.
pub async fn run(args: VerifyArgs) -> Result<ReleaseOrigin, VerifyError> {
    let platform = match args.platform {
        Some(platform) => platform,
        None => host_platform(std::env::consts::OS, std::env::consts::ARCH)?,
    };
    let config = load_config(&args.config)?;

    let refresh = if args.offline {
        Refresh::Offline
    } else {
        Refresh::Online
    };
    let root = trust_root(args.cache_dir, refresh).await?;
    let fetcher = public_fetcher()?;
    verify_release(
        &fetcher,
        &root,
        &config,
        &args.deployment,
        &args.tag,
        &platform,
    )
    .await
    .map_err(|source| VerifyError::Release {
        deployment: args.deployment,
        tag: args.tag,
        source: Box::new(source),
    })
}

/// The OCI platform of a Linux host with this `std::env::consts::ARCH`.
fn host_platform(os: &'static str, arch: &'static str) -> Result<Platform, VerifyError> {
    let architecture = match (os, arch) {
        ("linux", "aarch64") => "arm64",
        ("linux", "x86_64") => "amd64",
        _ => return Err(VerifyError::NoDefaultPlatform { os, arch }),
    };
    Ok(Platform {
        os: "linux".to_owned(),
        architecture: architecture.to_owned(),
        variant: None,
    })
}

#[cfg(test)]
mod tests {
    use landfall_core::tag::TagVerifyError;
    use landfall_origin::fetch::FetchError;
    use landfall_origin::release::ReleaseError;
    use landfall_origin::trust::TrustError;

    use super::{
        AccessError, ConfigError, EXIT_REFUSED, EXIT_UNVERIFIED, VerifyError, host_platform,
        load_config,
    };

    #[test]
    fn a_key_the_verifier_would_refuse_is_refused_at_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fleet.toml");
        std::fs::write(
            &path,
            "[approvers]\noperator = { credential_id = \"Y3JlZGVudGlhbA\", public_key = \"cHVibGljLWtleQ\" }\n",
        )
        .unwrap();
        let err = load_config(&path).unwrap_err();
        let VerifyError::Config { source, .. } = err else {
            panic!("{err}");
        };
        assert!(
            matches!(&*source, ConfigError::InvalidApprover { approver, .. } if approver.to_string() == "operator"),
            "{source}"
        );
    }

    fn release(source: ReleaseError) -> VerifyError {
        VerifyError::Release {
            deployment: "app/prod".parse().unwrap(),
            tag: "v1.2.3".parse().unwrap(),
            source: Box::new(source),
        }
    }

    #[test]
    fn refused_releases_exit_1_and_unverifiable_ones_exit_2() {
        let refused = release(ReleaseError::TagSignature(TagVerifyError::NotSigned));
        assert_eq!(refused.exit_code(), EXIT_REFUSED);
        assert_eq!(EXIT_REFUSED, 1);

        assert!(refused.to_string().ends_with("is refused"), "{refused}");

        let unavailable = release(ReleaseError::Index(FetchError::NotFound {
            url: "https://registry.example/v2/example/app/manifests/1.2.3".to_owned(),
        }));
        assert_eq!(unavailable.exit_code(), EXIT_UNVERIFIED);
        assert!(
            unavailable.to_string().ends_with("could not be verified"),
            "{unavailable}"
        );
        assert_eq!(EXIT_UNVERIFIED, 2);
        for error in [
            release(ReleaseError::UnknownDeployment("app/prod".parse().unwrap())),
            VerifyError::Access(AccessError::Trust(TrustError::Expired(
                "timestamp".to_owned(),
            ))),
            VerifyError::Access(AccessError::NoCacheDir),
            VerifyError::Access(AccessError::Token),
        ] {
            assert_eq!(error.exit_code(), EXIT_UNVERIFIED, "{error:?}");
        }
    }

    #[test]
    fn host_platform_uses_oci_architecture_names() {
        assert_eq!(
            host_platform("linux", "aarch64").unwrap().to_string(),
            "linux/arm64"
        );
        assert_eq!(
            host_platform("linux", "x86_64").unwrap().to_string(),
            "linux/amd64"
        );
    }

    #[test]
    fn other_hosts_need_an_explicit_platform() {
        for (os, arch) in [
            ("macos", "aarch64"),
            ("windows", "x86_64"),
            ("linux", "riscv64"),
        ] {
            let error = host_platform(os, arch).unwrap_err();
            assert!(
                matches!(error, VerifyError::NoDefaultPlatform { .. }),
                "{error:?}"
            );
            assert!(error.to_string().contains("pass --platform"), "{error}");
        }
    }
}
