//! `landfall verify`: verify one release of one deployment end to end, as a
//! host would before deploying it, and print where it came from.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use clap::Args;
use landfall_core::config::{self, ConfigError};
use landfall_core::ids::{DeploymentId, ReleaseTag};
use landfall_core::release::Platform;
use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use landfall_origin::release::{ReleaseError, ReleaseOrigin, verify_release};
use landfall_origin::trust::{Refresh, TrustError, load_trusted_root};
use thiserror::Error;

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
    /// No `--cache-dir` was given and no default can be derived.
    #[error("no cache directory: set XDG_CACHE_HOME or HOME, or pass --cache-dir")]
    NoCacheDir,
    /// The default cache directory could not be created.
    #[error("cannot create cache directory {}", .path.display())]
    CreateCacheDir {
        /// The directory.
        path: PathBuf,
        /// The I/O error.
        #[source]
        source: std::io::Error,
    },
    /// The Sigstore trust root could not be built.
    #[error("Sigstore trust root")]
    Trust(#[source] TrustError),
    /// The HTTP client could not be built.
    #[error("HTTP client")]
    Fetcher(#[source] FetchError),
    /// The release was refused.
    #[error("release {tag} of {deployment} is refused")]
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

/// Runs `landfall verify`.
///
/// # Errors
///
/// A [`VerifyError`]; [`VerifyError::Release`] when the release is refused.
pub async fn run(args: VerifyArgs) -> Result<ReleaseOrigin, VerifyError> {
    let platform = match args.platform {
        Some(platform) => platform,
        None => host_platform(std::env::consts::OS, std::env::consts::ARCH)?,
    };
    let bytes = std::fs::read(&args.config).map_err(|source| VerifyError::ReadConfig {
        path: args.config.clone(),
        source,
    })?;
    let config = config::parse(&bytes).map_err(|source| VerifyError::Config {
        path: args.config.clone(),
        source: Box::new(source),
    })?;

    let cache_dir = if let Some(dir) = args.cache_dir {
        dir
    } else {
        let dir = default_cache_dir(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
            .ok_or(VerifyError::NoCacheDir)?;
        create_dir(&dir)?;
        dir
    };
    let refresh = if args.offline {
        Refresh::Offline
    } else {
        Refresh::Online
    };
    let root = load_trusted_root(&cache_dir, refresh)
        .await
        .map_err(VerifyError::Trust)?;

    let fetcher = Fetcher::new(Endpoints::public().map_err(VerifyError::Fetcher)?)
        .map_err(VerifyError::Fetcher)?;
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

/// `$XDG_CACHE_HOME/landfall/tuf`, or `$HOME/.cache/landfall/tuf`. A
/// relative or empty value is ignored, as the XDG base directory
/// specification requires.
fn default_cache_dir(xdg_cache_home: Option<OsString>, home: Option<OsString>) -> Option<PathBuf> {
    let absolute = |value: Option<OsString>| value.map(PathBuf::from).filter(|p| p.is_absolute());
    absolute(xdg_cache_home)
        .or_else(|| absolute(home).map(|home| home.join(".cache")))
        .map(|base| base.join("landfall").join("tuf"))
}

fn create_dir(dir: &Path) -> Result<(), VerifyError> {
    std::fs::create_dir_all(dir).map_err(|source| VerifyError::CreateCacheDir {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{VerifyError, default_cache_dir, host_platform};

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

    #[test]
    fn cache_dir_follows_xdg_then_home() {
        let os = |s: &str| Some(OsString::from(s));
        assert_eq!(
            default_cache_dir(os("/xdg"), os("/home/u")),
            Some(PathBuf::from("/xdg/landfall/tuf"))
        );
        assert_eq!(
            default_cache_dir(None, os("/home/u")),
            Some(PathBuf::from("/home/u/.cache/landfall/tuf"))
        );
        // Relative or empty values are ignored.
        assert_eq!(
            default_cache_dir(os("cache"), os("/home/u")),
            Some(PathBuf::from("/home/u/.cache/landfall/tuf"))
        );
        assert_eq!(default_cache_dir(os(""), os("")), None);
        assert_eq!(default_cache_dir(None, None), None);
    }
}
