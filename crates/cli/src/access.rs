//! Getting at releases from this machine: the Sigstore trust root's cache, and a
//! fetcher with the operator's token.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use landfall_origin::fetch::{Endpoints, FetchError, Fetcher};
use landfall_origin::trust::{Refresh, TrustError, TrustRoot, load_trusted_root};
use thiserror::Error;

/// Why the means of verifying a release could not be had.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum AccessError {
    /// No cache directory was given and no default can be derived.
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
    /// `GITHUB_TOKEN` is set but cannot be used. The value is never shown.
    #[error("GITHUB_TOKEN is set but is not valid UTF-8 text or not a valid HTTP header value")]
    Token,
    /// The Sigstore trust root could not be built.
    #[error("Sigstore trust root")]
    Trust(#[source] TrustError),
    /// The HTTP client could not be built.
    #[error("HTTP client")]
    Fetcher(#[source] FetchError),
}

/// The Sigstore trust root, from `explicit` or else the default cache directory, which
/// is created when missing.
pub(crate) async fn trust_root(
    explicit: Option<PathBuf>,
    refresh: Refresh,
) -> Result<TrustRoot, AccessError> {
    let cache_dir = if let Some(dir) = explicit {
        dir
    } else {
        let dir = default_cache_dir(std::env::var_os("XDG_CACHE_HOME"), std::env::var_os("HOME"))
            .ok_or(AccessError::NoCacheDir)?;
        create_dir(&dir)?;
        dir
    };
    load_trusted_root(&cache_dir, refresh)
        .await
        .map_err(AccessError::Trust)
}

/// A fetcher for the public services. A non-empty `GITHUB_TOKEN` in the environment is
/// sent to the GitHub API (never to the registry) for its higher rate limit.
pub(crate) fn public_fetcher() -> Result<Fetcher, AccessError> {
    let mut fetcher = Fetcher::new(Endpoints::public().map_err(AccessError::Fetcher)?)
        .map_err(AccessError::Fetcher)?;
    if let Some(token) = github_token(std::env::var_os("GITHUB_TOKEN"))? {
        fetcher = fetcher
            .with_github_token(&token)
            .map_err(|_| AccessError::Token)?;
    }
    Ok(fetcher)
}

/// The GitHub token from the value of `GITHUB_TOKEN`: `None` when unset or
/// empty.
fn github_token(value: Option<OsString>) -> Result<Option<String>, AccessError> {
    match value {
        None => Ok(None),
        Some(value) if value.is_empty() => Ok(None),
        Some(value) => value
            .into_string()
            .map(Some)
            .map_err(|_| AccessError::Token),
    }
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

fn create_dir(dir: &Path) -> Result<(), AccessError> {
    std::fs::create_dir_all(dir).map_err(|source| AccessError::CreateCacheDir {
        path: dir.to_path_buf(),
        source,
    })
}

#[cfg(test)]
mod tests {
    use std::ffi::OsString;
    use std::path::PathBuf;

    use super::{AccessError, default_cache_dir, github_token};

    #[test]
    fn github_token_is_used_only_when_set_and_non_empty() {
        assert!(github_token(None).unwrap().is_none());
        assert!(github_token(Some(OsString::new())).unwrap().is_none());
        assert_eq!(
            github_token(Some(OsString::from("t0ken")))
                .unwrap()
                .as_deref(),
            Some("t0ken")
        );
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_github_token_is_an_error_that_does_not_show_it() {
        use std::os::unix::ffi::OsStringExt;
        let error = github_token(Some(OsString::from_vec(b"secret\xff".to_vec()))).unwrap_err();
        assert!(matches!(error, AccessError::Token), "{error:?}");
        assert!(!error.to_string().contains("secret"), "{error}");
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
