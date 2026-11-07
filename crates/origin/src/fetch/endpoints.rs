//! The two services a fetcher talks to, and the checks on their URLs.

use reqwest::Url;

use super::{FetchError, GITHUB_API};

/// The base URLs requests go to.
///
/// [`Endpoints::new`] accepts only `https` URLs. Plain `http`, for mock
/// servers, is reachable only through a constructor compiled into this crate's
/// tests and into builds with the `test-support` feature, which only
/// dev-dependencies enable.
#[derive(Debug, Clone)]
pub struct Endpoints {
    pub(super) github_api: Url,
    pub(super) registry: Url,
    pub(super) https_only: bool,
}

impl Endpoints {
    /// Endpoints for the GitHub REST API at `github_api` and the OCI registry
    /// at `registry`.
    ///
    /// # Errors
    ///
    /// [`FetchError::Endpoint`] when a URL is not `https`, has no host, or
    /// carries credentials, a query or a fragment.
    pub fn new(github_api: Url, registry: Url) -> Result<Self, FetchError> {
        check_endpoint(&github_api)?;
        check_endpoint(&registry)?;
        Ok(Self {
            github_api,
            registry,
            https_only: true,
        })
    }

    /// `https://api.github.com` and `https://ghcr.io`.
    ///
    /// # Errors
    ///
    /// None in practice: the URLs are constants that pass [`Endpoints::new`].
    pub fn public() -> Result<Self, FetchError> {
        let parse = |url: &str| {
            Url::parse(url).map_err(|_| FetchError::Endpoint {
                url: url.to_owned(),
                reason: "not a URL",
            })
        };
        Self::new(
            parse(GITHUB_API)?,
            parse(&format!("https://{}", crate::release::REGISTRY_HOST))?,
        )
    }

    /// Endpoints over plain `http`, for mock servers. Test builds and the
    /// `test-support` feature only: no release binary can reach it.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn plain_http(github_api: Url, registry: Url) -> Self {
        Self {
            github_api,
            registry,
            https_only: false,
        }
    }
}

fn check_endpoint(url: &Url) -> Result<(), FetchError> {
    let refuse = |reason| {
        Err(FetchError::Endpoint {
            url: url.to_string(),
            reason,
        })
    };
    if url.scheme() != "https" {
        return refuse("not https");
    }
    if url.host_str().is_none() {
        return refuse("no host");
    }
    if !url.username().is_empty() || url.password().is_some() {
        return refuse("carries credentials");
    }
    if url.query().is_some() || url.fragment().is_some() {
        return refuse("carries a query or a fragment");
    }
    Ok(())
}
