//! Fetchers for release material: signed tag objects from the GitHub API,
//! image indexes and Sigstore bundles from an OCI registry (GHCR).
//!
//! Everything fetched here is hostile input until it is verified. This module
//! checks only what binds the bytes to the name they were asked for (the git
//! object id, content digests, media types and sizes) and enforces size caps
//! while the body streams in. Signatures and attestations are verified
//! elsewhere: [`landfall_core::tag`] and [`crate::attestation`].
//!
//! Requests go over HTTPS only, with a connect timeout of 10 s and a total
//! timeout of 30 s. Bodies are never decompressed (no compression feature is
//! enabled in the HTTP client), so a cap applies to the bytes on the wire.

use std::time::Duration;

use reqwest::header::{HeaderName, HeaderValue};
use reqwest::{Client, redirect};

mod endpoints;
mod error;
mod github;
mod http;
mod listing;
mod registry;
#[cfg(test)]
mod tests;

pub use endpoints::Endpoints;
pub use error::{FetchError, RateLimitReset, Service};
pub(crate) use http::hex;
pub use listing::{ListedTag, MAX_LISTED_TAGS};

/// Cap on a GitHub API response for a tag ref or tag object.
pub const TAG_OBJECT_LIMIT: usize = 64 * 1024;

/// Cap on an image index or manifest, and on a registry token response.
pub const MANIFEST_LIMIT: usize = 1024 * 1024;

/// The public GitHub REST API.
const GITHUB_API: &str = "https://api.github.com";

/// Connect timeout for every request.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Total timeout for every request.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Redirects followed per request (a registry blob redirects to its storage).
const MAX_REDIRECTS: usize = 3;

/// Tag objects followed when peeling a tag to its commit.
const MAX_TAG_DEPTH: usize = 4;

const GITHUB_ACCEPT: &str = "application/vnd.github+json";

const GITHUB_API_VERSION: &str = "2022-11-28";

pub(crate) const OCI_INDEX: &str = "application/vnd.oci.image.index.v1+json";

const DOCKER_LIST: &str = "application/vnd.docker.distribution.manifest.list.v2+json";

pub(crate) const OCI_MANIFEST: &str = "application/vnd.oci.image.manifest.v1+json";

pub(crate) const BUNDLE_TYPE: &str = "application/vnd.dev.sigstore.bundle.v0.3+json";

/// The annotation on a bundle's referrer manifest and its descriptor naming
/// the predicate type of the attestation inside.
const PREDICATE_TYPE_ANNOTATION: &str = "dev.sigstore.bundle.predicateType";

/// The annotation buildx puts on the attestation manifests it adds to an
/// index; they declare the platform `unknown/unknown` and run nowhere.
const REFERENCE_TYPE_ANNOTATION: &str = "vnd.docker.reference.type";

const ATTESTATION_MANIFEST: &str = "attestation-manifest";

/// GitHub's count of requests left in the current rate-limit window.
const RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");

/// GitHub's end of the current rate-limit window, in Unix epoch seconds.
const RATELIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");

/// Fetches tag objects from the GitHub API and image indexes and bundles
/// from an OCI registry.
#[derive(Debug, Clone)]
pub struct Fetcher {
    client: Client,
    endpoints: Endpoints,
    /// Sent to the GitHub API only, never to the registry.
    github_token: Option<HeaderValue>,
}

impl Fetcher {
    /// A fetcher for `endpoints`, without a GitHub token.
    ///
    /// # Errors
    ///
    /// [`FetchError::Client`] when the HTTP client cannot be built.
    pub fn new(endpoints: Endpoints) -> Result<Self, FetchError> {
        let client = Client::builder()
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .https_only(endpoints.https_only)
            .redirect(redirect::Policy::limited(MAX_REDIRECTS))
            .user_agent(concat!("landfall/", env!("CARGO_PKG_VERSION")))
            .build()
            .map_err(FetchError::Client)?;
        Ok(Self {
            client,
            endpoints,
            github_token: None,
        })
    }

    /// Sends `token` to the GitHub API, for its higher rate limit. It is
    /// never sent to the registry.
    ///
    /// # Errors
    ///
    /// [`FetchError::Token`] when the token cannot be an HTTP header value.
    pub fn with_github_token(mut self, token: &str) -> Result<Self, FetchError> {
        let mut value =
            HeaderValue::from_str(&format!("Bearer {token}")).map_err(|_| FetchError::Token)?;
        value.set_sensitive(true);
        self.github_token = Some(value);
        Ok(self)
    }
}
