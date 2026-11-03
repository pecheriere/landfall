//! Why a fetch failed, and which service it was for.

use std::fmt;

use jiff::Timestamp;
use landfall_core::ids::{ImageDigest, ReleaseTag};
use thiserror::Error;

use super::MAX_TAG_DEPTH;

/// The service a request went to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The GitHub REST API.
    GitHubApi,
    /// The OCI registry.
    Registry,
}

impl fmt::Display for Service {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::GitHubApi => "the GitHub API",
            Self::Registry => "the registry",
        })
    }
}

impl Service {
    /// What to do about a rate limit, beyond waiting.
    fn rate_limit_hint(self) -> &'static str {
        match self {
            Self::GitHubApi => {
                "; requests with a GitHub token have a much higher limit \
                 (landfall verify reads it from GITHUB_TOKEN)"
            }
            Self::Registry => "",
        }
    }
}

/// When a rate limit lifts, as the server said.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RateLimitReset {
    /// At this time (`x-ratelimit-reset`).
    At(Timestamp),
    /// After this many seconds (`Retry-After`).
    After(u64),
    /// The server did not say, or said it in a form not read here.
    Unknown,
}

impl fmt::Display for RateLimitReset {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::At(at) => write!(f, "it resets at {at}"),
            Self::After(seconds) => write!(f, "retry after {seconds} s"),
            Self::Unknown => f.write_str("the server did not say when it resets"),
        }
    }
}

/// Why release material could not be fetched, or was refused.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FetchError {
    /// A base URL is not acceptable.
    #[error("invalid endpoint {url}: {reason}")]
    Endpoint {
        /// The URL as given.
        url: String,
        /// What is wrong with it.
        reason: &'static str,
    },
    /// The GitHub token cannot be sent as an HTTP header.
    #[error("the GitHub token is not a valid HTTP header value")]
    Token,
    /// The image name is not a lowercase registry path.
    #[error(
        "invalid image name {0:?}: expected 1 to 255 bytes of '/'-separated components of \
         [a-z0-9._-], each starting and ending with [a-z0-9]"
    )]
    Image(String),
    /// The HTTP client could not be built.
    #[error("HTTP client")]
    Client(#[source] reqwest::Error),
    /// The request failed: connection, TLS, timeout or body read.
    #[error("request to {url} failed")]
    Request {
        /// The URL requested.
        url: String,
        /// The transport error.
        #[source]
        source: reqwest::Error,
    },
    /// An answer redirected somewhere that isn't followed. This names the URL asked
    /// for and not the target, whose query may be a credential.
    #[error("{url} redirected, and that is refused: {reason}")]
    Redirect {
        /// The URL requested.
        url: String,
        /// Why it is refused.
        reason: &'static str,
    },
    /// The server answered 404.
    #[error("{url} returned 404 not found")]
    NotFound {
        /// The URL requested.
        url: String,
    },
    /// The server refused the request for its rate limit: HTTP 403 or 429
    /// with `x-ratelimit-remaining: 0` or a `Retry-After` header.
    #[error("{service} rate limit reached ({url} returned HTTP {status}); {reset}{hint}", hint = .service.rate_limit_hint())]
    RateLimited {
        /// The service that refused.
        service: Service,
        /// The URL requested.
        url: String,
        /// The HTTP status code, 403 or 429.
        status: u16,
        /// When the limit lifts.
        reset: RateLimitReset,
    },
    /// The server answered with a status other than 200 and 404.
    #[error("{url} returned HTTP {status}")]
    Status {
        /// The URL requested.
        url: String,
        /// The HTTP status code.
        status: u16,
    },
    /// The response body is larger than the cap for its kind.
    #[error("{url} returned more than {limit} bytes")]
    TooLarge {
        /// The URL requested.
        url: String,
        /// The cap, in bytes.
        limit: usize,
    },
    /// The response is not the JSON document expected.
    #[error("{url} returned malformed JSON")]
    Json {
        /// The URL requested.
        url: String,
        /// The parse error.
        #[source]
        source: serde_json::Error,
    },
    /// The response parsed but says something impossible or inconsistent.
    #[error("{url}: {reason}")]
    Malformed {
        /// The URL requested.
        url: String,
        /// What is wrong with it.
        reason: String,
    },
    /// The release tag cannot name an image in a registry: OCI tags are
    /// `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}`.
    #[error("tag {0} is not a valid OCI image tag: expected [A-Za-z0-9_][A-Za-z0-9._-]{{0,127}}")]
    OciTag(ReleaseTag),
    /// The tag ref points straight at a commit: there is no tag object.
    #[error("tag {tag} is a lightweight tag, not a tag object")]
    LightweightTag {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The tag object carries no signature, so GitHub serves no signed
    /// payload and its raw bytes cannot be reconstructed. Callers report this
    /// as "tag is not signed".
    #[error("tag {tag} is not signed: GitHub serves no signed payload for it")]
    NotSigned {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The reconstructed tag object is a SHA-1 collision attempt: its hash
    /// is not trustworthy as an object id.
    #[error("tag {tag}: the tag object's bytes contain a SHA-1 collision attack")]
    Sha1Collision {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The reconstructed tag object does not hash to the id it was fetched by.
    #[error("tag object id mismatch: fetched {expected:?}, the served bytes hash to {computed}")]
    ObjectId {
        /// The object id the tag ref named.
        expected: String,
        /// The git object id of the bytes served.
        computed: String,
    },
    /// The tag points at a tree or a blob, not a commit or tag object.
    #[error("tag {tag} points at a {found:?} object, not a commit")]
    ObjectType {
        /// The tag.
        tag: ReleaseTag,
        /// The git object type found.
        found: String,
    },
    /// The tag is a chain of more than four tag objects.
    #[error("tag {tag} nests more than {MAX_TAG_DEPTH} tag objects")]
    TagDepth {
        /// The tag.
        tag: ReleaseTag,
    },
    /// The response has a media type other than the ones asked for.
    #[error("{url} served media type {found:?}, expected {expected}")]
    MediaType {
        /// The URL requested.
        url: String,
        /// The media type served.
        found: String,
        /// What was acceptable.
        expected: &'static str,
    },
    /// The bytes served do not hash to the digest they were named by.
    #[error(
        "{url}: content digest mismatch: expected {expected:?}, the served bytes hash to \
         {computed}"
    )]
    Digest {
        /// The URL requested.
        url: String,
        /// The digest from the header or the referring descriptor.
        expected: String,
        /// The sha256 of the bytes served.
        computed: String,
    },
    /// Not exactly one SLSA provenance bundle refers to the digest.
    #[error("expected exactly one SLSA provenance bundle for {digest}, found {count}")]
    Bundles {
        /// The image digest.
        digest: ImageDigest,
        /// How many bundles refer to it.
        count: usize,
    },
    /// A paginated list goes on past what is read of it, so whatever it holds
    /// further on is unknown.
    #[error("{url}: the list goes on past {limit} {what}")]
    ListCap {
        /// The first page's URL.
        url: String,
        /// The cap.
        limit: usize,
        /// What is counted: `tags` or `pages`.
        what: &'static str,
    },
}

impl FetchError {
    /// Whether the material could not be obtained at all: a bad endpoint or
    /// token, a transport failure, a redirect that isn't followed, a 404, a rate
    /// limit, another HTTP status, or no provenance bundle yet (attestation is
    /// pushed after the image, so a release still being published has none).
    /// `false` when it was
    /// served and refused by a check here (size, media type, digest, object
    /// id, shape, several provenance bundles).
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Endpoint { .. }
                | Self::Token
                | Self::Client(_)
                | Self::Request { .. }
                | Self::Redirect { .. }
                | Self::NotFound { .. }
                | Self::RateLimited { .. }
                | Self::Status { .. }
                | Self::Bundles { count: 0, .. }
        )
    }
}
