//! Sending a request, following its redirects, and reading its answer within the size caps.

use std::time::Duration;

use jiff::Timestamp;
use landfall_core::ids::ImageDigest;
use reqwest::header::{
    ACCEPT, AUTHORIZATION, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue, LOCATION, RETRY_AFTER,
};
use reqwest::{RequestBuilder, Response, StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{
    FetchError, Fetcher, GITHUB_API_VERSION, MAX_REDIRECTS, RATELIMIT_REMAINING, RATELIMIT_RESET,
    RateLimitReset, Service,
};

const TOO_MANY: &str = "there are too many redirects";

/// A response that passed the status check, with its capped body.
pub(super) struct Fetched {
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

/// What is asked of each request of a GET, whichever host it reaches.
#[derive(Clone, Copy)]
pub(super) struct Transfer<'a> {
    /// The `Accept` header.
    pub(super) accept: &'a str,
    /// Who it is for, in what a failure says.
    pub(super) service: Service,
    /// The cap on the body.
    pub(super) limit: usize,
    /// A total timeout for each request, other than the client's.
    pub(super) timeout: Option<Duration>,
}

/// What a redirect to the host that has the credential does.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum SameHost {
    /// It is the same service, so the credential goes along: a renamed repository, say.
    KeepsCredential,
    /// It is refused: what this asks for has no reason to.
    Refused,
}

impl Fetcher {
    /// A GET of `url`, with `credential` on it if there is one, following redirects by
    /// hand. The client follows none, as what it does about a credential on one redirect
    /// doesn't hold over the next.
    ///
    /// The credential goes to `url`, and along redirects within its host and port as
    /// `same_host` says. The first redirect anywhere else goes to [`Self::follow`], which
    /// has no credential to send.
    pub(super) async fn get(
        &self,
        url: &Url,
        transfer: Transfer<'_>,
        credential: Option<&HeaderValue>,
        same_host: SameHost,
    ) -> Result<Fetched, FetchError> {
        let mut current = url.clone();
        for used in 0..=MAX_REDIRECTS {
            let mut request = self.request(&current, transfer);
            if transfer.service == Service::GitHubApi {
                request = request.header("x-github-api-version", GITHUB_API_VERSION);
            }
            if let Some(credential) = credential {
                request = request.header(AUTHORIZATION, credential.clone());
            }
            let response = request.send().await.map_err(|e| transport(url, e))?;
            let Some(next) = self.redirect_of(&response, &current, url)? else {
                return read(response, transfer, url).await;
            };
            if !on_same_host(&next, url) {
                return self.follow(next, url, transfer, used + 1).await;
            }
            if same_host == SameHost::Refused {
                return Err(redirect_refused(url, "it stays on the host asked"));
            }
            current = next;
        }
        Err(redirect_refused(url, TOO_MANY))
    }

    /// The rest of a GET of `asked`, from `first` on another host, with `used` redirects of
    /// the limit gone. It takes no credential, so it can't send one, and its requests carry
    /// nothing but `Accept`. It refuses to go back to the host of `asked`, which has no
    /// reason to be asked again with no credential.
    async fn follow(
        &self,
        first: Url,
        asked: &Url,
        transfer: Transfer<'_>,
        used: usize,
    ) -> Result<Fetched, FetchError> {
        let mut current = first;
        for _ in used..=MAX_REDIRECTS {
            let request = self.request(&current, transfer);
            let response = request.send().await.map_err(|e| transport(asked, e))?;
            let Some(next) = self.redirect_of(&response, &current, asked)? else {
                return read(response, transfer, asked).await;
            };
            if on_same_host(&next, asked) {
                return Err(redirect_refused(asked, "it comes back to the host asked"));
            }
            current = next;
        }
        Err(redirect_refused(asked, TOO_MANY))
    }

    /// A request with nothing on it that isn't for every host.
    fn request(&self, url: &Url, transfer: Transfer<'_>) -> RequestBuilder {
        let request = self.client.get(url.clone()).header(ACCEPT, transfer.accept);
        match transfer.timeout {
            Some(timeout) => request.timeout(timeout),
            None => request,
        }
    }

    /// Where `response` to a request for `current` redirects to, if it does. A redirect
    /// with no `Location` isn't one, and is an unexpected status like any other.
    fn redirect_of(
        &self,
        response: &Response,
        current: &Url,
        asked: &Url,
    ) -> Result<Option<Url>, FetchError> {
        let is_redirect = matches!(
            response.status(),
            StatusCode::MOVED_PERMANENTLY
                | StatusCode::FOUND
                | StatusCode::SEE_OTHER
                | StatusCode::TEMPORARY_REDIRECT
                | StatusCode::PERMANENT_REDIRECT
        );
        let Some(location) = response.headers().get(LOCATION).filter(|_| is_redirect) else {
            return Ok(None);
        };
        let location = location
            .to_str()
            .map_err(|_| redirect_refused(asked, "its location is not text"))?;
        next_hop(current, location, self.endpoints.https_only)
            .map(Some)
            .map_err(|reason| redirect_refused(asked, reason))
    }
}

/// What a `Location` on an answer for `current` points to, if it may be followed. A refusal
/// says why and not where, as the target's query may be a credential.
pub(super) fn next_hop(
    current: &Url,
    location: &str,
    https_only: bool,
) -> Result<Url, &'static str> {
    let next = current
        .join(location)
        .map_err(|_| "its location is not a URL")?;
    if !(next.scheme() == "https" || (!https_only && next.scheme() == "http")) {
        return Err("its location is not https");
    }
    if !next.username().is_empty() || next.password().is_some() {
        return Err("its location carries credentials");
    }
    Ok(next)
}

fn on_same_host(one: &Url, other: &Url) -> bool {
    one.host_str() == other.host_str()
        && one.port_or_known_default() == other.port_or_known_default()
}

fn redirect_refused(url: &Url, reason: &'static str) -> FetchError {
    FetchError::Redirect {
        url: url.to_string(),
        reason,
    }
}

/// A transport failure of a GET of `url`, without the URL the client has on it: after a
/// redirect that is a storage host's, whose query is a credential.
fn transport(url: &Url, source: reqwest::Error) -> FetchError {
    FetchError::Request {
        url: url.to_string(),
        source: source.without_url(),
    }
}

/// Refuses any status but 200 (naming a rate limit as such), and reads at most the
/// transfer's limit of body. `url` is what was asked for, which is what a failure names.
async fn read(
    mut response: Response,
    transfer: Transfer<'_>,
    url: &Url,
) -> Result<Fetched, FetchError> {
    let Transfer { service, limit, .. } = transfer;
    match response.status() {
        StatusCode::OK => {}
        StatusCode::NOT_FOUND => {
            return Err(FetchError::NotFound {
                url: url.to_string(),
            });
        }
        status => {
            let url = url.to_string();
            let status_code = status.as_u16();
            return Err(match rate_limit_reset(status, response.headers()) {
                Some(reset) => FetchError::RateLimited {
                    service,
                    url,
                    status: status_code,
                    reset,
                },
                None => FetchError::Status {
                    url,
                    status: status_code,
                },
            });
        }
    }
    let too_large = || FetchError::TooLarge {
        url: url.to_string(),
        limit,
    };
    // A declared length over the cap is refused before any byte is read; an
    // absent or false one is caught while streaming. Never preallocate from it.
    if response
        .content_length()
        .is_some_and(|length| usize::try_from(length).map_or(true, |length| length > limit))
    {
        return Err(too_large());
    }
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|e| transport(url, e))? {
        if chunk.len() > limit - body.len() {
            return Err(too_large());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(Fetched {
        headers: response.headers().clone(),
        body,
    })
}

/// When the rate limit lifts, for a response that is a rate-limit refusal:
/// HTTP 403 or 429 with `x-ratelimit-remaining: 0` or a `Retry-After`
/// header (GitHub's primary and secondary limits). `None` for any other
/// response.
fn rate_limit_reset(status: StatusCode, headers: &HeaderMap) -> Option<RateLimitReset> {
    if status != StatusCode::FORBIDDEN && status != StatusCode::TOO_MANY_REQUESTS {
        return None;
    }
    let text = |name: &HeaderName| headers.get(name).and_then(|v| v.to_str().ok());
    let number = |name: &HeaderName| text(name).and_then(|v| v.trim().parse::<u64>().ok());
    let exhausted = text(&RATELIMIT_REMAINING).is_some_and(|v| v.trim() == "0");
    if !exhausted && !headers.contains_key(RETRY_AFTER) {
        return None;
    }
    let reset = if let Some(seconds) = number(&RETRY_AFTER) {
        RateLimitReset::After(seconds)
    } else if let Some(at) = number(&RATELIMIT_RESET)
        .and_then(|epoch| i64::try_from(epoch).ok())
        .and_then(|epoch| Timestamp::from_second(epoch).ok())
    {
        RateLimitReset::At(at)
    } else {
        RateLimitReset::Unknown
    };
    Some(reset)
}

/// `base` with `segments` appended to its path, each percent-encoded.
pub(super) fn join(base: &Url, segments: &[&str]) -> Result<Url, FetchError> {
    let mut url = base.clone();
    url.path_segments_mut()
        .map_err(|()| FetchError::Endpoint {
            url: base.to_string(),
            reason: "cannot be a base URL",
        })?
        .pop_if_empty()
        .extend(segments);
    Ok(url)
}

pub(super) fn parse<'a, T: Deserialize<'a>>(url: &Url, body: &'a [u8]) -> Result<T, FetchError> {
    serde_json::from_slice(body).map_err(|source| FetchError::Json {
        url: url.to_string(),
        source,
    })
}

/// The media type of a response, without parameters.
pub(super) fn media_type(headers: &HeaderMap) -> String {
    headers
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .map(|value| value.trim().to_owned())
        .unwrap_or_default()
}

/// The sha256 digest of the body, which must equal `Docker-Content-Digest`
/// when the response has that header.
pub(super) fn content_digest(url: &Url, response: &Fetched) -> Result<ImageDigest, FetchError> {
    let computed = sha256_digest(&response.body);
    if let Some(header) = response.headers.get("docker-content-digest") {
        let expected = header.to_str().map_err(|_| FetchError::Malformed {
            url: url.to_string(),
            reason: "Docker-Content-Digest is not ASCII".to_owned(),
        })?;
        if expected != computed {
            return Err(FetchError::Digest {
                url: url.to_string(),
                expected: expected.to_owned(),
                computed,
            });
        }
    }
    computed.parse().map_err(|_| FetchError::Malformed {
        url: url.to_string(),
        reason: format!("computed digest {computed} did not parse"),
    })
}

pub(super) fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(&Sha256::digest(bytes)))
}

/// Lowercase hex.
pub(crate) fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    bytes
        .iter()
        .flat_map(|b| {
            [
                char::from(DIGITS[usize::from(b >> 4)]),
                char::from(DIGITS[usize::from(b & 0x0f)]),
            ]
        })
        .collect()
}
