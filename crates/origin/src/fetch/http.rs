//! Sending a request and reading its answer within the size caps.

use jiff::Timestamp;
use landfall_core::ids::ImageDigest;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderName, RETRY_AFTER};
use reqwest::{StatusCode, Url};
use serde::Deserialize;
use sha2::{Digest, Sha256};

use super::{FetchError, RATELIMIT_REMAINING, RATELIMIT_RESET, RateLimitReset, Service};

/// A response that passed the status check, with its capped body.
pub(super) struct Fetched {
    pub(super) headers: HeaderMap,
    pub(super) body: Vec<u8>,
}

/// Sends `request` to `service`, refuses any status but 200 (naming a rate
/// limit as such), and reads at most `limit` bytes of body.
pub(super) async fn send(
    request: reqwest::RequestBuilder,
    service: Service,
    url: &Url,
    limit: usize,
) -> Result<Fetched, FetchError> {
    // Without its URL: after a redirect that is the storage host's, whose query is a
    // credential, and the URL that was asked for is named anyway.
    let transport = |source: reqwest::Error| FetchError::Request {
        url: url.to_string(),
        source: source.without_url(),
    };
    let mut response = request.send().await.map_err(transport)?;
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
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
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
