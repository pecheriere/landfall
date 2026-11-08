//! Signed requests: nonce, then body, then host key and signature, then parse.

use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use axum::http::uri::PathAndQuery;
use http_body_util::BodyExt as _;
use landfall_core::ids::HostId;
use landfall_core::protocol::{
    self, HOST_HEADER, MAX_BODY_BYTES, NONCE_HEADER, Nonce, RequestSignature, SIGNATURE_HEADER,
    SigningKey, VerifyingKey,
};
use serde::de::DeserializeOwned;

use super::ApiState;
use super::problem::ApiProblem;

/// How much is read and thrown away past a body's limit before answering. Closing
/// with bytes unread can reset the connection and lose the answer on the way, so
/// this lets a body a little over the limit hear why. A much larger one may still
/// get the reset, and a client has to bound its retries.
pub(crate) const DRAIN_BYTES: usize = 64 * 1024;

/// Seed of the key a signature is checked against when the host is unknown. It is
/// public, in this file, so a signature by it proves nothing and is never accepted.
pub(super) const UNKNOWN_HOST_SEED: [u8; 32] = [0x6c; 32];

/// The key for an unknown host. Deriving it costs about what reading a real key
/// from its stored bytes does.
fn unknown_host_key() -> VerifyingKey {
    SigningKey::from_bytes(&UNKNOWN_HOST_SEED).verifying_key()
}

/// Reads up to `limit` bytes of a body, then up to [`DRAIN_BYTES`] more to discard.
async fn read_bounded(mut body: Body, limit: usize) -> Result<Bytes, ApiProblem> {
    let mut kept = Vec::new();
    let mut read = 0_usize;
    while read <= limit.saturating_add(DRAIN_BYTES) {
        let Some(frame) = body.frame().await else {
            break;
        };
        let Ok(frame) = frame else {
            return Err(if read > limit {
                ApiProblem::BodyTooLarge
            } else {
                ApiProblem::BadRequest
            });
        };
        // Anything else is trailers, which nothing here looks at.
        if let Ok(data) = frame.into_data() {
            read = read.saturating_add(data.len());
            if read <= limit {
                kept.extend_from_slice(&data);
            }
        }
    }
    if read > limit {
        Err(ApiProblem::BodyTooLarge)
    } else {
        Ok(Bytes::from(kept))
    }
}

/// Reads a body of at most `limit` bytes, for at most `timeout`.
pub(crate) async fn read_body(
    body: Body,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, ApiProblem> {
    tokio::time::timeout(timeout, read_bounded(body, limit))
        .await
        .unwrap_or(Err(ApiProblem::SlowRequest))
}

/// The value of a header that must appear exactly once and be valid text. A
/// repeated one is refused, so that a proxy and this code can never read
/// different values.
fn single_header<'a>(headers: &'a HeaderMap, name: &str) -> Result<&'a str, ApiProblem> {
    let mut values = headers.get_all(name).iter();
    match (values.next(), values.next()) {
        (Some(value), None) => value.to_str().map_err(|_| ApiProblem::Unsigned),
        _ => Err(ApiProblem::Unsigned),
    }
}

fn parsed_header<T: std::str::FromStr>(headers: &HeaderMap, name: &str) -> Result<T, ApiProblem> {
    single_header(headers, name)?
        .parse()
        .map_err(|_| ApiProblem::Unsigned)
}

/// A request whose signature verified: `host` is who signed it, the only
/// identity a handler may use, and `body` is the parsed body.
#[derive(Debug)]
pub(super) struct Signed<T> {
    pub(super) host: HostId,
    pub(super) body: T,
}

impl<T: DeserializeOwned> FromRequest<ApiState> for Signed<T> {
    type Rejection = ApiProblem;

    async fn from_request(request: Request, state: &ApiState) -> Result<Self, ApiProblem> {
        let (parts, body) = request.into_parts();
        let host: HostId = parsed_header(&parts.headers, HOST_HEADER)?;
        let nonce: Nonce = parsed_header(&parts.headers, NONCE_HEADER)?;
        let signature: RequestSignature = parsed_header(&parts.headers, SIGNATURE_HEADER)?;

        // The nonce goes first and is used up whatever follows: nobody gets a
        // signature checked, or a body read, without one.
        if !state.store.consume_nonce(&nonce).await? {
            return Err(ApiProblem::BadNonce);
        }
        // Before the key is looked up, so that a body over the limit gets the
        // same answer for a host that exists and one that does not.
        let bytes = read_body(body, MAX_BODY_BYTES, state.limits.body_timeout).await?;
        let key = state.store.host_key(&host).await?;

        // The path as sent, with its query: the signature covers both.
        let path = parts
            .uri
            .path_and_query()
            .map_or_else(|| parts.uri.path(), PathAndQuery::as_str);
        let known = key.is_some();
        let signature_holds = protocol::verify(
            &key.unwrap_or_else(unknown_host_key),
            &signature,
            &host,
            parts.method.as_str(),
            path,
            &nonce,
            &bytes,
        )
        .is_ok();
        // Both ways do the hashing and the check, so the time does not say which
        // hosts exist. The key for an unknown host is public: it never verifies
        // anything, however good the signature.
        if !(known && signature_holds) {
            state.note_refusal(&parts.extensions, "a request with a bad signature");
            return Err(ApiProblem::BadSignature);
        }

        let body = serde_json::from_slice(&bytes).map_err(|_| ApiProblem::BadRequest)?;
        Ok(Self { host, body })
    }
}
