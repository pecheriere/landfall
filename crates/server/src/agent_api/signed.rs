//! Signed requests: nonce, then body, then host key and signature, then parse.

use std::error::Error;
use std::time::Duration;

use axum::body::{Body, Bytes};
use axum::extract::{FromRequest, Request};
use axum::http::HeaderMap;
use axum::http::uri::PathAndQuery;
use http_body_util::LengthLimitError;
use landfall_core::ids::HostId;
use landfall_core::protocol::{
    self, HOST_HEADER, MAX_BODY_BYTES, NONCE_HEADER, Nonce, RequestSignature, SIGNATURE_HEADER,
};
use serde::de::DeserializeOwned;

use super::ApiState;
use super::problem::ApiProblem;

/// Reads a body of at most `limit` bytes, for at most `timeout`.
pub(super) async fn read_body(
    body: Body,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, ApiProblem> {
    match tokio::time::timeout(timeout, axum::body::to_bytes(body, limit)).await {
        Err(_) => Err(ApiProblem::SlowRequest),
        Ok(Ok(bytes)) => Ok(bytes),
        Ok(Err(error)) => {
            let over_limit = error
                .source()
                .is_some_and(<dyn Error>::is::<LengthLimitError>);
            Err(if over_limit {
                ApiProblem::BodyTooLarge
            } else {
                ApiProblem::BadRequest
            })
        }
    }
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
        let verified = key.is_some_and(|key| {
            protocol::verify(
                &key,
                &signature,
                &host,
                parts.method.as_str(),
                path,
                &nonce,
                &bytes,
            )
            .is_ok()
        });
        if !verified {
            state.note_refusal(&parts.extensions, "a request with a bad signature");
            return Err(ApiProblem::BadSignature);
        }

        let body = serde_json::from_slice(&bytes).map_err(|_| ApiProblem::BadRequest)?;
        Ok(Self { host, body })
    }
}
