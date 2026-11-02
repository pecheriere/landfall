//! The headers on every answer, whichever part of the controller gave it.

use axum::http::{HeaderValue, header};
use axum::response::Response;

/// The strict policy of the design: everything from this origin, nothing inline, and nothing
/// that could frame the pages, rewrite their links or submit a form anywhere. The pages have
/// no `<form>`: they `fetch`.
const CONTENT_SECURITY_POLICY: &str = "default-src 'self'; base-uri 'none'; form-action 'none'; \
                                       frame-ancestors 'none'; object-src 'none'";

/// Sets the headers, over anything a handler set.
pub(crate) async fn security_headers(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(CONTENT_SECURITY_POLICY),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}
