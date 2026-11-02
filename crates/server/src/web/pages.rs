//! The static files, built into the binary and each served by a route of its own, so that no
//! path from a request ever reaches a file. They say nothing about this controller and need
//! no session: what they show comes from the API, which does.

use axum::http::header;
use axum::response::{IntoResponse, Response};

const HTML: &str = "text/html; charset=utf-8";
const JAVASCRIPT: &str = "text/javascript; charset=utf-8";

fn file(content_type: &'static str, text: &'static str) -> Response {
    (
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-store"),
        ],
        text,
    )
        .into_response()
}

pub(super) async fn register() -> Response {
    file(HTML, include_str!("static/register.html"))
}

pub(super) async fn sign_in() -> Response {
    file(HTML, include_str!("static/sign-in.html"))
}

pub(super) async fn approvals() -> Response {
    file(HTML, include_str!("static/approvals.html"))
}

pub(super) async fn script() -> Response {
    file(JAVASCRIPT, include_str!("static/landfall.js"))
}
