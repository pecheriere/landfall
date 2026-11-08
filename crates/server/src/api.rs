//! `/api/v1`, the API for people and their agents, and the OpenAPI document that describes it.
//!
//! Every route is registered through one [`OpenApiRouter`], with its annotation, so a route
//! can't exist without its entry in the document, nor an entry without its route. The
//! document is generated from that, served at `GET /api/v1/openapi.json`, printed by
//! `landfall-server openapi` and checked in as `docs/api/openapi.json`, and a test fails when
//! the checked-in copy differs.
//!
//! Every success is JSON through `ApiJson`, and every refusal `application/problem+json`
//! with a stable code from the document's `Problem` schema. No answer carries a CORS header.

mod openapi;

use std::sync::LazyLock;

use axum::Router;
use axum::body::{Body, Bytes};
use axum::http::{HeaderName, HeaderValue, header};
use axum::middleware;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde::Serialize;
use utoipa::OpenApi as _;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

pub(crate) use self::openapi::{BadRequest, Forbidden, NotFound, RateLimited, Unauthenticated};
use crate::agent_api::{ApiState, deadline, json, note_client_source};
use crate::auth::HumanProblem;
use crate::requests;

/// What every answer of this API carries: no cache keeps it.
const NO_STORE: [(HeaderName, &str); 1] = [(header::CACHE_CONTROL, "no-store")];

/// A success: `T` as `application/json`, with `Cache-Control: no-store`.
#[derive(Debug)]
pub(crate) struct ApiJson<T>(pub T);

impl<T: Serialize> IntoResponse for ApiJson<T> {
    fn into_response(self) -> Response {
        json(&self.0, &NO_STORE)
    }
}

/// Every `/api/v1` operation, with the document's fixed part.
fn operations() -> OpenApiRouter<ApiState> {
    OpenApiRouter::with_openapi(openapi::ApiDoc::openapi())
        .merge(requests::routes())
        .routes(routes!(document))
}

/// The document, as pretty JSON with a final newline: what the route serves, `openapi`
/// prints and `docs/api/openapi.json` holds.
#[must_use]
pub fn openapi_document() -> String {
    let (_, document) = operations().split_for_parts();
    // Maps with string keys and plain values: serialising this cannot fail. If it ever did,
    // the document would be empty, and the test that compares it with the checked-in copy
    // would fail.
    let mut text = document.to_pretty_json().unwrap_or_default();
    text.push('\n');
    text
}

/// The document's bytes, made once.
static DOCUMENT: LazyLock<String> = LazyLock::new(openapi_document);

/// `GET /api/v1/openapi.json`. Public, as it says nothing about this controller: the same
/// bytes as every controller of this version.
#[utoipa::path(
    get,
    path = "/api/v1/openapi.json",
    operation_id = "getOpenApi",
    tag = "api",
    summary = "This document",
    description = "Public, as it says nothing about this controller: the same bytes from every \
                   controller of this version.",
    security(()),
    responses((
        status = 200,
        description = "This document.",
        content_type = "application/json",
    )),
)]
async fn document() -> Response {
    let mut response = Response::new(Body::from(Bytes::from_static(DOCUMENT.as_bytes())));
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    for (name, value) in NO_STORE {
        headers.insert(name, HeaderValue::from_static(value));
    }
    response
}

async fn not_found() -> HumanProblem {
    HumanProblem::NotFound
}

async fn method_not_allowed() -> HumanProblem {
    HumanProblem::MethodNotAllowed
}

/// The API's routes, with every answer `application/problem+json` that isn't a success.
pub(crate) fn router(state: ApiState) -> Router {
    let limit = state.limits().request_timeout;
    let (routes, _) = operations().split_for_parts();
    routes
        .route("/api/v1", any(not_found))
        .route("/api/v1/", any(not_found))
        .route("/api/v1/{*rest}", any(not_found))
        .method_not_allowed_fallback(method_not_allowed)
        .with_state(state.clone())
        .layer(middleware::from_fn_with_state(limit, deadline))
        .layer(middleware::from_fn_with_state(state, note_client_source))
}

#[cfg(test)]
mod tests;
