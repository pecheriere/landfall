//! What a client puts in a path and a query string, and how each is read.
//!
//! A query string is at most [`MAX_QUERY_BYTES`] and goes through `serde_urlencoded` into a
//! type that refuses unknown fields, so a parameter the operation doesn't take is refused
//! rather than ignored. An operation with no parameters takes [`NoQuery`], so that holds on
//! every route. Each type derives [`IntoParams`], and its operation names it in `params(…)`,
//! so the document says what is read.

use std::future::ready;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use utoipa::IntoParams;

use crate::agent_api::ApiProblem;
use crate::auth::HumanProblem;

/// The longest query string read, in bytes, as sent.
pub(crate) const MAX_QUERY_BYTES: usize = 2 * 1024;

/// The query string as `T`. Over [`MAX_QUERY_BYTES`], not in `T`'s shape, or naming a
/// parameter `T` doesn't take, it is `bad_request`.
#[derive(Debug)]
pub(crate) struct ApiQuery<T>(pub T);

impl<T: DeserializeOwned> ApiQuery<T> {
    fn read(raw: &str) -> Result<Self, HumanProblem> {
        if raw.len() > MAX_QUERY_BYTES {
            return Err(ApiProblem::BadRequest.into());
        }
        serde_urlencoded::from_str(raw)
            .map(Self)
            .map_err(|_| ApiProblem::BadRequest.into())
    }
}

impl<T, S> FromRequestParts<S> for ApiQuery<T>
where
    T: DeserializeOwned + IntoParams + Send,
    S: Sync,
{
    type Rejection = HumanProblem;

    fn from_request_parts(
        parts: &mut Parts,
        _: &S,
    ) -> impl Future<Output = Result<Self, HumanProblem>> + Send {
        ready(Self::read(parts.uri.query().unwrap_or_default()))
    }
}

/// No parameters: the query string of an operation that takes none, which refuses any.
#[derive(Debug, Deserialize, IntoParams)]
#[serde(deny_unknown_fields)]
#[into_params(parameter_in = Query)]
pub(crate) struct NoQuery {}

/// A deployment, by the two parts of its id.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub(crate) struct DeploymentPath {
    /// The deployment's name.
    #[param(example = "app")]
    pub(crate) name: String,
    /// The deployment's stage.
    #[param(example = "prod")]
    pub(crate) stage: String,
}

impl DeploymentPath {
    /// The id as a client wrote it, which may not be one.
    pub(crate) fn raw(&self) -> String {
        format!("{}/{}", self.name, self.stage)
    }
}

/// A row by its number.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Path)]
pub(crate) struct IdPath {
    /// Plain digits with no leading zero: any other way of writing a number names nothing.
    #[param(value_type = i64, minimum = 1, example = 42)]
    pub(crate) id: String,
}

impl IdPath {
    /// The number, if the path writes one the one way it can be written.
    pub(crate) fn number(&self) -> Option<i64> {
        request_number(&self.id)
    }
}

/// A number as a path has it: plain digits with no leading zero, so that one row has one
/// path.
fn request_number(raw: &str) -> Option<i64> {
    let canonical = !raw.starts_with('0') && raw.bytes().all(|b| b.is_ascii_digit());
    canonical.then(|| raw.parse().ok()).flatten()
}
