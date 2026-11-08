//! What a client puts in a path and a query string, and how each is read.
//!
//! A query string is at most [`MAX_QUERY_BYTES`] and goes through `serde_urlencoded` into a
//! type that refuses unknown fields, so a parameter the operation doesn't take is refused
//! rather than ignored. An operation with no parameters takes [`NoQuery`], so that holds on
//! every route. Each type derives [`IntoParams`], and its operation names it in `params(…)`,
//! so the document says what is read.
//!
//! A list that can grow is read a page at a time: [`Limit`] says how long a page is, and a
//! [`Cursor`] where the next one begins. A cursor is opaque to a client and tied to its list,
//! so one from another list, or one that was changed, is refused rather than read.

use std::future::ready;

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::de::{self, DeserializeOwned};
use serde::{Deserialize, Deserializer};
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

/// How many items a page holds: from 1 to 100, and 50 when a client leaves it out. Anything
/// else is refused, so that no request asks for an unbounded page.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Limit(u8);

impl Limit {
    /// The fewest items a page may hold.
    pub(crate) const MIN: u8 = 1;
    /// The most items a page may hold.
    pub(crate) const MAX: u8 = 100;
    /// What a page holds when a client doesn't say.
    pub(crate) const DEFAULT: u8 = 50;

    /// The limit a client sent, or the default.
    pub(crate) fn or_default(limit: Option<Self>) -> usize {
        usize::from(limit.map_or(Self::DEFAULT, |Self(n)| n))
    }
}

impl<'de> Deserialize<'de> for Limit {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let n = u64::deserialize(deserializer)?;
        u8::try_from(n)
            .ok()
            .filter(|n| (Self::MIN..=Self::MAX).contains(n))
            .map(Self)
            .ok_or_else(|| de::Error::custom("a limit is from 1 to 100"))
    }
}

/// The lists a cursor can belong to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CursorList {
    /// A deployment's releases.
    Releases,
    /// A deployment's deploys.
    Deploys,
    /// The audit log.
    Audit,
    /// The deployments.
    Deployments,
}

impl CursorList {
    fn name(self) -> &'static str {
        match self {
            Self::Releases => "releases",
            Self::Deploys => "deploys",
            Self::Audit => "audit",
            Self::Deployments => "deployments",
        }
    }

    fn named(name: &str) -> Option<Self> {
        [
            Self::Releases,
            Self::Deploys,
            Self::Audit,
            Self::Deployments,
        ]
        .into_iter()
        .find(|list| list.name() == name)
    }
}

/// Where the next page of a list begins: after the item `after` names, in the list's order.
/// On the wire it is the base64url, unpadded, of `v1.<list>.<after>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Cursor {
    list: CursorList,
    after: String,
}

impl Cursor {
    /// The longest `after` a cursor carries, in bytes: more than any id or tag a list is
    /// ordered by, so that a cursor is never a way to send the controller a long string.
    const MAX_AFTER_BYTES: usize = 160;

    /// A cursor of `list` that begins after `after`.
    pub(crate) fn new(list: CursorList, after: impl Into<String>) -> Self {
        Self {
            list,
            after: after.into(),
        }
    }

    /// What a client sends back.
    pub(crate) fn encode(&self) -> String {
        URL_SAFE_NO_PAD.encode(format!("v1.{}.{}", self.list.name(), self.after))
    }

    /// The cursor `raw` is, if it is one of `expected`'s. Anything else is `bad_request`: one
    /// of another list, one not in base64url without padding, one that doesn't say `v1`, and
    /// one whose `after` is empty or over 160 bytes.
    pub(crate) fn decode(raw: &str, expected: CursorList) -> Result<Self, ApiProblem> {
        let bytes = URL_SAFE_NO_PAD
            .decode(raw)
            .map_err(|_| ApiProblem::BadRequest)?;
        let text = String::from_utf8(bytes).map_err(|_| ApiProblem::BadRequest)?;
        let (list, after) = text
            .strip_prefix("v1.")
            .and_then(|rest| rest.split_once('.'))
            .ok_or(ApiProblem::BadRequest)?;
        if CursorList::named(list) != Some(expected)
            || after.is_empty()
            || after.len() > Self::MAX_AFTER_BYTES
        {
            return Err(ApiProblem::BadRequest);
        }
        Ok(Self::new(expected, after))
    }

    /// The item the next page begins after.
    pub(crate) fn after(&self) -> &str {
        &self.after
    }
}
