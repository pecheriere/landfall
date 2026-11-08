//! The controller's `/api/v1`, over HTTP, with the operator's token.
//!
//! The token goes to the controller the operator named and nowhere else: no proxy from the
//! environment, nothing but `https` to an `https` controller, and no redirect followed, since
//! one could take the token to another host. What comes back is hostile: a body is capped
//! while it is read, and every string in it is escaped by [`crate::display`] before it is
//! printed.

use std::time::Duration;

use landfall_api::{Problem, ProblemCode};
use landfall_core::controller_url::ControllerUrl;
use landfall_core::protocol::PROBLEM_CONTENT_TYPE;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE, HeaderValue, RETRY_AFTER};
use reqwest::{Client, RequestBuilder, Response, StatusCode, redirect};
use serde::Serialize;
use serde::de::DeserializeOwned;
use thiserror::Error;

use crate::display::wire_name;
use crate::settings::{Settings, TokenSource};

#[cfg(test)]
mod tests;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// The whole of one request, its body read included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The largest body read: a page of the API is far smaller.
const BODY_CAP: usize = 4 * 1024 * 1024;

/// The most of a problem's title kept, so that a hostile one can't flood a terminal.
const TITLE_CHARS: usize = 256;

/// A client for one controller. It has no `Debug`, as it holds the token.
pub struct ApiClient {
    http: Client,
    controller: ControllerUrl,
    token: Option<HeaderValue>,
    token_source: Option<TokenSource>,
}

impl ApiClient {
    /// A client for `settings`: the controller directly, with no proxy from the environment,
    /// no redirect followed, only `https` to an `https` controller, rustls, a connect timeout
    /// of 10 s and 30 s for each request.
    ///
    /// # Errors
    ///
    /// [`ApiError::Network`] if the HTTP client can't be built.
    pub fn new(settings: &Settings) -> Result<Self, ApiError> {
        let controller = settings.controller.clone();
        let builder = Client::builder()
            .no_proxy()
            .https_only(controller.is_https())
            .redirect(redirect::Policy::none())
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .user_agent(concat!("landfall/", env!("CARGO_PKG_VERSION")));
        // Plain HTTP makes no use of the system's CA certificates, as the agent's client has
        // it, so a machine without them can still reach a controller over loopback.
        let builder = if controller.is_https() {
            builder
        } else {
            builder.tls_certs_only([])
        };
        let http = builder.build().map_err(ApiError::network)?;
        Ok(Self {
            http,
            controller,
            token: settings.token.as_ref().map(crate::settings::Token::header),
            token_source: settings.token.as_ref().map(|token| token.source().clone()),
        })
    }

    /// `GET path?query`, and the body of its answer.
    ///
    /// # Errors
    ///
    /// An [`ApiError`] for anything but a success with a JSON body within the cap.
    pub async fn get(
        &self,
        path: &str,
        query: &[(&str, &str)],
    ) -> Result<serde_json::Value, ApiError> {
        let mut url = self.controller.join(path);
        if !query.is_empty() {
            url.query_pairs_mut().extend_pairs(query);
        }
        self.send(self.http.get(url)).await
    }

    /// `POST path` with `body` as JSON, and the body of its answer.
    ///
    /// # Errors
    ///
    /// An [`ApiError`] for anything but a success with a JSON body within the cap.
    pub async fn post<B: Serialize>(
        &self,
        path: &str,
        body: &B,
    ) -> Result<serde_json::Value, ApiError> {
        let body = serde_json::to_vec(body).map_err(ApiError::Parse)?;
        let request = self
            .http
            .post(self.controller.join(path))
            .header(CONTENT_TYPE, "application/json")
            .body(body);
        self.send(request).await
    }

    /// `value` as one of the API's types. Fields and values from a newer controller are
    /// tolerated, as the types say.
    ///
    /// # Errors
    ///
    /// [`ApiError::Parse`] if it isn't one.
    pub fn typed<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, ApiError> {
        T::deserialize(value).map_err(ApiError::Parse)
    }

    async fn send(&self, request: RequestBuilder) -> Result<serde_json::Value, ApiError> {
        let request = match &self.token {
            Some(token) => request.header(AUTHORIZATION, token.clone()),
            None => request,
        };
        let response = request.send().await.map_err(ApiError::network)?;
        let status = response.status();
        if status.is_success() {
            let body = read_capped(response).await?;
            return serde_json::from_slice(&body).map_err(ApiError::Parse);
        }
        Err(self.refusal(status, response).await)
    }

    /// What an answer other than a success means.
    async fn refusal(&self, status: StatusCode, response: Response) -> ApiError {
        if status.is_redirection() {
            return ApiError::Redirected {
                status: status.as_u16(),
            };
        }
        if status == StatusCode::UNAUTHORIZED {
            return ApiError::Unauthenticated {
                from: self.token_source.clone(),
            };
        }
        if status == StatusCode::TOO_MANY_REQUESTS {
            let retry_after_secs = response
                .headers()
                .get(RETRY_AFTER)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.trim().parse().ok());
            return ApiError::RateLimited { retry_after_secs };
        }
        let server = ApiError::Server {
            status: status.as_u16(),
        };
        if !status.is_client_error() || !is_problem(&response) {
            return server;
        }
        let Ok(body) = read_capped(response).await else {
            return server;
        };
        match serde_json::from_slice::<Problem>(&body) {
            Ok(problem) if problem.status == status.as_u16() => ApiError::Refused {
                status: problem.status,
                code: problem.code,
                title: problem.title.chars().take(TITLE_CHARS).collect(),
            },
            _ => server,
        }
    }
}

/// Whether the answer says it is the API's problem document.
fn is_problem(response: &Response) -> bool {
    response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(PROBLEM_CONTENT_TYPE))
}

/// Reads a body up to [`BODY_CAP`]; a larger one is an error, not a truncation.
async fn read_capped(mut response: Response) -> Result<Vec<u8>, ApiError> {
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(ApiError::network)? {
        if body.len() + chunk.len() > BODY_CAP {
            return Err(ApiError::TooLarge);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// Why a call to the API failed. No variant holds the token.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiError {
    /// The controller refused, with a problem document. Its title is hostile: escape it.
    #[error("the controller refused ({status}): {}: {title}", wire_name(code))]
    Refused {
        /// The HTTP status.
        status: u16,
        /// The stable code, [`ProblemCode::Unknown`] for one from a newer controller.
        code: ProblemCode,
        /// What it said, cut to 256 characters.
        title: String,
    },
    /// The controller didn't take the credentials.
    #[error("{}", unauthenticated(.from.as_ref()))]
    Unauthenticated {
        /// Where the token sent came from, `None` if none was sent.
        from: Option<TokenSource>,
    },
    /// Too many requests.
    #[error("the controller is rate limiting this client{}", retry_after(*.retry_after_secs))]
    RateLimited {
        /// What `Retry-After` said, in seconds.
        retry_after_secs: Option<u32>,
    },
    /// The controller failed, or something in front of it answered.
    #[error("the controller, or something in front of it, answered HTTP {status}")]
    Server {
        /// The HTTP status.
        status: u16,
    },
    /// A redirect, which isn't followed: it could take the token elsewhere. Where it pointed
    /// isn't repeated.
    #[error(
        "the controller answered with a redirect (HTTP {status}), which is not followed so that the token goes nowhere else: check --controller"
    )]
    Redirected {
        /// The HTTP status.
        status: u16,
    },
    /// The answer is over 4 MiB.
    #[error("the controller's answer is over {BODY_CAP} bytes")]
    TooLarge,
    /// The controller could not be reached, or the answer could not be read. The error's URL
    /// has no query and no credentials.
    #[error("cannot reach the controller")]
    Network(#[source] reqwest::Error),
    /// The answer isn't the JSON this CLI reads, or a body couldn't be written.
    #[error("the controller's answer is not one this CLI can read")]
    Parse(#[source] serde_json::Error),
}

impl ApiError {
    /// The exit status: 1 for a refusal by the controller, 2 for anything that kept the CLI
    /// from asking.
    #[must_use]
    pub fn exit_code(&self) -> u8 {
        match self {
            Self::Refused { .. } => 1,
            _ => 2,
        }
    }

    /// `error`, with its URL's query and any credentials taken out.
    fn network(mut error: reqwest::Error) -> Self {
        if let Some(url) = error.url_mut() {
            url.set_query(None);
            url.set_fragment(None);
            // Neither fails on a URL with a host, which is the only kind sent.
            let _ = url.set_username("");
            let _ = url.set_password(None);
        }
        Self::Network(error)
    }
}

fn unauthenticated(from: Option<&TokenSource>) -> String {
    match from {
        Some(source) => format!(
            "the controller did not accept the token from {source}: check it, or ask for a new one"
        ),
        None => "the controller wants a token and none is configured: set LANDFALL_TOKEN, or \
                 name a token file with --token-file, LANDFALL_TOKEN_FILE or token_file in the \
                 CLI's configuration file"
            .to_owned(),
    }
}

fn retry_after(seconds: Option<u32>) -> String {
    seconds.map_or_else(String::new, |seconds| format!(": try again in {seconds} s"))
}
