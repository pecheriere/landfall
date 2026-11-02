//! The agent's side of the agent API: the [`Controller`] trait the daemon goes
//! by, and [`HttpController`], which signs every request.
//!
//! The controller may be compromised, so what it answers is hostile: a body is
//! capped while it is read and its text is quoted and truncated before it
//! reaches an error. Redirects are not followed: a signature covers one path,
//! and a redirect could only take the request somewhere it was not meant for.

use std::error::Error;
use std::fmt::Write as _;
use std::future::Future;
use std::net::IpAddr;
use std::time::Duration;

use landfall_core::ids::HostId;
use landfall_core::protocol::{
    DeployReportBody, Disposition, HOST_HEADER, MAX_BODY_BYTES, NONCE_HEADER, Nonce, NonceResponse,
    PROBLEM_CONTENT_TYPE, Problem, ProblemCode, SIGNATURE_HEADER, SigningKey, WorkRequest,
    WorkResponse, sign,
};
use landfall_core::text::shown;
use reqwest::header::CONTENT_TYPE;
use reqwest::{Client, StatusCode, Url, redirect};
use serde::Serialize;

const ENROL_PATH: &str = "/agent/v1/enrol";
const NONCE_PATH: &str = "/agent/v1/nonce";
const WORK_PATH: &str = "/agent/v1/work";
const REPORT_PATH: &str = "/agent/v1/report";

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long an idle connection is kept for another request: under the ten seconds
/// after which the controller closes one, so that a request isn't sent down a
/// connection just as it closes, as a heartbeat every ten seconds otherwise can be.
const IDLE_CONNECTION: Duration = Duration::from_secs(5);
/// A plain request: a nonce, an enrolment, a report.
pub(crate) const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// `work` is held by the controller for up to 30 seconds.
const WORK_TIMEOUT: Duration = Duration::from_secs(45);
/// The agent API's own limit on a body, which holds for what comes back too.
const BODY_CAP: usize = MAX_BODY_BYTES;

/// What the agent asks of the controller. The HTTP client is one; tests have a
/// fake.
pub trait Controller: Send + Sync {
    /// Asks for work, stating the configuration and the host's state.
    fn work(
        &self,
        request: &WorkRequest,
    ) -> impl Future<Output = Result<WorkResponse, ControllerError>> + Send;

    /// Delivers a finished report. Success is the acknowledgement.
    fn report(
        &self,
        report: &DeployReportBody,
    ) -> impl Future<Output = Result<(), ControllerError>> + Send;
}

/// A request to the controller that did not go through.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ControllerError {
    /// The HTTP client could not be built.
    #[error("cannot build the HTTP client: {0}")]
    Client(String),
    /// It did not reach the controller, or no full answer came back, as with a
    /// connection reset: a server can reset when it closes with a body unread.
    /// Always worth trying again.
    #[error("controller unreachable: {0}")]
    Transport(String),
    /// Something answered with an error status. It may not be the controller at
    /// all, so this says nothing for good.
    #[error("controller answered {status}: {detail}")]
    Status {
        /// The status.
        status: StatusCode,
        /// What it said, quoted and truncated.
        detail: String,
    },
    /// The agent API itself refused a signed request, with a code that means the
    /// same request will be refused every time.
    #[error("controller refused the request for good ({status}): {code}: {title}")]
    Rejected {
        /// The status.
        status: StatusCode,
        /// The stable code.
        code: &'static str,
        /// What it said, quoted and truncated.
        title: String,
    },
    /// It answered success with something this agent can't read.
    #[error("controller's answer is not valid: {0}")]
    BadAnswer(String),
    /// A request could not be serialised.
    #[error("cannot serialise the request: {0}")]
    Serialise(String),
}

impl ControllerError {
    /// Whether the controller has read a report and said no for good, so that
    /// sending it again can't help. Only a 4xx to the signed request itself, as
    /// the API's own problem document with a code classified final, says that. A
    /// proxy's 404 or a failed nonce says nothing about the report.
    #[must_use]
    pub fn is_rejection(&self) -> bool {
        matches!(self, Self::Rejected { .. })
    }
}

/// `error` and each of its sources, on one line: `reqwest` and others keep the
/// useful part in the source.
pub(crate) fn error_chain(error: &dyn Error) -> String {
    let mut text = error.to_string();
    let mut source = error.source();
    while let Some(cause) = source {
        // Writing to a String cannot fail.
        let _ = write!(text, ": {cause}");
        source = cause.source();
    }
    text
}

/// Why a `--controller` URL is refused. The URL itself is not repeated: it may
/// hold credentials.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum UrlError {
    /// It does not parse.
    #[error("--controller is not a URL")]
    NotAUrl,
    /// A scheme other than `https` or `http`.
    #[error("--controller must be https://")]
    Scheme,
    /// It is `http://` and the flag was not given.
    #[error(
        "--controller is http://: requests are signed but work contents are visible, so this needs --allow-insecure-controller, and a loopback or tailnet (*.ts.net) name"
    )]
    NeedsFlag,
    /// It is `http://` to a host that is neither loopback nor on a tailnet.
    #[error(
        "--controller is http:// to a host that is not loopback or a tailnet (*.ts.net) name, which --allow-insecure-controller does not cover"
    )]
    NotPrivate,
    /// It carries credentials, a path, a query or a fragment.
    #[error("--controller must be only a scheme, a host and a port")]
    NotABase,
}

/// A controller URL the transport rule allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ControllerUrl(Url);

impl ControllerUrl {
    /// Checks `text` against the transport rule: `https://`, or with
    /// `allow_insecure` also `http://` to a loopback address, `localhost` or a
    /// tailnet name (`*.ts.net`). A tailnet's addresses are not accepted: from
    /// an address alone, `100.64.0.0/10` can't be told from any other carrier's
    /// shared space.
    ///
    /// # Errors
    ///
    /// [`UrlError`] saying which part of the rule it breaks.
    pub fn parse(text: &str, allow_insecure: bool) -> Result<Self, UrlError> {
        let url = Url::parse(text).map_err(|_| UrlError::NotAUrl)?;
        match url.scheme() {
            "https" => {}
            "http" if !allow_insecure => return Err(UrlError::NeedsFlag),
            "http" => {
                if !host_is_private(&url) {
                    return Err(UrlError::NotPrivate);
                }
            }
            _ => return Err(UrlError::Scheme),
        }
        let is_base = url.username().is_empty()
            && url.password().is_none()
            && url.host_str().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none();
        if !is_base {
            return Err(UrlError::NotABase);
        }
        Ok(Self(url))
    }

    fn join(&self, path: &str) -> Url {
        let mut url = self.0.clone();
        url.set_path(path);
        url
    }

    /// Where an enrolment goes.
    pub(crate) fn enrol_url(&self) -> Url {
        self.join(ENROL_PATH)
    }

    fn is_https(&self) -> bool {
        self.0.scheme() == "https"
    }
}

/// The URL's parser has normalised the host: lowercase, an IPv4 address in its
/// dotted form whatever way it was written, an IPv6 address in brackets.
fn host_is_private(url: &Url) -> bool {
    let Some(host) = url.host_str() else {
        return false;
    };
    let bare = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return ip.is_loopback();
    }
    host == "localhost" || host.ends_with(".ts.net")
}

/// The HTTP client for a controller: no redirects, a connect timeout, and with
/// an `https` URL nothing but `https`.
pub(crate) fn http_client(url: &ControllerUrl) -> Result<Client, ControllerError> {
    // No proxy from the environment: signed requests and enrolment codes go to
    // the controller the operator named, directly.
    Client::builder()
        .no_proxy()
        .connect_timeout(CONNECT_TIMEOUT)
        .pool_idle_timeout(IDLE_CONNECTION)
        .https_only(url.is_https())
        .redirect(redirect::Policy::none())
        .user_agent(concat!("landfall-agent/", env!("CARGO_PKG_VERSION")))
        .build()
        .map_err(|error| ControllerError::Client(error_chain(&error)))
}

/// Reads a body up to [`BODY_CAP`]; a larger one is an error, not a truncation.
async fn read_capped(mut response: reqwest::Response) -> Result<Vec<u8>, ControllerError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| ControllerError::Transport(error_chain(&error)))?
    {
        if body.len() + chunk.len() > BODY_CAP {
            return Err(ControllerError::BadAnswer(format!(
                "its body is over {BODY_CAP} bytes"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

/// The body of a successful response, or the error its status means. A
/// redirect is an error status here, since the client follows none.
pub(crate) async fn answer(response: reqwest::Response) -> Result<Vec<u8>, ControllerError> {
    let status = response.status();
    if status.is_success() {
        return read_capped(response).await;
    }
    let detail = read_capped(response).await.map_or_else(
        |_| "its error could not be read".to_owned(),
        |body| shown(&String::from_utf8_lossy(&body)),
    );
    Err(ControllerError::Status { status, detail })
}

/// The API's own refusal for good, if `body` is one: a 4xx with its content type,
/// its problem document, the status repeated in it and a code classified final.
fn final_problem(status: StatusCode, is_problem: bool, body: &[u8]) -> Option<ControllerError> {
    if !status.is_client_error() || !is_problem {
        return None;
    }
    let problem: Problem = serde_json::from_slice(body).ok()?;
    let code = ProblemCode::parse(&problem.code)?;
    (problem.status == status.as_u16() && code.disposition() == Disposition::Final).then(|| {
        ControllerError::Rejected {
            status,
            code: code.as_str(),
            title: shown(&problem.title),
        }
    })
}

/// [`answer`] for the signed POST itself, the only answer that can be a refusal
/// for good.
async fn signed_answer(response: reqwest::Response) -> Result<Vec<u8>, ControllerError> {
    let status = response.status();
    if status.is_success() {
        return read_capped(response).await;
    }
    let is_problem = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case(PROBLEM_CONTENT_TYPE));
    let Ok(body) = read_capped(response).await else {
        return Err(ControllerError::Status {
            status,
            detail: "its error could not be read".to_owned(),
        });
    };
    Err(
        final_problem(status, is_problem, &body).unwrap_or_else(|| ControllerError::Status {
            status,
            detail: shown(&String::from_utf8_lossy(&body)),
        }),
    )
}

/// The agent API over HTTP, signing with the host's key. Its `Debug` is not
/// derived: nothing should print what holds the key.
pub struct HttpController {
    http: Client,
    url: ControllerUrl,
    host: HostId,
    key: SigningKey,
}

impl HttpController {
    /// A client for `url`, signing as `host` with `key`.
    ///
    /// # Errors
    ///
    /// [`ControllerError::Client`] if the HTTP client cannot be built.
    pub fn new(url: ControllerUrl, host: HostId, key: SigningKey) -> Result<Self, ControllerError> {
        Ok(Self {
            http: http_client(&url)?,
            url,
            host,
            key,
        })
    }

    /// A fresh nonce. A failure here is never about what the nonce was for.
    async fn nonce(&self) -> Result<Nonce, ControllerError> {
        let response = self
            .http
            .get(self.url.join(NONCE_PATH))
            .timeout(REQUEST_TIMEOUT)
            .send()
            .await
            .map_err(|error| ControllerError::Transport(error_chain(&error)))?;
        let body = answer(response).await?;
        serde_json::from_slice::<NonceResponse>(&body)
            .map(|answer| answer.nonce)
            .map_err(|_| {
                ControllerError::BadAnswer(format!(
                    "not a nonce: {}",
                    shown(&String::from_utf8_lossy(&body))
                ))
            })
    }

    /// A signed POST of `value` as JSON. The signature covers the very bytes
    /// sent.
    async fn post(
        &self,
        path: &str,
        value: &impl Serialize,
        timeout: Duration,
    ) -> Result<Vec<u8>, ControllerError> {
        let body = serde_json::to_vec(value)
            .map_err(|error| ControllerError::Serialise(error.to_string()))?;
        let nonce = self.nonce().await?;
        let signature = sign(&self.key, &self.host, "POST", path, &nonce, &body);
        let response = self
            .http
            .post(self.url.join(path))
            .timeout(timeout)
            .header(CONTENT_TYPE, "application/json")
            .header(HOST_HEADER, self.host.as_ref())
            .header(NONCE_HEADER, nonce.to_string())
            .header(SIGNATURE_HEADER, signature.to_string())
            .body(body)
            .send()
            .await
            .map_err(|error| ControllerError::Transport(error_chain(&error)))?;
        signed_answer(response).await
    }
}

impl Controller for HttpController {
    async fn work(&self, request: &WorkRequest) -> Result<WorkResponse, ControllerError> {
        let body = self.post(WORK_PATH, request, WORK_TIMEOUT).await?;
        serde_json::from_slice(&body)
            .map_err(|error| ControllerError::BadAnswer(shown(&error.to_string())))
    }

    async fn report(&self, report: &DeployReportBody) -> Result<(), ControllerError> {
        self.post(REPORT_PATH, report, REQUEST_TIMEOUT)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use landfall_core::protocol::{
        DeployId, DeployReportBody, Nonce, ReportedOutcome, RequestSignature, SigningKey,
        WorkRequest, verify,
    };
    use serde_json::{Value, json};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use wiremock::matchers::{method, path};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    use super::{
        Controller, ControllerError, ControllerUrl, HttpController, NonceResponse,
        PROBLEM_CONTENT_TYPE, UrlError,
    };

    const NONCE: [u8; 32] = [0xab; 32];

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[3; 32])
    }

    fn client(server: &MockServer) -> HttpController {
        let url = ControllerUrl::parse(&server.uri(), true).unwrap();
        HttpController::new(url, "home-1".parse().unwrap(), key()).unwrap()
    }

    async fn serve_nonce(server: &MockServer) {
        Mock::given(method("GET"))
            .and(path("/agent/v1/nonce"))
            .respond_with(ResponseTemplate::new(200).set_body_json(NonceResponse {
                nonce: Nonce::from_bytes(NONCE),
            }))
            .mount(server)
            .await;
    }

    fn problem(status: u16, code: &str) -> ResponseTemplate {
        let document = json!({"code": code, "title": "no", "status": status});
        ResponseTemplate::new(status).set_body_raw(document.to_string(), PROBLEM_CONTENT_TYPE)
    }

    fn request() -> WorkRequest {
        WorkRequest {
            config_hash: [5; 32],
            running: Vec::new(),
        }
    }

    fn report() -> DeployReportBody {
        DeployReportBody {
            deploy_id: DeployId(7),
            outcome: ReportedOutcome::Deployed {},
            steps: Vec::new(),
        }
    }

    #[test]
    fn http_controller_needs_the_flag() {
        for (text, flag, want) in [
            ("https://controller.example", false, Ok(())),
            ("https://controller.example", true, Ok(())),
            ("https://controller.example:8443/", false, Ok(())),
            ("http://controller.example", false, Err(UrlError::NeedsFlag)),
            ("http://127.0.0.1:8080", false, Err(UrlError::NeedsFlag)),
            ("http://localhost:8080", false, Err(UrlError::NeedsFlag)),
            (
                "http://controller.tail1234.ts.net",
                false,
                Err(UrlError::NeedsFlag),
            ),
            ("http://127.0.0.1:8080", true, Ok(())),
            ("http://[::1]:8080", true, Ok(())),
            ("http://localhost:8080", true, Ok(())),
            ("http://controller.tail1234.ts.net:8080", true, Ok(())),
            // The flag covers loopback and tailnet names, and nothing else.
            ("http://controller.example", true, Err(UrlError::NotPrivate)),
            ("http://192.0.2.1", true, Err(UrlError::NotPrivate)),
            ("http://100.100.100.100", true, Err(UrlError::NotPrivate)),
            ("http://ts.net", true, Err(UrlError::NotPrivate)),
            ("http://evil-ts.net", true, Err(UrlError::NotPrivate)),
            (
                "http://controller.ts.net.example",
                true,
                Err(UrlError::NotPrivate),
            ),
            ("http://localhost.example", true, Err(UrlError::NotPrivate)),
            ("ftp://controller.example", true, Err(UrlError::Scheme)),
            ("file:///etc/passwd", true, Err(UrlError::Scheme)),
            ("controller.example", true, Err(UrlError::NotAUrl)),
            (
                "https://user:pw@controller.example",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/prefix",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/?a=1",
                false,
                Err(UrlError::NotABase),
            ),
            (
                "https://controller.example/#a",
                false,
                Err(UrlError::NotABase),
            ),
        ] {
            assert_eq!(
                ControllerUrl::parse(text, flag).map(|_| ()),
                want,
                "{text} with flag {flag}"
            );
        }
    }

    #[test]
    fn a_refused_url_is_not_repeated() {
        let err = ControllerUrl::parse("http://user:secret@controller.example", false).unwrap_err();
        assert!(!err.to_string().contains("secret"), "{err}");
    }

    #[tokio::test]
    async fn work_is_signed_as_sent_and_the_answer_is_parsed() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/work"))
            .respond_with(
                ResponseTemplate::new(200).set_body_json(json!({"work": null, "held_back": []})),
            )
            .mount(&server)
            .await;

        let response = client(&server).work(&request()).await.unwrap();
        assert_eq!(response.work, None);

        let requests = server.received_requests().await.unwrap();
        let post = requests
            .iter()
            .find(|r| r.method.as_str() == "POST")
            .unwrap();
        let header = |name: &str| post.headers.get(name).unwrap().to_str().unwrap().to_owned();
        assert_eq!(header("landfall-host"), "home-1");
        let nonce: Nonce = header("landfall-nonce").parse().unwrap();
        assert_eq!(nonce, Nonce::from_bytes(NONCE));
        let signature: RequestSignature = header("landfall-signature").parse().unwrap();
        verify(
            &key().verifying_key(),
            &signature,
            &"home-1".parse().unwrap(),
            "POST",
            "/agent/v1/work",
            &nonce,
            &post.body,
        )
        .unwrap();
        let sent: Value = serde_json::from_slice(&post.body).unwrap();
        assert_eq!(sent["config_hash"], "05".repeat(32));
    }

    #[tokio::test]
    async fn each_request_has_its_own_nonce() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/report"))
            .respond_with(ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let client = client(&server);
        client.report(&report()).await.unwrap();
        client.report(&report()).await.unwrap();
        let nonces = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|r| r.method.as_str() == "GET")
            .count();
        assert_eq!(nonces, 2);
    }

    #[tokio::test]
    async fn a_redirect_is_not_followed() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/report"))
            .respond_with(
                ResponseTemplate::new(307).insert_header("location", "/agent/v1/elsewhere"),
            )
            .mount(&server)
            .await;

        let err = client(&server).report(&report()).await.unwrap_err();

        assert!(matches!(err, ControllerError::Status { .. }), "{err}");
        let requests = server.received_requests().await.unwrap();
        assert!(
            requests
                .iter()
                .all(|r| r.url.path() != "/agent/v1/elsewhere"),
            "the signed request went on to another path"
        );
    }

    #[tokio::test]
    async fn an_oversized_answer_is_refused() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/work"))
            .respond_with(ResponseTemplate::new(200).set_body_string("x".repeat(1024 * 1024 + 1)))
            .mount(&server)
            .await;
        let err = client(&server).work(&request()).await.unwrap_err();
        assert!(matches!(err, ControllerError::BadAnswer(_)), "{err}");
    }

    #[tokio::test]
    async fn hostile_error_text_is_quoted_and_truncated() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        let hostile = format!("line\n<2>forged{}", "x".repeat(100_000));
        Mock::given(method("POST"))
            .and(path("/agent/v1/work"))
            .respond_with(ResponseTemplate::new(500).set_body_string(hostile))
            .mount(&server)
            .await;
        let err = client(&server).work(&request()).await.unwrap_err();
        let text = err.to_string();
        assert!(!text.contains('\n'), "{text}");
        assert!(text.len() < 256, "{}", text.len());
    }

    #[tokio::test]
    async fn an_unreadable_work_answer_is_an_error_not_no_work() {
        let server = MockServer::start().await;
        serve_nonce(&server).await;
        Mock::given(method("POST"))
            .and(path("/agent/v1/work"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({"held_back": []})))
            .mount(&server)
            .await;
        let err = client(&server).work(&request()).await.unwrap_err();
        assert!(matches!(err, ControllerError::BadAnswer(_)), "{err}");
    }

    #[tokio::test]
    async fn only_the_apis_final_refusal_of_the_post_is_a_rejection() {
        // Stable codes, with a status of the API's own.
        for (template, rejected, why) in [
            (problem(404, "unknown_deploy"), true, "final"),
            (problem(403, "not_claimed"), true, "final"),
            (problem(401, "bad_signature"), true, "final"),
            (problem(400, "bad_nonce"), false, "the code says retry"),
            (problem(429, "rate_limited"), false, "the code says retry"),
            (problem(404, "made_up"), false, "not a code of the API's"),
            (problem(500, "not_claimed"), false, "not a 4xx"),
            (
                ResponseTemplate::new(404).set_body_raw(
                    json!({"code": "not_claimed", "title": "no", "status": 403}).to_string(),
                    PROBLEM_CONTENT_TYPE,
                ),
                false,
                "the document's status differs",
            ),
            (
                ResponseTemplate::new(404)
                    .set_body_json(json!({"code": "not_claimed", "title": "no", "status": 404})),
                false,
                "not the API's content type",
            ),
            (ResponseTemplate::new(404), false, "a bare 404: a proxy's"),
            (ResponseTemplate::new(403), false, "a bare 403: a proxy's"),
            (
                ResponseTemplate::new(403).set_body_raw("<html>", PROBLEM_CONTENT_TYPE),
                false,
                "not a problem document",
            ),
            (ResponseTemplate::new(503), false, "a 5xx"),
        ] {
            let server = MockServer::start().await;
            serve_nonce(&server).await;
            Mock::given(method("POST"))
                .and(path("/agent/v1/report"))
                .respond_with(template)
                .mount(&server)
                .await;
            let err = client(&server).report(&report()).await.unwrap_err();
            assert_eq!(err.is_rejection(), rejected, "{why}: {err}");
        }
    }

    #[tokio::test]
    async fn a_failed_nonce_is_never_a_rejection() {
        for template in [
            ResponseTemplate::new(404),
            ResponseTemplate::new(403),
            problem(404, "not_claimed"),
            problem(403, "bad_signature"),
            problem(400, "bad_request"),
        ] {
            let server = MockServer::start().await;
            Mock::given(method("GET"))
                .and(path("/agent/v1/nonce"))
                .respond_with(template)
                .mount(&server)
                .await;
            let err = client(&server).report(&report()).await.unwrap_err();
            assert!(!err.is_rejection(), "{err}");
            let requests = server.received_requests().await.unwrap();
            assert!(requests.iter().all(|r| r.method.as_str() == "GET"));
        }
    }

    /// Serves one nonce, then reads the start of the next request and closes with
    /// the rest of its body unread, which resets the connection.
    async fn reset_after_nonce() -> ControllerUrl {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut first, _) = listener.accept().await.unwrap();
            let mut buffer = [0_u8; 4096];
            let _ = first.read(&mut buffer).await.unwrap();
            let body = json!({"nonce": "ab".repeat(32)}).to_string();
            let answer = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            first.write_all(answer.as_bytes()).await.unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            let mut start = [0_u8; 16];
            let _ = second.read(&mut start).await;
            drop(second);
        });
        ControllerUrl::parse(&format!("http://{address}"), true).unwrap()
    }

    #[tokio::test]
    async fn a_connection_reset_on_a_request_with_a_body_can_be_retried() {
        let url = reset_after_nonce().await;
        let controller = HttpController::new(url, "home-1".parse().unwrap(), key()).unwrap();
        let big = DeployReportBody {
            outcome: ReportedOutcome::RolledBack {
                reason: "x".repeat(512 * 1024),
            },
            ..report()
        };
        let err = controller.report(&big).await.unwrap_err();
        assert!(matches!(err, ControllerError::Transport(_)), "{err}");
        assert!(!err.is_rejection(), "{err}");

        let url = reset_after_nonce().await;
        let controller = HttpController::new(url, "home-1".parse().unwrap(), key()).unwrap();
        let err = controller.work(&request()).await.unwrap_err();
        assert!(matches!(err, ControllerError::Transport(_)), "{err}");
    }

    #[tokio::test]
    async fn a_controller_that_is_down_is_a_transport_error() {
        // A port that was free a moment ago, with nothing on it now.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let url = ControllerUrl::parse(&format!("http://{address}"), true).unwrap();
        let controller = HttpController::new(url, "home-1".parse().unwrap(), key()).unwrap();
        let err = controller.work(&request()).await.unwrap_err();
        assert!(matches!(err, ControllerError::Transport(_)), "{err}");
        assert!(!err.is_rejection());
    }
}
