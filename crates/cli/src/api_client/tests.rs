//! The client against loopback servers: what it sends, what it refuses to follow, and how it
//! reads each answer.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fmt::Write as _;
use std::io;
use std::path::Path;
use std::process::Command;

use landfall_api::{Page, ProblemCode, ReleaseBrief, ReleaseStatus};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{ApiClient, ApiError, BODY_CAP, NO_BODY, deployment_path, segment};
use crate::cli::ApiArgs;
use crate::settings::{Env, Files, Settings, TokenFileError, resolve};

const TOKEN: &str = "lf_Secret-token_0123456789";

struct FakeEnv(HashMap<&'static str, OsString>);

impl Env for FakeEnv {
    fn var_os(&self, name: &str) -> Option<OsString> {
        self.0.get(name).cloned()
    }
}

/// No configuration file and no token file.
struct NoFiles;

impl Files for NoFiles {
    fn config(&self, _: &Path) -> io::Result<String> {
        Err(io::ErrorKind::NotFound.into())
    }

    fn token_file(&self, _: &Path) -> Result<Vec<u8>, TokenFileError> {
        Err(TokenFileError::Open(io::ErrorKind::NotFound.into()))
    }
}

fn settings(controller: &str, token: Option<&str>) -> Settings {
    let mut env = HashMap::from([("HOME", OsString::from("/nonexistent"))]);
    if let Some(token) = token {
        env.insert("LANDFALL_TOKEN", token.into());
    }
    let args = ApiArgs {
        controller: Some(controller.to_owned()),
        allow_insecure_controller: true,
        ..ApiArgs::default()
    };
    resolve(&args, &FakeEnv(env), &NoFiles).unwrap()
}

fn client(server: &MockServer, token: Option<&str>) -> ApiClient {
    ApiClient::new(&settings(&server.uri(), token)).unwrap()
}

fn problem(status: u16, code: &str, title: &str) -> ResponseTemplate {
    ResponseTemplate::new(status).set_body_raw(
        json!({"code": code, "title": title, "status": status}).to_string(),
        "application/problem+json",
    )
}

/// The error and every source, as `landfall` prints it, and its `Debug`.
fn everything_about(error: &ApiError) -> String {
    let mut text = format!("{error:?}\n{error}");
    let mut source = std::error::Error::source(error);
    while let Some(cause) = source {
        write!(text, "\n{cause}\n{cause:?}").unwrap();
        source = cause.source();
    }
    text
}

#[tokio::test]
async fn bearer_is_sent_when_there_is_a_token_and_not_otherwise() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"ok": true})))
        .mount(&server)
        .await;

    let answer = client(&server, Some(TOKEN))
        .get("/api/v1/me", &[])
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&answer).unwrap(),
        json!({"ok": true})
    );
    client(&server, None).get("/api/v1/me", &[]).await.unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        requests[0].headers.get("authorization").unwrap(),
        &format!("Bearer {TOKEN}")
    );
    assert!(requests[1].headers.get("authorization").is_none());
    let agent = requests[0]
        .headers
        .get("user-agent")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(agent, concat!("landfall/", env!("CARGO_PKG_VERSION")));
}

#[tokio::test]
async fn post_sends_its_body_as_json_with_the_token() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .respond_with(ResponseTemplate::new(201).set_body_json(json!({"id": 7})))
        .mount(&server)
        .await;

    let client = client(&server, Some(TOKEN));
    let answer = client
        .post(
            "/api/v1/deployments/app/prod/requests",
            Some(&json!({"tag": "v1.3.0"})),
        )
        .await
        .unwrap();
    assert_eq!(answer, r#"{"id":7}"#);
    client
        .post("/api/v1/approvals/7/cancel", NO_BODY)
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 2);
    let (ask, cancel) = (&requests[0], &requests[1]);
    assert_eq!(ask.url.path(), "/api/v1/deployments/app/prod/requests");
    assert_eq!(ask.body, br#"{"tag":"v1.3.0"}"#);
    assert_eq!(ask.headers.get("content-type").unwrap(), "application/json");
    // A call that takes no body is sent none, and says of none that it is JSON.
    assert_eq!(cancel.url.path(), "/api/v1/approvals/7/cancel");
    assert_eq!(cancel.body, Vec::<u8>::new());
    assert!(cancel.headers.get("content-type").is_none());
    for request in &requests {
        assert_eq!(request.method.as_str(), "POST");
        assert_eq!(
            request.headers.get("authorization").unwrap(),
            &format!("Bearer {TOKEN}")
        );
    }
}

#[tokio::test]
async fn a_body_that_cannot_be_written_is_its_own_error_and_sends_nothing() {
    let server = MockServer::start().await;
    // JSON keys are strings: a map keyed by pairs can't be written.
    let body = std::collections::BTreeMap::from([((1, 2), 3)]);
    let error = client(&server, Some(TOKEN))
        .post("/api/v1/approvals/7/cancel", Some(&body))
        .await
        .unwrap_err();
    assert!(matches!(error, ApiError::Body(_)), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    assert!(
        error
            .to_string()
            .starts_with("cannot write the request's body"),
        "{error}"
    );
    assert!(!everything_about(&error).contains(TOKEN));
    assert!(server.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn query_is_sent_encoded() {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/deployments"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"items": []})))
        .mount(&server)
        .await;

    client(&server, Some(TOKEN))
        .get("/api/v1/deployments", &[("limit", "10"), ("cursor", "a&b")])
        .await
        .unwrap();

    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests[0].url.query(), Some("limit=10&cursor=a%26b"));
}

#[tokio::test]
async fn redirect_is_not_followed_and_the_token_stays() {
    let elsewhere = MockServer::start().await;
    let server = MockServer::start().await;
    let location = format!("{}/stolen?from=landfall", elsewhere.uri());
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(302).insert_header("location", location.as_str()))
        .mount(&server)
        .await;

    let error = client(&server, Some(TOKEN))
        .get("/api/v1/me", &[])
        .await
        .unwrap_err();
    assert!(
        matches!(error, ApiError::Redirected { status: 302 }),
        "{error:?}"
    );
    let text = everything_about(&error);
    assert!(!text.contains(&elsewhere.uri()), "{text}");
    assert!(!text.contains("stolen"), "{text}");
    assert!(elsewhere.received_requests().await.unwrap().is_empty());
}

#[tokio::test]
async fn problem_answers_become_refused_with_their_code() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/deployments/app/prod"))
        .respond_with(problem(404, "not_found", "no such deployment"))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/hosts"))
        .respond_with(ResponseTemplate::new(503).set_body_string("<html>down</html>"))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/audit"))
        .respond_with(ResponseTemplate::new(404).set_body_string("not the API"))
        .mount(&server)
        .await;
    let client = client(&server, Some(TOKEN));

    let error = client
        .get("/api/v1/deployments/app/prod", &[])
        .await
        .unwrap_err();
    let ApiError::Refused {
        status,
        code,
        title,
    } = &error
    else {
        panic!("{error:?}");
    };
    assert_eq!(
        (*status, *code, title.as_str()),
        (404, ProblemCode::NotFound, "no such deployment")
    );
    assert_eq!(error.exit_code(), 1);
    assert!(error.to_string().contains("not_found"), "{error}");

    let error = client.get("/api/v1/hosts", &[]).await.unwrap_err();
    assert!(
        matches!(error, ApiError::Server { status: 503 }),
        "{error:?}"
    );
    assert_eq!(error.exit_code(), 2);

    // A 4xx that isn't the API's own problem document is not a refusal by the controller.
    let error = client.get("/api/v1/audit", &[]).await.unwrap_err();
    assert!(
        matches!(error, ApiError::Server { status: 404 }),
        "{error:?}"
    );
}

#[tokio::test]
async fn unauthenticated_is_401_and_says_where_the_token_came_from() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/me"))
        .respond_with(problem(401, "unauthenticated", "who are you"))
        .mount(&server)
        .await;

    let error = client(&server, Some(TOKEN))
        .get("/api/v1/me", &[])
        .await
        .unwrap_err();
    assert!(
        matches!(error, ApiError::Unauthenticated { .. }),
        "{error:?}"
    );
    assert_eq!(error.exit_code(), 2);
    assert!(error.to_string().contains("LANDFALL_TOKEN"), "{error}");

    let error = client(&server, None)
        .get("/api/v1/me", &[])
        .await
        .unwrap_err();
    let text = error.to_string();
    for place in [
        "LANDFALL_TOKEN",
        "--token-file",
        "LANDFALL_TOKEN_FILE",
        "token_file",
    ] {
        assert!(text.contains(place), "{place} missing from {text}");
    }
}

#[tokio::test]
async fn rate_limited_carries_retry_after() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/me"))
        .respond_with(problem(429, "rate_limited", "slow down").insert_header("retry-after", "7"))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/hosts"))
        .respond_with(problem(429, "rate_limited", "slow down"))
        .mount(&server)
        .await;
    let client = client(&server, Some(TOKEN));

    let error = client.get("/api/v1/me", &[]).await.unwrap_err();
    assert!(
        matches!(
            error,
            ApiError::RateLimited {
                retry_after_secs: Some(7)
            }
        ),
        "{error:?}"
    );
    assert_eq!(error.exit_code(), 2);
    assert!(error.to_string().contains('7'), "{error}");
    let error = client.get("/api/v1/hosts", &[]).await.unwrap_err();
    assert!(
        matches!(
            error,
            ApiError::RateLimited {
                retry_after_secs: None
            }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn body_over_4_mib_is_cut_off() {
    let server = MockServer::start().await;
    let big = format!("\"{}\"", "a".repeat(BODY_CAP));
    Mock::given(path("/api/v1/me"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(big, "application/json"))
        .mount(&server)
        .await;
    let just = format!("\"{}\"", "a".repeat(BODY_CAP - 2));
    Mock::given(path("/api/v1/hosts"))
        .respond_with(ResponseTemplate::new(200).set_body_raw(just, "application/json"))
        .mount(&server)
        .await;
    let client = client(&server, Some(TOKEN));

    let error = client.get("/api/v1/me", &[]).await.unwrap_err();
    assert!(matches!(error, ApiError::TooLarge), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    assert!(client.get("/api/v1/hosts", &[]).await.is_ok());
}

#[tokio::test]
async fn unknown_fields_and_values_from_a_newer_controller_are_tolerated() {
    let server = MockServer::start().await;
    Mock::given(path("/api/v1/release"))
        .respond_with(ResponseTemplate::new(200).set_body_json(
            json!({"tag": "v1.0.0", "status": "teleporting", "added_later": {"x": 1}}),
        ))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/me"))
        .respond_with(problem(409, "quantum_conflict", "new refusal"))
        .mount(&server)
        .await;
    let client = client(&server, Some(TOKEN));

    let value = client.get("/api/v1/release", &[]).await.unwrap();
    let brief: ReleaseBrief = ApiClient::typed(&value).unwrap();
    assert_eq!(brief.status, ReleaseStatus::Unknown);
    assert_eq!(brief.tag.to_string(), "v1.0.0");

    let error = client.get("/api/v1/me", &[]).await.unwrap_err();
    assert!(
        matches!(
            error,
            ApiError::Refused {
                status: 409,
                code: ProblemCode::Unknown,
                ..
            }
        ),
        "{error:?}"
    );

    // What doesn't fit the type at all is a parse error, exit 2.
    let error = ApiClient::typed::<ReleaseBrief>(&json!({"tag": 1}).to_string()).unwrap_err();
    assert!(matches!(error, ApiError::Parse { .. }), "{error:?}");
    assert_eq!(error.exit_code(), 2);
}

#[tokio::test]
async fn token_is_never_in_output_or_errors() {
    let server = MockServer::start().await;
    let elsewhere = MockServer::start().await;
    for (route, answer) in [
        ("/refused", problem(403, "forbidden", "no")),
        ("/unauthenticated", problem(401, "unauthenticated", "no")),
        (
            "/limited",
            problem(429, "rate_limited", "no").insert_header("retry-after", "1"),
        ),
        ("/server", ResponseTemplate::new(500)),
        (
            "/redirected",
            ResponseTemplate::new(307).insert_header("location", elsewhere.uri().as_str()),
        ),
        (
            "/large",
            ResponseTemplate::new(200).set_body_string("x".repeat(BODY_CAP + 1)),
        ),
        (
            "/parse",
            ResponseTemplate::new(200).set_body_string("not json"),
        ),
    ] {
        Mock::given(path(route))
            .respond_with(answer)
            .mount(&server)
            .await;
    }
    let client = client(&server, Some(TOKEN));
    let mut errors = Vec::new();
    for route in [
        "/refused",
        "/unauthenticated",
        "/limited",
        "/server",
        "/redirected",
        "/large",
        "/parse",
    ] {
        errors.push(client.get(route, &[]).await.unwrap_err());
    }

    // A connection refused, to a port nothing listens on any more, with a query that must
    // not be repeated either.
    let closed = {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        listener.local_addr().unwrap().port()
    };
    let unreachable = ApiClient::new(&settings(
        &format!("http://127.0.0.1:{closed}"),
        Some(TOKEN),
    ))
    .unwrap();
    let error = unreachable
        .get("/api/v1/me", &[("cursor", "query-secret")])
        .await
        .unwrap_err();
    assert!(matches!(error, ApiError::Network(_)), "{error:?}");
    assert_eq!(error.exit_code(), 2);
    let text = everything_about(&error);
    assert!(!text.contains("query-secret"), "{text}");
    errors.push(error);

    assert_eq!(errors.len(), 8);
    for error in &errors {
        let text = everything_about(error);
        assert!(!text.contains(TOKEN), "{text}");
    }
    let debug = format!("{:?}", settings(&server.uri(), Some(TOKEN)));
    assert!(!debug.contains(TOKEN), "{debug}");
}

/// The name of the test the child process runs.
const PROXY_CHILD: &str = "api_client::tests::proxy_child";

/// Set only in the child process: the controller's address, then the address every
/// environment proxy variable names.
const CHILD_CONTROLLER: &str = "LANDFALL_TEST_PROXY_CONTROLLER";

#[tokio::test]
async fn http_proxy_in_the_environment_is_not_used() {
    let controller = MockServer::start().await;
    Mock::given(path("/api/v1/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"direct": true})))
        .mount(&controller)
        .await;
    let proxy = MockServer::start().await;
    Mock::given(method("GET"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"proxied": true})))
        .mount(&proxy)
        .await;

    // The process environment can't be changed safely in a test, so a child process of this
    // same test binary runs with the proxies set.
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            PROXY_CHILD,
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(CHILD_CONTROLLER, controller.uri())
        .env("HTTP_PROXY", proxy.uri())
        .env("http_proxy", proxy.uri())
        .env("HTTPS_PROXY", proxy.uri())
        .env("https_proxy", proxy.uri())
        .env("ALL_PROXY", proxy.uri())
        .env("all_proxy", proxy.uri())
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed"),
        "the child ran the test: {stdout}"
    );

    // The child's control request, from a client with the default proxy settings, went
    // through the proxy: so the variables were in effect. The landfall client's did not.
    let proxied = proxy.received_requests().await.unwrap();
    assert_eq!(proxied.len(), 1, "{proxied:?}");
    assert_eq!(proxied[0].url.path(), "/control");
    assert!(proxied[0].headers.get("authorization").is_none());
    let direct = controller.received_requests().await.unwrap();
    assert_eq!(direct.len(), 1);
    assert_eq!(direct[0].url.path(), "/api/v1/me");
}

/// Runs only as the child process of `http_proxy_in_the_environment_is_not_used`.
#[tokio::test]
#[ignore = "run by http_proxy_in_the_environment_is_not_used, with proxies in its environment"]
async fn proxy_child() {
    let Some(controller) = std::env::var_os(CHILD_CONTROLLER) else {
        return;
    };
    let controller = controller.into_string().unwrap();

    let control = reqwest::Client::new()
        .get(format!("{controller}/control"))
        .send()
        .await
        .unwrap();
    let control: serde_json::Value =
        serde_json::from_slice(&control.bytes().await.unwrap()).unwrap();
    assert_eq!(
        control,
        json!({"proxied": true}),
        "the proxy variables are in effect"
    );

    let answer = ApiClient::new(&settings(&controller, Some(TOKEN)))
        .unwrap()
        .get("/api/v1/me", &[])
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&answer).unwrap(),
        json!({"direct": true})
    );
}

#[test]
fn segments_are_percent_encoded() {
    assert_eq!(segment("v1.2.3-rc.1_x~y"), "v1.2.3-rc.1_x~y");
    assert_eq!(
        segment("release/../v1?x#y%41 +"),
        "release%2F..%2Fv1%3Fx%23y%2541%20%2B"
    );
    assert_eq!(segment("é"), "%C3%A9");
    assert_eq!(
        deployment_path(&"app/prod".parse().unwrap()),
        "/api/v1/deployments/app/prod"
    );

    // The encoded tag stays one segment of the URL sent: nothing in it is a separator.
    let settings = settings("https://landfall.example.com", None);
    let path = format!(
        "{}/releases/{}",
        deployment_path(&"app/prod".parse().unwrap()),
        segment("release/../v1?x#y%41")
    );
    let url = settings.controller.join(&path);
    assert_eq!(
        url.path(),
        "/api/v1/deployments/app/prod/releases/release%2F..%2Fv1%3Fx%23y%2541"
    );
    assert_eq!(url.query(), None);
    assert_eq!(url.fragment(), None);
}

/// A parse error says where and what kind of fault, and never repeats what the controller
/// sent, which serde's own message would, at any length.
#[tokio::test]
async fn parse_errors_say_where_and_never_repeat_the_answer() {
    let big = "A".repeat(1 << 20);
    let body = json!({"items": big, "next_cursor": null}).to_string();
    let error = ApiClient::typed::<Page<ReleaseBrief>>(&body).unwrap_err();
    let text = everything_about(&error);
    assert!(text.len() < 400, "{} bytes", text.len());
    assert!(!text.contains("AAAA"), "{text}");
    assert!(
        error.to_string().starts_with(
            "the controller's answer is not one this CLI can read: not the shape this CLI reads at line 1, column "
        ),
        "{error}"
    );
    assert_eq!(error.exit_code(), 2);

    let server = MockServer::start().await;
    Mock::given(path("/api/v1/hosts"))
        .respond_with(ResponseTemplate::new(200).set_body_raw("{\n\"a\": nope", "application/json"))
        .mount(&server)
        .await;
    Mock::given(path("/api/v1/audit"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_raw(b"{\"a\":\"\xff\"}".to_vec(), "application/json"),
        )
        .mount(&server)
        .await;
    let client = client(&server, None);
    let error = client.get("/api/v1/hosts", &[]).await.unwrap_err();
    assert!(
        matches!(
            error,
            ApiError::Parse {
                problem: "not JSON",
                line: 2,
                ..
            }
        ),
        "{error:?}"
    );
    let error = client.get("/api/v1/audit", &[]).await.unwrap_err();
    assert!(
        matches!(
            error,
            ApiError::Parse {
                problem: "not UTF-8",
                line: 1,
                column: 7
            }
        ),
        "{error:?}"
    );
}
