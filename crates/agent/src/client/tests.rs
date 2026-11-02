//! The signing client against a mock controller.

use landfall_core::protocol::{
    DeployId, DeployReportBody, Nonce, ReportedOutcome, SigningKey, WorkRequest,
};
use landfall_core::protocol::{NonceResponse, PROBLEM_CONTENT_TYPE};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::{ControllerUrl, HttpController};

mod connections;
mod requests;
mod transport;

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
        deployment: "app/prod".parse().unwrap(),
        tag: "v1.2.5".parse().unwrap(),
        digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
        outcome: ReportedOutcome::Deployed {},
        steps: Vec::new(),
    }
}
