//! Connections that break.

use landfall_core::protocol::{DeployReportBody, ReportedOutcome};
use serde_json::json;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

use super::super::{Controller, ControllerError, ControllerUrl, HttpController};
use super::{key, report, request};

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
