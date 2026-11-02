//! How long an idle connection is used again.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::TcpListener;

use super::super::{ControllerUrl, IDLE_CONNECTION, client_keeping_idle};

/// A server that keeps connections open for as long as the client does, and counts
/// them: all that can show whether the client went back to an idle one.
async fn counting_server() -> (String, Arc<AtomicUsize>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let connections = Arc::new(AtomicUsize::new(0));
    let counted = Arc::clone(&connections);
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            counted.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                let mut request = vec![0; 4096];
                while stream.read(&mut request).await.is_ok_and(|read| read > 0) {
                    let answer = b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n";
                    stream.write_all(answer).await.unwrap();
                }
            });
        }
    });
    (url, connections)
}

#[tokio::test]
async fn an_idle_connection_is_used_again_only_within_its_time() {
    let (url, connections) = counting_server().await;
    let parsed = ControllerUrl::parse(&url, true).unwrap();
    let idle = Duration::from_millis(200);
    let client = client_keeping_idle(&parsed, idle).unwrap();
    let get = async || {
        let answer = client.get(url.as_str()).send().await.unwrap();
        assert!(answer.status().is_success());
    };

    get().await;
    get().await;
    assert_eq!(connections.load(Ordering::SeqCst), 1, "within its time");

    tokio::time::sleep(idle * 2).await;
    get().await;
    assert_eq!(connections.load(Ordering::SeqCst), 2, "past its time");
}

/// Otherwise a request can go down a connection just as the controller closes it.
#[test]
fn an_idle_connection_is_let_go_before_the_controller_would() {
    let controller = landfall_server::serve::ServeOptions::default();
    assert!(IDLE_CONNECTION < controller.header_read_timeout);
}
