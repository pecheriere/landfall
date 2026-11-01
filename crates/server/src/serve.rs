//! Serving the routes over TCP, with the limits a hostile client calls for.
//!
//! `axum::serve` cannot set a timeout on reading a request's headers, so this is
//! a small accept loop over `hyper` instead. A client that connects and sends
//! nothing, or stops halfway through its headers, is dropped after
//! [`ServeOptions::header_read_timeout`], which also ends idle keep-alive
//! connections. Once the headers are in, the routes' own deadlines apply. The
//! number of connections is capped: past that they wait in the kernel's backlog.

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::Request;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tower::ServiceExt as _;

/// How long to wait before accepting again after `accept` itself failed, as it
/// does when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The server's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeOptions {
    /// How long a client has to send a request's headers, and how long an idle
    /// connection stays open.
    pub header_read_timeout: Duration,
    /// How many connections are served at once.
    pub max_connections: u32,
    /// How long stopping waits for requests in flight.
    pub drain_timeout: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            max_connections: 1024,
            drain_timeout: Duration::from_secs(5),
        }
    }
}

/// Ends when `closing` says so, or when nobody is left to say it.
async fn until_closing(mut closing: watch::Receiver<bool>) {
    drop(closing.wait_for(|closing| *closing).await);
}

/// Serves one connection until it ends, or until `closing` says to finish what
/// it is doing and stop. The peer's address reaches the routes as
/// [`ConnectInfo`]. A failed connection is the client's affair: nothing to log.
async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    options: ServeOptions,
    closing: watch::Receiver<bool>,
    permit: OwnedSemaphorePermit,
) {
    let service = service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        app.clone().oneshot(request.map(Body::new))
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout)
        .serve_connection(TokioIo::new(stream), service);
    tokio::pin!(connection);
    tokio::select! {
        result = connection.as_mut() => drop(result),
        () = until_closing(closing) => {
            connection.as_mut().graceful_shutdown();
            drop(connection.await);
        }
    }
    drop(permit);
}

/// Serves `app` on `listener` until `shutdown` completes, then lets requests in
/// flight finish for up to [`ServeOptions::drain_timeout`].
/// Failing to accept one connection is no reason to stop serving the others, so
/// it is logged and retried.
pub async fn run(
    listener: TcpListener,
    app: Router,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) {
    let permits = options.max_connections;
    let connections = Arc::new(Semaphore::new(
        usize::try_from(permits).unwrap_or(usize::MAX),
    ));
    let (closing, closing_rx) = watch::channel(false);
    tokio::pin!(shutdown);
    loop {
        let permit = tokio::select! {
            () = &mut shutdown => break,
            permit = connections.clone().acquire_owned() => permit,
        };
        // The semaphore is never closed, so this does not happen.
        let Ok(permit) = permit else { break };
        let accepted = tokio::select! {
            () = &mut shutdown => break,
            accepted = listener.accept() => accepted,
        };
        match accepted {
            Ok((stream, peer)) => {
                tokio::spawn(serve_connection(
                    stream,
                    peer,
                    app.clone(),
                    options,
                    closing_rx.clone(),
                    permit,
                ));
            }
            Err(error) => {
                crate::agent_api::log(&format!("cannot accept a connection: {error}"));
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
    drop(listener);
    closing.send_replace(true);
    // Every permit back means every connection is done.
    drop(tokio::time::timeout(options.drain_timeout, connections.acquire_many(permits)).await);
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;
    use std::time::Instant;

    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio::sync::oneshot;
    use tokio::task::JoinHandle;

    use super::*;

    const REQUEST: &[u8] = b"GET /peer HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";

    async fn peer(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    async fn slow() -> &'static str {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "done"
    }

    struct Server {
        addr: SocketAddr,
        stop: oneshot::Sender<()>,
        task: JoinHandle<()>,
    }

    async fn start(options: ServeOptions) -> Server {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = Router::new()
            .route("/peer", get(peer))
            .route("/slow", get(slow))
            .route("/hang", get(std::future::pending::<()>));
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(run(listener, app, options, async {
            drop(stopped.await);
        }));
        Server { addr, stop, task }
    }

    fn options() -> ServeOptions {
        ServeOptions {
            header_read_timeout: Duration::from_millis(100),
            ..ServeOptions::default()
        }
    }

    /// Reads until the server closes the connection; panics if it does not do
    /// so soon.
    async fn read_to_close(stream: &mut TcpStream) -> String {
        let mut out = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), stream.read_to_end(&mut out))
            .await
            .expect("the server should close the connection")
            .unwrap();
        String::from_utf8(out).unwrap()
    }

    #[tokio::test]
    async fn a_request_is_served_and_sees_its_peer() {
        let server = start(options()).await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream.write_all(REQUEST).await.unwrap();
        let answer = read_to_close(&mut stream).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(answer.ends_with("127.0.0.1"), "{answer}");
    }

    #[tokio::test]
    async fn a_client_that_stops_mid_headers_is_dropped() {
        let server = start(options()).await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream.write_all(b"GET /peer HTTP/1.1\r\nHo").await.unwrap();
        let started = Instant::now();
        read_to_close(&mut stream).await;
        assert!(started.elapsed() >= Duration::from_millis(50));
    }

    #[tokio::test]
    async fn a_client_that_sends_nothing_is_dropped() {
        let server = start(options()).await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        let answer = read_to_close(&mut stream).await;
        assert_eq!(answer, "");
    }

    #[tokio::test]
    async fn an_idle_keep_alive_connection_is_dropped() {
        let server = start(options()).await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(b"GET /peer HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let answer = read_to_close(&mut stream).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }

    #[tokio::test]
    async fn connections_past_the_cap_wait_their_turn() {
        let server = start(ServeOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_millis(300),
            ..ServeOptions::default()
        })
        .await;
        // This one takes the only place, sending nothing.
        let mut first = TcpStream::connect(server.addr).await.unwrap();
        // The kernel accepts this one, but nothing serves it until the first
        // is dropped for its silence.
        let mut second = TcpStream::connect(server.addr).await.unwrap();
        second.write_all(REQUEST).await.unwrap();
        let started = Instant::now();
        let answer = read_to_close(&mut second).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(started.elapsed() >= Duration::from_millis(200));
        read_to_close(&mut first).await;
    }

    #[tokio::test]
    async fn stopping_lets_a_request_in_flight_finish() {
        let server = start(options()).await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        server.stop.send(()).unwrap();

        let answer = read_to_close(&mut stream).await;
        assert!(answer.ends_with("done"), "{answer}");
        server.task.await.unwrap();
    }

    #[tokio::test]
    async fn stopping_does_not_wait_forever_for_a_client() {
        let server = start(ServeOptions {
            drain_timeout: Duration::from_millis(100),
            ..ServeOptions::default()
        })
        .await;
        // A request that will never finish.
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(
                b"GET /hang HTTP/1.1
Host: test

",
            )
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        server.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server.task)
            .await
            .expect("stopping should not hang")
            .unwrap();
    }
}
