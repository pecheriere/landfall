//! Serving the routes over TCP, with the limits a hostile client calls for.
//!
//! `axum::serve` cannot set a timeout on reading a request's headers, so this is
//! a small accept loop over `hyper` instead. Each way a client can hold a
//! connection has its own limit:
//!
//! - sending nothing, stopping halfway through its headers, or idling on a
//!   keep-alive connection: dropped after [`ServeOptions::header_read_timeout`];
//! - sending a body slowly, or a handler running long: the routes' own deadlines;
//! - not reading what it is sent: dropped once a write has made no progress for
//!   [`ServeOptions::write_timeout`];
//! - reading just fast enough to make progress, or sending one small request after
//!   another: none of the above applies, and these need no key. So every
//!   connection has [`ServeOptions::max_connection_lifetime`]: at that age it ends
//!   between requests, and a request in flight then has
//!   [`ServeOptions::finish_timeout`] before the connection is dropped anyway. A
//!   slot always turns over.
//!
//! What one client can hold until then is bounded by the caps: the connections
//! from one source are capped, and past that a new one is closed at once and
//! logged; the total is capped, and past that they wait in the kernel's backlog.

mod write_deadline;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

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

use self::write_deadline::WriteDeadline;
use crate::agent_api::{RefusalLog, log, source_key};

/// How long to wait before accepting again after `accept` itself failed, as it
/// does when the process is out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// The server's limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ServeOptions {
    /// How long a client has to send a request's headers, and how long an idle
    /// connection stays open.
    pub header_read_timeout: Duration,
    /// How long a write may make no progress before the client is dropped.
    pub write_timeout: Duration,
    /// How long a connection is kept. Longer than a long poll, so that an agent
    /// is not interrupted by it; a client just reconnects.
    pub max_connection_lifetime: Duration,
    /// How long a request in flight has to finish once its connection is past
    /// its lifetime or the server is stopping. Longer than any request may take,
    /// so that only a client holding on to its answer is cut off.
    pub finish_timeout: Duration,
    /// How many connections are served at once.
    pub max_connections: u32,
    /// How many of those one source may hold: a small share, so that one source
    /// cannot take the rest. Behind a proxy all agents are one source, and this
    /// needs raising: see `docs/operations.md`.
    pub max_connections_per_source: u32,
    /// How long stopping waits for requests in flight.
    pub drain_timeout: Duration,
}

impl Default for ServeOptions {
    fn default() -> Self {
        Self {
            header_read_timeout: Duration::from_secs(10),
            write_timeout: Duration::from_secs(10),
            max_connection_lifetime: Duration::from_secs(120),
            // The agent API's request deadline is 45 seconds.
            finish_timeout: Duration::from_secs(50),
            max_connections: 1024,
            max_connections_per_source: 32,
            drain_timeout: Duration::from_secs(5),
        }
    }
}

/// Live connections per source. Entries exist only for live connections, so it
/// is bounded by [`ServeOptions::max_connections`].
type SourceCounts = Arc<Mutex<HashMap<IpAddr, u32>>>;

/// One source's claim on a connection, given back when dropped.
#[derive(Debug)]
struct SourceSlot {
    counts: SourceCounts,
    source: IpAddr,
}

impl SourceSlot {
    /// A slot for `peer`, or `None` if it holds all it may.
    fn take(counts: &SourceCounts, peer: IpAddr, max: u32) -> Option<Self> {
        let source = source_key(peer);
        let mut locked = counts.lock().unwrap_or_else(PoisonError::into_inner);
        let count = locked.entry(source).or_insert(0);
        if *count >= max {
            return None;
        }
        *count += 1;
        Some(Self {
            counts: Arc::clone(counts),
            source,
        })
    }
}

impl Drop for SourceSlot {
    fn drop(&mut self) {
        let mut locked = self.counts.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(count) = locked.get_mut(&self.source) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                locked.remove(&self.source);
            }
        }
    }
}

/// Ends when `closing` says so, or when nobody is left to say it.
async fn until_closing(mut closing: watch::Receiver<bool>) {
    drop(closing.wait_for(|closing| *closing).await);
}

/// Serves one connection until it ends, or until it reaches its lifetime or
/// `closing` says to stop: then it finishes what it is doing, for up to
/// [`ServeOptions::finish_timeout`], or until `cut_off` says to drop it. The peer's address
/// reaches the routes as [`ConnectInfo`]. A failed connection is the client's affair: nothing to
/// log. What `_held` holds goes back after the connection and its handler are gone, as
/// [`run`] goes by that.
async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    options: ServeOptions,
    closing: watch::Receiver<bool>,
    cut_off: watch::Receiver<bool>,
    _held: (OwnedSemaphorePermit, SourceSlot),
) {
    let service = service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        app.clone().oneshot(request.map(Body::new))
    });
    let connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout)
        .serve_connection(
            TokioIo::new(WriteDeadline::new(stream, options.write_timeout)),
            service,
        );
    tokio::pin!(connection);
    let ended = tokio::select! {
        result = connection.as_mut() => {
            drop(result);
            true
        }
        () = tokio::time::sleep(options.max_connection_lifetime) => false,
        () = until_closing(closing) => false,
    };
    if !ended {
        connection.as_mut().graceful_shutdown();
        tokio::select! {
            finished = tokio::time::timeout(options.finish_timeout, connection) => drop(finished),
            () = until_closing(cut_off) => {}
        }
    }
}

/// Serves `app` on `listener` until `shutdown` completes, then lets requests in
/// flight finish for up to [`ServeOptions::drain_timeout`], and drops what's left of them. No
/// handler is running when this returns, so what the caller does next is the last word: nothing
/// can count a failure after it has written the counts down.
///
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
    let (cut_off, cut_off_rx) = watch::channel(false);
    let sources = SourceCounts::default();
    let refusals = RefusalLog::default();
    let started = Instant::now();
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
                // Over its cap the source's connection closes here, unserved,
                // and the place goes back with the permit.
                let slot =
                    SourceSlot::take(&sources, peer.ip(), options.max_connections_per_source);
                if let Some(slot) = slot {
                    tokio::spawn(serve_connection(
                        stream,
                        peer,
                        app.clone(),
                        options,
                        closing_rx.clone(),
                        cut_off_rx.clone(),
                        (permit, slot),
                    ));
                } else {
                    let now = i64::try_from(started.elapsed().as_secs()).unwrap_or(i64::MAX);
                    let line = format!(
                        "refused a connection from {}: it holds the {} that one source may \
                         (--max-connections-per-source; behind a proxy all clients are one source)",
                        source_key(peer.ip()),
                        options.max_connections_per_source,
                    );
                    refusals.note(now, &line);
                }
            }
            Err(error) => {
                log(&format!("cannot accept a connection: {error}"));
                tokio::time::sleep(ACCEPT_BACKOFF).await;
            }
        }
    }
    drop(listener);
    closing.send_replace(true);
    // Every permit back means every connection is done.
    drop(tokio::time::timeout(options.drain_timeout, connections.acquire_many(permits)).await);
    cut_off.send_replace(true);
    // Without a limit: each drops what it's doing the next time it runs, and no handler blocks.
    drop(connections.acquire_many(permits).await);
}

#[cfg(test)]
mod tests {
    use std::net::Ipv4Addr;

    use axum::extract::ConnectInfo;
    use axum::routing::get;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    use tokio::net::TcpStream;
    use tokio::sync::{Notify, oneshot};
    use tokio::task::JoinHandle;

    use super::{
        Arc, Duration, Instant, IpAddr, Router, ServeOptions, SocketAddr, SourceCounts, SourceSlot,
        TcpListener, run,
    };

    const REQUEST: &[u8] = b"GET /peer HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n";

    async fn peer(ConnectInfo(peer): ConnectInfo<SocketAddr>) -> String {
        peer.ip().to_string()
    }

    async fn slow() -> &'static str {
        tokio::time::sleep(Duration::from_millis(200)).await;
        "done"
    }

    /// More than the socket buffers at both ends can hold.
    const BIG: usize = 32 * 1024 * 1024;

    async fn big() -> Vec<u8> {
        vec![b'x'; BIG]
    }

    struct Server {
        addr: SocketAddr,
        stop: oneshot::Sender<()>,
        task: JoinHandle<()>,
    }

    async fn start(options: ServeOptions) -> Server {
        let app = Router::new()
            .route("/peer", get(peer))
            .route("/slow", get(slow))
            .route("/big", get(big))
            .route("/hang", get(std::future::pending::<()>));
        serving(app, options).await
    }

    async fn serving(app: Router, options: ServeOptions) -> Server {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
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
    async fn an_idle_connection_kept_open_is_dropped() {
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
            header_read_timeout: Duration::from_secs(1),
            ..ServeOptions::default()
        })
        .await;
        // This one takes the only place, sending nothing.
        let mut first = TcpStream::connect(server.addr).await.unwrap();
        // The kernel accepts this one, but nothing serves it until the first
        // is dropped for its silence.
        let mut second = TcpStream::connect(server.addr).await.unwrap();
        let started = Instant::now();
        second.write_all(REQUEST).await.unwrap();
        let answer = read_to_close(&mut second).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(started.elapsed() >= Duration::from_millis(500));
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
            .write_all(b"GET /hang HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        server.stop.send(()).unwrap();
        tokio::time::timeout(Duration::from_secs(5), server.task)
            .await
            .expect("stopping should not hang")
            .unwrap();
    }

    /// What the server does last as it stops goes by this: a handler still running could count
    /// something after the last time the counts are written down, and answer as if it had been.
    #[tokio::test]
    async fn no_handler_runs_on_once_stopping_is_over() {
        let running = Arc::new(Notify::new());
        let alive = Arc::new(());
        let (told, held) = (Arc::clone(&running), Arc::clone(&alive));
        let hang = move || async move {
            told.notify_one();
            std::future::pending::<()>().await;
            drop(held);
        };
        let app = Router::new().route("/hang", get(hang));
        let server = serving(
            app,
            ServeOptions {
                drain_timeout: Duration::from_millis(100),
                ..ServeOptions::default()
            },
        )
        .await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(b"GET /hang HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        running.notified().await;

        server.stop.send(()).unwrap();
        server.task.await.unwrap();

        assert_eq!(Arc::strong_count(&alive), 1, "a handler is still running");
        assert_eq!(read_to_close(&mut stream).await, "", "it answers nothing");
    }

    /// The only slot goes to a client that asks for more than the socket buffers
    /// hold and never reads it. Its write stops making progress, it is dropped,
    /// and the next client is served. The headers are long since in, so the
    /// header timeout has nothing to say about this, and it is set far away.
    #[tokio::test]
    async fn a_client_that_never_reads_does_not_keep_its_slot() {
        let server = start(ServeOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_millis(200),
            ..ServeOptions::default()
        })
        .await;
        let mut stuck = TcpStream::connect(server.addr).await.unwrap();
        stuck
            .write_all(b"GET /big HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        // The start of its answer has arrived, so it is being served and holds
        // the slot. It reads no more of it than this.
        stuck.read_exact(&mut [0; 12]).await.unwrap();

        let mut next = TcpStream::connect(server.addr).await.unwrap();
        next.write_all(REQUEST).await.unwrap();
        let answer = read_to_close(&mut next).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        // The slot came free because this one was cut off: it does not get it all.
        assert!(read_what_is_left(&mut stuck).await < BIG);
    }

    /// The only slot goes to a client that never stops reading, but so slowly that
    /// its answer would take most of a minute. The next client still gets the slot,
    /// once the connection's lifetime and the time to finish have passed.
    #[tokio::test]
    async fn a_client_that_trickles_does_not_keep_its_slot() {
        let server = start(ServeOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_secs(60),
            write_timeout: Duration::from_secs(60),
            max_connection_lifetime: Duration::from_millis(200),
            finish_timeout: Duration::from_millis(200),
            ..ServeOptions::default()
        })
        .await;
        let mut trickling = TcpStream::connect(server.addr).await.unwrap();
        trickling
            .write_all(b"GET /big HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        trickling.read_exact(&mut [0; 12]).await.unwrap();
        let reader = tokio::spawn(async move {
            let mut buffer = vec![0; 64 * 1024];
            loop {
                match trickling.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(_) => tokio::time::sleep(Duration::from_millis(100)).await,
                }
            }
        });

        let mut next = TcpStream::connect(server.addr).await.unwrap();
        next.write_all(REQUEST).await.unwrap();
        let answer = read_to_close(&mut next).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        reader.abort();
    }

    /// The only slot goes to a client sending one small request after another,
    /// each answered, so it is never idle. The next client still gets the slot, and
    /// the first sees its connection end between requests: every answer whole.
    #[tokio::test]
    async fn a_stream_of_small_requests_does_not_keep_its_slot() {
        let server = start(ServeOptions {
            max_connections: 1,
            header_read_timeout: Duration::from_secs(60),
            max_connection_lifetime: Duration::from_millis(500),
            ..ServeOptions::default()
        })
        .await;
        let mut busy = TcpStream::connect(server.addr).await.unwrap();
        // The first answer proves it holds the slot.
        assert!(keep_alive_exchange(&mut busy).await);
        let client = tokio::spawn(async move {
            let mut answered = 1;
            while keep_alive_exchange(&mut busy).await {
                answered += 1;
                tokio::time::sleep(Duration::from_millis(150)).await;
            }
            answered
        });

        let mut next = TcpStream::connect(server.addr).await.unwrap();
        next.write_all(REQUEST).await.unwrap();
        let answer = read_to_close(&mut next).await;
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
        assert!(client.await.unwrap() >= 1);
    }

    /// One request and its whole answer on a kept-alive connection, or `false` if
    /// the connection has ended. An answer cut short panics.
    async fn keep_alive_exchange(stream: &mut TcpStream) -> bool {
        let request = b"GET /peer HTTP/1.1\r\nHost: test\r\n\r\n";
        if stream.write_all(request).await.is_err() {
            return false;
        }
        let mut answer = Vec::new();
        let mut buffer = [0; 1024];
        while !answer.ends_with(b"127.0.0.1") {
            match stream.read(&mut buffer).await {
                Ok(0) | Err(_) => {
                    let text = String::from_utf8_lossy(&answer);
                    assert!(answer.is_empty(), "an answer was cut short: {text}");
                    return false;
                }
                Ok(count) => answer.extend_from_slice(&buffer[..count]),
            }
        }
        true
    }

    /// A request running when the connection reaches its lifetime is not cut off.
    #[tokio::test]
    async fn a_request_in_flight_finishes_past_the_lifetime() {
        let server = start(ServeOptions {
            max_connection_lifetime: Duration::from_millis(50),
            ..options()
        })
        .await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(b"GET /slow HTTP/1.1\r\nHost: test\r\n\r\n")
            .await
            .unwrap();
        let answer = read_to_close(&mut stream).await;
        assert!(answer.ends_with("done"), "{answer}");
    }

    /// How much more arrives before the connection ends, by close or reset.
    async fn read_what_is_left(stream: &mut TcpStream) -> usize {
        let mut total = 0;
        let mut buffer = vec![0; 64 * 1024];
        loop {
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buffer));
            match read.await.expect("the server should end the connection") {
                Ok(0) | Err(_) => return total,
                Ok(count) => total += count,
            }
        }
    }

    /// A client that keeps reading, however slowly it starts, gets all of it:
    /// the deadline is on progress, not on the whole answer.
    #[tokio::test]
    async fn a_client_that_reads_keeps_its_connection() {
        let server = start(ServeOptions {
            write_timeout: Duration::from_secs(2),
            ..options()
        })
        .await;
        let mut stream = TcpStream::connect(server.addr).await.unwrap();
        stream
            .write_all(b"GET /big HTTP/1.1\r\nHost: test\r\nConnection: close\r\n\r\n")
            .await
            .unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        let mut got = Vec::new();
        tokio::time::timeout(Duration::from_secs(30), stream.read_to_end(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert!(got.len() >= BIG, "{}", got.len());
    }

    #[tokio::test]
    async fn one_source_cannot_take_every_connection() {
        let server = start(ServeOptions {
            header_read_timeout: Duration::from_secs(60),
            max_connections_per_source: 1,
            ..ServeOptions::default()
        })
        .await;
        // Accepted in order, so this one has the place.
        let held = TcpStream::connect(server.addr).await.unwrap();

        // Closed at once, long before any timeout could do it.
        let mut over = TcpStream::connect(server.addr).await.unwrap();
        assert_eq!(read_to_close(&mut over).await, "");

        // When the first goes, its place is free again. How soon the server
        // notices is its business, so this tries for a while.
        drop(held);
        let mut answer = String::new();
        for _ in 0..50 {
            tokio::time::sleep(Duration::from_millis(50)).await;
            let mut again = TcpStream::connect(server.addr).await.unwrap();
            if again.write_all(REQUEST).await.is_ok() {
                let mut got = Vec::new();
                if again.read_to_end(&mut got).await.is_ok() && !got.is_empty() {
                    answer = String::from_utf8(got).unwrap();
                    break;
                }
            }
        }
        assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    }

    #[test]
    fn a_source_slot_is_given_back_and_leaves_nothing_behind() {
        let counts = SourceCounts::default();
        let ip: IpAddr = "192.0.2.1".parse().unwrap();
        let mapped: IpAddr = "::ffff:192.0.2.1".parse().unwrap();
        let first = SourceSlot::take(&counts, ip, 2).unwrap();
        let second = SourceSlot::take(&counts, mapped, 2).unwrap();
        assert!(SourceSlot::take(&counts, ip, 2).is_none());
        drop((first, second));
        assert!(counts.lock().unwrap().is_empty());
    }
}
