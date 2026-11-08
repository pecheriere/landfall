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
//!   slot always turns over;
//! - not closing its end once answered, or sending on after it: the lingering close,
//!   which keeps a body nobody read from resetting the connection and losing the
//!   answer, ends after [`ServeOptions::linger_timeout`] or 64 KiB, whichever comes
//!   first.
//!
//! What one client can hold until then is bounded by the caps: the connections
//! from one source are capped, and past that a new one is closed at once and
//! logged; the total is capped, and past that they wait in the kernel's backlog.

mod linger;
mod write_deadline;

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
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

use self::linger::linger;
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
    /// How long stopping waits for requests in flight. Those still running then get no answer.
    pub drain_timeout: Duration,
    /// How long stopping then waits for those to be gone. Each goes the next time it runs, so this
    /// is only for a handler blocking its thread, on a stuck stderr say, which can't be stopped.
    /// With `TimeoutStopSec=30` in the guide, this leaves room for what stopping does after it.
    pub cut_off_timeout: Duration,
    /// How long a connection that has given its last answer waits for the client to close its
    /// end, reading and throwing away what it still sends, so that closing doesn't reset the
    /// connection and lose the answer on the way. Stopping's cut-off ends it sooner.
    pub linger_timeout: Duration,
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
            cut_off_timeout: Duration::from_secs(5),
            linger_timeout: Duration::from_secs(2),
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
/// [`ServeOptions::finish_timeout`], or until `cut_off` says to drop it. Once hyper is done with
/// it, it [lingers](linger) for up to [`ServeOptions::linger_timeout`], or until `cut_off`. The
/// peer's address reaches the routes as [`ConnectInfo`]. A failed connection is the client's
/// affair: nothing to log. What `_held` holds goes back after the connection and its handler are
/// gone, lingering included, as [`run`] goes by that.
async fn serve_connection(
    stream: TcpStream,
    peer: SocketAddr,
    app: Router,
    options: ServeOptions,
    closing: watch::Receiver<bool>,
    cut_off: watch::Receiver<bool>,
    _held: (OwnedSemaphorePermit, SourceSlot),
) {
    // Boxed, so that the connection is `Unpin`: polled through a reference, it can still give its
    // stream back when it's done.
    let service = service_fn(move |mut request: Request<Incoming>| {
        request.extensions_mut().insert(ConnectInfo(peer));
        Box::pin(app.clone().oneshot(request.map(Body::new)))
    });
    let mut connection = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(options.header_read_timeout)
        .serve_connection(
            TokioIo::new(WriteDeadline::new(stream, options.write_timeout)),
            service,
        );
    // hyper ends it as it would anyway: the answer flushed whole, then the stream shut for
    // writing. Only the closing is left for the linger. An error ends it as well: whatever hyper
    // could still send has gone.
    let ended = tokio::select! {
        result = &mut connection => {
            drop(result);
            true
        }
        () = tokio::time::sleep(options.max_connection_lifetime) => false,
        () = until_closing(closing) => false,
    };
    if !ended {
        Pin::new(&mut connection).graceful_shutdown();
        let finished = tokio::select! {
            finished = tokio::time::timeout(options.finish_timeout, &mut connection) => {
                finished.is_ok()
            }
            () = until_closing(cut_off.clone()) => false,
        };
        if !finished {
            return;
        }
    }
    let stream = connection.into_parts().io.into_inner();
    tokio::select! {
        () = linger(stream, options.linger_timeout) => {}
        () = until_closing(cut_off) => {}
    }
}

/// Serves `app` on `listener` until `shutdown` completes, then lets requests in
/// flight finish for up to [`ServeOptions::drain_timeout`], and drops what's left of them. No
/// handler is running when this returns, so what the caller does next is the last word: nothing
/// can count a failure after it has written the counts down. The exception is what this gives: how
/// many connections were still there after [`ServeOptions::cut_off_timeout`], each with a handler
/// blocking its thread, and able to count something if it ever comes back.
///
/// Failing to accept one connection is no reason to stop serving the others, so
/// it is logged and retried.
pub async fn run(
    listener: TcpListener,
    app: Router,
    options: ServeOptions,
    shutdown: impl Future<Output = ()>,
) -> usize {
    let permits = options.max_connections;
    let total = usize::try_from(permits).unwrap_or(usize::MAX);
    let connections = Arc::new(Semaphore::new(total));
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
    let gone = tokio::time::timeout(options.cut_off_timeout, connections.acquire_many(permits));
    match gone.await {
        Ok(_) => 0,
        Err(_) => total.saturating_sub(connections.available_permits()),
    }
}

#[cfg(test)]
mod tests;
