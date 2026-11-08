//! The accept loop and its limits, over real TCP.

use std::net::Ipv4Addr;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::extract::ConnectInfo;
use axum::routing::{get, post};
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

/// Answers without reading the body it was sent.
async fn ignores() -> &'static str {
    "answered"
}

/// More than the socket buffers at both ends can hold.
const BIG: usize = 32 * 1024 * 1024;

async fn big() -> Vec<u8> {
    vec![b'x'; BIG]
}

struct Server {
    addr: SocketAddr,
    stop: oneshot::Sender<()>,
    task: JoinHandle<usize>,
}

async fn start(options: ServeOptions) -> Server {
    let app = Router::new()
        .route("/peer", get(peer))
        .route("/slow", get(slow))
        .route("/big", get(big))
        .route("/hang", get(std::future::pending::<()>))
        .route("/ignores", post(ignores));
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

/// The headers of a POST to `/ignores` whose two bytes of body haven't been sent.
const IGNORED_HEADERS: &[u8] =
    b"POST /ignores HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: 2\r\n\r\n";

/// Sends the headers of a request whose body the route never reads, waits for the answer to be
/// there, and only then sends the body.
async fn answered_before_its_body(server: &Server) -> TcpStream {
    let mut stream = TcpStream::connect(server.addr).await.unwrap();
    stream.write_all(IGNORED_HEADERS).await.unwrap();
    let mut byte = [0];
    stream.peek(&mut byte).await.unwrap();
    stream.write_all(b"{}").await.unwrap();
    stream
}

/// A body nobody read, arriving after the answer, would make closing reset the connection, and
/// the reset throws away an answer the client hasn't read yet. The connection lingers for it
/// instead.
#[tokio::test]
async fn an_answer_sent_before_its_body_arrives_is_not_lost() {
    let server = start(options()).await;
    let mut stream = answered_before_its_body(&server).await;
    // Time for a reset to come back, if one is coming, before the answer is read.
    tokio::time::sleep(Duration::from_millis(100)).await;
    let answer = read_to_close(&mut stream).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(answer.ends_with("answered"), "{answer}");
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

/// `app` served with short limits on stopping, with a request to `/hang` running, which told
/// `running` so.
async fn hanging(app: Router, running: &Notify) -> Hanging {
    let server = serving(
        app,
        ServeOptions {
            drain_timeout: Duration::from_millis(100),
            cut_off_timeout: Duration::from_secs(2),
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
    Hanging {
        stop: server.stop,
        task: server.task,
        _stream: stream,
    }
}

/// A server with a request running, whose connection stays open for as long as this does.
struct Hanging {
    stop: oneshot::Sender<()>,
    task: JoinHandle<usize>,
    _stream: TcpStream,
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

/// On real worker threads, where a connection's task is still dropping its handler while
/// `run` goes on, unless it waits.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_waits_for_a_handler_to_be_gone() {
    struct SlowToGo(Arc<AtomicBool>);
    impl Drop for SlowToGo {
        fn drop(&mut self) {
            std::thread::sleep(Duration::from_millis(300));
            self.0.store(true, Ordering::SeqCst);
        }
    }
    let gone = Arc::new(AtomicBool::new(false));
    let running = Arc::new(Notify::new());
    let (told, flag) = (Arc::clone(&running), Arc::clone(&gone));
    let hang = move || async move {
        let guard = SlowToGo(flag);
        told.notify_one();
        std::future::pending::<()>().await;
        drop(guard);
    };
    let server = hanging(Router::new().route("/hang", get(hang)), &running).await;

    server.stop.send(()).unwrap();

    assert_eq!(server.task.await.unwrap(), 0);
    assert!(
        gone.load(Ordering::SeqCst),
        "it returned with it still there"
    );
}

/// A handler that can't be cut off, as it never gives its thread back: it can't hold up
/// stopping past the limit, and `run` says it's there.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_handler_blocking_its_thread_holds_up_stopping_only_so_long() {
    let (release, blocked) = std::sync::mpsc::channel::<()>();
    let blocked = Arc::new(Mutex::new(blocked));
    let running = Arc::new(Notify::new());
    let told = Arc::clone(&running);
    let hang = move || async move {
        told.notify_one();
        let _ = blocked.lock().unwrap().recv();
    };
    let server = hanging(Router::new().route("/hang", get(hang)), &running).await;

    server.stop.send(()).unwrap();

    // Blocked until after this, so this returning at all is the point.
    let left = tokio::time::timeout(Duration::from_secs(60), server.task)
        .await
        .expect("it waited for the handler")
        .unwrap();
    assert_eq!(left, 1);
    drop(release);
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

/// A client that keeps sending after its answer, and never closes, holds its place only for the
/// linger: the next connection waits that long, and no longer.
#[tokio::test]
async fn a_lingering_connection_gives_its_place_back() {
    let linger = Duration::from_millis(300);
    let server = start(ServeOptions {
        max_connections: 1,
        linger_timeout: linger,
        ..options()
    })
    .await;
    let mut first = answered_before_its_body(&server).await;
    let answer = read_to_close(&mut first).await;
    assert!(answer.ends_with("answered"), "{answer}");
    let started = Instant::now();
    let sending = tokio::spawn(async move {
        while first.write_all(b"more").await.is_ok() {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    });

    let mut second = TcpStream::connect(server.addr).await.unwrap();
    second.write_all(REQUEST).await.unwrap();
    let answer = read_to_close(&mut second).await;
    assert!(answer.starts_with("HTTP/1.1 200"), "{answer}");
    assert!(started.elapsed() >= linger / 2, "{:?}", started.elapsed());
    sending.abort();
}

/// Stopping doesn't wait out a lingering connection: it goes with the cut-off, whatever is left of
/// its linger, and isn't counted as a handler left running.
#[tokio::test]
async fn stopping_cuts_a_lingering_connection_off() {
    let server = start(ServeOptions {
        drain_timeout: Duration::from_millis(100),
        linger_timeout: Duration::from_mins(10),
        ..options()
    })
    .await;
    let mut stream = answered_before_its_body(&server).await;
    let answer = read_to_close(&mut stream).await;
    assert!(answer.ends_with("answered"), "{answer}");

    // The client holds its end open, so the connection lingers.
    server.stop.send(()).unwrap();
    let left = tokio::time::timeout(Duration::from_secs(5), server.task)
        .await
        .expect("stopping should not wait out the linger")
        .unwrap();
    assert_eq!(left, 0);
    drop(stream);
}
