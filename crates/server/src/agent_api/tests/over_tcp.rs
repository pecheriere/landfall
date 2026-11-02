//! The real router behind the real accept loop, over real TCP, with a file-backed
//! store: what `landfall-server serve` runs.

use std::fmt::Write as _;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use landfall_core::protocol::{
    self, EnrolRequest, HOST_HEADER, MAX_BODY_BYTES, NONCE_HEADER, Nonce, NonceResponse, Problem,
    SIGNATURE_HEADER, SigningKey, WorkRequest, WorkResponse,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::oneshot;

use super::{ENROL, NONCE, REPORT, WORK, deployed_report, host, signing_key, test_limits};
use crate::agent_api::{ApiState, Limits};
use crate::serve::{self, ServeOptions};
use crate::store::{NewDeploy, Store};

const HOST: &str = "host-a";

/// One HTTP/1.1 exchange on its own connection: the status and the body.
async fn exchange(
    addr: SocketAddr,
    head: &str,
    extra_headers: &[(&str, String)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut extra = String::new();
    for (name, value) in extra_headers {
        write!(extra, "{name}: {value}\r\n").unwrap();
    }
    let request = format!(
        "{head} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: {}\r\n{extra}\r\n",
        body.len()
    );
    let mut stream = TcpStream::connect(addr).await.unwrap();
    stream.write_all(request.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();

    let mut answer = Vec::new();
    tokio::time::timeout(Duration::from_secs(10), stream.read_to_end(&mut answer))
        .await
        .expect("the server should answer and close")
        .unwrap();
    let split = answer
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    let status = std::str::from_utf8(&answer[9..12])
        .unwrap()
        .parse()
        .unwrap();
    (status, answer[split + 4..].to_vec())
}

async fn nonce(addr: SocketAddr) -> Nonce {
    let (status, body) = exchange(addr, &format!("GET {NONCE}"), &[], b"").await;
    assert_eq!(status, 200);
    serde_json::from_slice::<NonceResponse>(&body)
        .unwrap()
        .nonce
}

async fn signed_post(
    addr: SocketAddr,
    key: &SigningKey,
    path: &str,
    body: &[u8],
) -> (u16, Vec<u8>) {
    let nonce = nonce(addr).await;
    let signature = protocol::sign(key, &host(HOST), "POST", path, &nonce, body);
    let headers = [
        (HOST_HEADER, HOST.to_owned()),
        (NONCE_HEADER, nonce.to_string()),
        (SIGNATURE_HEADER, signature.to_string()),
    ];
    exchange(addr, &format!("POST {path}"), &headers, body).await
}

async fn queue(store: &Store) {
    let mut tx = store.begin().await.unwrap();
    sqlx::query(
        "INSERT INTO releases (deployment, tag, decision, reason, seen_at)
         VALUES ('app/prod', 'v1.0.1', 'auto', 'patch', 0)",
    )
    .execute(&mut *tx)
    .await
    .unwrap();
    let deploy = NewDeploy {
        deployment: "app/prod".parse().unwrap(),
        host: host(HOST),
        tag: "v1.0.1".parse().unwrap(),
        digest: format!("sha256:{}", "c".repeat(64)).parse().unwrap(),
        commit: "a".repeat(40).parse().unwrap(),
    };
    store.queue_deploy(&mut tx, &deploy).await.unwrap();
    tx.commit().await.unwrap();
    store.wake_agents();
}

/// A body over the limit is read far enough that its sender hears why, rather
/// than having the connection reset under it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_body_a_little_over_the_limit_gets_its_answer_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let config = landfall_core::config::parse(super::CONFIG.as_bytes()).unwrap();
    let state = ApiState::new(store, config, test_limits());
    let app = crate::router(state.clone());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(serve::run(
        listener,
        app,
        ServeOptions::default(),
        async move {
            drop(stopped.await);
            state.begin_shutdown();
        },
    ));

    let (status, body) = signed_post(
        addr,
        &signing_key(1),
        WORK,
        &vec![b' '; MAX_BODY_BYTES + 32 * 1024],
    )
    .await;
    assert_eq!(status, 413);
    let problem: Problem = serde_json::from_slice(&body).unwrap();
    assert_eq!(problem.code, "body_too_large");

    let (status, _) = exchange(
        addr,
        &format!("POST {ENROL}"),
        &[],
        &vec![b' '; 4 * 1024 + 32 * 1024],
    )
    .await;
    assert_eq!(status, 413);

    stop.send(()).unwrap();
    server.await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_enrols_polls_and_reports_over_tcp() {
    let dir = tempfile::tempdir().unwrap();
    let store = Store::open(&dir.path().join("controller.db"))
        .await
        .unwrap();
    let config = landfall_core::config::parse(super::CONFIG.as_bytes()).unwrap();
    let config_hash: [u8; 32] = hex::decode(config.hash()).unwrap().try_into().unwrap();
    let limits = Limits {
        long_poll: Duration::from_secs(30),
        ..test_limits()
    };
    let state = ApiState::new(store.clone(), config, limits);
    let app = crate::router(state.clone());
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, stopped) = oneshot::channel::<()>();
    let server = tokio::spawn(serve::run(
        listener,
        app,
        ServeOptions::default(),
        async move {
            drop(stopped.await);
            state.begin_shutdown();
        },
    ));

    let (status, _) = exchange(addr, "GET /healthz", &[], b"").await;
    assert_eq!(status, 200);

    // Enrol.
    let key = signing_key(1);
    let code = store.issue_enrol_code(&host(HOST), false).await.unwrap();
    let enrol = EnrolRequest {
        code: code.reveal().parse().unwrap(),
        host: host(HOST),
        public_key: key.verifying_key(),
    };
    let body = serde_json::to_vec(&enrol).unwrap();
    let (status, _) = exchange(addr, &format!("POST {ENROL}"), &[], &body).await;
    assert_eq!(status, 204);

    // The long poll is waiting over the network when the deploy is queued.
    let work = serde_json::to_vec(&WorkRequest {
        config_hash,
        running: Vec::new(),
    })
    .unwrap();
    let poll = signed_post(addr, &key, WORK, &work);
    let later = async {
        tokio::time::sleep(Duration::from_millis(100)).await;
        queue(&store).await;
    };
    let ((status, body), ()) = tokio::join!(poll, later);
    assert_eq!(status, 200);
    let answer: WorkResponse = serde_json::from_slice(&body).unwrap();
    let id = answer.work.unwrap().deploy_id;

    // Report, and a request with no signature is refused on the way past. It has
    // no body: one refused before its body is read is not read at all, and the
    // close can reset the connection before the answer arrives.
    let report = serde_json::to_vec(&deployed_report(id)).unwrap();
    let (status, _) = signed_post(addr, &key, REPORT, &report).await;
    assert_eq!(status, 204);
    let (status, _) = exchange(addr, &format!("POST {REPORT}"), &[], b"").await;
    assert_eq!(status, 401);

    assert_eq!(store.verify_audit().await.unwrap().first_bad, None);
    stop.send(()).unwrap();
    server.await.unwrap();
}
