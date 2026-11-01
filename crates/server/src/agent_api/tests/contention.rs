//! With another writer in the way, on a real file: these need a second
//! connection, which the in-memory store does not have.

use axum::http::StatusCode;
use landfall_core::protocol::Nonce;
use tempfile::TempDir;

use super::{Harness, WORK, signed_request, signing_key, test_limits};
use crate::store::Store;

/// A store that gives up on a lock at once, and a second store on the same file
/// to hold that lock.
async fn impatient() -> (TempDir, Harness, Store) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("controller.db");
    let writer = Store::open(&path).await.unwrap();
    let store = Store::open_impatient(&path).await.unwrap();
    (dir, Harness::on_store(store, test_limits()), writer)
}

#[tokio::test]
async fn a_busy_database_is_a_retryable_answer_and_not_a_failure() {
    let (_dir, h, writer) = impatient().await;
    let lock = writer.begin().await.unwrap();

    let answer = h.get_nonce().await;
    assert_eq!(answer.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(answer.code(), "busy");
    assert!(answer.headers.contains_key("retry-after"));

    drop(lock);
    assert_eq!(h.get_nonce().await.status, StatusCode::OK);
}

/// Anyone can send requests with made-up nonces. If each took the write lock,
/// that would be a way to block every writer without having anything.
#[tokio::test]
async fn an_unknown_nonce_does_not_take_the_write_lock() {
    let (_dir, h, writer) = impatient().await;
    let lock = writer.begin().await.unwrap();

    let unknown = Nonce::from_bytes([9; 32]);
    let request = signed_request(
        "nobody",
        &signing_key(1),
        WORK,
        WORK,
        &unknown,
        b"{}".to_vec(),
    );
    let answer = h.send(request).await;
    // Had it wanted the lock this would be `busy`.
    assert_eq!(answer.status, StatusCode::UNAUTHORIZED);
    assert_eq!(answer.code(), "bad_nonce");
    drop(lock);
}
