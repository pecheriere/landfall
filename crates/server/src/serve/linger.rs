//! Closing a connection without losing its last answer: what nginx calls a lingering close.
//!
//! A route may answer without reading all of the body it was sent: a refusal before the body, a
//! fallback, a route that takes none. Closing a socket with bytes unread, or having more arrive
//! after it is closed, makes the kernel send a reset, and a reset throws away whatever the client
//! hasn't read yet, the answer included. So once hyper is done with a connection, it is shut for
//! writing, which sends the end of the answer, and what the client still sends is read and thrown
//! away until it closes its end too, within a bound of time and of bytes.

use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

use crate::agent_api::DRAIN_BYTES;

/// Shuts `stream` for writing, then reads and discards until the client closes its end, for no
/// longer than `limit` and no more than [`DRAIN_BYTES`] in all.
pub(super) async fn linger<S: AsyncRead + AsyncWrite + Unpin>(mut stream: S, limit: Duration) {
    let discard = async {
        if stream.shutdown().await.is_err() {
            return;
        }
        let mut buf = [0; 4096];
        let mut left = DRAIN_BYTES;
        while left > 0 {
            match stream.read(&mut buf).await {
                Ok(0) | Err(_) => return,
                Ok(read) => left = left.saturating_sub(read),
            }
        }
    };
    drop(tokio::time::timeout(limit, discard).await);
}
