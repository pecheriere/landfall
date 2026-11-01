//! A stream whose writes must keep making progress.

use std::future::Future as _;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Sleep, sleep};

/// Wraps a stream so that a write, flush or shutdown waiting for longer than the
/// timeout fails with [`io::ErrorKind::TimedOut`]. The clock starts when the
/// stream first says "not yet", and any write that goes through stops it: a slow
/// client is fine, one that has stopped reading is not.
#[derive(Debug)]
pub(super) struct WriteDeadline<S> {
    inner: S,
    timeout: Duration,
    /// Running while a write is waiting.
    waiting: Option<Pin<Box<Sleep>>>,
}

impl<S> WriteDeadline<S> {
    pub(super) fn new(inner: S, timeout: Duration) -> Self {
        Self {
            inner,
            timeout,
            waiting: None,
        }
    }

    /// Applies the deadline to the result of polling a write. Polling the timer
    /// registers this task with it, so a client that never reads still gets the
    /// connection woken and closed.
    fn guarded<T>(
        &mut self,
        cx: &mut Context<'_>,
        poll: Poll<io::Result<T>>,
    ) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.waiting = None;
            return poll;
        }
        let timeout = self.timeout;
        let waiting = self.waiting.get_or_insert_with(|| Box::pin(sleep(timeout)));
        match waiting.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(Err(io::ErrorKind::TimedOut.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for WriteDeadline<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for WriteDeadline<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write(cx, buf);
        self.guarded(cx, poll)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let poll = Pin::new(&mut self.inner).poll_write_vectored(cx, bufs);
        self.guarded(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_flush(cx);
        self.guarded(cx, poll)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let poll = Pin::new(&mut self.inner).poll_shutdown(cx);
        self.guarded(cx, poll)
    }
}
