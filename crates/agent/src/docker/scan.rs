//! Looking for a string in a stream, line by line, in bounded chunks.

use std::io;

use tokio::io::{AsyncRead, AsyncReadExt};

use super::{LINE_LIMIT, READ_CHUNK};

/// Looks for a needle in a stream, line by line, holding at most
/// [`LINE_LIMIT`] bytes. A line longer than that is scanned as it fills,
/// keeping the last `needle.len() - 1` bytes, so a match across the
/// boundary is found. A needle never matches across a newline.
pub(super) struct LineScanner<'a> {
    needle: &'a [u8],
    pub(super) line: Vec<u8>,
}

impl<'a> LineScanner<'a> {
    pub(super) fn new(needle: &'a [u8]) -> Self {
        Self {
            needle,
            line: Vec::new(),
        }
    }

    fn matches(&self) -> bool {
        memchr::memmem::find(&self.line, self.needle).is_some()
    }

    /// Feeds more of the stream; whether the needle has been found.
    pub(super) fn feed(&mut self, mut data: &[u8]) -> bool {
        while !data.is_empty() {
            let end = memchr::memchr(b'\n', data);
            let (segment, rest) = match end {
                Some(i) => (&data[..i], &data[i + 1..]),
                None => (data, &[][..]),
            };
            if self.push(segment) || self.matches() {
                return true;
            }
            if end.is_some() {
                self.line.clear();
            }
            data = rest;
        }
        false
    }

    pub(super) fn push(&mut self, mut segment: &[u8]) -> bool {
        while !segment.is_empty() {
            let take = (LINE_LIMIT - self.line.len()).min(segment.len());
            self.line.extend_from_slice(&segment[..take]);
            segment = &segment[take..];
            if self.line.len() >= LINE_LIMIT {
                if self.matches() {
                    return true;
                }
                let keep = self.needle.len() - 1;
                self.line.drain(..self.line.len() - keep);
            }
        }
        false
    }

    /// The stream ended: the unterminated last line counts.
    pub(super) fn finish(&self) -> bool {
        self.matches()
    }
}

/// Scans a stream for the needle until it ends or matches.
pub(super) async fn scan<R: AsyncRead + Unpin>(
    reader: Option<R>,
    needle: &[u8],
) -> Result<bool, io::Error> {
    let Some(mut reader) = reader else {
        return Ok(false);
    };
    let mut scanner = LineScanner::new(needle);
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        let n = reader.read(&mut chunk).await?;
        if n == 0 {
            return Ok(scanner.finish());
        }
        if scanner.feed(&chunk[..n]) {
            return Ok(true);
        }
    }
}
