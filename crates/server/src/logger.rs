//! The controller's log: the only code that writes to stderr while it serves.
//!
//! A write to stderr can block for as long as whatever reads it is stuck: a stalled journald or log
//! driver, or a full pipe. Handlers and the watcher log from the runtime's threads, so a blocking
//! write there could take every thread, and with them the timers that stopping goes by. So a line
//! is only ever handed to a bounded queue, and one thread of the log's own does the writing. A line
//! that doesn't fit is dropped and counted, and the count is said before the next line that is
//! written. The queue holds at most [`CAPACITY`] lines of at most about [`MAX_LINE_BYTES`] each.
//!
//! Each line is `landfall-server: ` and then the line, on one line: a control character, or one
//! that [hides text](hides_text), is written as a `\uXXXX` escape, and a backslash as `\\`, so that
//! nothing passed in can make a line that looks like another, or pass for an escape.

use std::fmt::Write as _;
use std::io::{self, Write};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

/// How many lines wait for stderr at most.
const CAPACITY: usize = 256;

/// The most of a line written, in bytes, before it is cut short.
const MAX_LINE_BYTES: usize = 4096;

/// What ends a line that was cut short. It starts with a single backslash, which escaping always
/// doubles, so no line can end with it but one that was cut.
const CUT_SHORT: &str = " \\[cut short]";

/// How often a flush tries again to queue its mark while the queue is full.
const FLUSH_RETRY: Duration = Duration::from_millis(5);

const PREFIX: &str = "landfall-server: ";

/// What the writing thread is handed.
#[derive(Debug)]
enum Entry {
    /// A line ready to write, and how many were dropped since the line before it.
    Line { text: String, dropped_before: u64 },
    /// Told once everything queued before it is written, and how many were dropped since the line
    /// before it, which it says even with no line after it.
    Flush {
        done: mpsc::Sender<()>,
        dropped_before: u64,
    },
}

/// A log whose lines a thread of its own writes to a sink. Logging never waits.
#[derive(Debug)]
pub(crate) struct Logger {
    queue: SyncSender<Entry>,
    /// Lines that didn't fit since the last one that did.
    dropped: Arc<AtomicU64>,
}

impl Logger {
    /// Starts the thread that writes to `sink`, with room for `capacity` lines waiting.
    pub(crate) fn start(sink: impl Write + Send + 'static, capacity: usize) -> io::Result<Self> {
        let (queue, entries) = mpsc::sync_channel(capacity);
        std::thread::Builder::new()
            .name("landfall-log".to_owned())
            .spawn(move || write_all(&entries, sink))?;
        Ok(Self {
            queue,
            dropped: Arc::new(AtomicU64::new(0)),
        })
    }

    /// Queues `line`, made one line and cut short if long, or counts it if the queue is full.
    /// Callers pass only validated values or the controller's own messages, never an agent's text
    /// unquoted.
    pub(crate) fn log(&self, line: &str) {
        self.queue_text(one_line(line));
    }

    /// Queues `text` as it is, which may span lines: only for a command's own failure, as it
    /// ends, such as a configuration's parse error with the place it points at.
    pub(crate) fn log_as_is(&self, text: &str) {
        self.queue_text(text.to_owned());
    }

    /// Queues `text` with the count of lines dropped before it, or adds it to that count.
    ///
    /// With several threads logging at once, a count can be taken by one line and land a line or
    /// so away from where the lines were dropped, as two threads can queue in the other order from
    /// the one they took the count in. The total said is always right, and nothing is counted
    /// twice; keeping the order exact would need a lock around the queue.
    fn queue_text(&self, text: String) {
        let dropped_before = self.dropped.swap(0, Ordering::Relaxed);
        if let Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) =
            self.queue.try_send(Entry::Line {
                text,
                dropped_before,
            })
        {
            self.dropped
                .fetch_add(dropped_before.saturating_add(1), Ordering::Relaxed);
        }
    }

    /// How many dropped lines wait to be said: a flush takes them, so a test can tell when one began.
    #[cfg(test)]
    pub(crate) fn drops_waiting(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
    }

    /// Waits up to `limit` for everything queued so far to be written, with the count of what was
    /// dropped since. True if it was. This blocks its thread, so it is for once the runtime is
    /// gone, never for a runtime's thread.
    pub(crate) fn flush_within(&self, limit: Duration) -> bool {
        let deadline = Instant::now() + limit;
        let (done, flushed) = mpsc::channel();
        let mut mark = Entry::Flush {
            done,
            dropped_before: self.dropped.swap(0, Ordering::Relaxed),
        };
        loop {
            match self.queue.try_send(mark) {
                Ok(()) => break,
                Err(TrySendError::Full(back)) if Instant::now() < deadline => {
                    mark = back;
                    std::thread::sleep(FLUSH_RETRY);
                }
                Err(TrySendError::Full(back) | TrySendError::Disconnected(back)) => {
                    if let Entry::Flush { dropped_before, .. } = back {
                        self.dropped.fetch_add(dropped_before, Ordering::Relaxed);
                    }
                    return false;
                }
            }
        }
        flushed
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_ok()
    }
}

/// The writing thread: writes each line, after saying how many didn't fit or failed before it.
/// It ends when every [`Logger`] for it is gone; one stuck writing is left behind as the process
/// ends.
fn write_all(entries: &Receiver<Entry>, mut sink: impl Write) {
    let mut failed: u64 = 0;
    while let Ok(entry) = entries.recv() {
        let (text, dropped_before, done) = match entry {
            Entry::Line {
                text,
                dropped_before,
            } => (Some(text), dropped_before, None),
            Entry::Flush {
                done,
                dropped_before,
            } => (None, dropped_before, Some(done)),
        };
        let missed = dropped_before.saturating_add(failed);
        let mut out = String::new();
        if missed > 0 {
            // Writing to a String cannot fail.
            let _ = writeln!(
                out,
                "{PREFIX}{missed} more log lines were not written, as stderr was not taking them"
            );
        }
        if let Some(text) = &text {
            out.push_str(PREFIX);
            out.push_str(text);
            out.push('\n');
        }
        if !out.is_empty() {
            failed = match sink.write_all(out.as_bytes()).and_then(|()| sink.flush()) {
                Ok(()) => 0,
                // Nothing is left to tell if stderr itself is gone, but if it comes back, it hears
                // how much it missed.
                Err(_) => missed.saturating_add(u64::from(text.is_some())),
            };
        }
        if let Some(done) = done {
            let _ = done.send(());
        }
    }
}

/// Whether `character` reorders text, breaks a line, or is there without being seen: what a
/// terminal or a log viewer shows differently from what is there. Every format character (Unicode's
/// `Cf`, as of Unicode 17), the line and paragraph separators, and the variation selectors.
#[must_use]
pub(crate) fn hides_text(character: char) -> bool {
    matches!(
        character,
        '\u{ad}'
            | '\u{600}'..='\u{605}'
            | '\u{61c}'
            | '\u{6dd}'
            | '\u{70f}'
            | '\u{890}'..='\u{891}'
            | '\u{8e2}'
            | '\u{180e}'
            | '\u{200b}'..='\u{200f}'
            | '\u{2028}'..='\u{202e}'
            | '\u{2060}'..='\u{2064}'
            | '\u{2066}'..='\u{206f}'
            | '\u{fe00}'..='\u{fe0f}'
            | '\u{feff}'
            | '\u{fff9}'..='\u{fffb}'
            | '\u{110bd}'
            | '\u{110cd}'
            | '\u{13430}'..='\u{1343f}'
            | '\u{1bca0}'..='\u{1bca3}'
            | '\u{1d173}'..='\u{1d17a}'
            | '\u{e0000}'..='\u{e007f}'
            | '\u{e0100}'..='\u{e01ef}'
    )
}

/// Writes `character` as `\uXXXX`, two of them, a UTF-16 surrogate pair, past the first plane: as
/// JSON writes it, and never followed by a digit that could be read as part of it.
pub(crate) fn push_escaped(out: &mut String, character: char) {
    let mut units = [0; 2];
    for unit in character.encode_utf16(&mut units) {
        // Writing to a String cannot fail.
        let _ = write!(out, "\\u{unit:04x}");
    }
}

/// `line` on one line: controls and what [`hides_text`] escaped, a backslash doubled, and cut short
/// past [`MAX_LINE_BYTES`].
fn one_line(line: &str) -> String {
    let mut out = String::with_capacity(line.len().min(MAX_LINE_BYTES + CUT_SHORT.len()));
    for character in line.chars() {
        if out.len() >= MAX_LINE_BYTES {
            out.push_str(CUT_SHORT);
            break;
        }
        if character == '\\' {
            out.push_str("\\\\");
        } else if character.is_control() || hides_text(character) {
            push_escaped(&mut out, character);
        } else {
            out.push(character);
        }
    }
    out
}

/// The log on stderr, started on first use. `None` if its thread couldn't start, and then lines
/// are dropped: writing them here instead could block the thread that logs.
pub(crate) fn global() -> Option<&'static Logger> {
    static GLOBAL: OnceLock<Option<Logger>> = OnceLock::new();
    GLOBAL
        .get_or_init(|| Logger::start(io::stderr(), CAPACITY).ok())
        .as_ref()
}

/// Writes a line to the controller's log, without waiting: see [`Logger::log`].
pub(crate) fn log(line: &str) {
    if let Some(logger) = global() {
        logger.log(line);
    }
}

#[cfg(test)]
pub(crate) mod gate;
mod panics;
#[cfg(test)]
mod tests;

pub(crate) use self::panics::log_panics;
