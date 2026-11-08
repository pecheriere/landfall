//! A log line for a refusal nobody can be held to.
//!
//! A bad signature or an invalid enrolment code could come from anyone, so
//! auditing them would let anyone fill the audit log. They go to stderr instead,
//! and even that is capped, so that they cannot fill the disk through it.
//! Refusals a signer or a valid code can be held to are in the audit log. A
//! connection refused for its source's cap goes here too, from `serve`.

use std::sync::{Mutex, PoisonError};

use crate::logger::log;

/// The most lines written in one [`WINDOW_SECS`].
const LINES_PER_WINDOW: u32 = 60;

const WINDOW_SECS: i64 = 60;

/// What to do with one more line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Admit {
    /// Write it, after saying how many were dropped before it.
    Write { dropped_before: u64 },
    /// Count it and write nothing.
    Drop,
}

#[derive(Debug, Default)]
struct Window {
    started: i64,
    written: u32,
    dropped: u64,
}

impl Window {
    fn admit(&mut self, now: i64) -> Admit {
        // A clock stepped backwards starts a window too, rather than stalling.
        if now.saturating_sub(self.started) >= WINDOW_SECS || now < self.started {
            self.started = now;
            self.written = 0;
        }
        if self.written >= LINES_PER_WINDOW {
            self.dropped = self.dropped.saturating_add(1);
            return Admit::Drop;
        }
        self.written += 1;
        Admit::Write {
            dropped_before: std::mem::take(&mut self.dropped),
        }
    }
}

/// The capped log, shared by the requests.
#[derive(Debug, Default)]
pub(crate) struct RefusalLog(Mutex<Window>);

impl RefusalLog {
    /// Writes `line`, unless too many have gone already. `line` must hold only
    /// validated values.
    pub(crate) fn note(&self, now: i64, line: &str) {
        let admit = self
            .0
            .lock()
            // Three integers, valid at every step.
            .unwrap_or_else(PoisonError::into_inner)
            .admit(now);
        if let Admit::Write { dropped_before } = admit {
            if dropped_before > 0 {
                log(&format!("{dropped_before} more refusals were not logged"));
            }
            log(line);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{Admit, LINES_PER_WINDOW, WINDOW_SECS, Window};

    #[test]
    fn lines_are_capped_per_window_and_the_rest_counted() {
        let mut window = Window::default();
        let now = 1_000;
        for _ in 0..LINES_PER_WINDOW {
            assert_eq!(window.admit(now), Admit::Write { dropped_before: 0 });
        }
        assert_eq!(window.admit(now), Admit::Drop);
        assert_eq!(window.admit(now + 1), Admit::Drop);
        assert_eq!(
            window.admit(now + WINDOW_SECS),
            Admit::Write { dropped_before: 2 }
        );
    }

    #[test]
    fn a_clock_stepped_backwards_does_not_silence_the_log() {
        let mut window = Window::default();
        for _ in 0..=LINES_PER_WINDOW {
            window.admit(1_000);
        }
        assert_eq!(window.admit(500), Admit::Write { dropped_before: 1 });
    }
}
