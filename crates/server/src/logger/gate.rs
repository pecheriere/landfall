//! A stderr for tests that takes nothing until it is opened, so that what reaches it, and when, is
//! up to the test rather than to timing.

use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::Duration;

/// A wait that only a hung test waits out.
pub(crate) const PATIENCE: Duration = Duration::from_secs(60);

/// A stderr that takes nothing until it is opened, and keeps what it took.
#[derive(Clone, Default)]
pub(crate) struct Gate(Arc<(Mutex<GateState>, Condvar)>);

#[derive(Default)]
struct GateState {
    open: bool,
    /// Whether a write has come and is waiting, or went through.
    reached: bool,
    taken: Vec<u8>,
}

impl Gate {
    pub(crate) fn opened() -> Self {
        let gate = Self::default();
        gate.open();
        gate
    }

    pub(crate) fn open(&self) {
        let (state, changed) = &*self.0;
        state.lock().unwrap().open = true;
        changed.notify_all();
    }

    /// Waits until the writing thread is at the gate, holding a line it took from the queue.
    pub(crate) fn wait_for_a_write(&self) {
        let (state, changed) = &*self.0;
        let (_state, waited) = changed
            .wait_timeout_while(state.lock().unwrap(), PATIENCE, |state| !state.reached)
            .unwrap();
        assert!(!waited.timed_out(), "nothing came to be written");
    }

    /// What it took so far, line by line.
    pub(crate) fn lines(&self) -> Vec<String> {
        let (state, _) = &*self.0;
        String::from_utf8(state.lock().unwrap().taken.clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Gate {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let (state, changed) = &*self.0;
        let mut state = state.lock().unwrap();
        state.reached = true;
        changed.notify_all();
        let mut state = changed.wait_while(state, |state| !state.open).unwrap();
        state.taken.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
