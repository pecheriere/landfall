use std::io::{self, Write};
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::{CUT_SHORT, Logger, MAX_LINE_BYTES};

/// A wait that only a hung test waits out.
const PATIENCE: Duration = Duration::from_secs(60);

/// A stderr that takes nothing until it is opened, and keeps what it took.
#[derive(Clone, Default)]
struct Gate(Arc<(Mutex<GateState>, Condvar)>);

#[derive(Default)]
struct GateState {
    open: bool,
    /// Whether a write has come and is waiting, or went through.
    reached: bool,
    taken: Vec<u8>,
}

impl Gate {
    fn opened() -> Self {
        let gate = Self::default();
        gate.open();
        gate
    }

    fn open(&self) {
        let (state, changed) = &*self.0;
        state.lock().unwrap().open = true;
        changed.notify_all();
    }

    /// Waits until the writing thread is at the gate, holding a line it took from the queue.
    fn wait_for_a_write(&self) {
        let (state, changed) = &*self.0;
        let (_state, waited) = changed
            .wait_timeout_while(state.lock().unwrap(), PATIENCE, |state| !state.reached)
            .unwrap();
        assert!(!waited.timed_out(), "nothing came to be written");
    }

    fn lines(&self) -> Vec<String> {
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

/// A stderr that fails its first `failing` writes, then takes everything into `gate`.
struct FailsFirst {
    failing: usize,
    gate: Gate,
}

impl Write for FailsFirst {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.failing > 0 {
            self.failing -= 1;
            return Err(io::Error::from(io::ErrorKind::BrokenPipe));
        }
        self.gate.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
fn lines_are_written_in_order_each_after_the_prefix() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log("first");
    logger.log("second");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        ["landfall-server: first", "landfall-server: second"]
    );
}

/// Every line on a stderr that takes nothing, far more than the queue holds, goes at once.
#[test]
fn logging_never_waits_for_a_stderr_that_takes_nothing() {
    let gate = Gate::default();
    let logger = Logger::start(gate.clone(), 4).unwrap();
    logger.log("held");
    gate.wait_for_a_write();

    let started = Instant::now();
    for line in 0..10_000 {
        logger.log(&format!("line {line}"));
    }
    assert!(started.elapsed() < PATIENCE, "logging waited");

    let started = Instant::now();
    assert!(!logger.flush_within(Duration::from_millis(50)));
    assert!(
        started.elapsed() < PATIENCE,
        "flushing waited past its limit"
    );
}

#[test]
fn what_did_not_fit_is_said_before_the_next_line_written() {
    let gate = Gate::default();
    let logger = Logger::start(gate.clone(), 2).unwrap();
    logger.log("held");
    gate.wait_for_a_write();
    logger.log("queued 1");
    logger.log("queued 2");
    for _ in 0..5 {
        logger.log("lost");
    }

    gate.open();
    assert!(logger.flush_within(PATIENCE));
    logger.log("after");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: held",
            "landfall-server: queued 1",
            "landfall-server: queued 2",
            "landfall-server: 5 more log lines were not written, as stderr was not taking them",
            "landfall-server: after",
        ]
    );
}

#[test]
fn a_line_that_failed_to_write_is_counted_once_stderr_takes_lines_again() {
    let gate = Gate::opened();
    let sink = FailsFirst {
        failing: 2,
        gate: gate.clone(),
    };
    let logger = Logger::start(sink, 8).unwrap();
    logger.log("gone");
    logger.log("also gone");
    logger.log("back");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: 2 more log lines were not written, as stderr was not taking them",
            "landfall-server: back",
        ]
    );
}

/// Nothing passed in can start a line of its own, or hide what's on it.
#[test]
fn a_line_stays_one_line_whatever_it_holds() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log("refused x\nlandfall-server: decision: forged\r\u{1b}[2J\u{202e}txt\u{7f}");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: refused x\\u000alandfall-server: decision: forged\\u000d\\u001b[2J\
             \\u202etxt\\u007f"
        ]
    );
}

#[test]
fn a_long_line_is_cut_short() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log(&"é".repeat(MAX_LINE_BYTES));
    assert!(logger.flush_within(PATIENCE));
    let lines = gate.lines();
    assert_eq!(lines.len(), 1);
    let line = lines[0].strip_prefix("landfall-server: ").unwrap();
    assert!(line.ends_with(CUT_SHORT), "{line}");
    assert_eq!(line.len(), MAX_LINE_BYTES + CUT_SHORT.len());
}

/// A command's own failure keeps the lines it spans, as a parse error's pointer needs them.
#[test]
fn a_failure_logged_as_is_keeps_its_lines() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log_as_is("cannot parse c.toml:\n  |\n1 | x =\n  |    ^");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: cannot parse c.toml:",
            "  |",
            "1 | x =",
            "  |    ^"
        ]
    );
}
