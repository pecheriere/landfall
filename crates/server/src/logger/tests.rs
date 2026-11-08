use std::io::{self, Write};
use std::time::{Duration, Instant};

use super::gate::{Gate, PATIENCE};
use super::{CUT_SHORT, Logger, MAX_LINE_BYTES, hides_text};

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

/// A flush says what was dropped, even with no line after it to say it before.
#[test]
fn a_flush_says_what_was_dropped_with_no_line_after_it() {
    let gate = Gate::default();
    let logger = Logger::start(gate.clone(), 1).unwrap();
    logger.log("held");
    gate.wait_for_a_write();
    logger.log("queued");
    for _ in 0..3 {
        logger.log("lost");
    }

    gate.open();
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: held",
            "landfall-server: queued",
            "landfall-server: 3 more log lines were not written, as stderr was not taking them",
        ]
    );
}

/// The same for a line that failed to write, with nothing logged after it.
#[test]
fn a_flush_says_what_failed_to_write_with_no_line_after_it() {
    let gate = Gate::opened();
    let sink = FailsFirst {
        failing: 1,
        gate: gate.clone(),
    };
    let logger = Logger::start(sink, 8).unwrap();
    logger.log("gone");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        ["landfall-server: 1 more log lines were not written, as stderr was not taking them"]
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

/// Nothing passed in can start a line of its own, hide what's on it, or pass for an escape.
#[test]
fn a_line_stays_one_line_whatever_it_holds() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log("refused x\nlandfall-server: decision: forged\r\u{1b}[2J\u{202e}txt\u{7f}");
    logger.log(r"a literal \u000a, and a \ alone");
    logger.log("zw\u{200b}\u{200d} shy\u{ad} wj\u{2060} vs\u{fe0f} tag\u{e0041} mvs\u{180e} ok é");
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: refused x\\u000alandfall-server: decision: forged\\u000d\\u001b[2J\
             \\u202etxt\\u007f",
            r"landfall-server: a literal \\u000a, and a \\ alone",
            r"landfall-server: zw\u200b\u200d shy\u00ad wj\u2060 vs\ufe0f tag\udb40\udc41 mvs\u180e ok é",
        ]
    );
}

/// Every format character is escaped, whatever plane it is on, and nothing printable is.
#[test]
fn every_format_character_hides_text_and_nothing_printable_does() {
    // Unicode 17's `Cf`, as `unicodedata` lists it.
    let format = [
        0xad..=0xad,
        0x600..=0x605,
        0x61c..=0x61c,
        0x6dd..=0x6dd,
        0x70f..=0x70f,
        0x890..=0x891,
        0x8e2..=0x8e2,
        0x180e..=0x180e,
        0x200b..=0x200f,
        0x202a..=0x202e,
        0x2060..=0x2064,
        0x2066..=0x206f,
        0xfeff..=0xfeff,
        0xfff9..=0xfffb,
        0x110bd..=0x110bd,
        0x110cd..=0x110cd,
        0x13430..=0x1343f,
        0x1bca0..=0x1bca3,
        0x1d173..=0x1d17a,
        0xe0001..=0xe0001,
        0xe0020..=0xe007f,
    ];
    for code in format.into_iter().flatten() {
        let character = char::from_u32(code).unwrap();
        assert!(hides_text(character), "U+{code:04X}");
    }
    for character in ['a', 'é', '\u{2014}', '\u{4e2d}', '\u{1f600}', ' '] {
        assert!(!hides_text(character), "{character:?}");
    }
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

/// Only a line that was cut ends with the mark: one that says it itself has its backslash doubled.
#[test]
fn a_line_cant_pass_for_one_cut_short() {
    let gate = Gate::opened();
    let logger = Logger::start(gate.clone(), 8).unwrap();
    logger.log(&format!("only says so{CUT_SHORT}"));
    assert!(logger.flush_within(PATIENCE));
    assert_eq!(
        gate.lines(),
        [r"landfall-server: only says so \\[cut short]"]
    );
    assert!(!gate.lines()[0].ends_with(CUT_SHORT));
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
