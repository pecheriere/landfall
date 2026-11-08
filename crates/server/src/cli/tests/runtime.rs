//! How a command's runtime ends: what's logged, a failure, and a panic, against a stderr that takes
//! nothing until the test opens it, so that nothing here goes by timing.

use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;

use super::super::{
    CliError, EXIT_COULD_NOT_RUN, Ending, FLUSH_TIMEOUT, FailureTo, Logger, on_a_runtime_ending,
};
use crate::logger::gate::{Gate, PATIENCE};

const FAILURE: &str = "landfall-server: GITHUB_TOKEN is set but is not valid UTF-8 text or not a \
                       valid HTTP header value";

/// An ending with `log`, which has as long as it takes, and a stderr that keeps what it is given.
fn ending<'a>(
    log: Option<&'a Logger>,
    failure: FailureTo,
    stderr: &'a mut Vec<u8>,
) -> Ending<'a, &'a mut Vec<u8>> {
    Ending {
        log,
        flush_timeout: PATIENCE,
        failure,
        stderr,
    }
}

/// A stderr that keeps what it is given, and what the log had written when it was first given
/// anything.
struct Seeing {
    log: Gate,
    log_by_then: Option<Vec<String>>,
    said: Vec<u8>,
}

impl Write for Seeing {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.log_by_then.is_none() {
            self.log_by_then = Some(self.log.lines());
        }
        self.said.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// The process ends, with a task blocking its thread.
#[test]
fn a_task_blocking_its_thread_cant_keep_the_process() {
    let (blocked_for_good, blocked) = mpsc::channel::<()>();
    let (result, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let mut stderr = Vec::new();
        let code = on_a_runtime_ending(
            async move {
                let (started, has_started) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    started.send(()).unwrap();
                    let _ = blocked.recv();
                });
                has_started.await.unwrap();
                Ok(7)
            },
            ending(None, FailureTo::Stderr, &mut stderr),
        );
        result.send(code).unwrap();
    });
    let code = ended.recv_timeout(PATIENCE);
    assert_eq!(code, Ok(7));
    drop(blocked_for_good);
}

/// With a stderr that takes nothing, what `serve` logs, its failure included, can't keep the
/// process: the log has its limit, and no more, once the runtime is gone.
#[test]
fn a_stderr_that_takes_nothing_cant_keep_the_process() {
    let log = Logger::start(Gate::default(), 4).unwrap();
    let (result, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let ending = Ending {
            log: Some(&log),
            flush_timeout: FLUSH_TIMEOUT,
            failure: FailureTo::Log,
            stderr: io::sink(),
        };
        let code = on_a_runtime_ending(
            async {
                for _ in 0..100 {
                    log.log("a line from a runtime's thread");
                }
                Err(CliError::GitHubToken)
            },
            ending,
        );
        result.send(code).unwrap();
    });
    let code = ended.recv_timeout(PATIENCE);
    assert_eq!(code, Ok(EXIT_COULD_NOT_RUN));
}

/// A panic out of the work still has the log flushed. Only a flush says what was dropped when no
/// line comes after, so the count here is written by the flush or not at all.
#[test]
fn the_log_is_flushed_when_the_work_panics() {
    let gate = Gate::default();
    let log = Logger::start(gate.clone(), 1).unwrap();
    let mut stderr = Vec::new();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        on_a_runtime_ending(
            async {
                log.log("held");
                gate.wait_for_a_write();
                log.log("queued");
                log.log("lost");
                gate.open();
                panic!("the work failed");
            },
            ending(Some(&log), FailureTo::Log, &mut stderr),
        )
    }));
    assert!(unwound.is_err());
    assert_eq!(
        gate.lines(),
        [
            "landfall-server: held",
            "landfall-server: queued",
            "landfall-server: 1 more log lines were not written, as stderr was not taking them",
        ]
    );
    assert_eq!(stderr, [] as [u8; 0]);
}

/// `serve`'s failure goes to the log after what it logged.
#[test]
fn serves_failure_goes_to_the_log() {
    let gate = Gate::opened();
    let log = Logger::start(gate.clone(), 8).unwrap();
    let mut stderr = Vec::new();
    let code = on_a_runtime_ending(
        async {
            log.log("logged");
            Err(CliError::GitHubToken)
        },
        ending(Some(&log), FailureTo::Log, &mut stderr),
    );
    assert_eq!(code, EXIT_COULD_NOT_RUN);
    assert_eq!(gate.lines(), ["landfall-server: logged", FAILURE]);
    assert_eq!(stderr, [] as [u8; 0]);
}

/// Any other command's failure goes straight to stderr, once what was logged is written.
#[test]
fn another_commands_failure_goes_straight_to_stderr_after_the_log() {
    let gate = Gate::opened();
    let log = Logger::start(gate.clone(), 8).unwrap();
    let mut stderr = Seeing {
        log: gate.clone(),
        log_by_then: None,
        said: Vec::new(),
    };
    let code = on_a_runtime_ending(
        async {
            log.log("logged");
            Err(CliError::GitHubToken)
        },
        Ending {
            log: Some(&log),
            flush_timeout: PATIENCE,
            failure: FailureTo::Stderr,
            stderr: &mut stderr,
        },
    );
    assert_eq!(code, EXIT_COULD_NOT_RUN);
    assert_eq!(
        stderr.log_by_then,
        Some(vec!["landfall-server: logged".to_owned()])
    );
    assert_eq!(
        String::from_utf8(stderr.said).unwrap(),
        format!("{FAILURE}\n")
    );
    assert_eq!(gate.lines(), ["landfall-server: logged"]);
}
