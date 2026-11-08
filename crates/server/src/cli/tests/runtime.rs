//! How a command's runtime ends: what's logged, a failure, and a panic, against a stderr that is
//! slow or takes nothing.

use std::io::{self, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::super::{CliError, EXIT_COULD_NOT_RUN, FailureTo, Logger, on_a_runtime_logging};

/// A wait that only a hung test waits out.
const PATIENCE: Duration = Duration::from_secs(60);

/// A stderr that takes nothing, for as long as its sender is held.
struct Stuck(mpsc::Receiver<()>);

impl Write for Stuck {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        let _ = self.0.recv();
        Err(io::ErrorKind::BrokenPipe.into())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

/// A stderr that takes its time over each write, and keeps what it took.
#[derive(Clone, Default)]
struct Slow(Arc<Mutex<Vec<u8>>>);

impl Slow {
    fn lines(&self) -> Vec<String> {
        String::from_utf8(self.0.lock().unwrap().clone())
            .unwrap()
            .lines()
            .map(str::to_owned)
            .collect()
    }
}

impl Write for Slow {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        std::thread::sleep(Duration::from_millis(200));
        self.0.lock().unwrap().extend_from_slice(buf);
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
        let code = on_a_runtime_logging(
            async move {
                let (started, has_started) = tokio::sync::oneshot::channel();
                tokio::spawn(async move {
                    started.send(()).unwrap();
                    let _ = blocked.recv();
                });
                has_started.await.unwrap();
                Ok(7)
            },
            None,
            FailureTo::Stderr,
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
    let (stuck_for_good, stuck) = mpsc::channel::<()>();
    let log = Logger::start(Stuck(stuck), 4).unwrap();
    let (result, ended) = mpsc::channel();
    std::thread::spawn(move || {
        let code = on_a_runtime_logging(
            async {
                for _ in 0..100 {
                    log.log("a line from a runtime's thread");
                }
                Err(CliError::GitHubToken)
            },
            Some(&log),
            FailureTo::Log,
        );
        result.send(code).unwrap();
    });
    let code = ended.recv_timeout(PATIENCE);
    assert_eq!(code, Ok(EXIT_COULD_NOT_RUN));
    drop(stuck_for_good);
}

/// A panic out of the work is logged by the hook, and what's queued is still written before the
/// unwinding goes on: the stderr here takes longer over a line than the runtime takes to end.
#[test]
fn what_was_logged_is_written_when_the_work_panics() {
    let sink = Slow::default();
    let log = Logger::start(sink.clone(), 8).unwrap();
    let unwound = catch_unwind(AssertUnwindSafe(|| {
        on_a_runtime_logging(
            async {
                log.log("before the panic");
                panic!("the work failed");
            },
            Some(&log),
            FailureTo::Log,
        )
    }));
    assert!(unwound.is_err());
    assert_eq!(sink.lines(), ["landfall-server: before the panic"]);
}

/// `serve`'s failure goes to the log after what it logged. Any other command's goes straight to
/// stderr, however long it takes, once what was logged is written.
#[test]
fn a_failure_goes_to_the_log_only_for_serve() {
    for (failure, expected) in [
        (
            FailureTo::Log,
            &[
                "landfall-server: logged",
                "landfall-server: GITHUB_TOKEN is set but is not valid UTF-8 text or not a valid HTTP \
                 header value",
            ][..],
        ),
        (FailureTo::Stderr, &["landfall-server: logged"][..]),
    ] {
        let sink = Slow::default();
        let log = Logger::start(sink.clone(), 8).unwrap();
        let code = on_a_runtime_logging(
            async {
                log.log("logged");
                Err(CliError::GitHubToken)
            },
            Some(&log),
            failure,
        );
        assert_eq!(code, EXIT_COULD_NOT_RUN);
        assert_eq!(sink.lines(), expected, "{failure:?}");
    }
}
