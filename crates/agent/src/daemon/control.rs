//! What paces the daemon: the stop signal and the backoff.

use std::io;
use std::time::{Duration, Instant};

use landfall_core::protocol::ReportedOutcome;
use serde::Serialize;
use tokio::signal::unix::{SignalKind, signal};
use tokio::sync::watch;

use super::StepOutcome;
use crate::journal::{self, Priority};

/// Tells the daemon to stop. A deploy in flight finishes first.
#[derive(Debug, Clone)]
pub struct Shutdown(watch::Receiver<bool>);

/// The sending side of a [`Shutdown`].
#[derive(Debug)]
pub struct ShutdownTrigger(watch::Sender<bool>);

impl ShutdownTrigger {
    /// Asks the daemon to stop.
    pub fn stop(&self) {
        // Nobody listening means the daemon is gone already.
        let _ = self.0.send(true);
    }
}

impl Shutdown {
    /// A pair: the trigger, and what the daemon goes by.
    #[must_use]
    pub fn channel() -> (ShutdownTrigger, Self) {
        let (sender, receiver) = watch::channel(false);
        (ShutdownTrigger(sender), Self(receiver))
    }

    /// Stops on SIGTERM or SIGINT.
    ///
    /// # Errors
    ///
    /// When the signal handlers cannot be installed.
    pub fn on_signals() -> io::Result<Self> {
        #[derive(Serialize)]
        struct Stopping {
            event: &'static str,
        }
        let mut terminate = signal(SignalKind::terminate())?;
        let mut interrupt = signal(SignalKind::interrupt())?;
        let (trigger, shutdown) = Self::channel();
        tokio::spawn(async move {
            tokio::select! {
                _ = terminate.recv() => {}
                _ = interrupt.recv() => {}
            }
            journal::emit(
                Priority::Info,
                &Stopping {
                    event: "agent_stopping",
                },
            );
            trigger.stop();
        });
        Ok(shutdown)
    }

    pub(super) fn requested(&self) -> bool {
        *self.0.borrow()
    }

    /// Returns once a stop is asked for; never, if the trigger is gone.
    pub(super) async fn wait(&self) {
        let mut receiver = self.0.clone();
        if receiver.wait_for(|stop| *stop).await.is_err() {
            std::future::pending::<()>().await;
        }
    }
}

/// How long to wait after each step. A poll that found nothing goes again soon,
/// and only a release that deployed, or a long enough quiet, resets the backoff.
/// Everything else makes it grow: a refusal or a rollback that is reported well
/// must not be able to repeat every second, however the controller mixes them
/// with answers of no work.
#[derive(Debug, Clone)]
pub struct Pacing {
    floor: Duration,
    backoff: Backoff,
    quiet_after: Duration,
    last_trouble: Option<Instant>,
}

impl Pacing {
    /// `floor` between polls that are fine; `backoff` while they aren't, until
    /// `quiet_after` has gone by without trouble.
    #[must_use]
    pub fn new(floor: Duration, backoff: Backoff, quiet_after: Duration) -> Self {
        Self {
            floor,
            backoff,
            quiet_after,
            last_trouble: None,
        }
    }

    /// The wait after `outcome`, at `now` by the monotonic clock.
    pub fn after(&mut self, outcome: &StepOutcome, now: Instant) -> Duration {
        match outcome {
            StepOutcome::NoWork => {
                let quiet = self
                    .last_trouble
                    .is_none_or(|last| now.duration_since(last) >= self.quiet_after);
                if quiet {
                    self.backoff.reset();
                }
                self.floor
            }
            StepOutcome::Finished {
                outcome: ReportedOutcome::Deployed {},
                delivered: true,
                ..
            } => {
                self.backoff.reset();
                self.last_trouble = None;
                self.floor
            }
            _ => {
                self.last_trouble = Some(now);
                self.backoff.next_delay()
            }
        }
    }
}

/// What a backoff waits for: doubling from `min` up to `max`, each wait drawn
/// between half of that and all of it, so that hosts that failed together don't
/// come back together.
#[derive(Debug, Clone)]
pub struct Backoff {
    min: Duration,
    max: Duration,
    next: Duration,
}

impl Backoff {
    /// A backoff from `min` to `max`.
    #[must_use]
    pub fn new(min: Duration, max: Duration) -> Self {
        Self {
            min,
            max,
            next: min,
        }
    }

    /// The next wait, and a longer one after it.
    pub fn next_delay(&mut self) -> Duration {
        let full = self.next;
        self.next = (self.next * 2).min(self.max);
        // Without a random number the wait is simply the longest.
        let draw = getrandom::u32().unwrap_or(u32::MAX);
        full / 2 + (full / 2).mul_f64(f64::from(draw) / f64::from(u32::MAX))
    }

    /// Back to the shortest, after something went well.
    pub fn reset(&mut self) {
        self.next = self.min;
    }
}
