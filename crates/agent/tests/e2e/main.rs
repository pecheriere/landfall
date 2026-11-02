//! The controller and the agent together: real processes, real signals, real
//! HTTP on loopback and a real `SQLite` file, in the order an operator meets them.
//!
//! What runs as what:
//!
//! - The controller is this test binary run again as `landfall_server::cli::run`,
//!   the whole of what its `main` does, or as `run_watching`, the same with a
//!   [`world::FileSource`] for the watcher: no test repository signs real releases.
//! - The agent is the real `landfall-agent` binary for `enrol`, and
//!   `landfall_agent::daemon::run_with` with a [`world::FileVerifier`] and a
//!   [`world::SimDocker`] for the cases that deploy, for the same reason. Both fakes
//!   read files, so a test changes the world they see while the processes run, and a
//!   process that is restarted finds it as it was.
//! - `binaries.rs` runs the real `serve` and `landfall-agent run`, which go through
//!   the real source and verifier, as far as is possible with no network. `live.rs`
//!   runs them on a real release, and `docker.rs` runs `run_with` on a real Docker.
//!
//! This binary runs itself, rather than a helper binary of the crate, so that nothing
//! with a fake verifier can ever be built into a package.

#![cfg(test)]

mod binaries;
mod docker;
mod flow;
mod harness;
mod live;
mod outage;
mod restart;
mod rollback;
mod seams;
mod world;

/// Not a test: what [`harness`] runs as a process. It does nothing without its
/// variable, so that `--ignored` finds nothing wrong with it.
#[test]
#[ignore = "not a test: the end-to-end tests run this as a process"]
fn child_process() {
    if let Ok(spec) = std::env::var(harness::CHILD_SPEC) {
        std::process::exit(harness::run_child(&spec).into());
    }
}
