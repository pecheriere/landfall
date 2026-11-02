//! The landfall agent: deploys verified releases to compose services on its
//! host. The binary in `main.rs` is a thin command-line front end.

pub mod checks;
pub mod cli;
pub mod client;
pub mod compose;
pub mod daemon;
pub mod deploy;
pub mod docker;
pub mod enrol;
pub mod journal;
pub mod safefs;
pub mod state;
#[cfg(test)]
pub mod testing;
