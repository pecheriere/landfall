//! `landfall`: command-line client for the landfall API, as a library behind a thin
//! binary, so that its tests can reach what a command does.

mod access;
pub mod agent_release;
pub mod cli;
pub mod host;
pub mod project;
pub mod verify;

pub use access::AccessError;
