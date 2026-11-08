//! `landfall`: command-line client for the landfall API, as a library behind a thin
//! binary, so that its tests can reach what a command does.

mod access;
pub mod agent_release;
pub mod api_client;
pub mod cli;
pub mod display;
pub mod host;
pub mod project;
pub mod read;
pub mod settings;
pub mod verify;
mod whoami;

pub use access::AccessError;
