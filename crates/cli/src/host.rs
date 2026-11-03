//! `landfall host`: what puts an agent on a host, over the operator's own SSH.
//!
//! Everything here is pure: [`facts`] reads what a read-only probe of the target printed,
//! [`mod@unit`] renders the systemd units, and [`plan`] the one script that runs as root. What
//! the target prints is hostile, and what is rendered runs as root, so [`shell`] is the only
//! way a value reaches a script.

pub mod facts;
pub mod plan;
pub mod shell;
pub mod unit;

#[cfg(test)]
mod tests;
