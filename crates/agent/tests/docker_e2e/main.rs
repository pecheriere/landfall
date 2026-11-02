//! The deploy engine and the binary against a real Docker daemon. All of it
//! is `#[ignore]`d, and runs with
//! `cargo test -p landfall-agent --all-features --locked -- --ignored docker`.
//!
//! The images are public and multi-platform, on the registry the agent deploys
//! from, each pinned by the digest of its index: tags 1.36 and 1.28 of
//! `ghcr.io/containerd/busybox`, a copy of busybox, whose `sh`, `sleep` and
//! `httpd` serve as the service.
//!
//! Which tests need what:
//!
//! - `docker_foreign_owner_*` needs root, as the agent's capabilities would
//!   give it, and Linux, whose bind mounts keep the owner a container sets. It
//!   skips otherwise, unless `LANDFALL_TEST_REQUIRE_ROOT` is set, as it is in
//!   CI, which makes that a failure. The others run as any user who can reach
//!   Docker: their containers run as that user, so the data stays readable.
//! - `docker_http_*` needs Linux: the host must reach a Docker bridge network,
//!   which a Mac's Docker cannot give it.

#![cfg(test)]

mod deploys;
mod harness;
#[cfg(target_os = "linux")]
mod linux;
mod refusals;
mod rollbacks;
mod status;

#[path = "../support/compose_project.rs"]
mod compose_project;
