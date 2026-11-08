//! `landfall` against a real controller over loopback: the server's real router and accept
//! loop, a real SQLite file, real tokens and a real passkey sign-in. Nothing here needs Docker
//! or the network, so it runs in the normal suite. `harness` says what is real and what is
//! written straight to the store.

#![cfg(test)]

mod flow;
mod harness;
