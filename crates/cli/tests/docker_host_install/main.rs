//! `host install` against a real `sshd`, real systemd, `sudo` and `useradd` in a throwaway
//! container, with the real agent and controller from `LANDFALL_TEST_DIST`. All of it is
//! `#[ignore]`d. `README.md` here says what they need, how to run them, and what they can't show.

#![cfg(test)]

mod connection;
mod harness;
mod install;
mod interrupts;
