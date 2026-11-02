# AGENTS.md

## Purpose

landfall is continuous delivery for self-hosters: it watches GitHub releases,
verifies where each one came from, and deploys it to Docker Compose hosts
with health checks and automatic rollback, under per-deployment rules and
passkey approvals. Agents drive it through a typed API. Design:
`docs/design/landfall.md`.

## Crate map

- `landfall-core` (`crates/core`): shared library with no I/O: validated
  identifiers, configuration types and the pure verification and rule logic.
- `landfall-approval` (`crates/approval`): verifies a WebAuthn assertion against
  a key from local configuration, and parses an attestation, trusting none of it,
  for its key.
  No I/O: `cose` (COSE keys, ES256 and EdDSA only), `client_data`,
  `authenticator_data`, `assertion`, `registration`, `config` (`parse_config`, how
  every binary loads a configuration: core takes this crate's key check as a
  required argument, because the check needs cryptography core doesn't link, and
  clippy refuses a direct call to core's `parse`), and
  `software`, a software authenticator for tests, behind the `test-support`
  feature, which only dev-dependencies may enable, as a step in CI checks.
- `landfall-origin` (`crates/origin`): release origin verification that needs
  the Sigstore stack or the network: build-provenance bundles and their
  Fulcio certificate identity, the TUF trust root, and the fetchers for
  signed tag objects, a repository's tags (GitHub API), image indexes, bundles
  and referrer tags (GHCR), `verify_release`, which composes them for one
  release, and `candidates`, which finds every digest attested for it.
- `landfall-server` (`crates/server`): the controller. Watches releases,
  verifies origin, evaluates rules, runs approval ceremonies, keeps state and
  the audit log, serves the API and the web UI. A library plus a thin binary;
  modules: `store` (the only code that touches SQLite: migrations, transactions,
  appending to and verifying the audit log, enrolment codes, hosts, nonces,
  deploys, running state, release decisions and holds, API tokens, sessions, deploy
  requests), `audit` (audit events and the hash-chain encoding), `report` (bounding
  a deploy report before it is stored), `agent_api` (the routes agents call:
  signed-request extractor, handlers, problem answers, rate limit), `auth` (the
  `Principal` extractor, which makes the exact-`Origin` check for a session, `can`,
  the one place that says what a principal may do, each principal's budget for state
  changes, secrets that are only stored hashed, and the human API's problem answers),
  `requests` (the human API's routes: `asking` for a deploy, `approving` one and
  `cancelling` one), `web` (the browser's side: the static pages and their one script, the
  security headers on every answer, `registration`, `sign_in` and sign-out, and `ceremonies`,
  the challenges and failure counts in memory), `watcher` (release discovery, origin
  verification, rule decisions and queueing, behind a `ReleaseSource` trait),
  `serve` (the accept loop, with header timeouts and a connection cap), `cli`
  (`serve`, `enrol-code`, `token`, `passkey-invite`, `backup`, `audit verify`, `audit
  show`, behind the thin `main.rs`).
- `landfall-agent` (`crates/agent`): runs on every target host. Pulls work
  from the controller, verifies again against its local configuration,
  deploys, checks, rolls back. A library plus a thin binary; modules:
  `state` (the agent's own directory: deployed and in-progress records,
  the previous override, reports, a per-deployment lock, the log of used approval
  nonces; `state/` has `error`, `records`, `dir`, `deployment` and `nonces`), `safefs`
  (the only code that may touch a
  directory a container can write to: no-follow walking by directory
  descriptor, atomic write, snapshot, restore, prune; `safefs/` has `error`,
  `paths`, `files`, `snapshot`, `removal` and `copy`),
  `docker` (the only code that runs the Docker CLI, behind a trait in
  `docker.rs`; `docker/` has the `cli` driver, `process` for running commands,
  `parse` for their output, `scan`, `types` and `error`), `compose`
  (the override file the agent owns, compose directory resolution), `checks`
  (post-deploy checks: health, HTTP probe, command, log window), `deploy` (the
  sequence, rollback and recovery, drift, recording every step in a report;
  `deploy/` has `sequence`, `preflight`, `rollback`, `recovery`, `drift`,
  `report`, `error`, `files` and `offload`), `journal`
  (the only code that writes to stderr: syslog-prefixed JSON lines), `client`
  (the `Controller` trait and the signing HTTP client), `enrol` (the host's key
  and the enrolment request), `daemon` (`run`: one poll is `daemon::step`, which
  judges each work item by the host's own rule and records, verifies an approval and
  spends its nonce under the deployment's lock (`daemon/approval.rs`), deploys, and keeps
  reports in an outbox until acknowledged), `cli` (`status`, `recover`, `enrol`
  and `run`, behind the thin `main.rs`). `daemon::run_with` and the server's
  `cli::run_watching` take a fake verifier and source, for the end-to-end tests;
  nothing on a command line leads to them.
- `landfall-cli` (`crates/cli`, binary `landfall`): API client for humans and
  agents.

Central rule: the controller orchestrates, the host decides. Nothing the
controller says can make an agent run a release its local configuration does
not allow.

## Commands

```sh
cargo fmt
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
```

## CI and supply chain

- Actions are pinned to the full commit SHA of a release at least 7 days old
  (comment with the tag); `persist-credentials: false` on every checkout;
  `--locked` everywhere. Only GitHub-owned actions and the allow-listed
  third-party ones (dtolnay/rust-toolchain, Swatinem/rust-cache,
  EmbarkStudios/cargo-deny-action, zizmorcore/zizmor-action,
  ossf/scorecard-action, docker/setup-buildx-action,
  docker/build-push-action, docker/login-action, docker/metadata-action)
  may be used.
- Build caches (rust-cache, the Docker build cache) are for CI only. The
  release workflow's publish job builds without a cache.
- The Dockerfile pins the Rust base image by digest (the version in
  `rust-toolchain.toml`) and its build tools by version, each a release at
  least 7 days old; Dependabot proposes base image updates.
- `crate-age` refuses `Cargo.lock` versions younger than 7 days (README,
  "Dependency age"). Pin an older version with
  `cargo update -p <crate> --precise <version>`; allow-list entries are only
  for security fixes and must name a RUSTSEC or GHSA id.
- Releases come from signed `v*` tags on main (`git tag -s`). The release
  workflow reruns CI and crate-age, then publishes a multi-arch image to
  GHCR with a build-provenance attestation.
- Run `GH_TOKEN=$(gh auth token) uvx zizmor .` before pushing; it must report
  no findings.
- Fix, don't exempt: a failing advisory, lint or zizmor finding is fixed, not
  ignored in `deny.toml`, `#[allow]` or a zizmor config.

## Conventions

- Errors use `thiserror`; no `unwrap`/`expect` outside tests.
- Lints are strict (`unsafe_code` forbidden, clippy `all` and `pedantic` at
  deny). No `#[allow]`/`#[expect]` without a `reason = "..."`.
- The repository is public and generic: no hostnames, addresses, user names
  or other details of anyone's infrastructure in code, docs, tests or
  commit messages.
- Commits: conventional-commit subject, no AI attribution trailers.
- Keep files small: split a source file by responsibility before it passes
  about 800 lines of code, and move a large test module into its own file. When
  a change would push a file past that, split it in the same change, or track
  the split as an issue. The parts of `foo.rs`
  go in `foo/`, its tests in `foo/tests.rs` (shared fixtures) and
  `foo/tests/<scenario>.rs`, as `daemon` does. A test names what it imports
  rather than using `use super::*`.

## Testing rules

Tests specify behavior; no tests that restate implementation or exist for
coverage.

Tests against a real Docker are `#[ignore]`d and named with a `docker_` prefix,
which is how CI selects them:
`cargo test -p landfall-agent --all-features --locked -- --ignored docker`.
`docker_e2e/main.rs` lists what each needs. The `foreign_owner` tests need root and
skip without it, unless `LANDFALL_TEST_REQUIRE_ROOT` is set, as it is in CI, which
makes that a failure.

Tests against the real GitHub, GHCR and Sigstore are `#[ignore]`d and named with a
`live_` prefix, which is how the nightly job in `advisories.yml` selects them: `live_`
must not appear in the name of any other test.

`crates/agent/tests/e2e/` runs the controller and the agent together as real
processes, over loopback and a real SQLite file. The agent has `landfall-server` as a
dev-dependency for it; the server depends on nothing of the agent's.

`crates/server/tests/browser/` drives the web pages in a real browser with Chromium's virtual
authenticator. It is `#[ignore]`d and named with a `browser_` prefix, and needs Node, `openssl`
and Playwright, so CI doesn't run it: run it by hand after changing a page or the policy. Its
`main.rs` says how. Playwright's version is pinned in its `package-lock.json`, by the same seven
days as a crate.

### Linux tests on a Mac

Some tests only run on Linux (symlink owners and times through `O_PATH`). Run
them in the toolchain's image:

```sh
docker run --rm -v "$PWD":/src:ro -v landfall-linux-target-<checkout>:/target \
  -v landfall-linux-cargo:/usr/local/cargo/registry -e CARGO_TARGET_DIR=/target \
  -w /src rust:1.99-bookworm \
  sh -c 'cargo test -p landfall-agent --locked 2>&1 | grep -E "test result|FAILED|panicked|^error"'
```

The target volume must be private to one checkout: with one shared between
worktrees, the mtimes cargo compares can make it reuse a binary built from another
checkout's source, which proves nothing about this one.

## Security review

Required before merge for changes to origin verification, approvals,
authentication, grants, the agent's host access or outbound HTTP. Run the
`security-review` skill or an equivalent review and record the findings in
the PR.

## Definition of done

Formatting, clippy, tests and `cargo deny check` are all green, and the docs
are updated to match the change.
