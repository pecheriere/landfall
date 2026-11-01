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
- `landfall-origin` (`crates/origin`): release origin verification that needs
  the Sigstore stack or the network: build-provenance bundles and their
  Fulcio certificate identity, the TUF trust root, and the fetchers for
  signed tag objects (GitHub API), image indexes and bundles (GHCR), and
  `verify_release`, which composes them for one release.
- `landfall-server` (`crates/server`): the controller. Watches releases,
  verifies origin, evaluates rules, runs approval ceremonies, keeps state and
  the audit log, serves the API and the web UI.
- `landfall-agent` (`crates/agent`): runs on every target host. Pulls work
  from the controller, verifies again against its local configuration,
  deploys, checks, rolls back. A library plus a thin binary; modules:
  `state` (the agent's own directory: deployed and in-progress records,
  the previous override, reports, a per-deployment lock), `safefs` (the only
  code that may touch a directory a container can write to: no-follow walking
  by directory descriptor, atomic write, snapshot, restore, prune),
  `docker` (the only code that runs the Docker CLI, behind a trait), `compose`
  (the override file the agent owns, compose directory resolution), `checks`
  (post-deploy checks: health, HTTP probe, command, log window), `deploy` (the
  sequence, rollback and recovery, recording every step in a report), `journal`
  (the only code that writes to stderr: syslog-prefixed JSON lines).
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

## Testing rules

Tests specify behavior; no tests that restate implementation or exist for
coverage.

## Security review

Required before merge for changes to origin verification, approvals,
authentication, grants, the agent's host access or outbound HTTP. Run the
`security-review` skill or an equivalent review and record the findings in
the PR.

## Definition of done

Formatting, clippy, tests and `cargo deny check` are all green, and the docs
are updated to match the change.
