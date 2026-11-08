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
- `landfall-api` (`crates/api`): the wire types of `/api/v1`, which the controller serialises
  and the CLI reads. No I/O: `requests`, `deployments` (who am I, and the deployments, with
  `DeploymentRef`, which never names one the reader can't view), `releases` (a deployment's
  releases and `ReleaseStory`, with the commits a release brings), `deploys` (a deploy, its
  steps and `Why`), `hosts`, `audit` (a row of the log as a principal may see it), `problem`
  (`Problem` and its stable `ProblemCode`s), `page` and `raw` (`RawJson`, the audit row's and a
  deploy step's `detail` kept as their JSON text, never as a tree). Each enum that can grow has
  an `Unknown` for a value from a newer controller, which no controller sends. Its `openapi`
  feature derives each type's schema, and only the controller enables it.
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
  the Sigstore stack or the network: build-provenance bundles, for an image digest
  or a named release file (`attestation/file.rs`, the name and digest checked
  together), and their Fulcio certificate identity, the TUF trust root, and the
  fetchers for
  signed tag objects, a repository's tags, a release's files and the commits between two
  commits (`fetch/commits.rs`, GitHub's compare, a page at a time) (GitHub API), image
  indexes, bundles and referrer tags (GHCR), `verify_release`, which composes them for
  one release, `candidates`, which finds every digest attested for it, and `artifact`,
  whose `verify_release_file` returns one file of a release once its signed tag, the
  release's sums and the attestation all agree on it. Its `test-support` feature,
  which only dev-dependencies may enable, adds plain-http endpoints and a trust root
  from a snapshot, for another crate's tests against mock servers.
- `landfall-server` (`crates/server`): the controller. Watches releases,
  verifies origin, evaluates rules, runs approval ceremonies, keeps state and
  the audit log, serves the API and the web UI. A library plus a thin binary;
  modules: `store` (the only code that touches SQLite: migrations, transactions, appending to
  and verifying the audit log, enrolment codes, hosts, nonces, deploys, running state, release
  decisions and holds, API tokens, sessions, deploy requests, `commits`, the commit ranges
  between verified releases, `views`, what the API reads to show deployments, `history`, what
  it reads of releases, their requests and deploys, and deploys' steps, and `latest`, each
  deployment's latest release, kept where releases are recorded, in `highest_releases` and
  `first_tags`), `audit` (audit events and the hash-chain encoding), `report` (bounding a
  deploy report before it is stored), `agent_api` (the routes agents call: signed-request
  extractor, handlers, problem answers, rate limit, and `client_source`, who a request is from,
  which every per-source limit and the capped log go by), `auth` (the `Principal` extractor,
  which makes the exact-`Origin` check on a session's state change and the `Sec-Fetch-Site`
  check on its read, `can`, the one place that says what a principal may do, each credential's
  budgets for state changes and for reads, secrets that are only stored hashed, and the human
  API's problem answers), `api` (`/api/v1`: one `OpenApiRouter` registers each route with its
  annotation, `ApiJson` is every success, `query` the path and query-string parameters, a query
  string refusing any it doesn't take, with a page's `Limit` and its `Cursor`, `visible`, the
  one place that says what a principal may be told of a deployment (404 or 403, and a deployment
  shown or unseen), `deployments`, who am I and the deployments, `releases`, a deployment's
  releases and one's story, `story`, the one pure function that says where a release stands and
  why, `deploys`, the deploys and `why` of one, `why`, the pure function that explains a deploy,
  `hosts`, the hosts seen through their deployments, `audit` (and `audit/detail`, what a row shows
  of its detail and host to one principal), the log as far as a principal may see it, and
  `openapi` the document's fixed part: its schemes and shared refusals; the document is served at
  `/api/v1/openapi.json`, printed by `openapi` and checked in as `docs/api/openapi.json`, which a
  test compares: regenerate it with `cargo run -p landfall-server -- openapi >
  docs/api/openapi.json`, never edit it by hand),
  `requests` (the human API's routes: `asking` for a deploy, `approving` one and `cancelling`
  one), `web` (the browser's side: the static pages and their one script, the security headers
  on every answer, `registration`, `sign_in` and sign-out, and `ceremonies`, the challenges and
  failure counts in memory), `watcher`
  (release discovery, origin verification, rule decisions and queueing, behind a
  `ReleaseSource` trait, and `commits`, which fetches the commits between verified releases
  after each tick, within GitHub's budget),
  `serve` (the accept loop, with header timeouts and a connection cap), `logger` (the only code
  that writes to stderr while serving: a bounded queue to a thread of its own, which drops and
  counts what doesn't fit, so that logging never blocks a runtime thread; `panics`, the hook
  `serve` sends panics to it by; and `gate`, a stderr for tests that takes nothing until opened),
  `cli`
  (`serve`, `enrol-code`, `token`, `passkey-invite`, `backup`, `audit verify`, `audit
  show`, `openapi`, behind the thin `main.rs`).
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
  `cli::run_watching` and `run_watching_within` take a fake verifier and source, for the
  end-to-end tests; nothing on a command line leads to them.
- `landfall-cli` (`crates/cli`, binary `landfall`): API client for humans and
  agents. A library plus a thin binary; modules: `cli` (the command line, exit
  statuses, `ApiArgs`, the API flags each API command flattens, never global, since `host
  install` has its own `--controller`, and `run_with`, the library entry, which prints every
  failure through `display::safe`), `settings` (where the controller is and which token goes
  to it: flags, then the environment, then `cli.toml`; the token never in argv, a token file
  regular, not a link, owned by the user and theirs alone, and with no token no `Authorization`
  header, for warden), `api_client` (`/api/v1` with the token: no
  proxy from the environment, no redirect followed, bodies capped, `ApiError` and its exit
  status, `segment`, the one way a value goes into a path, and the `Api` trait the commands
  call it through, so tests can use a fake), `display` (`safe` and `write_json`, which escape
  controls, bidi and invisible characters, and `safe` doubles a backslash, in whatever the
  controller sent before a terminal sees it), `whoami` (`landfall whoami`), `read` (`status`,
  `history`, `release`, `releases`, `why`, `hosts`, `audit` and `approvals`, over `Api`, used
  generically; `status` pages within
  1,000 deployments, 20 pages or 8 MiB of answers, the others make at most three calls;
  answers are kept as text, never as a JSON tree; `render`, each view for a person, every
  server string escaped), `ask` (`request deploy`, `rollback`, which says it means one, and
  `cancel`; each prints where an approver signs, as agents can't), `verify`
  (`landfall verify`), `access` (the trust root's cache and the operator's token), `project`
  (what landfall trusts about its own releases: its repository, ids and workflow as constants,
  and `assets/release-signers`, read by the
  same rule as `release_preflight.py`, whose test keeps the keys in the two test tables
  equal), `agent_release` (the names of an agent's files, and `AgentSource`, which
  `GitHubReleases` implements by that trust), and `host` (`host install` and `host upgrade`:
  `facts`, what a read-only probe of the target says and whether it's fit; `shell`, the only way a
  value reaches a script; `unit`, the systemd units as the guide has them; `plan`, the script that
  runs as root; `ssh`, the system's `ssh`, its forced options and one connection; and `install` and
  `upgrade`). Their `run_with` takes a fake source and remote, for the tests, and nothing on a
  command line leads to them.

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
- BuildKit, which every binary is built inside, is pinned by digest in each
  `docker/setup-buildx-action` step (`driver-opts`, with `cache-binary: false`).
  Dependabot can't read that, so `.github/buildkit/Dockerfile` holds the same
  reference and is never built. To bump it, take Dependabot's pull request and put
  the same line in the workflows: `test_buildkit_pin.py` fails until they agree.
- The Dockerfile's `binaries` stage holds static `landfall-agent`, `landfall` and
  `landfall-server`, from the image's own builder. `docker-build` builds it on
  every PR (`docker buildx build --target binaries --platform
  linux/arm64,linux/amd64 --provenance=false --sbom=false --output
  type=local,dest=dist .`) and publishes nothing. `check_binaries.py` then wants
  each to be a static PIE (`ET_DYN`, `DF_1_PIE`, no `PT_INTERP`, `DT_NEEDED` or text
  relocations) for its directory's architecture, whole, with arm64 load segments
  that suit a kernel with 16 KiB pages, mode 0755, and a size within its
  `MAX_BYTES` budget. PIE comes from `RUSTFLAGS` in the Dockerfile's builder, as
  `.cargo/` stays out of the build and a profile can't set it.
- zig, which is the C compiler and linker, is upstream's tarball, by `ADD --checksum`
  for each platform a build runs on, so no package repository can change it. Dependabot
  can't bump it: take the hashes from `index.json` at ziglang.org and verify each file's
  `.minisig` against the key published there. CI also runs the arm64 binaries' `--version`
  under the QEMU in the pinned BuildKit image, which is a third copy of that reference.
- `macos.yml` tests and builds the CLI on an arm64 Mac, only when a change can
  reach it. It is filtered by path, so it can't be a required check, and isn't.
- `crate-age` refuses `Cargo.lock` versions younger than 7 days (README,
  "Dependency age"). Pin an older version with
  `cargo update -p <crate> --precise <version>`; allow-list entries are only
  for security fixes and must name a RUSTSEC or GHSA id.
- Releases come from signed `v*` tags on main (`git tag -s`). `release.yml` reruns
  CI and crate-age, builds with no cache, and publishes in one job, `publish`, with no
  environment and no approval: the tag's signature is the only gate, as a stolen token
  could approve a deployment through the API but can't forge the signature. The owner
  signs the tag with `scripts/release-tag <version> --commit <sha>`, which agents never run,
  and which refuses without a terminal: it shows the range since the last signed release
  and any change to the signers file, `.github/`, itself and `Cargo.*`, refuses a signers
  change without `--signers-change`, and wants the version typed. Its tests are
  `test_release_tag.py`, with the terminal injected. `CONTRIBUTING.md` has the procedure, and
  `test_release_workflow.py` holds what the workflow must keep doing: edit the two
  together.
- **The dry run:** a push to main that changes `workspace.package.version`, and a
  `workflow_dispatch` run, build and check everything a tag does, but skip `preflight`
  and `publish`, so they attest nothing. The `version` job decides, with
  `version_bump.py` against `github.event.before`, and `on-main` needs it, so any other
  push to main stops there. `preflight` and `publish` want
  `github.event_name == 'push' && github.ref_type == 'tag'`, and `smoke` compares
  versions only on a tag. `scripts/release-tag` refuses a commit with no full, green dry
  run.
- `smoke` and `publish` download by artifact id, which can't be rebound as a name can,
  and `publish` reruns `check_binaries.py`. macOS has no such check: `smoke` running
  those same bytes there is what stands in for it.
- **Release assets,** with these exact names, which the attestation and the CLI
  rely on: `landfall-agent-<v>-linux-{arm64,amd64}`,
  `landfall-<v>-linux-{arm64,amd64}`, `landfall-<v>-darwin-arm64`, `SHA256SUMS`,
  `landfall.rb`, `LICENSE-MIT` and `LICENSE-APACHE`, written by
  `assemble_release.py`, all subjects of one attestation, and
  `landfall-<v>.sigstore.json`, the attestation itself. The binaries are raw
  executables, so the hash a host checks is the attested one. The attest step stays
  in `release.yml`, as the verifier refuses a reusable workflow's identity.
- **The tag proof:** `release_preflight.py` reads the tag object through the API
  and has `ssh-keygen` check it against `crates/cli/assets/release-signers` at the
  tagged commit, before `publish` can run. This is what landfall's CLI
  trusts about its own binaries, and has nothing to do with a deployment's optional
  `origin.signed_tags`. A signers file with no key refuses every tag.
- **One attempt:** `preflight` and `publish` fail at once if `GITHUB_RUN_ATTEMPT` isn't 1, as
  hosts refuse a release attested by two attempts and a tag can't be moved. The way
  out of any failed run is a version bump and a new tag.
- **Homebrew:** landfall holds no token for the tap and runs nothing for it. The tap's own
  scheduled workflow reads the latest stable release, verifies it with the tap's script and
  key, and opens a pull request that merges itself when green. `assemble_release.py` writes
  the formula, which `brew style` must accept (`on_macos` may not hold `url`).
- The last step of `publish` sends the tag with `draft=false`, as the API can otherwise
  publish with no tag, and reads the release back: not a draft, this tag, immutable. A
  failure there may mean a public release, so it's checked by hand. The draft is found by
  the URL `gh` printed, polling for about 2 minutes, as the listing can lag.
- `crate_age.py` tries a lookup up to 5 times on a 429, a 5xx or a network error, honouring
  `Retry-After` up to a minute, and not on a 404.
- `check-bundle` reads a bundle's shape only: `gh attestation verify` checks the
  signature and identity, in `publish`, on every file, before the draft exists. These
  scripts run under `python3 -I`, so they can't import each other, and tests keep
  what they share equal. CI sets `LANDFALL_TEST_REQUIRE_RUBY`, so the formula's
  `ruby -c` test can't skip there.
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

`crates/cli/tests/docker_host_install/` runs `host install` over the real `ssh`, against a real
`sshd`, systemd, `sudo` and the real agent and controller, in a throwaway container with no host
mounts. Those are `#[ignore]`d and named `docker_` too, and don't run in the normal suite: CI's
`host-install` job runs them, and so should you by hand after changing `crates/cli/src/host/`. They
need Docker, `ssh`, `ssh-keygen`, `pgrep`, `nc`, the image `landfall-test-sshd`, and the binaries for this
machine's platform in `LANDFALL_TEST_DIST`, and panic saying what to run if one is missing. The
`README.md` there has the commands, why each container flag, and what they can't show.

Tests against the real GitHub, GHCR and Sigstore are `#[ignore]`d and named with a
`live_` prefix, which is how the nightly job in `advisories.yml` selects them: `live_`
must not appear in the name of any other test.

`crates/agent/tests/e2e/` runs the controller and the agent together as real
processes, over loopback and a real SQLite file. The agent has `landfall-server` as a
dev-dependency for it; the server depends on nothing of the agent's. `e2e/approvals/` is a
person's way through it, with a software passkey over the real routes, and has the controller lie by
writing to its own database: a host's refusal is the point of those.

`crates/cli/tests/controller/` runs `landfall` through `cli::run_with` against a real controller
in the test's runtime: the server's router and accept loop on loopback, a SQLite file, real tokens
and a real passkey sign-in with the software authenticator. What the watcher and a host would say is
written through the store's own functions, so it needs neither Docker nor the network and runs in
the normal suite. The CLI has `landfall-server` as a dev-dependency for it.

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
