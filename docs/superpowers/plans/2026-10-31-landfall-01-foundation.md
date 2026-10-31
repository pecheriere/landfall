# landfall plan 01: Foundation (config, rules, deploy intents) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A pure, I/O-free `landfall-core` crate that parses and validates the fleet configuration, decides what a rule allows for a candidate version, and produces the canonical deploy intent and its approval challenge, which every later part (controller, agent, CLI) builds on.

**Architecture:** One new library crate, `crates/core`, with one module per concern: validated identifiers, configuration, rule decisions, deploy intents. No network, filesystem, clock or randomness inside it: callers pass bytes and values in. The three binaries don't use it yet; plans 02+ do.

**Tech Stack:** Rust 1.99 (edition 2024), serde 1.0.229 (derive), toml 0.9.8, semver 1.0.28, sha2 0.11.1, hex 0.4.3, thiserror 2.0.21. If any of these is younger than 7 days when you add it, `crate-age` fails: pick the newest version it accepts (`python3 -I .github/scripts/crate_age.py --base main`).

**Spec:** `docs/design/landfall.md` (sections 5.1, 6.1, 6.2, 6.3, 8.2).

## Roadmap (later plans, one PR each, written when the previous one merges)

| Plan | Delivers |
|---|---|
| 01 Foundation (this) | `landfall-core`: config, rule decisions, deploy intents |
| 02 Origin verification | tag signature (SSH) verification, Sigstore bundle + Fulcio identity checks, TUF trust root, "exactly one digest" rule |
| 03 Agent deploy engine | compose override, `docker compose` driver, checks, symlink-safe backup/restore, rollback, journald logging |
| 04 Controller core | SQLite state + hash-chained audit, release watcher, agent protocol (Ed25519-signed agent requests), deploy orchestration |
| 05 Approvals and grants | passkey registration and assertions, host-side verification, API tokens, grants |
| 06 API + CLI | OpenAPI v1, `why`, `landfall` CLI |
| 07 Web UI | design language (Bobbin the otter), pages from the spec |
| 08 Logs and notifications | VictoriaLogs queries per deploy, webhook notifications |

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace `edition = "2024"`; the workspace lints in `Cargo.toml` apply (`unsafe_code = "forbid"`, clippy `all` + `pedantic` denied, `unwrap_used`, `expect_used`, `print_stdout`, `print_stderr`, `todo`, `dbg_macro` denied; tests may unwrap per `clippy.toml`). No `#[allow]`/`#[expect]` without `reason = "..."`.
- `landfall-core` performs no I/O, reads no clock and draws no randomness.
- Every config struct uses `#[serde(deny_unknown_fields)]`: a typo in the config is an error, never ignored.
- Errors are `thiserror` enums; every validation error names the deployment id (or section) and the offending value, so an operator can fix the file from the message alone.
- Full gate before each commit: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --all-features --locked && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked && cargo deny --all-features --locked check`.
- Build output goes wherever your `CARGO_TARGET_DIR` points; never commit machine-specific paths.
- Public, generic repository: no hostnames, addresses or user names of any real deployment in code, docs or tests (use `example/app`, `home-1`, `maintainer`, `operator`).
- Commits: conventional-commit subject, no `Co-Authored-By`, `Claude-Session` or "Generated with" trailers.
- Tests specify behaviour; none restate the implementation or exist for coverage.

## Review Focus

1. **A pre-release candidate (`v1.3.0-rc.1`) under a rule without `prereleases = true`** is refused with reason "prerelease", never auto-deployed, and never treated as higher than `v1.3.0`'s predecessor by accident → Task 3 `prerelease_is_refused_unless_opted_in`.
2. **The same or an older version** never deploys automatically: equal is refused ("already running"), lower needs a manual request plus approval → Task 3 `equal_is_refused_and_lower_is_manual`.
3. **The first deploy of a deployment (nothing running)** is never automatic → Task 3 `first_deploy_is_manual`.
4. **Tags that only look like versions** (`v1.2`, `v01.2.3`, `1.2.3` when the prefix is `v`, `v1.2.3+build`, `release-1.2.3`) are rejected by `parse_tag` with a reason, and `v1.2.3+build` is rejected (build metadata would let two tags compare equal) → Task 1 `tags_that_only_look_like_versions_are_rejected`.
5. **An intent field containing a quote, newline or non-ASCII character** cannot make two different intents produce the same challenge → Task 4 `distinct_intents_never_share_a_challenge`.

---

### Task 1: Crate and validated identifiers

**Files:**
- Create: `crates/core/Cargo.toml`, `crates/core/src/lib.rs`, `crates/core/src/ids.rs`
- Modify: `Cargo.toml` (members += `crates/core`; workspace deps `landfall-core = { path = "crates/core" }`, `serde`, `toml`, `semver`, `sha2`, `hex`, `thiserror`), `.dockerignore` (unchanged pattern already covers `crates/`), `Dockerfile` (copy `crates/core/Cargo.toml` and stub `crates/core/src/lib.rs` in the dependency layer, add `-p landfall-core` to the `cargo clean`), `AGENTS.md` (crate map gains `landfall-core`)

**Interfaces:**
- Produces, all in `landfall_core::ids`, each a newtype with `FromStr`, `Display`, `AsRef<str>`, serde (de)serialisation through `FromStr` (so an invalid value fails config parsing), `Debug`, `Clone`, `PartialEq`, `Eq`, `Hash`:
  - `DeploymentId`: `<name>/<stage>`, each part `[a-z0-9][a-z0-9-]{0,62}`.
  - `HostId`, `PrincipalId`: `[a-z0-9][a-z0-9-]{0,62}`.
  - `RepoName`: `<owner>/<repo>`, GitHub rules: owner `[A-Za-z0-9-]{1,39}`, repo `[A-Za-z0-9._-]{1,100}`, repo not `.` or `..`.
  - `ImageDigest`: exactly `sha256:` + 64 lowercase hex.
  - `CommitSha`: exactly 40 lowercase hex.
  - `TagPattern`: config syntax `"<prefix>*"`, prefix `[A-Za-z0-9._/-]{0,32}` (e.g. `"v*"`, `"*"`); method `fn parse_tag(&self, tag: &str) -> Result<semver::Version, TagError>`: strip the literal prefix, then parse strict semver (`semver::Version::parse`), then refuse build metadata.
- `IdError` (one variant per type, carrying the rejected text) and `TagError { tag: String, reason: &'static str }` in `ids`.

- [ ] **Step 1: Write the failing tests** in `crates/core/src/ids.rs` (`#[cfg(test)] mod tests`):
  - `ids_accept_valid_values`: `"app/prod".parse::<DeploymentId>()` ok; `"example/app".parse::<RepoName>()` ok; `ImageDigest` of `"sha256:" + "a".repeat(64)` ok; `CommitSha` of `"0123456789abcdef0123456789abcdef01234567"` ok.
  - `ids_reject_invalid_values`: each errs: `DeploymentId` `"app"`, `"App/prod"`, `"app/prod/x"`, `"-app/prod"`; `RepoName` `"example"`, `"example/.."`, `"ex ample/app"`; `ImageDigest` `"sha256:" + "A".repeat(64)`, `"sha512:..."`, 63 hex; `CommitSha` 39 hex and uppercase.
  - `tags_parse_with_their_prefix`: pattern `"v*"`: `parse_tag("v1.2.3") == Version::new(1, 2, 3)`; `parse_tag("v1.3.0-rc.1")` is ok with pre `rc.1`. Pattern `"*"`: `parse_tag("1.2.3")` ok.
  - `tags_that_only_look_like_versions_are_rejected`: pattern `"v*"`: `v1.2`, `v01.2.3`, `1.2.3`, `v1.2.3+build`, `release-1.2.3` all `Err`; the `+build` error's reason mentions build metadata.
  - `invalid_ids_fail_deserialisation`: `toml::from_str::<Wrapper>("id = \"App\"")` errs, with `Wrapper { id: DeploymentId }`.
- [ ] **Step 2: Run** `cargo test -p landfall-core` → FAIL (types missing).
- [ ] **Step 3: Implement** the types above. Hand-written byte checks (no regex crate).
- [ ] **Step 4: Run** the full gate → PASS.
- [ ] **Step 5: Commit** `feat(core): validated identifiers and tag parsing`.

### Task 2: Fleet configuration

**Files:**
- Create: `crates/core/src/config.rs`, `docs/configuration.md`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: Task 1 ids.
- Produces (`landfall_core::config`):
  - `pub fn parse(text: &str) -> Result<Config, ConfigError>`: TOML parse, then `validate`. A `Config` value only exists validated.
  - `pub fn config_hash(bytes: &[u8]) -> String`: lowercase hex SHA-256 of the raw file bytes (the drift check compares these).
  - `Config { signers: BTreeMap<PrincipalId, String>, approvers: BTreeMap<PrincipalId, Approver>, deployments: Vec<Deployment>, grants: Vec<Grant> }` with `fn deployment(&self, id: &DeploymentId) -> Option<&Deployment>` and `fn deployments_for_host(&self, host: &HostId) -> impl Iterator<Item = &Deployment>`.
  - `Approver { credential_id: String, public_key: String }` (opaque base64url text; plan 05 parses them).
  - `Deployment { id, repo: Repo, host: HostId, compose: Compose, origin: Origin, rule: Rule, checks: Vec<Check>, backup: Option<Backup>, promote_to: Option<Promotion> }`.
  - `Repo { name: RepoName, id: u64, owner_id: u64 }`; `Compose { dir: String, service: String }` (`dir` absolute, no `..` component; `service` `[a-z0-9][a-z0-9_.-]*`).
  - `Origin { workflow: String, tags: TagPattern, signers: Vec<PrincipalId> }` (`workflow` starts with `.github/workflows/` and ends `.yml` or `.yaml`, no `..`).
  - `Rule { auto: Option<Level>, approve: Option<Level>, approvers: Vec<PrincipalId>, prereleases: bool }` (`prereleases` defaults false); `enum Level { Patch, Minor, Any }` (TOML `"patch" | "minor" | "any"`), ordered `Patch < Minor < Any`.
  - `enum Check { ContainerHealthy, Http { path: String, network: String, expect: u16 }, Command { argv: Vec<String> }, NoLogMatch { pattern: String, within_secs: u32 } }`; TOML forms: the string `"container-healthy"`, or a table with exactly one of the keys `http` (with `network`, `expect`), `command`, `no_log_match` (with `within_secs`).
  - `Backup { paths: Vec<String>, stop: bool }` (`stop` defaults true; paths relative, no `..`, non-empty).
  - `Promotion { deployment: DeploymentId, healthy_for_secs: u64 }`; TOML `promote_to = { deployment = "app/prod", healthy_for = "24h" }`, duration `<n>m|<n>h|<n>d`.
  - `Grant { principal: PrincipalId, deployments: Vec<DeploymentId>, can: Vec<Permission> }`, `enum Permission { View, Request, Approve, Rollback }`.
  - `ConfigError`: `Toml(String)` plus one variant per validation rule below, each carrying the deployment id or section and the value.
- Validation rules (each a `ConfigError` variant):
  1. deployment ids unique;
  2. every `origin.signers` entry exists in `[signers]` and the list is non-empty;
  3. every `rule.approvers` entry exists in `[approvers]`; non-empty whenever `approve` is set;
  4. if both set, `approve > auto` (an approval level not broader than `auto` is meaningless);
  5. `checks` non-empty;
  6. `promote_to.deployment` exists, isn't itself, and promotion chains have no cycle;
  7. every grant's deployments exist; `Approve` only for principals listed in `[approvers]`;
  8. `compose.dir` + `compose.service` unique per host (two deployments can't own one service).

- [ ] **Step 1: Write the failing tests** in `crates/core/src/config.rs`, around one `const EXAMPLE: &str` holding the spec's section 6.1 example adapted to valid values (signer `maintainer`, approver `operator`, deployments `app/prod` on `home-1` and `app/staging` promoting to `app/prod` after `24h`, one grant):
  - `example_parses`: `parse(EXAMPLE)` ok; `app/prod`'s rule is `auto = Some(Patch), approve = Some(Minor)`; `app/staging`'s promotion is `healthy_for_secs == 86_400`; `deployments_for_host("home-1")` yields both.
  - `unknown_fields_are_errors`: EXAMPLE with `rul = { auto = "patch" }` added to a deployment errs, and the message contains `rul`.
  - `each_validation_rule_is_enforced`: one case per rule 1–8, each a minimal edit of EXAMPLE, asserting the matching `ConfigError` variant and that its `Display` names the deployment id.
  - `checks_parse_in_both_forms`: `checks = ["container-healthy", { http = "/health", network = "app", expect = 200 }, { command = ["/app", "healthcheck"] }, { no_log_match = "panicked", within_secs = 30 }]` parses to the four variants; `{ http = "/h", command = ["x"] }` errs.
  - `config_hash_is_sha256_hex`: `config_hash(b"")` equals `"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"`.
- [ ] **Step 2: Run** `cargo test -p landfall-core config` → FAIL.
- [ ] **Step 3: Implement.** Deserialise into private raw structs, then convert and validate into the public types (so `Config` can't be built unvalidated).
- [ ] **Step 4: Write `docs/configuration.md`**: every key, its type, default and meaning, the validation rules in plain words, and the example (same values as the test's EXAMPLE). Link it from README "Status".
- [ ] **Step 5: Run** the full gate → PASS.
- [ ] **Step 6: Commit** `feat(core): fleet configuration parsing and validation`.

### Task 3: Rule decisions

**Files:**
- Create: `crates/core/src/rule.rs`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: `config::{Rule, Level}`.
- Produces (`landfall_core::rule`):
  - `pub fn decide(rule: &Rule, running: Option<&semver::Version>, candidate: &semver::Version) -> Decision`
  - `enum Decision { Auto, NeedsApproval, Manual, Refused(Refusal) }`; `enum Refusal { Prerelease, AlreadyRunning }`. `Decision::needs_approval(&self) -> bool` is true for `NeedsApproval` and `Manual`.
- Semantics (spec 6.2): pre-release candidate without `prereleases` → `Refused(Prerelease)`; equal → `Refused(AlreadyRunning)`; nothing running → `Manual`; lower → `Manual`; higher: let `part` = `Patch` if major and minor equal, `Minor` if major equal, else `Any`; `Auto` if `auto >= part`, else `NeedsApproval` if `approve >= part`, else `Manual`.

- [ ] **Step 1: Write the failing tests** (table-driven, `rule(auto, approve)` helper):
  - `higher_versions_follow_the_levels`: with `auto = Patch, approve = Minor`, running `1.2.3`: `1.2.4` → Auto; `1.3.0` → NeedsApproval; `2.0.0` → Manual. With `auto = Any`: `2.0.0` → Auto. With neither set: `1.2.4` → Manual.
  - `equal_is_refused_and_lower_is_manual`: running `1.2.3`: `1.2.3` → `Refused(AlreadyRunning)`; `1.2.2` → Manual even with `auto = Any`.
  - `first_deploy_is_manual`: running `None`, `auto = Any` → Manual.
  - `prerelease_is_refused_unless_opted_in`: running `1.2.3`, candidate `1.3.0-rc.1`, `auto = Any`: `Refused(Prerelease)`; with `prereleases = true` → Auto. Running `1.3.0-rc.1`, candidate `1.3.0`, `auto = Patch`, `prereleases = true` → Auto (same major.minor, higher).
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full gate → PASS.
- [ ] **Step 5: Commit** `feat(core): rule decisions for candidate versions`.

### Task 4: Deploy intents and approval challenges

**Files:**
- Create: `crates/core/src/intent.rs`
- Modify: `crates/core/src/lib.rs`

**Interfaces:**
- Consumes: Task 1 ids.
- Produces (`landfall_core::intent`):
  - `DeployIntent { deployment: DeploymentId, tag: String, commit: CommitSha, digest: ImageDigest, expected_running: Option<ImageDigest>, nonce: [u8; 32] }` (`serde` for transport; nonce as 64-hex in serde).
  - `fn canonical_bytes(&self) -> Vec<u8>`: domain-separated, unambiguous encoding (below).
  - `fn challenge(&self) -> [u8; 32]`: SHA-256 of `canonical_bytes()`. This is the WebAuthn challenge in plan 05; the agent recomputes it.
- Encoding (fixed; the agent and controller must agree byte for byte): the ASCII bytes `landfall-deploy-intent-v1`, then for each field in the order above a 4-byte big-endian length followed by the field's bytes: the id/tag/commit/digest as UTF-8; `expected_running` as the digest's UTF-8, or zero length when `None`; the nonce's 32 raw bytes.

- [ ] **Step 1: Write the failing tests:**
  - `challenge_is_stable`: a fixed intent (`app/prod`, `v1.2.4`, commit of 40 `a`, digest of 64 `b`, expected running digest of 64 `c`, nonce `[7; 32]`) has a challenge equal to a hex constant computed once in the test from the documented encoding written out by hand in the test (build the expected bytes with explicit pushes, hash them with `sha2`).
  - `distinct_intents_never_share_a_challenge`: changing any single field (including `expected_running` from `Some` to `None`, and moving bytes between `tag` and `deployment` boundaries, e.g. tag `"v1.2.4"` vs a tag ending in a quote or newline) changes the challenge.
  - `intent_round_trips_through_json`: `serde_json` is a dev-dependency only; serialise then deserialise gives an equal intent; a nonce that is not 64 hex fails.
- [ ] **Step 2: Run** → FAIL. **Step 3: Implement.** **Step 4: Run** the full gate → PASS.
- [ ] **Step 5: Commit** `feat(core): deploy intents and approval challenges`.
