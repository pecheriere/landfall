# landfall plan 04: Controller core Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A running controller and a running agent that work together: the controller sees a new signed release, verifies it, decides it may deploy automatically, and hands it to the right host; the host verifies everything again, deploys, and reports back; every event lands in a tamper-evident log.

**Architecture:** `landfall-server` becomes a library plus a thin binary: `store` (SQLite, hash-chained audit), `agent_api` (enrol, nonce, work, report), `watcher` (release discovery and rule decisions). Wire types and request signing live in `landfall-core::protocol`, because both sides use them and they're pure. `landfall-agent run` is a new long-running command wrapping the deploy engine from plan 03. The agent connects out; the controller never connects to a host.

**Tech Stack:** Rust 1.99 (edition 2024); `axum` 0.8; `sqlx` 0.9 (`runtime-tokio`, `sqlite`, `migrate`, no compile-time query macros), as in warden; `ed25519-dalek` 2.2 (`rand_core` for key generation); `tokio`; `reqwest`; `tower` (body limits, timeouts). Pick the newest version `crate-age` accepts; pin fresh transitive crates with `cargo update -p <crate> --precise <older>`.

**Spec:** `docs/design/landfall.md` (sections 4, 5.2, 6.2, 6.4, 8.1, 8.3); `docs/configuration.md`; `docs/operations.md`.

## Rulings made while writing this plan

- **Approvals stay refused here.** Only `Decision::Auto` runs. `NeedsApproval` and `Manual` are recorded with their reason and wait for plan 05. The first deploy of a deployment is manual, so until plan 05 a deployment only moves once its state exists; the end-to-end test seeds it. The human API, UI and CLI are plans 06 and 07: this plan's only controller routes are the agent API and `GET /healthz`.
- **Long poll, not WebSocket:** `POST /agent/v1/work` holds for up to 30 s. It needs no connection state, survives proxies, and every request is signed the same way.
- **Signed requests use a controller nonce, not the clock** (a Pi may have no RTC). The agent fetches a single-use nonce, then signs a length-prefixed encoding (as `landfall_core::intent` does, but with 8-byte lengths because method and path are unbounded) of the fields `landfall-agent-v1`, host id (the `Landfall-Host` header only selects the key; the id is signed so a signature never verifies for another host), method, path (with the query string, if any), the nonce's 32 raw bytes and the 32-byte SHA-256 of the body, with its Ed25519 key. No newline or other byte in a field can shift into another. The controller consumes the nonce on first use, and nonces expire after 5 minutes by the controller's own clock. An unknown, used or expired nonce is refused before the signature is looked at.
- **Enrolment:** `landfall-server enrol-code --host <id>` prints a one-time code (32 random bytes, stored only as a SHA-256, valid 1 hour). `landfall-agent enrol --controller <url> --code-file <path>` generates the key in the state directory (0600, never overwritten) and sends the public key with the code. The code is bound to that one host id. A host with a key already enrolled needs an explicit `enrol-code --host <id> --replace`, recorded in the audit log.
- **A host only sees its own work.** Identity comes from the signature, never from a host id in the body. `work` and `report` are scoped to the signer's host, and a report for another host's deploy is refused.
- **Config hash:** every `work` request carries the SHA-256 of the agent's config. A mismatch makes `work` answer with no work and a stated reason for that host, and records it (spec: "hash drift blocks deploys"). The controller reads its config once at start-up.
- **Exactly one run (closes #11):** the watcher enumerates candidates from the registry: `GET /v2/<image>/tags/list`, keeping `sha256-<hex>` referrer tags, verifying each candidate's bundle against this release's identity. A verified result is cached by (digest, tag) with the run its certificate names, so each attestation is verified once. The rule exists to catch a re-run release workflow, not image variants, so it counts runs and not digests: every verified candidate must come from one run and attempt (the Fulcio Run Invocation URI, `.../actions/runs/<id>/attempts/<n>`), and the digest the version tag resolves to must be among them. Several digests from one run pass, as `1.37.4` and `1.37.4-alpine` of the fixture project do. Two runs, or two attempts of one run, refuse the release, naming both; so does a run URI that does not parse strictly as that shape. A version tag's digest outside the set is a hold that retries, not a refusal: one bad registry answer must not outlive its cause, and a hold queues nothing. A durable refusal is for verification results only (signature, attestation, the run rule). A project with its variants in separate workflow runs is refused too, which is accepted and documented. An unreadable tag list or a cap reached (5,000 tags) fails closed with a reason, while an unverifiable candidate is ignored and logged, so it can't block a release. The agent keeps its single-candidate check: enumeration is controller-side, as in spec 12's table, and a second digest would still be built by the configured workflow from the signed commit.
- **The agent's decisions are its own.** It re-verifies origin with its own trust root and re-runs `decide` from its own `Deployed` record. If the controller's work names a release the host's rule doesn't make `Auto`, it refuses, journals and reports it. A compromised controller can only ask.
- **Reports survive an outage.** The agent writes each finished report to its state directory before sending, retries with backoff, and removes it on acknowledgement. Reports are idempotent by deploy id.
- **Issue #4:** `compose::resolve_dirs` comes back with a real caller: `landfall-agent run` refuses to start if two of its deployments resolve to one directory or one is missing (closes #4).
- **Drift:** the agent runs the plan 03 `drift` check every minute and reports changes. A drifted deployment gets no automatic deploys until it clears.
- **Transport:** the controller serves plain HTTP on its configured listen address, for a tailnet or a TLS-terminating proxy. The agent's `--controller` URL must be `https://`, or `http://` to a loopback or a tailnet name only with an explicit `--allow-insecure-controller`, since requests are signed but work contents are visible. Docs say so.
- **Audit:** an append-only table where `hash = sha256(prev_hash || canonical event bytes)`, written in the same transaction as the state change it records. Canonical bytes follow `landfall_core::intent`'s length-prefixed style. `landfall-server audit verify` walks the chain and reports the first bad row. Report text from an agent is stored quoted and bounded.
- **The Docker image must still build.** The server now pulls in `landfall-origin`, so `aws-lc-sys`' C build enters the musl/zig Dockerfile: Task 1 proves this before anything else depends on it.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply. No `#[allow]`/`#[expect]` without `reason = "..."`. `unsafe_code` is forbidden. Public error enums are `#[non_exhaustive]`.
- Everything from an agent, GitHub or a registry is hostile: bodies capped before parsing (agent API 1 MiB), timeouts on every request, no panics, text quoted and truncated in errors.
- Secrets: enrolment codes and private keys are never logged, stored raw or put in errors. `Debug` on types holding them is redacted.
- SQL is parameterised only. All writes that change state and audit go in one transaction.
- Full gate before each commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`. `uvx zizmor .` when a workflow changes.
- Public, generic repository: no real hostnames or user names. Conventional commits, with no attribution trailers.

## Review Focus

1. **A replayed or reordered signed request** (same nonce twice; a signature moved to another path or body) is refused → Task 2 `signature_covers_method_path_nonce_and_body`, Task 3 `nonce_works_once`.
2. **One host asking for or reporting on another's deploy** is refused → Task 3 `host_sees_only_its_own_work`, `report_for_another_hosts_deploy_is_refused`.
3. **A compromised controller asks for a release the host's rule doesn't allow, or a downgrade** → the agent refuses, journals and reports it, and nothing runs → Task 5 `controller_cannot_force_a_non_auto_deploy`.
4. **A row edited, deleted or reordered in the audit log** is found by `audit verify` → Task 1 `tampering_is_detected`.
5. **The controller is down during a deploy** → the deploy finishes, the report is kept and delivered later, once → Task 5 `report_survives_a_controller_outage`.

---

### Task 1: Server crate, store, audit

**Files:** Create `crates/server/src/{lib.rs,store.rs,audit.rs,cli.rs}`, `crates/server/migrations/0001_init.sql`. Modify `crates/server/src/main.rs`, `crates/server/Cargo.toml`, `Cargo.toml`, `Dockerfile`, `AGENTS.md`, `deny.toml` (licences only, if needed).

**Interfaces:**
- `store::Store::open(path: &Path) -> Result<Store, StoreError>`: WAL, foreign keys on, migrations run; the file is created 0600. `Store::open_in_memory()` under `#[cfg(test)]`.
- `audit::AuditEvent { kind: EventKind, deployment: Option<DeploymentId>, host: Option<HostId>, detail: serde_json::Value }`; `Store::append(&self, tx, event)`; `Store::verify_audit(&self) -> Result<AuditReport, StoreError>`; `AuditReport { rows: u64, first_bad: Option<u64> }`.
- Tables: `hosts`, `enrol_codes`, `nonces`, `releases`, `deploys`, `deploy_steps`, `audit_events`. Deploy states: `queued`, `claimed`, `finished` with outcome text. One active (`queued` or `claimed`) deploy per deployment, enforced by a partial unique index.
- CLI: `landfall-server serve --config <file> --db <file> --listen <addr>`, `enrol-code --host <id> [--replace]`, `audit verify`. `serve` here only opens the store and answers `GET /healthz`.

- [ ] **Step 1: Prove the Docker build first.** Add `landfall-origin` as a dependency, reference it, and run `docker build .`. Fix the builder stage for `aws-lc-sys` properly; don't drop the dependency. Keep the dependency-layer pattern. Report the time, cold and cached.
- [ ] **Step 2: Failing tests:** `hash_chain_links_each_row`, `tampering_is_detected` (edit detail, delete a row, swap two rows: each gives `first_bad`), `audit_row_and_state_change_commit_together` (a failing state change leaves no audit row), `only_one_active_deploy_per_deployment`, `db_file_is_private`, `migrations_run_on_an_empty_file_and_are_idempotent`.
- [ ] **Step 3: Implement. Step 4: Full gate. Step 5: Commit** `feat(server): store and hash-chained audit log`.

### Task 2: Protocol and request signing (core)

**Files:** Create `crates/core/src/protocol.rs`. Modify `crates/core/src/lib.rs`, `crates/core/Cargo.toml`, `Cargo.toml`.

**Interfaces:**
- `signing_bytes(method: &str, path: &str, nonce: &Nonce, body: &[u8]) -> Vec<u8>`; `sign(key: &SigningKey, ...) -> RequestSignature`; `verify(key: &VerifyingKey, sig, ...) -> Result<(), SignatureError>`. `Nonce` is 32 random bytes, hex on the wire; core takes it as a value and draws no randomness.
- Headers: `Landfall-Host`, `Landfall-Nonce`, `Landfall-Signature`.
- `EnrolRequest { code, host, public_key }`, `WorkRequest { config_hash, running: Vec<RunningState> }`, `WorkResponse { work: Option<DeployWork>, held_back: Vec<HeldBack> }`, `DeployWork { deploy_id, deployment, tag, digest, commit }`, `DeployReportBody { deploy_id, outcome, steps }`, `RunningState { deployment, tag, digest, drift, phase }`. All `deny_unknown_fields`; ids use the validated newtypes.

- [ ] **Step 1: Failing tests:** `signature_covers_method_path_nonce_and_body` (table: changing any one fails), `signing_bytes_cannot_be_confused_across_fields` (a newline in a path can't shift bytes into the nonce: reject or length-prefix), `signature_from_another_key_is_refused`, `unknown_fields_are_refused`, `round_trips_through_json`.
- [ ] **Step 2-4: Implement, gate. Step 5: Commit** `feat(core): agent protocol and request signing`.

### Task 3: Agent API

**Files:** Create `crates/server/src/agent_api.rs`. Modify `crates/server/src/{lib.rs,cli.rs,store.rs}`.

**Interfaces:** `agent_api::router(state: ApiState) -> axum::Router`, with `POST /agent/v1/enrol`, `GET /agent/v1/nonce`, `POST /agent/v1/work`, `POST /agent/v1/report`. Errors are problem+json with stable codes. A signed-request extractor checks the nonce, then the host key, then the signature over the raw body, then parses. `GET /agent/v1/nonce` is unauthenticated, so it's rate-limited per source and outstanding nonces are capped; a full table refuses rather than grows.

- [ ] **Step 1: Failing tests** (real router, in-memory store, `tower::ServiceExt`): `enrol_with_a_valid_code_records_the_key`, `code_works_once`, `code_is_bound_to_its_host`, `expired_code_is_refused`, `reenrol_needs_replace`, `nonce_works_once`, `expired_nonce_is_refused`, `nonce_table_cannot_grow_without_bound`, `host_sees_only_its_own_work`, `report_for_another_hosts_deploy_is_refused`, `report_is_idempotent`, `config_hash_mismatch_gives_no_work_and_says_why`, `oversized_body_is_refused`, `work_long_poll_returns_when_work_arrives`, `work_long_poll_times_out_empty`, `claimed_work_is_redelivered_after_a_reconnect` (same deploy id, so an agent crash can't lose it), `every_change_is_audited`.
- [ ] **Step 2-4: Implement, gate. Step 5: Commit** `feat(server): agent API with enrolment and signed requests`.

### Task 4: Release watcher

**Files:** Create `crates/server/src/watcher.rs`. Modify `crates/origin/src/fetch.rs` (`list_release_tags`, `list_referrer_digests`), `crates/origin/src/release.rs`, `crates/server/src/{lib.rs,cli.rs}`.

**Interfaces:**
- `trait ReleaseSource`, implemented by a thin wrapper over `Fetcher` and `verify_release`, and by a fake in tests: `tags(&self, deployment) -> Result<Vec<ReleaseTag>, _>`, `verify(&self, deployment, tag) -> Result<ReleaseOrigin, ReleaseError>`, `attested_digests(&self, deployment, tag) -> Result<Vec<ImageDigest>, _>`.
- `watcher::tick(store, config, source) -> TickSummary`: for each deployment and each tag matching its pattern not yet decided: verify, enumerate digests, apply `select_release_digest`, `decide`, apply promotion, and record. `Auto` queues a deploy if no active one exists, only for the highest eligible version. Interval 5 minutes, with a per-repo backoff on errors and on rate limits.
- Promotion (spec 6.4): a `promote_to` target gets no proposal until the version has been healthy on the source for `healthy_for`, by the controller's clock from the source's report. Recorded and shown as controller-enforced only.
- A transient failure (network, rate limit, no bundle yet) retries at a later tick; a refusal is recorded once and not re-verified until its inputs change.

- [ ] **Step 1: Failing tests** with a fake source: `new_patch_release_queues_a_deploy`, `only_the_highest_eligible_version_is_queued`, `minor_under_patch_rule_waits_with_its_reason`, `first_deploy_is_manual_and_recorded`, `refused_release_records_the_reason_once`, `several_attested_digests_refuse_the_release`, `unreadable_tag_list_fails_closed`, `unverifiable_candidate_is_ignored`, `transient_failure_retries`, `no_second_deploy_while_one_is_active`, `promotion_waits_for_healthy_for`, `running_state_comes_from_reports`, wiremock tests for the new fetchers (caps, pagination, hostile bodies), and an ignored `live_` test listing a real image's referrer tags.
- [ ] **Step 2-4: Implement, gate. Step 5: Commit** `feat(server): watch releases, enumerate attested digests, queue automatic deploys`.

### Task 5: Agent daemon

**Files:** Create `crates/agent/src/daemon.rs`, `crates/agent/src/client.rs`, `crates/agent/src/enrol.rs`. Modify `crates/agent/src/{lib.rs,cli.rs,compose.rs,state.rs}`, `docs/operations.md`.

**Interfaces:**
- `trait Controller` (the HTTP client, faked in tests): `work`, `report`. `trait Verifier` wrapping `verify_release`, faked in tests.
- `daemon::step<D, C, V>(docker, controller, verifier, config, state_dir, options) -> StepOutcome`: one poll. Refuses to deploy while that deployment has an in-progress marker or drift. For a work item: verify, `decide` from its own `Deployed` record, require `Auto`, build `DeployPlan::from_verified`, `deploy::run`, persist the report, send it.
- `landfall-agent run --config <file> --controller <url> [--state-dir] [--allow-insecure-controller]`: `resolve_dirs` at start, one deployment at a time per host in v0, TUF refresh daily, backoff on errors with jitter, clean shutdown on SIGTERM (a deploy in flight finishes; the unit's `TimeoutStopSec` documents it).
- `landfall-agent enrol --controller <url> --code-file <path>`.

- [ ] **Step 1: Failing tests** with fakes: `controller_cannot_force_a_non_auto_deploy` (minor under a patch rule; downgrade; same version: nothing runs, journal and report say why), `failed_verification_runs_nothing`, `in_progress_marker_blocks_work`, `drift_blocks_work`, `report_survives_a_controller_outage`, `report_is_sent_once_after_a_restart`, `aliased_directories_refuse_to_start`, `missing_directory_refuses_to_start`, `key_file_is_private_and_never_overwritten`, `http_controller_needs_the_flag`, `backoff_grows_and_resets`, `sigterm_waits_for_the_deploy`.
- [ ] **Step 2-4: Implement, gate, Linux run. Step 5: Commit** `feat(agent): daemon that polls, re-verifies and deploys`.

### Task 6: End to end

**Files:** Create `crates/server/tests/e2e.rs` (or under `crates/agent/tests`, wherever the dependency direction allows). Modify `docs/operations.md`, `README.md`, `docs/design/landfall.md`, `.github/workflows/ci.yml` if a step is needed.

- [ ] **Step 1: In-process end-to-end test** (real server, real SQLite file, real HTTP on loopback, real agent client, fake `ReleaseSource` and `Verifier`, `FakeDocker`): enrol; seed a running version; a new patch tag appears; the watcher queues it; the agent claims, deploys, reports; the audit chain verifies and names every step. A second case with a failing check ends `RolledBack`, and the running state stays on the old version. A third restarts the server mid-deploy.
- [ ] **Step 2: Real-Docker test** with the `docker_` prefix: the same flow with the real `DockerCli` and pinned digests, `Verifier` still fake (no test repo signs real releases).
- [ ] **Step 3: Docs:** running the controller, enrolling a host, the long-running agent unit, what a compromised controller can and can't do, the transport rule. The audit log's limit: the chain alone cannot show rows cut from the end with the sequence record lowered, a dropped table, an old backup restored or a whole forged history. The procedure: keep the head `audit verify` prints (`head_seq`, `head_hash`) somewhere the controller can't write, and compare later: `head_seq` must not have gone down, and `audit verify --at <kept seq>` must print the kept hash as `at_hash` (it prints null and exits 1 if the row is gone). An external anchor stays out of scope. Update spec sections touched by the rulings.
- [ ] **Step 4: Full gate; `uvx zizmor .`. Step 5: Commit** `test: controller and agent end to end; operations guide`.
