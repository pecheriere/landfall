# landfall plan 05: Approvals and grants Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A person can approve a deploy with a passkey, and the host checks that approval itself against its own configuration. That unlocks first deploys, minor and major upgrades, retrying a failed release and manual rollbacks, without giving the controller any new power.

**Architecture:** A new crate, `crates/approval`, verifies WebAuthn assertions; the agent and the controller both use it. The agent accepts a non-automatic deploy only with an assertion that signs the exact intent it's about to execute, by a key and approver in its local config, from the state it's in now. The controller gets principals, sessions, API tokens, grants, and the requests and approvals that carry an assertion from a browser to a host.

**Tech Stack:** Rust 1.99 (edition 2024); `aws-lc-rs` for ES256 and Ed25519 verification (already in the tree through rustls, no new crypto); `minicbor` for COSE and attestation objects; `base64` (already in the tree); `axum`, `sqlx` as in plan 04. Pick the newest version `crate-age` accepts.

**Spec:** `docs/design/landfall.md` (sections 6.2, 6.3, 8.1, 8.2, 8.3, 12); `docs/configuration.md`; `docs/operations.md`.

## Rulings made while writing this plan

- **Our own small WebAuthn verifier, not `webauthn-rs`.** Task 1 confirms from its current manifest whether it pulls in OpenSSL, which the Rust rules forbid; if a suitable crate without it exists, say so. The host only needs assertion verification, which is a short, well-specified check over two byte strings: authenticator data and client data. Registration only needs the attestation parsed for its COSE key: no attestation is trusted, since the operator reviews the key and copies it into the config by pull request (spec 6.3). So any `fmt` is accepted, including `packed` self attestation from real passkeys, and `attStmt` is ignored; `type`, origin, challenge, RP ID hash and flags are still checked. Registration parses leniently and normalises: reordered attestation entries, reordered COSE labels and non-minimal lengths are accepted, and the canonical COSE encoding is what's stored and shown. Config load stays strict on that canonical form, so each key has one encoding and one fingerprint.
- **Algorithms:** ES256 and EdDSA only. Anything else is refused at config load, naming the approver.
- **Issue #7:** `rule.approvers` is authoritative on the host, and it's the only thing the host checks. A grant's `approve` is the controller's gate for showing and accepting a ceremony. Config validation refuses a grant giving `approve` on a deployment whose `rule.approvers` doesn't list that principal, so the two can't disagree. Closes #7.
- **Issue #6:** approver keys are parsed and validated at config load. Closes #6.
- **RP ID and origin are config:** a required top-level `[approval] rp_id = "...", origin = "https://..."` when any deployment can need an approval (all can, since first deploys are manual). The RP ID must be the origin's exact hostname, never a parent domain, validated at load.
- **What the host checks,** per spec 6.3, in `crates/approval`, all required: signature over `authenticatorData || SHA-256(clientDataJSON)` with the key from local config; credential ID matches that approver's; `type` is `webauthn.get`; `origin` is exactly the configured one, and `crossOrigin` is absent or false; `rpIdHash` is the SHA-256 of the configured RP ID; UP and UV flags set; `challenge` equals the base64url of `intent.challenge()`. Strict parsing: clientDataJSON is parsed by JSON with duplicate keys refused, and trailing authenticator data is allowed only when the ED flag declares it. The signature counter is not checked: synced passkeys report 0, and replay is stopped by the nonce log and the expected running digest.
- **What the host checks about the intent:** every field equals what it verified or holds: deployment and tag from the work, commit and digest from its own verification, `expected_running` from its own `Deployed` record (`None` for a first deploy). A nonce already in its on-disk log is refused. The nonce is recorded, with fsync, before the deploy starts, so a crash can't reuse it. No clock is used.
- **Which decisions take an approval:** `NeedsApproval` and `Manual` run only with a valid assertion. `Auto` ignores any assertion attached. `Refused(Prerelease)` stays refused unless the rule opts in, and `AlreadyRunning` stays refused: an approval never overrides these, and to redeploy the same release you'd need a different release. A release on the failure record runs with a valid approval: that is the manual retry the operations guide promises, and a successful deploy removes it from the record. A downgrade with a valid approval is the manual rollback (spec 6.2). The automatic rollback after a failed check is unchanged.
- **Principals:** every principal is named in the config, and the kinds are told apart by how they authenticate. A human holds a passkey the controller knows; an API token belongs to a named principal. `approve` is enforced in code as human only, spec 8.2: a token can never approve, whatever the config says.
- **Registration:** `landfall-server passkey-invite --principal <name>` prints a one-time link (32 random bytes, stored as SHA-256, valid 1 hour). The page runs the ceremony and shows the COSE key, credential id and fingerprint to copy into the config by pull request. The agent trusts only that file. The controller stores the key too, for sign-in. Accepted residual risk, stated in the docs: a compromised controller could substitute its own key during registration (spec 6.3).
- **Sign-in:** a passkey assertion over a server challenge gives a session: an opaque 32-byte token, stored as SHA-256, in a `__Host-` cookie, `HttpOnly; Secure; SameSite=Strict`, for 12 hours, ended on sign-out. State-changing requests also require the exact `Origin`. Approvals always take a fresh assertion, whatever the session says (spec 8.1).
- **API tokens:** `landfall-server token create --principal <name>` prints a token once (32 random bytes, stored as SHA-256), `token revoke`. Grants apply to tokens and sessions alike. `agents_via_warden` and the rest of the human API are plan 06.
- **Requests:** a person or token with `request` asks for (deployment, tag). The controller builds the intent with a fresh random nonce and `expected_running` from the host's last report, and stores the deploy as `awaiting_approval`. An approver with the grant signs it. A deploy row then moves to `queued`, carrying intent and assertion to the host. If the running digest changes first, the request goes `stale`, and asking again makes a new intent. The watcher records `NeedsApproval` and `Manual` as waiting, as now, and doesn't make requests by itself.
- **Pages are minimal and functional:** static HTML with one external script for the ceremonies, under the strict CSP of spec 3 (`default-src 'self'`, no inline script or style). Registration, sign-in, and a list of what's awaiting you with an approve button that shows the intent's fields. The design language is plan 07. These are the pages it restyles.
- **What the operator sees:** the challenge is opaque to a person, so a lying controller page could show one release and sign another (spec 6.3). Accepted and documented; `landfall approve`, computing the hash locally, is plan 06.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply. No `#[allow]`/`#[expect]` without `reason = "..."`. `unsafe_code` is forbidden. Public error enums are `#[non_exhaustive]`.
- Files stay under about 800 lines of code, and tests in their own files, split by scenario.
- Everything from a browser, an agent or the controller is hostile: bodies capped before parsing, no panics, text quoted and truncated in errors and audit rows. WebAuthn parsers get a table of malformed inputs.
- Secrets: invite codes, tokens and session tokens are never logged or stored raw, and `Debug` is redacted. Compare by hash, in SQL or in constant time.
- Every state change writes its audit row in one transaction: registration, sign-in, token create and revoke, request, approval, stale, and every refusal attributable to a principal. Host refusals of an approval are final `Refused` with the reason and are journalled at critical priority: this is the signal of a controller lying.
- Full gate before each commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`.
- Public, generic repository: nothing personal. Conventional commits, with no attribution trailers.

## Review Focus

1. **An assertion for another intent, another deployment, another host's state, or another origin, or a replay** is refused on the host, and nothing runs → Task 1 and Task 3 tests.
2. **A compromised controller with a stolen session, and no passkey,** can't get any non-automatic deploy run → Task 3 `controller_cannot_forge_an_approval`.
3. **A token, or a person without the grant,** can't approve or request; a person with `request` and no `approve` can't approve → Task 4.
4. **CSRF, session fixation or a stolen cookie** can't complete an approval, since each takes a fresh assertion → Task 5.
5. **A crash between recording the nonce and deploying** leaves the approval spent and the service untouched, with a clear state → Task 3 `crash_after_recording_the_nonce_spends_the_approval`.

---

### Task 1: The approval crate

**Files:** Create `crates/approval/` (`lib.rs`, `cose.rs`, `assertion.rs`, `registration.rs`, tests in their own files). Modify `Cargo.toml`, `Dockerfile`, `AGENTS.md`, `deny.toml` (licences only).

**Interfaces:**
- `CoseKey::parse(&[u8]) -> Result<CoseKey, CoseError>`: ES256 (P-256, uncompressed point on the curve) or EdDSA (Ed25519) only; duplicate map keys refused. `CoseKey::fingerprint(&self) -> String`.
- `struct Assertion { credential_id, authenticator_data, client_data_json, signature }`, all bytes, base64url on the wire. `struct Expect<'a> { key: &'a CoseKey, credential_id: &'a [u8], rp_id: &'a str, origin: &'a str, challenge: &'a [u8] }`. `fn verify(assertion: &Assertion, expect: &Expect<'_>) -> Result<(), AssertionError>`, with a variant per check, naming expected and found, and no secret.
- `fn parse_registration(attestation_object: &[u8], client_data_json: &[u8], rp_id, origin, challenge) -> Result<Registered, RegistrationError>`: any format, `attStmt` ignored, `type` `webauthn.create`, UP and UV, AT flag, returns credential id and `CoseKey` in its canonical encoding.
- `#[cfg(any(test, feature = "test-support"))]` `SoftwareAuthenticator`, generating keys and producing assertions and attestation objects, used by later tasks' tests, with knobs to break each field.

- [ ] **Step 1:** Check `webauthn-rs`'s manifest and record the finding. Then failing tests: `valid_assertion_verifies` (ES256 and EdDSA), `real_browser_vectors_verify` (a committed vector captured from Chromium's virtual authenticator, with how to regenerate it in a README), one test per check with exactly one field wrong, `signature_over_other_bytes_is_refused`, `crossorigin_true_is_refused`, `duplicate_json_keys_are_refused`, `parent_domain_rp_id_is_refused`, `extensions_flag_without_data_is_refused`, `trailing_bytes_without_the_flag_are_refused`, `curve_point_off_the_curve_is_refused`, `unknown_algorithm_is_refused`, `malformed_inputs_never_panic` (a table, plus truncating every valid vector at every length).
- [ ] **Step 2-4: Implement, gate, Linux. Step 5: Commit** `feat(approval): verify WebAuthn assertions`.

### Task 2: Config

**Files:** Modify `crates/core/src/config/`, `docs/configuration.md`, `crates/core/Cargo.toml` if `CoseKey` lives behind a parse-only form.

**Interfaces:** `landfall-core` stays free of aws-lc: config holds approver keys as validated bytes through a small trait or a function supplied by `crates/approval`, whichever keeps core pure and validation at load for all three binaries; decide and record it. `[approval] rp_id, origin`. `Config::approver(&PrincipalId)`. Rule 7 gains the #7 check.

- [ ] **Step 1: Failing tests:** `approver_key_must_parse` (closes #6), `unsupported_algorithm_names_the_approver`, `duplicate_credential_ids_are_refused`, `rp_id_must_be_the_origins_hostname`, `origin_must_be_https_with_no_path`, `approve_grant_must_be_a_listed_approver` (closes #7), example configs updated.
- [ ] **Step 2-4: Implement, gate. Step 5: Commit** `feat(core): approval settings and validated approver keys`.

### Task 3: Agent: run an approved deploy

**Files:** Create `crates/agent/src/daemon/approval.rs`, tests in `daemon/tests/approvals.rs`. Modify `crates/agent/src/daemon/judge.rs`, `crates/agent/src/state.rs` or its split parts, `crates/core/src/protocol.rs` (`DeployWork` gains `approval: Option<Approval { intent, assertion }>`, explicit null), `docs/operations.md`.

**Interfaces:** `judge` per the Rulings. `StateDir` gains a used-nonce log: append with fsync, one line per nonce, read at start. A corrupt log refuses approvals (fail closed) and is journalled. A release on the failure record runs with a valid approval, and a successful deploy removes it.

- [ ] **Step 1: Failing tests** with `FakeDocker` and `SoftwareAuthenticator`: `first_deploy_with_an_approval_runs`, `minor_under_an_approve_rule_runs`, `downgrade_with_an_approval_runs`, `failed_release_retried_with_an_approval_runs_and_clears_the_record`, `controller_cannot_forge_an_approval` (no assertion; assertion by a key not in config; by an approver not in this deployment's `rule.approvers`; for another intent, each field changed in turn), `approval_for_another_running_digest_is_refused`, `replayed_nonce_is_refused`, `replayed_nonce_is_refused_after_a_restart`, `crash_after_recording_the_nonce_spends_the_approval`, `auto_ignores_an_attached_assertion`, `prerelease_and_same_version_stay_refused`, `corrupt_nonce_log_refuses_approvals`, `refused_approval_is_critical_in_the_journal`. One real `docker_` test.
- [ ] **Step 2-4: Implement, gate, Linux. Step 5: Commit** `feat(agent): run approved deploys, verified on the host`.

### Task 4: Controller: principals, tokens, grants, requests

**Files:** Create `crates/server/src/auth/`, `crates/server/src/requests.rs`, `crates/server/migrations/0003_approvals.sql`, tests alongside. Modify `crates/server/src/{store,cli,lib}.rs`.

**Interfaces:** `passkey-invite`, `token create`, `token revoke`. `Principal` extractor from a session or a token. `can(principal, deployment, Permission) -> bool` from config grants, in one place, with `approve` human only. `POST /api/v1/deployments/{deployment}/requests` (`request` grant), `GET /api/v1/approvals`, `POST /api/v1/approvals/{id}` (with assertion, fresh), problem+json. `stale` when the host's reported running digest moves. Queued rows carry the approval to `work`.

- [ ] **Step 1: Failing tests:** `token_is_shown_once_and_stored_hashed`, `revoked_token_is_refused`, `token_cannot_approve_whatever_the_config_says`, `request_needs_the_grant`, `approve_needs_the_grant_and_a_listed_approver`, `requester_without_approve_cannot_approve`, `approval_needs_a_fresh_assertion_by_this_principal`, `assertion_for_another_intent_is_refused_by_the_controller_too`, `request_goes_stale_when_the_running_digest_moves`, `one_open_request_per_deployment`, `a_request_for_a_release_never_verified_is_refused`, `every_change_is_audited`, `refusals_by_a_principal_are_audited`.
- [ ] **Step 2-4: Implement, gate, Linux. Step 5: Commit** `feat(server): principals, API tokens, grants and deploy requests`.

### Task 5: Ceremonies and minimal pages

**Files:** Create `crates/server/src/web/` (routes, static HTML and one JS file, included at compile time), tests. Modify `crates/server/src/lib.rs`.

**Interfaces:** `GET /passkeys/register/{code}`, `POST` begin and finish; `GET /sign-in`, `POST` begin and finish, `POST /sign-out`; `GET /approvals`. Headers on every response: the strict CSP, `X-Content-Type-Options`, `Referrer-Policy`, `frame-ancestors 'none'`. Challenges are single-use and expire in 5 minutes. Exact `Origin` required on state changes.

- [ ] **Step 1: Failing tests:** `invite_works_once`, `registration_page_shows_key_and_fingerprint`, `sign_in_with_a_registered_passkey_works`, `sign_in_with_an_unknown_credential_says_the_same_as_a_bad_one`, `challenge_works_once`, `expired_challenge_is_refused`, `session_cookie_has_the_required_attributes`, `session_id_changes_at_sign_in`, `wrong_origin_is_refused_on_every_state_change`, `csp_has_no_inline_or_external_sources`, `pages_have_no_inline_script_or_style`, `signed_out_session_is_refused`. Then a real-browser run: Chromium with its virtual authenticator through Playwright, driving registration, sign-in and an approval against the real binary, as a `live_`-prefixed test or a committed script, whichever is simplest to keep working; say which.
- [ ] **Step 2-4: Implement, gate. Step 5: Commit** `feat(server): passkey ceremonies and minimal approval pages`.

### Task 6: End to end, docs

**Files:** Modify `crates/agent/tests/e2e/`, `docs/operations.md`, `docs/design/landfall.md`, `README.md`.

- [ ] **Step 1: End-to-end tests** (real server and agent, `SoftwareAuthenticator`): a first deploy requested, approved and deployed; a minor upgrade; a manual rollback; a failed release retried; a controller database restored between approval and delivery; a stale approval after the host moved; a host refusing a forged approval, seen in the audit log as such.
- [ ] **Step 2: Docs:** registering a passkey and copying it into the config, the RP ID and HTTPS requirement (WebAuthn needs a secure context; a tailnet name with `tailscale serve`, or a TLS proxy, both work), sign-in, tokens, requests and approvals, what a lying controller page can and can't do, losing a passkey.
- [ ] **Step 3: Full gate; Linux; `docker build`; `uvx zizmor .`. Step 4: Commit** `test: approvals end to end; docs`.
