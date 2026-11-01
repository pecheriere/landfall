# landfall plan 02: Origin verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Given a deployment from the fleet config and a release tag, decide whether that release is maintainer-signed and built by the configured workflow from the signed commit, and produce the verified facts ("where it came from") or a precise refusal.

**Architecture:** Pure checks live in `landfall-core` (SSH tag signature, signer keys parsed at config load, digest selection, platform check). A new library crate `crates/origin` (`landfall-origin`) holds what needs the network or the Sigstore stack: the TUF-backed trust root, Sigstore bundle verification and Fulcio identity matching, and the GitHub and GHCR fetchers, composed by one `verify_release` function. The CLI gets `landfall verify` so a maintainer can run the whole check against a real release.

**Tech Stack:** Rust 1.99 (edition 2024); `ssh-key` 0.6.7 (`default-features = false, features = ["std", "ed25519"]`); `sigstore-verify`, `sigstore-trust-root`, `sigstore-types` 0.15.1 (feature `tuf` on the trust-root crate); `reqwest` (rustls, already in that tree) and `tokio`; `serde_json`; dev: `wiremock`. Pick the newest version `crate-age` accepts (`python3 -I .github/scripts/crate_age.py --base main`); if a fresh transitive crate is flagged, pin it with `cargo update -p <crate> --precise <older>`.

**Spec:** `docs/design/landfall.md` (sections 4, 5.1, 5.2, 12).

## Rulings made while writing this plan

- Sigstore: `sigstore-verify` family (sigstore/sigstore-rust), not the older `sigstore` crate, which exposes no typed certificate extensions and pulls `rsa` (RUSTSEC-2023-0071). A feasibility spike verified a real GitHub build-provenance bundle end to end with it, online and offline, and rejected ten tampered variants.
- Signer keys are ed25519 only in v0: `ssh-key`'s `p256` feature compiles `crypto-bigint` 0.5.5 (RUSTSEC-2026-0387). Other key types are a config error naming the key. Closes #6 for signers.
- Tag signatures are a per-deployment option (maintainer decision, 2026-10-31): `origin.signed_tags`, default `true`. With `false`, `origin.signers` must be empty, the tag may be lightweight, and the release commit is what the GitHub tag ref points to (peeled). The attestation checks are always on. The docs state the weaker guarantee.
- The image is `ghcr.io/<owner>/<repo>` with the repo name lowercased (v0: your own images, on GHCR). No new config key.
- `deny.toml` licences gain `ISC`, `BSD-3-Clause`, `MPL-2.0`, `CDLA-Permissive-2.0` (required by rustls, webpki-root-certs and option-ext in the Sigstore tree). Allowing a licence is not exempting a finding.
- "Exactly one digest per release": this plan ships the pure rule (`select_release_digest`) over the candidates it is given. Enumerating every attested digest for a tag needs the controller's release watcher (plan 04); tracked as an issue opened in Task 5.

## Rulings made during execution

- TUF expiry is its own error, `TrustError::Expired(String)`: the TUF client reports failures as text only, so it is recognised by the client's exact expiry message; other offline failures are `TrustError::Cache`, online ones `TrustError::Fetch`.
- The registry is looked up by the bare semantic version (`v1.2.3` -> `ghcr.io/<owner>/<repo>:1.2.3`), as `docker/metadata-action` `type=semver` tags it. The tag is a lookup hint only.
- Bundle selection: among the referrers of the digest, exactly one must have the bundle artifact type and the predicate type annotation `https://slsa.dev/provenance/v1` (SBOMs and unannotated descriptors are skipped, not counted); the selected manifest's own annotation must agree, and the bundle's signed statement is checked again by `verify_bundle`.
- Tag object ids are computed with `sha1-checked` (SHA-1 with collision detection); a collision attack is refused.
- The release tag must satisfy the OCI tag grammar `[A-Za-z0-9_][A-Za-z0-9._-]{0,127}` before it is used in a registry path.
- Bundles must be format v0.3 with exactly one Rekor v1 entry carrying an inclusion proof and an inclusion promise; Rekor v2 entries are refused until supported (#12).
- The Build Config URI must equal the SAN: the configured workflow attests itself; reusable-workflow pinning is refused in v0.
- `Platform` lives in `landfall-core` (`release` module) with the digest and platform rules; `landfall-origin` re-exports it once, from its crate root.
- The trust root is a newtype, `landfall_origin::trust::TrustRoot`, made only by `load_trusted_root` (a test-build constructor reads fixture snapshots); `verify_bundle` and `verify_release` take `&TrustRoot`, so production code verifies only against a root that came through TUF.
- `landfall verify` exit codes: 0 verified, 1 release refused (a verification check failed on material that was obtained), 2 could not verify (configuration, usage, network, HTTP status including 404, rate limit, trust root). `ReleaseError::is_refusal` and `FetchError::is_unavailable` draw the line; a missing or ambiguous provenance bundle is a refusal.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply (`unsafe_code = "forbid"`, clippy `all` + `pedantic` denied, `unwrap_used`, `expect_used`, `print_stdout`, `print_stderr`, `todo`, `dbg_macro` denied; tests may unwrap). No `#[allow]`/`#[expect]` without `reason = "..."`.
- `landfall-core` stays free of I/O, clock and randomness; time is passed in.
- Fail closed: every verification step returns a typed error naming what was expected and what was found; no step is skippable by configuration.
- Trust only the Fulcio certificate extensions and signed objects, never the provenance predicate or a registry tag.
- Errors are `thiserror` enums. No panics on attacker-controlled input (bundles, manifests, tag objects, API JSON).
- Fetchers: HTTPS only, base URLs injectable for tests, timeouts on every request (connect 10 s, total 30 s), response bodies capped (tag object 64 KiB, manifest 1 MiB, bundle 4 MiB) before parsing.
- Full gate before each commit: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --all-features --locked && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked && cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`.
- Public, generic repository: no real hostnames, addresses or user names. Test fixtures come from a public, widely used third-party project (not the maintainer's own repos), or are generated by a committed script with a throwaway key. Never commit a private key (push protection rejects it, and it must not exist anyway): commit the public key and the signed output only.
- Commits: conventional-commit subject, no `Co-Authored-By`, `Claude-Session` or "Generated with" trailers.

## Review Focus

1. **A tag object whose signed payload is altered by one byte (or has a trailing newline added)** fails verification, and a valid signature from a key not in the deployment's `origin.signers` is refused naming the key fingerprint → Task 1 `tampered_payload_is_refused`, `unknown_signer_is_refused`.
2. **A lightweight (unsigned) tag or an annotated tag with no signature** is refused with "tag is not signed", the case of releases cut by `gh release create` → Task 1 `unsigned_tag_is_refused`.
3. **A valid bundle for the right repo but a different tag, commit, workflow, trigger (`workflow_dispatch`) or a self-hosted runner** is refused, naming the extension that differed → Task 2 `each_identity_mismatch_is_named`.
4. **Expired or missing TUF metadata in offline mode** refuses to build a trust root rather than falling back to the embedded root alone → Task 3 `offline_with_empty_cache_fails_closed`.
5. **A hostile registry or API response (huge body, wrong media type, digest that does not match the bytes served)** is refused before parsing → Task 4 `oversized_body_is_refused`, `manifest_digest_mismatch_is_refused`.

---

### Task 1: Signer keys and SSH tag signatures (core)

**Files:**
- Create: `crates/core/src/tag.rs`, `crates/core/tests/fixtures/tag/` (signed tag objects + `README.md` + `make-fixtures.sh`)
- Modify: `crates/core/src/config/mod.rs`, `crates/core/src/config/raw.rs`, `crates/core/src/lib.rs`, `crates/core/Cargo.toml`, `Cargo.toml`, `docs/configuration.md`

**Interfaces:**
- Produces in `landfall_core::config`: `[signers]` values parsed into `SignerKey` (wraps `ssh_key::PublicKey`, ed25519 only, comment ignored); `fn signer(&self, id: &PrincipalId) -> Option<&SignerKey>`; `SignerKey::fingerprint(&self) -> String` (`SHA256:<base64>` as `ssh-keygen -l` prints). New `ConfigError` variant naming the signer and reason for an unparsable or non-ed25519 key.
- Produces in `landfall_core::tag`:
  - `struct SignedTag { pub tag: ReleaseTag, pub commit: CommitSha, pub signer: PrincipalId, pub fingerprint: String }`
  - `fn verify_tag(raw: &[u8], expected_tag: &ReleaseTag, signers: &[(PrincipalId, &SignerKey)]) -> Result<SignedTag, TagVerifyError>`
  - `TagVerifyError` variants: `NotSigned`, `Malformed { reason }`, `WrongType { found }` (object type must be `commit`), `WrongTag { found }`, `BadSignature`, `UnknownSigner { fingerprint }`, `WrongNamespace { found }`.
- Algorithm: the signed payload is `raw` up to the start of the last line beginning `-----BEGIN SSH SIGNATURE-----`; the rest is the armored `SshSig`. Parse headers (`object`, `type`, `tag`, `tagger`) from the payload only; headers end at the first empty line; duplicate or missing `object`/`type`/`tag` is `Malformed`. Verify with namespace `git`.

- [ ] **Step 1: Generate fixtures.** `make-fixtures.sh` creates a throwaway ed25519 key in a temp dir, a temp repo, and `git tag -s` (gpg.format=ssh) tags `v1.2.3` (valid), plus a second key's `v1.2.3` (unknown signer), and an unsigned annotated tag; writes raw tag objects (`git cat-file tag`) and the public keys, deletes the private keys. Commit only outputs.
- [ ] **Step 2: Write failing tests** in `tag.rs`: `valid_tag_verifies` (commit, signer, fingerprint as `ssh-keygen -lf` printed when generating, recorded in the README), `tampered_payload_is_refused` (flip a byte in the tagger line; append `\n` to the payload), `unknown_signer_is_refused`, `unsigned_tag_is_refused`, `wrong_tag_name_is_refused` (expect `v1.2.4`), `non_commit_object_is_refused` (fixture script also signs a tag of a tree object → `WrongType`), and `duplicate_headers_are_malformed` (a payload with two `object` lines → `Malformed`; headers are parsed before the signature is checked).
  In `config`: `signer_keys_are_parsed` (fixture key), `non_ed25519_signer_is_rejected` (an `ecdsa-sha2-nistp256` key text), `garbage_signer_is_rejected`; existing tests whose example key is not a real key get the fixture key.
- [ ] **Step 3: Run** `cargo nextest run -p landfall-core` → FAIL.
- [ ] **Step 4: Implement.** Update `docs/configuration.md` `[signers]` (ed25519 only; how to get the line: the `.pub` file).
- [ ] **Step 5: Full gate → PASS. Commit** `feat(core): parse signer keys and verify SSH-signed release tags`. Close #6 for signers in the PR body (COSE keys remain for plan 05: edit the issue title accordingly at PR time).

### Task 2: Sigstore bundle verification and Fulcio identity (origin crate)

**Files:**
- Create: `crates/origin/Cargo.toml`, `crates/origin/src/lib.rs`, `crates/origin/src/attestation.rs`, `crates/origin/tests/fixtures/attestation/` (one real bundle, its image index digest, a `trusted_root.json` snapshot, `README.md` with source and commands)
- Modify: `Cargo.toml` (member, deps), `deny.toml` (licences, per ruling), `Dockerfile` (dependency layer: `crates/origin/Cargo.toml` + stub `src/lib.rs`; add `-p landfall-origin` to `cargo clean`), `AGENTS.md` (crate map), `.github/dependabot.yml` unchanged (cargo already covered)

**Interfaces:**
- Consumes: `landfall_core::ids::{ReleaseTag, CommitSha, ImageDigest, RepoName}`, `config::{Repo, Origin}` accessors.
- Produces in `landfall_origin::attestation`:
  - `struct Expected<'a> { pub repo: &'a RepoName, pub repo_id: u64, pub owner_id: u64, pub workflow: &'a str, pub tag: &'a ReleaseTag, pub commit: &'a CommitSha }`
  - `struct VerifiedAttestation { pub digest: ImageDigest, pub san: String, pub commit: CommitSha, pub git_ref: String, pub repo_id: u64, pub owner_id: u64, pub run_url: String, pub rekor_log_index: u64, pub integrated_time: i64 }`
  - `fn verify_bundle(bundle_json: &[u8], digest: &ImageDigest, root: &TrustedRoot, expected: &Expected<'_>) -> Result<VerifiedAttestation, AttestationError>` where `TrustedRoot` is re-exported from `sigstore-trust-root`.
  - `AttestationError::{Bundle(String), Signature(String), Subject { expected, found }, Identity { field: &'static str, expected: String, found: String }}`
- Identity rules, from the spec: SAN = `https://github.com/<repo>/<workflow>@refs/tags/<tag>`; issuer `https://token.actions.githubusercontent.com`; Source Repository Digest = commit; Source Repository Ref = `refs/tags/<tag>`; Source Repository Identifier = repo_id; Source Repository Owner Identifier = owner_id; Build Trigger = `push`; Runner Environment = `github-hosted`. Repo name comparison is ASCII case-insensitive (GitHub names are); ids are exact. Reusable-workflow pinning is not in v0 (no config key exists yet).

- [ ] **Step 1: Fixtures.** Pick a public, widely used third-party project that publishes multi-arch GHCR images with `attest-build-provenance` (its tag signing does not matter here); download one bundle (`gh attestation download oci://...` or the attestations API), record image, index digest, repo and owner ids, workflow, tag, commit in the README; snapshot `trusted_root.json` (`gh attestation trusted-root` prints it). Verification in tests is offline against that snapshot.
- [ ] **Step 2: Write failing tests:** `real_bundle_verifies` (every `VerifiedAttestation` field equals the README values); `each_identity_mismatch_is_named` (table: wrong repo id, owner id, workflow, tag, commit; for each, `Identity.field` is the expected name); trigger and runner mismatches: re-sign is impossible, so test the matcher function `match_identity(&CertificateIdentity, &Expected)` directly with a struct literal for `workflow_dispatch` and `self-hosted`; `wrong_digest_is_refused` (`Subject`); `tampered_bundle_is_refused` (flip one base64 char of the signature; flip one byte of the DSSE payload; drop the inclusion proof) each `Err`; `garbage_is_refused` (empty, `{}`, 4 MiB of `[`) without panic.
- [ ] **Step 3: Run** → FAIL. **Step 4: Implement**, with `match_identity` a pure function over a small `CertificateIdentity` struct mapped from `ci_claims`.
- [ ] **Step 5: Full gate → PASS** (crate-age too). **Commit** `feat(origin): verify build-provenance bundles and their Fulcio identity`.

### Task 3: Trust root from TUF

**Files:**
- Create: `crates/origin/src/trust.rs`, `crates/origin/assets/sigstore-root.json` (public-good root, with source URL and version noted in a sibling `README.md`)
- Modify: `crates/origin/src/lib.rs`, `.github/workflows/advisories.yml` (nightly job `live` running `cargo test -p landfall-origin --locked -- --ignored`)

**Interfaces:**
- Produces: `enum Refresh { Online, Offline }`; `async fn load_trusted_root(cache_dir: &Path, refresh: Refresh) -> Result<TrustedRoot, TrustError>`. Embedded root bootstraps TUF; cache under `cache_dir`; `Offline` re-verifies the cache and fails when it is missing or its timestamp has expired. `TrustError::{Cache(String), Expired, Fetch(String)}`.

- [ ] **Step 1: Failing tests:** `offline_with_empty_cache_fails_closed` (temp dir, `Offline` → `Err`); `cache_dir_must_exist` (nonexistent dir → `Cache` error, never created implicitly elsewhere); `live_refresh_then_offline` marked `#[ignore = "network: runs nightly in advisories.yml"]`: `Online` into a temp dir, then `Offline` from it, both `Ok`, and the root verifies Task 2's fixture bundle.
- [ ] **Step 2: Run → FAIL. Step 3: Implement** with `TufConfig` pinned to `https://tuf-repo-cdn.sigstore.dev` and the embedded root, the HTTP client carrying the Global Constraints timeouts.
- [ ] **Step 4: Full gate → PASS**; also run the ignored test once locally. `uvx zizmor .` clean. **Commit** `feat(origin): Sigstore trust root from TUF, fail closed offline`.

### Task 4: GitHub and GHCR fetchers

**Files:**
- Create: `crates/origin/src/fetch.rs`
- Modify: `crates/origin/src/lib.rs`

**Interfaces:**
- Produces: `struct Fetcher` built with `Fetcher::new(Endpoints)` where `Endpoints { github_api: Url, registry: Url }` (defaults `https://api.github.com`, `https://ghcr.io`), optional GitHub token for rate limits (sent only to `github_api`).
  - `async fn tag_object(&self, repo: &RepoName, tag: &ReleaseTag) -> Result<Vec<u8>, FetchError>`: `git/ref/tags/<tag>` → must be `type: tag` (a lightweight tag returns `FetchError::LightweightTag`) → `git/tags/<sha>`; raw object = `verification.payload` + `verification.signature` bytes exactly (no added newline); recompute the git object id `sha1("tag <len>\0" + raw)` and require it equals `<sha>`.
  - `async fn resolve_index(&self, image: &str, tag: &ReleaseTag) -> Result<(ImageDigest, Vec<Platform>), FetchError>`: anonymous pull token, `GET /v2/<image>/manifests/<tag>` accepting OCI index and Docker manifest list only; digest = sha256 of the bytes received, compared to `Docker-Content-Digest` when present.
  - `async fn bundle(&self, image: &str, digest: &ImageDigest) -> Result<Vec<u8>, FetchError>`: referrers tag `sha256-<hex>` → manifest(s) with artifactType `application/vnd.dev.sigstore.bundle.v0.3+json` → its single layer blob, digest checked against the descriptor. Zero or several bundles → `FetchError::Bundles { count }`.
  - `async fn tag_commit(&self, repo: &RepoName, tag: &ReleaseTag) -> Result<CommitSha, FetchError>`: the commit the tag ref points to, peeling an annotated tag (used when `signed_tags = false`). Test: `tag_commit_peels_annotated_and_lightweight`.
  - `struct Platform { pub os: String, pub architecture: String, pub variant: Option<String> }`
- [ ] **Step 1: Failing tests** with `wiremock`: `tag_object_round_trips` (serve Task 1 fixture split into payload/signature JSON; bytes equal the fixture), `lightweight_tag_is_refused`, `tag_object_id_mismatch_is_refused`, `index_digest_is_computed_from_bytes`, `manifest_digest_mismatch_is_refused` (header disagrees), `single_arch_manifest_is_refused`, `bundle_is_found_by_referrers_tag`, `two_bundles_are_refused`, `oversized_body_is_refused` (limit + 1 bytes), `token_is_not_sent_to_registry`.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Commit** `feat(origin): fetch tag objects, image indexes and bundles`.

### Task 5: verify_release, digest and platform rules, `landfall verify`

**Files:**
- Create: `crates/core/src/release.rs`, `crates/origin/src/release.rs`, `crates/cli/src/verify.rs`
- Modify: `crates/core/src/lib.rs`, `crates/origin/src/lib.rs`, `crates/cli/src/main.rs`, `crates/cli/Cargo.toml`, `docs/configuration.md` (link), `README.md` (verify command)

**Interfaces:**
- Produces in `landfall_core::release`: `fn select_release_digest(candidates: &[ImageDigest]) -> Result<&ImageDigest, DigestRuleError>` (`None` / `Several { digests }`; duplicates of the same digest count once); `fn require_platform(platforms: &[Platform], want: &Platform) -> Result<(), PlatformError>` (`Platform` moves to core; origin re-exports it; `variant` matches when `want.variant` is `None` or equal).
- Produces in `landfall_origin::release`: `struct ReleaseOrigin { pub commit: CommitSha, pub tag: Option<SignedTag>, pub attestation: VerifiedAttestation, pub platforms: Vec<Platform> }` (serde `Serialize`); `async fn verify_release(fetcher: &Fetcher, root: &TrustedRoot, config: &Config, deployment: &DeploymentId, tag: &ReleaseTag, platform: &Platform) -> Result<ReleaseOrigin, ReleaseError>`. Order: tag pattern → if `origin.signed_tags`: tag object + signature (signers from `origin.signers`), else `tag_commit` (and `ReleaseOrigin.tag` is `None`, so `tag: Option<SignedTag>` plus `commit: CommitSha`) → index digest and platforms → `select_release_digest(&[digest])` → bundle → `verify_bundle` with the signed commit → platform. `ReleaseError` wraps each step's error with the step name.
- CLI: `landfall verify --config <file> --deployment <id> --tag <tag> [--platform linux/arm64] [--cache-dir <dir>] [--offline]`, prints `ReleaseOrigin` as JSON on stdout, exits non-zero with the error chain on stderr. `--platform` defaults to the running machine's. The workspace lint denies `print_stdout`: write through `std::io::Write` on a locked stdout handle.
- [ ] **Step 1: Failing tests:** core `several_digests_are_refused`, `same_digest_twice_counts_once`, `no_digest_is_refused`, `missing_platform_is_refused`, `variant_must_match_when_asked`. Origin, with `wiremock`: one test per step that fails at that step (bad tag pattern, lightweight tag when signed, unsigned deployment succeeds past the tag step with a lightweight tag, bad signature, single-arch manifest, no bundle, identity mismatch, missing platform) and asserts the `ReleaseError` names that step. No fixture tag and bundle share a repo, so the success path is checked by hand in Step 4; a nightly live test against landfall's own first signed release is tracked as an issue opened in Step 5.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS**, then run `landfall verify` by hand against one real attested, SSH-signed release and paste the JSON in the task report (not in the repo).
- [ ] **Step 5: Open issues** "Nightly live verify of landfall's own latest release" and "Find every attested digest for a release tag (exactly-one rule needs candidate discovery)" referencing spec 5.2 step 4, for plan 04. **Commit** `feat: verify a release end to end; landfall verify`.
