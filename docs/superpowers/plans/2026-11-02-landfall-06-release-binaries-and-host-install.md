# landfall plan 06: Release binaries and `host install` Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A signed tag publishes attested `landfall-agent` and `landfall` binaries beside the image (#21), and `landfall host install <user@host> --host <id>` takes a host from nothing to enrolled, from a release it verified itself, over the operator's own SSH (#22).

**Architecture:** The Dockerfile's builder also produces the static binaries, and `release.yml` attests them in one bundle and publishes them through a draft. `landfall-origin` gains a verifier for a named release file, sharing `verify_bundle`'s checks. The CLI drives the system `ssh`: a read-only probe, an unprivileged upload, and one generated script run once under `sudo`, printed first. The agent gets no self-update and the controller no new route.

**Tech Stack:** Rust 1.99 (edition 2024). No new crate except `url` as a direct dependency of `landfall-core` (already in the tree through `reqwest`). OpenSSH's `ssh` on the operator's machine. Python 3 standard library for release scripts, as `crate_age.py` is. `cargo-zigbuild` and `zig` as already pinned in the Dockerfile. GitHub-owned actions only, so the allow-list doesn't change.

**Spec:** issues #21 and #22; `docs/design/landfall.md` (sections 3, 4, 5.2, 9, 12); `docs/operations.md` ("Requirements", "Running it under systemd", "Enrolling a host", "Running the agent", "Upgrading"); the public repository baseline that design section 3 refers to.

## Rulings made while writing this plan

Each says what it costs if it is wrong.

- **One plan, five PRs, in order.** PR A: build and check binaries, publishing nothing. PR B: publish them. PR C: verify a release file. PR D: `host install`. PR E: `host upgrade` and the guide. PR C to E can merge before any release exists, since their tests use fixtures and a fake source. *If wrong:* a late discovery about the real bundle (see the first-tag list) means a follow-up PR on merged code, not a redo.
- **Targets:** `landfall-agent` for linux/arm64 and linux/amd64; `landfall` for those and darwin/arm64, as #21 says. No macOS on Intel, no Windows, and no `landfall-server` binary, whose route remains the image. Linux binaries are static musl from the existing Dockerfile builder, with zig, so there is one way to build them; macOS builds natively on a GitHub-hosted arm64 runner. *If wrong:* adding a target is one line in the build matrix and one in the asset table.
- **One builder invocation.** `cargo zigbuild -p landfall-server -p landfall-agent -p landfall-cli`, so the dependency layer is shared and the PR dry run costs little more than today's image build. Features unify across the three, which can make the agent slightly larger; the size budget would show it. *If wrong:* split the agent into its own invocation and pay for a second compile of the dependency tree.
- **Raw executables, not archives.** The attested digest is then the file the target runs, so the hash checked on the host is the attested one, with no unpacking step on a root path. Licences are their own assets. *If wrong:* Homebrew still accepts a raw file; an archive could be added beside it in a later release.
- **Signing is keyless: one attestation with every file as a subject.** `actions/attest-build-provenance` with `subject-path: out/*` gives one Sigstore bundle, attached to the release as `landfall-<version>.sigstore.json`. No key exists to lose. `sigstore-types` 0.15's `matches_sha256` is an `any` over subjects (read for this plan), so `verify_bundle`'s Sigstore step accepts this shape. The bundle is an asset, not fetched from GitHub's attestation API, because that API can answer `bundle: null` with a compressed `bundle_url` (seen on `cli/cli` while writing this plan). *If wrong:* per-file attestations mean one attest step per file, and the verifier is unaffected.
- **The subject's name is checked as well as its digest.** A bundle vouches for every file of the release, so digest alone would accept the amd64 agent asked for as arm64, or the CLI as the agent. The new check wants a subject with both the exact name and the digest, in the signed statement. *If wrong:* it fails closed on a name format we misjudged, which the first-tag check in the publish job catches before anything is public.
- **One verifier.** `landfall-origin` gains `attestation::verify_file_bundle`, on the same internals as `verify_bundle` (same parse rules, same identity match, Rekor v1 with proof and promise). The identity is constants in the CLI: repository `pecheriere/landfall`, id `1441186089`, owner id `1872741`, `.github/workflows/release.yml`. Numeric ids, so a re-created account can't take over. *If wrong:* a fork changes one file and rebuilds, and there is deliberately no flag for it.
- **`host install` also requires the signed tag, not only the attestation.** #22 names the attestation; the design's reason for signed tags applies more here, since the agent is root-equivalent: a stolen GitHub token can run the workflow but can't sign a tag. The trusted public key is in `crates/cli/assets/release-signers`, an `ssh-ed25519` line with no comment, which the owner supplies. Rotating that key needs a new CLI, installed by hand with `gh attestation verify`. *If wrong:* an empty file makes `host install` refuse with a clear message, and the release preflight refuses to publish such a CLI, so the failure is early.
- **The workflow can't attest on a dry run, on purpose.** `verify_bundle` requires build trigger `push`. A `workflow_dispatch` run builds, checks and smoke-tests, then skips `publish`; it writes nothing to Rekor. So the real bundle is first seen at the first tag, and the publish job checks its shape before anything becomes public. *If wrong:* the first tag's run fails in `publish`, leaving a draft, and the fix goes out under the next patch tag.
- **A publish run has one attempt.** The design's rule 4 refuses a release whose image was attested by two attempts, and tags can't be moved. So `publish` fails at once if `GITHUB_RUN_ATTEMPT` isn't 1, and the way out of any failed release is a new patch tag. Files go up as a draft before the image is pushed, as the draft is the part that can be abandoned. *If wrong:* a transient failure costs one patch number.
- **`release` environment:** `publish` runs in it. GitHub silently creates a missing environment with no protection, so an `environment-guard` job reads it through the API and fails unless it has a required reviewer, and `publish` needs that job. It doesn't exist today (checked: the repository has no environments), and today's `publish` runs without one, which this plan fixes. *If wrong:* if the job's token can't read the environment, the dispatch run shows it before any tag.
- **SSH is the system's `ssh`, never a library.** So the user's agent, `ProxyJump`, tailnet SSH and hardware keys all work and no key material comes near landfall. Forced on every call, whatever the config says (`-o` wins over `~/.ssh/config`): `BatchMode=yes`, `StrictHostKeyChecking=yes`, `VerifyHostKeyDNS=no`, `UpdateHostKeys=no`, `ForwardAgent=no`, `ForwardX11=no`, `ClearAllForwardings=yes`, `PermitLocalCommand=no`, `SendEnv=-*`, and `GITHUB_TOKEN` removed from the child's environment. An unknown host is refused, and the message says to connect once by hand and compare the fingerprint; landfall never runs `ssh-keyscan` or accepts a key. *If wrong:* password SSH logins are refused outright, which suits the agent-only rule and is stated in the guide.
- **One connection:** a `ControlMaster` socket in a fresh 0700 directory under `/tmp` (a macOS `$TMPDIR` is too long for a socket), `ControlPersist=60`, closed on exit, so a hardware key is touched once. *If wrong:* more touches, nothing worse.
- **sudo:** the whole privileged part is one script and one `sudo sh -c '<script>'`, printed first, in full, with its SHA-256. It is passed as an argument so that no file in a user-writable directory is run as root. It holds no secret. With a terminal it uses `ssh -tt` and sudo's own prompt, so landfall never sees the password; without one it uses `sudo -n` and refuses cleanly. Already root runs `sh -c` without sudo. No `sudo -S`, no `doas`. *If wrong:* a sudoers file that allows only named commands can't use this; the guide gives the manual steps it already has. On a terminal it asks `y/N` after printing; `--yes` skips that, and no terminal without `--yes` refuses.
- **Secrets:** the enrolment code goes from `--code-file` over `ssh` stdin into a `mktemp -d` directory (umask 077), last and immediately before the script. The script moves it to `/var/lib/landfall-agent/.enrol-code`, 0600, owned by the agent, and removes it on every exit path. It never appears in argv, the printed plan or an error. A leftover after a cut connection is one-time and expires within the hour, and the next run removes stale upload directories. `GITHUB_TOKEN` is never sent to the target; the unit has `EnvironmentFile=-/etc/landfall/agent.env`, for the operator to fill. *If wrong:* a code exposed on the host for its short life, to the same user who holds sudo.
- **Hash checks are root's.** The script copies the upload to a root-owned `/usr/local/bin/.landfall-agent.new` and only then compares its SHA-256 with the verified digest written in the script, and renames. A check before the copy would leave a window for another process of the login user to swap the file. *If wrong:* nothing weaker than a local-user race could get in.
- **Idempotence and interruption:** every step looks first and changes only what differs, each file arrives by rename, and `agent.key` is only ever touched by `landfall-agent enrol`, which never overwrites it. A rerun converges from any point, so there is no resume state. *If wrong:* a step that isn't convergent; `docker_interrupted_at_every_step_converges` exists to find that.
- **The host still decides.** The CLI never talks to the controller, and the code is minted by the operator on the controller as today. An existing `/etc/landfall/fleet.toml` or unit that differs is **refused** unless `--replace-config` or `--replace-unit` is given, because silently replacing the host's own rules would be the one way this command could loosen them. Config comes from the operator's file, checked by `parse_config` before connecting, and must have a deployment for `--host` (else the agent can't start). `install` refuses a different agent binary already there (use `upgrade`). Compose directories must already exist; they are never created. *If wrong:* a little friction on a re-install, by design.
- **Version floors:** Linux 5.8 (documented), `docker compose` plugin v2, Docker client 20.10, the oldest a compose v2 plugin supports. Checked from client commands, so no sudo is needed to see them; the daemon is checked as the agent's user in the script. Low on purpose: nothing in the repo shows a higher floor is needed. *If wrong:* an old Docker passes this check and the deploy's own preflight refuses it with its own message.
- **Which release:** the CLI's own version, `v<CARGO_PKG_VERSION>`, or `--tag`. Today's workspace version is `0.0.0`, so a release must bump it: the preflight refuses a tag that isn't `v<workspace version>`, and a CLI at `0.0.0` refuses to guess and asks for `--tag`. *If wrong:* the tag fails at preflight, which costs a tag number.
- **`host upgrade`:** same verification and script path; touches only the binary and a restart. Refuses a downgrade without `--allow-downgrade`, and a host with no unit. Keeps `/usr/local/bin/landfall-agent.previous` and prints how to go back; it doesn't roll back by itself. It restarts with `--no-block`, as a stop waits for a running deploy (up to three hours): waits two minutes, then says plainly if the agent is still finishing a deploy. Operator-run, in line with "landfall never deploys landfall". *If wrong:* the new binary fails to start; deployed services are untouched and the printed command restores it.
- **Homebrew tap: a second repository, created by the owner.** `brew install <owner>/landfall/landfall` needs one named `homebrew-landfall`. Pushing to it from this repo's workflow would need a long-lived token, so nothing here does. `release.yml` generates `landfall.rb`, pinned by SHA-256 and attested as a subject, and attaches it. A workflow in the tap, whose template lives here in `packaging/homebrew-tap/`, polls for the latest release, runs `gh attestation verify` on the formula and commits it with the tap's own token. Everything else works without a tap. No `curl | sh` script. *If wrong:* the owner copies one file per release by hand.
- **macOS binaries aren't notarised:** that needs a paid identity and a long-lived certificate, which this project refuses. Homebrew and `gh release download` don't set the quarantine flag; a browser does, and the guide says so. *If wrong:* some people meet a Gatekeeper dialog.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply. No `#[allow]`/`#[expect]` without `reason = "..."`. `unsafe_code` forbidden. No `unwrap`/`expect` outside tests. Public error enums are `#[non_exhaustive]`.
- Source files stay under about 800 lines of code, and tests go in their own files, as `foo/tests.rs` and `foo/tests/<scenario>.rs`, naming what they import.
- Public baseline: actions pinned to the full SHA of a release at least 7 days old, with the tag in a comment; `persist-credentials: false`; `--locked`; `timeout-minutes` on test jobs; publish jobs in the `release` environment with no build cache; values through `env`, never inline; `GH_TOKEN=$(gh auth token) uvx zizmor .` reports nothing before a workflow change is pushed.
- Everything fetched, and everything a target prints, is hostile: bodies capped before parsing, text quoted and truncated in errors, no panics.
- Nothing personal in code, docs, tests or commits: example names only (`app/prod`, `home-1`, `user@host.example`, `https://controller.example`). The project's own repository name and public ids are already public, and appear only in `crates/cli/src/project.rs` and the workflow.
- **No real host, network or firewall change as part of testing.** Host tests run against a throwaway container with `sshd`: no host mounts, no `--network host`, port published on `127.0.0.1` only.
- Never tag or release, and never `gh release` from a shell: only `release.yml` does that, after the owner's tag and approval.
- Security review (`security-review` skill) before merging PR B, C, D and E, recorded in the PR. Each PR says what was and wasn't verified, separating CI from local.
- Gate before each commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`. Python: `ruff check`, `ruff format --check`, `python3 -I -m unittest discover -s .github/scripts -p 'test_*.py'`. Conventional commits, no attribution trailers.

**Release assets,** for version `1.2.3`, exact names, the same in Python and Rust:

| Asset | Attested subject |
|---|---|
| `landfall-agent-1.2.3-linux-arm64`, `landfall-agent-1.2.3-linux-amd64` | yes |
| `landfall-1.2.3-linux-arm64`, `landfall-1.2.3-linux-amd64`, `landfall-1.2.3-darwin-arm64` | yes |
| `SHA256SUMS`: `<hex>  <name>` for every other subject, sorted by name | yes |
| `landfall.rb`, `LICENSE-MIT`, `LICENSE-APACHE` | yes |
| `landfall-1.2.3.sigstore.json` | no: it is the attestation |

**Which tests need what:**

| Tests | Needs | When |
|---|---|---|
| Everything not `#[ignore]`d, including the `sh -n` and quoting tests | `/bin/sh` | Normal suite. No Docker, no network, adds seconds |
| `crates/cli/tests/docker_host_install/`, `#[ignore]`d, named `docker_` | Docker, `ssh`, `ssh-keygen`, `LANDFALL_TEST_DIST` | CI's separate `host-install` job, and by hand after changing `crates/cli/src/host/`. `check` keeps `-p landfall-agent`, so it doesn't run them. About two minutes |
| `live_` in `crates/cli` | Network, and a real release | Nightly in `advisories.yml`. Passes with nothing to do until a release exists |
| Binary dry run | Docker buildx | Second step of `docker-build`, sharing its cache; a few minutes more on a cold cache, little on a warm one |
| macOS build and tests | macOS runner | Own workflow, filtered by path, not a required check, so most PRs skip it |

## Review Focus

1. **A valid file of the same release under the wrong name,** such as the amd64 agent as arm64, or the CLI as the agent, must be refused, though its digest is attested → Task 4 `another_files_digest_is_refused_under_this_name`.
2. **A user's `ssh_config` that weakens host-key checking** (`StrictHostKeyChecking no`, `UserKnownHostsFile /dev/null`) must not weaken this command → Task 8 `docker_config_that_turns_off_checking_is_still_refused`.
3. **An install cut off at any point,** including during upload, leaves no code behind on the next run, keeps the key and converges → Task 8 `docker_interrupted_at_every_step_converges`, `docker_nothing_secret_is_left_behind`.
4. **A host with something already there:** an existing key, a config or unit the operator changed, an agent already running → Task 8 `docker_existing_key_survives_a_new_code`, `docker_changed_config_is_refused`, and Task 6 `a_code_for_a_running_agent_is_refused_in_the_script`.
5. **An arm64 kernel with 16 KiB pages** (the default on some single-board computers) can't run a binary whose load segments are aligned to 4 KiB, and fails only there → Task 1 `arm64_load_segments_must_suit_16k_pages`. No test here runs on such a kernel, which is on the owner's list.

## What only the owner can do

Nothing here is needed before PR A to E merge, except step 1 for a green dispatch run.

1. **Create the `release` environment,** with yourself as required reviewer and deployments limited to tags matching `v[0-9]*`. Add `host-install` to the `main` ruleset's required checks.
2. **Supply the tag-signing public key** for `crates/cli/assets/release-signers`: the `ssh-ed25519` key you sign tags with (other types are refused). It goes in by PR.
3. **Choose the first version.** An agent bumps `workspace.package.version` and the `landfall-*` path dependency versions by PR. Then run the `Release` workflow by `workflow_dispatch` on main and check it's green.
4. **Tag and approve:** `git tag -s v<version>`, push the tag, approve the `publish` job. **Never re-run a failed run:** abandon its draft and tag the next patch.
5. **After the first release,** check the first-tag list in Task 3, then try `landfall host install --dry-run` on a host of your choice, and a real install on a spare one, which covers what the container can't: a real sudo password prompt, real Docker and, if you have one, a 16 KiB-page kernel.
6. **Homebrew:** create `homebrew-landfall` as a public repo under the same baseline, add the files from `packaging/homebrew-tap/`, run its workflow once, then `brew install` and `landfall --version`.

---

## PR A: build and check, publishing nothing (#21)

### Task 1: Static binaries from the builder, checked on every PR

**Files:** Modify `Dockerfile`, `.github/workflows/ci.yml`, `Cargo.toml` (only if Step 5 says so), `AGENTS.md`. Create `.github/scripts/check_binaries.py`, `.github/scripts/test_check_binaries.py`, `.github/workflows/macos.yml`.

**Interfaces:**
- Dockerfile stage `binaries`, before the unnamed final stage (which must stay last and stay the image): `FROM scratch AS binaries` holding `/landfall-agent`, `/landfall`, `/landfall-server`. `docker buildx build --target binaries --platform linux/arm64,linux/amd64 --output type=local,dest=dist .` gives `dist/linux_arm64/` and `dist/linux_amd64/`.
- `check_binaries.py <dist>`: exit 1 naming each failure. For each file in `linux_arm64` and `linux_amd64`: ELF, `e_machine` right for the directory (`0xB7`, `0x3E`), no `PT_INTERP`, every `PT_LOAD` `p_align` at least `0x4000` on arm64, size within `MAX_BYTES`. Pure Python header parsing, no `readelf`.

- [ ] **Step 1: Failing tests** in `test_check_binaries.py`, building small ELF headers in bytes: `accepts_a_static_binary`, `dynamic_binary_is_refused` (has `PT_INTERP`), `wrong_architecture_for_its_directory_is_refused`, `arm64_load_segments_must_suit_16k_pages` (`p_align` `0x1000` refused, `0x10000` accepted, `0x1000` on amd64 accepted), `over_budget_is_refused`, `not_an_elf_is_refused`, `truncated_header_does_not_crash`. Run: `python3 -I -m unittest discover -s .github/scripts -p 'test_*.py'`. Expected: FAIL.
- [ ] **Step 2: Implement `check_binaries.py`.** Run the tests. Expected: PASS.
- [ ] **Step 3: Dockerfile.** Both `cargo zigbuild` lines take `-p landfall-server -p landfall-agent -p landfall-cli`; the `cargo clean` line adds `-p landfall-agent -p landfall-cli`. Install to `/out/binaries/`, and the `binaries` stage copies that. Keep the image's contents as they are.
- [ ] **Step 4: Build both platforms locally** with the command above into the scratch directory, and run `check_binaries.py`. Expected: arch and static checks pass. If the arm64 alignment check fails, add `[target.aarch64-unknown-linux-musl] rustflags = ["-C", "link-arg=-Wl,-z,max-page-size=65536"]` to a new `.cargo/config.toml`, rebuild, recheck.
- [ ] **Step 5: Measure and set the budget.** Record each binary's size in the PR. Try `lto = "thin"` and `codegen-units = 1` under `[profile.release]`; keep them only if the agent shrinks by more than 15% and the cold build grows by under 50%, and record the numbers either way. Set `MAX_BYTES` to the kept size times 1.25, rounded up to a MiB, with a comment giving the measured size and date. This answers #21's size question.
- [ ] **Step 6: CI.** In `docker-build`, after the image build: `docker/build-push-action` with `target: binaries`, `outputs: type=local,dest=dist`, `provenance: false`, `sbom: false`, `push: false`, `cache-from: type=gha,scope=docker-build`, then `python3 -I .github/scripts/check_binaries.py dist` and `dist/linux_amd64/landfall --version` and `dist/linux_amd64/landfall-agent --version`. New `macos.yml`, `on: pull_request` and `push` to main, `paths:` `crates/cli/**`, `crates/origin/**`, `crates/core/**`, `crates/approval/**`, `Cargo.lock`, `rust-toolchain.toml`, `.github/workflows/macos.yml`; a pinned arm64 macOS runner label; rust-cache; `timeout-minutes: 30`; `cargo test -p landfall-cli --locked` and `cargo build --release --locked -p landfall-cli --target aarch64-apple-darwin`, then run `--version`. A path-filtered workflow can't be a required check, and isn't.
- [ ] **Step 7: Gate; `uvx zizmor .`; `docker build .` still gives the image; update `AGENTS.md` CI section.** Open PR A from a fresh branch. Commit: `feat(ci): build and check static agent and CLI binaries`.

## PR B: publish them (#21)

### Task 2: Assemble the release files

**Files:** Create `.github/scripts/assemble_release.py`, `.github/scripts/release_preflight.py`, `.github/scripts/test_assemble_release.py`, `.github/scripts/test_release_preflight.py`, `crates/cli/assets/release-signers` (empty).

**Interfaces:**
- `assemble_release.py assemble --dist <linux artifacts> --macos <dir> --version <v> --repo <owner/name> --out <dir>`: copies with the exact names in the assets table, mode 0755; copies the licences; writes `SHA256SUMS` and `landfall.rb`.
- `assemble_release.py check-bundle --bundle <file> --out <dir>`: refuses unless the bundle is v0.3, has exactly one tlog entry with `inclusionProof` and `inclusionPromise`, predicate type `https://slsa.dev/provenance/v1`, and its statement names every file in `<dir>` by **basename and sha256**, and no other. This is what proves the Rust verifier will accept it, before anything is public.
- `release_preflight.py --tag <tag>`: refuses unless the tag is `v` plus `workspace.package.version` from `Cargo.toml` (`tomllib`), and `crates/cli/assets/release-signers` holds at least one `ssh-ed25519` line.

- [ ] **Step 1: Failing tests:** `names_match_the_table`, `missing_input_binary_is_refused`, `sums_cover_every_subject_and_are_sorted`, `sums_do_not_list_themselves`, `formula_pins_each_platform_url_and_hash`, `formula_has_any_of_license_and_a_version_test`, `formula_parses_as_ruby` (`ruby -c`, skipped with a message where `ruby` is missing, required in CI by `LANDFALL_TEST_REQUIRE_RUBY`), `bundle_naming_every_file_passes`, `bundle_missing_a_file_is_refused`, `bundle_with_a_wrong_digest_is_refused`, `bundle_with_an_extra_subject_is_refused`, `bundle_without_a_promise_is_refused`, `prerelease_versions_name_files_the_same_way`; `tag_must_match_workspace_version`, `empty_signers_are_refused`, `comment_only_signers_are_refused`, `non_ed25519_signer_is_refused`. Expected: FAIL.
- [ ] **Step 2: Implement.** The formula: `desc`, `homepage`, `version`, `license any_of: ["MIT", "Apache-2.0"]`, `on_macos { depends_on arch: :arm64; url; sha256 }`, `on_linux { on_arm {...}; on_intel {...} }`, `bin.install Dir["landfall-*"].first => "landfall"`, and `test do assert_match version.to_s, shell_output("#{bin}/landfall --version") end`. Run the tests. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `feat(release): assemble release files and a Homebrew formula`.

### Task 3: The release workflow

**Files:** Modify `.github/workflows/release.yml`, `.github/workflows/ci.yml` (`LANDFALL_TEST_REQUIRE_RUBY: "1"` on the Python test step), `AGENTS.md`, `CONTRIBUTING.md`, `docs/design/landfall.md` (section 3: binaries are attested too). Create `packaging/homebrew-tap/README.md`, `packaging/homebrew-tap/update-formula.yml`.

**Interfaces:** Triggers are the tag push as now, plus `workflow_dispatch`. Top-level `permissions: contents: read`.

| Job | Runs on dispatch | Needs | Does |
|---|---|---|---|
| `on-main`, `crate-age`, `ci` | yes | as now | unchanged |
| `preflight` | tag only | `on-main` | `release_preflight.py --tag "$GITHUB_REF_NAME"`, through `env` |
| `environment-guard` | yes | | `permissions: { actions: read, contents: read }`; `gh api` on the `release` environment, fails unless `protection_rules` has `required_reviewers` |
| `build-linux` | yes | `on-main` | Buildx, `target: binaries`, no cache inputs, `check_binaries.py`, upload artifact, 7-day retention, `if-no-files-found: error` |
| `build-macos` | yes | `on-main` | Toolchain, no rust-cache, `cargo build --release --locked -p landfall-cli --target aarch64-apple-darwin`, upload |
| `smoke` | yes | both builds | Matrix: `ubuntu-24.04`, `ubuntu-24.04-arm`, the macOS label. Download only, run each native binary's `--version`, and on a tag compare with the tag |
| `publish` | **no**: `if: github.event_name == 'push'` | all above | See below |

`publish`: `environment: release`; `permissions: { contents: write, packages: write, id-token: write, attestations: write }`; no cache of any kind. In order:

1. Fail if `GITHUB_RUN_ATTEMPT` isn't `1`, saying why and to tag the next patch.
2. Checkout, download artifacts, `assemble_release.py assemble` into `out/`.
3. `actions/attest-build-provenance` (the existing pin), `subject-path: out/*`, in `release.yml` itself: `verify_bundle` refuses a reusable workflow's identity.
4. `assemble_release.py check-bundle` with `steps.attest.outputs.bundle-path`, then copy it to `out/landfall-<version>.sigstore.json`.
5. `gh release create "$TAG" out/* --draft --verify-tag --generate-notes`, with `--prerelease --latest=false` when the version has a `-`.
6. The existing image steps, unchanged, ending with its attestation.
7. `gh release edit "$TAG" --draft=false`. Files locked by immutable releases from here.

`update-formula.yml`, for the tap: `on: schedule` (daily) and `workflow_dispatch`; `permissions: contents: write`; `gh release view --repo pecheriere/landfall --json tagName` for the latest; `gh release download` of `landfall.rb`; `gh attestation verify landfall.rb --repo pecheriere/landfall --signer-workflow pecheriere/landfall/.github/workflows/release.yml --source-ref "refs/tags/$tag" --deny-self-hosted-runners`; commit to `Formula/landfall.rb` if changed.

**How far this can be checked without a tag:**

| Check | Covers | Who |
|---|---|---|
| `uvx zizmor .`, `actionlint` if available, and reading the job graph | Syntax, pins, permissions | PR B |
| Python tests with made-up bundles | Names, sums, formula, bundle shape | PR B |
| `ci.yml`'s binary step | Linux build with a cache, static, sizes | Every PR |
| `workflow_dispatch` on main, after merge | Cache-free Linux and macOS builds, smoke on all three, the environment guard. Publishes nothing, writes nothing to Rekor | Owner, or an agent with the owner's say-so |

**Only the first tag shows** (the first-tag list): the reviewer's approval works; a real bundle passes `check-bundle`, confirming subject names are basenames; `gh release` from draft to public; the release reads `immutable: true`; `gh attestation verify` passes on a file; `live_agent_release_verifies` goes from nothing to do to a real pass that night; `landfall verify` still works on the image, proving `candidates` doesn't see binary attestations (they aren't pushed to the registry).

- [ ] **Step 1: Write the workflow.** Resolve pins for `actions/upload-artifact` and `actions/download-artifact` (GitHub-owned, so already allowed), each at least 7 days old, with `gh api`. Use the `$/` self-reference as now. Run: `GH_TOKEN=$(gh auth token) uvx zizmor .`. Expected: no findings, including on `packaging/homebrew-tap/update-formula.yml`, passed by path.
- [ ] **Step 2: Docs.** `AGENTS.md`, "CI and supply chain": release assets, one attempt, the guard. `CONTRIBUTING.md`: how to cut a release, the owner's list. `packaging/homebrew-tap/README.md`: how the tap is set up, and why no token crosses repositories.
- [ ] **Step 3: Gate; security review. Commit:** `feat(release): publish attested binaries through a draft`. Open PR B, listing the first-tag items as not verified.

## PR C: verify a release file (#22)

### Task 4: `verify_file_bundle` in `landfall-origin`

**Files:** Modify `crates/origin/src/attestation.rs`. Create `crates/origin/src/attestation/file.rs`, `crates/origin/src/attestation/tests/files.rs`, `crates/origin/tests/fixtures/attestation-files/` (with a README giving how it was obtained).

**Interfaces:**
- Split a private `verify_parsed(bundle: &Bundle, digest: &ImageDigest, root: &TrustRoot, expected: &Expected<'_>) -> Result<VerifiedAttestation, AttestationError>` out of `verify_bundle`, holding everything after the statement check. `verify_bundle`'s behaviour and tests don't change.
- `pub struct FileSubject<'a> { pub name: &'a str, pub digest: &'a ImageDigest }`.
- `pub fn verify_file_bundle(bundle_json: &[u8], subjects: &[FileSubject<'_>], root: &TrustRoot, expected: &Expected<'_>) -> Result<VerifiedAttestation, AttestationError>`: `subjects` non-empty; `parse_bundle`; predicate check; each subject must appear in the signed statement with that exact name and sha256 together; then `verify_parsed` once on the first subject's digest. The result's `digest` is the first subject's.
- New variant `AttestationError::FileSubject { name: String, expected: String, found: String }`, a refusal under `is_refusal`. `found` lists the statement's names, truncated and quoted.
- A pure `fn find_subject(statement: &Statement, subject: &FileSubject<'_>) -> Result<(), AttestationError>`, so name logic is tested without a signature.

- [ ] **Step 1: Fixture.** `gh attestation download` a real multi-subject bundle from a widely used public project (start with the newest `cli/cli` release) into the fixture directory, with `trusted_root.json`, following the existing fixture README's recipe; check `.subject | length > 1` and Rekor v1 with both proof and promise. If none can be found, say so in the README and rely on `find_subject` tests plus the vaultwarden fixture's single subject, and list multi-subject as first-tag only.
- [ ] **Step 2: Failing tests** in `tests/files.rs`: `real_bundle_verifies_for_each_named_file`, `another_files_digest_is_refused_under_this_name`, `right_name_with_a_wrong_digest_is_refused`, `name_that_only_contains_the_wanted_name_is_refused`, `no_subjects_is_refused`, `wrong_repo_id_is_refused`, `wrong_commit_is_refused`, `dispatch_trigger_is_refused` (`match_identity`, with `build_trigger` `workflow_dispatch`), `tampered_payload_is_refused`, `oversized_bundle_is_refused`. Run: `cargo nextest run -p landfall-origin files`. Expected: FAIL.
- [ ] **Step 3: Implement.** Keep `attestation.rs` under the limit by moving the new code to `file.rs`. Run the same. Expected: PASS, and the existing attestation tests unchanged.
- [ ] **Step 4: Gate. Commit:** `feat(origin): verify a named release file against its bundle`.

### Task 5: Fetch and verify a release's files; the CLI becomes a library

**Files:** Create `crates/origin/src/fetch/assets.rs`, `crates/origin/src/fetch/tests/assets.rs`, `crates/origin/src/artifact.rs`, `crates/origin/src/artifact/tests.rs`, `crates/cli/src/lib.rs`, `crates/cli/src/cli.rs`, `crates/cli/src/cli/tests.rs`, `crates/cli/src/project.rs`, `crates/cli/src/agent_release.rs`, `crates/cli/src/agent_release/tests.rs`. Modify `crates/origin/src/fetch.rs`, `crates/origin/src/lib.rs`, `crates/origin/src/release.rs`, `crates/core/src/config/signer.rs`, `crates/cli/src/main.rs`, `crates/cli/src/verify.rs`, `crates/cli/Cargo.toml`, `Dockerfile` (`cli` joins the `lib.rs` stub loop), `.github/workflows/advisories.yml` (add `-p landfall-cli` to both lines), `AGENTS.md` crate map.

**Interfaces:**
- `Fetcher::release_assets(&self, repo: &RepoName, tag: &ReleaseTag) -> Result<Vec<ReleaseAsset>, FetchError>`: `GET /repos/<repo>/releases/tags/<tag>`, capped at `MANIFEST_LIMIT`. `ReleaseAsset { id: u64, name: String, size: u64 }`.
- `Fetcher::release_asset(&self, repo: &RepoName, asset: &ReleaseAsset, limit: usize) -> Result<Vec<u8>, FetchError>`: `GET /repos/<repo>/releases/assets/<id>`, `Accept: application/octet-stream`, the per-request timeout `ASSET_TIMEOUT` of 10 minutes (the client's 30 s doesn't suit a binary), refused before reading if `asset.size > limit`, and capped while streaming. The token goes to the API, and not to the redirect's storage host.
- `pub const BINARY_LIMIT: usize = 64 * 1024 * 1024`, `SUMS_LIMIT = 64 * 1024`.
- `pub async fn signed_commit(fetcher, repo: &RepoName, tag, signers: &[(PrincipalId, &SignerKey)]) -> Result<(CommitSha, SignedTag), ReleaseError>`, extracted from `verify_release_origin`, which then calls it.
- `SignerKey::parse` becomes `pub`.
- `artifact.rs`: `pub struct ReleaseIdentity<'a> { repo: &'a RepoName, repo_id: u64, owner_id: u64, workflow: &'a str, signers: &'a [(PrincipalId, &'a SignerKey)] }`. `pub struct VerifiedFile { pub name: String, pub bytes: Vec<u8>, pub digest: ImageDigest, pub commit: CommitSha, pub tag: SignedTag, pub attestation: VerifiedAttestation }`, whose `Debug` leaves out the bytes. `pub async fn verify_release_file(fetcher, root, identity: &ReleaseIdentity<'_>, tag: &ReleaseTag, name: &str, bundle_name: &str) -> Result<VerifiedFile, FileError>`. Order: signed tag, list assets, download `name`, `SHA256SUMS` and the bundle, parse sums strictly (`<64 lowercase hex>  <name>`, a duplicate refused), compare, `verify_file_bundle` for both `name` and `SHA256SUMS`, off the runtime. Nothing is returned before all pass. `FileError::is_refusal()` follows `ReleaseError::is_refusal`: fetch errors and unparseable bundles aren't refusals; signature, identity, sums and subject mismatches are.
- `project.rs`: `REPO`, `REPO_ID: u64 = 1_441_186_089`, `OWNER_ID: u64 = 1_872_741`, `WORKFLOW`, `SIGNERS: &str = include_str!("../assets/release-signers")`; `fn signers() -> Result<Vec<(PrincipalId, SignerKey)>, ProjectError>` (none is `ProjectError::NoSigners`, naming what to do).
- `agent_release.rs`: `pub enum Arch { Arm64, Amd64 }`, with `Arch::from_uname(&str) -> Option<Arch>` (`aarch64`, `arm64`; `x86_64`). `pub fn agent_asset(version: &semver::Version, arch: Arch) -> String`, `bundle_asset(version)`, per the table. `pub struct VerifiedAgent { tag, version, arch, bytes, sha256: String, summary: String }`, with public `new`, as `daemon::run_with`'s fakes are: nothing on a command line reaches it. `pub trait AgentSource { async fn agent(&self, tag: &ReleaseTag, arch: Arch) -> Result<VerifiedAgent, AgentReleaseError>; }`. `GitHubReleases` implements it with `project.rs`, the trust cache and token handling moved out of `verify.rs` into `pub(crate)` functions both use. `pub fn default_tag(version: &str, explicit: Option<ReleaseTag>) -> Result<ReleaseTag, AgentReleaseError>`, which refuses `0.0.0` without `--tag`.
- `lib.rs` and `cli.rs` hold `Cli`, `Command`, `CliError` and `run`; `main.rs` is thin, as the agent's is. Exit statuses stay 0, 1, 2.

- [ ] **Step 1: Failing tests** with `wiremock` and the Task 4 fixture: `assets_are_listed`, `oversized_asset_is_refused_before_download`, `asset_longer_than_it_said_is_cut_off`, `token_goes_to_the_api_and_not_the_redirect_target` (two servers, on two ports), `missing_release_is_not_found`, `verify_release_file_needs_every_check` (a table: no signature, unknown signer, missing sums, name absent from sums, a sums mismatch, duplicate names in sums, a bundle for another tag, each giving its own error and returning no bytes), `network_failure_is_not_a_refusal`. In `crates/cli`: `asset_names_are_exactly_the_tables`, `arch_from_uname` (`armv7l`, `i686` and empty are `None`), `no_signers_refuses`, `dev_version_needs_a_tag`, `project_constants_match_the_workspace` (`CARGO_PKG_REPOSITORY`). Expected: FAIL.
- [ ] **Step 2: Implement.** Move `main.rs`'s tests to `cli/tests.rs`, unchanged in substance. Run: `cargo nextest run -p landfall-origin -p landfall-cli`. Expected: PASS.
- [ ] **Step 3: Live test,** `#[ignore]`, in `crates/cli/src/agent_release/tests.rs`: `live_agent_release_verifies` lists the repository's releases through the fetcher; with no release or no signers it returns, after a line on stderr; otherwise it verifies the newest non-prerelease's agent for both arches. And `live_project_ids_are_this_repository` checks the ids against `GET /repos/<repo>`, always.
- [ ] **Step 4: Gate; `docker build .`; security review. Commit:** `feat(cli): fetch and verify an agent release`. Open PR C.

## PR D: `host install` (#22)

### Task 6: The plan: facts, quoting, unit, script

Pure code, tested without a target.

**Files:** Create `crates/core/src/controller_url.rs` with tests moved from the agent, and under `crates/cli/src/host/`: `facts.rs`, `shell.rs`, `unit.rs`, `plan.rs`, and `tests/{facts,shell,unit,plan}.rs` with `tests.rs`. Modify `crates/agent/src/client.rs`, `crates/core/src/lib.rs`, `crates/core/Cargo.toml`, `Cargo.toml` (`url`, at the version in `Cargo.lock`).

**Interfaces:**
- Move `ControllerUrl::parse`, `UrlError` and `host_is_private` to `landfall_core::controller_url`, adding `as_str()` and `join(&self, path)`. The agent's `enrol_url` and the like stay in the agent, as functions over it. Behaviour and tests unchanged.
- `shell::quote(&str) -> String`, POSIX single quoting; `shell::remote_command(script: &str) -> String` is `exec sh -c <quoted>`, so that a non-POSIX login shell still runs `sh`.
- `facts::PROBE: &str`, a read-only POSIX script printing `key=value` lines, nothing needing root: `os`, `machine`, `kernel`, `uid`, `has_sudo`, `has_systemctl`, `has_sha256sum`, `has_runuser`, `docker_client`, `compose`, `clock` (`date +%s`), `agent_version`, `unit_present`, and one `dir_exists:<path>=0|1` per compose directory. `facts::HostFacts::parse(&str) -> Result<HostFacts, FactsError>`: capped at 64 KiB, each value 256 bytes, unknown keys ignored, control characters refused.
- `facts::check(&HostFacts, now: i64, dirs: &[&str]) -> Result<Vec<Warning>, Vec<Refusal>>`. Refused: not `Linux`; unknown arch; kernel below 5.8; no `systemctl`, `sha256sum` or `runuser`; no compose v2 or Docker client below 20.10 (naming the fix); a missing compose directory; neither root nor `sudo`. Warning: clock more than 60 s off.
- `unit::agent_unit(&UnitInput) -> Result<String, UnitError>` and `unit::recover_unit(&[&str])`, per `docs/operations.md`, plus `EnvironmentFile=-/etc/landfall/agent.env`. `UnitInput { controller: &ControllerUrl, host: &HostId, allow_insecure: bool, compose_dirs: &[&str] }`. `UnitError::UnsafePath` for a directory that isn't absolute or holds whitespace, a quote, `%`, `$`, `\` or a control character, since a unit can't say them safely. `ReadWritePaths` sorted.
- `plan::InstallRequest { sha256: &str, version: &str, config_sha256: &str, replace_config: bool, replace_unit: bool, enrol: Option<EnrolTarget>, unit: &str, recover_unit: &str, upload: &str }`, with `EnrolTarget { controller: &ControllerUrl, host: &HostId, allow_insecure: bool }`: `Some` means a code is uploaded, and no field holds the code. `plan::Step { title: String, shell: String }`. `plan::install_steps(&InstallRequest) -> Vec<Step>`, then `plan::render(&[Step]) -> String`: `set -eu`, `umask 077`, a `trap` on `EXIT HUP INT TERM` removing `.new` files, `.enrol-code` and the upload directory, and `echo "landfall: step N: title"` before each.

Steps, each looking before changing: **preflight** (a code with the unit active is refused: stop it first, since `enrol` needs the lock; no code and no `agent.key` is refused; a differing `/usr/local/bin/landfall-agent` is refused, naming `host upgrade`; a differing config or unit is refused without its flag; all before any change) → **user** (`useradd --system --home-dir /var/lib/landfall-agent --no-create-home --shell /usr/sbin/nologin --groups docker landfall-agent`, or `usermod -aG docker` if it exists without the group; refuse uid 0) → **state** (`install -d -o landfall-agent -g landfall-agent -m 0700`, contents untouched) → **config** (`/etc/landfall/fleet.toml`, 0644, root, by rename) → **binary** (root-owned `.new`, compare `sha256sum`, rename) → **docker** (`runuser -u landfall-agent -- docker version`, proving the agent's user reaches the socket) → **units** (both, by rename, `daemon-reload`) → **enrol** (when there is a code, via `.enrol-code`, `runuser`, removed after) → **start** (`systemctl enable --now landfall-agent`, wait 3 s, `is-active`, on failure the last 20 journal lines and exit 1).

- [ ] **Step 1: Failing tests:** `quote_survives_sh` (a table through `/bin/sh -c 'printf %s …'`: quotes, `$(…)`, backticks, newlines, unicode, leading `-`), `probe_output_parses`, `value_with_a_control_character_is_refused`, `oversized_output_is_refused`, `each_refusal_is_named` (a table, one fact off at a time), `kernel_versions_compare_as_numbers` (`5.10` passes, `5.8.0-generic` passes, `5.7` fails), `old_docker_is_refused`, `unit_matches_the_operations_guide` (`include_str!` of the guide: each directive of the agent's block, with example values, is in the rendered unit), `unsafe_path_is_refused`, `paths_with_several_deployments_are_all_read_write`, `insecure_flag_reaches_exec_start`, `script_parses` (`sh -n`), `script_never_holds_the_code` (the request has no field for it; the script names only the path `.enrol-code`), `a_code_for_a_running_agent_is_refused_in_the_script` (running the preflight in `sh` against stubs on `PATH` and temp paths), `differing_config_is_refused_before_any_change`, `the_key_is_never_written_by_the_script` (no step's text names `agent.key` except `test -e` in preflight), `steps_print_in_order`. Expected: FAIL.
- [ ] **Step 2: Implement.** Paths in `plan.rs` are constants, with a test-only prefix only through `InstallRequest`'s fields if the stub test needs it; no environment variable changes them. Run: `cargo nextest run -p landfall-cli -p landfall-core -p landfall-agent`. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `feat(cli): plan an agent install as a printed script`.

### Task 7: SSH and the command

**Files:** Create `crates/cli/src/host.rs`, `crates/cli/src/host/ssh.rs`, `crates/cli/src/host/install.rs`, `crates/cli/src/host/tests/{ssh,install}.rs`. Modify `crates/cli/src/cli.rs`, `crates/cli/Cargo.toml`.

**Interfaces:**
- `ssh::Destination::parse(&str) -> Result<Destination, SshError>`: `[user@]host` or `ssh://[user@]host[:port]`; refuses a leading `-`, whitespace and control characters.
- `ssh::options() -> &'static [&'static str]`: the ruling's forced `-o` list. `ssh::args(dest, control: &Path, config: Option<&Path>, tty: Tty, command: &str) -> Vec<OsString>`, where `--` comes before the destination.
- `pub trait Remote { fn run(&self, command: &str, stdin: &[u8]) -> Result<Output, SshError>; fn run_privileged(&self, script: &str, interactive: bool) -> Result<i32, SshError>; }`. `OpenSsh` implements it with `std::process::Command`: stdin written from a thread, output capped at 1 MiB, `GITHUB_TOKEN` removed, stdio inherited for `run_privileged`. Exit 255 is `SshError::Connection`, with a hint when stderr says `Host key verification failed`. A private control directory, removed with `ssh -O exit` on `Drop`.
- `host::HostCommand` (clap): `install <DEST> --host <ID> --config <FILE> --controller <URL> [--allow-insecure-controller] [--code-file <FILE>] [--tag <TAG>] [--dry-run] [--yes] [--replace-config] [--replace-unit] [--ssh-config <FILE>] [--cache-dir <DIR>]`.
- `install::run_with<S: AgentSource, R: Remote>(args: &InstallArgs, source: &S, remote: &R, runtime: &Runtime, out: &mut dyn Write, confirm: &mut dyn Confirm) -> Result<Outcome, HostError>`, with `pub trait Confirm { fn is_terminal(&self) -> bool; fn ask(&mut self, script_sha256: &str) -> io::Result<bool>; }`. Remote calls are sync, outside `block_on`; the source's fetch runs inside it.

Order: local checks first (config by `parse_config`, deployments for the host, controller URL rule, destination, code file a regular non-link file holding an `EnrolCode`) → probe → `facts::check` → `source.agent`, verified before anything is sent → render → print where it came from, every step and the script's hash → `--dry-run` stops here, exit 0, nothing written on the target → confirm → remove stale upload directories, upload binary and config → upload the code → `run_privileged`.

- [ ] **Step 1: Failing tests,** with a `FakeRemote` recording every command and stdin, a fake source and fake confirm: `destination_cannot_be_an_option` (a table), `forced_options_come_before_the_destination`, `options_include_strict_host_checking_and_batch_mode`, `nothing_is_sent_before_verification` (a failing source: only the probe ran), `verification_failure_exits_1`, `connection_failure_exits_2`, `dry_run_uploads_nothing_and_runs_nothing_privileged`, `plan_is_printed_before_it_runs` (`out` holds every step before `run_privileged`'s call), `no_terminal_without_yes_refuses`, `declining_changes_nothing`, `code_goes_by_stdin_and_never_in_a_command` (no recorded command, nor `out`, contains the code; only stdin does), `code_is_uploaded_last`, `a_host_with_no_deployment_is_refused_without_connecting`, `bad_controller_url_is_refused_without_connecting`, `a_linked_code_file_is_refused`, `github_token_is_not_passed_to_ssh` (`args` and the command's env list), `help_documents_the_exit_statuses`. Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-cli`. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `feat(cli): host install over the operator's own SSH`.

### Task 8: Against a real `sshd`, in a container

**Files:** Create `crates/cli/tests/docker_host_install/main.rs`, `harness.rs`, `install.rs`, `Dockerfile`, `README.md`, `fake-docker.sh`, `fleet.toml`. Modify `.github/workflows/ci.yml`, `AGENTS.md` ("Testing rules"), `.config/nextest.toml` only if the 180 s limit proves short.

**Interfaces:**
- Image: Debian slim, pinned by digest, with `systemd`, `openssh-server`, `sudo`, `ca-certificates`. `operator` has passwordless sudo; `needs-password` needs a password. `fake-docker.sh` on `PATH` answers `docker --version`, `docker version` and `docker compose version --short`, as the agent starts without running anything. A `docker` group exists. `/srv/compose/app` exists.
- Harness: requires `LANDFALL_TEST_DIST` (the `binaries` output for the local platform) and image `landfall-test-sshd`, and panics with what to run if either is missing. A fresh container per test: `docker run -d --cgroupns=private --cap-add SYS_ADMIN --security-opt seccomp=unconfined --tmpfs /run --tmpfs /run/lock -p 127.0.0.1::22 <image>`, the smallest set found to boot systemd (if `--privileged` is truly needed, record why in the README), with no host mounts and removed on drop. A temp dir holds a throwaway `ssh-keygen` key and an `ssh_config` (`Port`, `IdentityFile`, `IdentitiesOnly`, `UserKnownHostsFile`), and `known_hosts` holds the container's key read through `docker exec`. The real controller runs in the container from `dist`, on `127.0.0.1:8080`, with `http://127.0.0.1:8080` and `--allow-insecure-controller`: a code from `landfall-server enrol-code` through `docker exec`. `FixedSource` hands out `dist`'s real agent through `VerifiedAgent::new`. The commands go through `run_with` with real `OpenSsh`.

- [ ] **Step 1: Write the tests,** each `#[ignore]`d, named `docker_`:
  - `docker_install_from_nothing_to_enrolled`: exit 0; `systemctl is-active landfall-agent`; the agent's user exists and its state directory is 0700; `agent.key` is 0600; `landfall-server audit show` has the host's enrolment.
  - `docker_install_twice_changes_nothing`: second run with no code exits 0; mtimes of binary, config and units, and the key's bytes, are unchanged; the service wasn't restarted (`ActiveEnterTimestamp`).
  - `docker_existing_key_survives_a_new_code`: stop the unit, run with a new code; same key bytes.
  - `docker_unknown_host_key_is_refused`: empty `known_hosts`; exit 2 with the hint, and `known_hosts` stays empty.
  - `docker_changed_host_key_is_refused`: another key in `known_hosts`.
  - `docker_config_that_turns_off_checking_is_still_refused`: `ssh_config` with `StrictHostKeyChecking no` and `UserKnownHostsFile /dev/null`.
  - `docker_dry_run_changes_nothing`: the listing of `/usr/local/bin`, `/etc/landfall`, `/etc/systemd/system` and `/var/lib`, and `/etc/passwd`, are the same before and after.
  - `docker_interrupted_at_every_step_converges`: for each N, render only the first N steps and run them through `run_privileged`, then the full install; the end state equals a clean install's, with the same key if one was made.
  - `docker_nothing_secret_is_left_behind`: after success and after a failed enrol (a bad code): no `.enrol-code`, no `/tmp/landfall-install.*`; after a killed upload, the next run removes the stale directory.
  - `docker_tampered_upload_is_refused`: a `Remote` wrapper flips one byte of the binary's stdin; exit 1, and no `/usr/local/bin/landfall-agent`.
  - `docker_changed_config_is_refused`: changed `fleet.toml`, exit 1, file unchanged; with `--replace-config` it passes. Same for the unit.
  - `docker_sudo_needing_a_password_without_a_terminal_is_refused`: as `needs-password`; `sudo -n` fails, exit 1, nothing changed.
- [ ] **Step 2: Build and run on this machine.** Run: `docker buildx build --target binaries --output type=local,dest=<scratch dir>/dist .`, `docker build -t landfall-test-sshd crates/cli/tests/docker_host_install`, `LANDFALL_TEST_DIST=<scratch dir>/dist cargo test -p landfall-cli --locked -- --ignored docker_`. Expected: all pass, and a note of how long. `<scratch dir>` is any throwaway path; don't set any `CARGO_*` variable.
- [ ] **Step 3: CI job `host-install`:** `ubuntu-latest`, `timeout-minutes: 30`, separate from `check` and so not slowing it; toolchain, rust-cache, buildx; the `binaries` target with `platforms: linux/amd64`, `cache-from: type=gha,scope=docker-build`, no `cache-to`; the image; then the test command, with `dist` as its `LANDFALL_TEST_DIST`.
- [ ] **Step 4: `AGENTS.md`:** what these need, how to run them, and that they don't run in the normal suite. `README.md` in the test directory: the same, and why each container flag.
- [ ] **Step 5: Gate; `uvx zizmor .`; security review. Commit:** `test(cli): host install against a real sshd in a container`. Open PR D, listing what the container doesn't show: a real sudo prompt, real Docker, a real release.

## PR E: upgrade and the guide (#22)

### Task 9: `host upgrade`, and documenting all of it

**Files:** Create `crates/cli/src/host/upgrade.rs`, `crates/cli/src/host/tests/upgrade.rs`, `crates/cli/tests/docker_host_install/upgrade.rs`. Modify `crates/cli/src/host.rs`, `crates/cli/src/host/plan.rs`, `docs/operations.md`, `docs/design/landfall.md`, `README.md`, `SECURITY.md` (only if it names what releases are), `AGENTS.md`.

**Interfaces:**
- `HostCommand::Upgrade`: `<DEST> [--tag <TAG>] [--allow-downgrade] [--dry-run] [--yes] [--ssh-config <FILE>] [--cache-dir <DIR>]`.
- `upgrade::run_with<S: AgentSource, R: Remote>(…same shape as install…) -> Result<Outcome, HostError>`.
- `upgrade::decide(running: &str, wanted: &semver::Version, allow_downgrade: bool) -> Result<Decision, HostError>`. `Decision::{Nothing, Upgrade, Downgrade}`. A running version that isn't a semantic version needs `--allow-downgrade`, as nothing can be said of it.
- `plan::upgrade_steps(&UpgradeRequest) -> Vec<Step>`: **preflight** (the unit exists) → **binary** (root-owned `.new`, compare hash, `cp -p` the old to `landfall-agent.previous`, rename) → **restart** (`systemctl restart --no-block landfall-agent`; poll up to 120 s for active with the new `--version`; a unit still `deactivating` isn't a failure: print that it's finishing a deploy and will start on the new binary; a failed one is exit 1, with the journal lines and the command to restore `.previous`). Never touches config, units or key.

- [ ] **Step 1: Failing tests:** `newer_is_an_upgrade`, `same_version_does_nothing_and_runs_nothing_privileged`, `older_is_refused_without_the_flag`, `older_passes_with_the_flag`, `prerelease_orders_below_its_release`, `unparseable_running_version_needs_the_flag`, `no_unit_is_refused_naming_install`, `upgrade_never_mentions_the_key_config_or_units`, `dry_run_changes_nothing`. And `#[ignore]`d `docker_upgrade_replaces_only_the_binary` (the fixture wraps the real agent in a shell script answering `--version` differently; key, config and units unchanged, `.previous` holds the old file, service active), `docker_downgrade_is_refused_then_allowed`, `docker_upgrade_that_cannot_start_says_how_to_go_back` (a new binary that exits 2; exit 1; output has the restore command, which works). Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-cli`, then the Docker tests as in Task 8. Expected: PASS.
- [ ] **Step 3: Docs.**
  - `docs/operations.md`: a new section, "Installing an agent with `landfall host install`", before "Running it under systemd", and keep the manual steps as they are, for anyone who won't run a script as root. It says what's verified and against what; what SSH settings are forced, and why password logins and unknown hosts are refused; how to accept a new host (connect once, compare the fingerprint); the sudo rule and what a sudoers file needs; what happens to the code; `--dry-run`; what it refuses and each `--replace-*`; an interrupted run; `host upgrade`, its `.previous`, and "upgrade the agents and the controller together". In "Upgrading": `landfall never deploys itself` stays, and a pointer. Its opening line about no `landfall` command for approvals stays true: only add the host commands to it.
  - **First trust:** getting the first `landfall` is `brew install` once the tap exists, or `gh release download` and `gh attestation verify <file> --repo pecheriere/landfall --signer-workflow pecheriere/landfall/.github/workflows/release.yml`. A browser download on macOS is quarantined, and the guide says what that means.
  - `docs/design/landfall.md`: section 4, the agent's install path, and that this doesn't change who decides; section 9, the commands; section 12, a row: a stolen GitHub token vs a host install (signed tag and attestation, residual: the maintainer's key, and a host's own operator).
  - `README.md`: an install section, with the Homebrew line marked as needing the tap.
  - `AGENTS.md`: `landfall-cli`'s crate map entry, with `host/` modules; say that `run_with` takes a fake source and nothing on a command line leads to it.
- [ ] **Step 4: Gate; the Docker tests; security review. Commit:** `feat(cli): host upgrade, and the guide for installing an agent`. Open PR E. PR B and PR E say `Part of #21` and `Part of #22`, and don't close them: the owner closes each once the first tag and a real install have proved it.

---

## Self-review

- **#21:** agent and CLI targets (Task 1); attestation and checksums (Tasks 2, 3); signed tag on main, CI and crate-age rerun, no build cache, immutable release through a draft (Task 3); agent size (Task 1, Step 5); Homebrew formula generated and pinned (Task 2), tap as an owner step (Task 3 template). homebrew-core stays out.
- **#22:** download by the CLI's version and arch (Task 5, Task 6 probe); verified before anything leaves, with `landfall-origin` and the checksum (Tasks 4, 5, order pinned by `nothing_is_sent_before_verification`); user's SSH with no key handling (Task 7); hash on target, user, state directory, unit, kernel and Docker checks, enrolment by file (Task 6); printed steps and `--dry-run` (Task 7); idempotent, key never overwritten (Tasks 6, 8); upgrade with downgrade refusal (Task 9).
- **Hard limits:** owner's steps and how far a workflow can be checked (Task 3 tables); baseline (Global Constraints, Task 3); nothing personal; container only; file sizes (a new file per responsibility; `attestation.rs` and `verify.rs` shrink or hold); which tests need Docker, and how the slow ones stay out of the normal suite (table).
