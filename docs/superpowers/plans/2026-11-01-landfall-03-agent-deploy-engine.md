# landfall plan 03: Agent deploy engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Given a verified release, the agent deploys it to a compose service on its host: pull by digest, back up, write the override, start, run checks, and on any failure put back the previous healthy version and its data, recording every step.

**Architecture:** `crates/agent` becomes a library plus a thin binary. `state` owns the agent's own directory, `safefs` owns every filesystem operation in directories a container can write to, `docker` is the only code that runs the Docker CLI (behind a trait, so the sequence is tested with a fake), `compose` renders and validates the override, `checks` runs post-deploy checks, `deploy` is the sequence and rollback. A real-Docker end-to-end test runs in CI.

**Tech Stack:** Rust 1.99 (edition 2024); `rustix` (fs, no-follow directory-fd walking); `tokio` (process, time); `reqwest` (already in the tree, for the HTTP probe); `serde`, `serde_json`; `jiff`; dev: `tempfile`. Pick the newest version `crate-age` accepts; pin fresh transitive crates with `cargo update -p <crate> --precise <older>`.

**Spec:** `docs/design/landfall.md` (sections 4, 7, 12); `docs/configuration.md`.

## Rulings made while writing this plan

- **No deploy command yet.** First deploys are manual and need an approval (plan 05), and a release reaches the agent through the controller (plan 04), so a `deploy` command could not run anything today. The engine is a library entry point, `deploy::run(&DeployPlan, ...)`, exercised by tests and the end-to-end test. The binary gets `status` and `recover`. Plans 04 and 05 add the authorising path.
- **`DeployPlan` can only be built from a `ReleaseOrigin`** (`DeployPlan::from_verified`), plus a `#[cfg(test)]` constructor. Rule and approval checks stay with the caller (plans 04, 05).
- **One deployment per compose directory on a host (closes #5).** Validation rule 8 becomes "two deployments on one host use the same `compose.dir`". Overrides and backups are per directory; loosening this later is compatible, tightening it would not be.
- **Directories are resolved at agent start-up (closes #4).** `compose::resolve_dirs` canonicalises each of the host's `compose.dir` values and refuses to run if two resolve to the same directory or one is not a directory.
- **The HTTP check gains a required `port`** (`{ http, network, port, expect }`): the spec's check had no way to name the port. The agent connects from the host to the container's address on the named Docker network, with no proxy and no redirects. This needs no probe image and adds nothing to trust. The docs say the host must be able to reach that network (true for Docker bridge networks on Linux, unless a firewall forbids it).
- **No-follow walking instead of `openat2`:** every path is opened one component at a time, relative to a directory file descriptor, with `O_NOFOLLOW`. This is the "equivalent" the spec allows, needs no kernel version check and also runs on the developers' macOS. Names come from `readdir` or from validated config paths, so no component is `.` or `..`.
- **Symlinks inside backed-up trees are copied as symlinks**, never followed, on snapshot and on restore. Devices, sockets and FIFOs are refused, naming the path. Hard links become separate files.
- **Ownership:** chown only when the owner differs from the agent's; failure is an error. The systemd unit documented here grants `CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE`, `CAP_DAC_READ_SEARCH`, because container files belong to other users and the dedicated user can't otherwise read or restore them. The Docker socket already makes the agent root-equivalent (spec 4), and the docs say so.
- **First deploy:** with no override yet, the agent writes a placeholder override (`services: {}`), so a `COMPOSE_FILE` naming it works, and treats the placeholder as the previous state. If the base compose file gives the service an image, rollback starts that; if not, there is nothing to start, so rollback stops the service and the outcome is `FailedNoPrevious`, not the critical `RollbackFailed`.
- **`COMPOSE_FILE` is checked before anything stops:** preflight writes the new override, runs `docker compose config`, requires the service's resolved image to equal the pinned reference, and puts the previous override back. Without that entry in `.env` the deploy is refused naming the fix. After `up`, the running container's `Config.Image` must equal the pinned reference too.
- **Check timing is fixed in v0:** retry every 5 s, deadline 180 s, in `EngineOptions` so tests shorten them; a per-deployment setting can come later. All observing checks must pass in the same round; `no_log_match` windows then run from container start.
- **Backups kept:** the newest 3 per deployment.
- **Interrupted deploys:** before changing anything, the agent writes `in-progress.json`. While it exists further deploys are refused; `landfall-agent recover --deployment <id>` runs the rollback path. Power loss therefore never leaves a half-deployed service looking healthy.
- **Journal:** one JSON object per line on stderr with a `<N>` syslog-priority prefix, which journald understands with `SyslogLevelPrefix` (its default). A failed rollback is priority 2 (critical). Notifications are plan 08.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply (`unsafe_code = "forbid"`, clippy `all` + `pedantic` denied, `unwrap_used`, `expect_used`, `print_stdout`, `print_stderr`, `todo`, `dbg_macro` denied; tests may unwrap). No `#[allow]`/`#[expect]` without `reason = "..."`.
- Docker is run with argument vectors, never through a shell. Child environment: `COMPOSE_FILE`, `COMPOSE_PROJECT_NAME` and `COMPOSE_PROFILES` removed, so the stack's `.env` decides. Every Docker call has a timeout, and captured output is capped (16 MiB) before parsing.
- **`docker compose config` output contains interpolated secrets.** Parse only `services.<service>.image` and `.build`, and never log, store or put the output in an error. The same for container environments: never read or print them.
- Everything in a compose directory or a container's output is hostile: no path into a directory a container can write is opened without `safefs`; no panics on it; log text and container strings are quoted and truncated in errors.
- `DeployReport` records each step with start time, duration and outcome. It is written before the function returns, also when the deploy fails.
- Errors are `thiserror` enums naming the deployment, the path or command, and the reason.
- Full gate before each commit: `cargo fmt --check && cargo clippy --workspace --all-targets --all-features --locked -- -D warnings && cargo test --workspace --all-features --locked && RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked && cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`. `uvx zizmor .` must be clean when a workflow changes.
- Public, generic repository: no real hostnames, addresses or user names (use `example/app`, `home-1`, `/srv/compose/app`).
- Commits: conventional-commit subject, no `Co-Authored-By`, `Claude-Session` or "Generated with" trailers.

## Review Focus

1. **A container replaces a backed-up directory or file with a symlink to `/etc`, between snapshot and restore or during either** → nothing outside the tree is read, written, chowned or deleted → Task 2 `symlink_swapped_during_restore_stays_inside`, `snapshot_copies_symlinks_as_symlinks`.
2. **The check fails after a backup with `stop = true`** → the previous image and the data are back and the service is running, outcome `RolledBack` → Task 5 `failed_check_restores_image_and_data`.
3. **Backup fails part-way (a FIFO in the tree, a full disk) after the service stopped** → the service is started again on the previous image, no data restored from the partial copy → Task 5 `failed_backup_restarts_without_restoring`.
4. **The agent dies mid-deploy** → the next deploy refuses naming `recover`, and `recover` restores the previous state → Task 5 `interrupted_deploy_blocks_until_recovered`.
5. **`COMPOSE_FILE` doesn't include the override, or the service has `build:`** → refused before anything stops, naming the fix → Task 5 `missing_compose_file_entry_refuses_before_stop`, `build_service_is_refused`.

---

### Task 1: Config changes, agent state

**Files:**
- Create: `crates/agent/src/lib.rs`, `crates/agent/src/state.rs`
- Modify: `crates/core/src/config/mod.rs`, `crates/core/src/config/raw.rs`, `docs/configuration.md`, `crates/agent/Cargo.toml`, `crates/agent/src/main.rs`, `Cargo.toml`, `Dockerfile` (agent stub gains `src/lib.rs`), `AGENTS.md` (agent module map)

**Interfaces:**
- Core: `Check::Http` gains `port: u16` (required, 1 to 65535). Rule 8 refuses two deployments on one host with the same `compose.dir`, naming both ids. Example config and docs updated.
- `state::StateDir::open(path: &Path) -> Result<StateDir, StateError>`: the directory must exist, be owned by the agent's user and not be group- or world-writable.
- `StateDir::deployment(&self, id: &DeploymentId) -> Result<DeploymentState, StateError>`; directory name is the id with `/` replaced by `__` (ids can't contain `_`).
- `DeploymentState` methods: `lock(&self) -> Result<DeployLock, StateError>` (non-blocking `File::try_lock`; a held lock is `StateError::Busy`), `deployed() -> Result<Option<Deployed>, _>`, `set_deployed(&Deployed)`, `in_progress() -> Result<Option<InProgress>, _>`, `set_in_progress(&InProgress)`, `clear_in_progress()`, `write_report(&DeployReport)`, `backups_dir() -> PathBuf`. Writes are temp file + fsync + rename + directory fsync.
- `struct Deployed { tag: ReleaseTag, version: semver::Version, digest: ImageDigest, commit: CommitSha, deployed_at: jiff::Timestamp }`, `struct InProgress { tag: ReleaseTag, digest: ImageDigest, previous_can_start: bool, backup: Option<String>, started_at: jiff::Timestamp }`; the previous override's bytes live beside it in `previous-override.yaml` (`set_previous_override(&[u8])`, `previous_override()`). Serde derives; unknown fields refused.

- [ ] **Step 1: Failing tests.** Core: `http_check_requires_a_port`, `port_zero_is_rejected`, `two_deployments_cannot_share_a_directory` (different services, same dir). Agent: `state_dir_must_not_be_group_writable`, `second_lock_is_busy`, `deployed_round_trips`, `in_progress_round_trips_and_clears`, `corrupt_state_is_an_error_not_empty` (garbage JSON → `StateError::Corrupt` naming the file, never treated as "nothing deployed").
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Step 5: Commit** `feat(agent): state directory; config: http port, one deployment per directory`.

### Task 2: safefs

**Files:**
- Create: `crates/agent/src/safefs.rs`
- Modify: `crates/agent/src/lib.rs`, `crates/agent/Cargo.toml`, `Cargo.toml`

**Interfaces:**
- `struct Root` opens an absolute trusted directory (`Root::open(&Path)`), holding its fd. Every operation takes a `RelPath` (validated: non-empty components, no `.`/`..`, no leading `/`), walking with `openat(.., O_NOFOLLOW | O_DIRECTORY | O_CLOEXEC)`, one component at a time.
- `fn write_atomic(root: &Root, name: &RelPath, bytes: &[u8], mode: u32) -> Result<(), SafeFsError>`: `O_CREAT|O_EXCL|O_NOFOLLOW` temp beside it, fsync, `renameat`, directory fsync. `fn read_file(root, name, cap: usize) -> Result<Option<Vec<u8>>, SafeFsError>`: `O_NOFOLLOW`; must be a regular file; `None` when absent.
- `fn snapshot(source: &Root, paths: &[RelPath], dest: &Path) -> Result<SnapshotStats, SafeFsError>`: copies into `<dest>.partial`, then renames to `dest`, so a partial copy never looks complete. A missing path is `SafeFsError::Missing`. Preserves mode, uid, gid and mtime. Copies symlinks as symlinks, refuses special files naming the path.
- `fn restore(snapshot: &Path, target: &Root, paths: &[RelPath]) -> Result<(), SafeFsError>`: for each path, removes what is there now (`unlinkat`, descending by fd, never following), then recreates from the snapshot, without following anything. Chown uses `fchownat(AT_SYMLINK_NOFOLLOW)` / `fchown` on the fd.
- `fn prune(backups: &Path, keep: usize) -> Result<(), SafeFsError>`: removes the oldest beyond `keep` by directory name, which is an RFC 3339-derived sortable id; `.partial` leftovers are removed too.

- [ ] **Step 1: Failing tests:** `snapshot_and_restore_round_trip` (nested dirs, modes 0640 and 0750, mtime kept, file contents, empty dir), `snapshot_copies_symlinks_as_symlinks` (an absolute link to a sentinel file: the snapshot holds the link and the sentinel's content is not in it), `special_file_is_refused` (a FIFO; error names the path; no `dest`, and `.partial` removed), `parent_symlink_is_refused` (`data` → elsewhere: a snapshot of `data/x` errs), `restore_removes_what_the_container_added`, `symlink_swapped_during_restore_stays_inside` (the target's `data` is a symlink to a sentinel directory before restore: afterwards the sentinel is untouched and `data` is a real directory), `root_escape_paths_are_rejected` (`..`, `/etc`, `a//b` in `RelPath`), `write_atomic_replaces_but_refuses_symlink_temp`, `read_file_refuses_symlink`, `prune_keeps_newest`. Tests that need another owner are skipped by design; the end-to-end test covers ownership.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Step 5: Commit** `feat(agent): symlink-safe snapshot and restore`.

### Task 3: Docker driver and compose override

**Files:**
- Create: `crates/agent/src/docker.rs`, `crates/agent/src/compose.rs`
- Modify: `crates/agent/src/lib.rs`, `crates/agent/Cargo.toml`

**Interfaces:**
- `trait Docker: Send + Sync` (async, using native async fn in traits with generics, no `dyn`), each method taking the compose directory where relevant:
  - `pull(&self, image: &str) -> Result<(), DockerError>`
  - `compose_service(&self, dir: &Path, service: &str) -> Result<ServiceConfig, DockerError>`: `ServiceConfig { image: Option<String>, has_build: bool }`; missing service is `DockerError::NoSuchService`.
  - `compose_up(&self, dir, service)`: `docker compose up -d --no-deps <service>`; `compose_stop(&self, dir, service)`
  - `container(&self, dir, service) -> Result<Option<ContainerId>, _>` (`compose ps -q`; a validated hex id)
  - `inspect(&self, id: &ContainerId) -> Result<ContainerInfo, _>`: only `ContainerInfo { image: String, status: String, health: Option<String>, started_at: jiff::Timestamp, networks: BTreeMap<String, Option<IpAddr>> }`, via `docker inspect --format` on those fields alone, so the environment is never read.
  - `exec(&self, id, argv: &[String]) -> Result<bool, _>`; `logs_contain(&self, id, since: jiff::Timestamp, needle: &str) -> Result<bool, _>` (streams lines, stopping at a match, holding at most one 1 MiB line).
- `struct DockerCli { timeout: Duration }` implements it with `tokio::process`, per Global Constraints; `kill_on_drop(true)`.
- `compose::image_ref(repo: &RepoName, digest: &ImageDigest) -> String` (`ghcr.io/<lowercased>@sha256:...`, same derivation as `landfall_origin`: expose and reuse theirs).
- `compose::render_override(service: &str, image: &str, deployment: &DeploymentId, tag: &ReleaseTag, commit: &CommitSha) -> String`: YAML with a do-not-edit comment, `services.<service>.image` and labels `dev.landfall.deployment`, `.version`, `.commit`, every value double-quoted (their grammars exclude `"` and `\`). `compose::PLACEHOLDER` is the `services: {}` file. `OVERRIDE_FILE = "compose.landfall.yaml"`.
- `compose::resolve_dirs(config: &Config, host: &HostId) -> Result<BTreeMap<DeploymentId, PathBuf>, ComposeError>`.

- [ ] **Step 1: Failing tests:** `override_has_the_pinned_image` (exact expected text for a fixture), `aliased_directories_are_refused` (a symlink and its target as two deployments' dirs), `missing_directory_is_refused`, parsing tests on captured JSON: `compose_config_finds_image_and_build` and `compose_config_error_never_contains_the_output` (a config with `SECRET=hunter2`, malformed for the parser: error text lacks `hunter2`), `inspect_output_parses` (network without an IP, no healthcheck), `container_id_rejects_non_hex`, `oversized_output_is_refused`, `timeout_kills_the_child` (`DockerCli` with a stub `docker` script on `PATH` that sleeps; the stub in a temp dir).
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Step 5: Commit** `feat(agent): Docker driver and compose override`.

### Task 4: Checks

**Files:**
- Create: `crates/agent/src/checks.rs`, `crates/agent/src/testing.rs` (`#[cfg(test)]`: `FakeDocker`, scripted responses, a call log)
- Modify: `crates/agent/src/lib.rs`, `Cargo.toml`

**Interfaces:**
- `struct CheckOptions { interval: Duration, deadline: Duration, http_timeout: Duration }` with `Default` of 5 s / 180 s / 5 s.
- `async fn run_checks<D: Docker>(docker: &D, dir: &Path, service: &str, checks: &[Check], options: &CheckOptions) -> Result<CheckSummary, CheckFailure>`. `CheckFailure { check: String, reason: String }` names the last failure (e.g. `checks[1] http /health on app: expected 200, got 503`). `CheckSummary` holds each check's attempts and time.
- `ContainerHealthy`: healthy passes; no healthcheck defined fails immediately (it can never pass); `starting`/`unhealthy` retries. `Http`: reqwest to `http://<ip>:<port><path>`, no proxy, no redirects; a network the container isn't on fails immediately naming it. `Command`: `exec`. `NoLogMatch`: after the observing checks pass, wait until `started_at + within_secs`, then `logs_contain` since start; a match fails. A container that goes away is retried until the deadline.

- [ ] **Step 1: Failing tests** with `FakeDocker` and a real local TCP server for HTTP: `healthy_container_passes`, `no_healthcheck_fails_at_once` (one inspect, no waiting), `starting_then_healthy_passes`, `http_wrong_status_fails_naming_it`, `http_does_not_follow_redirects` (302 when 200 expected, location not fetched), `http_network_not_attached_fails_at_once`, `command_exit_nonzero_retries_then_fails`, `log_match_fails_after_window`, `all_observing_checks_must_pass_in_one_round`, `deadline_is_respected` (with short options, using `tokio::time::pause`).
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Step 5: Commit** `feat(agent): post-deploy checks`.

### Task 5: Deploy sequence, rollback, recovery

**Files:**
- Create: `crates/agent/src/deploy.rs`, `crates/agent/src/journal.rs`
- Modify: `crates/agent/src/lib.rs`

**Interfaces:**
- `DeployPlan::from_verified(deployment: &Deployment, tag: &ReleaseTag, version: semver::Version, origin: &ReleaseOrigin) -> DeployPlan` (fields private, getters); needs a digest and commit from `origin`.
- `async fn run<D: Docker>(docker: &D, state: &DeploymentState, deployment: &Deployment, compose_dir: &Path, plan: &DeployPlan, options: &EngineOptions) -> Result<DeployReport, DeployError>`. `DeployError` means it never started (locked, interrupted deploy present, preflight refusal, pull failed); nothing was changed. Anything after that is a `DeployReport`.
- `DeployReport { deployment, tag, digest, outcome: Outcome, steps: Vec<Step>, started_at, finished_at }`; `Outcome::{Deployed, RolledBack { reason }, FailedNoPrevious { reason }, RollbackFailed { reason, rollback_reason }}`; `Step { name, started_at, millis, result }`.
- `async fn recover<D: Docker>(docker, state, deployment, compose_dir, options) -> Result<DeployReport, DeployError>`: `NothingToRecover` when there is no `in-progress.json`.
- Sequence, per spec 7.2 and the Rulings: lock → refuse an interrupted deploy → preflight (read the current override or write the placeholder; base config: service exists, no `build`; write the new override, resolved image must equal the pinned reference; put the previous one back) → pull → write `in-progress.json` + `previous-override.yaml` → backup (`stop` first if `backup.stop`; `snapshot` to `backups/<id>`) → write override → `up` → verify the running image → checks → success: `set_deployed`, prune backups, clear in-progress. Failure anywhere after in-progress: rollback: previous override back; stop, restore the backup if one completed; `up`, or stop if `previous_can_start` is false; verify and re-run checks when started; clear in-progress on every outcome except `RollbackFailed`, which stays so that deploys remain blocked.
- `journal::emit(priority: Priority, event: &impl Serialize)`: writes `<N>{json}\n` to a locked stderr. `Outcome::RollbackFailed` is `Priority::Critical`.

- [ ] **Step 1: Failing tests** with `FakeDocker` (recording the call order) and real temp dirs: `successful_deploy_runs_steps_in_order` (exact call order; state updated; backups pruned; override content), `failed_check_restores_image_and_data` (data file changed by "the deploy" is back), `failed_up_rolls_back`, `failed_backup_restarts_without_restoring`, `wrong_running_image_rolls_back`, `failed_rollback_is_critical_and_blocks` (`RollbackFailed`, in-progress kept, next `run` refuses), `first_deploy_failure_with_no_base_image_stops_service` (`FailedNoPrevious`), `first_deploy_failure_with_base_image_starts_it` (`RolledBack`), `interrupted_deploy_blocks_until_recovered`, `recover_without_in_progress_is_an_error`, `missing_compose_file_entry_refuses_before_stop` (no stop or up in the call log; previous override intact), `build_service_is_refused`, `pull_failure_changes_nothing`, `no_backup_declared_never_stops`, `stop_false_backs_up_without_stopping`, `report_is_written_on_every_outcome`, `concurrent_deploy_is_busy`.
- [ ] **Step 2: Run → FAIL. Step 3: Implement. Step 4: Full gate → PASS. Step 5: Commit** `feat(agent): deploy sequence with rollback and recovery`.

### Task 6: Binary, real-Docker end-to-end test, operations docs

**Files:**
- Create: `crates/agent/tests/docker_e2e.rs`, `crates/agent/tests/fixtures/` (if needed), `docs/operations.md`
- Modify: `crates/agent/src/main.rs`, `.github/workflows/ci.yml`, `README.md`, `docs/design/landfall.md` (spec 7.4 port; rule 8; first-deploy and interrupted-deploy behaviour)

**Interfaces:**
- `landfall-agent status --config <file> --host <id> [--state-dir <dir>]`: JSON per deployment on stdout: resolved dir, `Deployed` record, in-progress flag, running image, `drift: bool` (running image differs from the override, spec 7.1; this is the check the plan 04 loop will call every minute). `deploy::drift<D: Docker>(...)` is the function behind it.
- `landfall-agent recover --config <file> --deployment <id> [--state-dir <dir>]`. Exit codes: 0 success, 1 rollback failed, 2 could not run.
- Default state dir `/var/lib/landfall-agent`.
- `docs/operations.md`: `.env` with `COMPOSE_FILE=compose.yaml:compose.landfall.yaml`, why the override stays out of the host's config repo, the systemd unit (dedicated user, `docker` group, `AmbientCapabilities` per the Rulings, `ProtectSystem=strict`, `ReadWritePaths`, `NoNewPrivileges`), Docker socket being root-equivalent, host-to-bridge reachability for HTTP checks, NTP, `recover`.

- [ ] **Step 1: End-to-end test**, `#[ignore = "docker: runs in ci.yml"]`, real `DockerCli`, a temp compose project using two public multi-arch images pinned by digest (a small HTTP-capable image, recorded in a comment), and a local network created and removed by the test:
  - `real_deploy_then_failed_check_rolls_back`: deploy digest A with an `http` check → `Deployed`, container running A. Write data; deploy digest B with a check that fails (`command = ["false"]`), `backup = { paths = ["data"], stop = true }` → `RolledBack`, container running A, data restored, and owner and mode kept (a file chowned by a container running as root to uid 1000 when the test runs as root or has the rights; otherwise mode only, and the test says which).
  - `real_symlink_in_backup_is_not_followed`: a container creates `data/link -> /etc`; backup and restore complete; nothing under `/etc` changes.
  - Cleans up with `docker compose down -v` even on failure (a guard's `Drop` using `std::process`).
- [ ] **Step 2:** CI: add to the `check` job, after `cargo test`, `cargo test -p landfall-agent --locked --test docker_e2e -- --ignored`. If Docker isn't running locally, say so in the report: CI is the proof, and the PR must show that step passing.
- [ ] **Step 3: Implement the binary, `drift` and docs**, with tests: `drift_is_reported`, `no_drift_when_images_match`, CLI tests for exit codes via `assert` on the library's result mapping.
- [ ] **Step 4: Full gate → PASS**; `uvx zizmor .` clean. **Step 5: Commit** `feat(agent): status and recover commands, Docker end-to-end test, operations guide`.
