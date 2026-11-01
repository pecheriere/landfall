# landfall: design

Status: draft, reviewed once (builder check and security review), 2026-10-31.

## 1. Intent

A small continuous-delivery system for self-hosters. A signed release goes in; a verified, healthy
container comes out on one or more hosts, or the previous version stays and you can see exactly why.

Why: self-hosters who publish their own images deploy them by hand or with
image updaters that trust whatever a registry tag points at. landfall deploys
only releases whose origin it can prove, automatically where the operator allows
it, with full traceability from running container back to commit, and an
interface agents can drive and debug on their own.

Who it serves, in order:
1. **Agents** (AI coding and home assistants): a typed API and CLI to see state, investigate a failed deploy
   down to its logs, and request deploys. Agents never approve.
2. **The operator**: a pleasant web UI to see every pipeline per repo and host, approve with a passkey,
   and read a version's whole story.

Success: a patch release reaches its host minutes after its tag with the operator doing
nothing; a minor release waits for one passkey tap on their phone; a broken release never stays
running, and an agent can explain why in one API call.

## 2. Scope

### v0 goals
- Watch configured repositories for release tags.
- Verify each release's origin, on the host, before anything runs (section 5).
- Per-deployment rules: automatic (by semver part, upward only), passkey approval, or manual (section 6).
- Deploy Docker Compose services by digest on hosts running a small agent; checks; automatic rollback
  (section 7).
- Grants: who may view, request, deploy, approve, roll back which deployment (section 8).
- Staging deployments on their own address. Promotion conditions are shown and enforced by the
  controller only (section 6.4).
- Logs per deployment from VictoriaLogs, tied to the exact version (section 10).
- Typed OpenAPI, a CLI, and a server-rendered web UI with its own design language and mascot.
- Notifications through a webhook (for example Home Assistant).
- Optional [warden](https://github.com/pecheriere/warden) integration (section 8.4).

### Later (v0 must not block these, must not build them)
- Host and container map with live health; metrics.
- Third-party images without provenance (a separate, explicitly weaker "digest only" mode that could
  replace image-update scripts). Not in v0.
- Docker secrets management. Docker Swarm. Cloud hosts. Traffic-splitting canaries.
- Promotion enforced on the host (staging agents signing health reports).
- Self-update of landfall.

### Non-goals
- Building images. CI builds and attests; landfall only consumes.
- Editing host configuration beyond the image reference (compose files, networks, firewalls stay in
  the host's own config repo).
- Kubernetes.

### Anti-goals (failure even if it works)
- Any path where GitHub, a GitHub token, or the controller alone can make a host run code the host's
  own configuration did not allow. (Sections 4, 5.2 and 6.3 say how; section 12 lists what remains.)
- Any inbound connection to a host from the internet or from CI.
- Rules or grants loosened through the API or UI.
- A silent failure: every refusal, failed check and rollback is recorded with its reason, logged on the
  host itself, and notified.
- Checks that can be switched off by configuration.

## 3. Constraints

- Rust, edition 2024, pinned toolchain; the project's repository baseline (CI, crate-age 7 days,
  zizmor, CodeQL, Scorecard, Dependabot with cooldown, signed tags, trusted publishing, attested images).
  Workspace lints as in coffer: `unsafe_code = "forbid"`, clippy `all` + `pedantic` denied, no
  `unwrap`/`expect` outside tests, no `#[allow]` without a reason.
- Web UI as in coffer: server-rendered (maud + axum), no JS framework, strict CSP (`default-src 'self'`,
  no inline script or style), self-hosted fonts and SVG, themes as token files, WCAG AA, works at 360 px.
- Arm64 and amd64 hosts. The host agent must stay small.
- The public repository is generic: no hostnames, network names or accounts of any deployment in code, docs or tests.
- Release workflows of consumed repos need nothing unusual
  (signed `v*` tags, image pushed to GHCR, `attest-build-provenance` with `push-to-registry: true` on
  the multi-arch index digest).

## 4. Architecture

Three binaries from one workspace:

| Part | Runs on | Does |
|---|---|---|
| `landfall-server` (controller) | one host | watches releases, verifies origin, evaluates rules, runs approval ceremonies, keeps state and the audit log, serves API + UI, queries logs |
| `landfall-agent` | every target host | pulls work from the controller, verifies again, deploys, runs checks, rolls back, reports |
| `landfall` (CLI) | anywhere | API client for humans and agents |

Connections:
- Agent → controller only (outbound HTTPS, long poll or WebSocket). The controller never connects to
  a host. A private network such as Tailscale is recommended; the product only assumes HTTPS.
- Controller → GitHub API and registry (read-only; an optional read-only token for rate limits).
- Agent → GitHub (tag and commit objects, public, read-only), registry (pull by digest, attestation),
  Sigstore TUF mirror.
- Controller → VictoriaLogs query API (read-only).

**Central principle: the controller orchestrates, the host decides.** Each agent reads a local
configuration (section 6.1) naming the deployments it runs, their origin, the trusted tag signers, the
rule and the approvers' public keys. Before deploying, the agent itself verifies origin and tag
signature, re-evaluates the rule, and checks any approval assertion against that local config. A
compromised controller can delay, refuse and lie in the UI, and can ask for a deploy the rules allow;
it cannot make a host run a release that is not maintainer-signed, attested and allowed by local config.

**Agent packaging:** a systemd service on the host running as a dedicated user in the `docker`
group (Docker socket access is root-equivalent; stated plainly in the docs), with systemd sandboxing
(`ProtectSystem=strict`, `ReadWritePaths=` limited to the managed compose directories, its state and
its backup directory, `NoNewPrivileges`). Not a container, so it can't be stopped by its own deploys.

landfall never deploys landfall: the controller and agents are upgraded by hand in v0.

## 5. Release origin

### 5.1 Input
A release is a **tag** matching the deployment's pattern (default `v<semver>`) on a configured repo.
A GitHub Release object is optional and only used for notes. Prereleases are ignored unless the rule
opts in.

### 5.2 What is verified, on the agent (the controller runs the same checks first, to explain)
All must pass:

1. **Maintainer-signed tag.** The annotated tag object is fetched from GitHub and its signature is
   verified against the tag-signer keys in the host's local config (SSH signature format, as `git
   tag -s` with an SSH key produces; OpenPGP later). The signed tag names
   a commit; that commit is "the release commit". A stolen GitHub token or a compromised workflow
   therefore cannot produce a deployable release.
   This check is on by default and can be turned off per deployment (`origin.signed_tags = false`)
   for projects that don't sign their tags. The release commit is then the commit the tag ref points
   to, and that deployment loses the protection above against a stolen token or compromised workflow.
2. **Attestation found by digest, digest found by tag.** The controller resolves the image's semver tag
   in the registry to a digest as a lookup hint only. Nothing trusts the mutable tag: the binding is
   step 3.
3. **Attestation bound to the release.** A GitHub build-provenance bundle for that digest verifies
   against the Sigstore trust root, and the **Fulcio certificate extensions** (never the provenance
   predicate, which the job writes itself) match:
   - SAN = `https://github.com/<owner>/<repo>/<workflow path>@refs/tags/<tag>`;
   - issuer `https://token.actions.githubusercontent.com`;
   - Source Repository Digest = the release commit from step 1; Source Repository Ref =
     `refs/tags/<tag>`;
   - numeric repository ID and owner ID equal the configured ones (recorded at enrolment), so a
     renamed or re-created account can't take over;
   - Build Trigger = `push`; Runner Environment = `github-hosted`.
   The configured `workflow` is the file that attests. A deployment may instead pin a reusable workflow
   (SAN = reusable workflow, Build Config URI = caller); the config says which. v0 refuses
   reusable-workflow pinning: the Build Config URI must equal the SAN.
   The bundle must be in format v0.3 with exactly one Rekor v1 transparency log entry carrying an
   inclusion proof and an inclusion promise; Rekor v2 entries are refused until supported (#12).
4. **Exactly one digest per release.** If several validly attested digests exist for one (repo, tag)
   (a re-run release workflow), the release is refused with that reason.
5. **Platform present.** The digest is a multi-arch index containing the host's platform. The index
   digest is what is pinned and recorded.

Trust root: the agent embeds the Sigstore public-good `root.json`, keeps its TUF cache on disk,
refreshes from `tuf-repo-cdn.sigstore.dev`, and fails closed when metadata expires. Public repos only in
v0 (private repos use GitHub's own Sigstore instance with a different trust root; later).

Everything verified is stored with the release and shown as "where it came from": tag, signer key,
commit, workflow run, digest, certificate identity, transparency-log entry.

## 6. Rules and approvals

### 6.1 Configuration
One TOML file per fleet, in a git repository the operator reviews by pull request (signed commits). The
same file is deployed to the controller and to every agent by the operator's normal config deployment
(configuration management, a config repo, or by hand); each agent reads only its own host's deployments. Nothing generates
or rewrites it. The controller re-reads it on SIGHUP or file change and records a config event with
the file's hash. Each agent reports its file hash; a mismatch is shown as an error on every affected
deployment and blocks deploys there until fixed.

```toml
[signers]
maintainer = "ssh-ed25519 AAAA… (tag signing key)"

[approvers]
operator = { credential_id = "…", public_key = "…cose…" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }   # major: manual + approval
checks = [{ http = "/health", network = "app", expect = 200 }]
backup = { paths = ["state"], stop = true }

[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }   # first deploys and downgrades still need one
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "24h" }
```

`origin.tags` is required (there is no default pattern), and so is `rule.approvers` on every
deployment. The full key reference and validation rules are in `docs/configuration.md`.

### 6.2 Rule kinds
- `auto = "patch" | "minor" | "any"`: deploy without a human when the new version is **higher** than
  the running one and differs by at most that part. Downgrades are never automatic.
- `approve = "minor" | "any"`: versions covered need a passkey approval from one of `approvers`.
- Anything outside `auto` and `approve` (major, by default) is manual: a grant holder must request it
  **and** an approver must approve it. So every non-automatic deploy, and every rollback
  that is not the automatic one after a failed check, carries an approval the host verifies.
- Rules decide **when** a deploy may start. Origin verification, digest pinning, checks and automatic
  rollback are in code and always run. A deployment with no check that observes the service (an HTTP
  probe, a command, or a Docker healthcheck that is actually defined) is a config error.

### 6.3 Passkey approvals, verified on the host
- The approval is a WebAuthn assertion. Its challenge is the hash of a canonical deploy intent:
  `{deployment id, tag, release commit, image digest, expected running digest, nonce}`.
- The agent verifies: signature against the approver key in local config; credential ID; `type =
  webauthn.get`; exact origin; rpIdHash = the configured RP ID, which is the controller's exact
  hostname (never a parent domain); UP and UV flags set; challenge = hash of the intent it received.
- **Replay:** the intent names the digest that must be running now. The agent refuses if it
  isn't, and records used nonces on disk, so an approval works once and only from the state it was
  given for. No dependence on the host clock (a Pi without RTC).
- **What the operator sees:** the ceremony runs on the controller's page, so the page could show
  one thing while the challenge covers another. Because every deployable release is maintainer-signed,
  upward-only for auto, and bound to the running digest, the worst a lying controller can do with an
  approval is install a different maintainer-signed release on that same deployment. Accepted for v0 and
  stated in the docs. The CLI also offers `landfall approve` that computes the intent hash locally and
  shows it next to the page's, for anyone who wants the stronger path.
- **Registration:** passkeys are registered on the controller's page, which shows the new
  credential's public-key fingerprint. The operator copies key and fingerprint into the config by pull
  request; the agent only trusts keys from that file. Accepted residual risk: a compromised controller
  during registration could substitute its own key. Combined with signed tags, that still only allows
  maintainer-signed releases.

### 6.4 Promotion
`promote_to` makes the controller refuse to propose a version to the target until it has been healthy
on the source deployment for the given time. Enforced by the controller only in v0, and shown as such.
Host-side enforcement is later.

## 7. Deploying on a host

### 7.1 Compose ownership
- For a landfall-managed service, the host repo's `compose.yaml` keeps everything except the image
  reference.
- The stack's `.env` (or the compose file's `include`) sets `COMPOSE_FILE=compose.yaml:compose.landfall.yaml`
  so that any `docker compose` command, by hand or from scripts, uses the agent's
  override.
- `compose.landfall.yaml` is written only by the agent: `image: <repo>@sha256:<index digest>` plus labels.
  Back it up with the host, but keep it out of the host's config repo.
- Services with `build:` are refused.
- Other image updaters must not manage a service landfall manages.
- The agent compares the running container's image with its override every minute and reports drift
  as an error.

### 7.2 Sequence
Each step recorded with timings and outcome:
1. Receive intent; verify origin (5.2), rule and approval (6) locally.
2. Pull by digest.
3. Backup the deployment's declared `backup.paths`: stop the service first when `stop = true`
   (default true when backup is declared).
4. Write the override, `docker compose up -d --no-deps <service>`.
5. Checks (7.4) with retries and a deadline.
6. Success: record, notify. Failure: restore the previous override **and the backup, if one is
   declared**, start, re-run checks, record, notify. A failed rollback is the loudest state:
   notified as critical and logged to the host journal.

Rollback target is always the previously healthy digest.

### 7.3 Backup safety
Backup directories are writable by the container, and the agent is root-equivalent. Snapshot and
restore never follow symlinks (openat2 with `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS`, or an equivalent
crate) and preserve ownership and modes. Special files are refused.

### 7.4 Checks
Checks are Rust types with typed parameters; configuration chooses and parameterises them, never adds
code. v0: Docker healthcheck (fails if the image defines none), HTTP probe from inside a Docker network,
command exit status inside the container, "no log line matching X in the first N seconds". Each check
reports a short reason string used verbatim in the "why" view.

## 8. Identity and grants

### 8.1 Principals
- Humans: sign in with a passkey; approvals always need a fresh assertion.
- Agents: an API token per agent (hashed at rest, shown once). Identity through a
  trusted reverse-proxy header is out of v0.
- Host agents: an Ed25519 key generated on the host; the public key is enrolled with a one-time code
  and requests are signed. A host agent can only fetch its own host's work and report on it.

### 8.2 Grants
Per principal and deployment (exact ids, no globs in v0): `view`, `request`, `approve` (humans
with a registered passkey only, enforced in code), `rollback` (request a manual rollback, which still
needs approval). Grants live in the same reviewed config file.

### 8.3 Audit
Every event (release seen, verification result, rule decision, request, approval, deploy step, check,
rollback, config change) is appended to a hash-chained log in SQLite, as in warden, and exposed via the
API. The agent also writes each decision and failure to its host's journal, so the host's own alerting
sees refusals even if the controller is down or lying.

### 8.4 Warden integration (optional)
- Warden holds an agent's landfall token and injects it on proxied API calls, so the agent never has it.
  This uses warden's existing API-secret injection; v0 adds no warden code.
- A controller setting `agents_via_warden = true` accepts agent tokens only from the configured warden
  source address.
- Approval notifications can go out through any webhook, warden included; the approval itself is
  always the landfall passkey assertion.

## 9. API and CLI

- REST, JSON, `/api/v1`, OpenAPI 3.1 generated from code at `/api/v1/openapi.json`; problem+json errors
  with stable codes; cursor pagination.
- Every UI view is one API resource: deployments, releases (with origin story), deploys (steps, checks,
  logs), approvals, hosts, audit events.
- `GET /api/v1/deploys/{id}/why`: a deploy's outcome in order, written for an agent to act on.
- CLI `landfall`: `status`, `why`, `logs`, `request deploy`, `approve`, `rollback`, `hosts`.

## 10. Logs

The agent labels each container `landfall.deployment`, `landfall.deploy`, `landfall.version`. With Docker's
journald driver (`labels` option) the labels land on each log line, and Vector forwards them to
VictoriaLogs. The controller queries VictoriaLogs (configured URL, read-only) by deploy id and time
window. Without VictoriaLogs the logs view says logs aren't configured.

## 11. UI and design language

- Pages: deployments overview (pipeline per repo × host, "needs you" filter), deployment (history, rule,
  grants), version story (origin, timeline, checks, logs, actions), approval, hosts, audit.
- Direction: same family as [coffer](https://github.com/pecheriere/coffer)'s "Mochi" (soft, round, colourful, Fredoka + Nunito,
  light and dark) with its own palette (lagoon teal, coral, sunshine for waiting) and its own huggable
  mascot, Bobbin the otter, who carries a little shipping container.
- Themes as token files, like coffer's.

## 12. Security summary

| Threat | Mitigation | Residual |
|---|---|---|
| Stolen GitHub token / compromised workflow | Host verifies the maintainer's tag signature + cert identity bound to the signed commit | none beyond the maintainer's signing key; with `origin.signed_tags = false`, anyone who can push a tag and run the release workflow can ship a deployable release |
| Compromised controller | Host re-verifies origin, signature, rule, approval; upward-only auto; running-digest binding | can trigger allowed auto deploys, delay, lie in UI, mislead an approval to another maintainer-signed release, bypass promotion |
| Stolen agent API token | Agents can't approve; per-deployment grants; optional warden-only | can request deploys the rules allow |
| Replayed approval | Running-digest binding + nonce log | none |
| Registry swaps an image | Pull by index digest; digest is the attestation subject | none |
| Container attacks the agent via backups | No symlink following, no special files | none known |
| Rule loosened quietly | Rules only in reviewed repo; hash drift blocks deploys | a reviewer approving a bad PR |
| Host agent compromised | Only that host; key only reads its own work | that host |

## 13. Left to the builder

Crate choices (Sigstore verification, WebAuthn, OpenAPI generation, openat2), storage schema, agent ↔
controller protocol details, retry timings, CLI output format, page layouts within the design language,
and which further check types to add.

