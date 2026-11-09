# landfall plan 08: Logs per deploy, and the notification webhook Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent investigating a failed deploy reads that deploy's container logs in one call, `GET /api/v1/deploys/{id}/logs` or `landfall logs <id>`, as far as its grants reach. The operator hears of approvals, failures, rollbacks and refusals through a signed webhook (Home Assistant, warden, or anything that takes a POST), and nothing about a deployment the webhook isn't configured for.

**Architecture:** The agent labels each container with `landfall.deployment`, `landfall.version`, `landfall.commit` and the new `landfall.deploy`. Docker's journald driver copies those labels onto each log line, and the operator's Vector forwards the lines to VictoriaLogs. The controller queries VictoriaLogs read-only. The query is built only from the deploy's own row and the configuration's validated field names, never from a string the caller sent, and every value in it is quoted. It runs within a time window, a line cap, a byte cap, a timeout, a per-credential budget and a global concurrency cap. Notifications come from the audit log, which is already the one record of everything that happens. A notifier task reads new audit rows after a cursor kept per webhook. It maps each row exhaustively to an event or to nothing, keeps only rows about the webhook's own deployments, and puts each event in a durable outbox. A sender per webhook delivers the events in order, signed by the Standard Webhooks scheme (HMAC-SHA256), with no proxy, no redirects, timeouts and size caps. A resolver refuses private, loopback and link-local addresses unless the webhook allows the private network, and refuses link-local always. Retries back off with jitter for up to 24 hours. Neither part can block or fail a deploy: logs are only read when asked, and notifications run in their own task over their own tables.

**Tech Stack:** Rust 1.99 (edition 2024). New direct dependencies: `hmac` 0.13 in `landfall-server` (already in `Cargo.lock` at 0.13.0, built on the workspace's `sha2` 0.11), and `reqwest` as a direct dependency of `landfall-server` (already in the tree through `landfall-origin`, rustls only, with `stream`). Task 3 confirms both against `crate-age` and `deny.toml`. Two container images are used only by `#[ignore]`d `docker_` tests: VictoriaLogs and Vector, each pinned by digest to a release at least 7 days old, which CI may pull (the owner agreed, 2026-11-08). Nothing else is new.

**Spec:** `docs/design/landfall.md`, sections 2 (logs and webhook goals; the "silent failure" anti-goal), 4 (controller → VictoriaLogs, read-only), 7.2 (notify on success, failure and a failed rollback, which is critical), 8.2 and 8.3 (grants and what the API may show; this plan changes both: a `logs` grant in 8.2, and two controller-wide alerts a webhook may opt into in 8.3), 6.1 (the fleet file goes to every host, so this plan adds a controller-only secrets file beside it), 8.4 (approval notifications through any webhook, warden included), 9 (deploys' logs as an API resource, `landfall logs`), 10 (labels, journald, Vector, VictoriaLogs, "logs aren't configured") and 12. Plan 07's rulings on visibility, budgets, problem answers, the OpenAPI document and the grant test still stand.

## Rulings made while writing this plan

The spec is the authority. Each ruling below decides something the spec leaves open, or names the spec line it follows, and says what it costs if it is wrong.

- **Five PRs, eleven tasks, in order.**
  - PR A: labels and the deploy id (Task 1), the `[logs]` and `[[webhook]]` configuration (Task 2), and the controller's secrets file, which holds each webhook's URL and key, with its outbound network policy (Task 3).
  - PR B: the VictoriaLogs client (Task 4) and `getDeployLogs` under the new `logs` grant (Task 5).
  - PR C: logs against a real VictoriaLogs and a real journald pipeline (Task 6), and `landfall logs` (Task 7).
  - PR D: webhook events and their signature (Task 8), and the outbox the notifier fills (Task 9).
  - PR E: delivery, `landfall-server webhook test` and wiring into `serve` (Task 10), then end to end, and the docs and spec (Task 11).

  Each PR is reviewable alone and leaves `main` working. *If wrong:* a later PR reshapes a configuration key an earlier one shipped, before any release.
- **The labels are the spec's, `landfall.*`, and the deploy id is `landfall.deploy`.** Section 10 left the choice to this plan. The code writes `dev.landfall.*`, a reverse-DNS prefix, which by Docker's convention claims a domain. The spec names `landfall.*`. Neither name is read by any code: `pinned_image` reads only the image line, and drift compares images. So nothing breaks. An override written before this plan, restored by a rollback, keeps its old labels until the next deploy, and `docs/operations.md` says so. The journald driver turns a label key into a field name by upper-casing it and replacing what journald doesn't allow with `_`, so `landfall.deploy` becomes `LANDFALL_DEPLOY`. Task 6's Linux test pins that rather than trusting this paragraph. *If wrong:* the operator's Vector config renames a field, which `[logs]` already allows.
- **The deploy id reaches the override through `DeployPlan`.** `DeployPlan::from_verified` gains `deploy_id: DeployId`. The daemon has it from `DeployWork`, and the tests that call `deploy::run` pass one. `recover` and rollback restore saved bytes and write no new label. *If wrong:* nothing that decides reads a label; logs of a restored container sit under the previous deploy's id, which is what that container is.
- **Logs are read by deploy, under a grant of their own, `logs` (the owner's decision, 2026-11-08).** Section 9 lists logs under deploys as an API resource. An application's logs can hold secrets it printed, which state never holds, so an AI agent given `view` to watch deploys must not read them by that grant alone. Task 5 changes spec 8.2 to add `logs` beside `view`, `request`, `approve` and `rollback`, per principal and deployment, exact ids, as every grant is.
  - **`getDeployLogs` takes `logs` on the deploy's deployment**, by plan 07's visibility rule: `404` without any grant there, `403` with another grant (`view` alone included), and `404` for a deployment the configuration no longer has.
  - **`logs` implies nothing, and nothing implies it.** That is how grants work today: `can()` in `crates/server/src/auth/grants.rs` checks each `Permission` alone, and `request` doesn't imply `view` either. `view` doesn't imply `logs`, which is the point of the decision. `logs` doesn't imply `view`: a holder of `logs` alone learns, from a logs answer, the deploy's deployment, its window (`since`, `until`) and whether it was claimed, which the lines themselves say more of, and nothing else. Making `logs` require `view` in the configuration would refuse a file for a harmless combination, and would break the grant test's rule that each role is tried alone (`holder_of`). `docs/configuration.md` recommends granting the two together.
  - **A token may hold `logs`.** Unlike `approve`, nothing about logs needs a person: an agent investigating a failed deploy is the use the goal names.
  - **In code:** `Permission::Logs` (`"logs"`) in `crates/core/src/config/mod.rs`, one arm in `can()` (`Permission::View | Permission::Request | Permission::Rollback | Permission::Logs => granted`), `Permission::Logs` on the wire in `crates/api/src/deployments.rs` (an older CLI reads it as `Unknown`, which it already handles), one more entry in `PERMISSIONS` in `crates/server/src/api/deployments.rs`, so `whoAmI` lists it, and a generalisation of `visible::viewable_by_id` to `permitted_by_id(config, principal, id, permission)`, which `viewable_by_id` calls with `View`.

  *If wrong:* an operator who wanted `view` to cover logs adds `"logs"` to each grant, one word per grant.
- **The query is built from the controller's own values only.** The LogsQL text is `<deployment_field>:=<q(deployment id)> <deploy_field>:=<q(deploy id)> | sort by (_time) | offset <k> | limit <n+1> | fields _time, _msg`. `q` is LogsQL's double-quoted string, with `\` and `"` escaped and every control character written as `\uXXXX`. Field names come from the configuration and must match `[A-Za-z_][A-Za-z0-9_]{0,63}`. The deployment id comes from the deploy's row, and the deploy id is an integer. Times go in the HTTP `start` and `end` parameters as RFC 3339, made by `jiff` from integers. `k` and `n` are integers the controller bounds. Nothing the caller sends reaches the query as text: `since`, `until` and `limit` are parsed as integers first, and the cursor decodes to integers and is checked against the path's deploy id. A test against the real VictoriaLogs (Task 6) stores lines whose deployment value holds `"`, `\`, `|`, ` OR `, `*` and a newline, and shows that each exact match returns its own line and no other. *If wrong:* the escaping test fails there before it ships.
- **The window, the caps and the pages.** The lower bound is the deploy's `claimed_at` minus 60 seconds. A deploy never claimed has no container, and gets `state: "not_started"` without a query. The default upper bound is `finished_at` plus 600 seconds, or now while it runs. `since` and `until` (unix seconds) may move the window anywhere from the lower bound to now, so an agent can read today's lines of a container still running. A `since` below the lower bound is raised to it, and the answer echoes the window used. A span over 24 hours, or `until` not after `since`, is `400 bad_request`. `limit` is 1 to 1,000, default 200. Each message is cut at 8 KiB on a character boundary, marked `cut: true`. The VictoriaLogs answer is read as a stream under 8 MiB, and over that is `502 logs_unavailable` (too large). Lines come oldest first, a page at a time. The cursor (list `logs`) holds `<deploy id>.<last _time in ns>.<lines already given at that ns>`. The next query starts at that time, with `offset` skipping those lines. The offset is capped at 100,000, and past it the cursor is refused. Lines with the same nanosecond may page unstably, and `docs/api.md` says so. *If wrong:* a very chatty container needs more pages, never a bigger answer.
- **"Not configured" is a state, a failing VictoriaLogs is a problem.** Section 10 says the view says logs aren't configured. So without `[logs]` the answer is `200` with `state: "not_configured"` and no lines. That is a fact about this controller that an agent should read, not an error to retry. A VictoriaLogs that times out, refuses, answers other than 200, or sends something that doesn't parse or is too large is `502 logs_unavailable`. Its title names which of those, never the URL or the body. So the CLI exits 2, as for any server error. *If wrong:* a script treating every 200 as lines reads `state` first, as `docs/api.md` says.
- **Field names are configured, with defaults from the journald pipeline.** `[logs]` holds `deployment_field` (default `LANDFALL_DEPLOYMENT`) and `deploy_field` (default `LANDFALL_DEPLOY`). VictoriaLogs' own `_time` and `_msg` are fixed. `docs/operations.md` gives the Vector configuration that Task 6 runs, so the defaults are the names that configuration produces. *If wrong:* an operator with Vector's `docker_logs` source sets the two names to its `label.*` fields.
- **The controller's secrets live in one file outside the fleet configuration.** The fleet file is reviewed in a repository and copied to every host (section 6.1), so it holds no secret. `landfall-server serve --secrets <FILE>` reads a TOML file. It must be a regular file opened with no-follow, owned by the controller's user, with `mode & 0o077 == 0`, and at most 16 KiB. Its schema, keyed by webhook name:

  ```toml
  [webhook.home-assistant]
  url = "https://hooks.example.com/landfall"
  key = "whsec_<base64>"

  [logs]
  bearer = "<token>"
  ```

  - `key` is 24 to 64 random bytes in the Standard Webhooks key form. `url` is the webhook's address (next ruling). `[logs] bearer` is optional, for a VictoriaLogs behind an authenticating proxy. `[logs]` may be left out, and any table or key not listed here is refused (`deny_unknown_fields`).
  - **Every `[[webhook]]` in the fleet file needs a `[webhook.<name>]` with both `url` and `key`.** `serve` refuses to start without one, naming the webhook and the missing key, and so does `webhook test`. With no `--secrets` at all, a configuration with webhooks is refused the same way.
  - **A `[webhook.<name>]` that no `[[webhook]]` names is refused too, not warned about.** It is either a typo, whose intended webhook is then refused anyway for having no entry, or a webhook taken out of the fleet file whose URL, a capability, should be deleted rather than kept on disk with nothing reading it. A warning would go to a log nobody reads at start-up. The fleet file is read once, at start-up (`ServeArgs::config`'s doc), so the operator edits both files and then restarts, and no window exists in which a correct pair is refused. If the spec's re-read on SIGHUP (6.1) is built later, it must re-read the secrets file with the fleet file and keep the old pair when the new one doesn't check. *If wrong:* removing a webhook takes one more edit before the restart.
  - Keys, URLs and the bearer have redacted `Debug`, no `Display`, and appear in no log line, audit row, API answer or error.

  *If wrong:* the operator keeps one more file with mode 0600, as they do for the database.
- **The webhook's URL is a capability, so it lives in the secrets file (the owner's decision, 2026-11-08).** A receiver often takes a capability in its URL: a Home Assistant webhook id, a token in a query string. In the fleet file it would be readable on every host and in the config repository. So the fleet file's `[[webhook]]` keeps the name, what it receives (`events`, `deployments`, `controller_alerts`) and the network policy (`allow_private_network`), which a reviewer should see, and the secrets file holds where it goes. The consequences:
  - **Parsing moves.** Core's configuration no longer sees a webhook URL, so it can't check it. `secrets::load(path, &config)` parses each `url` with core's `TargetUrl::parse(text, webhook.policy())`, after the fleet file is parsed, with the policy that fleet file sets: `https` or `http` only, no userinfo, no fragment, `http` only with `allow_private_network`, and an IP-literal host checked by `net::allows`. So the literal SSRF check runs when secrets load, at start-up and in `webhook test`, before the database opens. A query string is allowed, since it is where some receivers take their token.
  - **`[logs] url` stays in the fleet file**, parsed by core as before: it names the operator's own service, holds no capability, and its bearer is already in the secrets file.
  - **The URL is never shown.** Not in a log line, an audit row (`webhook_gave_up`, `webhook_dropped`, `webhook_tested` name the webhook), an API answer (no route reads webhooks), an error (`TargetError`, `SecretsError` and `OutboundError` name the webhook and the reason, never the text; `reqwest::Error::without_url`), `Debug` (`WebhookSecret`'s is redacted, and core's `TargetUrl` prints only its scheme), or `webhook test`'s output.
  - **The configuration's hash no longer covers it.** Moving or rotating a receiver changes the secrets file and needs a controller restart, and doesn't put every host in configuration drift.
  - **A reviewer no longer sees where notifications go**, only what each named webhook receives and whether it may reach the private network. The operator who holds the secrets file decides where.

  *If wrong:* the URL moves back to `[[webhook]] url`, and `secrets::load` drops one key.
- **Signatures follow Standard Webhooks.** The spec says nothing on signing. Standard Webhooks is a published scheme with receiver libraries in many languages, so a receiver needn't write its own check. Each request carries:
  - `webhook-id: landfall-<audit seq>`, the same on every retry, which a receiver uses to drop duplicates;
  - `webhook-timestamp: <unix seconds of this attempt>`;
  - `webhook-signature: v1,<base64 of HMAC-SHA256(key, "<id>.<timestamp>.<body>")>`.

  The body is the exact bytes signed. `docs/operations.md` carries a test vector, and a test checks it. *If wrong:* a receiver that wants another scheme checks this one, which is HMAC over the body as most are.
- **Where a webhook may connect.** One function in core, `net::class(ip) -> AddrClass`, says what an address is: `Public`, `Private` (RFC 1918, CGNAT `100.64.0.0/10` (tailnets), IPv6 ULA `fc00::/7`), `Loopback`, or `Never`. `Never` covers link-local (`169.254.0.0/16`, the cloud metadata address included, and `fe80::/10`), unspecified, multicast, broadcast, `0.0.0.0/8`, documentation and benchmarking ranges, and IPv4-mapped, IPv4-compatible and NAT64 (`64:ff9b::/96`) addresses, which are judged by the IPv4 address they embed. The policy:
  - **Public addresses** are allowed for `https://`.
  - **Private and loopback** need `allow_private_network = true` on that webhook.
  - **`Never`** is refused always.
  - **`http://`** is allowed only with `allow_private_network = true`, and then only to private or loopback addresses. A Home Assistant on the LAN is the common case, and HMAC keeps it from being forged.

  The check runs twice. Once on an IP literal in the URL, since the connector doesn't resolve literals: for a webhook when the secrets file is loaded against the configuration, and for `[logs] url` when the configuration is parsed. Then in a custom `reqwest` DNS resolver on every connection, which drops each address the policy refuses and fails if none is left. So a name that resolves to `169.254.169.254`, or that changes after start-up (DNS rebinding), connects nowhere. `[logs] url` goes through the same policy, as the operator's own service: `https://` anywhere but `Never`, and `http://` only to private or loopback. *If wrong:* a receiver at a link-local address can't be reached, and the operator gives it another address.
- **Notifications come from the audit log, at least once, in order.** Every event the spec wants notified is already an audit row, written in the transaction that decided it. So the notifier reads `audit_events` after its cursor, which can't miss a row: SQLite has one writer, so `seq` order is commit order. It writes the events and the advanced cursor in one transaction. Each webhook has its own cursor. A webhook new to the configuration starts at the current head, with no backfill. A webhook taken out of the configuration has its cursor and outbox deleted at start-up. A sender delivers one event at a time per webhook, oldest first, at most 5 a second. A crash re-sends at most the event in flight, under the same `webhook-id`. *If wrong:* a receiver sees a duplicate it can drop by id.
- **The events, their severities and what each carries.** One pure function, `events::from_row`, has an exhaustive `match` on `EventKind`, so a new kind doesn't compile until it says whether it notifies:

  | Event | From | Severity |
  |---|---|---|
  | `approval_needed` | `deploy_requested` | info |
  | `approval_closed` | `request_approved`, `request_expired`, `request_stale`, `request_cancelled` | info |
  | `deploy_finished` | `deploy_finished` | `deployed`: info; `nothing_changed`, `deferred`, `rolled_back`, `failed_no_previous`: warning; `rollback_failed`: critical (spec 7.2) |
  | `deploy_refused` | `deploy_refused` | critical (the kind's own doc: "treat it as an alert") |
  | `release_refused` | `release_seen` with `refused` | warning |
  | `config_drift` | `config_drift` | warning |
  | `running_drift` | `running_drift` | warning |
  | `controller_alert` | `sign_in_barred_key`, `access_throttled`, only to a webhook with `controller_alerts = true` | `sign_in_barred_key`: critical (the kind's doc: "treat it as an alert"); `access_throttled`: warning |
  | `test` | `landfall-server webhook test` only | info |

  Every other kind gives no event. `from_row` says which kind of subscription a row needs, a `Topic`: `Deployment(EventName)` for the rows above `controller_alert`, `Controller` for the two alerts. An event carries `type`, `id`, `at`, `severity`, `deployment`, `host`, a one-line `summary` in the controller's words, and typed `data`. `approval_needed` adds `approve_url` from `[approval]`, so a phone notification can open the page.

  Free text comes only from fields whose writer can't name another deployment: a host's `reason` and `rollback_reason` for its own deploy, and the verifier's `refused` for this deployment's own repository. Those fields are already quoted and bounded by `landfall_core::text`. Rule reasons and request reasons, which can name a promotion source or who cancelled, are left out. A `controller_alert` carries the alert's kind, the principal, the credential kind (`via`), the count, and for `access_throttled` which allowance (`changes`, `reads` or `logs`). It leaves out the source addresses `sign_in_barred_key` records, and any session or token id: they stay with `landfall-server audit show`, which the summary names. *If wrong:* a notification says less than the audit row, and links to where the rest is read.
- **A webhook hears only of its own deployments.** `[[webhook]]` has `deployments` (exact ids, no globs, as grants are) and `events`, non-empty unless the webhook only takes controller alerts (below), and each name must exist. A row with a deployment is sent only if that deployment is listed. A host-only row (`config_drift`) is sent only if a listed deployment is on that host, which is plan 07's audit rule.
  - **Controller-wide alerts by opt-in (the owner's decision, 2026-11-08).** `[[webhook]]` takes `controller_alerts` (default `false`). With it `true`, the webhook also receives `sign_in_barred_key` (someone holds a key registered for a principal) and `access_throttled` (a credential went over a budget), as `controller_alert`. Spec 8.3 keeps controller-wide rows away from the API because no per-deployment grant covers them and a stolen agent token is the threat they would serve; a webhook isn't a token, and the reviewed fleet file says which receiver gets them. Task 8 changes spec 8.3's text to say so. Both kinds are already aggregated before they are written (ceremonies' failure counts, the budget's dropped counts), so an attacker can't make the receiver hear more than one row per count and flush.
  - **Every other controller-wide row is never sent**, `controller_alerts` or not: tokens, passkeys, sign-ins, refused registrations, and the webhook's own `webhook_gave_up`, `webhook_dropped` and `webhook_tested`, so a failing webhook can't feed itself.
  - `events` and `deployments` must be both non-empty or both empty, and both empty only with `controller_alerts = true`: a webhook that can receive nothing is a mistake the configuration refuses.

  *If wrong:* the operator lists one more deployment, or turns `controller_alerts` off.
- **Retries, give-ups and bounds.**
  - **Retried:** a 2xx is delivered. A 408, 429 or 5xx, a timeout or a connection failure is retried, honouring `Retry-After` up to the cap.
  - **Given up at once:** any 3xx (redirects are never followed), and every other 4xx.
  - **Backoff:** starts at 10 s and doubles to a cap of 15 minutes, with equal jitter (a random point in the upper half of the step, from `getrandom`).
  - **Give-up:** an event still undelivered 24 hours after it was queued is given up.
  - **Pending cap:** at most 1,000 events per webhook. Beyond that the oldest are dropped, and the count is logged.
  - **Records:** a give-up or a drop writes one controller-wide audit row, `webhook_gave_up` or `webhook_dropped`, with the webhook's name, the seq and the last status. They never carry the URL, a key or a response body. These kinds give no event, so a failing webhook can't feed itself.
  - **Timeouts:** connect 5 s, whole request 10 s.
  - **Bodies:** a request body is at most 16 KiB, with summaries cut to fit. A response body is never read beyond 4 KiB, and never logged.

  *If wrong:* a receiver down for more than a day misses what happened meanwhile, and the audit rows say what it missed.
- **Logs have a budget of their own.** A logs query costs VictoriaLogs far more than a read costs SQLite. So each credential gets a logs bucket of 20 at once, refilling at 1 a second, beside its read bucket. The controller runs at most 4 VictoriaLogs queries at once, and a fifth is `503 busy` at once, never queued. Over the bucket the answer is `429 rate_limited`, titled "too many log queries by this credential", with `Retry-After`, counted in `access_throttled` with `"logs": true`. `throttled_event(spender, dropped, reads: bool)` in `auth/budget.rs` takes a `Allowance { Changes, Reads, Logs }` (not `Bucket`, which `agent_api/rate_limit.rs` already names) instead, and writes `"reads": true`, `"logs": true` or neither, so existing rows read the same. *If wrong:* an agent paging a long window waits a few seconds.
- **The payload's schema is in the OpenAPI document.** `WebhookEvent` lives in `landfall-api` and derives its schema. It goes in the document's top-level `webhooks` (OpenAPI 3.1) if `utoipa` 6 writes that, and in `components.schemas` with a reference from `info.description` if not. Task 8 checks which, and records it. A test validates real payloads against that schema. *If wrong:* the schema is in components only, and `docs/api.md` points there.
- **`landfall-server webhook test --config <FILE> --secrets <FILE> [--db <FILE>] <NAME>`** sends one signed `test` event at once, to the URL in the secrets file, through the same client and policy, and prints the webhook's name and the status, never the URL. It writes nothing but, with `--db`, its audit row, `webhook_tested`. An operator setting up Home Assistant needs to see one arrive. *If wrong:* one subcommand to remove.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply. No `#[allow]` or `#[expect]` without `reason = "..."`. `unsafe_code` is forbidden. No `unwrap` or `expect` outside tests. Public error enums are `#[non_exhaustive]`.
- Source files stay under about 800 lines of code. Tests go in their own files, as `foo/tests.rs` and `foo/tests/<scenario>.rs`, naming what they import. `crates/server/src/cli.rs` (570), `store.rs` (589), `watcher.rs` (668), `config/mod.rs` (561) and `config/raw.rs` (555) take only what a task names; new code goes in new files. `crates/server/src/api/tests/deployments.rs` (746) and `watcher/tests/commits.rs` (650) take nothing. `api/tests/grants.rs` (646) takes only Task 5's `CASES` row and its path function, and `api/tests.rs` (552) only the `logs` role.
- Every `/api/v1` route takes a `Principal` first. Query strings are capped at 2 KiB and refuse unknown parameters. Every answer is JSON with `Cache-Control: no-store` and no CORS header, and every refusal is `application/problem+json` with a stable `code` in the document's `Problem` schema.
- No secret anywhere it can be read: webhook URLs and keys, the VictoriaLogs bearer and the secrets file's contents never appear in an answer, a log line, an audit row, an error or `Debug` output. A webhook's URL is a secret like its key: logs, audit rows, errors and `webhook test` name the webhook by `name`.
- Every outbound request (VictoriaLogs and webhooks) is made by a `reqwest` client built by `outbound::client` only. That means `.no_proxy()`, `redirect::Policy::none()`, `https_only` when the URL is `https://`, the policy's resolver, a connect and a total timeout, a streamed body under a cap, and `User-Agent: landfall/<version>`.
- Nothing about logs or notifications may block, slow or fail a deploy, a report or the watcher. The notifier and senders are their own tasks. Their database writes are short transactions of their own, and a failure there is logged and retried, never propagated.
- Hostile text (log lines, hosts' reasons, receiver answers) is never logged by the controller. It is JSON-escaped in answers and escaped again by the CLI's `display::safe` before a terminal sees it.
- Nothing personal: example names only (`app/prod`, `app/staging`, `home-1`, `operator`, `ci`, `https://landfall.example.com`, `https://hooks.example.com/landfall`, `http://192.0.2.10:9428` only in tests that expect a refusal of documentation ranges, and `10.0.0.5` for a private address).
- Security review (the `security-review` skill or an equivalent) before merging every PR of this plan: each touches grants, outbound HTTP or the agent's host access. Each PR says what was and wasn't verified, separating CI from local.
- Gate before each commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`. Never set `CARGO_TARGET_DIR` or any other `CARGO_*` variable. A workflow change passes `GH_TOKEN=$(gh auth token) uvx zizmor .` with no findings. Conventional commits, no attribution trailers.

**The new `/api/v1` operation and its grant**, as the document's `security` lists it (`T` token, `S` session):

| Operation | Path | Roles | Task |
|---|---|---|---|
| `getDeployLogs` | `GET /api/v1/deploys/{id}/logs` | T, S: `logs` | 5 |

## Review Focus

1. **A crafted value reaching LogsQL.** A `since` of `1 OR *`, a `limit` of `1|delete`, a cursor whose payload holds `"`, a deployment id at the edge of its grammar, a field name with a space in the configuration. Each must be refused before any query, or arrive quoted so that it matches only itself → Task 2 `field_names_outside_the_grammar_are_refused`; Task 4 `quoting_escapes_quotes_backslashes_and_controls`, `query_is_built_from_integers_and_validated_ids_only`; Task 5 `non_integer_window_and_limit_are_refused`, `a_cursor_of_another_deploy_is_refused`; Task 6 `docker_logs_exact_match_is_exact_for_hostile_values`.
2. **A webhook that reaches inside the network.** A URL naming `169.254.169.254`, `[::ffff:169.254.169.254]`, `[64:ff9b::a9fe:a9fe]`, `localhost` or a public name that later resolves to `10.0.0.5`. A 302 to an internal address. A proxy in the environment. Each must connect nowhere unless the webhook allows the private network, and link-local never → Task 2 `class_table`, `target_url_literals_follow_the_policy`; Task 3 `webhook_url_literals_follow_the_webhooks_policy`, `resolver_drops_refused_addresses`, `a_rebinding_name_connects_nowhere`; Task 10 `redirect_is_given_up_not_followed`, `proxy_in_the_environment_is_not_used`.
3. **A notification telling a receiver about a deployment it isn't configured for.** A host-only row from a host with only other deployments. A request cancelled by a rollback of another deployment. A rule reason naming a promotion source. A controller-wide row to a webhook without `controller_alerts`, or any controller-wide row but the two alerts to one with it → Task 8 `rows_outside_the_webhooks_deployments_give_nothing`, `host_rows_need_a_listed_deployment_on_that_host`, `controller_alerts_reach_only_webhooks_that_opt_in`, `other_controller_wide_rows_never_notify`, `controller_alerts_carry_no_sources_or_credential_ids`, `no_free_text_from_a_writer_that_can_name_another_deployment`.
4. **A receiver that is slow, down, or hostile.** It hangs for a minute, answers 500 for two days, sends a 1 GiB body or redirects. Deploys and the watcher must go on unaffected, nothing past the caps is read or kept, and retries must back off and stop → Task 10 `a_hanging_receiver_times_out_and_is_retried`, `backoff_doubles_with_jitter_to_the_cap`, `undelivered_after_24_hours_is_given_up_and_audited`, `a_huge_answer_is_not_read`; Task 11 `a_dead_receiver_does_not_slow_a_deploy`.
5. **A secret leaking.** The webhook's URL or key, the VictoriaLogs bearer or the secrets file's text appearing in `Debug`, an error, a log line, an audit row, an answer or `webhook test`'s output. A secrets file others can read, or a link. A URL left in the fleet file, where every host reads it → Task 2 `a_url_in_the_fleet_file_is_refused`, `target_url_debug_shows_only_the_scheme`; Task 3 `secrets_debug_is_redacted`, `webhook_urls_appear_in_no_error`, `readable_or_linked_secrets_file_is_refused`; Task 9 `gave_up_deletes_and_audits_without_url_or_key`; Task 10 `no_log_line_or_audit_row_holds_the_key_or_url`, `webhook_test_prints_the_name_not_the_url`.
6. **Logs read by a grant that doesn't cover them.** A token with `view`, or with every grant but `logs`, reading a deploy's logs; a holder of `logs` alone reading state → Task 5 `view_alone_cannot_read_logs`, the `CASES` row for `getDeployLogs` under `logs` (the grant test tries every other role there, and every role but `view` against each `view` operation), `whoami_lists_logs_only_where_granted`.

## Pre-flight: tasks sharing files or interfaces

Run the tasks in order. These are the places where two tasks meet, so a parallel run would conflict, or a later task depends on a name an earlier one fixed:

| Shared | Tasks | How |
|---|---|---|
| `crates/agent/src/compose.rs`, `deploy.rs`, `deploy/files.rs`, `daemon/judge.rs`, and every `DeployPlan::from_verified` and `render_override` caller | 1 | Nothing later touches them |
| `crates/core/src/config/{mod,raw}.rs`, new `config/{logs,webhook}.rs` | 2 | Task 2 adds the sections; Tasks 4, 8 and 10 read them through getters |
| `crates/core/src/net.rs` (`AddrClass`, `class`, `TargetUrl`) | 2, 3 | Task 2 creates it for `[logs] url`'s literal check; Task 3's `secrets::load` parses webhook URLs with `TargetUrl::parse`, and its resolver calls `allows` |
| `Cargo.toml`, `crates/server/Cargo.toml` | 3 | `hmac`, `reqwest` (`rustls`, `stream`); dev: `wiremock` |
| `crates/server/src/secrets.rs`, `outbound.rs` | 3 | Task 3 creates both; Tasks 4 and 10 use `outbound::client`, `Secrets` and `WebhookSecret` (a webhook's URL and key) |
| `crates/server/src/cli.rs` (`ServeArgs`, `serve_watching`) | 3, 10 | Task 3 adds `--secrets` and loads it; Task 10 spawns the notifier and adds `webhook test` |
| `crates/server/src/agent_api.rs` (`ApiState::new`, `Limits`) | 4, 5 | Task 4 adds the optional `LogsClient` to `ApiState`; Task 5 adds `logs_rate_per_second`, `logs_burst`, `logs_concurrency` |
| `crates/server/src/auth/budget.rs`, `auth/problem.rs`, `crates/api/src/problem.rs` | 5 | `spend_logs`, `Allowance`, `LogsOverBudget`, `LogsUnavailable` |
| `Permission` in `crates/core/src/config/mod.rs` and `crates/api/src/deployments.rs`; `auth/grants.rs` (`can`); `api/deployments.rs` (`PERMISSIONS`); `api/visible.rs` (`permitted_by_id`) | 5 | The `logs` grant; Task 8 reads nothing of it |
| `crates/server/src/api.rs`, `api/query.rs` (`CursorList::Logs`), `api/tests.rs` (`ROLES`, `grant_sets`), `api/tests/grants.rs` | 5 | One `routes!` merge, one cursor list, one seed and the `logs` role, one `CASES` row |
| `crates/api/src/lib.rs` | 5, 8 | `logs`; `webhook` |
| `crates/server/src/audit.rs` (`EventKind`) | 9 | `WebhookGaveUp`, `WebhookDropped`, `WebhookTested`; `api/audit/detail.rs`'s exhaustive match lists them as never shown |
| `crates/server/migrations/0009_webhooks.sql`, `store.rs` (`mod webhooks;`) | 9 | One migration, one module line |
| `docs/api/openapi.json` | 5, 8 | Regenerated, never edited by hand |
| `docs/api.md` | 5, 8 | Logs; the webhook payload |
| `crates/cli/src/read.rs`, `read/render.rs`, `cli/tests.rs` | 7 | `Logs` command, its renderer, the OpenAPI row |
| `.github/workflows/ci.yml` | 6 | One step for the server's `docker_` tests; zizmor clean |
| `docs/design/landfall.md` | 5 (8.2, and the section 12 row on logs), 8 (8.3), 11 (the rest) | Each PR changes the spec where its behaviour changes |
| `docs/configuration.md` | 2 (`[logs]`, `[[webhook]]`, validation rules), 5 (the `logs` grant) | |
| `docs/operations.md`, `README.md`, `AGENTS.md` | 6 (logs section), 11 (the rest) | |

## What the next plans hold

- **Plan 09, approvals hardening.** #30: re-check runs for non-automatic releases, and cancel a queued approved deploy. #31: a host-side minimum version, so one approval can't downgrade to a release with known holes. `landfall approve`, which computes the intent's hash locally (spec 6.3) from `IntentView` and makes the assertion with a platform passkey where one is available, so the approver needn't trust the page's choice of what is signed. The `approval_needed` webhook event can then carry the intent hash, so a phone shows what will be signed.
- **Then the web UI (section 11).** The pages over this API: the pipeline per repo and per host, the version story with its logs (`getDeployLogs` behind the page's session), "needs you", the design language and Bobbin. If its audit page needs controller-wide rows, they come through a controller-level grant enforced like `approve`, as plan 07 says. Webhook delivery status, if the owner wants it on a page, comes through that same controller-level grant, never to a token.
- **Not planned yet:** #74 (`agents_via_warden`), #61 and #60 stay where they are tracked.

---

## PR A: labels, configuration, secrets and the outbound policy

### Task 1: The spec's labels, and the deploy id on every container

**Files:** Modify `crates/agent/src/compose.rs` (`render_override` and its tests), `crates/agent/src/deploy.rs` (`DeployPlan` gains `deploy_id`), `crates/agent/src/deploy/files.rs`, `crates/agent/src/daemon/judge.rs`, and the callers in `crates/agent/src/daemon/tests.rs`, `daemon/tests/approval_order.rs`, `deploy/tests.rs`, `deploy/tests/plan_and_report.rs`, `deploy/tests/drift.rs`, `cli/tests.rs`, `tests/e2e/harness.rs`, `tests/docker_e2e/harness.rs` and `tests/docker_daemon.rs`.

**Interfaces:**
- Produces: `pub fn render_override(service: &str, image: &str, deployment: &DeploymentId, tag: &ReleaseTag, commit: &CommitSha, deploy: DeployId) -> String`, writing labels `landfall.deployment`, `landfall.version`, `landfall.commit` and `landfall.deploy` (the decimal id, quoted like every value), in that order. `pub const LABEL_DEPLOYMENT: &str = "landfall.deployment"`, `LABEL_VERSION`, `LABEL_COMMIT` and `LABEL_DEPLOY`, so docs and tests name them from one place.
- `DeployPlan::from_verified(deployment, tag, version, origin, deploy_id: DeployId) -> Self`, and `pub fn deploy_id(&self) -> DeployId`.

- [ ] **Step 1: Failing tests** in `compose.rs`'s tests:
  - `override_labels_name_the_deploy`: the rendered text holds `landfall.deploy: "42"` and the other three `landfall.*` labels, and no `dev.landfall`.
  - `pinned_image_reads_an_override_written_before_plan_08`: a recorded override with the old `dev.landfall.*` labels still gives `Pin::Image`.
  - The existing `pinned_image_recognises_nothing_else` and `quoting_escapes_what_could_break_out` pass unchanged.

  In `deploy/tests/plan_and_report.rs`: `the_override_carries_the_works_deploy_id`.
  Run: `cargo nextest run -p landfall-agent compose plan_and_report`. Expected: FAIL.
- [ ] **Step 2: Implement.** The daemon passes `work.deploy_id` where `judge.rs` builds the plan. Run: `cargo nextest run -p landfall-agent`. Expected: PASS.
- [ ] **Step 3: Gate; Linux, and the agent's `docker_` tests, as the override's bytes changed. Commit:** `feat(agent): label containers with the spec's names and the deploy id`.

### Task 2: `[logs]` and `[[webhook]]` in the fleet configuration

**Files:** Create `crates/core/src/net.rs`, `crates/core/src/net/tests.rs`, `crates/core/src/config/logs.rs`, `crates/core/src/config/webhook.rs`, `crates/core/src/config/tests/{logs,webhooks}.rs`. Modify `crates/core/src/lib.rs` (`pub mod net;`), `crates/core/src/config/mod.rs` (fields, getters, error variants, `mod` lines), `crates/core/src/config/raw.rs` (raw sections and their conversion), `crates/core/src/config/tests.rs` (`mod` lines), `docs/configuration.md` (`[logs]` and `[[webhook]]` sections, their validation rules, and that a webhook's URL and key are in the controller's secrets file, not here).

**Interfaces:**
- `net.rs`: `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub enum AddrClass { Public, Private, Loopback, Never }` and `#[must_use] pub fn class(ip: IpAddr) -> AddrClass`, by the ranges in the Rulings, judging IPv4-mapped, IPv4-compatible and `64:ff9b::/96` addresses by their embedded IPv4. `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub struct NetPolicy { pub private: bool }`, and `#[must_use] pub fn allows(policy: NetPolicy, https: bool, ip: IpAddr) -> bool`, with this table:

  | Class | `https://` | `http://` |
  |---|---|---|
  | `Never` | refused | refused |
  | `Public` | allowed | refused |
  | `Private`, `Loopback` | allowed with `private` | allowed with `private` |

  `pub struct TargetUrl { url: Url, https: bool }` with `TargetUrl::parse(text: &str, policy: NetPolicy) -> Result<TargetUrl, TargetError>`. It takes `https` or `http` only. It refuses userinfo and a fragment, refuses `http` without `policy.private`, and checks an IP-literal host with `allows`. A host name is checked at connection time instead. It has getters `url()`, `https()` and `host_literal() -> Option<IpAddr>`. Its `Debug` is written by hand and prints only the scheme (`TargetUrl { scheme: "https", .. }`), because the server's secrets hold webhook URLs in it. `TargetError` is `#[non_exhaustive]` and never repeats the URL, which may hold a capability path or a token in its query. `TargetUrl` lives in core so that one parser serves both `[logs] url` here and webhook URLs in the server's secrets file (Task 3).
- `config/logs.rs`: `pub struct Logs { url: TargetUrl, deployment_field: String, deploy_field: String, timeout: Duration, account_id: Option<u32>, project_id: Option<u32> }`, with getters. TOML: `url` (required), `deployment_field` (default `LANDFALL_DEPLOYMENT`), `deploy_field` (default `LANDFALL_DEPLOY`), `timeout_secs` (1 to 30, default 10), `account_id`, `project_id`. A field name must match `[A-Za-z_][A-Za-z0-9_]{0,63}`, and the two must differ. The policy is `NetPolicy { private: true }`: the operator's own service, so `http://` to the private network is allowed and `Never` isn't.
- `config/webhook.rs`: `pub struct Webhook { name: WebhookName, events: BTreeSet<EventName>, deployments: BTreeSet<DeploymentId>, controller_alerts: bool, policy: NetPolicy }`, with getters. No URL: it is in the secrets file (Rulings). `WebhookName` matches `[a-z0-9][a-z0-9-]{0,31}`, implements `Deserialize` by `FromStr`, so the server's secrets file keys its tables by it, and `Ord`. `pub enum EventName { ApprovalNeeded, ApprovalClosed, DeployFinished, DeployRefused, ReleaseRefused, ConfigDrift, RunningDrift }`, written `snake_case` (`test` can't be subscribed; every webhook gets it from `webhook test`; `controller_alert` isn't an `EventName`: `controller_alerts` subscribes to it). TOML: `[[webhook]]` with `name`, `events` (default empty), `deployments` (default empty), `controller_alerts` (default false) and `allow_private_network` (default false), and `deny_unknown_fields`. `events` and `deployments` must be both non-empty or both empty, and both empty only with `controller_alerts = true`. Every deployment must exist, and names are distinct. A `url` key gets its own `ConfigError` variant, saying a webhook's URL goes in the controller's secrets file, rather than serde's unknown-field message; it doesn't repeat the value.
- `Config` gains `logs: Option<Logs>` and `webhooks: Vec<Webhook>`, with `pub fn logs(&self) -> Option<&Logs>`, `pub fn webhooks(&self) -> &[Webhook]` and `pub fn webhook(&self, name: &WebhookName) -> Option<&Webhook>`. New `ConfigError` variants each name the section and the value through `shown_in_config`. The URL is never shown whole, only its scheme and the reason.

- [ ] **Step 1: Failing tests.**
  - In `net/tests.rs`: `class_table`, with at least `8.8.8.8` and `2001:4860::1` (Public), `10.0.0.5`, `172.16.0.1`, `192.168.1.1`, `100.64.0.1` and `fd00::1` (Private), `127.0.0.1` and `::1` (Loopback), and `169.254.169.254`, `fe80::1`, `0.0.0.0`, `::`, `224.0.0.1`, `255.255.255.255`, `192.0.2.10`, `::ffff:169.254.169.254`, `::ffff:127.0.0.1` (Loopback through the mapping), `64:ff9b::a9fe:a9fe` (Never) and `64:ff9b::808:808` (Public). Also `policy_table`, for each class × scheme × `private`.
  - In `config/tests/logs.rs`: `logs_parse_with_defaults`, `field_names_outside_the_grammar_are_refused` (`a b`, `a"b`, `a:b`, empty, 65 characters, a leading digit), `the_two_fields_must_differ`, `timeout_outside_1_to_30_is_refused`, `logs_url_with_userinfo_is_refused_without_repeating_it`, `logs_url_at_link_local_is_refused`, `no_logs_section_is_none`.
  - In `net/tests.rs`, for `TargetUrl::parse` directly: `target_url_literals_follow_the_policy` (`https://10.0.0.5/` refused without `private` and accepted with it; `https://[::ffff:169.254.169.254]/` and `http://169.254.169.254/` refused with it; `http://hooks.example.com/` refused without it; `https://hooks.example.com/landfall?token=x` accepted), `target_url_refuses_fragment_userinfo_and_other_schemes` (each error's `Display` holds neither the path nor the query), `target_url_debug_shows_only_the_scheme`.
  - In `config/tests/webhooks.rs`: `webhook_parses`, `unknown_event_is_refused`, `test_cannot_be_subscribed`, `events_and_deployments_go_together` (one empty and the other not is refused), `a_webhook_that_receives_nothing_is_refused` (both empty without `controller_alerts`), `a_controller_alerts_only_webhook_parses` (both empty with it), `unknown_deployment_is_refused`, `duplicate_names_are_refused`, `bad_names_are_refused`, `a_url_in_the_fleet_file_is_refused` (the error names the secrets file and doesn't hold the URL's path), and `the_hash_covers_the_new_sections`.

  Run: `cargo nextest run -p landfall-core`. Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-core -p landfall-agent -p landfall-server`. Expected: PASS. Hosts ignore both sections, and the agent's tests are unchanged.
- [ ] **Step 3: Gate. Commit:** `feat(config): logs and webhooks, and where outbound requests may go`.

### Task 3: The controller's secrets file, and one way to make an outbound client

**Files:** Create `crates/server/src/secrets.rs`, `crates/server/src/secrets/tests.rs`, `crates/server/src/outbound.rs`, `crates/server/src/outbound/tests.rs`. Modify `Cargo.toml` and `crates/server/Cargo.toml` (`hmac`, `reqwest` with `rustls` and `stream`; `toml` and `url`, already workspace dependencies through core, for the secrets file and `TargetUrl`'s `Url`; dev: `wiremock`), `crates/server/src/lib.rs` (`mod secrets; mod outbound;`), `crates/server/src/cli.rs` (`ServeArgs.secrets: Option<PathBuf>`, loaded by `secrets::load(path, &config)`, or `none_needed`, before the database opens), `crates/server/src/cli/tests.rs`, `deny.toml` (licences only, if needed).

**Interfaces:**
- `secrets.rs`:
  - `pub(crate) struct Secrets { webhooks: BTreeMap<WebhookName, WebhookSecret>, logs_bearer: Option<Bearer> }`, with `webhook(&self, name: &WebhookName) -> Option<&WebhookSecret>` and `logs_bearer(&self) -> Option<&Bearer>`.
  - `pub(crate) struct WebhookSecret { url: TargetUrl, key: WebhookKey }`, with getters, a hand-written `Debug` that prints neither (`WebhookSecret { .. }`), and no `Display`.
  - `pub(crate) fn load(path: &Path, config: &Config) -> Result<Secrets, SecretsError>`. It opens the file with `O_NOFOLLOW` and checks the open descriptor: a regular file, owned by the effective uid, `mode & 0o077 == 0`, at most 16 KiB. It parses TOML with `deny_unknown_fields`, into a raw form whose `url` is a plain string held only inside `load`. Then it checks the file against `config`, so that no `Secrets` exists unchecked: each `[[webhook]]` must have a `[webhook.<name>]` with `url` and `key`; a `[webhook.<name>]` no `[[webhook]]` names is refused (Rulings); and each `url` goes through `TargetUrl::parse(url, webhook.policy())`, so the literal-address policy and the scheme rule are those the fleet file sets for that webhook.
  - `pub(crate) fn none_needed(config: &Config) -> Result<Secrets, SecretsError>`, for `serve` without `--secrets`: an empty `Secrets` if the configuration has no webhook, and otherwise the error `load` gives for the first webhook without an entry.
  - `WebhookKey` holds the decoded bytes (24 to 64) of `whsec_<standard base64>`. `Bearer` holds 1 to 512 visible ASCII characters. Both have redacted `Debug` and no `Display`.
  - `SecretsError` is `#[non_exhaustive]`. It names the path, the webhook and which key (`url`, `key` or `bearer`) and why (missing, malformed, refused by the network policy with the `TargetError` reason), never a value. A TOML syntax error is reported by line and column only: `toml`'s own message quotes the offending text, which may be a URL or a key, so it is never passed on.
- `outbound.rs`:
  - `pub(crate) struct Target<'a> { pub url: &'a TargetUrl, pub policy: NetPolicy, pub connect: Duration, pub total: Duration }`.
  - `pub(crate) fn client(target: &Target<'_>, resolver: Arc<dyn Lookup>) -> Result<reqwest::Client, OutboundError>` builds the client by the Global Constraints, with `dns_resolver(Arc<PolicyResolver>)`.
  - `pub(crate) trait Lookup: Send + Sync { fn lookup(&self, host: &str) -> BoxFuture<'_, io::Result<Vec<IpAddr>>>; }`. `SystemLookup` uses `tokio::net::lookup_host`. Tests pass a fixed table.
  - `PolicyResolver` keeps only the addresses `net::allows` passes for the target's scheme and policy, and fails with "no address this target may connect to" when none is left.
  - `pub(crate) async fn read_capped(response: reqwest::Response, cap: usize) -> Result<Bytes, OutboundError>` streams the body and stops at the cap.
  - `OutboundError` is `#[non_exhaustive]`: `Refused`, `Timeout`, `Connect`, `Status(u16)`, `TooLarge`, `Redirect(u16)`. Its `Display` holds no URL, which `reqwest::Error::without_url` ensures.

- [ ] **Step 1: Check the crates.** `hmac` 0.13 and `reqwest`'s `dns_resolver` and `stream` at versions `crate-age` accepts, their licences against `deny.toml`, and `cargo tree -e normal` showing no OpenSSL. Record the findings in the PR.
- [ ] **Step 2: Failing tests.**
  - In `secrets/tests.rs`:
    - `secrets_parse`: two webhooks and a bearer.
    - `readable_or_linked_secrets_file_is_refused` (0640, 0604 and a symlink to a 0600 file), `oversized_file_is_refused`.
    - `short_or_long_key_is_refused`, `key_without_whsec_prefix_is_refused`.
    - `every_webhook_needs_a_url_and_a_key`: an entry missing either, and a webhook with no entry, are each refused naming the webhook and the key.
    - `an_entry_for_an_unknown_webhook_is_refused`.
    - `webhook_url_literals_follow_the_webhooks_policy`: `https://10.0.0.5/` refused for a webhook without `allow_private_network` and accepted for one with it; `http://169.254.169.254/` and `https://[64:ff9b::a9fe:a9fe]/` refused for both; `http://hooks.example.com/` refused without it.
    - `fragment_and_userinfo_in_a_webhook_url_are_refused`.
    - `without_secrets_a_configuration_with_webhooks_is_refused`, and `without_secrets_no_webhooks_is_fine` (`none_needed`).
    - `secrets_debug_is_redacted`: the key's base64, the URL's path (`/capability-token`) and query, and the bearer appear in no `Debug` of `Secrets`, `WebhookSecret`, `WebhookKey` or `Bearer`.
    - `webhook_urls_appear_in_no_error`: every refusal above, and a TOML syntax error on the `url` line, hold neither the URL's path nor its query in `Display` or `Debug`.
  - In `outbound/tests.rs`, with `wiremock` on loopback:
    - `resolver_drops_refused_addresses`: a lookup giving `[169.254.169.254, 10.0.0.5]` under `private: true` leaves `10.0.0.5`.
    - `a_rebinding_name_connects_nowhere`: a name whose lookup gives `127.0.0.1` under `private: false` fails as `Refused`, and the mock receives nothing.
    - `loopback_is_reached_only_with_private`.
    - `http_to_a_public_address_is_refused`: a lookup giving `8.8.8.8` for an `http://` target with `private: true`.
    - `redirect_is_not_followed`: a 302 to a second mock gives `Redirect(302)`, and the second mock receives nothing.
    - `proxy_in_the_environment_is_not_used`, as plan 07's CLI test does it: a child process with `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` set.
    - `read_capped_stops_at_the_cap`.
    - `errors_hold_no_url`: the path `/capability-token` appears in no error's `Display` or `Debug`.
  - In `cli/tests.rs`: `serve_refuses_webhooks_without_secrets`, `serve_refuses_a_webhook_url_the_policy_refuses` (before the database file is created).

  Run: `cargo nextest run -p landfall-server secrets outbound`. Expected: FAIL.
- [ ] **Step 3: Implement.** Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 4: Gate; `docker build .`; security review of PR A. Commit:** `feat(server): a secrets file, and outbound requests only where policy allows`. Open PR A.

## PR B: reading logs

### Task 4: The VictoriaLogs client

**Files:** Create `crates/server/src/logs.rs`, `crates/server/src/logs/logsql.rs`, `crates/server/src/logs/tests.rs`, `crates/server/src/logs/tests/{logsql,client}.rs`. Modify `crates/server/src/lib.rs` (`mod logs;`), `crates/server/src/agent_api.rs` (`ApiState` gains `logs: Option<Arc<LogsClient>>` and `pub(crate) fn logs(&self) -> Option<&LogsClient>`; `ApiState::new` takes it), `crates/server/src/cli.rs` (built from `config.logs()` and the bearer), and every `ApiState::new` caller in tests.

**Interfaces:**
- `logs/logsql.rs`:
  - `#[must_use] pub(crate) fn quoted(value: &str) -> String`: a LogsQL double-quoted string, `\` and `"` escaped, every `char::is_control` and U+2028/U+2029 as `\uXXXX`.
  - `pub(crate) struct LogsQuery<'a> { pub deployment_field: &'a str, pub deploy_field: &'a str, pub deployment: &'a DeploymentId, pub deploy: i64, pub offset: u32, pub limit: u16 }`, and `#[must_use] pub(crate) fn text(query: &LogsQuery<'_>) -> String`, which gives exactly the shape in the Rulings. The field names were validated by the configuration and are quoted too, as LogsQL allows, so a later change to the grammar can't open a hole.
- `logs.rs`:
  - `pub(crate) const MAX_ANSWER: usize = 8 * 1024 * 1024`, `pub(crate) const MAX_MESSAGE: usize = 8 * 1024`, `pub(crate) const MAX_LINES: u16 = 1000`.
  - `pub(crate) struct LogsClient { client: reqwest::Client, base: Url, logs: Logs, bearer: Option<Bearer>, permits: Semaphore }`. `LogsClient::new(logs: &Logs, bearer: Option<Bearer>, lookup: Arc<dyn Lookup>, concurrency: usize) -> Result<Self, OutboundError>` goes through `outbound::client`, with connect 5 s and the configured timeout as the total.
  - `pub(crate) async fn query(&self, q: &LogsQuery<'_>, start: Timestamp, end: Timestamp) -> Result<Vec<LogLine>, LogsError>` sends `POST <base>/select/logsql/query`, form-encoded: `query`, `start`, `end` (RFC 3339 with nanoseconds) and `limit`. It sets `AccountID` and `ProjectID` when configured, and `Authorization: Bearer` when a bearer is. It reads the JSON-lines answer through `read_capped(MAX_ANSWER)`. Each line is an object, with `_time` parsed by `jiff` and `_msg` a string, cut at `MAX_MESSAGE` with `cut: true`. Any other field is ignored. It takes a permit with `try_acquire`, and none free is `LogsError::Busy`.
  - `pub(crate) struct LogLine { pub at: Timestamp, pub message: String, pub cut: bool }`.
  - `pub(crate) enum LogsError { Busy, Timeout, Refused, Status(u16), TooLarge, Unreadable }`, `#[non_exhaustive]`. Each has a fixed title, and none repeats a URL, a body or a line.

- [ ] **Step 1: Failing tests.**
  - In `logs/tests/logsql.rs`: `quoting_escapes_quotes_backslashes_and_controls` (a table that includes `a"b`, `a\b`, `\n`, `\u{1b}`, `\u{2028}` and plain `app/prod`), `quoting_round_trips` (a small reader of the quoted form, in the test, gives back the input for a `proptest` of arbitrary strings), `query_is_built_from_integers_and_validated_ids_only` (the exact text for one `LogsQuery`, pinned as a string).
  - In `logs/tests/client.rs`, with `wiremock`:
    - `query_sends_the_form_and_headers` (form fields, tenant headers, bearer).
    - `lines_are_parsed_and_other_fields_dropped`.
    - `long_messages_are_cut_on_a_character_boundary` (a multibyte character across 8 KiB).
    - `answer_over_8_mib_is_too_large`.
    - `a_slow_answer_times_out` (paused time).
    - `non_200_is_status_without_the_body`.
    - `unparseable_line_is_unreadable`.
    - `a_fifth_concurrent_query_is_busy`.
    - `bearer_never_appears_in_errors_or_debug`.

  Run: `cargo nextest run -p landfall-server logs`. Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `feat(logs): a read-only VictoriaLogs client that builds its own queries`.

### Task 5: `GET /api/v1/deploys/{id}/logs`

**Files:** Create `crates/api/src/logs.rs`, `crates/server/src/api/logs.rs`, `crates/server/src/api/tests/logs.rs`. Modify `crates/api/src/lib.rs`, `crates/api/src/problem.rs` (`LogsUnavailable`), `crates/server/src/api.rs` (`.merge(logs::routes())`), `crates/server/src/api/query.rs` (`CursorList::Logs`), `crates/server/src/api/openapi.rs` (a `LogsUnavailable` response; `503` reuses the existing `Busy`), `crates/server/src/auth/budget.rs` (logs bucket, `spend_logs`, `throttled_event` takes an `Allowance` for its `reads: bool`), `crates/server/src/auth/problem.rs` (`LogsOverBudget`, `LogsUnavailable`), `crates/server/src/agent_api.rs` (`Limits`), `crates/server/src/api/tests.rs` (seed: a claimed and finished deploy on `app/prod`, a fake VictoriaLogs; `ROLES` gains `"logs"`, last, so every existing holder keeps its name; `grant_sets` counts to `1 << ROLES.len()` rather than a fixed 16), `crates/server/src/api/tests/grants.rs` (one `CASES` row), `crates/server/src/api/tests/deployments.rs` (only the expected `can` lists of `a_tokens_grants_never_list_approve`, which gain `"logs"`; nothing else, as it is at 746), `docs/api.md`, `docs/api/openapi.json`.
For the `logs` grant: `crates/core/src/config/mod.rs` (`Permission::Logs`), `crates/core/src/config/tests/parsing.rs`, `crates/api/src/deployments.rs` (`Permission::Logs`), `crates/server/src/auth/grants.rs` (`can`'s arm), `crates/server/src/api/deployments.rs` (`PERMISSIONS` gains `(Permission::Logs, Granted::Logs)`), `crates/server/src/api/visible.rs` (`permitted_by_id`), `docs/configuration.md` (`[[grant]]`'s `can` and validation rule 7), `docs/design/landfall.md` (8.2, and section 12).

**Interfaces:**
- `landfall-api`:
  - `LogsView { state: LogsState, deploy: i64, since: i64, until: i64, lines: Vec<LogLineView>, next_cursor: Option<String> }`.
  - `LogsState { Listed, NotConfigured, NotStarted, #[serde(other)] Unknown }`.
  - `LogLineView { at: String, at_ns: i64, message: String, cut: bool }`. `at` is RFC 3339 with nanoseconds, and `at_ns` the same instant for sorting.
  - `ProblemCode::LogsUnavailable`.
- `Limits` gains `logs_rate_per_second: u32` (1), `logs_burst: u32` (20) and `logs_concurrency: usize` (4), documented as plan 07's are.
- `Budget::spend_logs(&mut self, spender: &Spender, now: i64) -> bool`, with its own dropped counts.
- `api/logs.rs`:
  - `LogsQuery { since: Option<i64>, until: Option<i64>, limit: Option<LogsLimit>, cursor: Option<String> }`, `deny_unknown_fields`, deriving `IntoParams`. `LogsLimit(u16)` is 1 to 1,000, default 200.
  - The handler takes, in this order: the `Principal` (charged a read as every route is), the deploy, refused unless `permitted_by_id(config, principal, deployment, Permission::Logs)` passes (`404` or `403` by `visibility`, as `viewable_by_id` gives them), then `spend_logs`. Then come the window (Rulings), `not_configured` without a client, `not_started` without `claimed_at`, and the query.
  - The cursor is decoded with `CursorList::Logs`, and its `after` parsed as `<deploy>.<ns>.<k>`. A deploy other than the path's, a `k` over 100,000 or an `ns` outside the window is `400 bad_request`.
  - `LogsError::Busy` is `503 busy`. The other errors are `502 logs_unavailable` with the error's fixed title.
- `#[utoipa::path]` with `operation_id = "getDeployLogs"`, `security(("token" = ["logs"]), ("session" = ["logs"]))`, and responses 200, 400, 401, 403, 404, 429, 502 and 503.
- The `logs` grant, by the Rulings: `Permission::Logs` in core and on the wire, `can()`'s arm, `PERMISSIONS`, and `pub(crate) fn permitted_by_id<'a>(config: &'a Config, principal: &Principal, id: Option<&DeploymentId>, permission: Permission) -> Result<&'a Deployment, HumanProblem>` in `visible.rs`, of which `viewable_by_id` becomes the `View` case.
- Spec 8.2 becomes: "Per principal and deployment (exact ids, no globs in v0): `view`, `request`, `approve` (humans with a registered passkey only, enforced in code), `rollback` (request a manual rollback, which still needs approval), `logs` (read a deploy's container logs; apart from `view` because an application's logs can hold secrets it printed, so an agent trusted to watch state doesn't read them unless granted). No grant implies another. Grants live in the same reviewed config file." Section 12 gains a row: logs read with a stolen token: the `logs` grant, apart from `view`, the logs budget, the global cap; residual: what the application wrote to its logs, for a token that holds `logs`.

- [ ] **Step 1: Failing tests** in `api/tests/logs.rs`, with a fake VictoriaLogs (`wiremock`) behind a real `LogsClient`:
  - `lines_of_a_deploy_come_oldest_first`.
  - `the_query_names_the_deploy_and_its_deployment` (asserts the received form's `query` text).
  - `the_default_window_runs_from_claim_to_ten_minutes_after_finish`.
  - `since_below_the_claim_is_raised_and_echoed`.
  - `a_window_over_24_hours_or_reversed_is_refused`.
  - `non_integer_window_and_limit_are_refused`: `since=1%20OR%20*`, `limit=1|x`, `limit=0` and `limit=1001`. None reaches the fake.
  - `pages_follow_the_cursor_across_lines_sharing_a_nanosecond`.
  - `a_cursor_of_another_deploy_is_refused`.
  - `a_cursor_of_another_list_is_refused`.
  - `without_logs_configured_it_says_so`.
  - `a_deploy_never_claimed_is_not_started_without_a_query`.
  - `victorialogs_down_is_502_logs_unavailable`.
  - `a_fifth_query_at_once_is_busy`.
  - `logs_spend_their_own_bucket`: 21 at one instant; the last is 429 with the logs title, and a plain read still passes.
  - `logs_throttles_are_counted_with_logs_true`.
  - `logs_of_an_unseen_deploy_are_not_found`.
  - `logs_of_a_deployment_no_longer_configured_are_not_found`.
  - `view_alone_cannot_read_logs`: a token holding `view` on `app/prod` gets `403` and the fake receives nothing; the same principal's token after `logs` is added to the grant gets `200`.

  Also the `CASES` row for `getDeployLogs` (role `logs`). With `"logs"` in `ROLES`, the grant test then tries a holder of every other role (`view` included) there and expects `403`, a holder of `logs` alone and expects `200`, and a holder of every role but `view`, `logs` included, against every `view` operation and expects `403`. `every_success_answer_matches_its_documented_schema` covers the answer.
  In `api/tests/deployments.rs`'s `a_tokens_grants_never_list_approve`, the expected lists gain `"logs"`. In `crates/core/src/config/tests/parsing.rs`: `the_logs_grant_parses`. In `api/tests/logs.rs` too, so `deployments.rs` takes no new test: `whoami_lists_logs_only_where_granted`.
  Expected: FAIL.
- [ ] **Step 2: Implement; regenerate the document.** Document the operation, its `logs` grant (in the grants table, and in the list of grants beside `view`), the window, the caps, the states, the budget, the unstable order of same-nanosecond lines, and that logs are the container's own words, unverified and possibly secret-bearing, in `docs/api.md`. In `docs/configuration.md`, `can` lists `"logs"`, says it is apart from `view` and why, and recommends granting the two together. Change spec 8.2 and add the section 12 row, as above. Run: `cargo nextest run -p landfall-server -p landfall-api`. Expected: PASS.
- [ ] **Step 3: Gate; security review of PR B. Commit:** `feat(api): a deploy's logs, by its id and window`. Open PR B.

## PR C: logs for real, and from the CLI

### Task 6: Against a real VictoriaLogs, and a real journald pipeline

**Files:** Create `crates/server/tests/docker_logs/main.rs`, `crates/server/tests/docker_logs/stack.rs`, `crates/server/tests/docker_logs/vector.toml`, `crates/server/tests/docker_logs/README.md`. Modify `crates/server/Cargo.toml` (dev-dependencies, if any are needed), `.github/workflows/ci.yml` (one step), `docs/operations.md` (a new section, "Logs", after "What a deploy does"), `AGENTS.md` (testing rules: what these tests need).

**Interfaces:**
- `stack.rs` starts containers through the `docker` CLI, with images pinned by digest as constants: `VICTORIALOGS_IMAGE` and `VECTOR_IMAGE`, each a release at least 7 days old, with the tag in a comment. It waits for readiness by polling `/health` with a deadline, and removes its containers on drop. Each test names its containers with a random suffix.
- Two kinds of test, all `#[ignore]` and named `docker_logs_…`:
  - **VictoriaLogs only** (needs Docker): lines go in through VictoriaLogs' JSON-lines insert API with the default field names. A real controller (router and `serve::run` on loopback, a store in a temp directory, the store's own functions for the deploy) then answers `getDeployLogs` through `LogsClient`.
  - **The pipeline** (needs Docker with the journald log driver and a host journal, so Linux): a container started with `--log-driver journald --log-opt labels=landfall.deployment,landfall.version,landfall.commit,landfall.deploy` and those labels prints known lines. Vector, with `vector.toml` and the host's journal mounted read-only, forwards them to VictoriaLogs. The controller reads them back by deploy id. Without journald the test skips, unless `LANDFALL_TEST_REQUIRE_JOURNALD` is set, which makes that a failure, as `LANDFALL_TEST_REQUIRE_ROOT` does.
- `ci.yml`: after the agent's Docker step, `cargo test -p landfall-server --all-features --locked -- --ignored docker_logs`, with `LANDFALL_TEST_REQUIRE_JOURNALD: "1"`.

- [ ] **Step 1: Write the tests** in `main.rs`:
  - `docker_logs_a_deploys_lines_come_back_in_order`.
  - `docker_logs_exact_match_is_exact_for_hostile_values`: lines stored under deployment values `a"b`, `a\b`, `a|b`, `a OR b`, `*`, `a\nb` and `app/prod`, and under deploy ids `4` and `42`. The client's query for each value returns exactly its own lines; deploy `4` doesn't match `42`.
  - `docker_logs_paging_and_window_hold`.
  - `docker_logs_tenant_headers_reach_their_tenant`.
  - `docker_logs_journald_labels_become_the_default_fields`: the pipeline test. It pins `LANDFALL_DEPLOYMENT` and `LANDFALL_DEPLOY` as the field names, and fails naming the fields VictoriaLogs actually holds if they differ.

  Run, on Linux with Docker: `LANDFALL_TEST_REQUIRE_JOURNALD=1 cargo test -p landfall-server --all-features --locked -- --ignored docker_logs`. Expected: PASS. If the field names differ, change the defaults in Task 2's `Logs` and say so in the PR.
- [ ] **Step 2: Docs.** "Logs" in `docs/operations.md` covers:
  - the labels and what each holds;
  - Docker's `daemon.json` (`"log-driver": "journald", "log-opts": {"labels": "landfall.deployment,landfall.version,landfall.commit,landfall.deploy"}`), or the same per service in the host's `compose.yaml`, since the agent's override never sets a logging driver (spec 7.1);
  - `vector.toml` as the test runs it;
  - `[logs]` and its keys, and the bearer in the secrets file;
  - the network rule;
  - that an override restored from before plan 08 has no `landfall.deploy` label until the next deploy;
  - that the agent's `no_log_match` check works with journald, as `docker logs` reads it;
  - that logs may hold secrets the application prints, which is why reading them takes the `logs` grant and `view` doesn't.
- [ ] **Step 3: Gate; `uvx zizmor .`. Commit:** `test(logs): against a real VictoriaLogs and a real journald pipeline`.

### Task 7: `landfall logs`

**Files:** Modify `crates/cli/src/read.rs` (`ReadCommand::Logs(LogsArgs)`), `crates/cli/src/read/render.rs` (`logs`), `crates/cli/src/read/tests/{render,commands}.rs`, `crates/cli/src/cli/tests.rs` (`every_cli_call_is_in_the_openapi_document` gains `getDeployLogs`; `whoami_prints_the_logs_grant`), and `render.rs`'s `why` (a last line, `logs: landfall logs <id>`). `render.rs` is at 518 lines of code; if `logs` and its helpers would take it past about 750, put them in a new `read/render/logs.rs` in this PR.

**Interfaces:**
- `landfall logs <DEPLOY_ID> [--since <TIME>] [--until <TIME>] [--limit <N>] [--all]`, with the flattened `ApiArgs`. `TIME` is unix seconds or RFC 3339, parsed by `jiff` and sent as unix seconds. One page by default. `--all` follows `next_cursor` up to 20 pages, 10,000 lines or 8 MiB of answers, or until a cursor repeats, and then prints a line saying which.
- Human output: one line per log line, `<at> <message>`, with the message through `display::safe` (so a newline inside a message is escaped and every entry stays one line), and ` [cut]` after a cut one. `not_configured` prints "this controller has no [logs] settings, so it can't read logs", and `not_started` prints "this deploy was never claimed by its host, so it has no logs". Both exit 0. `--json` prints the body as received, and with `--all`, `{"items": [...]}` of every line, as `status` does.
- `502 logs_unavailable` and `503 busy` exit 2 by plan 07's statuses.
- A `403 forbidden` from `getDeployLogs` exits as any refusal does, and adds one line after the problem: "reading logs takes the `logs` grant on the deploy's deployment, which `view` doesn't give; `landfall whoami` lists yours". An agent holding `view` meets this first, so the hint saves it a guess.
- `landfall whoami` prints `logs` like any grant, through `wire_name`; no code changes there, only a test.

- [ ] **Step 1: Failing tests.**
  - In `read/tests/render.rs`: `log_lines_are_escaped_one_per_line` (messages holding `\x1b]0;x\x07`, `\r`, `\n`, `\u{9b}2J` and `\u{202e}`; each output line starts with a timestamp, and none of those bytes appears), `not_configured_and_not_started_say_why`, `cut_lines_are_marked`, `why_ends_with_the_logs_command`.
  - In `read/tests/commands.rs`: `logs_sends_the_window_as_unix_seconds`, `rfc3339_and_unix_times_are_both_taken`, `a_bad_time_is_refused_before_any_call`, `logs_all_stops_at_its_bounds_and_says_so`, `logs_unavailable_exits_2`, `forbidden_logs_name_the_logs_grant`.
  - In `cli/tests.rs`: `whoami_prints_the_logs_grant` (a `can` of `["view", "logs"]` prints `view, logs`).

  Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-cli`. Expected: PASS.
- [ ] **Step 3: Gate; `docker build .`; security review of PR C. Commit:** `feat(cli): landfall logs`. Open PR C.

## PR D: webhook events and the outbox

### Task 8: Events from audit rows, and their signature

**Files:** Create `crates/api/src/webhook.rs`, `crates/server/src/notify.rs`, `crates/server/src/notify/events.rs`, `crates/server/src/notify/sign.rs`, `crates/server/src/notify/tests.rs`, `crates/server/src/notify/tests/{events,sign,schema}.rs`. Modify `crates/api/src/lib.rs`, `crates/server/src/lib.rs` (`mod notify;`), `crates/server/src/api/openapi.rs` (the payload's schema, by the Rulings), `docs/api.md` (a section, "Webhook events"), `docs/api/openapi.json`, `docs/design/landfall.md` (8.3).

**Interfaces:**
- `landfall-api::webhook`:
  - `WebhookEvent { id: String, at: i64, severity: Severity, deployment: Option<DeploymentId>, host: Option<HostId>, summary: String, #[serde(flatten)] data: EventData }`.
  - `Severity { Info, Warning, Critical, #[serde(other)] Unknown }`.
  - `EventData`, `#[serde(tag = "type", content = "data", rename_all = "snake_case")]`, with these variants:
    - `ApprovalNeeded { request: i64, tag: ReleaseTag, requested_by: PrincipalId, approve_url: Option<String> }`;
    - `ApprovalClosed { request: i64, tag: ReleaseTag, how: ClosedHow }`, where `ClosedHow` is `Approved`, `Expired`, `Stale` or `Cancelled`;
    - `DeployFinished { deploy: i64, tag: ReleaseTag, outcome: Outcome, reason: Option<String>, rollback_reason: Option<String> }`;
    - `DeployRefused { deploy: i64, tag: ReleaseTag, reason: Option<String> }`;
    - `ReleaseRefused { tag: ReleaseTag, reason: String }`;
    - `ConfigDrift { drifted: bool }`;
    - `RunningDrift { drift: bool }`;
    - `ControllerAlert { alert: AlertKind, principal: PrincipalId, via: Option<Via>, count: u64, allowance: Option<Allowance> }`, where `AlertKind` is `SignInBarredKey` or `AccessThrottled`, `count` is the row's `attempts` or `dropped`, and `allowance` (`changes`, `reads` or `logs`) is set for `access_throttled` only. `Via` is the wire type `whoAmI` already uses. Nothing else of the row: no `sources`, no session or token id;
    - `Test {}`.

    `AlertKind` and the wire `Allowance` have an `Unknown`, as every growable wire enum does.

    `Outcome` is plan 07's.
- `notify/events.rs`:
  - `pub(crate) struct Row<'a> { pub seq: i64, pub ts: i64, pub kind: EventKind, pub deployment: Option<&'a DeploymentId>, pub host: Option<&'a HostId>, pub detail: &'a str }`.
  - `#[derive(Debug, Clone, Copy, PartialEq, Eq)] pub(crate) enum Topic { Deployment(EventName), Controller }`.
  - `#[must_use] pub(crate) fn from_row(row: &Row<'_>, config: &Config) -> Option<(Topic, WebhookEvent)>` has the exhaustive `match` of the Rulings' table, reads only the listed fields of `detail`, and gives `None` for a detail that doesn't parse.
  - `#[must_use] pub(crate) fn wanted(webhook: &Webhook, config: &Config, topic: Topic, row: &Row<'_>) -> bool` holds the scope rule. `Deployment(name)`: subscribed event, and the row's deployment listed, or, for a host-only row, a listed deployment on that host by the current configuration. `Controller`: `webhook.controller_alerts()`, and nothing else.
  - `pub(crate) const MAX_BODY: usize = 16 * 1024` and `pub(crate) fn body(event: &WebhookEvent) -> Vec<u8>`, which cuts `summary`, then `reason` and `rollback_reason`, on character boundaries until the JSON fits.
  - `summary` is one line made by the controller, such as `v1.2.3 rolled back on home-1: <reason>` or `v1.3.0 of app/prod waits for an approver`, with the quoted reason as stored.
- `notify/sign.rs`:
  - `#[must_use] pub(crate) fn signature(key: &WebhookKey, id: &str, timestamp: i64, body: &[u8]) -> String` gives `v1,<base64>`.
  - `pub(crate) fn headers(key: &WebhookKey, id: &str, timestamp: i64, body: &[u8]) -> [(HeaderName, HeaderValue); 3]`.

- [ ] **Step 1: Check `utoipa`'s `webhooks`.** Whether `utoipa` 6 writes OpenAPI 3.1's top-level `webhooks`. Record which way the schema goes, by the Rulings.
- [ ] **Step 2: Failing tests.**
  - In `notify/tests/events.rs`:
    - `every_notified_kind_maps_as_the_table_says`: one row per line of the table, each outcome of `deploy_finished` with its severity.
    - `other_kinds_give_nothing`: every other `EventKind`, by an exhaustive list in the test.
    - `rows_outside_the_webhooks_deployments_give_nothing`.
    - `host_rows_need_a_listed_deployment_on_that_host`: `config_drift` on `home-1` reaches a webhook for `app/prod` on `home-1`, and not one for `app/edge` on `home-2`.
    - `controller_alerts_reach_only_webhooks_that_opt_in`: `sign_in_barred_key` and `access_throttled` (each allowance) give `controller_alert` with the table's severities to a webhook with `controller_alerts = true`, whatever its deployments, and nothing to one without.
    - `other_controller_wide_rows_never_notify`: `token_created`, `token_revoked`, `passkey_invite_issued`, `passkey_registered`, `signed_in`, `sign_in_refused`, `registration_refused`, `access_refused` and `signed_out`, to a webhook with `controller_alerts = true` (Task 9 adds `webhook_gave_up` and `webhook_dropped` to this list).
    - `controller_alerts_carry_no_sources_or_credential_ids`: a `sign_in_barred_key` row whose `sources` hold `10.0.0.5` gives a payload without it.
    - `no_free_text_from_a_writer_that_can_name_another_deployment`: a `request_cancelled` whose reason names `app/secret`, and a `deploy_requested` from a promotion; neither payload contains `app/secret`.
    - `approval_needed_links_to_the_approval_page`, and to nothing without `[approval]`.
    - `a_detail_that_does_not_parse_gives_nothing`.
    - `body_fits_16_kib_with_a_huge_reason`.
    - `hostile_reason_stays_as_stored_and_json_escaped`.
  - In `notify/tests/sign.rs`:
    - `signature_matches_the_standard_webhooks_vector`: the published example key, id, timestamp and body give the published signature.
    - `docs_vector_matches`: the vector printed in `docs/operations.md` (read by `include_str!` between two marker lines) verifies.
    - `signature_covers_id_timestamp_and_body`: changing any one changes it.
  - In `notify/tests/schema.rs`: `every_event_matches_the_documented_schema`, which validates one payload of each type with `jsonschema` against the document.

  Run: `cargo nextest run -p landfall-server notify`. Expected: FAIL.
- [ ] **Step 3: Implement; regenerate the document.** Document the event types, fields, severities, scope rule (with `controller_alerts`), signature headers and the at-least-once, ordered promise in `docs/api.md`. In spec 8.3, after "They stay with `landfall-server audit show` on the controller.", add: "Two of them, a key that may not sign in being used (`sign_in_barred_key`) and a credential over its budget (`access_throttled`), also go to a webhook the reviewed file marks `controller_alerts = true`, by principal and count only: a webhook isn't a token, and the file says who receives them." Run: `cargo nextest run -p landfall-server -p landfall-api`. Expected: PASS.
- [ ] **Step 4: Gate. Commit:** `feat(notify): webhook events from the audit log, signed by Standard Webhooks`.

### Task 9: The outbox, filled from the audit log

**Files:** Create `crates/server/migrations/0009_webhooks.sql`, `crates/server/src/store/webhooks.rs`, `crates/server/src/store/tests/webhooks.rs`, `crates/server/src/notify/scan.rs`, `crates/server/src/notify/tests/scan.rs`. Modify `crates/server/src/store.rs` (`mod webhooks;`), `crates/server/src/store/tests.rs` (`mod webhooks;`), `crates/server/src/audit.rs` (`WebhookGaveUp = "webhook_gave_up"`, `WebhookDropped = "webhook_dropped"`, `WebhookTested = "webhook_tested"`), `crates/server/src/api/audit/detail.rs` (the three listed with the never-shown kinds), `crates/server/src/notify.rs`, `crates/server/src/notify/tests/events.rs` (the three new kinds in `other_controller_wide_rows_never_notify`).

**Interfaces:**
- `0009_webhooks.sql`:
  - `webhook_cursors (webhook TEXT PRIMARY KEY, seq INTEGER NOT NULL) STRICT`;
  - `webhook_outbox (id INTEGER PRIMARY KEY, webhook TEXT NOT NULL, seq INTEGER NOT NULL, body BLOB NOT NULL, queued_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0, next_try INTEGER NOT NULL, last_status INTEGER, UNIQUE (webhook, seq)) STRICT`;
  - an index on `webhook_outbox (webhook, seq)`.

  The body is stored as built, so a retry sends the same bytes under a fresh timestamp and signature.
- `store/webhooks.rs`:
  - `Store::webhook_cursors(&self) -> Result<HashMap<String, i64>, StoreError>`.
  - `Store::audit_after(&self, seq: i64, limit: u32) -> Result<Vec<AuditRow>, StoreError>`, on the primary key.
  - `Store::enqueue_webhooks(&self, batch: &Batch<'_>, now: i64) -> Result<Dropped, StoreError>`: in one transaction it inserts the events, sets each webhook's cursor, and drops the oldest past `MAX_PENDING` (1,000) per webhook. It writes one `webhook_dropped` audit row per webhook that dropped any, with the count, and returns the counts.
  - `Store::start_webhooks(&self, names: &[&WebhookName]) -> Result<(), StoreError>`: at start-up, a missing cursor starts at the current head, and the cursors and outbox of names not given are deleted.
  - `Store::next_webhook_event(&self, webhook, now) -> Result<Option<Pending>, StoreError>`, the oldest due.
  - `Store::webhook_delivered(&self, id)`.
  - `Store::webhook_retry(&self, id, next_try, status: Option<u16>)`.
  - `Store::webhook_gave_up(&self, id, why: GaveUp) -> Result<(), StoreError>`, which deletes the row and writes `webhook_gave_up` with `{webhook, seq, attempts, last_status, why}`.
- `notify/scan.rs`: `pub(crate) async fn scan_once(store: &Store, config: &Config, now: i64) -> Result<usize, StoreError>` reads at most 500 rows after the lowest cursor, builds each webhook's events by `from_row` and `wanted`, and enqueues them. `pub(crate) const SCAN_INTERVAL: Duration = Duration::from_secs(2)`.

- [ ] **Step 1: Failing tests.**
  - In `store/tests/webhooks.rs`:
    - `a_new_webhook_starts_at_the_head`.
    - `a_removed_webhook_is_forgotten`.
    - `enqueue_and_cursor_move_together`: a failure injected after the insert leaves both unchanged.
    - `past_1000_pending_the_oldest_are_dropped_and_audited_once`.
    - `next_event_is_the_oldest_due`.
    - `gave_up_deletes_and_audits_without_url_or_key`.
  - In `notify/tests/scan.rs`:
    - `scan_enqueues_only_wanted_events`.
    - `scan_resumes_after_a_restart_without_repeats`.
    - `scan_reads_at_most_500_rows_a_pass`.
    - `webhook_rows_never_enqueue_events`: a `webhook_gave_up` row gives nothing, to a webhook with `controller_alerts = true` too.
  - In `notify/tests/events.rs`, `other_controller_wide_rows_never_notify` gains the three new kinds.
    - `a_scan_failure_is_logged_and_the_next_pass_goes_on`.

  Run: `cargo nextest run -p landfall-server webhooks scan`. Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-server`. Expected: PASS, with every existing audit test unchanged.
- [ ] **Step 3: Gate; security review of PR D. Commit:** `feat(notify): an outbox per webhook, filled from the audit log`. Open PR D.

## PR E: delivery, end to end, and the docs

### Task 10: Delivery, retries, `webhook test`, and the notifier in `serve`

**Files:** Create `crates/server/src/notify/send.rs`, `crates/server/src/notify/backoff.rs`, `crates/server/src/notify/tests/{send,backoff}.rs`, `crates/server/src/cli/webhook.rs`, `crates/server/src/cli/tests/webhook.rs`. Modify `crates/server/src/notify.rs` (`pub(crate) async fn run(store, config, secrets, lookup, stop: watch::Receiver<bool>)`), `crates/server/src/cli.rs` (`serve_watching` spawns `notify::run` beside the watcher and the flusher and joins it on shutdown; `Command::Webhook`), `crates/server/src/cli/tests.rs` (`mod webhook;`).

**Interfaces:**
- `notify/backoff.rs`:
  - `pub(crate) const FIRST: Duration = Duration::from_secs(10)`, `CAP: Duration = Duration::from_secs(900)`, `GIVE_UP_AFTER: Duration = Duration::from_secs(86_400)`.
  - `#[must_use] pub(crate) fn delay(attempts: u32, retry_after: Option<Duration>, random: u64) -> Duration` gives `step = min(FIRST * 2^attempts, CAP)` and returns `step / 2 + random % (step / 2 + 1)`. A `Retry-After` within `CAP` replaces it if larger. The random value is injected, from `getrandom` in production.
- `notify/send.rs`:
  - `pub(crate) struct Sender { client: reqwest::Client, url: Url, key: WebhookKey, name: WebhookName }`, with a hand-written `Debug` showing only `name`. `Sender::new(webhook: &Webhook, secret: &WebhookSecret, lookup: Arc<dyn Lookup>) -> Result<Sender, OutboundError>` takes the policy from the fleet file's `Webhook` and the URL and key from the secrets file, and builds the client through `outbound::client` with connect 5 s and total 10 s.
  - `pub(crate) async fn send(&self, id: &str, body: &[u8], now: i64) -> Verdict`: `POST` with `Content-Type: application/json`, the three signature headers, and the body. It never reads the response body beyond 4 KiB, and drops it.
  - `pub(crate) enum Verdict { Delivered, Retry { status: Option<u16>, retry_after: Option<Duration> }, GiveUp { status: Option<u16>, why: GaveUp } }`, by the Rulings.
  - `pub(crate) async fn deliver_loop(store, sender, stop)` takes the oldest due event, sends it, records the verdict, and gives up an event whose `queued_at` is more than `GIVE_UP_AFTER` ago. It sleeps until the next due time or 200 ms, whichever is later, and stops when `stop` turns true. Each verdict other than `Delivered` is logged through `logger` as `webhook <name>: <status or error kind>, attempt <n>`, and nothing more.
- `notify::run` builds one `Sender` per `config.webhooks()` entry from `secrets.webhook(name)`, which `secrets::load` has already guaranteed exists, and runs `scan_once` every `SCAN_INTERVAL` and one `deliver_loop` per webhook, each as its own task. A store error in any of them is logged and retried at its next turn, and never ends `serve`.
- `cli/webhook.rs`: `landfall-server webhook test --config <FILE> --secrets <FILE> [--db <FILE>] <NAME>` parses the configuration, loads the secrets against it with `secrets::load` (so the same refusals as `serve`, the URL's policy check included, come first), builds the `test` event (`id` `landfall-test-<unix ns>`, deployment and host `null`), sends it once through `Sender`, prints `webhook <name>: <verdict>` and never the URL, writes `webhook_tested` with `{webhook, status}` if `--db` is given, and exits 0 on `Delivered` and 1 otherwise.

- [ ] **Step 1: Failing tests.**
  - In `notify/tests/backoff.rs`: `backoff_doubles_with_jitter_to_the_cap` (a table of attempts × random edges, every value in `[step/2, step]`), `retry_after_is_honoured_up_to_the_cap`.
  - In `notify/tests/send.rs`, with `wiremock` on loopback and `private: true`:
    - `a_delivery_is_signed_and_verifies`: the mock checks the headers against `sign::signature`.
    - `2xx_is_delivered`.
    - `5xx_408_and_429_are_retried`.
    - `other_4xx_is_given_up_at_once`.
    - `redirect_is_given_up_not_followed`.
    - `a_hanging_receiver_times_out_and_is_retried` (paused time).
    - `a_huge_answer_is_not_read` (a 1 GiB streamed body; the delivery completes and memory isn't held).
    - `events_go_out_in_order_one_at_a_time`.
    - `the_same_event_keeps_its_id_across_retries`.
    - `undelivered_after_24_hours_is_given_up_and_audited`.
    - `loopback_without_private_network_connects_nowhere`.
    - `no_log_line_or_audit_row_holds_the_key_or_url`: after a give-up, `logger::gate`'s captured stderr and every audit row are searched for the key's base64 and the URL's path.
    - `proxy_in_the_environment_is_not_used`.
    - `stop_ends_the_loop_with_the_event_kept`.
  - In `cli/tests/webhook.rs`: `webhook_test_sends_one_signed_test_event` (to the URL from the secrets file), `webhook_test_of_an_unknown_name_fails`, `webhook_test_exits_1_on_refusal`, `webhook_test_refuses_secrets_that_dont_match_the_config` (a missing entry, and an entry for no webhook), `webhook_test_prints_the_name_not_the_url` (stdout and stderr hold neither the URL's path nor its query, on success and on a refusal).

  Run: `cargo nextest run -p landfall-server notify webhook`. Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-server`. Expected: PASS, with `serve_upkeep` and `stuck_stderr` unchanged.
- [ ] **Step 3: Gate. Commit:** `feat(notify): deliver webhooks with retries, and send a test one`.

### Task 11: End to end, and the docs

**Files:** Create `crates/agent/tests/e2e/notify.rs`. Modify `crates/agent/tests/e2e/main.rs` (`mod notify;`), `crates/agent/tests/e2e/world.rs` (a webhook receiver on loopback, the secrets file holding its URL and key with mode 0600, `[[webhook]]` with `allow_private_network` and no URL), `docs/operations.md`, `docs/configuration.md`, `docs/design/landfall.md`, `docs/api.md`, `README.md`, `AGENTS.md`.

**Interfaces:**
- The e2e world gains `Receiver`, an axum server on `127.0.0.1:0` that records each request's headers and body and answers what the test sets (200, 500 or a hang).

- [ ] **Step 1: Write the tests** in `e2e/notify.rs`, over the real controller and agent:
  - `a_failed_deploy_notifies_with_a_signed_rollback_event`: a release whose check fails rolls back. The receiver gets `deploy_finished` with `rolled_back`, severity `warning`, the host's reason, and a signature that verifies.
  - `an_approval_request_notifies_with_the_approval_page`.
  - `a_dead_receiver_does_not_slow_a_deploy`: the receiver hangs on every request. A deploy completes within the same deadline as without a webhook, and the outbox holds its events.
  - `a_receiver_back_after_an_outage_gets_everything_in_order`.
  - `a_deployment_outside_the_webhook_is_never_mentioned`: a second deployment's deploy happens, and no request body contains its id.

  Run: `cargo nextest run -p landfall-agent --test e2e notify`. Expected: PASS.
- [ ] **Step 2: Docs.**
  - `docs/operations.md`, a new section, "Notifications", after "Logs". It covers:
    - `[[webhook]]` and each key (`name`, `events`, `deployments`, `controller_alerts`, `allow_private_network`), and that it has no URL;
    - the secrets file: its rules (owner-only, no link, 16 KiB), its schema keyed by webhook name (`url` and `key` for each, `[logs] bearer`), that every webhook needs an entry and an entry with no webhook is refused, `whsec_` keys made with `head -c 32 /dev/urandom | base64`, and that changing either file takes a controller restart;
    - why the URL is in the secrets file: a receiver's URL is often a capability (a Home Assistant webhook id), the fleet file goes to every host, and landfall never logs, audits or prints it;
    - the event table;
    - the scope rule;
    - the network rule, and why link-local is never reached;
    - `controller_alerts`: the two alerts, what they carry and leave out, and that they go only to a webhook that opts in;
    - how to verify a signature, with the test vector between the marker lines `docs_vector_matches` reads;
    - retries, give-ups and the audit rows they write;
    - Home Assistant: a webhook trigger, its URL in the secrets file, `allow_private_network = true` in the fleet file, and a notification from `trigger.json.summary`;
    - warden as a receiver;
    - `landfall-server webhook test`;
    - that a webhook new to the file starts from now.
  - `docs/configuration.md`: `[[webhook]]` gains `controller_alerts` if Task 2's text didn't already say it, and points to `docs/operations.md` for the secrets file.
  - `docs/design/landfall.md`:
    - Section 4: "Controller → webhook receivers (signed POST, outbound only)" beside the VictoriaLogs line.
    - Section 6.1: the controller's secrets (each webhook's URL and key, the VictoriaLogs bearer) are in a separate file only the controller's user can read, never in the fleet file, which every host receives.
    - Section 9: `landfall logs` built.
    - Section 10: what exists — the labels, journald, Vector, VictoriaLogs, `[logs]`, the window and the caps, "not configured".
    - Section 8.4: approval notifications built, through any webhook.
    - Section 12, three more rows:
      - a webhook used to reach inside the network: the address policy, set in the reviewed fleet file and checked on the URL's literal at start-up and on every resolved address, no redirects, no proxy; residual: an allowed private receiver can be made to receive at most what the events carry;
      - a forged notification: HMAC; residual: whoever holds the secrets file;
      - a receiver's capability URL leaked: it is only in the controller's secrets file, never in the fleet file, a log, an audit row or an answer; residual: whoever can read the controller's secrets file.

      (The row on logs read with a stolen token is Task 5's.)
  - `docs/api.md`: complete for both.
  - `README.md`: one line each for logs and notifications.
  - `AGENTS.md`: the server's `secrets`, `outbound`, `logs` and `notify` modules; the agent's labels; the `docker_logs` tests and what they need.
- [ ] **Step 3: Full gate; Linux (the agent's tests, as Tasks 1 and 11 touch them); `docker build .`; security review of PR E. Commit:** `test(notify): webhooks end to end; docs`. Open PR E.

---

## Self-review

- **Spec coverage.**
  - Section 2, logs per deployment tied to the exact version: Tasks 1, 4 to 7. The deploy id names the exact deploy, and its row names the version.
  - Section 2, notifications through a webhook: Tasks 8 to 11.
  - Section 2, the "silent failure" anti-goal: every refusal, failed check and rollback is notified as `deploy_finished`, `deploy_refused` or `release_refused` (Task 8). A webhook that can't deliver is itself recorded (Task 9).
  - Section 4, controller → VictoriaLogs read-only: Task 4 only reads.
  - Section 7.2, notify on success and failure, with a failed rollback critical: Task 8's table.
  - Sections 8.2 and 8.3: logs under the new `logs` grant, with spec 8.2 changed (Task 5); webhook scope by configured deployments, and of controller-wide rows only `sign_in_barred_key` and `access_throttled`, only to a webhook with `controller_alerts = true`, with spec 8.3 changed (Task 8).
  - Section 6.1: the fleet file holds no secret; webhook URLs and keys are in the controller's secrets file (Task 3), and the spec says so (Task 11).
  - Section 8.4, approval notifications through any webhook: `approval_needed` (Task 8), with warden documented as a receiver (Task 11).
  - Section 9, deploys with logs as a resource, and `landfall logs`: Tasks 5 and 7.
  - Section 10, every sentence: labels with the deploy id (Task 1), journald and Vector (Task 6), the URL in configuration (Task 2), by deploy id and time window (Task 5), "not configured" (Task 5).
  - Section 12: three rows (Task 11).
- **The brief's requirements.**
  - Signed payloads: Standard Webhooks HMAC-SHA256.
  - Timeouts, size caps and no redirects: `outbound`.
  - SSRF: `net::class`, the literal check (on the secrets file's URLs against the fleet file's policy) and the policy resolver.
  - Retries with backoff and jitter: Task 10.
  - Never blocking deploys: own tasks, own tables; Task 11 `a_dead_receiver_does_not_slow_a_deploy`.
  - No hidden deployments or hosts: Task 8.
  - Secrets never logged, the webhook URL counted as one: Tasks 2 (`TargetUrl`'s `Debug`), 3, 9 and 10.
  - Logs scoped per deploy and by their own grant: Task 5.
  - Injection impossible: Task 4, with the real proof in Task 6.
  - Size and time bounds, and the read budget: Tasks 4 and 5.
  - Escaped CLI output: Task 7.
  - The OpenAPI document and the grant test: Task 5's `CASES` row under `logs`, and `logs` in the test's `ROLES`.
- **Types.**
  - `NetPolicy`, `AddrClass`, `TargetUrl` (Task 2) are used by Task 3's resolver and clients.
  - `Logs`, `Webhook`, `WebhookName`, `EventName` (Task 2) are used by Tasks 4, 8, 9 and 10.
  - `Secrets`, `WebhookSecret`, `WebhookKey`, `Bearer`, `Lookup`, `outbound::client`, `read_capped` (Task 3) are used by Tasks 4 and 10.
  - `Permission::Logs`, `permitted_by_id` and `Allowance` (Task 5) are used by Task 8's `controller_alert` (`Allowance`, through the audit row's detail) and Task 7's hint.
  - `LogsClient`, `LogsQuery`, `LogLine`, `LogsError` (Task 4) are used by Task 5.
  - `LogsView` and `LogsState` (Task 5) are used by Task 7.
  - `WebhookEvent`, `EventData`, `Topic`, `Row`, `from_row`, `wanted`, `body`, `signature` (Task 8) are used by Tasks 9 and 10.
  - The store's webhook functions and the three new `EventKind`s (Task 9) are used by Task 10.
  - `DeployPlan::deploy_id` (Task 1) feeds the label that Tasks 5 and 6 query by.
- **File sizes.** All new code is in new files: `net.rs`, `config/{logs,webhook}.rs`, `secrets.rs`, `outbound.rs`, `logs/`, `api/logs.rs`, `notify/`, `store/webhooks.rs`, `cli/webhook.rs`. `cli.rs`, `store.rs`, `config/mod.rs` and `config/raw.rs` gain only module lines, fields, getters and a spawn; `raw.rs` grows by its two raw sections, about 50 lines, staying under 650. `config/mod.rs` gains one `Permission` variant (Task 5). `api/tests/grants.rs` (646) gains one `CASES` row and a path function, about 12 lines; `api/tests.rs` (552) a role and the seed. `cli/read/render.rs` (518) splits `logs` into `read/render/logs.rs` if it would pass about 750.
- **Proportion:** eleven tasks in five PRs, with interfaces and test names. The only code in the plan is the shape of the query and the backoff formula, which the tests alone don't fix.

## Owner's decisions (2026-11-08)

1. **Webhook URLs live in the controller's secrets file**, next to each webhook's `whsec_` key, keyed by webhook name. The fleet file's `[[webhook]]` keeps its name, what it receives and its network policy, and no URL. Rulings: "The controller's secrets live in one file outside the fleet configuration" and "The webhook's URL is a capability"; Tasks 2, 3, 10 and 11.
2. **Logs have their own grant, `logs`**, not `view`: logs can hold secrets an application printed, and an AI agent with `view` must not get them by that alone. A spec 8.2 change. Ruling: "Logs are read by deploy, under a grant of their own"; Tasks 5 and 7.
3. **Controller-wide security alerts may go by webhook**, opt-in per webhook with `controller_alerts = true`: `sign_in_barred_key` and `access_throttled`, and no other controller-wide row. A spec 8.3 change. Ruling: "A webhook hears only of its own deployments"; Tasks 2 and 8.
4. **CI may pull VictoriaLogs and Vector images**, pinned by digest and at least 7 days old, for the `docker_logs` tests. Task 6.
