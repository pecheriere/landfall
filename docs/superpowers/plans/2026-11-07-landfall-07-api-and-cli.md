# landfall plan 07: The typed API and the `landfall` CLI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** An agent with a token can see every deployment it may view, read a release's whole story (where it came from, which commits it holds, why it did or didn't deploy, its checks and outcome), ask why a deploy ended as it did, and request a deploy or a rollback. It does all of this through a versioned OpenAPI 3.1 API generated from the code, and through a `landfall` command over it. The operator still approves on the web, with a passkey.

**Architecture:** A new crate, `landfall-api`, holds the `/api/v1` wire types. The controller serialises them and the CLI reads them. The controller builds its `/api/v1` routes through `utoipa-axum`'s `OpenApiRouter`, so a route can't exist without its entry in the document. Query types derive `IntoParams` and handlers return a typed `ApiJson<T>`, so parameters and bodies are documented from the same types. The document is served at `/api/v1/openapi.json` and checked in as `docs/api/openapi.json`, and a test fails when the two differ. Each operation names its grant in its OpenAPI `security` requirement. One test drives every operation in the served document against that grant, and checks every success body against the operation's schema. Reads come from the store's existing tables, plus commit lists the watcher fetches from GitHub, within a GitHub budget that leaves origin verification its share. The CLI is a thin, typed HTTP client: no proxy, no redirects, bounded bodies and escaped output.

**Tech Stack:** Rust 1.99 (edition 2024). New: `utoipa` 6 and `utoipa-axum` 0.3, and `jsonschema` 0.60 as a dev-dependency of the server, with default features off (no remote `$ref` resolution). Task 1 confirms all three against `crate-age`, axum 0.8 and the licence list, and records the finding. `reqwest` moves from a dev-dependency to a dependency of `landfall-cli`; it is already in the tree through `landfall-origin`, with rustls only. Nothing else is new.

**Spec:** `docs/design/landfall.md` sections 1, 2, 8.1 to 8.4, 9, 10 and 12; `docs/operations.md` ("API tokens, requests and approvals", "Passkeys and signing in", "From nothing to a first deploy"); plan 05's rulings on principals, grants, budgets and problem answers, which stand.

## Rulings made while writing this plan

Each says what it costs if it is wrong. These are the rulings as amended by the review; the next section says what changed.

- **Five PRs, twelve tasks, in order.** PR A: the API crate and its document (Task 1), query parameters, cursors and the grant test (Task 2), and the read budget (Task 3). PR B: deployments (Task 4), commit ranges (Task 5), and releases with their story (Task 6). PR C: deploys and `why` (Task 7), then hosts and the audit log (Task 8). PR D: the CLI's client (Task 9) and its read commands (Task 10). PR E: asking from the CLI (Task 11), and an end-to-end run with the guide (Task 12). Each PR is reviewable alone and leaves `main` working. *If wrong:* a later PR reshapes a type an earlier one shipped. The checked-in document makes that visible in review.
- **Logs are the next plan, not this one.** Section 10 needs a label this code doesn't write. The agent labels containers `dev.landfall.deployment`, `dev.landfall.version` and `dev.landfall.commit` (`crates/agent/src/compose.rs`), and no label carries the deploy id the spec queries by. Logs also need the controller's first outbound client to a service the operator runs, a LogsQL query built safely from hostile values, and field names that depend on the operator's Docker, journald and Vector setup. Only a test against a real Vector and VictoriaLogs can pin those names. That is a plan of its own, with its own security review. It also decides between the spec's `landfall.*` label names and the code's `dev.landfall.*`. This plan leaves room: `DeployView` has no `logs` field yet. *If wrong:* agents wait one plan longer for logs, and read the host's journal meanwhile.
- **Issues #30 and #31 belong to plan 09.** Both change what hosts and the watcher do with approvals, not what an agent can see or ask. #30 re-enumerates runs for non-automatic releases and settles or cancels a queued approved deploy. #31 adds a host-side minimum version. They go together in an approvals-hardening plan after logs, with `landfall approve`'s locally computed intent hash (spec 6.3). That plan can rely on `IntentView`, which mirrors `DeployIntent` exactly. #60 belongs to `host install`, not this plan. *If wrong:* a queued approved row stays uncancellable for one more plan, as today, and hosts still refuse it.
- **The OpenAPI document is generated, served, checked in and tested.** Every wire type derives `utoipa`'s schema, and every handler has `#[utoipa::path]`. `OpenApiRouter::routes(routes!(handler))` registers the route and its document entry together, so neither can exist alone. Every query and path parameter type derives `IntoParams` and is named in `params(…)`. Every handler returns `ApiJson<T>` (`T: ToSchema + Serialize`), and the annotation's body is `T`. `landfall-server openapi` prints the document. `docs/api/openapi.json` holds that output. `openapi_document_is_checked_in` fails when the two differ, and its failure message gives the command to regenerate. `every_success_answer_matches_its_documented_schema` validates real bodies against the document. `info.version` is `"1"`, the API's version rather than the workspace's, so a release bump doesn't touch the file. Task 1 confirms the crates. If `utoipa-axum` doesn't fit, Task 1 stops and reports back: it doesn't build the fallback on its own. *If wrong:* the plan is amended once, before Task 2.
- **The grant is in the document, and the test reads it from there.** Each operation's `security` has two schemes: `token` (HTTP bearer) and `session` (the `__Host-landfall-session` cookie). Each scheme lists the roles that may call the operation, as OpenAPI 3.1 allows for schemes that aren't OAuth. Roles are the configuration's `view`, `request`, `approve` and `rollback`, plus `requester` for cancelling one's own request. A list means any one of them applies. An empty list means any authenticated principal, for a list filtered by what they may see. `approve` appears under `session` only, because a token never approves. Where the release decides which role applies, the operation also carries `x-landfall-grant`, mapping each role to the case it governs: `requestDeploy` has `{"request": "a tag above what runs, or the first deploy", "rollback": "a tag below what runs"}`. The test reads that mapping too. The public document has `security: [{}]`. *If wrong:* a tool that reads `security` as OAuth scopes shows odd scope names, and nothing breaks.
- **The grant test gives each case fresh state.** `every_operation_enforces_its_documented_grant` enumerates the served document, not a hand-written list. It builds a new `World` for each (operation, role) pair, so a state change made by one role can't turn the next into a `409` that passes "not 401, 403 or 404". `World::seed` runs `app/prod` at `v1.2.0` and records `v1.3.0` (higher) and `v1.1.0` (lower) as verified. `app/prod` has no open request and no promotion, so nothing but the grant decides `requestDeploy` there; the seeded open request, which `approveRequest` and `cancelRequest` act on, is on `app/staging`. A table `CASES` gives each (operationId, role) its request: `requestDeploy` sends `v1.3.0` for `request` and `v1.1.0` with `"rollback": true` for `rollback`. Each role is also tried against the other's case, which must answer `403`. An operation, role or `x-landfall-grant` key missing from `CASES` fails the test, naming it. *If wrong:* a new operation needs a row before its PR passes, which is the point.
- **Reading anything about a deployment takes `view`.** `GET /api/v1/approvals` keeps plan 05's rule (`approve` or `view`), so an approver sees what waits for them. As in plan 05, a principal with no grant at all on a deployment gets the same `404 not_found` as for one that doesn't exist, and one with some other grant gets `403 forbidden`. A deploy, release or request of a deployment the configuration no longer has is `404` to everyone. **A deployment the principal can't see is never named:** a promotion source or target, or a story reason about one, reads "a deployment you can't view". *If wrong:* an approver without `view` can't read the story of what they sign, and the operator adds `view` to their grant.
- **Hosts and the audit log are seen through deployments.** Section 8.2 grants per deployment and adds no host or audit grant. So a host is listed to a principal who may view a deployment on it, and the listing shows only those deployments. With another grant on a deployment there and no `view`, `getHost` is `403`, by plan 05's rule. An audit row with a deployment is seen with `view` on that deployment. **A row with a host and no deployment is seen only if its kind is on the allow-list, `host_enrolled` and `config_drift`, and only with `view` on a deployment of that host.** `enrol_code_issued`, `enrol_refused` (which names another host) and a `report_refused` with no deployment stay on the controller. **A row with neither (tokens, passkeys, sign-ins, throttling) never comes through the API, in plan 07 or with a token ever** (spec 8.3, amended in this commit). Grants are applied in SQL, so a page is never short of what the principal may see, and its cursor can't reach past it. Sequence numbers and ids are global, so gaps count activity the principal can't see. That is accepted and documented. *If wrong:* an operator who wants those rows reads them with `landfall-server audit show`.
- **The story's status is one pure function with a fixed precedence.** `story::status(&StoryInputs) -> StatusExplained` lives in its own file and is table-tested. The first match wins, in this order:
  1. `running`: the host runs this digest.
  2. `deploying`: a queued or claimed deploy of it.
  3. `awaiting_approval`: an open request for it.
  4. `refused`: decision `refused`, by verification or the rule.
  5. `held`: a hold on this tag or on the whole deployment.
  6. `superseded`: a higher version than this one is running. When the decision is `needs_approval` or `manual`, its `next` is `rollback`, naming `landfall rollback`.
  7. `failed`: its last finished deploy was `rolled_back`, `failed_no_previous` or `rollback_failed`. It isn't retried automatically (spec 7.2).
  8. `host_refused`.
  9. `deferred`: by decision or by last outcome.
  10. `promotion_pending`.
  11. `needs_request`: decision `needs_approval` or `manual`. The `next` action is `request`. A release lower than what runs is `superseded` before it gets here, so a rollback's `next` comes from status 6.
  12. `waiting`: `auto`, and nothing known in the way.

  Each status comes with its reasons in order and at most one `next` action. *If wrong:* one status reads oddly in a corner case. The table shows which, and the order is one list to change.
- **Commit ranges are between verified releases only, and keyed by commit.** A range has a head and a base. Both must be releases whose record is `settled()` (a commit and a digest, not `origin_refused`) under the current configuration's hash. The base is the highest lower version of the same deployment that is settled. With none, the story says this is the first. A refused or unsigned tag gets no range and is never a base. A range is stored by `(repo, base_commit, head_commit)`, not by tag, and the story looks it up from the releases' current commits. So a moved tag leaves its old list behind, two deployments of one repository share one fetch, and nothing goes stale. *If wrong:* a release whose base hasn't verified yet shows `not_yet` until it does.
- **Commits come from GitHub, exactly, within its limits, and say so.** An approver reads the list to decide, so a list that quietly misses commits is worse than none. The fetch is GitHub's compare, `GET /repos/{repo}/compare/{base}...{head}?per_page=100&page={n}`, which is exact: every commit reachable from the head and not from the base, merged branches included, oldest first, with `status` and `total_commits`. No GitHub endpoint is both exact and free of file patches, as far as this plan found: the commits listing is patch-free but ordered by date, and GraphQL's history needs a token every time. So compare it is, and each page's body is streamed under an 8 MiB cap. Page 1 gives the status and total. A status other than `ahead` or `identical` means the base isn't an ancestor of the head, which is `base_not_found`. With 100 commits or fewer, page 1 holds them all. With more, the newest 100 are the last two pages' tail, fetched as such, so at most 3 requests a range. The range keeps those 100 and the total, and the story says "the newest 100 of N", never presenting part as whole. **A page over the cap, or GitHub's own answer that the comparison is too large (a 422),** is `too_large`: no list, and a link to GitHub's compare page, `https://github.com/{repo}/compare/{base}...{head}`, built from the validated repo name and the two shas. Each commit keeps its sha, its first message line (200 characters, quoted) and the author login GitHub attributes by email, which is not verified.

  It runs only after the tick's verifications, and only within a GitHub budget. With the controller's `GITHUB_TOKEN`: at most 12 requests a tick, and only while `x-ratelimit-remaining` stays at 1,000 or above. Without a token: at most 3 requests a tick, enough for one range, and only while it stays at 30 or above. A range is fetched whole within one tick or left for the next, never stored half-done. It stops at the first 403 or 429, rate-limit headers or not. Patches cost bandwidth, which these caps bound. It runs only for releases first recorded after migration `0006` ran, by a new `releases.first_seen_at` that is set on insert and never changed (`seen_at` changes on every verification, a configuration change included): no backfill of old ones. A failure leaves the range absent, to be tried again after an hour, and never holds or refuses anything. The API reports `"source": "github"` and `"verified": false`, a constant in the schema; only the release commit is verified. A range that couldn't be fetched shows as unknown (`not_yet`, `unavailable`, `not_recorded`), never as an empty list. *If wrong:* a busy fleet without a token fills commit lists slowly, and each one says it's still waiting.
- **Reads have a budget of their own.** Plan 05 charged only state changes. A read API this size would let a stolen token keep SQLite busy. So each credential gets a read bucket of 300 at once, refilling at 10 a second; as for writes, each session has its own and a principal's tokens share one. A CLI command makes at most three calls, and a page polls every few seconds. Over the budget, a read gets `429 rate_limited` with `Retry-After` and writes nothing. The count goes in `access_throttled` with `"reads": true`, by the existing flush. **A read with a session is refused before it is charged** if `Sec-Fetch-Site` is present and is neither `same-origin` nor `none`. `SameSite=Strict` still sends the cookie on a same-site `GET`, so without this a page on a sibling subdomain could drain an operator's bucket. Every list that can grow is paginated (`limit` 1 to 100, default 50, `cursor` opaque), and every query has an index. `listHosts` and `listApprovals` aren't paginated: the configuration bounds them, with one open request per deployment. *If wrong:* an agent sweeping a large fleet meets a 429 and waits a few seconds.
- **The CLI keeps the token to itself.** The token never goes in argv. It comes from `LANDFALL_TOKEN`, or from a file named by `--token-file`, `LANDFALL_TOKEN_FILE` or `token_file` in the CLI's config. The file must be a regular file, not a link, not readable by group or others on Unix, and at most 256 bytes. With no token configured, the CLI sends no `Authorization` header, which is how a warden proxy injects one (spec 8.4). The API flags belong to the API commands, not to `landfall` as a whole, since `host install` already has its own `--controller` and `--allow-insecure-controller`: `landfall status --json`, not `landfall --json status`. The controller URL goes through `landfall_core::controller_url::ControllerUrl::parse`, as the agent's does: `https://`, or, with `--allow-insecure-controller`, `http://` to a loopback address, `localhost` or a tailnet (`*.ts.net`) name. A refusal gets the CLI's own message, about a bearer token in clear. The client calls `.no_proxy()`, as the agent's does, so no environment variable routes the token through a proxy. It sets `.https_only(true)` for an `https://` controller, and refuses redirects (`redirect::Policy::none()`), since a redirect could carry the token elsewhere. *If wrong:* someone who reaches the controller through a proxy uses a tunnel or the warden route; a `--proxy` setting can come later.
- **What the CLI prints is escaped.** Human output passes every server string through `display::safe`, and so does every error `main` prints, problem titles included. `safe` escapes C0 and C1 controls, DEL, and the bidi and line controls (U+061C, U+200E, U+200F, U+2028, U+2029, U+202A to U+202E and U+2066 to U+2069) as `\u{…}`. `--json` prints the body as it was received, as a `serde_json::Value`, not re-serialised from the typed values. DEL, C1 and the same controls are escaped as `\uXXXX`, which `serde_json` alone doesn't do. *If wrong:* a terminal shows an escape sequence as text.
- **Compatibility runs one way: an older CLI against a newer controller.** Within `/api/v1` the controller only adds fields and enum values. The CLI's types ignore unknown fields, and each enum that can grow has `#[serde(other)] Unknown`, shown as `unknown` and left out of the schema. The controller still refuses unknown fields in what it's sent. So the CLI never sends a field the older controller lacks unless it's meant: `rollback` is skipped when false. *If wrong:* a newer CLI's `landfall rollback` gets `bad_request` from an older controller. The message says to upgrade the controller.
- **Approving stays on the page, and the CLI says where.** A request's answer gains `approve_url`: the configuration's `[approval] origin` followed by `/approvals`, or `null` without `[approval]`. `landfall request` and `landfall approvals` print it, with one line saying an approver signs it there with a passkey and agents can't approve. `landfall approve` is plan 09, and its assertion is still made on the page. *If wrong:* nothing; the page is unchanged.
- **`landfall rollback` says what it means.** The request body gains an optional `"rollback": true`. With it, a tag that isn't lower than what runs is refused with `409 not_a_rollback`, and so is any tag when nothing runs or the running tag doesn't parse. So an agent can't ask for an upgrade by mistake under the `rollback` grant's name. The check runs before `RequestOpen` and before `cancel_open_request`, so the refusal changes nothing else. Without the flag, plan 05's behaviour stands. *If wrong:* one more problem code.
- **Exit statuses stay 0, 1, 2.** 0: done. 1: the controller refused (a problem answer other than `401` and `429`). 2: the CLI couldn't ask, for a configuration, credentials (`401`), network, rate-limit or server error. `--help` says so, as `verify`'s does. *If wrong:* a script retries a refusal; the code in the problem body tells it not to.

## Rulings on the plan review

The review (8 Important, 17 Minor) approved the plan with changes:

| Finding | Change | Where it is held |
|---|---|---|
| I1 Grant test couldn't honour `requestDeploy`; `cancelRequest` listed `approve` for tokens; a `409` passed for a role | Roles by tag direction in `x-landfall-grant`; two seeded tags; a fresh `World` per case; `approve` session-only | Task 2 `every_operation_enforces_its_documented_grant`, `each_role_is_refused_the_case_it_does_not_govern` |
| I2 Ranges from refused releases; stale after a moved tag | Settled releases only; keyed by `(repo, base_commit, head_commit)` | Task 5 `a_refused_release_is_neither_compared_nor_a_base`, `a_moved_tag_is_compared_again` |
| I3 Rate limit, backfill, `too_large`, oldest 100 | Compare kept for exactness (owner's ruling), streamed under a cap, newest 100 by fetching the last pages, `too_large` with GitHub's compare link and never a partial list as whole; budget after verification, no backfill, unknown shown as unknown | Task 5 `compares_stop_when_the_rate_limit_is_low`, `verification_runs_before_commits`, `releases_seen_before_the_migration_are_never_fetched`, `the_newest_100_come_from_the_last_pages`, `over_the_cap_is_too_large_with_a_link` |
| I4 Unfiltered audit page a scan | One branch per scope on its index, `UNION ALL`, outer limit | Task 8 `audit_page_uses_an_index` (unfiltered, `kind`, deployment) |
| I5 Token through an environment proxy | `.no_proxy()`, `.https_only` | Task 9 `http_proxy_in_the_environment_is_not_used` |
| I6 Bodies and parameters could drift | `IntoParams`, `ApiJson<T>`, schema validation of real answers, deterministic output, `Unknown` out of the schema | Task 1 `document_is_generated_the_same_twice`; Task 2 `every_success_answer_matches_its_documented_schema` |
| I7 Task 1 too large; budget in a read task | Tasks 1, 2 and 3 in PR A | Pre-flight table |
| I8 Host-only rows too wide | Allow-list `host_enrolled`, `config_drift` | Task 8 `host_rows_of_enrolment_are_not_listed` |

**Minors applied:** 1 (unseen deployments not named: Task 4 `promotion_to_an_unseen_deployment_is_not_named`), 2 (documented in `docs/api.md` and the section 12 row), 3 (`MeView.grants` through `can`: Task 4 `a_tokens_grants_never_list_approve`), 4 (`not_a_rollback` placement and edges: Task 11), 5 (`skip_serializing_if`; one-way compatibility), 6 (paging capped at 20 pages and stopped on a repeated cursor: Task 10), 7 (error path, `\r`, extra controls, DEL: Task 9), 8 (`--json` passes the body through: Task 10), 9 (the CLI's own URL messages: Task 9), 10 (author unverified; a `base_not_found` reason line: Tasks 6 and 10), 11 (`Sec-Fetch-Site`: Task 3), 12 (spec wording: section 8.3 amended in this commit, Task 12's edits worded for plan 09, labels left to plan 08), 13 (holds bounded at the newest 50 with a count; `listHosts` and `listApprovals` bounded by the configuration), 14 (`getHost` 403: Task 8), 15 (file lists; `reqwest` moves from dev-dependency; the tick's call lives in `watcher/commits.rs`), 16 (`source` and a constant `verified`), 17 (the public route in Global Constraints, `Cache-Control` tested). **Left:** none.

## Rulings on the pre-flight scan

A read-only scan against the code found these, and each is now in the task it affects:

- **The grant seed:** the open request moves to `app/staging`, because `asking` refuses `request_open` before it checks grants. The "no grant" principal gets a grant on `app/other` only, because a principal the configuration doesn't name gets 401. A `Case`'s body is built from the `World`, because an approval needs a fresh assertion (Task 2). *If wrong:* the grant test fails on 409 or 401 instead of testing grants.
- **Each query type lands with its first user**, since `dead_code` under `-D warnings` fails the gate. `Limit`, `Cursor` and `CursorList` go to Task 4, `TagPath` to Task 6 and `HostPath` to Task 8. Task 2 puts `ApiQuery<NoQuery>` on every operation without parameters. *If wrong:* Task 2 fails clippy.
- **One id rule:** `request_number` moves to `api/query.rs`, and `IdPath` and the request handlers share it (Task 2). *If wrong:* two rules drift.
- **Promotion is seeded on `app/canary` → `app/beta`,** never on `app/prod` (Task 4). *If wrong:* `requestDeploy` answers `promotion_pending` in the grant test.
- **Reuse over copies:** holds come back as the store's `Hold`, which gains `reason()`. Open requests come from `Store::open_requests`. `ApiJson` replaces `requests::no_store` (Tasks 1, 4 and 6). *If wrong:* two shapes of one row.
- **Reads over budget get their own title,** through `HumanProblem::ReadsOverBudget` with the code `rate_limited`, and `budget.rs`'s module doc is rewritten (Task 3). *If wrong:* a read is refused for "too many state changes".
- **`deploys (deployment, tag, id)`** joins `0005` for `deploys_of_release` (Task 4). *If wrong:* each story scans its deployment's deploys.
- **Six `ReleaseSource` impls,** `tests/stuck_stderr.rs` included. The tick's one call goes in `watcher/ticking.rs`. `ReleaseSource::has_github_token` and `ReleaseError::Compare` are new, and a bare 403 or 429 stops the tick (Task 5). *If wrong:* Task 5 doesn't compile, or a plain 403 doesn't stop it.
- **`releases.first_seen_at`** in `0006` decides what is fetched, because `seen_at` moves on every verification (Task 5). *If wrong:* the first configuration change backfills every old release, within the budget.
- **`hosts_show_only_viewable_deployments` puts `app/edge` on `home-2`,** since `app/other` is on `home-1` and a deployment has one host (Task 8). *If wrong:* the test's configuration doesn't parse.
- **The merge test checks parsing,** against a recorded compare body in `fetch/tests/commits.rs`, not against the fake's own output (Task 5). *If wrong:* a test that asserts its input.
- **`superseded` carries the rollback `next`,** and `needs_request` always says `request` (Task 6). *If wrong:* an agent is told to `request` an older tag.
- **The audit query has at most 400 branches,** under SQLite's 500-term limit on a compound `SELECT`, each branch a subquery with its own `ORDER BY` and `LIMIT` (Task 8). *If wrong:* a large scope fails as a 500 instead of a 400.
- **The API flags are flattened onto each API command** (`ApiArgs`), not global (Task 9). *If wrong:* clap panics on the duplicate `--controller`.
- **`cli::run_with(cli, env, out, err)`** is the library entry, and `run` calls it. Error escaping is tested through it (Task 9), and the end-to-end tests use it (Task 12). *If wrong:* tests change the process environment and can't capture output.
- **`Api` is used generically** (`<A: Api>`, methods returning `impl Future + Send`), not as `&dyn Api`, which async methods don't allow (Tasks 10 and 11). *If wrong:* Task 10 doesn't compile.
- **Task 12 signs in for real:** an invite from `Store::issue_passkey_invite`, then registration and sign-in over HTTP with the `SoftwareAuthenticator`, with no new server feature. *If wrong:* the test can't get a session, because `begin_session_for_test` is crate-private.
- **The file lists and the pre-flight table** now name every file a task touches (`lib.rs`, `cli/tests.rs`, `requests/tests.rs`, `api/tests/document.rs`, `audit.rs`, `store/releases.rs`, `origin/src/release.rs`). *If wrong:* a task touches a file its reviewer doesn't expect.

## Global Constraints

- `rust-toolchain.toml` 1.99; workspace lints apply. No `#[allow]` or `#[expect]` without `reason = "..."`. `unsafe_code` is forbidden. No `unwrap` or `expect` outside tests. Public error enums are `#[non_exhaustive]`.
- Source files stay under about 800 lines of code. Tests go in their own files, as `foo/tests.rs` and `foo/tests/<scenario>.rs`, naming what they import. `crates/server/src/requests.rs`, `store.rs` and `watcher.rs` (681 lines of code) take nothing beyond what a task names: module lines and a trait method (the tick's one call goes in `watcher/ticking.rs`). New reads go in new files.
- Every `/api/v1` route takes a `Principal` before anything else. The one exception is `GET /api/v1/openapi.json`: it is public, has no budget and serves static bytes that say nothing about this controller. Query strings are capped at 2 KiB and parsed with unknown parameters refused. Every answer, the document included, is JSON with `Cache-Control: no-store` and no CORS header. Every refusal is `application/problem+json` with a stable `code` listed in the document's `Problem` schema.
- No secret in any answer, log line or audit row: tokens and session tokens appear nowhere, not even hashed. A request's nonce and challenge are already shown to whoever may see the request, and that stands.
- Hostile text (commit messages, author logins, check names, reasons from hosts, anything from GitHub) is stored through `landfall_core::text` (`quoted`, `shown`), as today, and escaped again by the CLI before it reaches a terminal.
- Outbound requests to GitHub stay within the budget in the Rulings, and verification always goes first.
- Nothing personal: example names only (`app/prod`, `app/staging`, `home-1`, `operator`, `ci`, `https://landfall.example.com`, `example/app`).
- Security review (the `security-review` skill or an equivalent) before merging every PR of this plan, since each one touches authentication, grants or outbound HTTP. Each PR says what was and wasn't verified, separating CI from local.
- Gate before each commit: `cargo fmt --check`, `cargo clippy --workspace --all-targets --all-features --locked -- -D warnings`, `cargo test --workspace --all-features --locked`, `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked`, `cargo deny --all-features --locked check`. Iterate with `cargo nextest run -p <crate>`. Never set `CARGO_TARGET_DIR` or any other `CARGO_*` variable. Conventional commits, no attribution trailers.

**Every `/api/v1` operation and its grant,** as the document's `security` lists it (`T` token, `S` session). `[]` means any authenticated principal, with the answer filtered to what they may view; each list's own task tests the filtering.

| Operation | Path | Roles | Task |
|---|---|---|---|
| `getOpenApi` | `GET /api/v1/openapi.json` | public | 1 |
| `listApprovals` | `GET /api/v1/approvals` | T, S: `[]`, filtered by `approve` or `view` | 1 (existing) |
| `requestDeploy` | `POST /api/v1/deployments/{name}/{stage}/requests` | T, S: `request` (tag above, or first deploy), `rollback` (tag below) | 1 (existing) |
| `approveRequest` | `POST /api/v1/approvals/{id}` | S: `approve` | 1 (existing) |
| `cancelRequest` | `POST /api/v1/approvals/{id}/cancel` | T: `requester`, `rollback`; S: `requester`, `approve`, `rollback` | 1 (existing) |
| `whoAmI` | `GET /api/v1/me` | T, S: `[]` | 4 |
| `listDeployments` | `GET /api/v1/deployments` | T, S: `[]`, filtered by `view` | 4 |
| `getDeployment` | `GET /api/v1/deployments/{name}/{stage}` | T, S: `view` | 4 |
| `listReleases` | `GET /api/v1/deployments/{name}/{stage}/releases` | T, S: `view` | 6 |
| `getRelease` | `GET /api/v1/deployments/{name}/{stage}/releases/{tag}` | T, S: `view` | 6 |
| `listDeploys` | `GET /api/v1/deployments/{name}/{stage}/deploys` | T, S: `view` | 7 |
| `getDeploy` | `GET /api/v1/deploys/{id}` | T, S: `view` | 7 |
| `whyDeploy` | `GET /api/v1/deploys/{id}/why` | T, S: `view` | 7 |
| `listHosts` | `GET /api/v1/hosts` | T, S: `[]`, filtered by `view` | 8 |
| `getHost` | `GET /api/v1/hosts/{host}` | T, S: `view` | 8 |
| `listAudit` | `GET /api/v1/audit` | T, S: `[]`, filtered by `view` | 8 |

## Review Focus

1. **Hostile text reaching an operator's terminal.** A commit message, author, check name, host reason or problem title holding an ANSI escape, a C1 CSI, a carriage return or a bidi override must appear escaped when `landfall` prints it, in either output mode and on the error path → Task 10 `hostile_text_is_escaped_in_human_output`; Task 9 `json_output_escapes_c1_del_and_bidi`, `errors_are_escaped`.
2. **A side route telling a principal about a deployment they may not view.** A host's list, an audit row, a deploy's `why` by id, a promotion, a crafted cursor or a count must show nothing of it. A page must never come back short because rows were filtered after the limit → Task 8 `hosts_show_only_viewable_deployments`, `audit_rows_follow_view_in_sql`, `a_crafted_cursor_reaches_nothing_unseen`, `host_rows_of_enrolment_are_not_listed`; Task 7 `why_of_an_unseen_deploy_is_not_found`; Task 4 `promotion_to_an_unseen_deployment_is_not_named`.
3. **A deployment taken out of the configuration** while its deploys, releases, requests and audit rows stay in the database must be `404` on every route and absent from every list → Task 7 `deploy_of_a_deployment_no_longer_configured_is_not_found`; Task 8 `audit_of_a_removed_deployment_is_not_listed`.
4. **The CLI leaking its token** in argv, through a redirect to another host, through an environment proxy, over `http://` to a host outside the rule, in an error or `Debug` output, or from a token file others can read → Task 9 `redirect_is_not_followed_and_the_token_stays`, `http_proxy_in_the_environment_is_not_used`, `token_is_never_in_output_or_errors`, `insecure_url_is_refused`, `readable_token_file_is_refused`.
5. **A large fleet and a long history:** millions of audit rows, 5,000 tags on a deployment, `limit=100000`, a cursor from another list, an untokened controller with many new releases. Queries stay on an index and bounded, and GitHub calls never crowd out verification → Task 4 `limit_outside_1_to_100_is_refused`; Task 2 `cursor_of_another_list_is_refused`; Task 8 `audit_page_uses_an_index`; Task 6 `five_thousand_releases_page_in_version_order`; Task 5 `compares_stop_when_the_rate_limit_is_low`.

## Pre-flight: tasks sharing files or interfaces

Run the tasks in order. These are the places where two tasks meet, so a parallel run would conflict, or a later task depends on a name an earlier one fixed:

| Shared | Tasks | How |
|---|---|---|
| `crates/api/src/lib.rs` and its modules | 1, 4, 6, 7, 8, 11 | Task 1 fixes `Page<T>`, `Problem`, `ProblemCode`, `IntentView`, `RequestView`; the others each add their module |
| `Cargo.toml`, `crates/server/Cargo.toml` | 1, 2 | Task 1 adds the crate and `utoipa`, `utoipa-axum`, `jsonschema`; Task 2 adds `serde_urlencoded` as a direct dependency (already in the tree through `reqwest`) |
| `crates/server/src/api.rs` (`router`, `ApiDoc`, `ApiJson`) | 1, 2, 4, 6, 7, 8 | Task 1 owns the assembly and `ApiJson`, Task 2 adds `ApiQuery`, the rest add `routes!(…)` lines |
| `crates/server/src/api/query.rs` | 2, 4, 6, 8 | Task 2 creates it (`ApiQuery`, `NoQuery`, `DeploymentPath`, `IdPath`, `request_number`); Task 4 adds `Limit`, `Cursor`, `CursorList`; Task 6 `TagPath`; Task 8 `HostPath` |
| `crates/server/src/api/tests.rs` | 1, 2, 4, 6, 7, 8 | Task 1 creates it with `mod document;` and a small app helper; Task 2 adds `World` and `World::seed`; later tasks add seeds |
| `crates/server/src/api/tests/document.rs` | 1, 11 | Task 11 adds `approve_url` to `approvals_json_is_unchanged` |
| `crates/server/src/api/tests/grants.rs` (`CASES`), `api/tests/query.rs` | 2, 4, 6, 7, 8, 11 | Task 2 writes both; Task 4 adds the cursor tests; each later task adds its `CASES` rows |
| `crates/server/src/api/deployments.rs` | 4, 6 | Task 4 creates it; Task 6 fills `latest` |
| `crates/server/src/api/visible.rs` | 4, 6, 7, 8 | Task 4 creates `shown_deployment` and moves `visibility` there; the others call them |
| `docs/api/openapi.json` | 1, 2, 4, 6, 7, 8, 11 | Regenerated by each task, never edited by hand |
| `docs/api.md` | 1, 2, 3, 4, 5, 6, 7, 8, 11 | Each task documents its part |
| `crates/server/src/auth/budget.rs`, `auth/principal.rs`, `agent_api.rs` (`Limits`) | 3 | Nothing later touches them |
| `crates/server/src/auth/problem.rs`, `crates/api/src/problem.rs` | 1, 3, 11 | Task 3 adds `ReadsOverBudget` (`rate_limited`); Task 11 adds `NotARollback` to both |
| `crates/server/migrations/` | 4 (`0005`), 5 (`0006`), 8 (`0007`) | Three files, in that order |
| `crates/server/src/store.rs` | 4, 5, 6 | One `mod` line each: `views`, `commits`, `history` |
| `crates/server/src/store/releases.rs` | 4, 5 | Task 4 adds `Hold::reason()`; Task 5 sets `first_seen_at` in `record_release` |
| `ReleaseSource` trait and its six impls | 5 | `watcher.rs`, `watcher/source.rs`, `watcher/tests.rs`, `server/tests/serve_upkeep.rs`, `server/tests/browser/main.rs`, `server/tests/stuck_stderr.rs`, `agent/tests/e2e/world.rs`; the call to `after_tick` in `watcher/ticking.rs` |
| `store/views.rs` | 4, 8 | Task 4 creates it, Task 8 adds hosts and the audit page |
| `store/history.rs` | 6, 7 | Task 6 creates it, Task 7 adds deploys and steps |
| `crates/server/src/requests.rs`, `requests/*.rs` | 1 (annotations, router type, `ApiJson`), 2 (`params(…)`, `ApiQuery<NoQuery>`, `request_number` moved), 11 (`rollback`, `approve_url`, `mod rollback_flag;`) | |
| `crates/cli/Cargo.toml` | 9, 12 | Task 9 the dependencies; Task 12 the dev-dependencies |
| `crates/cli/src/lib.rs` | 9, 10, 11 | `settings`, `api_client`, `display`; `read`; `ask` |
| `crates/cli/src/cli.rs` (`Command`, `CliError`, `run_with`) | 9, 10, 11 | Task 9 adds `ApiArgs`, `ApiError`, `run_with` and escaping on the error path; Tasks 10 and 11 add commands |
| `crates/cli/src/cli/tests.rs` | 9, 10, 11 | Task 9 `errors_are_escaped`; Task 10 `every_cli_call_is_in_the_openapi_document`; Task 11 adds its three rows |
| `docs/operations.md`, `docs/design/landfall.md`, `README.md` | 12 | Section 8.3 was already amended with this plan |
| `AGENTS.md` | 1 (crate map), 9 (CLI modules), 12 | |

## What the next plans hold

- **Plan 08, logs (section 10).** It picks the label names (the spec's `landfall.*` or the code's `dev.landfall.*`) and adds the deploy id. It adds `[logs]` to the configuration (the VictoriaLogs URL, the field names and a query timeout), `GET /api/v1/deploys/{id}/logs` by deploy id and window, bounded and paginated and saying when logs aren't configured, and `landfall logs`. It tests against a real Vector and VictoriaLogs in Docker.
- **Plan 09, approvals hardening:** #30, #31, and `landfall approve` computing the intent's hash locally (spec 6.3).
- **Then the web UI (section 11).** The pages over this API, the pipeline view per repo and per host, the version story, "needs you", the design language and Bobbin. **If its audit page needs controller-wide rows,** they come through a controller-level grant enforced like `approve`: a passkey session only, never a token, whatever the file says, with the session-only rule in the document's `security` so the grant test covers it (spec 8.3). Triggering a release check, staging on its own address in the UI, and more hosts come with it or after it.

---

## PR A: the API crate, the document, the grant test and the read budget

### Task 1: `landfall-api` and the generated document, behaviour unchanged

**Files:** Create `crates/api/` (`Cargo.toml`, `src/lib.rs`, `src/page.rs`, `src/problem.rs`, `src/requests.rs`), `crates/server/src/api.rs`, `crates/server/src/api/openapi.rs`, `crates/server/src/api/tests.rs` (`mod document;` and a small app helper that seeds through `Store`'s public functions), `crates/server/src/api/tests/document.rs`, `docs/api/openapi.json`, `docs/api.md`. Modify `Cargo.toml` (members, `landfall-api`, `utoipa`, `utoipa-axum`, `jsonschema`), `crates/server/Cargo.toml`, `crates/server/src/lib.rs` (`router` merges `api::router` in place of `requests::router`), `crates/server/src/requests.rs` (the router becomes an `OpenApiRouter<ApiState>`, and `RequestView` moves to `landfall-api`), `crates/server/src/requests/{asking,approving,cancelling}.rs` (annotations and `ApiJson` only; `ApiJson` replaces `requests::no_store`, so one helper sets `Cache-Control`), `crates/server/src/auth/problem.rs` and `crates/server/src/agent_api/problem.rs` (`code()` returns a `ProblemCode`), `crates/server/src/cli.rs` (`openapi`), `Dockerfile` (a `COPY crates/api/Cargo.toml` line, and `api` in the stub step), `deny.toml` (licences only, if needed), `AGENTS.md` (crate map).

**Interfaces:**
- `landfall-api` has no I/O and depends on `landfall-core`, `serde` and `serde_json`. Its `openapi` feature adds `utoipa`, with `#[cfg_attr(feature = "openapi", derive(utoipa::ToSchema))]` on every type. Core ids appear as themselves, with `#[cfg_attr(feature = "openapi", schema(value_type = String, example = "app/prod"))]`. Only `landfall-server` enables `openapi`.
- `pub struct Page<T> { pub items: Vec<T>, pub next_cursor: Option<String> }`.
- `pub struct Problem { pub code: ProblemCode, pub title: String, pub status: u16 }`. `pub enum ProblemCode` has every stable code of `ApiProblem` and `HumanProblem` as a `snake_case` variant, plus `#[serde(other)] Unknown`, which is left out of the schema. `HumanProblem::code()` and `ApiProblem`'s return a `ProblemCode`; the bytes on the wire don't change.
- `pub struct IntentView` mirrors `DeployIntent`'s JSON exactly (`deployment`, `tag`, `commit`, `digest`, `expected_running`, `nonce` as 64 hex digits), with `impl From<&DeployIntent>`. `pub struct RequestView { id, host, intent: IntentView, challenge, state, requested_by, created_at, expires_at, can_approve, can_cancel }`. `pub struct ApprovalsView { approvals: Vec<RequestView> }`. `pub struct NewRequest { tag: ReleaseTag }`, with `deny_unknown_fields`; Task 11 adds `rollback`.
- `crates/server/src/api.rs`: `pub(crate) struct ApiJson<T>(pub T)`, an `IntoResponse` with `application/json` and `Cache-Control: no-store`. `pub(crate) fn router(state: ApiState) -> Router` builds one `OpenApiRouter<ApiState>` from `requests::routes()` and this module's routes, and splits it into the axum router and the `utoipa::openapi::OpenApi`. It adds `GET /api/v1/openapi.json`, serving the document's bytes, and keeps plan 05's `/api/v1` fallbacks and its `deadline` and `note_client_source` layers. `pub fn openapi_document() -> String` gives pretty JSON with a final newline; the route, the CLI subcommand and the tests all use it.
- `api/openapi.rs`: `#[derive(OpenApi)] struct ApiDoc`, with `info(title = "landfall", version = "1")`, `openapi = 3.1.0`, the `token` (HTTP bearer) and `session` (`apiKey`, cookie `__Host-landfall-session`) schemes, the `Problem` schema, and reusable responses: `Unauthenticated` (401), `Forbidden` (403), `NotFound` (404), `RateLimited` (429, with `Retry-After`) and `BadRequest` (400). `requestDeploy` carries `x-landfall-grant`.
- `landfall-server openapi` prints `openapi_document()`.

- [ ] **Step 1: Check the crates.** Check `utoipa`, `utoipa-axum` and `jsonschema` at the newest versions `crate-age` accepts: axum 0.8 support, OpenAPI 3.1 output, `security` with role lists for a scheme that isn't OAuth, `x-` extensions on an operation, and JSON Schema 2020-12 validation without network `$ref`s. Check their dependency trees in `cargo tree` (no OpenSSL, no proc-macro stack beyond `syn` 2) and their licences against `deny.toml`. Record the findings in the PR. If one doesn't fit, stop and report back with what would replace it.
- [ ] **Step 2: Failing tests** in `api/tests/document.rs`:
  - `openapi_document_is_checked_in`: `openapi_document()` equals `include_str!` of `docs/api/openapi.json`. On failure the message is `run: cargo run -p landfall-server -- openapi > docs/api/openapi.json`.
  - `document_is_generated_the_same_twice`: two calls give the same bytes.
  - `served_document_is_the_same_bytes`: `GET /api/v1/openapi.json` with no credentials gets 200, `application/json`, `Cache-Control: no-store` and the same bytes.
  - `document_is_openapi_3_1`: `openapi` is `3.1.0` and `info.version` is `1`.
  - `every_operation_has_an_id_security_and_problem_answers`: each operation has an `operationId` from the table under Global Constraints, a `security` list, 401 and 429 responses referencing `Problem`, and 404 where the path has a parameter. `getOpenApi` is exempt.
  - `every_problem_code_is_in_the_schema`: each variant of `HumanProblem` and `ApiProblem`, by an exhaustive `match` in the test, has its code in the schema's enum, and `unknown` isn't there.
  - `approvals_json_is_unchanged`: for a request seeded through `Store`'s public functions (`World` comes in Task 2), the body of `GET /api/v1/approvals` has the same keys as what plan 05 shipped. Task 11 adds `approve_url` to the expected keys.
  - `api_answers_have_no_cors_headers`: a `GET` with `Origin: https://other.example` gets no `Access-Control-*` header.

  Run: `cargo nextest run -p landfall-server api::`. Expected: FAIL.
- [ ] **Step 3: Implement.** Annotate plan 05's four handlers without changing their behaviour; `requests/tests` must pass unchanged. Generate `docs/api/openapi.json` with the command. Start `docs/api.md`: authentication, the grant column with `x-landfall-grant`, problem answers and their codes, and the version promise ("within `/api/v1`, fields and values are only added; an older CLI works with a newer controller"). Run: `cargo nextest run -p landfall-server -p landfall-api`. Expected: PASS.
- [ ] **Step 4: Gate. Commit:** `feat(api): a wire crate and the generated OpenAPI document`.

### Task 2: Query parameters, cursors, and every operation tested against its grant and schema

**Files:** Create `crates/server/src/api/query.rs`, `crates/server/src/api/tests/{grants,query,schemas}.rs`. Modify `Cargo.toml` and `crates/server/Cargo.toml` (`serde_urlencoded` as a direct dependency; it is already in the tree through `reqwest`), `crates/server/src/api.rs`, `crates/server/src/api/tests.rs` (`World`), `crates/server/src/requests.rs` (`request_number` moves to `api/query.rs`), `crates/server/src/requests/{asking,approving,cancelling}.rs` (`params(…)` and `ApiQuery<NoQuery>`), `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `api/query.rs`: `pub(crate) struct ApiQuery<T>(pub T)`, an extractor for `T: DeserializeOwned + IntoParams`. The query string is at most 2 KiB and goes through `serde_urlencoded` into `T` with `deny_unknown_fields`; any rejection is `ApiProblem::BadRequest`. `pub(crate) struct NoQuery {}` (`deny_unknown_fields`) is taken as `ApiQuery<NoQuery>` by every operation with no query parameters, plan 05's four included, so an unknown parameter is refused on every route. Path parameters `DeploymentPath { name, stage }` and `IdPath { id }` derive `IntoParams`. An id is plain digits with no leading zero, by `request_number`, which moves here from `requests.rs`; `IdPath` and the request handlers share it. Each other query type lands with its first user, as an unused one fails `-D warnings`: `Limit`, `Cursor` and `CursorList` in Task 4, `TagPath` in Task 6, `HostPath` in Task 8.
- `api/tests.rs`: `pub(super) struct World { app: Router, store: Store, tokens: HashMap<&'static str, ApiToken>, sessions: HashMap<&'static str, SessionToken> }`. `World::seed() -> World` sets up a fresh in-memory store and `app/prod`, `app/staging` and `app/other` on `home-1`, with `app/prod` running `v1.2.0` and `v1.3.0` and `v1.1.0` verified. `app/prod` has no open request and no promotion, so only grants decide `requestDeploy` there (`asking` refuses `request_open` before it looks at grants). It creates principals for each role alone on `app/prod` and `app/staging`, one with every grant on both, one with no grant on either (it holds `view` on `app/other` only, since a principal the configuration doesn't name gets 401), and the requester of one seeded open request on `app/staging`, which has its own verified release and host report. A case's deployment is `app/staging` for `approveRequest` and `cancelRequest`, and `app/prod` for every other operation. Each has a token, and the approver has a session. Later tasks add to `seed`, never a promotion or an open request on `app/prod`.
- `api/tests/grants.rs`: `const CASES: &[Case]`, where `Case { operation: &str, role: &str, method, path: fn(&World) -> String, body: fn(&World) -> Option<String> }` holds the concrete request each role makes, built from the `World` because `approveRequest`'s body is a fresh assertion by the `SoftwareAuthenticator` over the seeded request's challenge. It also holds the cross cases for `x-landfall-grant`.

- [ ] **Step 1: Failing tests.**
  - In `api/tests/query.rs`: `unknown_query_parameter_is_refused` (on `listApprovals` and on `requestDeploy`), `query_string_over_2_kib_is_refused`, `non_canonical_ids_are_refused_as_not_found` (`01`, `+1`, `1.0`, a 30-digit number). The cursor tests come with `Cursor` in Task 4.
  - In `api/tests/grants.rs`, `every_operation_enforces_its_documented_grant`, for each operation in the served document and each case, on a fresh `World::seed()`:
    - with no credentials, 401, unless the operation is public;
    - a token of the principal with no grant on the case's deployment (and `view` on `app/other`) gets 404;
    - a principal holding every grant on the case's deployment except the listed roles gets 403 (a session with the right `Origin` for a role listed only under `session`, and a token for the token's list);
    - a principal holding exactly one listed role gets neither 401, 403 nor 404, nor a `409`.
    - An operation with `[]` gets only the first check, plus `200` for the principal with no grant on `app/prod` or `app/staging`.

    `each_role_is_refused_the_case_it_does_not_govern`: `request` asking for `v1.1.0` and `rollback` asking for `v1.3.0` both get 403. `every_documented_operation_and_role_has_a_case` fails naming any operation, role or `x-landfall-grant` key without a row in `CASES`. `a_token_never_approves_even_with_the_grant`.
  - In `api/tests/schemas.rs`, `every_success_answer_matches_its_documented_schema`: every 2xx body from the grant cases is validated with `jsonschema` against the schema the document gives for that operation and status, with `$ref`s resolved within the document.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Regenerate the document, as the path parameters gain their documentation. Add pagination, cursors and the ids rule to `docs/api.md`. Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `test(api): every operation against its documented grant and schema`.

### Task 3: A budget for reads, and session reads only from the controller's own pages

**Files:** Create `crates/server/src/api/tests/reads.rs` (`World` exists by now; `auth` has no test module). Modify `crates/server/src/api/tests.rs` (`mod reads;`), `crates/server/src/auth/budget.rs` (and its module doc, which says reads cost nothing), `crates/server/src/auth/principal.rs`, `crates/server/src/auth/problem.rs` (`ReadsOverBudget`), `crates/server/src/agent_api.rs` (`Limits`), `docs/api.md`.

**Interfaces:**
- `Limits` gains `read_rate_per_second: u32` (10) and `read_burst: u32` (300), each documented as plan 05's are.
- `Budget` gains a second `RateLimiter<Spender>` for reads, keyed by the same `Spender::Session` and `Spender::Tokens`, and `pub(crate) fn spend_read(&mut self, spender: &Spender, now: i64) -> Spent`, with its own dropped counts. `throttled_event` gains `reads: bool`, written as `"reads": true` only when it is set.
- In the `Principal` extractor, a safe method with a session is first checked for `Sec-Fetch-Site`. When the header is present and is neither `same-origin` nor `none`, the read is refused as `HumanProblem::BadOrigin`, with nothing charged, and counted as plan 05 counts a bad `Origin`. Otherwise the read goes to the read bucket. A token's read goes to its principal's tokens' read bucket. Over the budget, a read is `HumanProblem::ReadsOverBudget`: `429 rate_limited`, titled "too many reads by this credential", with `Retry-After`, and it writes nothing. `OverBudget` keeps its title for state changes, which are unchanged.

- [ ] **Step 1: Failing tests:**
  - `reads_spend_their_own_bucket`: 301 reads of `listApprovals` at one instant; the last gets 429 `rate_limited` with `Retry-After` and the reads title, and a `POST` still passes.
  - `a_session_and_tokens_read_apart`.
  - `read_throttles_are_counted_with_reads_true`.
  - `a_read_over_budget_writes_nothing`: the audit row count is unchanged until the flush.
  - `a_cross_site_session_read_is_refused_and_charges_nothing`: `Sec-Fetch-Site: same-site`, then `cross-site`; each is 403 `bad_origin`, and the bucket is untouched.
  - `same_origin_and_absent_fetch_site_are_read`.
  - `a_token_read_ignores_fetch_site`.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Document the read budget and the `Sec-Fetch-Site` rule in `docs/api.md`. Run: `cargo nextest run -p landfall-server`. Expected: PASS, with `requests/tests/budget.rs` unchanged.
- [ ] **Step 3: Gate; `docker build .`; security review of PR A. Commit:** `feat(auth): a budget for reads, and session reads from the controller's own pages`. Open PR A.

## PR B: deployments, commit ranges and release stories

### Task 4: Who am I, and deployments

**Files:** Create `crates/api/src/deployments.rs`, `crates/server/src/api/deployments.rs`, `crates/server/src/api/visible.rs`, `crates/server/src/store/views.rs`, `crates/server/migrations/0005_read_indexes.sql`, `crates/server/src/api/tests/deployments.rs`. Modify `crates/server/src/store.rs` (`mod views;` only), `crates/server/src/store/releases.rs` (`Hold::reason()` only), `crates/server/src/requests.rs` (`visibility` moves to `api/visible.rs`), `crates/server/src/api.rs`, `crates/server/src/api/query.rs` (`Limit`, `Cursor`, `CursorList`), `crates/server/src/api/tests.rs`, `crates/server/src/api/tests/grants.rs`, `crates/server/src/api/tests/query.rs` (the cursor tests), `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `0005_read_indexes.sql` creates indexes on `deploys (deployment, id)`, `deploys (deployment, tag, id)` and `deploy_requests (deployment, tag)`. Indexes only.
- `api/query.rs` gains `pub(crate) struct Limit(u8)`, 1 to 100, default 50, documented with its bounds, and `pub(crate) struct Cursor { list: CursorList, after: String }`, encoded as the base64url of `v1.<list>.<after>`, where `CursorList` is one of `releases`, `deploys`, `audit` or `deployments`. `Cursor::decode(raw, expected: CursorList) -> Result<Cursor, ApiProblem>` refuses another list's cursor, a bad encoding and an `after` over 160 bytes.
- `api/visible.rs`: `visibility` moves here from `requests.rs`, and every read uses it for 404 against 403. `pub(crate) fn shown_deployment(config, principal, id: &DeploymentId) -> DeploymentRef`, deciding by `can(.., Permission::View)`, where `DeploymentRef` is `Seen(DeploymentId)` or `Unseen`, serialised as the id or as `null` with `"unseen": true`. The text form for reasons is `"a deployment you can't view"`. Every view that names another deployment goes through it.
- `landfall-api`:
  - `MeView { principal: PrincipalId, via: Via, grants: Vec<GrantView>, approve_url: Option<String> }`, with `Via { Token, Session, #[serde(other)] Unknown }` and `GrantView { deployment: DeploymentId, can: Vec<Permission> }`. `can` lists only what `can()` allows for this principal now, so a token never lists `approve`.
  - `DeploymentSummary { id, repo: RepoName, host: HostId, running: Option<RunningView>, latest: Option<ReleaseBrief>, open_request: Option<i64>, needs_you: bool }`. `needs_you` is for a session: a token never approves, so it is always `false` for one, and `docs/api.md` says so.
  - `RunningView { tag: Option<ReleaseTag>, digest: Option<ImageDigest>, phase: String, busy: bool, drift: bool, config_drift: bool, healthy_secs: Option<i64>, last_report: Option<i64> }`.
  - `ReleaseBrief { tag: ReleaseTag, status: ReleaseStatus }`.
  - `DeploymentView { summary: DeploymentSummary, rule: RuleView, promote_to: Option<PromotionView>, promoted_from: Vec<PromotionView>, holds: Vec<HoldView>, holds_total: u32 }`, holding the newest 50 holds.
  - `RuleView { auto: Option<String>, approve: Option<String>, approvers: Vec<PrincipalId>, prereleases: bool }`.
  - `PromotionView { deployment: DeploymentRef, healthy_for_secs: u64 }`.
  - `HoldView { tag: Option<ReleaseTag>, reason: String, since: i64, last_try: i64 }`.
  - `ReleaseStatus`, declared here with the twelve values of the Rulings plus `Unknown`. Task 6 computes it; until then `latest` is `None`.
- `store/views.rs`: `Store::running_states(&self, ids: &[&DeploymentId]) -> Result<HashMap<DeploymentId, RunningRow>, StoreError>` and `Store::holds_of_deployment(&self, id: &DeploymentId, limit: u32) -> Result<(Vec<(Option<ReleaseTag>, Hold)>, u32), StoreError>`, the newest `limit` and the count of all. Holds are the store's existing `Hold`, which gains `pub fn reason(&self) -> &str`. `RunningRow` is a plain, crate-private row: `WatchedRunning` plus `healthy_secs`, `last_report` and `config_drift`, kept apart because the watcher reads `WatchedRunning` in its transaction and needs none of those. Open requests come from the existing `Store::open_requests(now)`.
- Routes: `whoAmI`; `listDeployments` with `ApiQuery<DeploymentsQuery { host: Option<HostId>, repo: Option<RepoName>, needs_you: Option<bool>, limit: Option<Limit>, cursor: Option<String> }>`, ordered by deployment id; and `getDeployment`. Deployments come from the configuration. A report from a host the configuration no longer pairs with that deployment is ignored, as the watcher does.

- [ ] **Step 1: Failing tests** in `api/tests/deployments.rs`:
  - `me_names_the_principal_its_grants_and_where_to_approve`.
  - `a_tokens_grants_never_list_approve`: the approver's token shows `view`, `request` and `rollback`; their session adds `approve`.
  - `list_holds_only_viewable_deployments`: with `view` on `app/prod` and `request` on `app/staging`, a principal sees one.
  - `list_filters_by_host_repo_and_needs_you`.
  - `needs_you_is_an_open_request_this_principal_can_approve`.
  - `list_pages_in_id_order`: three deployments, `limit=2`, then the cursor.
  - `limit_outside_1_to_100_is_refused`: `0`, `101`, `100000`, `-1` and `x`.
  - `deployment_shows_rule_promotion_holds_and_running`, on `app/canary`.
  - In `api/tests/query.rs`: `cursor_round_trips`, `cursor_of_another_list_is_refused`, `malformed_cursor_is_refused` (a table: not base64url, wrong prefix, empty, over 160 bytes).
  - `holds_keep_the_newest_50_and_count_all`.
  - `promotion_to_an_unseen_deployment_is_not_named`: the seed adds `app/canary` promoting to `app/beta`, never a promotion on `app/prod`, which would make the grant test's `requestDeploy` a `409 promotion_pending`. With `view` on `app/canary` only, its `promote_to` reads `unseen`, and nothing in the body contains `app/beta`.
  - `a_report_from_a_host_no_longer_paired_is_ignored`.
  - `unseen_deployment_is_not_found_and_another_grant_is_forbidden`.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Add the seed and the `CASES` rows. Regenerate the document. Run: `cargo nextest run -p landfall-server`. Expected: PASS, with the grant and schema tests now covering the three new operations.
- [ ] **Step 3: Gate. Commit:** `feat(api): who am I, and deployments`.

### Task 5: Commit ranges between verified releases, within GitHub's budget

**Files:** Create `crates/origin/src/fetch/commits.rs`, `crates/origin/src/fetch/tests/commits.rs`, `crates/server/src/watcher/commits.rs`, `crates/server/src/watcher/tests/commits.rs`, `crates/server/src/store/commits.rs`, `crates/server/migrations/0006_commit_ranges.sql`. Modify `crates/origin/src/fetch.rs` (`mod commits;`, its `pub use`, and `Fetcher::has_github_token`), `crates/origin/src/release.rs` (`ReleaseError::Compare`), `crates/server/src/watcher.rs` (`mod commits;` and the two trait methods only), `crates/server/src/watcher/ticking.rs` (one call to `commits::after_tick` at the end of `tick`), `crates/server/src/watcher/source.rs`, and the other five `ReleaseSource` impls: `crates/server/src/watcher/tests.rs`, `crates/server/tests/serve_upkeep.rs`, `crates/server/tests/browser/main.rs`, `crates/server/tests/stuck_stderr.rs`, `crates/agent/tests/e2e/world.rs`. Also `crates/server/src/store.rs` (`mod commits;` only), `crates/server/src/store/releases.rs` (`record_release` sets `first_seen_at` on insert only), `docs/api.md`.

**Interfaces:**
- `fetch/commits.rs`: `pub const COMPARE_PAGE_LIMIT: usize = 8 * 1024 * 1024`, `pub const COMPARE_PER_PAGE: u8 = 100`, `pub const KEPT_COMMITS: usize = 100` and `pub const COMMIT_SUMMARY_CHARS: usize = 200`.
- `Fetcher::compare_page(&self, repo: &RepoName, base: &CommitSha, head: &CommitSha, page: u32) -> Result<ComparePage, FetchError>`: `GET /repos/{repo}/compare/{base}...{head}?per_page=100&page={page}`, streamed under `COMPARE_PAGE_LIMIT`, with the GitHub token as other calls send it. `pub enum ComparePage { Listed { status: CompareStatus, total: u64, commits: Vec<ListedCommit>, rate_remaining: Option<u32> }, TooLarge { rate_remaining: Option<u32> } }`: `TooLarge` for a body over the cap or a 422. `pub enum CompareStatus { Ahead, Identical, Behind, Diverged }`; any other value is a parse error. Only `status`, `total_commits` and `commits[].{sha, commit.message, author.login}` are read; `files` is skipped without being kept. `pub struct ListedCommit { pub sha: CommitSha, pub summary: String, pub author: Option<String> }`. `summary` is the message's first line through `quoted(_, COMMIT_SUMMARY_CHARS)`. `author` is the login if it matches GitHub's login grammar (`[A-Za-z0-9-]{1,39}`), else `None`. `pub fn compare_url(repo: &RepoName, base: &CommitSha, head: &CommitSha) -> String`. `fetch.rs` re-exports these, and gains `pub fn has_github_token(&self) -> bool`.
- `ReleaseSource` gains `fn compare_page(&self, deployment: &DeploymentId, base: &CommitSha, head: &CommitSha, page: u32) -> impl Future<Output = Result<ComparePage, ReleaseError>> + Send;` and `fn has_github_token(&self) -> bool;`. `LiveSource` calls the fetcher with the deployment's repo, wrapping a failure as `ReleaseError::Compare(FetchError)`, and answers `has_github_token` from the fetcher. There are six impls: `LiveSource`, and the fakes in `watcher/tests.rs`, `serve_upkeep.rs`, `browser/main.rs`, `stuck_stderr.rs` and the agent's `e2e/world.rs`. Each fake returns `Listed { status: Ahead, total: 0, commits: vec![], rate_remaining: Some(5000) }` and `has_github_token() == false` unless its test says otherwise.
- `0006_commit_ranges.sql`:
  - `commit_ranges (repo, base_commit, head_commit, state CHECK IN ('listed','too_large','base_not_found','unavailable'), total INTEGER, last_try INTEGER, PRIMARY KEY (repo, base_commit, head_commit))`;
  - `range_commits (repo, base_commit, head_commit, position, sha, summary, author NULL, PRIMARY KEY (repo, base_commit, head_commit, position))`;
  - `commits_since (at INTEGER NOT NULL)`, holding one row inserted by the migration with the time it ran;
  - `ALTER TABLE releases ADD COLUMN first_seen_at INTEGER NOT NULL DEFAULT 0`, then `UPDATE releases SET first_seen_at = seen_at`. `record_release` sets it on insert and never on conflict, unlike `seen_at`, which every verification moves, a configuration change included.

  The three new tables are `STRICT`.
- `store/commits.rs`: `Store::commit_range(&self, repo, base, head) -> Result<Option<CommitRange>, StoreError>` and `Store::record_commit_range(&self, repo, base, head, range: &NewRange<'_>) -> Result<(), StoreError>`, which replaces the range and its commits in one transaction. `Store::ranges_wanted(&self, config: &Config, config_hash: &str, now: i64) -> Result<Vec<WantedRange>, StoreError>` yields, newest version first across deployments, each settled release whose `first_seen_at` is at or after `commits_since.at` and whose base exists, with no range stored or an `unavailable` one tried more than `COMMIT_RETRY_SECS` ago. Each `(repo, base, head)` appears once.
- `watcher/commits.rs`:
  - `pub(crate) const COMMIT_RETRY_SECS: i64 = 3600`.
  - `pub(crate) struct GitHubBudget { requests_left: u8, floor: u32 }`, with `GitHubBudget::for_tick(has_token: bool) -> Self`: 12 requests and a floor of 1,000 with a token, 3 and 30 without.
  - `pub(crate) fn pages_for_newest(total: u64) -> Vec<u32>`: `[1]` for 100 or fewer, else the last two pages by `ceil(total / 100)` (page 1 already read is reused when it is one of them), so the kept commits are the newest `KEPT_COMMITS`.
  - `pub(crate) fn base_for(tag: &ReleaseTag, settled: &[(ReleaseTag, CommitSha)]) -> Option<(ReleaseTag, CommitSha)>`: the highest semantic version below `tag`, where a pre-release orders below its release, as `semver` says.
  - `pub(crate) async fn after_tick<S: ReleaseSource>(store, source, config, now) -> usize` is called from `ticking.rs` once the tick's verifications are done. It takes the hash from `config.hash()` and the budget from `GitHubBudget::for_tick(source.has_github_token())`. It walks `ranges_wanted`. For each range it reads page 1; `behind` or `diverged` is recorded as `base_not_found`, `TooLarge` as `too_large`; otherwise it reads `pages_for_newest(total)` and keeps the newest `KEPT_COMMITS`, newest first. A range starts only if the budget left covers the requests it can need (3), and is recorded only once all its pages came back. It stops for the tick when the budget is spent, a page's `rate_remaining` falls below the floor, or GitHub answers 403 or 429: `FetchError::RateLimited`, or `FetchError::Status` with 403 or 429 when the rate-limit headers are missing.
  - It writes no audit row, since it decides nothing. A failure records `unavailable`, logged once per range.

- [ ] **Step 1: Failing tests.**
  - In `fetch/tests/commits.rs` with `wiremock`: `compare_page_is_parsed` (status, total, sha, first line only, login, rate remaining), `files_are_skipped`, `summary_is_quoted_and_cut` (a message with a newline, ANSI escapes and 500 characters), `odd_login_is_dropped`, `merge_commits_are_parsed_in_order` (a recorded compare body holding a merge commit with two parents and the branch's commits; all are kept in GitHub's order), `over_the_cap_is_too_large_with_a_link` (a 9 MiB body is `TooLarge`, and `compare_url` names the repo and both shas), `a_422_is_too_large`, `unknown_status_is_an_error`, `token_goes_with_the_request`.
  - In `watcher/tests/commits.rs`:
    - `base_is_the_highest_lower_settled_version`: a table with `v1.2.3` over `v1.2.0` and `v1.1.9`; pre-release `v1.3.0-rc.1` below `v1.3.0`; none below gives `None`.
    - `a_refused_release_is_neither_compared_nor_a_base`: `v1.2.5` with `origin_refused` sits between `v1.2.0` and `v1.3.0`. It gets no range, and `v1.3.0`'s base is `v1.2.0`.
    - `a_release_not_settled_under_this_configuration_is_skipped`.
    - `a_moved_tag_is_compared_again`: `v1.3.0` re-recorded with a new commit gets a new range for the new head, and the story no longer shows the old one.
    - `pages_for_newest_table`: 0, 1, 100 give `[1]`; 101 gives `[1, 2]`; 250 gives `[2, 3]`; 1,000 gives `[9, 10]`.
    - `the_newest_100_come_from_the_last_pages`: a 250-commit comparison; the kept 100 are commits 151 to 250 of GitHub's order, newest first, and `total` is 250.
    - `behind_or_diverged_is_base_not_found`.
    - `too_large_is_recorded_without_a_list`.
    - `a_range_is_never_stored_half_done`: the budget runs out between page 1 and the last pages; nothing is stored, and the next tick fetches it whole.
    - `two_deployments_of_one_repo_share_one_range`.
    - `verification_runs_before_commits`: a fake source records call order within a tick.
    - `compares_stop_when_the_rate_limit_is_low`: a page with `rate_remaining` below the floor stops the tick, and the next tick goes on.
    - `a_bare_403_stops_the_tick`: a `Status { 403 }` with no rate-limit headers stops it as a rate limit would.
    - `untokened_ticks_make_at_most_three_requests`.
    - `a_rate_limited_answer_stops_the_tick_and_holds_nothing`: the release's decision and holds stay as they were.
    - `releases_seen_before_the_migration_are_never_fetched`.
    - `a_configuration_change_does_not_make_old_releases_eligible`: a release recorded before the migration and verified again under a new configuration hash keeps its `first_seen_at` and isn't fetched.
    - `unavailable_is_retried_after_an_hour`.

  Run: `cargo nextest run -p landfall-origin commits` and `-p landfall-server commits`. Expected: FAIL.
- [ ] **Step 2: Implement.** Document the source, why compare (exact, merged branches included), the unverified author, which 100 are kept, `too_large` and its link, `base_not_found`, and the budget in `docs/api.md`. Run: `cargo nextest run -p landfall-origin -p landfall-server -p landfall-agent`. Expected: PASS, with every existing watcher and end-to-end test unchanged.
- [ ] **Step 3: Gate; Linux, as the agent's e2e changed. Commit:** `feat(watcher): record the commits between verified releases, as GitHub compares them`.

### Task 6: Releases and their story

**Files:** Create `crates/api/src/releases.rs`, `crates/server/src/api/releases.rs`, `crates/server/src/api/story.rs`, `crates/server/src/api/tests/{releases,story}.rs`, `crates/server/src/store/history.rs`. Modify `crates/server/src/store.rs` (`mod history;` only), `crates/server/src/api.rs`, `crates/server/src/api/query.rs` (`TagPath`, deriving `IntoParams`), `crates/server/src/api/deployments.rs` (fills `latest`), `crates/server/src/api/tests.rs`, `crates/server/src/api/tests/grants.rs`, `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `landfall-api`:
  - `ReleaseView { tag, status: ReleaseStatus, decision: Decision, first_seen_at: i64, seen_at: i64 }`. `first_seen_at` is when the controller first recorded it; `seen_at` is when it was last verified.
  - `Decision { Auto, NeedsApproval, Manual, Refused, Deferred, #[serde(other)] Unknown }`.
  - `ReleaseStory { release: ReleaseView, reasons: Vec<String>, next: Option<NextAction>, origin: Option<OriginView>, commits: CommitsView, requests: Vec<RequestBrief>, deploys: Vec<DeployBrief> }`.
  - `OriginView { commit, digest, signer: Option<PrincipalId>, san: String, run_url: String, rekor_log_index: Option<u64>, integrated_time: Option<i64> }`, read from the `origin` column.
  - `CommitsView { source: CommitSource, verified: bool, state: CommitsState, base: Option<ReleaseTag>, total: Option<u64>, compare_url: Option<String>, commits: Vec<CommitView> }`. `CommitSource { Github, #[serde(other)] Unknown }`. `verified` is documented as `const: false`. `CommitsState { Listed, TooLarge, BaseNotFound, First, NotYet, Unavailable, NotRecorded, Unknown }`. Only `Listed` carries commits: all of them when `total` equals their count, else the newest 100, which `total` says. `TooLarge`, `BaseNotFound`, `NotYet`, `Unavailable` and `NotRecorded` carry none and mean unknown, not empty. `compare_url` is set whenever there is a base.
  - `CommitView { sha, summary, author: Option<String> }`.
  - `RequestBrief { id, state, requested_by, approved_by: Option<PrincipalId>, created_at, closed_reason: Option<String> }`.
  - `DeployBrief { id, state, outcome: Option<Outcome>, created_at, finished_at: Option<i64> }`.
  - `Outcome { Deployed, RolledBack, NothingChanged, FailedNoPrevious, RollbackFailed, Refused, Deferred, Unknown }`, the stored names.
  - `NextAction { kind: NextKind, detail: String }`, with `NextKind { Request, Rollback, Approve, Wait, FixHost, Recover, None, Unknown }`. `detail` is the controller's own text, such as the CLI command to run or the approval page.
- `store/history.rs`: `Store::release_rows(&self, deployment) -> Result<Vec<ReleaseRow>, StoreError>`, at most `MAX_LISTED_TAGS`, the watcher's own bound. They are sorted by version in memory for each page, because the order is `semver`'s and no index holds it. `docs/api.md` states that bound. `Store::release_row(&self, deployment, tag) -> Result<Option<ReleaseRow>, StoreError>`, with `origin` and `seen_at`. `Store::requests_of_release(&self, deployment, tag, limit: u32) -> Result<Vec<RequestRow>, StoreError>` and `Store::deploys_of_release(&self, deployment, tag, limit: u32) -> Result<Vec<DeployRow>, StoreError>`, newest first. A story keeps the newest 20 requests and the newest 20 deploys.
- `api/story.rs`: `pub(crate) struct StoryInputs<'a> { tag: &'a ReleaseTag, digest: Option<&'a ImageDigest>, decision: Decision, decision_reason: &'a str, running: Option<&'a RunningRow>, active_deploy: bool, open_request: bool, hold: Option<&'a Hold>, last_outcome: Option<(Outcome, &'a str)>, promotion_waits_for: Option<DeploymentRef>, lower_than_running: bool }`, `pub(crate) struct StatusExplained { status: ReleaseStatus, reasons: Vec<String>, next: Option<NextAction> }`, and `#[must_use] pub(crate) fn status(inputs: &StoryInputs<'_>) -> StatusExplained`, by the precedence in the Rulings. Here `Decision` is `landfall-api`'s, imported as `ApiDecision` because story.rs also uses `landfall_core::rule::Decision`. Promotion uses `Store::promotion_waits_for`, as asking does, through `shown_deployment`. The commit range is looked up from the release's current commit and its base's, by `base_for`. A `base_not_found` range adds a reason line saying the previous release's commit isn't an ancestor of this one (a rewritten history). A `too_large` range adds one pointing at `compare_url`.
- Routes: `listReleases`, with `ApiQuery<ReleasesQuery { limit, cursor }>`. The highest version comes first by `semver`, tags that don't parse come last in string order, and the cursor holds the last tag. `getRelease` is `404` for a tag the controller hasn't recorded.

- [ ] **Step 1: Failing tests.**
  - In `api/tests/story.rs`: `status_table`, with one row per status of the precedence, each with the inputs that produce it, its first reason and its `next` (for `needs_request`, `next.kind` is always `request`; for `superseded` with `needs_approval` or `manual`, it is `rollback`); `precedence_holds_when_several_apply` (running and held at once is `running`; a held release that a higher one superseded is `held`; failed and superseded is `superseded`); and `promotion_reason_does_not_name_an_unseen_deployment`.
  - In `api/tests/releases.rs`:
    - `story_has_origin_commits_requests_and_deploys`.
    - `commits_say_github_and_unverified`.
    - `first_release_says_first`.
    - `a_range_not_fetched_is_unknown_not_empty`: `not_yet`, `unavailable`, `not_recorded` and `too_large` each have an empty `commits` and are distinct from `listed` with zero commits.
    - `base_not_found_adds_a_reason`.
    - `too_large_has_no_commits_and_links_to_github`.
    - `a_cut_list_says_newest_100_of_total`.
    - `a_rolled_back_release_says_failed_and_not_retried`.
    - `a_release_that_never_verified_has_no_origin_and_no_commits`.
    - `five_thousand_releases_page_in_version_order`: 5,000 tags seeded, in pages of 100; each page's first tag is lower than the previous page's last.
    - `unparseable_tags_come_last`.
    - `unrecorded_tag_is_not_found`.
    - `deployment_summary_shows_the_latest_release_and_its_status`.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Add the seed and the `CASES` rows. Regenerate the document. Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 3: Gate; security review of PR B. Commit:** `feat(api): releases and their story`. Open PR B.

## PR C: deploys, why, hosts and the audit log

### Task 7: Deploys and `why`

**Files:** Create `crates/api/src/deploys.rs`, `crates/server/src/api/deploys.rs`, `crates/server/src/api/why.rs`, `crates/server/src/api/tests/{deploys,why}.rs`. Modify `crates/server/src/store/history.rs`, `crates/server/src/api.rs`, `crates/server/src/api/tests.rs`, `crates/server/src/api/tests/grants.rs`, `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `landfall-api`:
  - `DeployView { id, deployment, host, tag, digest, commit, state: DeployState, outcome: Option<Outcome>, reason: Option<String>, rollback_reason: Option<String>, request: Option<i64>, approved_by: Option<PrincipalId>, created_at, claimed_at: Option<i64>, finished_at: Option<i64>, steps: Vec<StepView> }`.
  - `DeployState { Queued, Claimed, Finished, Unknown }`.
  - `StepView { position: u32, name: String, millis: i64, failure: Option<String>, detail: Option<serde_json::Value> }`: the stored detail, already bounded (checks with their attempts and millis, backup counts).
  - `Why { deploy: i64, outcome: Option<Outcome>, summary: String, events: Vec<WhyEvent>, next: Option<NextAction> }`.
  - `WhyEvent { at: Option<i64>, what: WhyKind, text: String }`.
  - `WhyKind { Requested, Approved, Queued, Claimed, Step, StepFailed, RolledBack, RollbackFailed, HostRefused, Deferred, Finished, Unknown }`.
- `store/history.rs` gains `Store::deploy(&self, id: i64) -> Result<Option<DeployRow>, StoreError>`, with `request_id` and the request's `requested_by` and `approved_by`; `Store::deploy_steps(&self, id: i64) -> Result<Vec<StepRow>, StoreError>`; and `Store::deploys_of_deployment(&self, deployment, before: Option<i64>, limit: u32) -> Result<Vec<DeployRow>, StoreError>`, on the `(deployment, id)` index.
- `api/why.rs`: `#[must_use] pub(crate) fn explain(deploy: &DeployRow, steps: &[StepRow]) -> Why`, pure.
  - Events come in time order: requested (by whom), approved (by whom), queued, claimed, each step (a failure as `StepFailed`, with its text), then the outcome.
  - `summary` is one sentence an agent can act on, such as "v1.2.3 failed its checks on home-1 and rolled back to the previous version; it won't be retried automatically".
  - `next` by outcome:
    - `rolled_back` and `failed_no_previous`: `request`, naming a newer release or a retry with an approval.
    - `rollback_failed`: `recover`, naming `landfall-agent recover` on that host.
    - `refused`: `fix_host`, quoting the host's reason and saying it is an alert.
    - `deferred` and `nothing_changed`: `wait`.
    - `deployed`: `none`.
    - Queued or claimed: `wait`.
- Routes: `listDeploys` (`ApiQuery<DeploysQuery { limit, cursor }>`, newest first), `getDeploy` and `whyDeploy`. A deploy whose deployment the configuration doesn't have is `404`, and so is one the principal can't view, by the visibility rule.

- [ ] **Step 1: Failing tests.**
  - In `api/tests/why.rs`: `explain_table`, with one row per outcome (each of the seven, plus queued and claimed), asserting that `summary` names the tag and host, the event kinds come in order, and `next.kind` is right; `a_step_failure_is_quoted_not_raw` (a failure with a newline and an escape stays as stored); `approver_and_requester_are_named`.
  - In `api/tests/deploys.rs`:
    - `deploy_has_steps_with_checks`.
    - `history_pages_newest_first`.
    - `why_of_an_unseen_deploy_is_not_found`: a principal with `view` on `app/staging` only, asking for an `app/prod` deploy, gets the same 404 as for id 999999.
    - `deploy_of_a_deployment_no_longer_configured_is_not_found`: with rows for `app/old` in the database and `app/old` absent from the configuration, `getDeploy`, `whyDeploy` and `listDeploys` all give 404, even for a principal whose grants once named it.

  Expected: FAIL.
- [ ] **Step 2: Implement; seed; add the `CASES` rows; regenerate.** Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 3: Gate. Commit:** `feat(api): deploys, and why each ended as it did`.

### Task 8: Hosts and the audit log

**Files:** Create `crates/api/src/hosts.rs`, `crates/api/src/audit.rs`, `crates/server/src/api/hosts.rs`, `crates/server/src/api/audit.rs`, `crates/server/migrations/0007_audit_indexes.sql`, `crates/server/src/api/tests/{hosts,audit}.rs`. Modify `crates/server/src/store/views.rs`, `crates/server/src/audit.rs` (`EventKind` gains `FromStr` by its names), `crates/server/src/api/query.rs` (`HostPath`, deriving `IntoParams`), `crates/server/src/api.rs`, `crates/server/src/api/tests.rs`, `crates/server/src/api/tests/grants.rs`, `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `0007_audit_indexes.sql` creates indexes on `audit_events (deployment, seq)`, `audit_events (deployment, kind, seq)` and `audit_events (host, kind, seq) WHERE deployment IS NULL`. Indexes only; the audit triggers are unaffected.
- `landfall-api`: `HostView { id: HostId, enrolled_at: Option<i64>, config_drift: bool, last_report: Option<i64>, deployments: Vec<DeploymentSummary> }`. `last_report` is the newest `running_states.last_report` among its deployments, since `hosts` has no such column. `AuditEntry { seq: i64, ts: i64, kind: String, deployment: Option<DeploymentId>, host: Option<HostId>, detail: serde_json::Value }`. `detail` is parsed, or, for a row that doesn't parse (a tampered one), is `{"unreadable": "<first 256 characters, quoted>"}`. There is no hash: verifying is `landfall-server audit verify`'s job.
- `store/views.rs` gains `Store::hosts(&self, ids: &[&HostId]) -> Result<HashMap<HostId, HostRow>, StoreError>` and `Store::audit_page(&self, scope: &AuditScope<'_>, filter: &AuditFilter<'_>, before: Option<i64>, limit: u32) -> Result<Vec<AuditRow>, StoreError>`. `AuditScope { deployments: &[&DeploymentId], hosts: &[&HostId] }` is what the principal may see; its hosts are those with a viewable deployment. `AuditFilter { deployment: Option<&DeploymentId>, host: Option<&HostId>, kind: Option<&str> }`. `pub(crate) const HOST_ROW_KINDS: [&str; 2] = ["host_enrolled", "config_drift"]`.
- The audit query, built for the scope and filter: one branch per scoped deployment, `SELECT * FROM (SELECT seq, ts, kind, deployment, host, detail FROM audit_events WHERE deployment = ? [AND kind = ?] AND seq < ? ORDER BY seq DESC LIMIT ?)`, and one branch per scoped host and allowed kind, `SELECT * FROM (SELECT … FROM audit_events WHERE deployment IS NULL AND host = ? AND kind = ? AND seq < ? ORDER BY seq DESC LIMIT ?)`. Each branch is a subquery because SQLite allows no `ORDER BY` or `LIMIT` on a bare member of a compound `SELECT`. The branches are combined with `UNION ALL` under an outer `ORDER BY seq DESC LIMIT ?`. Each branch reads at most `limit` rows from its index. Rows with neither a deployment nor a host are never selected. `pub(crate) const MAX_AUDIT_BRANCHES: usize = 400`, under SQLite's default limit of 500 terms in a compound `SELECT`, and at most 2,000 bound parameters. A scope over it is refused with `bad_request`, asking for a `deployment` or `host` filter; the configuration bounds the scope.
- Routes: `listHosts`, the hosts named by configured deployments the principal may view, by id; `getHost`, which is 404 for a host with no deployment the principal sees and 403 for one where they hold another grant but no `view`; and `listAudit`, with `ApiQuery<AuditQuery { deployment, host, kind, limit, cursor }>`. `kind` must be one of `EventKind`'s names, else 400. A `deployment` or `host` filter the principal can't see gives an empty page, never 403 or 404, so the filter says nothing.

- [ ] **Step 1: Failing tests.**
  - In `api/tests/hosts.rs`:
    - `hosts_show_only_viewable_deployments`: `home-1` runs `app/prod` and `app/other`. With `view` on `app/prod` only, `home-1` lists one deployment, `home-2` (which runs only `app/edge`; a deployment has one host) is absent, and `getHost` for `home-2` gives 404.
    - `host_with_only_another_grant_is_forbidden`.
    - `host_never_enrolled_is_listed_without_enrolled_at`.
    - `host_shows_config_drift_and_last_report`.
  - In `api/tests/audit.rs`:
    - `audit_rows_follow_view_in_sql`: 60 rows across `app/prod`, `app/other`, `home-1` and controller-wide kinds. With `view` on `app/prod`, `limit=50` gives exactly 50 visible rows, none of `app/other` and none controller-wide.
    - `host_rows_are_seen_through_a_deployment_on_that_host`: `host_enrolled` and `config_drift` only.
    - `host_rows_of_enrolment_are_not_listed`: `enrol_code_issued`, `enrol_refused` and a `report_refused` with no deployment are absent, whatever the grants.
    - `controller_wide_rows_are_never_listed`: `token_created`, `signed_in`, `access_throttled` and `passkey_registered` are absent, whatever the grants, for a token and for a session.
    - `audit_of_a_removed_deployment_is_not_listed`.
    - `a_crafted_cursor_reaches_nothing_unseen`: a cursor whose `before` is the seq of an unseen row yields only visible rows.
    - `filter_on_an_unseen_deployment_is_an_empty_page`.
    - `unknown_kind_is_refused`.
    - `tampered_detail_is_unreadable_not_an_error`.
    - `a_scope_over_400_branches_is_refused`: 400 branches answer a page; 401 are `400 bad_request`, never a `500`.
    - `audit_page_uses_an_index`: `EXPLAIN QUERY PLAN` of the unfiltered scoped query, of the `kind` filter and of a deployment filter, for a scope of three deployments and one host. Each names one of `0007`'s indexes in every branch, and none contains `SCAN audit_events`.

  Expected: FAIL.
- [ ] **Step 2: Implement; seed; add the `CASES` rows; regenerate.** Document the audit rule, the allow-list and that global sequence numbers and ids show gaps, in `docs/api.md`. Run: `cargo nextest run -p landfall-server`. Expected: PASS.
- [ ] **Step 3: Gate; security review of PR C. Commit:** `feat(api): hosts and the audit log, as far as a principal may see`. Open PR C.

## PR D: the CLI's client and its read commands

### Task 9: The client: where the controller is, the token, answers and escaping

**Files:** Create `crates/cli/src/api_client.rs`, `crates/cli/src/api_client/tests.rs`, `crates/cli/src/settings.rs`, `crates/cli/src/settings/tests.rs`, `crates/cli/src/display.rs`, `crates/cli/src/display/tests.rs`. Modify `crates/cli/Cargo.toml` (`landfall-api`, `reqwest` moved from dev-dependencies to dependencies with `rustls` and `stream`, `serde`, `toml`), `crates/cli/src/lib.rs` (`settings`, `api_client`, `display`), `crates/cli/src/cli.rs` (`ApiArgs`, `CliError::Api`, `run_with`, and every error printed through `display::safe`), `crates/cli/src/cli/tests.rs` (`errors_are_escaped`), `AGENTS.md` (crate map).

**Interfaces:**
- `settings.rs`:
  - `pub struct Settings { pub controller: ControllerUrl, pub token: Option<Token> }`.
  - `pub struct Token(String)`: redacted `Debug`, no `Display`, and `pub(crate) fn header(&self) -> HeaderValue`, marked sensitive.
  - `pub fn resolve(flags: &ApiArgs, env: &dyn Env, files: &dyn Files) -> Result<Settings, SettingsError>`.
    - The controller comes from `--controller`, then `LANDFALL_CONTROLLER`, then `controller` in the config file. The config file is `--cli-config`, else `$XDG_CONFIG_HOME/landfall/cli.toml`, else `~/.config/landfall/cli.toml`; a missing default file is fine, and a missing named one isn't.
    - Insecure transport is allowed by `--allow-insecure-controller` or `allow_insecure_controller = true`.
    - The token comes from `LANDFALL_TOKEN` (non-empty), then `--token-file`, then `LANDFALL_TOKEN_FILE`, then `token_file`. Two sources set at once is an error naming both.
    - A token file must be a regular file opened with no-follow, with `mode & 0o077 == 0` on Unix, at most 256 bytes, holding one line of `[A-Za-z0-9_-]` after trimming one final newline.
    - The config file is TOML with `deny_unknown_fields`: `controller`, `token_file` and `allow_insecure_controller`.
  - `SettingsError::Controller(UrlError)` has the CLI's own message for each case: an `http://` controller would get the bearer token in clear, so the flag is needed and only for loopback, `localhost` or `*.ts.net`.
  - `pub trait Env` and `pub trait Files`, for tests.
- `ApiArgs` (clap `Args`, flattened into each API command, never `global = true`, because `host install` already has `--controller` and `--allow-insecure-controller` and clap panics on a duplicate): `--controller <URL>`, `--allow-insecure-controller`, `--token-file <FILE>`, `--cli-config <FILE>`, `--json`. So it is `landfall status --json`, not `landfall --json status`.
- `cli.rs`: `pub fn run_with(cli: Cli, env: &dyn Env, out: &mut dyn Write, err: &mut dyn Write) -> u8` is the library entry. Every command writes to `out`, and failures go to `err` through `display::safe`. `run` calls it with the process environment, stdout and stderr. Token files are read from the real file system.
- `api_client.rs`: `pub struct ApiClient`.
  - `pub fn new(settings: &Settings) -> Result<ApiClient, ApiError>`: `reqwest` with `.no_proxy()`, `.https_only(controller is https)`, `redirect::Policy::none()`, a connect timeout of 10 s, a request timeout of 30 s and `User-Agent: landfall/<version>`.
  - `pub async fn get(&self, path: &str, query: &[(&str, &str)]) -> Result<serde_json::Value, ApiError>`, `pub async fn post<B: Serialize>(&self, path: &str, body: &B) -> Result<serde_json::Value, ApiError>`, and `pub fn typed<T: DeserializeOwned>(value: &serde_json::Value) -> Result<T, ApiError>`. Bodies are capped at 4 MiB while streaming. Path segments go through one function, `pub(crate) fn segment(&str) -> String`, which percent-encodes everything outside the unreserved characters. A deployment id is split into `{name}/{stage}` by `DeploymentId`'s own grammar.
- `pub enum ApiError` (`#[non_exhaustive]`):
  - `Refused { status: u16, code: ProblemCode, title: String }`: exit 1.
  - `Unauthenticated`: exit 2, saying where the token was looked for.
  - `RateLimited { retry_after_secs: Option<u32> }`: exit 2.
  - `Server { status: u16 }`: exit 2.
  - `Redirected { status: u16 }`: exit 2, naming no location.
  - `TooLarge`.
  - `Network(#[source] reqwest::Error)`, with the URL's query and any credentials stripped.
  - `Parse`: exit 2.

  No variant holds the token.
- `display.rs`: `#[must_use] pub fn safe(text: &str) -> Cow<'_, str>` escapes C0 (including `\r` and `\n`), DEL, C1, U+061C, U+200E, U+200F, U+2028, U+2029, U+202A to U+202E and U+2066 to U+2069 as `\u{XX}`. `#[must_use] pub fn safe_lines(text: &str) -> Cow<'_, str>` is the same except that it keeps `\n`. `pub fn write_json(out: &mut dyn Write, value: &serde_json::Value) -> io::Result<()>` prints pretty JSON with DEL, C1 and the same controls escaped as `\uXXXX`, through a `serde_json::ser::Formatter` that overrides `write_string_fragment`.

- [ ] **Step 1: Failing tests.**
  - In `settings/tests.rs`:
    - `flag_beats_env_beats_file`.
    - `two_token_sources_are_refused_naming_both`.
    - `no_token_is_allowed_for_a_proxy_that_adds_one`.
    - `insecure_url_is_refused`: `http://controller.example` is refused with or without the flag; `http://127.0.0.1:8080` and `http://landfall.example.ts.net` are refused without it and pass with it. Each message speaks of the token.
    - `readable_token_file_is_refused`: 0644 is refused and 0600 passes.
    - `linked_token_file_is_refused`.
    - `token_file_over_256_bytes_is_refused`.
    - `token_with_odd_characters_is_refused`.
    - `unknown_config_key_is_refused`.
    - `named_config_file_must_exist`.
    - `token_debug_is_redacted`.
  - In `api_client/tests.rs`, with `wiremock`:
    - `bearer_is_sent_when_there_is_a_token_and_not_otherwise`.
    - `http_proxy_in_the_environment_is_not_used`: `HTTP_PROXY`, `HTTPS_PROXY` and `ALL_PROXY` pointed at a second server, set through the client builder's test seam or a child process. That server receives nothing.
    - `redirect_is_not_followed_and_the_token_stays`: a 302 to a second server. That server receives nothing, and the error names no location.
    - `problem_answers_become_refused_with_their_code`.
    - `401_is_unauthenticated_and_says_where_the_token_came_from`.
    - `429_carries_retry_after`.
    - `body_over_4_mib_is_cut_off`.
    - `unknown_fields_and_values_from_a_newer_controller_are_tolerated`: an extra field, a `status` of `"teleporting"` read as `Unknown`, and a new problem code read as `ProblemCode::Unknown`.
    - `token_is_never_in_output_or_errors`: every `ApiError`'s `Display` and `Debug`, and a failed connection's, searched for the token.
    - `segments_are_percent_encoded`: a tag with `/`, `?`, `#`, `%` and `..`.
  - In `display/tests.rs`:
    - `safe_escapes_controls_and_bidi`: a table of `\x1b[31m`, `\u{9b}31m`, `\r`, `\u{202e}`, `\u{2066}`, `\u{200f}`, `\u{2028}`, `\x07` and `\x7f`, with plain accented text unchanged and borrowed.
    - `safe_lines_keeps_newlines_and_escapes_carriage_returns`.
    - `json_output_escapes_c1_del_and_bidi`: the output parses back to the same value and holds no byte of U+009B, U+007F or U+202E.
  - In `cli/tests.rs`: `errors_are_escaped`: a `Refused` whose title holds `\x1b]0;x\x07`, written to `err` by `run_with`, comes out escaped.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-cli`. Expected: PASS, with the existing `verify` and `host` tests unchanged.
- [ ] **Step 3: Gate. Commit:** `feat(cli): a client for the controller's API`.

### Task 10: Reading: status, history, release, why, hosts, audit, approvals, whoami

**Files:** Create `crates/cli/src/read.rs`, `crates/cli/src/read/render.rs`, `crates/cli/src/read/tests.rs`, `crates/cli/src/read/tests/{render,commands}.rs`. Modify `crates/cli/src/lib.rs` (`pub mod read;`), `crates/cli/src/cli.rs`, `crates/cli/src/cli/tests.rs`.

**Interfaces:**
- Commands, each with the flattened `ApiArgs` (`landfall status --json`). With `--json`, each prints the body as received, through `display::write_json`, and a paged command prints `{"items": [...]}` from every page it read.
  - `landfall whoami` → `GET /api/v1/me`.
  - `landfall status [<DEPLOYMENT>] [--host <ID>] [--repo <NAME>] [--needs-you]`. Without a deployment, it reads `listDeployments` page by page, stopping at 1,000 items or 20 pages, or when a cursor comes back that it has already seen, with a line saying which. It prints one line per deployment: id, host, running tag and phase, latest release and its status, and `needs you` where that applies. With a deployment, it reads `getDeployment`: rule, promotion, holds (and how many more), running, latest.
  - `landfall history <DEPLOYMENT> [--limit <N>]` → `listDeploys`.
  - `landfall release <DEPLOYMENT> <TAG>` → `getRelease`: status, reasons, `next`, origin, commits, requests and deploys. Commits are headed "commits, as GitHub lists them (not verified; authors are GitHub's attribution)", with "the newest 100 of N; all of them at <compare_url>" when cut. `too_large` prints "too large to list here: <compare_url>". An unknown state is printed as its reason, never as "no commits".
  - `landfall releases <DEPLOYMENT> [--limit <N>]` → `listReleases`.
  - `landfall why <DEPLOY_ID>` → `whyDeploy`: the summary, the events, and `next`.
  - `landfall hosts [<HOST>]` → `listHosts` or `getHost`.
  - `landfall audit [--deployment <ID>] [--host <ID>] [--kind <KIND>] [--limit <N>]` → `listAudit`.
  - `landfall approvals` → `listApprovals`: each request with its intent and `approve_url`, and the line from the Rulings.
- `read::run_with<A: Api>(command: &ReadCommand, client: &A, out: &mut dyn Write, json: bool) -> Result<(), CliError>` runs over `pub trait Api`, so tests can use a fake. Its two methods mirror `ApiClient`'s and return `impl Future<Output = Result<serde_json::Value, ApiError>> + Send`. It is used generically, never as `&dyn Api`: a method returning `impl Future` isn't dyn-compatible, and `async-trait` would be a new dependency. `render.rs` has one `pub(crate) fn` per view, taking the `landfall-api` type and `&mut dyn Write`, with every server string through `display::safe` or `safe_lines`.
- `cli.rs`: these commands' `--help` gives the exit statuses from the Rulings.

- [ ] **Step 1: Failing tests.**
  - In `read/tests/render.rs`:
    - `hostile_text_is_escaped_in_human_output`: a release story whose commit summary holds `\x1b]0;owned\x07`, an author with `\r`, a check name with `\u{9b}2J` and a host reason with `\u{202e}`. None of those bytes appears in the output; each is escaped.
    - `status_line_shows_needs_you`.
    - `story_heads_commits_as_unverified_and_says_how_many`.
    - `unknown_commit_state_is_not_printed_as_none`.
    - `too_large_prints_the_link_and_no_list`.
    - `why_prints_summary_events_and_next`.
    - `unknown_status_prints_unknown`.
  - In `read/tests/commands.rs`, with a fake `Api` recording calls:
    - `status_pages_until_done`: two pages, one call each.
    - `status_stops_at_1000_items_or_20_pages_and_says_so`.
    - `a_repeated_cursor_stops_paging`.
    - `each_command_calls_its_operation`: a table from command line to method and path.
    - `refused_exits_1_and_unreachable_exits_2`.
    - `json_passes_new_fields_and_values_through`: a body with an extra field and a status of `"teleporting"` comes out with both, unchanged.
  - In `cli/tests.rs`: `every_cli_call_is_in_the_openapi_document` (each method and path in the table above, with parameters as `{…}`, is an operation of `include_str!` of `docs/api/openapi.json`) and `help_documents_the_exit_statuses`.

  Expected: FAIL.
- [ ] **Step 2: Implement.** Run: `cargo nextest run -p landfall-cli`. Expected: PASS.
- [ ] **Step 3: Gate; `docker build .` (the binaries stage); security review of PR D. Commit:** `feat(cli): status, history, release stories, why, hosts and audit`. Open PR D.

## PR E: asking from the CLI, end to end, and the guide

### Task 11: Requesting a deploy or a rollback, and cancelling

**Files:** Create `crates/cli/src/ask.rs`, `crates/cli/src/ask/tests.rs`, `crates/server/src/requests/tests/rollback_flag.rs`. Modify `crates/server/src/requests/tests.rs` (`mod rollback_flag;`), `crates/server/src/api/tests/document.rs` (`approvals_json_is_unchanged` expects `approve_url` too), `crates/cli/src/lib.rs` (`pub mod ask;`), `crates/cli/src/cli/tests.rs` (`every_cli_call_is_in_the_openapi_document` gains `requestDeploy` and `cancelRequest`), `crates/api/src/requests.rs` (`NewRequest.rollback`, `RequestView.approve_url`), `crates/api/src/problem.rs` (`ProblemCode::NotARollback`), `crates/server/src/requests.rs` (`view` fills `approve_url`), `crates/server/src/requests/asking.rs`, `crates/server/src/auth/problem.rs` (`NotARollback`), `crates/server/src/api/tests/grants.rs` (the `rollback` case sends the flag), `crates/cli/src/cli.rs`, `docs/api.md`, `docs/api/openapi.json`.

**Interfaces:**
- `NewRequest { tag: ReleaseTag, #[serde(default, skip_serializing_if = "is_false")] rollback: bool }`, still with `deny_unknown_fields`. In `asking`, once the running release is known and before `RequestOpen` and `cancel_open_request` are considered: with `rollback`, a tag that isn't lower than what runs is `HumanProblem::NotARollback` (`409 not_a_rollback`, "this release is not lower than what runs, so it is not a rollback"). So is any tag when nothing runs or the running tag doesn't parse as a version. It is audited as `request_refused`, like the others, and nothing else changes in that transaction.
- `RequestView.approve_url: Option<String>`: `format!("{}/approvals", origin)` from `[approval]`, else `None`, on every answer that carries a `RequestView`.
- Commands:
  - `landfall request deploy <DEPLOYMENT> <TAG>` → `requestDeploy` with no flag.
  - `landfall rollback <DEPLOYMENT> <TAG>` → `requestDeploy` with `rollback: true`.
  - `landfall cancel <REQUEST_ID>` → `cancelRequest`.

  Each prints the request's id, state, intent fields and `expires_at`. For an open request it then prints `An approver signs this at <approve_url> with their passkey. Agents can't approve.`, or, with no `approve_url`, `This controller has no [approval] settings, so nobody can approve yet.`. A `bad_request` answer to `rollback` adds that an older controller may not know the flag. `ask::run_with<A: Api>(command: &AskCommand, client: &A, out: &mut dyn Write, json: bool) -> Result<(), CliError>`.

- [ ] **Step 1: Failing tests.**
  - In `requests/tests/rollback_flag.rs`:
    - `rollback_flag_with_a_higher_tag_is_refused_and_audited`.
    - `rollback_flag_on_a_first_deploy_is_refused`.
    - `rollback_flag_with_an_unparseable_running_tag_is_refused`.
    - `not_a_rollback_leaves_an_open_request_open`: an open request is neither cancelled nor replaced.
    - `rollback_flag_with_a_lower_tag_needs_the_rollback_grant`.
    - `no_flag_keeps_plan_05s_behaviour`.
    - `unknown_body_field_is_still_refused`.
    - `approve_url_follows_the_configured_origin_and_is_null_without_one`.
  - In `ask/tests.rs`, with a fake `Api`:
    - `request_prints_where_to_approve`.
    - `request_deploy_sends_no_rollback_field`.
    - `rollback_sends_the_flag`.
    - `not_a_rollback_exits_1_with_its_code`.
    - `request_open_exits_1_naming_the_open_request`.
    - `cancel_calls_cancel`.
    - `no_approval_settings_says_nobody_can_approve`.
  - In `cli/tests.rs`: `every_cli_call_is_in_the_openapi_document` gains the rows for `request deploy`, `rollback` and `cancel`.

  Expected: FAIL.
- [ ] **Step 2: Implement; update the `CASES` rows; regenerate.** Run: `cargo nextest run -p landfall-server -p landfall-cli`. Expected: PASS, with `requests/tests` unchanged except for the new field.
- [ ] **Step 3: Gate. Commit:** `feat(cli): request a deploy or a rollback, and cancel a request`.

### Task 12: The CLI against a real controller, and the guide

**Files:** Create `crates/cli/tests/controller/main.rs`, `crates/cli/tests/controller/harness.rs`, `crates/cli/tests/controller/flow.rs`. Modify `crates/cli/Cargo.toml` (dev-dependencies: `landfall-server`, `landfall-approval` with `test-support`, `tempfile`), `docs/operations.md`, `docs/design/landfall.md`, `docs/api.md`, `README.md`, `AGENTS.md`.

**Interfaces:**
- `harness.rs` runs a real controller in the test's runtime: `landfall_server::serve::run` on `127.0.0.1:0`, over `landfall_server::router`, with a store in a temp directory. The configuration has `app/prod` on `home-1`, `[approval]` at `https://landfall.example.com`, an approver `operator` whose `[approvers]` key is a `SoftwareAuthenticator`'s, and grants for `ci` (`view`, `request` and `rollback` on `app/prod`) and `reader` (`view` on `app/prod`), each with a token from `Store::create_token`. Releases and running state are written through the store's own functions (`record_release`, `record_host_state`), as the server's tests do: no agent and no network. The operator's session is obtained for real, with no new server feature (`begin_session_for_test` is crate-private and test-only): an invite from `Store::issue_passkey_invite`, then registration and sign-in over HTTP through the web routes, with the `SoftwareAuthenticator` signing for the configured origin and each request carrying `Origin: https://landfall.example.com`. The session cookie comes from the sign-in answer. The CLI runs through `cli::run_with`, with an `Env` holding `LANDFALL_TOKEN`, buffers for `out` and `err`, the real `ApiClient`, `http://127.0.0.1:<port>` and `--allow-insecure-controller`.

- [ ] **Step 1: Write the tests** in `flow.rs`:
  - `an_agent_finds_a_waiting_release_and_asks`, as `ci`: `status` shows `app/prod` with `v1.3.0` as `needs_request`; `release app/prod v1.3.0` shows it, with its commit state; `request deploy app/prod v1.3.0` exits 0 and prints the approval URL; `approvals` lists it with `can_approve` false.
  - `the_operator_approves_and_why_explains`: the operator registers and signs in as the harness describes, and the approval is made with the software authenticator through `POST /api/v1/approvals/{id}` with that session, and a report of a rolled-back deploy is recorded through the store. `history` lists the deploy; `why <id>` says it rolled back and names `request` as next; `release` says `failed`.
  - `a_reader_can_read_and_not_ask`: as `reader`, `status` works and `request deploy` exits 1 with `forbidden`.
  - `rollback_of_a_higher_tag_exits_1_with_not_a_rollback`.
  - `a_revoked_token_exits_2`, with `unauthenticated`.
  - `json_output_parses_as_the_api_types`: each read command's `--json` output parses into its `landfall-api` type.

  Run: `cargo nextest run -p landfall-cli --test controller`. Expected: PASS.
- [ ] **Step 2: Docs.**
  - `docs/operations.md`: a new section, "The `landfall` command", after "API tokens, requests and approvals". It covers the settings and where each is read from; the token's rules and why it never goes in argv; that no proxy is used; warden (no token, a proxy URL, `agents_via_warden`); the transport rule; `--json` for agents and the exit statuses; the read budget and the `Sec-Fetch-Site` rule; and what an agent can and can't do (it can't approve). "From nothing to a first deploy" step 6 becomes `landfall request deploy app/prod v1.2.3`, with the token in `LANDFALL_TOKEN`, and step 7 says `landfall approvals` prints where to sign. The opening line about no `landfall` command for approvals changes to say the assertion is made on the page.
  - `docs/api.md`: complete; the grant table and `x-landfall-grant`; the audit rule and its allow-list; global ids; the commits caveats.
  - `docs/design/landfall.md`:
    - Section 9: what's built (`status`, `why`, `request deploy`, `rollback`, `hosts` and the rest); that `logs` is plan 08; and that `landfall approve` is plan 09, with the assertion still made on the page.
    - Section 10: only what exists today, the agent's `dev.landfall.*` labels, with plan 08 deciding the final names and adding the deploy id.
    - Section 12: a row for a stolen agent token reading state. Mitigations: `view` shows only what it grants, the read budget, and controller-wide audit rows staying off the API. Residual: global ids show how much happened elsewhere.

    Section 8.3 was already amended with this plan.
  - `README.md`: the CLI in the overview, with a two-line example.
  - `AGENTS.md`: the crate map (`landfall-api`; the server's `api` module and its files; the CLI's `settings`, `api_client`, `display`, `read` and `ask`), and that `docs/api/openapi.json` is regenerated, never edited.
- [ ] **Step 3: Full gate; Linux (`landfall-agent` tests, as Task 5 touched its e2e); `docker build .`; security review of PR E. Commit:** `test(cli): the CLI against a real controller; docs`. Open PR E.

---

## Self-review

- **Spec coverage.**
  - Section 1 (agents see state, investigate, request, never approve): Tasks 4, 6, 7, 10 and 11. Approving stays on the page, and its URL is printed (Task 11).
  - Section 8.2 (grants per principal and deployment, `approve` human only): the document's `security`, `x-landfall-grant` and Task 2's grant test, plus the visibility rule in every read task.
  - Section 8.3 (audit through the API): Task 8, with controller-wide rows kept off the API, never readable with a token, and the spec amended to say so.
  - Section 8.4 (warden): no token is sent when none is set, and no proxy is used (Task 9); documented in Task 12.
  - Section 9: REST, JSON, `/api/v1`, and OpenAPI 3.1 generated from code at `/api/v1/openapi.json` (Task 1); problem+json with stable codes (Task 1); cursor pagination (Task 2); deployments, releases with their origin story, deploys with steps and checks, approvals, hosts and audit events (Tasks 4, 6, 7 and 8); `GET /api/v1/deploys/{id}/why` (Task 7); CLI `status`, `why`, `request deploy`, `rollback` and `hosts` (Tasks 10 and 11).
  - Not here: `logs` and section 10 are plan 08, with the reasons in the Rulings; `landfall approve` is plan 09.
- **The owner's wants:**
  - A pipeline per repo and per host: `listDeployments` filters and `HostView`.
  - Clicking a version to see why it did or didn't deploy, and which commits it holds: Tasks 5 and 6.
  - An agent-first, typed OpenAPI: Tasks 1 and 2, and `landfall-api`.
  - Grants per repo and host: through deployments (Rulings).
  - Locked down: Global Constraints, Task 3, Review Focus.
  - A CLI: Tasks 9 to 11.
  - Later, and named in the next plans: triggering a push, canaries, staging on another address, many hosts and cloud.
- **The review:** each Important finding has a named test in the table above, and every Minor is applied. The owner's later ruling chose an exact commit list over a patch-free one: Task 5 uses compare, bounded per page and per tick, and a range too large is a link, never a partial list shown as whole.
- **Types:**
  - `ReleaseStatus` is declared in Task 4 and computed in Task 6.
  - `Outcome`, `NextAction` and `NextKind` are declared in Task 6 and used in Task 7.
  - `RunningRow` (Task 4's `store/views.rs`) and the store's existing `Hold` feed Task 6's `StoryInputs`.
  - `DeploymentRef` and `shown_deployment` (Task 4) are used by Tasks 6 and 8.
  - `Page<T>` (Task 1), and `Cursor`, `CursorList`, `ApiQuery` and `Limit` (Task 2), are used by Tasks 4, 6, 7 and 8.
  - `World` and `CASES` (Task 2) are extended by Tasks 4, 6, 7, 8 and 11.
  - `ComparePage`, `compare_url` and `base_for` (Task 5) are used by Task 6.
  - `Api` (Task 10) is reused by Task 11.
  - `ProblemCode::NotARollback` is added in Task 11 with `HumanProblem::NotARollback`, and `every_problem_code_is_in_the_schema` holds them together.
- **File sizes:** reads go in new files (`store/views.rs`, `store/history.rs`, `store/commits.rs`, `api/*.rs`, `watcher/commits.rs`). `requests.rs` loses `request_number` and `visibility` to `api/`; `store.rs` and `watcher.rs` gain only module lines and trait methods; the tick's one call is in `watcher/ticking.rs`. Each test file covers one scenario.
- **Proportion:** twelve tasks in five PRs, with interfaces and test names only. The one exception is the audit query's shape, on which both the index rule and the visibility rule depend.

## Open questions

None left for the owner. The controller-wide audit rows question was settled: they aren't readable through the API in plan 07, and never with a token (spec 8.3).
