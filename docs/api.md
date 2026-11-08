# The landfall API

The controller's API for people and their agents is under `/api/v1`. It is described by an
OpenAPI 3.1 document, [`api/openapi.json`](api/openapi.json), which the controller generates
from its own routes, so the two can't disagree. A controller serves the same bytes at
`GET /api/v1/openapi.json`, with no credentials, and `landfall-server openapi` prints them.
A test fails when the checked-in copy differs; to regenerate it:

```sh
cargo run -p landfall-server -- openapi > docs/api/openapi.json
```

How to make a token and ask for a first deploy is in
[`operations.md`](operations.md#api-tokens-requests-and-approvals). The `landfall` command is a
client of this API, and [its section there](operations.md#the-landfall-command) says how it finds
the controller and its token; its `--json` prints these answers as they were received.

## Authentication

Every operation but the document itself takes credentials, before it reads anything else.
There are two kinds, the document's two security schemes:

- `token`: an API token from `landfall-server token create`, sent as
  `Authorization: Bearer <token>`. A token is for a program or an agent, and never approves.
- `session`: the `__Host-landfall-session` cookie that a passkey sign-in on the controller's
  own pages sets. A state change with a session must also send the configured `[approval]`
  origin as `Origin`, or it is refused with `403 bad_origin`. A read with a session is refused
  the same way when it carries a `Sec-Fetch-Site` that is anything but `same-origin` or `none`,
  or carries it twice. A browser sends that header itself, and `SameSite=Strict` doesn't stop a
  page on a sibling subdomain from sending the cookie with a `GET`, as that is the same site.
  A client that isn't a browser sends no such header and is read as usual. A token is never
  checked for either.

A call refused for where it came from costs nothing from a budget, and writes no row of its own:
it is counted, with a bad `Origin`, in one `access_refused` audit row each watcher interval.

No answer carries a CORS header, so a page on another origin can't read one.

## Budgets

Each credential has two budgets: one for state changes and one for reads, so that neither can
use up the other. Each session has its own, and all of a principal's tokens share one.

| | At once | Refills |
|---|---|---|
| State changes (`POST`) | 120 | 1 a second |
| Reads (`GET`) | 300 | 10 a second |

A `landfall` command makes at most three calls, but for `status` with no deployment, which reads
at most 20 pages, 1,000 deployments or 8 MiB of answers, and a page polls every few seconds, so
neither comes near the read budget; an agent sweeping a large fleet may, and waits. Over a budget, a call gets
`429 rate_limited` with `Retry-After` in seconds (1 for a read, 5 for a state change), and
writes nothing. The count of those goes in an `access_throttled` audit row: for state changes, at
the next state change within the budget, within one watcher interval, or when the controller
stops, whichever is first; for reads, with `"reads": true`, within one watcher interval or when
the controller stops, so that a read never writes. The budgets are kept in memory, so a restart
gives them back.

## Grants

Each operation's `security` lists, under each scheme, the roles that may call it. A role is
one of the configuration's grants on the deployment concerned (`view`, `request`, `approve`,
`rollback`), or `requester`, for whoever asked for the request at hand. Any one role in the
list is enough. An empty list means any authenticated principal, and the answer then holds
only what they may see.

| Operation | Token | Session |
|---|---|---|
| `getOpenApi` | public | public |
| `listApprovals` | any, filtered by `approve` or `view` | the same |
| `whoAmI` | any | the same |
| `listDeployments` | any, filtered by `view` | the same |
| `getDeployment` | `view` | `view` |
| `listReleases` | `view` | `view` |
| `getRelease` | `view` | `view` |
| `listDeploys` | `view` | `view` |
| `getDeploy` | `view` | `view` |
| `whyDeploy` | `view` | `view` |
| `listHosts` | any, filtered by `view` | the same |
| `getHost` | `view` | `view` |
| `listAudit` | any, filtered by `view` | the same |
| `requestDeploy` | `request`, `rollback` | `request`, `rollback` |
| `approveRequest` | never | `approve` |
| `cancelRequest` | `requester`, `rollback` | `requester`, `approve`, `rollback` |

Where the request itself decides which role applies, the operation says so in
`x-landfall-grant`, mapping each role to the case it governs. `requestDeploy` has:

```json
{
  "request": "a tag above what runs, or the first deploy",
  "rollback": "a tag below what runs"
}
```

A principal with no grant at all on a deployment is told `404 not_found`, the same as for a
deployment that doesn't exist. One with some other grant there is told `403 forbidden`.
A deployment a principal can't view is never named to them, not even where another
deployment's view would: a promotion to or from one reads `"deployment": null, "unseen": true`,
and a reason about one says "a deployment you can't view". Nor is it told how many there are:
`promoted_from` lists those the principal may view, by id, then at most one such marker for all
the others, with the longest `healthy_for_secs` among them.

## Who am I, and deployments

`whoAmI` (`GET /api/v1/me`) names the principal, says whether it came by `token` or `session`,
and lists each deployment they hold a grant on with what they may do to it now, by this
credential. A token never lists `approve`, even for an approver. `approve_url` is where an
approver signs a request with a passkey: the configured `[approval]` origin and `/approvals`.

`listDeployments` (`GET /api/v1/deployments`) lists the deployments of the configuration that
the principal may view, by id, a page at a time. `host`, `repo` and `needs_you` keep only those
that match. Each shows what its host last said (`running`), its request waiting for an approver
(`open_request`) and `needs_you`, whether that request is one this principal could sign. A token
never approves, so `needs_you` is always `false` for a token, and `needs_you=true` lists nothing
for one. `latest` is its newest release, the first `listReleases` shows, with where it stands,
or `null` when the controller has recorded none. The controller keeps each deployment's newest
release as it records releases, so a page costs the same however long the histories are.

`getDeployment` (`GET /api/v1/deployments/{name}/{stage}`) adds the rule, where its releases go
on to (`promote_to`) and come from (`promoted_from`), and its holds: the newest 50, with
`holds_total` counting all of them.

`running` is what the deployment's host, as the configuration has it now, last reported. A
report from a host the configuration no longer pairs with the deployment is ignored, as the
watcher ignores it, so a deployment moved to a host that hasn't reported it shows `null`.

## Releases and their story

`listReleases` (`GET /api/v1/deployments/{name}/{stage}/releases`) lists the releases the
controller recorded for a deployment, each with its `status`, the `decision` the watcher last
recorded, when it was first recorded (`first_seen_at`) and when it was last verified
(`seen_at`). It is in the order of semantic versions, highest first, by the deployment's tag
pattern, where a pre-release is below its release; tags the pattern doesn't read come last, in
string order. No index holds that order, so each page sorts the deployment's releases in memory:
at most 5,000 of them, the bound the watcher keeps on a deployment's tags, and those first
recorded most recently when there are more, which an index gives without sorting its whole
history.

`getRelease` (`GET /api/v1/deployments/{name}/{stage}/releases/{tag}`) is a release's story. A
tag holding `/` is sent with it as `%2F`, and a tag the controller hasn't recorded is
`404 not_found`. The story has:

- `release`, as the list shows it;
- `reasons`, why it stands where it does, in order, and `next`, the one thing to do next: its
  `kind` (`request`, `rollback`, `approve`, `wait`, `fix_host`, `recover` or `none`) and a
  `detail` in the controller's words, such as the command to run;
- `origin`, where it came from as the controller verified it: the release commit, the digest,
  the tag's signer, the attestation's workflow identity and run, and its transparency-log
  entry. It is `null` unless the release verified and hasn't been refused since;
- `commits`, below;
- its newest 20 requests and its newest 20 deploys, newest first.

`reasons` quote stored text: a hold's reason, a host's reason for a deploy's outcome, and the
watcher's reason for its decision where that reason is what decided, such as a refusal by
verification. Otherwise a decision is put in the rule's words, so that a reason recorded
before something changed is never shown, and a deployment the principal can't view is never
named: it reads "a deployment you can't view". Like every text from GitHub or a host, escape
it before showing it.

A release's `status` is the first of these that applies:

1. `running`: its host runs this tag at this digest.
2. `deploying`: a deploy of it is queued or claimed.
3. `awaiting_approval`: a request for it waits for an approver. `next` says where an approver
   signs it; agents can't.
4. `refused`: verification refused it, or the rule does with what runs now.
5. `held`: something it needs couldn't be read yet, for it or the whole deployment. The
   controller tries again by itself.
6. `superseded`: a higher version runs. When asking is how it would deploy, `next` is a
   `rollback`, through `landfall rollback`.
7. `failed`: its last deploy rolled back, failed with nothing to go back to, or failed and so
   did going back. It isn't tried again by itself: a request is how to try again.
8. `host_refused`: its host refused its last deploy.
9. `deferred`: its host said not now, and is asked again after a while.
10. `promotion_pending`: it waits to be reported healthy for long enough on the deployment it
    is promoted from, which is named only to a principal who may view it.
11. `needs_request`: it deploys only when someone asks; `next` is always a `request`.
12. `waiting`: it deploys by itself, and nothing known stands in the way.

A status goes by verification, then by what the rule says with what runs now. What the watcher
recorded from a release's past deploys shows in the status from the deploys themselves: so a
release the rule would deploy by itself, which the watcher won't try again after a failed
deploy, needs a request, as asking allows.

## Commits between releases

The controller keeps the commits between each verified release and the one below it, for a
release's story to show. Both ends must be releases verified under the current configuration
and not refused since: a refused or unsigned tag gets no list and is never the start of one.
The start is the highest lower version of the same deployment, where a pre-release is below
its release. A list is kept by repository and commit, not by tag, so a moved tag is compared
again from its new commit, and two deployments of one repository share one list.

- **Source.** The list is GitHub's compare (`GET /repos/{repo}/compare/{base}...{head}`), which
  is exact: every commit reachable from the release and not from the one below it, merged
  branches included. It says `"source": "github"`.
- **Author.** Each commit keeps its id, the first line of its message (200 characters,
  quoted) and the login GitHub attributes it to by its email. Nothing verifies that login, so
  it says `"verified": false`; only the release commit itself is verified.
- **The newest 100.** A list keeps the newest 100 commits, newest first, and GitHub's total,
  so a longer one reads as the newest 100 of N and never as the whole.
- **`too_large`.** When a page of GitHub's answer is over 8 MiB, or GitHub says the comparison
  is too large to compute (422), there is no list, only a link to GitHub's compare page,
  `https://github.com/{repo}/compare/{base}...{head}`, built from the configured repository
  name and the two commit ids.
- **`base_not_found`.** When the release below isn't an ancestor of this one (GitHub says
  `behind` or `diverged`), the history was rewritten between them, and there is no list.
- **Not yet, or unavailable.** A list that wasn't fetched yet, or couldn't be, is unknown, never
  an empty list. A failure is tried again after an hour; it holds and refuses nothing.
- **In a story.** `commits` has `source` (`github`), `verified` (always `false`), `state`,
  `base` (the release below, where the list starts), `total`, `compare_url` and `commits`. Only
  `listed` carries commits, newest first: all of them when `total` is their count, else the
  newest 100 of `total`, which `reasons` also says. `first` means no verified release is below
  it. `too_large`, `base_not_found`, `not_yet` (not fetched yet), `unavailable` (tried, and
  tried again later) and `not_recorded` (never fetched: the release isn't verified under this
  configuration, or was recorded before the controller compared commits) carry none, and mean
  unknown, not empty. `compare_url` is GitHub's page comparing the two whenever there is a
  base; `too_large` and `base_not_found` each add a line to `reasons`.
- **The budget.** Verification has GitHub first: commits are fetched only after a watcher
  tick's verifications are done. With the controller's `GITHUB_TOKEN` a tick makes at most 12
  requests, and only while GitHub reports at least 1,000 requests left; without one, at most 3,
  one list, and only while it reports at least 30. A list needs at most 3 requests, and is
  stored only once all of them came back. Once GitHub reports fewer requests left than that, or
  answers 403 or 429, no commits are asked for until its rate-limit window ends
  (`x-ratelimit-reset` or `Retry-After`, believed for a day at most), or for an hour when it
  doesn't say.
  Only releases first recorded after the controller was upgraded to this version are compared:
  nothing is fetched for the history it already had.

## Deploys, and why each ended as it did

`listDeploys` (`GET /api/v1/deployments/{name}/{stage}/deploys`) lists a deployment's deploys,
newest first, a page at a time. `getDeploy` (`GET /api/v1/deploys/{id}`) is one deploy: the
release sent (`tag`, `digest`, `commit`) and to which `host`, its `state` (`queued`, `claimed` or
`finished`) and `outcome`, its host's `reason` and `rollback_reason`, the `request` it came from
and who signed it (`approved_by`), both `null` for one the controller queued by itself, when it
was queued, taken and finished, and its `steps`. Each step has its position, its name, how long
it took, its `failure`, and its `detail` as the controller stored it, bounded: for checks, each
check with its attempts and milliseconds; for a backup, what it copied. A list gives every
deploy's steps too.

`whyDeploy` (`GET /api/v1/deploys/{id}/why`) says why a deploy ended as it did, or where it
stands if it hasn't:

- `events`, in time order: who asked (`requested`) and who signed (`approved`), for a deploy
  that came from a request, then `queued`, `claimed`, each step (`step`, or `step_failed` with
  its failure), and how it ended: `rolled_back`, `rollback_failed`, `host_refused`, `deferred`,
  or `finished` for a deploy that runs, changed nothing, or failed with nothing to go back to.
  A step has no time of its own, so its `at` is `null`;
- `summary`, one sentence to act on, naming the tag and the host;
- `next`, the one thing to do: `request` a newer release, or a retry, which an approver signs,
  after a rollback or a failure with nothing to go back to; `recover`, with
  `landfall-agent recover` on the host, after a failed rollback; `fix_host` after a refusal,
  quoting the host's reason, since a host refusing what the controller sent it is an alert;
  `wait` while it is queued or claimed, after the host said not now, or after it changed
  nothing; `none` once it runs.

An `outcome` of `null` on a deploy whose `state` is `finished` is an outcome this controller
can't read, recorded by a newer one: the deploy is still listed and shown, here and in a
release's story, and `why` says it can't explain it. The controller never sends an outcome
name its own document doesn't list.

A step's name and failure, and a host's reasons, are the host's words, quoted when they were
stored, and `events` and `summary` quote them: escape them before showing them.

A deploy's `host` is the host it was sent to, named only to a principal who may see that host,
as `getHost` and the audit log show hosts: through a deployment on it now that they may view.
A deploy made before its deployment moved to another host can have gone to a host they can't
see; its `host` is then `null`, and `why` says "a host you can't view".

Seeing a deploy takes `view` on its deployment. With no grant there, a deploy is the same
`404 not_found` as a number no deploy has, and with some other grant it is `403 forbidden`. A
deploy of a deployment the configuration no longer has is `404` to everyone, as is that
deployment's list, whatever the database still holds of it.

## Hosts and the audit log

There is no grant on a host or on the audit log: both are seen through the deployments a
principal may view.

`listHosts` (`GET /api/v1/hosts`) lists, by id, each host the configuration puts a deployment
on that the principal may view, and `getHost` (`GET /api/v1/hosts/{host}`) is one of them. A
host shows only those deployments, each as `listDeployments` shows it, and never one the
principal can't view. It says when it enrolled (`enrolled_at`, `null` if it never has), whether
its configuration differs from the controller's (`config_drift`), and when it last reported
(`last_report`): the newest report among the deployments shown, so it says nothing of when the
host last spoke of one the principal can't view. A host with no deployment the principal holds
a grant on is `404 not_found`, the same as a host no deployment names; with some other grant on
a deployment there and no `view`, `403 forbidden`.

`listAudit` (`GET /api/v1/audit`) is the audit log, newest first, a page at a time, holding:

- each row about a deployment the principal may view, whatever its kind;
- each row about a host alone, with no deployment, whose kind is `host_enrolled` or
  `config_drift`, where the principal may view a deployment the configuration puts on that host.
  Other rows about a host alone, such as `enrol_code_issued`, `enrol_refused` (which can name
  another host) and a `report_refused` with no deployment, stay on the controller;
- never a row about neither: API tokens, passkeys, sign-ins and throttling. No grant covers
  them, and a stolen token is the threat they would serve. `landfall-server audit show` reads
  them on the controller.

A deployment the configuration no longer has is in no one's view, so its rows aren't listed,
whatever the database still holds. Each entry has its `seq`, its time, its `kind`, the
`deployment` and `host` it is about, and its `detail`. There is no hash:
`landfall-server audit verify` checks the chain.

A row stays as it was written, and some rows hold words that name another deployment or host:
the watcher's reason for a release that waits for promotion names the deployment it waits on,
and a refused report names what the report claimed. So an entry never shows a row as stored:

- `host` is `null` unless the principal may see that host, by the rule `getHost` follows: a
  host's own rows are only listed then, but a deployment's row can name another host, such as one
  that signed a report of a deploy that wasn't its own, or the host the deployment was on before;
- `detail` holds only the fields its kind lists, and drops anything else the row holds. A kind
  with no list shows `{}`, and so does a kind this controller doesn't know, whose name is then
  quoted;
- a deployment a detail names, as a request's end does, is shown as a promotion's is:
  `{"deployment": "app/prod"}`, or `{"deployment": null, "unseen": true}` for one the principal
  can't view. A host it names is `null` unless they may see it;
- free text is shown where its writer can't name another deployment or host: what a host said
  of its own deploy, why verifying or fetching the deployment's own releases failed, why a request
  ended or was refused. A `rule_decision`'s reason is said again in the rule's own words when it
  is one of them, and is left out otherwise, as when the release waits for promotion: its
  `decision` says `manual`, and the deployment's view and the release's story say where it waits
  as the principal may be told. A `report_refused` row shows its reason only when it is one of
  the controller's own that name nothing: `no such deploy`, `another host's deploy`, `never
  handed out`.

Rows of `request_refused`, `approval_refused` and `cancel_refused` name who was refused, in
`by`: the principal, how they proved it, and the id of their token if they used one, never the
token. That includes a principal with no grant on the deployment at all, whom the deployment's
viewers should know is trying (spec 8.3). `deploy_requested` names who asked the same way.

A detail that isn't a JSON object, which only someone editing the database writes, reads
`{"unreadable": "..."}`, its first 256 characters quoted, rather than failing the page. A detail
holds text from hosts and GitHub: escape it before showing it.

`deployment`, `host` and `kind` narrow the page. `host` is the host's own rows and those of the
deployments the configuration puts on it. `kind` must be a name the log uses, such as
`deploy_queued`, or the request is `400 bad_request`. A `deployment` or `host` the principal
can't see gives an empty page, never `403` or `404`, so a filter says nothing of what exists.
What the principal may see is applied in the query, before the page is cut, so a page is never
short and a cursor can't reach a row outside it. The query reads each deployment and each host's
two kinds from an index of its own, at most 400 at once: a principal who may view more is
refused with `400 bad_request` and asked to filter by `deployment` or `host`.

Sequence numbers, like deploy and request numbers, are shared by the whole controller, so a gap
between two rows a principal sees is activity they can't see. That is accepted: it tells them
how much happened, never what.

## Asking for a deploy

`requestDeploy` (`POST /api/v1/deployments/{name}/{stage}/requests`) takes the tag to deploy,
`{"tag": "v1.3.0"}`, and makes the intent from the controller's own records. A tag above what
runs, or a first deploy, takes `request`; a tag below takes `rollback`, and a rollback by
someone with that grant takes the place of a request already open on the deployment.

`"rollback": true` says the request means a rollback, as `landfall rollback` sends. Then a tag
that isn't lower than what runs is refused with `409 not_a_rollback`, and so is any tag when
nothing runs or what runs isn't a version, so nobody asks for an upgrade under the `rollback`
grant's name by mistake. That is decided before an open request is looked at, so the refusal
changes nothing but its `request_refused` audit row, and, as every request does, ends the open
requests whose 24 hours have passed: an open request still in its time stays open. Without the
flag, or with it `false`, the tag alone decides, as before. A client leaves the flag out when
it is `false`, as `landfall` does, so a controller that doesn't know it, which refuses a field
it doesn't know with `400 bad_request`, is sent it only by a rollback.

Each request in an answer, from `requestDeploy` and in `listApprovals`, has `approve_url`:
where an approver signs it with a passkey, the configured `[approval]` origin and
`/approvals`, or `null` without `[approval]`. Approving takes a session; an agent's token
can't. `cancelRequest` (`POST /api/v1/approvals/{id}/cancel`) takes no body.

## Refusals

Every answer that isn't a success is `application/problem+json` (RFC 9457):

```json
{ "code": "request_open", "title": "this deployment already has a request waiting for an approver", "status": 409 }
```

Act on `code`, which never changes its meaning; the document's `ProblemCode` schema lists
every one. `title` is for people and may change. A `429 rate_limited` and a `503 busy` come
with `Retry-After`, in seconds. Each operation's `responses` lists every refusal it can give,
with the codes each status can carry. The answers operations share are the document's reusable
responses: `BadRequest` (400), `Unauthenticated` (401), `Forbidden`, `BadOrigin` and
`ReadForbidden` (403),
`NotFound` (404), `SlowRequest` (408), `BodyTooLarge` (413), `RateLimited` (429), `Internal` and
`InternalOrUnreadable` (500), and `Busy` (503).

## Paths and query strings

A query string is at most 2 KiB, and a parameter the operation doesn't take is refused with
`400 bad_request`, not ignored. An operation with no parameters refuses any query string.

An id in a path, such as a request's number, is plain digits with no leading zero. A path is
percent-decoded first, so `%31` is the same `1`. Any other way of writing a number, such as
`01`, `+1` or `1.0`, or one too large to be an id, names nothing and is `404 not_found`.

## Pages

A list that can grow comes a page at a time, as `{"items": [...], "next_cursor": ...}`. `limit`
is how many items a page holds, from 1 to 100, 50 if left out. To get the next page, send the
same request with `cursor` set to the last page's `next_cursor`; on the last page it is `null`.
A cursor is opaque: it belongs to the list that gave it, and one from another list, or one that
was changed, is refused with `400 bad_request`. A page is never short of what the principal
may see: what they may not see is left out before the page is cut, not after.

`listDeployments` is paged in order of deployment id, `listReleases` in order of version, and
`listDeploys` and `listAudit` newest first. `listApprovals` and `listHosts` aren't paged, as
the configuration bounds them: a deployment has at most one open request, and one host.

## Versions

`info.version` is the API's version, `1`, not the controller's. Within `/api/v1`, fields and
values are only added; an older CLI works with a newer controller. So a client ignores fields
it doesn't know, and reads a value it doesn't know, such as a new problem code, as unknown.
What a client sends is still refused if it has a field the controller doesn't know.

Every answer has `Cache-Control: no-store`: a success, which is `application/json`, the
document included, and a refusal.
