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
[`operations.md`](operations.md#api-tokens-requests-and-approvals).

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

A CLI command makes at most three calls and a page polls every few seconds, so neither comes
near the read budget; an agent sweeping a large fleet may, and waits. Over a budget, a call gets
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

A step's name and failure, and a host's reasons, are the host's words, quoted when they were
stored, and `events` and `summary` quote them: escape them before showing them.

Seeing a deploy takes `view` on its deployment. With no grant there, a deploy is the same
`404 not_found` as a number no deploy has, and with some other grant it is `403 forbidden`. A
deploy of a deployment the configuration no longer has is `404` to everyone, as is that
deployment's list, whatever the database still holds of it.

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

An id in a path, such as a request's number, is plain digits with no leading zero, so one row
has one path. Any other way of writing a number, such as `01`, `+1` or `1.0`, or one too large
to be an id, names nothing and is `404 not_found`.

## Pages

A list that can grow comes a page at a time, as `{"items": [...], "next_cursor": ...}`. `limit`
is how many items a page holds, from 1 to 100, 50 if left out. To get the next page, send the
same request with `cursor` set to the last page's `next_cursor`; on the last page it is `null`.
A cursor is opaque: it belongs to the list that gave it, and one from another list, or one that
was changed, is refused with `400 bad_request`. A page is never short of what the principal
may see: what they may not see is left out before the page is cut, not after.

`listDeployments` is paged in order of deployment id, `listReleases` in order of version, and
`listDeploys` newest first. `listApprovals` isn't paged, as the
configuration bounds it: a deployment has at most one open request.

## Versions

`info.version` is the API's version, `1`, not the controller's. Within `/api/v1`, fields and
values are only added; an older CLI works with a newer controller. So a client ignores fields
it doesn't know, and reads a value it doesn't know, such as a new problem code, as unknown.
What a client sends is still refused if it has a field the controller doesn't know.

Every answer has `Cache-Control: no-store`: a success, which is `application/json`, the
document included, and a refusal.
