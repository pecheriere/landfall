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
and a reason about one says "a deployment you can't view".

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
for one. `latest` is `null` until the controller says where releases stand.

`getDeployment` (`GET /api/v1/deployments/{name}/{stage}`) adds the rule, where its releases go
on to (`promote_to`) and come from (`promoted_from`), and its holds: the newest 50, with
`holds_total` counting all of them.

`running` is what the deployment's host, as the configuration has it now, last reported. A
report from a host the configuration no longer pairs with the deployment is ignored, as the
watcher ignores it, so a deployment moved to a host that hasn't reported it shows `null`.

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

`listDeployments` is paged in order of deployment id. `listApprovals` isn't paged, as the
configuration bounds it: a deployment has at most one open request.

## Versions

`info.version` is the API's version, `1`, not the controller's. Within `/api/v1`, fields and
values are only added; an older CLI works with a newer controller. So a client ignores fields
it doesn't know, and reads a value it doesn't know, such as a new problem code, as unknown.
What a client sends is still refused if it has a field the controller doesn't know.

Every answer has `Cache-Control: no-store`: a success, which is `application/json`, the
document included, and a refusal.
