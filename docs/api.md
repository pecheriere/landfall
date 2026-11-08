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
  origin as `Origin`, or it is refused with `bad_origin`.

No answer carries a CORS header, so a page on another origin can't read one.

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

## Refusals

Every answer that isn't a success is `application/problem+json` (RFC 9457):

```json
{ "code": "request_open", "title": "this deployment already has a request waiting for an approver", "status": 409 }
```

Act on `code`, which never changes its meaning; the document's `ProblemCode` schema lists
every one. `title` is for people and may change. A `429 rate_limited` comes with
`Retry-After`, in seconds. The answers operations share are the document's reusable
responses: `Unauthenticated` (401), `Forbidden` (403), `NotFound` (404), `RateLimited` (429)
and `BadRequest` (400).

## Versions

`info.version` is the API's version, `1`, not the controller's. Within `/api/v1`, fields and
values are only added; an older CLI works with a newer controller. So a client ignores fields
it doesn't know, and reads a value it doesn't know, such as a new problem code, as unknown.
What a client sends is still refused if it has a field the controller doesn't know.

Every success is `application/json` with `Cache-Control: no-store`, the document included.
