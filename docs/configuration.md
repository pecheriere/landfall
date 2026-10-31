# Configuration

landfall reads one TOML file per fleet. Keep it in a git repository you review
by pull request, and deploy the same file to the controller and to every agent.
Nothing generates or rewrites it. Each agent uses only its own host's
deployments. The file must be UTF-8. The controller and agents compare the
SHA-256 of the exact file bytes (so a whitespace change is a different hash); a
mismatch is an error on every affected deployment and blocks deploys there.

Every table is strict: an unknown key is an error, never ignored.

## Example

```toml
[signers]
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyOnly"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = [{ http = "/health", network = "app", expect = 200 }]
backup = { paths = ["state"], stop = true }

[[deployment]]
id = "app/staging"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app-staging", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "any", approvers = ["operator"] }
checks = ["container-healthy"]
promote_to = { deployment = "app/prod", healthy_for = "24h" }

[[grant]]
principal = "operator"
deployments = ["app/prod", "app/staging"]
can = ["view", "request", "approve", "rollback"]
```

## `[signers]`

A table of `name = "<ssh public key>"`. Names are `[a-z0-9][a-z0-9-]{0,62}`.
These are the keys allowed to sign release tags.

## `[approvers]`

A table of `name = { credential_id, public_key }`, both opaque base64url text
(a WebAuthn credential id and its COSE public key). Names follow the same
pattern as signers.

## `[[deployment]]`

| Key | Type | Default | Meaning |
|---|---|---|---|
| `id` | string | required | `<name>/<stage>`, each part `[a-z0-9][a-z0-9-]{0,62}`. Unique. |
| `repo` | table | required | `name` (`<owner>/<repo>`), `id` and `owner_id` (GitHub numeric ids, integers). |
| `host` | string | required | Host that runs it, `[a-z0-9][a-z0-9-]{0,62}`. |
| `compose.dir` | string | required | Absolute, canonical directory of the compose project: no trailing or doubled `/`, no `.` or `..` component (so one directory has one spelling). |
| `compose.service` | string | required | Service name, `[a-z0-9][a-z0-9_.-]*`. |
| `origin.workflow` | string | required | Release workflow, exactly `.github/workflows/<name>.yml` or `.yaml`, with `<name>` non-empty `[A-Za-z0-9._-]+` (no subdirectory). |
| `origin.tags` | string | required, no default | Release tag pattern: a prefix of up to 32 `[A-Za-z0-9._/-]` and a final `*`, for example `v*` or `*`. The prefix must not end with a digit or `.` (with `v1*`, `v12.0.0` would read as `2.0.0`). The rest of the tag must be strict semver without build metadata. |
| `origin.signers` | list | required | Keys of `[signers]` trusted for this deployment; at least one. |
| `rule.auto` | `"patch"`, `"minor"` or `"any"` | none | Deploy without a human when the new version is higher than the running one and differs by at most this part. |
| `rule.approve` | `"patch"`, `"minor"` or `"any"` | none | Versions up to this level need a passkey approval. |
| `rule.approvers` | list | required | Keys of `[approvers]` who may approve; at least one. |
| `rule.prereleases` | bool | `false` | Whether prerelease versions are eligible. |
| `checks` | list | required | Post-deploy checks; at least one (see below). |
| `backup.paths` | list | required if `backup` | Paths relative to `compose.dir`, non-empty and canonical (no leading, trailing or doubled `/`, no `.` or `..` component). |
| `backup.stop` | bool | `true` | Stop the service while copying. |
| `promote_to.deployment` | string | required if `promote_to` | Deployment to promote to; it must have the same `repo.id`. |
| `promote_to.healthy_for` | string | required if `promote_to` | How long this deployment must stay healthy: `<n>m`, `<n>h` or `<n>d`, `n` above zero. |

Anything outside `auto` and `approve` (major releases by default) is manual: a
grant holder requests it and an approver approves it.

Release tags themselves (whatever the pattern) are at most 128 bytes of
`[A-Za-z0-9._/+-]` and must be valid git ref names: no `..`, no empty
component (leading, trailing or doubled `/`), not starting with `-`, no
component starting with `.` or ending with `.lock`, not ending with `.`.

### Checks

Each entry is the string `"container-healthy"` or a table with exactly one of
`http`, `command` or `no_log_match`:

- `"container-healthy"`: the container's Docker healthcheck reports healthy.
  The image must define a healthcheck; if it defines none, the check fails at
  deploy time.
- `{ http = "/health", network = "app", expect = 200 }`: an HTTP probe from
  inside a Docker network. The path starts with `/` and contains only visible
  ASCII (no spaces or control characters); the network matches Docker's
  network name grammar `[A-Za-z0-9][A-Za-z0-9_.-]*`, at most 128 bytes;
  `expect` is a status code from 100 to 599.
- `{ command = ["/app", "healthcheck"] }`: a command run in the container,
  exit 0 is healthy; non-empty argv.
- `{ no_log_match = "panicked", within_secs = 30 }`: no log line may contain
  the text during the window. It is a plain substring match, not a regex. Both
  values are non-empty and above zero.

`no_log_match` does not observe the service on its own, so every deployment
also needs at least one of `"container-healthy"`, `http` or `command`.

## `[[grant]]`

| Key | Type | Meaning |
|---|---|---|
| `principal` | string | Who. |
| `deployments` | list | Deployment ids the grant applies to; at least one. |
| `can` | list | Any of `"view"`, `"request"`, `"approve"`, `"rollback"`; at least one. |

Several grants for the same principal combine: the principal may do each
listed action on each listed deployment of every one of its grants.

## Validation rules

The file is refused, with an error naming the deployment and the value, when:

1. two deployments share an `id`;
2. `origin.signers` is empty or names a signer not in `[signers]`;
3. `rule.approvers` is empty or names someone not in `[approvers]`. It is
   required for every deployment, even fully automatic ones: first deploys and
   downgrades are manual and always need an approval;
4. both `auto` and `approve` are set and `approve` is not broader than `auto`
   (`patch` < `minor` < `any`);
5. `checks` is empty, or contains no check that observes the service (only
   `no_log_match` entries; add `"container-healthy"`, `http` or `command`);
6. `promote_to` names a deployment that does not exist, the deployment itself,
   a deployment with a different `repo.id`, or closes a cycle of promotions
   (the error lists the cycle, for example `app/staging -> app/prod ->
   app/staging`);
7. a grant has an empty `deployments` or `can`, names a deployment that does
   not exist, or gives `approve` to a principal not in `[approvers]`;
8. two deployments on one host use the same `compose.dir` and `compose.service`.

Malformed values are refused too, naming the deployment, the key and the
value: relative or non-canonical paths, an `origin.workflow` outside
`.github/workflows/`, an `origin.tags` prefix ending in a digit or `.`, a bad
`healthy_for`, an http check with a bad path, network or status, and an
unknown or ill-formed check. Check errors name the entry, for example
`checks[2]` (or `checks[2].network` for a bad value), and the keys found in it.
