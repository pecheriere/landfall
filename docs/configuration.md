# Configuration

landfall reads one TOML file per fleet. Keep it in a git repository you review
by pull request, and deploy the same file to the controller and to every agent.
Nothing generates or rewrites it. Each agent uses only its own host's
deployments. The controller and agents compare the SHA-256 of the file bytes; a
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
| `origin.workflow` | string | required | Release workflow, `.github/workflows/<name>.yml` or `.yaml`, canonical (no `.` or `..` component). |
| `origin.tags` | string | required | Release tag pattern: a prefix and a final `*`, for example `v*`. The rest of the tag must be strict semver without build metadata. |
| `origin.signers` | list | required | Keys of `[signers]` trusted for this deployment; at least one. |
| `rule.auto` | `"patch"`, `"minor"` or `"any"` | none | Deploy without a human when the new version is higher than the running one and differs by at most this part. |
| `rule.approve` | `"patch"`, `"minor"` or `"any"` | none | Versions up to this level need a passkey approval. |
| `rule.approvers` | list | required | Keys of `[approvers]` who may approve; at least one. |
| `rule.prereleases` | bool | `false` | Whether prerelease versions are eligible. |
| `checks` | list | required | Post-deploy checks; at least one (see below). |
| `backup.paths` | list | required if `backup` | Paths relative to `compose.dir`, non-empty and canonical (no leading, trailing or doubled `/`, no `.` or `..` component). |
| `backup.stop` | bool | `true` | Stop the service while copying. |
| `promote_to.deployment` | string | required if `promote_to` | Deployment to promote to. |
| `promote_to.healthy_for` | string | required if `promote_to` | How long this deployment must stay healthy: `<n>m`, `<n>h` or `<n>d`, `n` above zero. |

Anything outside `auto` and `approve` (major releases by default) is manual: a
grant holder requests it and an approver approves it.

### Checks

Each entry is either the string `"container-healthy"` (the container's Docker
healthcheck) or a table with exactly one of:

- `{ http = "/health", network = "app", expect = 200 }`: an HTTP probe; the path
  starts with `/`.
- `{ command = ["/app", "healthcheck"] }`: a command; non-empty argv.
- `{ no_log_match = "panicked", within_secs = 30 }`: the logs must not match
  the pattern during the window; both non-empty and above zero.

## `[[grant]]`

| Key | Type | Meaning |
|---|---|---|
| `principal` | string | Who. |
| `deployments` | list | Deployment ids the grant applies to. |
| `can` | list | Any of `"view"`, `"request"`, `"approve"`, `"rollback"`. |

## Validation rules

The file is refused, with an error naming the deployment and the value, when:

1. two deployments share an `id`;
2. `origin.signers` is empty or names a signer not in `[signers]`;
3. `rule.approvers` is empty or names someone not in `[approvers]`. It is
   required for every deployment, even fully automatic ones: first deploys and
   downgrades are manual and always need an approval;
4. both `auto` and `approve` are set and `approve` is not broader than `auto`
   (`patch` < `minor` < `any`);
5. `checks` is empty;
6. `promote_to` names a deployment that does not exist, the deployment itself,
   or closes a cycle of promotions;
7. a grant names a deployment that does not exist, or gives `approve` to a
   principal not in `[approvers]`;
8. two deployments on one host use the same `compose.dir` and `compose.service`.

Malformed values (relative or non-canonical paths, a bad `healthy_for`, an
unknown or ill-formed check) are refused too; check errors name the entry,
for example `checks[2]`, and the keys found in it.
