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
maintainer = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKM1hoe1SDmmzbmxw5ZYTs7Vl0gw0s+eR1YJtTVyV9sn"

[approvers]
operator = { credential_id = "Y3JlZGVudGlhbA", public_key = "cHVibGljLWtleQ" }

[[deployment]]
id = "app/prod"
repo = { name = "example/app", id = 1234, owner_id = 5678 }
host = "home-1"
compose = { dir = "/srv/compose/app", service = "app" }
origin = { workflow = ".github/workflows/release.yml", tags = "v*", signers = ["maintainer"] }
rule = { auto = "patch", approve = "minor", approvers = ["operator"] }
checks = [{ http = "/health", network = "app", port = 8080, expect = 200 }]
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

Only `ssh-ed25519` keys are supported; any other key type is a configuration
error naming the signer. The value is the contents of the key's `.pub` file
(for example `~/.ssh/id_ed25519.pub`); a trailing comment is ignored. Sign
release tags with `git tag -s` and `gpg.format = ssh`. Tags signed with
OpenPGP or X.509 (`gpg.format = openpgp` or `x509`) are refused as
unsupported.

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
| `origin.signed_tags` | bool | `true` | Whether the release tag must be signed by a maintainer key. Leave it on (see below). |
| `origin.signers` | list | required unless `signed_tags = false` | Keys of `[signers]` trusted for this deployment; at least one. Must be absent or empty when `signed_tags` is `false`. |
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

### Release images

A deployment's image is `ghcr.io/<owner>/<repo>`, the `repo.name` in
lowercase, tagged with the release's version without the tag pattern's
prefix: release tag `v1.2.3` is looked up as `ghcr.io/example/app:1.2.3`, what
`docker/metadata-action` produces with `type=semver,pattern={{version}}`. The
registry tag is only a lookup hint: the attestation binds the digest to the
release.

The release workflow (`origin.workflow`) must meet every one of these rules,
which are checked against the Fulcio certificate of the attestation, not
against anything the workflow writes itself:

- It runs on the tag push: `on: push: tags: [...]`. Releases built on
  `release: published`, `workflow_dispatch` or any other trigger are refused
  (the certificate's Build Trigger must be `push`).
- It runs on a GitHub-hosted runner; self-hosted runners are refused.
- The workflow that attests is the configured one: the attestation is made by
  a step of `origin.workflow` itself. An attestation made inside a reusable
  workflow it calls is refused in v0 (the certificate's Build Config URI must
  equal its SAN).
- It attests with `actions/attest-build-provenance` and
  `push-to-registry: true`, so the bundle is stored in the registry next to
  the image.
- The image is a multi-arch index (an OCI image index or a Docker manifest
  list), published at `ghcr.io/<owner>/<repo>` with the bare version tag, the
  `v` (or other tag pattern prefix) dropped, as `docker/metadata-action`
  `type=semver` does.
- The package is public: landfall pulls anonymously.
- The release tag has no `+build` metadata: `+` is not allowed in an image
  tag, so such a release can never verify (the tag pattern refuses build
  metadata anyway).

To check a deployment's `repo` and `origin` against a real release, run
[`landfall verify`](../README.md#verifying-a-release). Hosts need a
synchronised clock (NTP): a clock running behind refuses a fresh release with
"integrated time … in the future".

### `origin.signed_tags = false`

With `signed_tags = false` landfall does not check who signed the tag. The
build attestation alone then binds the image to the release workflow and
commit, not to a maintainer, so a stolen GitHub token or a compromised
workflow can produce a deployable release. Leave `signed_tags` on unless you
accept that. Listing `origin.signers` while it is `false` is an error, never
silently ignored.

### Checks

Each entry is the string `"container-healthy"` or a table with exactly one of
`http`, `command` or `no_log_match`:

- `"container-healthy"`: the container's Docker healthcheck reports healthy.
  The image must define a healthcheck; if it defines none, the check fails at
  deploy time.
- `{ http = "/health", network = "app", port = 8080, expect = 200 }`: an HTTP
  probe. The agent connects from the host to the container's address on the
  named Docker network and the given port, with no proxy and no redirects, so
  the host must be able to reach that network (true for Docker bridge
  networks on Linux, unless a firewall forbids it). The path starts with `/`
  and contains only visible ASCII (no spaces or control characters); the
  network matches Docker's network name grammar `[A-Za-z0-9][A-Za-z0-9_.-]*`,
  at most 128 bytes; `port` is a TCP port from 1 to 65535 and is required;
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
2. `origin.signers` is empty (with `signed_tags` on), is set while `signed_tags` is `false`, or names a signer not in `[signers]`;
   a `[signers]` value is not an `ssh-ed25519` public key; two `[signers]`
   names hold the same key (the error names both);
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
8. two deployments on one host use the same `compose.dir` (the agent keeps
   overrides and backups per directory, so a directory has one deployment).

Malformed values are refused too, naming the deployment, the key and the
value: relative or non-canonical paths, an `origin.workflow` outside
`.github/workflows/`, an `origin.tags` prefix ending in a digit or `.`, a bad
`healthy_for`, an http check with a bad path, network or status, and an
unknown or ill-formed check. Check errors name the entry, for example
`checks[2]` (or `checks[2].network` for a bad value), and the keys found in it.
