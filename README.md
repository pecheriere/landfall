# landfall

Continuous delivery for self-hosters: a signed GitHub release goes in, a
verified and healthy container comes out on your hosts, or the previous
version stays and you can see exactly why.

**Status:** early development; nothing usable yet. The design is in
[`docs/design/landfall.md`](docs/design/landfall.md); the configuration
file is documented in [`docs/configuration.md`](docs/configuration.md).

## How it will work

- **A release is a signed tag.** Each host checks the tag signature against
  keys in its own configuration, and checks the GitHub build-provenance
  attestation of the image against that exact commit, before anything runs.
- **The controller orchestrates, the host decides.** A small agent on each
  host pulls its work from the controller; nothing connects in to a host.
  A compromised controller or a stolen GitHub token cannot make a host run a
  release its configuration does not allow.
- **Rules per deployment:** deploy patch releases automatically, ask for a
  passkey approval on minor ones, keep majors manual. Rules live in a config
  file you review by pull request; the API and UI only read them.
- **Checks and rollback always run:** health checks after every deploy, and
  the previous version comes back on its own when they fail.
- **Agent-first:** a typed OpenAPI ([`docs/api.md`](docs/api.md)) and the
  `landfall` CLI show where each deployment stands, a release's story and why
  a deploy ended as it did, so an agent can find out why a release did not
  land, and ask for one. It can't approve: that takes a person's passkey.
  The logs of one deploy come next.

  ```sh
  landfall status --json                    # the token in LANDFALL_TOKEN, never in argv
  landfall request deploy app/prod v1.3.0   # prints where an approver signs it
  ```

  [The guide](docs/operations.md#the-landfall-command) has its settings.

## Components

| Binary | Runs on | Role |
|---|---|---|
| `landfall-server` | one host (container image `ghcr.io/pecheriere/landfall`) | controller, API, web UI |
| `landfall-agent` | every target host (systemd service) | verifies, deploys, checks, rolls back |
| `landfall` | anywhere | command-line client |

## Installing

landfall has no release yet, so none of this has anything to fetch until the first tag. Then:

```sh
# From the owner's tap, which every stable release reaches: packaging/homebrew-tap/README.md.
brew install pecheriere/tap/landfall
# Or a release's file, for Linux on arm64 or amd64, or macOS on arm64.
gh release download <tag> --repo pecheriere/landfall --pattern 'landfall-*-darwin-arm64'
```

**The first `landfall` is the one that needs care,** as it's what checks everything after it:

- `gh attestation verify <file> --repo pecheriere/landfall --signer-workflow
  pecheriere/landfall/.github/workflows/release.yml --source-ref refs/tags/<tag>
  --deny-self-hosted-runners` checks that these exact bytes were built by this repository's release
  workflow, on a GitHub-hosted runner, from that tag. **It does not check that the maintainer signed the
  tag:** someone holding the owner's GitHub token could pass it with a release of their own.
- To check that too, clone the repository and run `git verify-tag` with the key whose fingerprint is in
  [`SECURITY.md`](SECURITY.md), compare `SECURITY.md` with a copy you got some other way, and add
  `--source-digest` with the tag's commit. [The guide's first trust](docs/operations.md#first-trust) has
  the commands, as the key's file and the digest each need a particular form.
- `brew install` checks only the SHA-256 in the tap's formula, so it trusts the tap, which pulls each
  stable release itself and checks its formula's attestation, and the release's signed tag against the
  tap's own copy of the key, before it merges. Homebrew itself verifies neither the attestation nor the tag.
- `landfall host install` checks the tag's signature, the attestation and the sums every time, against
  what the installed `landfall` holds.
- A browser download on macOS is quarantined: [the guide](docs/operations.md#first-trust) says what that
  means. A release's file is a raw executable, so `chmod +x` it.

Then, from your machine, over your own `ssh`, with a script as root that it shows you first:

```sh
landfall host install user@host.example --host home-1 --config fleet.toml \
  --controller https://controller.example --code-file code --dry-run
landfall host upgrade user@host.example --dry-run
```

[The guide](docs/operations.md#installing-an-agent-with-landfall-host-install) has what it needs, what it
checks and what it refuses.

## Verifying a release

`landfall verify` runs the origin checks a host runs before deploying, against
one release, and prints what it verified as JSON (tag signer and key
fingerprint, release commit, image index digest, certificate identity, workflow
run, transparency-log entry, platforms):

```sh
landfall verify --config fleet.toml --deployment app/prod --tag v1.2.3 \
  [--platform linux/arm64] [--cache-dir <dir>] [--offline]
```

The exit status says what happened, and on failure the failing step and its
reason go to stderr:

| Exit | Meaning |
|---|---|
| 0 | the release is verified |
| 1 | the release is refused: a verification check failed |
| 2 | the release could not be verified: configuration, usage, network, rate limit or trust root error, or no provenance bundle published yet; it may verify on a later try |

`--platform` defaults to the running machine's on Linux and is required
elsewhere. The Sigstore trust root is refreshed through TUF into `--cache-dir`
(default `$XDG_CACHE_HOME/landfall/tuf` or `~/.cache/landfall/tuf`).
`--offline` means the trust root comes from that cache only, without
refreshing it, and fails when the cache is missing or expired; tags, image
indexes and bundles are still fetched from GitHub and the registry.

Anonymous GitHub API requests are limited to 60 an hour per address. When
`GITHUB_TOKEN` is set and non-empty, it is sent to the GitHub API (never to the
registry) for the authenticated limit; it is never printed. A token with no
scopes is enough for public repositories. Keep it out of shell history, for
example with a secret manager that injects it for one command:

```sh
GITHUB_TOKEN="$(gh auth token)" landfall verify --config fleet.toml ...
op run --env-file=landfall.env -- landfall verify --config fleet.toml ...
```

A rate limit is reported with the time it resets.

The host needs a synchronised clock (NTP). The transparency log's integrated
time must not be in the future, so with a clock running behind a fresh release
can't be verified, and exit status 2 says "the transparency log's time is ahead
of this machine's clock".

## Running the controller and the agent

The controller watches releases, verifies them and queues what its rules make automatic. Each host's
agent asks for that work, verifies it again for itself, deploys, checks, rolls back and reports.
What a rule doesn't make automatic, a first deploy included, runs once it is asked for and an
approver signs it with a passkey, which the host verifies against its own file. The pages for that
are minimal, and the rest of the human API, the web UI and a `landfall` command for it are still to
come. [The operations guide](docs/operations.md#from-nothing-to-a-first-deploy) has the steps.
Passkeys need the controller behind HTTPS, and have only been tried with software and virtual
authenticators so far, not on a real device or through a real proxy.

```sh
landfall-server serve --config fleet.toml --db controller.db --listen 127.0.0.1:8080
landfall-server enrol-code --host home-1 --db controller.db
landfall-server audit verify --db controller.db [--at <seq>]

landfall-agent enrol --controller https://controller.example --host home-1 --code-file <file>
landfall-agent run --config fleet.toml --controller https://controller.example --host home-1
landfall-agent status --config fleet.toml --host home-1 [--state-dir <dir>]
landfall-agent recover --config fleet.toml --deployment app/prod [--state-dir <dir>]
```

Set `GITHUB_TOKEN` for the controller: the anonymous limit runs out on first contact.
Keep the head `audit verify` prints somewhere the controller can't write: the chain
alone can't show a backup restored or a history rewritten whole.
[`docs/operations.md`](docs/operations.md) has all of this, and the systemd units.

`status` prints one JSON object per deployment of the host: its directory, what
is deployed, whether a deploy is unfinished, what the override file is, the running
image and whether it has drifted from the override, or the error that kept it from
being read. `recover` rolls back an interrupted deploy, and exits 0 on success, 1
if the rollback failed and 2 if it could not run. The state directory defaults to
`/var/lib/landfall-agent`.

A host needs Linux 5.8 or later, a unique uid for the agent, and four
capabilities (`CAP_CHOWN`, `CAP_FOWNER`, `CAP_DAC_OVERRIDE`, `CAP_FSETID`), and
each stack needs
`COMPOSE_FILE=compose.yaml:compose.landfall.yaml` in its `.env`. The Docker socket
it uses is root-equivalent. See [`docs/operations.md`](docs/operations.md) for
these, the systemd unit, and what to do when a deploy goes wrong.

## Development

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for setup and the checks every
change must pass, and [`AGENTS.md`](AGENTS.md) for conventions.

## Dependency age

Every crate version in `Cargo.lock` must have been published on crates.io at
least 7 days before it is added, so a compromised or broken release has time to
be noticed and yanked. On each pull request,
[`.github/scripts/crate_age.py`](.github/scripts/crate_age.py) compares
`Cargo.lock` with the base branch's, looks up the publish date of every registry
crate version that is new or changed, and fails the build for one younger than
7 days. Unchanged versions are never looked up, so a pull request that leaves
`Cargo.lock` alone makes no request to crates.io; a lookup that fails fails the
check rather than skipping the crate, after a few tries for a failure that can
pass. The release workflow runs the same check on the whole lock file, so a tag
never ships a version that skipped it, even one pushed straight to `main`.

The one exception is the oldest release that fixes a security advisory. List it
in [`.github/crate-age-allow.toml`](.github/crate-age-allow.toml), one entry per
crate version, with a reason that names the advisory (RUSTSEC or GHSA):

```toml
[[allow]]
name = "example-crate"
version = "1.2.3"
reason = "Oldest release without RUSTSEC-0000-0000"
```

An entry covers that exact version only. Once its version leaves `Cargo.lock`
the entry is stale and fails the check, so it is removed with the update that
replaces the crate. Run the check locally on the working tree against `main`:

```sh
python3 -I .github/scripts/crate_age.py --base main
```

A version that is too young is fixed by pinning an older one
(`cargo update -p <crate> --precise <version>`), not by an allow entry.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.
