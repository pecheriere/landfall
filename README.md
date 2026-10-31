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
- **Agent-first:** a typed OpenAPI and a CLI expose everything the web UI
  shows, down to the logs of one deploy, so an agent can find out why a
  release did not land.

## Components

| Binary | Runs on | Role |
|---|---|---|
| `landfall-server` | one host (container image `ghcr.io/pecheriere/landfall`) | controller, API, web UI |
| `landfall-agent` | every target host (systemd service) | verifies, deploys, checks, rolls back |
| `landfall` | anywhere | command-line client |

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
check rather than skipping the crate. The release workflow runs the same check
against the previous release tag, so a tag never ships a version that skipped
it, even one pushed straight to `main`.

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
