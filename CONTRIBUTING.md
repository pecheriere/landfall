# Contributing

Humans and agents follow the same rules; see `AGENTS.md` for conventions.

## Setup

Install [rustup](https://rustup.rs); the pinned toolchain in
`rust-toolchain.toml` is fetched automatically. Install `cargo-deny` with
`cargo install cargo-deny --locked`. To lint the workflows, install
[uv](https://docs.astral.sh/uv/) and run `uvx zizmor .`.

## Checks

```sh
cargo fmt --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --all-features --locked
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps --locked
cargo deny check
```

All five must pass (run `cargo fmt` to fix formatting); CI runs them on
every pull request.

## Pull requests

- Keep a change focused and explain the why in the description.
- Add tests that specify the new behavior; update the docs.
- Changes touching origin verification, approvals, authentication, grants,
  the agent's host access or outbound HTTP need a security review recorded
  in the PR.

## Cutting a release

A signed tag on `main` publishes attested binaries and an attested image, through
`.github/workflows/release.yml`. Only the repository's owner tags and approves. A fork that
wants its own releases does each of these for itself, with its own key.

### Once, by the owner

1. **Create the `release` environment,** with yourself as a required reviewer,
   `prevent_self_review` off (or nobody can approve) and deployments limited to tags matching
   `v[0-9]*`. Turn `can_admins_bypass` off, as it defaults to on. Until this exists,
   `environment-guard` fails on every run. That is correct: GitHub would otherwise create
   the environment with no protection when `publish` named it.
2. **Turn on immutable releases** in the repository's settings, so a published release's
   files can't change.
3. **Supply the tag-signing public key:** the `ssh-ed25519` key you sign tags with, as other
   types are refused. It goes in `crates/cli/assets/release-signers`, one
   `ssh-ed25519 <base64>` line with no comment, and its fingerprint in `SECURITY.md`, by pull
   request. **That file holds no key until then, and the release preflight refuses every
   tag.** That is correct too. In that file only `\n` ends a line, a carriage return
   anywhere is refused, and a line is skipped only if it is empty or starts with `#`.

To rotate the key, let two overlap: release N carries both and is signed by the old one, and
release N+1 is signed by the new one.

### For each release

1. Bump `workspace.package.version` and the `landfall-*` path dependency versions in
   `Cargo.toml` by pull request. The tag must be `v` plus that version, or preflight refuses it.
   For a first release, or after changing the workflow, prefer a release candidate such as
   `0.1.0-rc.1`: it is marked as a prerelease and not as the latest.
2. Run the `Release` workflow by `workflow_dispatch` on `main`, and check that it's green. It
   builds with no cache, runs each binary on a real kernel of each kind and reads the
   environment, and it stops before `publish`, so it attests nothing and writes nothing to the
   transparency log. It can't check the tag, since there isn't one.
3. `git tag -s v<version>` on that commit, and push the tag.
4. Approve the `publish` job when it asks.
5. If there's a Homebrew tap, copy the formula over by hand:
   [`packaging/homebrew-tap/README.md`](packaging/homebrew-tap/README.md).

### What a failed run costs

**A version number, whatever failed.** Hosts refuse a release attested by two attempts of a
run, and a tag can't be moved, so a re-run of any job is attempt 2 and `publish` refuses it.
**Never re-run a failed release run.** Abandon its draft if it left one, bump the version by
pull request, and tag again. A flake anywhere costs this too.

- A failure before `publish` (preflight, CI, a build, the smoke test) costs the tag number and
  nothing else, and nobody is asked to approve anything.
- A failure in `publish` before the draft exists leaves nothing public.
- After the draft exists, delete the draft. If the last step fails after the image is
  attested, hosts can deploy that image while the binaries never appear. The design makes
  the Release object optional, so this is accepted.
- **An outage at ziglang.org** fails a build with no cache closed, as the Dockerfile fetches
  zig from there by checksum. If it reaches a tag, it costs a version number. The
  `workflow_dispatch` run shows it, which is one reason to do that just before tagging.

## Commit style

Use [conventional commits](https://www.conventionalcommits.org), for example
`feat: verify tag signatures`. A DCO sign-off is not required.
