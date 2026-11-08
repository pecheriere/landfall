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
`.github/workflows/release.yml`, with nobody asked to approve anything: the tag's signature is the
only gate. A stolen GitHub token could approve a deployment through the API, so an approval would add
nothing against that, but it can't forge the signature, which `preflight` proves before `publish` can
run, and which every host and the Homebrew tap check again with their own copy of the key. Only the
repository's owner signs tags. A fork that wants its own releases does each of these for itself, with
its own key.

### Once, by the owner

1. **Turn on immutable releases** in the repository's settings, so a published release's
   files can't change. The workflow can't read this setting beforehand, so a dry run won't
   show it. The last step of `publish` reads the release back and fails if it isn't immutable,
   by which time the release is public. You can read it yourself:
   `gh api repos/<owner>/<repo>/immutable-releases` should answer `"enabled":true`.
2. **Protect the release tags with a ruleset,** on `refs/tags/v[0-9]*`, with `update`, `deletion`
   and `non_fast_forward` rules and no bypass. That is what makes a tag impossible to move or
   delete, which the rest of this page relies on. Leave out a `creation` rule, or the tag can't
   be pushed.
3. **Supply the tag-signing public key:** the `ssh-ed25519` key you sign tags with, as other
   types are refused. It goes in `crates/cli/assets/release-signers`, one
   `ssh-ed25519 <base64>` line with no comment, and its fingerprint in `SECURITY.md`, by pull
   request. **A file with no key makes the release preflight refuse every tag.** That is correct
   too. In that file only `\n` ends a line, a carriage return anywhere is refused, and a line is
   skipped only if it is empty or starts with `#`. Keep this key apart from the one that signs
   your commits, somewhere that asks you before each signature: anything running as you can use
   a key file on disk with no prompt, and this one decides what hosts install as root.
4. **Add `host-install` to the `main` ruleset's required checks,** once the job has run on `main`. A
   required check that doesn't exist yet leaves every pull request pending for ever. Never filter
   that job by path while it's required, as one that doesn't run blocks a merge too.
5. **Let releases reach the Homebrew tap,** `<owner>/homebrew-tap`, which the owner's command-line
   tools share:
   - Create a fine-grained personal access token limited to that one repository, with
     **Contents: read and write** and **Pull requests: read and write**, and nothing else: no
     Workflows permission, so it can't change the tap's CI. Keep it apart from the token any other
     project uses for the same tap, so that each can be revoked alone.
   - Create a `homebrew-tap` environment in this repository, with "Selected branches and tags" and
     exactly one rule, the **tag** rule `v[0-9]*`, so only a run on a release tag can read it. Add
     the token there as the secret `HOMEBREW_TAP_TOKEN`. It needs no reviewers: the tap's checks
     decide what merges.
   - In the tap, allow auto-merge, and require its checks on `main`, as `homebrew.yml` asks GitHub
     to merge once they pass.

   Until the secret exists, `homebrew.yml` fails after each release, and nothing else does.
6. **If a `release` environment is left from before,** delete it: nothing names it any more.

To rotate the key, let two overlap: release N carries both and is signed by the old one, and
release N+1 is signed by the new one.

### For each release

1. Bump `workspace.package.version` and the `landfall-*` path dependency versions in
   `Cargo.toml`, with the `Cargo.lock` that follows from it, as every build is `--locked`, by pull
   request. The tag must be `v` plus that version, or preflight refuses it.
   For a first release, or after changing the workflow, prefer a release candidate such as
   `0.1.0-rc.1`: it is marked as a prerelease and not as the latest, and never reaches Homebrew.
2. When that pull request merges, the push to `main` starts the `Release` workflow's dry run on
   its own: it builds with no cache, runs each binary on a real kernel of each kind, and skips
   `preflight` and `publish`, so it attests nothing and writes nothing to the transparency log.
   If a later commit landed on `main` since, run the workflow by `workflow_dispatch` on `main`, as
   the tag goes on `main`'s head and only a version change starts the dry run.
3. Once it's green, check immutable releases once more, with the `gh api` call above: this is the
   one setting that goes red only after publishing. Then, from a clean clone:

   ```sh
   scripts/release-tag <version> --push
   ```

   It refuses unless `origin/main` is at that version, its dry run passed in full, and the tag is
   new, here and on origin. Then it signs `v<version>` on that commit with git's signing key,
   checks the signature against the signers file, deletes the tag if it doesn't match, and pushes
   it. Name the release key with `--signing-key "key::ssh-ed25519 <base64>"` if it isn't git's
   default. Leave out `--push` to see the push command instead. Agents never run it.
4. Nothing else. The tag runs `preflight`, then `publish`, then starts `homebrew.yml`, which,
   for a release that isn't a candidate, opens a pull request in the tap with the new formula and
   turns on auto-merge. The tap's checks verify the formula's attestation, and the signed tag
   against the tap's own copy of the key, refuse a downgrade or a candidate, and merge only when
   green. [`packaging/homebrew-tap/README.md`](packaging/homebrew-tap/README.md) says how to check
   a formula by hand.
5. After a first release candidate, before the real tag, go through "The first-tag list" in
   [the plan that added this workflow](docs/superpowers/plans/2026-11-02-landfall-06-release-binaries-and-host-install.md):
   what only a real tag can show, such as a real bundle, and a real download. Its items about the
   approval are gone with the approval. Two wait for later: Homebrew for the real release, and a
   real `landfall host upgrade` for a second release.

### What a failed run costs

**A version number, whatever failed.** Hosts refuse a release attested by two attempts of a
run, and a tag can't be moved, so a re-run of any job is attempt 2 and `publish` refuses it.
**Never re-run a failed release run.** Abandon its draft if it left one, bump the version by
pull request, and tag again. A flake anywhere costs this too. A dry run can be re-run freely.

- A failure before `publish` (preflight, CI, a build, the smoke test) costs the tag number and
  nothing else.
- A failure in `publish` before the draft exists leaves nothing public.
- After the draft exists, delete the draft.
- If the image is pushed but its attestation step fails, a tag is left in the registry with no
  attestation. Hosts refuse it, so it's harmless: leave it, or delete that package version.
- If the last step fails to publish the draft after the image is attested, hosts can deploy
  that image while the binaries never appear. The design makes the Release object optional, so
  this is accepted.
- **If that step fails to publish or to read the release back, the release may already be
  public,** as a failed try may have been applied. Check it by hand before doing anything else: it should not be a draft, should have this tag, and
  should read as immutable. It could be public with the wrong tag or not locked, and it may not
  be possible to repair it, in which case the way on is still a new version.
- **The `homebrew` job or `homebrew.yml` failing** costs nothing: the release is out. Run
  `homebrew.yml` by `workflow_dispatch` on the tag (`gh workflow run homebrew.yml --ref v<version>`)
  once the cause is fixed. It stops cleanly if the tap's branch or pull request already exists.
- **crates.io failing** past the few tries each lookup gets fails `crate-age`, which looks up
  every locked crate on a release, and so costs a version number. A pull request's check can
  simply be re-run.
- **`host-install` failing** on a release's `ci` costs a version number, as a re-run is a second
  attempt: a flake there, a Debian mirror with the image's cache cold, or Docker Hub. Accepted, as
  this job is what shows a release's script works, and the dry run shows most of it.
- **An outage at ziglang.org** fails a build with no cache closed, as the Dockerfile fetches
  zig from there by checksum. If it reaches a tag, it costs a version number. The dry run shows
  it, which is one reason `scripts/release-tag` wants one for the exact commit.

## Commit style

Use [conventional commits](https://www.conventionalcommits.org), for example
`feat: verify tag signatures`. A DCO sign-off is not required.
