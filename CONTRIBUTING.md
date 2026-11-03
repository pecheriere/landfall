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

1. **Create the `release` environment.** `environment-guard` reads these settings and refuses
   anything else, by name:
   - **Required reviewers:** at least one, such as yourself.
   - **Prevent self-review:** off (`prevent_self_review`), or a sole maintainer can't approve.
   - **Allow administrators to bypass:** off (`can_admins_bypass`). It defaults to on, and left
     on, an admin could publish with no reviewer, and the guard stays red with `can_admins_bypass
     is not off, so an admin could publish with no reviewer`. A repository a user owns offers
     this switch too.
   - **Deployment branches and tags:** "Selected branches and tags" (`custom_branch_policies`
     on, `protected_branches` off), with exactly one rule: the **tag** rule `v[0-9]*`. A branch
     rule, another pattern, or "Protected branches only" would refuse the tag at `publish`, or
     let other refs through.

   Until this exists, `environment-guard` fails on every run. That is correct: GitHub would
   otherwise create the environment with no protection when `publish` named it.
2. **Turn on immutable releases** in the repository's settings, so a published release's
   files can't change. The workflow can't read this setting beforehand, so a manual run won't
   show it. The last step of `publish` reads the release back and fails if it isn't immutable,
   by which time the release is public. You can read it yourself:
   `gh api repos/<owner>/<repo>/immutable-releases` should answer `"enabled":true`.
3. **Protect the release tags with a ruleset,** on `refs/tags/v[0-9]*`, with `update`, `deletion`
   and `non_fast_forward` rules and no bypass. That is what makes a tag impossible to move or
   delete, which the rest of this page relies on. Leave out a `creation` rule, or the tag can't
   be pushed.
4. **Supply the tag-signing public key:** the `ssh-ed25519` key you sign tags with, as other
   types are refused. It goes in `crates/cli/assets/release-signers`, one
   `ssh-ed25519 <base64>` line with no comment, and its fingerprint in `SECURITY.md`, by pull
   request. **A file with no key makes the release preflight refuse every tag.** That is correct
   too. In that file only `\n` ends a line, a carriage return anywhere is refused, and a line is
   skipped only if it is empty or starts with `#`. Keep this key apart from the one that signs
   your commits, somewhere that asks you before each signature: anything running as you can use
   a key file on disk with no prompt, and this one decides what hosts install as root.

5. **Add `host-install` to the `main` ruleset's required checks,** once the job has run on `main`. A
   required check that doesn't exist yet leaves every pull request pending for ever. Never filter
   that job by path while it's required, as one that doesn't run blocks a merge too.

To rotate the key, let two overlap: release N carries both and is signed by the old one, and
release N+1 is signed by the new one.

### For each release

1. Bump `workspace.package.version` and the `landfall-*` path dependency versions in
   `Cargo.toml`, with the `Cargo.lock` that follows from it, as every build is `--locked`, by pull
   request. The tag must be `v` plus that version, or preflight refuses it.
   For a first release, or after changing the workflow, prefer a release candidate such as
   `0.1.0-rc.1`: it is marked as a prerelease and not as the latest.
2. Run the `Release` workflow by `workflow_dispatch` on `main`, and check that it's green. It
   builds with no cache, runs each binary on a real kernel of each kind and reads the
   environment's settings, and it skips `publish`, so it attests nothing and writes nothing to
   the transparency log. It skips `preflight` too, since there's no tag to prove.
3. Check immutable releases once more, with the `gh api` call above: this is the one setting that
   goes red only after publishing. Then `git tag -s v<version>` on that commit, naming the release
   key with `-c user.signingkey="key::ssh-ed25519 <base64>"` if it isn't git's default, and push the
   tag.
4. Approve the `publish` job when it asks, **within 7 days**: the build jobs' artifacts expire
   after that, and a later approval fails at the download and spends the version.
5. If there's a Homebrew tap, and this isn't a release candidate, which shouldn't reach
   `brew upgrade`, copy the formula over by hand:
   [`packaging/homebrew-tap/README.md`](packaging/homebrew-tap/README.md).
6. After a first release candidate, before the real tag, go through "The first-tag list" in
   [the plan that added this workflow](docs/superpowers/plans/2026-11-02-landfall-06-release-binaries-and-host-install.md):
   what only a real tag can show, such as the approval, a real bundle, and a real download. Two
   wait for later: Homebrew for the real release, as above, and a real `landfall host upgrade` for
   a second release.

### What a failed run costs

**A version number, whatever failed.** Hosts refuse a release attested by two attempts of a
run, and a tag can't be moved, so a re-run of any job is attempt 2 and `publish` refuses it.
**Never re-run a failed release run.** Abandon its draft if it left one, bump the version by
pull request, and tag again. A flake anywhere costs this too.

- A failure before `publish` (preflight, CI, a build, the smoke test) costs the tag number and
  nothing else, and nobody is asked to approve anything.
- Rejecting the `publish` approval spends the version too, and leaves nothing public.
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
- **crates.io failing** past the few tries each lookup gets fails `crate-age`, which looks up
  every locked crate on a release, and so costs a version number. A pull request's check can
  simply be re-run.
- **`host-install` failing** on a release's `ci` costs a version number, as a re-run is a second
  attempt: a flake there, a Debian mirror with the image's cache cold, or Docker Hub. Accepted, as
  this job is what shows a release's script works, and the `workflow_dispatch` run shows most of it.
- **An outage at ziglang.org** fails a build with no cache closed, as the Dockerfile fetches
  zig from there by checksum. If it reaches a tag, it costs a version number. The
  `workflow_dispatch` run shows it, which is one reason to do that just before tagging.

## Commit style

Use [conventional commits](https://www.conventionalcommits.org), for example
`feat: verify tag signatures`. A DCO sign-off is not required.
