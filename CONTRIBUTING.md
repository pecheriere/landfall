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
5. **The Homebrew tap,** `<owner>/homebrew-tap`, which the owner's command-line tools share,
   pulls releases itself: this repository holds no token for it, and needs no environment or
   secret for it. A scheduled workflow in the tap reads landfall's latest stable release, verifies
   it with the tap's own script and its own copy of the release key, and opens a pull request that
   merges itself once the tap's checks pass, with a token the tap keeps in an environment limited
   to its `main`. Its setup is the tap's.

   The tap's `scope` check lets a pull request that isn't signed by you only change a formula that
   already exists. So **the first stable release's formula is added by you,** once that release is
   out, in a clone of the tap's `main`, where `scripts/landfall.py` lives once the tap's own pull
   request adding it has merged:

   ```sh
   git switch -c landfall-<version> origin/main
   python3 -I scripts/landfall.py fetch <version> Formula/landfall.rb
   git add Formula/landfall.rb && git commit -m "landfall <version>"
   git push -u origin landfall-<version>
   gh pr create --fill
   ```

   The commit is signed with your **commit** key, one the tap lists as a maintainer's, not the
   release key, which signs only tags. The script verifies what it fetches as the tap's workflow
   does, and the pull request merges once the tap's checks pass. Every later stable release
   reaches the tap on its own.
6. **If a `release` environment is left from before,** delete it: nothing names it any more.
7. **Keep your own copy of the release keys,** which `scripts/release-tag` trusts and the
   repository can't change, written as `crates/cli/assets/release-signers` is. Make it from the keys
   in `SECURITY.md`, after comparing their fingerprints with a copy you got some other way, such as
   the one you keep with the key itself. The helper refuses it inside the checkout, through a link,
   owned by anyone but you or root, or writable by anyone but its owner, and it refuses to sign when
   the repository's signers differ from it, so for a rotation you change this file first, on purpose.
   - **Owned by you**, at the default `${XDG_CONFIG_HOME:-~/.config}/landfall/release-signers` with
     `chmod 600`, it holds against a stolen GitHub token, which can't reach your machine. It doesn't
     hold against code running as you, such as an agent you leave running unattended: that can edit
     the file, and then land a matching commit and tag.
   - **Owned by root**, for example
     `sudo install -D -m 0644 -o root <copy> /usr/local/etc/landfall/release-signers`, then
     `scripts/release-tag ... --trusted-signers /usr/local/etc/landfall/release-signers`, the key
     list itself can't be changed without `sudo`. That is all it protects. Code running as you can
     still put its own `git` first on your `PATH`, edit the helper in your clone, or change an alias
     or your shell history so the flag is dropped, and show you a clean review of something else.
   - **So against code running as you, the helper holds nothing.** What remains is the 1Password
     prompt before each signature with the release key, and your judgment about when you sign.
     Release from a session with no unattended agents running as you, or from a separate macOS
     account that runs none.

To rotate the key, let two overlap: release N carries both keys and is signed by the old one, and
release N+1 is signed by the new one. Add the new key to your own copy (step 7) before release N.
Drop the old key from the repository in a release after N+1, and from your copy at the same time.
From then on the tags the old key signed no longer verify against your copy, which is harmless:
they are all below N+1, which the new key signed and the helper still finds as a release behind
the commit, so it warns about none of them. If you drop the old key at N+1 itself, N+1's
own run finds no release behind it that your copy verifies: it warns about every earlier tag and
shows the whole history. That is expected then, and the way to avoid it is to keep the old key, in
the repository and in your copy, until N+1 is out.

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
   one setting that goes red only after publishing. Then, from a clean clone, at a terminal:

   ```sh
   scripts/release-tag <version> --commit <sha> --push
   ```

   `<sha>` is the merge commit of the version bump's pull request, the one you saw. It refuses
   unless `origin/main` is exactly that commit, at that version, its dry run passed in full, and
   the tag is new, here and on origin. It also refuses unless the keys in
   `crates/cli/assets/release-signers` at that commit are exactly the keys in your own copy ("Once"
   step 7, or `--trusted-signers <path>`), and then shows both sets of fingerprints. The last
   release is the highest `v*` tag one of your keys signed: a key added in the repository can't
   vouch for a tag, and any `v*` tag above it that none of your keys signed is named in a warning,
   which you look into. Before anything is signed it shows the commit and the dry run, every commit
   since that release with its signature status and files, and in full any change to the signers
   file, `.github/`, `scripts/release-tag`, `Cargo.toml` and `Cargo.lock`, with any control
   characters shown as escapes. **Read them.** With no release of yours behind it, as on the first
   run, it shows the signers file whole with its fingerprints, lists the files in `.github/` and
   `Cargo.lock` by name, and shows the rest whole.
   Then it asks you to type the version, with no flag to skip that, signs `v<version>` on that
   commit with git's signing key, checks the signature against the signers file, deletes the tag
   if it doesn't match, says what it pushes and pushes it. It signs with the key in your own copy
   ("Once" step 7), which it passes to git as `key::<type> <base64>`, so there is no flag for it; during a
   rotation that file holds two keys, so name the signing one with `--signing-key <path to a file
   holding it>` or `--signing-key "key::ssh-ed25519 <base64>"`, keeping the space. Before asking, it
   checks that your SSH agent offers that key: `SSH_AUTH_SOCK` has to reach the agent that holds the
   release key, such as 1Password's. `IdentityAgent` in `~/.ssh/config` covers `ssh` alone, not git
   signing. If `gpg.ssh.program` names something other than `ssh-keygen`, git signs its own way, so
   it says so and skips that check; the signature is verified after signing either way. A
   `--signing-key` that isn't one of your trusted keys is refused before the review. Leave out `--push` to see
   the push command instead. **The first time, run it without `--push`,** as its checks of a dry
   run's jobs haven't met a real one yet: a refusal there costs nothing. Agents never run it, and
   it refuses when stdin isn't a terminal.
4. Nothing else for landfall. The tag runs `preflight`, then `publish`. For a release that isn't
   a candidate, the tap's scheduled workflow then proposes the new formula and merges it once its
   checks pass: they verify the formula's attestation, and the signed tag against the tap's own
   copy of the key, and refuse a downgrade or a candidate. The first stable release's formula is
   yours to add, by "Once" step 5.
   [`packaging/homebrew-tap/README.md`](packaging/homebrew-tap/README.md) says how to check a
   formula by hand.
5. After a first release candidate, before the real tag, go through "The first-tag list" in
   [the plan that added this workflow](docs/superpowers/plans/2026-11-02-landfall-06-release-binaries-and-host-install.md):
   what only a real tag can show, such as a real bundle, and a real download. Its items about the
   approval are gone with the approval, and its Homebrew item, copying the formula by hand, is now
   the signed first formula of "Once" step 5. A real `landfall host upgrade` waits for a second
   release.

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
