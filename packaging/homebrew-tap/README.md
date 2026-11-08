# The Homebrew tap

landfall's formula lives in the owner's tap, `pecheriere/homebrew-tap`, which the owner's
command-line tools share, and installs with `brew install pecheriere/tap/landfall`. Everything else
about landfall works without it. A fork does the same with its own names.

## How a release gets there

Every release has `landfall.rb` as an attested asset, pinning each platform's file by URL and
SHA-256. After a stable release is published, `.github/workflows/homebrew.yml` checks that its tag
is `v` plus the workspace version, verifies the formula against the release's attestation, and opens
a pull request in the tap that writes it to `Formula/landfall.rb`, with auto-merge on. It does that
through the GitHub API with a token limited to the tap, and never checks out or runs anything of the
tap's. Release candidates never reach the tap: the workflow skips any tag with a suffix, and any
release marked as a prerelease.

The tap decides what merges. Its CI, from the tap's own `main`, verifies the formula's attestation
and the release's signed tag against the tap's own copy of the key, refuses a downgrade and a release
candidate, and the pull request merges only when that is green. A stolen landfall token can run the
release workflow, but can't sign a tag, so it can't get a formula past those checks.

## Checking a formula by hand

To see for yourself that a formula is the one a release attested, and that the owner signed its tag:

```sh
gh release download "$tag" --repo pecheriere/landfall --pattern landfall.rb
commit=$(git -C landfall rev-parse --verify "$tag^{commit}")
echo "$commit"
gh attestation verify landfall.rb --repo pecheriere/landfall \
  --signer-workflow pecheriere/landfall/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --deny-self-hosted-runners \
  --source-digest "$commit"
git -C landfall -c gpg.ssh.allowedSignersFile=<allowed signers> verify-tag "$tag"
```

`landfall` is a clone of this repository holding the tag, and `--source-digest` ties the
attestation to the commit that signed tag names, which the ref alone doesn't. **Stop if `echo`
printed no commit,** as an empty `--source-digest` checks nothing, and passes. `<allowed signers>`
is a file you keep outside it, with a line `landfall-release ssh-ed25519 <base64>` for each key in
`crates/cli/assets/release-signers`, whose fingerprints you have compared with `SECURITY.md` and
with a copy you got some other way, since a stolen token can change the repository too. The
formula in the tap should be byte for byte the `landfall.rb` you checked.
