# The Homebrew tap

landfall's formula lives in the owner's tap, `pecheriere/homebrew-tap`, which the owner's
command-line tools share, and installs with `brew install pecheriere/tap/landfall`. Everything else
about landfall works without it. A fork does the same with its own names.

## How a release gets there

Every release has `landfall.rb` as an attested asset, pinning each platform's file by URL and
SHA-256. The tap pulls it: landfall holds no token for the tap and runs nothing for it.

- A scheduled workflow in the tap reads landfall's latest stable release, verifies it with the
  tap's own script and its own copy of the release key, the formula's attestation and the signed
  tag both, and opens a pull request that merges itself once the tap's checks pass. Its token is
  the tap's, in an environment limited to the tap's `main`.
- The tap's checks refuse a downgrade and a release candidate, so release candidates never reach
  `brew upgrade`.
- The tap's `scope` check lets a pull request that isn't signed by the owner only change a formula
  that already exists. So the first stable release's formula is added by the owner: on a branch
  of the tap's `main`, where `scripts/landfall.py` lives once the tap's pull request adding it has
  merged, `python3 -I scripts/landfall.py fetch <version> Formula/landfall.rb`, a commit signed
  with the owner's commit key (not the release key), and a pull request in the tap.
  `CONTRIBUTING.md` has the commands. Every later release is automatic.

A stolen landfall token can run landfall's release workflow, but can't sign a tag, so it can't get
a formula past the tap's checks, and it holds nothing that reaches the tap.

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
