# The Homebrew tap

`brew install <owner>/landfall/landfall` needs a public repository of that owner's named
`homebrew-landfall`, holding `Formula/landfall.rb`. Everything else about landfall works without
one. This page is what its owner does, by hand. A fork does the same with its own names.

## Creating the tap

Create `homebrew-landfall` as a public repository under the same baseline as this one, with one
directory, `Formula/`.

## For each release

Every release has `landfall.rb` as an attested asset, pinning each platform's file by URL and
SHA-256. Check it, and the tag, before copying it:

```sh
gh release download "$tag" --repo pecheriere/landfall --pattern landfall.rb
gh attestation verify landfall.rb --repo pecheriere/landfall \
  --signer-workflow pecheriere/landfall/.github/workflows/release.yml \
  --source-ref "refs/tags/$tag" --deny-self-hosted-runners \
  --source-digest "$(git -C landfall rev-parse --verify --quiet "$tag^{commit}")"
git -C landfall -c gpg.ssh.allowedSignersFile=<allowed signers> verify-tag "$tag"
```

`landfall` is a clone of this repository holding the tag, and `--source-digest` ties the
attestation to the commit that signed tag names, which the ref alone doesn't. `<allowed signers>`
is a file you keep outside it, with a line `landfall-release ssh-ed25519 <base64>` for each key in
`crates/cli/assets/release-signers`, whose fingerprints you have compared with `SECURITY.md` and
with a copy you got some other way, since a stolen token can change the repository too.

Then copy the file to `Formula/landfall.rb` in the tap, and commit it.

## Why this isn't automated

A workflow that committed the formula would take the latest release on `gh attestation verify`
alone, which skips the signed tag: a stolen owner token can run the release workflow, but can't sign
a tag. It could then reach every `brew upgrade` by the next day. So a person copies one verified
file for each release. A later workflow that did this would need its own copy of the key, and would
have to check the tag with it.
