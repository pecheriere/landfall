# Release file attestation fixture

A real GitHub build-provenance bundle with many files as subjects, from a public,
widely used third-party project, verified offline by
`crates/origin/src/attestation/tests/files.rs`. Verifying a named file needs only
digests, so no binary of the release is kept here.

| What | Value |
|---|---|
| Repository | `nektos/act` |
| Repository id | `163883279` |
| Owner id | `3813618` |
| Workflow | `.github/workflows/release.yml` |
| Tag | `v0.2.94` |
| Commit | `3fde8e609623104b099747ff67166561ecb7e6be` |
| Run | `https://github.com/nektos/act/actions/runs/41234509130/attempts/1` |
| Rekor log index | `3614772332` |
| Integrated time | `1793475369` (2026-10-31T19:36:09Z) |
| Subjects | 12, by basename, including `checksums.txt` |

The SAN and the Build Config URI are both
`https://github.com/nektos/act/.github/workflows/release.yml@refs/tags/v0.2.94`, the
build trigger `push` and the runner environment `github-hosted`.

## Files

- `bundle.json`: the Sigstore bundle (v0.3, DSSE, SLSA provenance v1, one Rekor v1
  entry with an inclusion proof and a promise). GitHub also holds a `release`
  attestation for the same digests, with another predicate type: this is not that one.
- `checksums.txt`: the release's own file of that name, 981 bytes, whose sha256 is a
  subject of the bundle.
- `trusted_root.json`: a snapshot of the Sigstore public-good trusted root (the first
  line of `gh attestation trusted-root`), so the tests run offline.

## How they were obtained (2026-11-02)

```sh
# The digest of checksums.txt, as GitHub lists it; shasum on the file agrees.
gh api repos/nektos/act/releases/tags/v0.2.94 \
  --jq '.assets[] | select(.name == "checksums.txt") | .digest'

# Bundle: selected by predicate type. The other fixture's recipe selects by subject,
# which here would not tell the SLSA bundle from the `release` attestation.
gh api /repos/nektos/act/attestations/sha256:bcc018e12c30f9d875b36c01ef36dd11d4923bde9d6f0dd2313e54ab7aa2051a \
  --jq '.attestations[].bundle | select((.dsseEnvelope.payload | @base64d | fromjson | .predicateType) == "https://slsa.dev/provenance/v1")' \
  > bundle.json

# checksums.txt: a read of the release's asset.
gh release download v0.2.94 --repo nektos/act --pattern checksums.txt

# Trusted root: the public-good instance (line 1; line 2 is GitHub's own instance).
gh attestation trusted-root | head -n 1 > trusted_root.json

# Ids, and the tag's target commit.
gh api repos/nektos/act --jq '{id, owner: .owner.id}'
gh api repos/nektos/act/git/ref/tags/v0.2.94 --jq .object.sha  # tag object
gh api repos/nektos/act/git/tags/<tag object sha> --jq .object.sha
```

An independent implementation accepted the bundle when it was taken, and refused it
with another commit in place of the real one:

```sh
gh attestation verify checksums.txt --bundle bundle.json --repo nektos/act \
  --signer-workflow nektos/act/.github/workflows/release.yml \
  --source-ref refs/tags/v0.2.94 \
  --source-digest 3fde8e609623104b099747ff67166561ecb7e6be
```

The certificate claims (Fulcio extensions `1.3.6.1.4.1.57264.1.8` to `.1.24`) can be
read with
`jq -r .verificationMaterial.certificate.rawBytes bundle.json | base64 -d | openssl x509 -inform DER -noout -text`.
