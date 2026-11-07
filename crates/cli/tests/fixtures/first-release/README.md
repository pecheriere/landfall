# First release fixture

The material of landfall's first release, `v0.1.0-rc.1`, kept as it was published, so
`crates/cli/src/agent_release/tests/first_release.rs` verifies it offline in the normal
suite: the release key on the release tag, the release workflow's own bundle and the
release's own sums, through `verify_release_file` with the identity and signers this build
embeds. Verifying a named file needs only digests, and `LICENSE-MIT` is small and is listed
in the sums, so no binary of the release is kept here.

| What | Value |
|---|---|
| Repository | `pecheriere/landfall` |
| Repository id | `1441186089` |
| Owner id | `1872741` |
| Workflow | `.github/workflows/release.yml` |
| Tag | `v0.1.0-rc.1`, a prerelease, immutable |
| Tag object | `eb34bcbd17ead0bd41238f1d3f624c0f83c23fd6` |
| Commit | `42e8a3c14edc7a869fe6a45e9d1712a5e59bfea5` |
| Tag signer | `SHA256:NQDx0iXAXnjJDtJz662lf+yEZuX46AZ20/RHcBU0TIk`, the key in `crates/cli/assets/release-signers` |
| Run | `https://github.com/pecheriere/landfall/actions/runs/42409255476/attempts/1` |
| Rekor log index | `3746720453` |
| Integrated time | `1794089053` (2026-11-07T22:04:13Z) |
| Published | 2026-11-07T22:19:19Z |
| Subjects | 9, by basename: the 8 files `SHA256SUMS` lists, and `SHA256SUMS` |

The SAN is
`https://github.com/pecheriere/landfall/.github/workflows/release.yml@refs/tags/v0.1.0-rc.1`.

## Files

- `tag-ref.json`: `GET /repos/pecheriere/landfall/git/ref/tags/v0.1.0-rc.1`, as GitHub
  answered it.
- `tag-object.json`: `GET /repos/pecheriere/landfall/git/tags/<tag object>`, as GitHub
  answered it: the signed tag object. Only its `verification.payload` and
  `verification.signature` are used, and together they hash back to its id. The other
  fields, such as `message`, are not read.
- `landfall-0.1.0-rc.1.sigstore.json`: the release's bundle (v0.3, DSSE, SLSA provenance
  v1, one Rekor entry), the release asset of that name.
- `SHA256SUMS`: the release's file of that name, 740 bytes, whose sha256 is a subject of
  the bundle.
- `LICENSE-MIT`: the release's file of that name, 1077 bytes, listed in `SHA256SUMS` and a
  subject of the bundle.
- `trusted_root.json`: a snapshot of the Sigstore public-good trusted root (the first line
  of `gh attestation trusted-root`), so the test runs offline. Taken on 2026-11-07, it is
  byte-identical to the snapshots in `crates/origin/tests/fixtures/attestation/` and
  `attestation-files/`, so this release needs no newer root than they do. It is kept here
  anyway, so that this fixture stands alone and its recipe rebuilds all of it, and a cli
  test doesn't reach into another crate's fixtures.

The test serves the release's listing itself, with GitHub's ids, names and sizes of the
three assets it asks for, as nothing in the listing is verified.

## How they were obtained (2026-11-07)

Each command only reads. The files went into a new, empty directory first.

```sh
gh release download v0.1.0-rc.1 --repo pecheriere/landfall \
  --pattern LICENSE-MIT --pattern SHA256SUMS --pattern 'landfall-0.1.0-rc.1.sigstore.json'
gh api repos/pecheriere/landfall/git/ref/tags/v0.1.0-rc.1 > tag-ref.json
gh api repos/pecheriere/landfall/git/tags/eb34bcbd17ead0bd41238f1d3f624c0f83c23fd6 \
  > tag-object.json
gh attestation trusted-root | head -n 1 > trusted_root.json
```

## How they were checked

The three release files have the digests GitHub lists for them, and `cmp` found the files
here identical to the downloads:

```sh
gh api repos/pecheriere/landfall/releases/tags/v0.1.0-rc.1 \
  --jq '.assets[] | select(.name == "LICENSE-MIT" or .name == "SHA256SUMS"
    or .name == "landfall-0.1.0-rc.1.sigstore.json") | "\(.digest) \(.name)"'
shasum -a 256 LICENSE-MIT SHA256SUMS landfall-0.1.0-rc.1.sigstore.json
```

| File | sha256 |
|---|---|
| `LICENSE-MIT` | `7f938b6860cf9430784996eb1e4ccd093b34d4be0e5437862c5c7aa6f1dcc584` |
| `SHA256SUMS` | `2700656b8e91f46972ae4fe376bb8a855a46a3fa1dab58091747e1afb43eeb6b` |
| `landfall-0.1.0-rc.1.sigstore.json` | `677104cd1719d6e13746c2300d04eebbec381b74cfb237d19e5c44ea92d9f6bc` |

The tag object needs no outside digest: the test refuses it unless its payload and
signature hash to the id the ref names.

An independent implementation accepted the bundle for `LICENSE-MIT` when it was taken, and
refused it with another commit in place of the real one:

```sh
gh attestation verify LICENSE-MIT --bundle landfall-0.1.0-rc.1.sigstore.json \
  --repo pecheriere/landfall \
  --signer-workflow pecheriere/landfall/.github/workflows/release.yml \
  --source-ref refs/tags/v0.1.0-rc.1 \
  --source-digest 42e8a3c14edc7a869fe6a45e9d1712a5e59bfea5 \
  --deny-self-hosted-runners
```

The subjects can be listed with
`jq -r '.dsseEnvelope.payload | @base64d | fromjson | .subject[] | "\(.digest.sha256)  \(.name)"' landfall-0.1.0-rc.1.sigstore.json`.
