# Attestation fixture

A real GitHub build-provenance bundle from a public, widely used third-party
project, verified offline by the tests in `crates/origin/src/attestation.rs`.

| What | Value |
|---|---|
| Repository | `dani-garcia/vaultwarden` |
| Repository id | `121898717` |
| Owner id | `725423` |
| Workflow | `.github/workflows/release.yml` |
| Tag | `1.37.4` |
| Commit | `7c188967e7a467b19b2757bc3326f9cf3ccae327` |
| Image | `ghcr.io/dani-garcia/vaultwarden:1.37.4` |
| Index digest | `sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055` (`index-digest.txt`) |
| Run | `https://github.com/dani-garcia/vaultwarden/actions/runs/37388798451/attempts/1` |
| Rekor log index | `3097402908` |
| Integrated time | `1791243479` (2026-10-05T23:37:59Z) |

The SAN is
`https://github.com/dani-garcia/vaultwarden/.github/workflows/release.yml@refs/tags/1.37.4`,
the build trigger `push` and the runner environment `github-hosted`.

## Files

- `bundle.json`: the Sigstore bundle (v0.3, DSSE, SLSA provenance v1) whose
  in-toto subject is `ghcr.io/dani-garcia/vaultwarden` at the index digest.
  The project attests the same digest for three registries; this is the GHCR
  one.
- `index-digest.txt`: the multi-arch image index digest the bundle attests.
- `index.json`: the image index itself, the exact bytes the registry serves
  for the release tag (their sha256 is the index digest). It lists
  `linux/amd64`, `linux/arm64`, `linux/arm/v7` and `linux/arm/v6`, each with
  a buildx attestation manifest. With it, `crates/origin/src/release.rs`
  verifies the whole release offline against mock GitHub and registry
  servers (as a deployment with `signed_tags = false`: the project's tags are
  not signed by a key in these fixtures).
- `trusted_root.json`: a snapshot of the Sigstore public-good trusted root
  (the first line of `gh attestation trusted-root`), so the test runs offline.

## How they were obtained (2026-10-31)

```sh
# Index digest: the registry's Docker-Content-Digest for the release tag.
token=$(curl -s 'https://ghcr.io/token?scope=repository:dani-garcia/vaultwarden:pull' | jq -r .token)
curl -sI -H "Authorization: Bearer $token" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  https://ghcr.io/v2/dani-garcia/vaultwarden/manifests/1.37.4 | grep -i docker-content-digest

# Index: the same request's body; its sha256 is the digest above.
curl -s -H "Authorization: Bearer $token" \
  -H 'Accept: application/vnd.oci.image.index.v1+json' \
  https://ghcr.io/v2/dani-garcia/vaultwarden/manifests/1.37.4 > index.json

# Bundle: the GHCR attestation for that digest.
gh api /repos/dani-garcia/vaultwarden/attestations/sha256:efb3cde962015fcc036b2ea625242248611943b27212ebf4392841fb30fad055 \
  --jq '.attestations[].bundle | select((.dsseEnvelope.payload | @base64d | fromjson | .subject[0].name) == "ghcr.io/dani-garcia/vaultwarden")' \
  > bundle.json

# Trusted root: the public-good instance (line 1; line 2 is GitHub's own instance).
gh attestation trusted-root | head -n 1 > trusted_root.json

# Ids, and the tag's target commit.
gh api repos/dani-garcia/vaultwarden --jq '{id, owner: .owner.id}'
gh api repos/dani-garcia/vaultwarden/git/ref/tags/1.37.4 --jq .object.sha  # tag object
gh api repos/dani-garcia/vaultwarden/git/tags/<tag object sha> --jq .object.sha
```

The certificate claims (Fulcio extensions `1.3.6.1.4.1.57264.1.8` to `.1.24`)
can be read with
`jq -r .verificationMaterial.certificate.rawBytes bundle.json | base64 -d | openssl x509 -inform DER -noout -text`.
