# Embedded Sigstore TUF root

`sigstore-root.json` is the trust anchor for the public-good Sigstore TUF
repository (`https://tuf-repo-cdn.sigstore.dev`). It is the only material
the trust root is bootstrapped from; everything else is verified against it.

- Source: <https://github.com/sigstore/root-signing>, file `metadata/root.json`
  at commit `a180c17821f8316a70d834d4d9eec0b4ecb1922c`; byte-identical to
  `https://tuf-repo-cdn.sigstore.dev/16.root.json`.
- Root version: 16 (expires 2027-04-22T19:27:31Z).
- SHA-256: `27aea7e372aa7864065174f0661784fcf8b0e28b1dbfebeada31a0f1fb19167f`.

The TUF client walks forward from this root through newer root versions the
repository publishes, each signed by the previous one, so an old embedded
root still bootstraps after its own expiry. Refresh it from the source above
periodically anyway: a shorter chain means fewer downloads, and an offline
load with an empty cache has only the embedded root to start from, which must
not have expired by then.
