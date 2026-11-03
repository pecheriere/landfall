# Security policy

landfall decides what code runs on your hosts, so security reports are very
welcome.

Report vulnerabilities privately through GitHub security advisories:
<https://github.com/pecheriere/landfall/security/advisories/new>.

Please do not open a public issue for a suspected vulnerability.

## Supported versions

landfall has no release yet. Once it has, only the latest release gets fixes.

## Release signing

Release tags must be signed with this SSH key, which the `landfall` CLI also carries, in
`crates/cli/assets/release-signers`:

```text
SHA256:NQDx0iXAXnjJDtJz662lf+yEZuX46AZ20/RHcBU0TIk (ED25519)
```

Compare it with `ssh-keygen -lf <file holding the key>`. This page can change along with that
file, so an unexpected change to either is worth reporting.

Keys rotate by overlap: one release's `landfall` carries both keys, and that release is signed by the old
one, and the next by the new. A test keeps every key in that file listed here. Why this matters, and what
each way of getting `landfall` checks, is in
[the guide's first trust](docs/operations.md#first-trust).
