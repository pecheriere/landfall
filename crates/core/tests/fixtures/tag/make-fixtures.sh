#!/usr/bin/env bash
# Regenerates the signed tag fixtures in this directory. A development tool:
# it is not run in CI. Everything happens in a temporary directory with
# throwaway ed25519 keys; the private keys are deleted before the script
# exits and only public keys and raw tag objects are written here.
#
# Usage: make-fixtures.sh
# Afterwards update the commit, fingerprints and README from the printed lines.
set -euo pipefail

out="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# Isolate from any personal git or ssh-agent configuration.
export GIT_CONFIG_GLOBAL=/dev/null
export GIT_CONFIG_NOSYSTEM=1
unset SSH_AUTH_SOCK
export GIT_AUTHOR_NAME=maintainer GIT_AUTHOR_EMAIL=maintainer@example.invalid
export GIT_COMMITTER_NAME=maintainer GIT_COMMITTER_EMAIL=maintainer@example.invalid
export GIT_AUTHOR_DATE='2026-01-01T00:00:00+0000'
export GIT_COMMITTER_DATE='2026-01-01T00:00:00+0000'

ssh-keygen -q -t ed25519 -N '' -C '' -f "$work/signer"
ssh-keygen -q -t ed25519 -N '' -C '' -f "$work/other"
ssh-keygen -q -t ecdsa -b 256 -N '' -C '' -f "$work/ecdsa"

git init -q -b main "$work/repo"
cd "$work/repo"
git -c commit.gpgsign=false commit -q --allow-empty -m 'release commit'

sign() { # key tag-name object message
  git -c gpg.format=ssh -c "user.signingkey=$work/$1.pub" tag -s -m "$4" "$2" "$3"
}
dump() { # tag-name output
  git cat-file tag "$1" >"$out/$2"
  git tag -d "$1" >/dev/null
}

sign signer v1.2.3 HEAD 'release v1.2.3'
dump v1.2.3 valid.tag
sign other v1.2.3 HEAD 'release v1.2.3'
dump v1.2.3 unknown-signer.tag
git -c commit.gpgsign=false -c tag.gpgsign=false tag -a -m 'release v1.2.3' v1.2.3 HEAD
dump v1.2.3 unsigned.tag
sign signer v1.2.3 'HEAD^{tree}' 'release v1.2.3'
dump v1.2.3 tree-object.tag
# The attestation fixture's tag name (crates/origin/tests/fixtures/attestation)
# on this commit: a signed tag that matches that bundle in everything but the
# commit.
sign signer 1.37.4 HEAD 'release 1.37.4'
dump 1.37.4 other-commit.tag

# The same signed bytes signed in another namespace, appended the way git does.
sed '/^-----BEGIN SSH SIGNATURE-----$/,$d' "$out/valid.tag" >"$work/payload"
ssh-keygen -q -Y sign -f "$work/signer" -n file "$work/payload"
cat "$work/payload" "$work/payload.sig" >"$out/wrong-namespace.tag"

awk '{print $1, $2}' "$work/signer.pub" >"$out/signer.pub"
awk '{print $1, $2}' "$work/other.pub" >"$out/other.pub"
awk '{print $1, $2}' "$work/ecdsa.pub" >"$out/ecdsa.pub"

echo "commit:      $(git rev-parse HEAD)"
echo "signer:      $(ssh-keygen -lf "$work/signer.pub")"
echo "other:       $(ssh-keygen -lf "$work/other.pub")"
rm -f "$work"/signer "$work"/other "$work"/ecdsa
