"""Prove a tag before anyone is asked to approve its release.

Refuses unless all of these hold, and fails closed on anything it didn't expect:

- the tag is `v` plus `workspace.package.version` in `Cargo.toml`;
- `crates/cli/assets/release-signers` holds at least one good key, and nothing else;
- the tag object, read through the GitHub API (the bytes the CLI will read) is annotated, names
  this tag and this commit as a commit, and has an SSH signature in the `git` namespace that
  `ssh-keygen -Y verify` accepts for one of those keys.

GitHub's own `verified` is never read: it says whether GitHub knows the key, and this asks whether
the project does. Nothing here is about a deployment's `origin.signed_tags`, which is a host's own
rule about what it deploys: this is what landfall's CLI trusts about landfall's own binaries.

No value reaches a shell. `gh` and `ssh-keygen` get an argument list, and every value that becomes
an argument was checked against a pattern first. `ssh-keygen` reads the signed bytes on stdin and
everything else from files in a private directory, with no token in its environment.

This runs under `python3 -I`, which keeps a script's directory off the import path, so it stands
alone. `test_release_scripts_run.py` keeps what it shares with `assemble_release.py` equal.

Usage: release_preflight.py --tag TAG --sha COMMIT --repo OWNER/NAME
"""

import argparse
import base64
import json
import os
import re
import subprocess
import sys
import tempfile
import tomllib
from collections.abc import Callable
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
SIGNERS_FILE = Path("crates/cli/assets/release-signers")

VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.+$)[A-Za-z0-9._-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")

MAX_ANSWER_BYTES = 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 60
MAX_SHOWN = 200

KEY_TYPE = "ssh-ed25519"
KEY_BYTES = 32
LENGTH_BYTES = 4
# The wire format: a length and the type, then a length and the key.
KEY_PREFIX = (
    len(KEY_TYPE).to_bytes(LENGTH_BYTES, "big")
    + KEY_TYPE.encode()
    + KEY_BYTES.to_bytes(LENGTH_BYTES, "big")
)
WIRE_BYTES = len(KEY_PREFIX) + KEY_BYTES
# 51 bytes fill their last base64 group exactly, so this is the one spelling of a key.
KEY_FIELD = re.compile(r"[A-Za-z0-9+/]{68}")
FIELDS_IN_A_KEY_LINE = 2

PRINCIPAL = "landfall-release"
NAMESPACE = "git"
# One block and nothing else: `ssh-keygen` reads the first block, and `verify_tag` the last.
SSH_SIGNATURE = re.compile(
    r"-----BEGIN SSH SIGNATURE-----\n(?:[A-Za-z0-9+/=]+\n)+-----END SSH SIGNATURE-----\n?"
)

# Edwards25519, for what a key must be. The checks are `landfall-approval`'s for a passkey, and
# issue 36's for a signer: `ssh-keygen` verifies with a small-order key, whose signatures anyone
# can forge.
P = 2**255 - 19
D = -121665 * pow(121666, -1, P) % P
SQRT_MINUS_ONE = pow(2, (P - 1) // 4, P)
Y_MASK = (1 << 255) - 1
DOUBLINGS_TO_CLEAR_THE_COFACTOR = 3


class RefusedError(Exception):
    """A tag must not be released, for the reason given."""


def shown(value: object) -> str:
    """Return a value safe to print on one line of a GitHub annotation, and not too long."""
    text = ascii(str(value))[1:-1]
    return text if len(text) <= MAX_SHOWN else f"{text[:MAX_SHOWN]}..."


def point_x(y: int) -> int | None:
    """Return an x for this y on the curve, with either sign, or None if there is none."""
    x_squared = (y * y - 1) * pow(D * y * y + 1, -1, P) % P
    x = pow(x_squared, (P + 3) // 8, P)
    if x * x % P != x_squared:
        x = x * SQRT_MINUS_ONE % P
    return x if x * x % P == x_squared else None


def double(x: int, y: int) -> tuple[int, int]:
    """Double a point. On this curve the denominators can't be zero."""
    x_squared, y_squared = x * x % P, y * y % P
    return (
        2 * x * y * pow(y_squared - x_squared, -1, P) % P,
        (y_squared + x_squared) * pow(2 + x_squared - y_squared, -1, P) % P,
    )


def key_fault(key: bytes) -> str | None:
    """Say what's wrong with 32 bytes as an Ed25519 public key, if anything."""
    encoded = int.from_bytes(key, "little")
    y = encoded & Y_MASK
    if y >= P:
        return "not a canonical encoding: y is at least p"
    x = point_x(y)
    if x is None:
        return "not a point on the curve"
    if x == 0 and encoded != y:
        return "not a canonical encoding: x is zero and has a sign"
    point = (x, y)
    for _ in range(DOUBLINGS_TO_CLEAR_THE_COFACTOR):
        point = double(*point)
    return "a point of small order" if point == (0, 1) else None


def signer_line_fault(line: str) -> str | None:
    """Say what's wrong with a line as `ssh-ed25519 <base64>`, if anything."""
    fields = line.split(" ")
    if len(fields) != FIELDS_IN_A_KEY_LINE:
        return "it is not exactly a key type and a key, each after a single space"
    if fields[0] != KEY_TYPE:
        return f"it is not an {KEY_TYPE} key"
    if not KEY_FIELD.fullmatch(fields[1]):
        return f"its key is not the base64 of {WIRE_BYTES} bytes"
    raw = base64.b64decode(fields[1])
    if not raw.startswith(KEY_PREFIX):
        return f"its key's bytes are not those of an {KEY_TYPE} key"
    fault = key_fault(raw[len(KEY_PREFIX) :])
    return f"its key is {fault}" if fault else None


def parse_signers(text: str) -> list[str]:
    r"""Return the keys in a signers file: at least one, each a whole line, and none twice.

    Only `\n` ends a line, and a carriage return anywhere is refused, as an editor can show such
    a file unlike how it's read. An empty line, or one whose first character is `#`, is skipped.
    Everything else must be exactly a key: a key's comment usually carries a name, so one is
    refused. The Rust parser of this file must apply the same rule.
    """
    if "\r" in text:
        msg = "the signers file holds a carriage return"
        raise RefusedError(msg)
    keys: list[str] = []
    for number, line in enumerate(text.split("\n"), start=1):
        if not line or line.startswith("#"):
            continue
        fault = signer_line_fault(line)
        if fault is not None:
            msg = f"line {number} of the signers file is refused: {fault}"
            raise RefusedError(msg)
        if line in keys:
            msg = f"line {number} of the signers file repeats a key"
            raise RefusedError(msg)
        keys.append(line)
    if not keys:
        msg = "the signers file holds no key, so no tag can be proved"
        raise RefusedError(msg)
    return keys


def workspace_version(root: Path) -> str:
    """Return the workspace's version, which must be one a release can have."""
    try:
        with (root / "Cargo.toml").open("rb") as file:
            version = tomllib.load(file)["workspace"]["package"]["version"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        msg = f"Cargo.toml has no readable workspace.package.version: {shown(error)}"
        raise RefusedError(msg) from error
    if not isinstance(version, str) or not VERSION.fullmatch(version):
        msg = f"Cargo.toml has the version {shown(version)}, which a release can't have"
        raise RefusedError(msg)
    return version


def read_signers(root: Path) -> list[str]:
    """Return the keys in this repository's signers file."""
    path = root / SIGNERS_FILE
    try:
        # As bytes: reading as text would turn a carriage return into a line's end.
        text = path.read_bytes().decode("utf-8")
    except (OSError, ValueError) as error:
        msg = f"{SIGNERS_FILE} could not be read: {shown(error)}"
        raise RefusedError(msg) from error
    return parse_signers(text)


def refuse_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing a repeated key: two readers can take different ones."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            msg = f"repeated key {shown(key)}"
            raise ValueError(msg)
        result[key] = value
    return result


def refuse_constant(name: str) -> None:
    """Refuse NaN and Infinity, which aren't JSON."""
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def gh_api(path: str) -> object:
    """Return GitHub's answer for a path, as JSON no larger than the cap. The path was checked."""
    try:
        result = subprocess.run(
            ["gh", "api", "--method", "GET", path],
            capture_output=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        msg = f"gh api {shown(path)} could not run: {shown(error)}"
        raise RefusedError(msg) from error
    if result.returncode != 0:
        said = result.stderr.decode("utf-8", errors="replace")
        msg = f"gh api {shown(path)} failed: {shown(said)}"
        raise RefusedError(msg)
    if len(result.stdout) > MAX_ANSWER_BYTES:
        msg = f"gh api {shown(path)} answered more than {MAX_ANSWER_BYTES} bytes"
        raise RefusedError(msg)
    try:
        return json.loads(
            result.stdout.decode("utf-8"),
            object_pairs_hook=refuse_repeats,
            parse_constant=refuse_constant,
        )
    except (ValueError, RecursionError) as error:
        msg = f"gh api {shown(path)} answered what isn't JSON: {shown(error)}"
        raise RefusedError(msg) from error


def tag_object_sha(tag: str, ref: object) -> str:
    """Return the tag object a ref points at, wanting a ref that points at one."""
    if not isinstance(ref, dict) or ref.get("ref") != f"refs/tags/{tag}":
        msg = f"GitHub's answer for the tag {shown(tag)} is not that ref"
        raise RefusedError(msg)
    target = ref.get("object")
    if not isinstance(target, dict):
        msg = f"GitHub's answer for the tag {shown(tag)} has no object"
        raise RefusedError(msg)
    if target.get("type") == "commit":
        msg = f"{shown(tag)} is a lightweight tag: it has no signature to prove"
        raise RefusedError(msg)
    sha = target.get("sha")
    if target.get("type") != "tag" or not isinstance(sha, str) or not COMMIT.fullmatch(sha):
        msg = f"the ref of {shown(tag)} doesn't point at a tag object"
        raise RefusedError(msg)
    return sha


def signed_material(answer: object, requested: str) -> tuple[dict[str, Any], str, str]:
    """Return a tag object's answer, its signed bytes as text and its signature, wanting both."""
    if not isinstance(answer, dict) or answer.get("sha") != requested:
        msg = f"GitHub's answer for the tag object {shown(requested)} is not that object"
        raise RefusedError(msg)
    verification = answer.get("verification")
    if not isinstance(verification, dict):
        msg = "GitHub's answer for the tag object has no verification"
        raise RefusedError(msg)
    payload, signature = verification.get("payload"), verification.get("signature")
    if signature is None or payload is None:
        msg = "the tag is not signed"
        raise RefusedError(msg)
    if not isinstance(payload, str) or not isinstance(signature, str):
        msg = "GitHub's answer has a payload or signature that isn't text"
        raise RefusedError(msg)
    if not payload.endswith("\n"):
        msg = "the tag object's signed bytes have no final newline, which the CLI can't read"
        raise RefusedError(msg)
    if not SSH_SIGNATURE.fullmatch(signature):
        msg = "the tag's signature is not one SSH signature (git tag -s with gpg.format = ssh)"
        raise RefusedError(msg)
    return answer, payload, signature


def tag_headers(payload: str) -> dict[str, str]:
    """Read the header block of a tag object: `object`, `type` and `tag`, each exactly once.

    Read as `landfall-core`'s `verify_tag` reads it, up to the first empty line, so a message
    can't speak for a header.
    """
    headers: dict[str, str] = {}
    for line in payload.split("\n"):
        if not line:
            break
        name, separator, value = line.partition(" ")
        if not separator:
            msg = f"the tag object has a header line with no value: {shown(line)}"
            raise RefusedError(msg)
        if name in {"object", "type", "tag"}:
            if name in headers:
                msg = f"the tag object has a second {name} header"
                raise RefusedError(msg)
            headers[name] = value
    for name in ("object", "type", "tag"):
        if name not in headers:
            msg = f"the tag object has no {name} header"
            raise RefusedError(msg)
    return headers


def check_headers(payload: str, tag: str, sha: str) -> None:
    """Want the signed bytes to name this tag, and this commit as a commit."""
    headers = tag_headers(payload)
    if headers["tag"] != tag:
        msg = f"the tag object is named {shown(headers['tag'])}, not {shown(tag)}"
        raise RefusedError(msg)
    if headers["type"] != "commit":
        msg = f"the tag object points at a {shown(headers['type'])}, not a commit"
        raise RefusedError(msg)
    if headers["object"] != sha:
        msg = f"the tag object points at {shown(headers['object'])}, not {shown(sha)}"
        raise RefusedError(msg)


def check_answer_agrees(answer: dict[str, Any], tag: str, sha: str) -> None:
    """Want the rest of GitHub's answer to agree with the signed bytes, already checked."""
    if answer.get("tag") != tag:
        msg = f"GitHub says the tag object is named {shown(answer.get('tag'))}, not {shown(tag)}"
        raise RefusedError(msg)
    target = answer.get("object")
    if not isinstance(target, dict) or target.get("sha") != sha or target.get("type") != "commit":
        msg = f"GitHub says the tag object points at something other than {shown(sha)}"
        raise RefusedError(msg)


def verify_signature(payload: bytes, signature: str, signers: list[str]) -> None:
    """Have `ssh-keygen` verify the signature, against an allowed-signers file of these keys."""
    with tempfile.TemporaryDirectory() as directory:
        allowed = Path(directory) / "allowed_signers"
        allowed.write_text(
            "".join(f"{PRINCIPAL} {key}\n" for key in signers),
            encoding="utf-8",
        )
        signature_file = Path(directory) / "tag.sig"
        signature_file.write_text(signature, encoding="utf-8")
        try:
            result = subprocess.run(
                [
                    "ssh-keygen",
                    "-Y",
                    "verify",
                    "-n",
                    NAMESPACE,
                    "-I",
                    PRINCIPAL,
                    "-f",
                    str(allowed),
                    "-s",
                    str(signature_file),
                ],
                input=payload,
                capture_output=True,
                check=False,
                timeout=COMMAND_TIMEOUT_SECONDS,
                env={"PATH": os.environ.get("PATH", os.defpath)},
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            msg = f"ssh-keygen could not run: {shown(error)}"
            raise RefusedError(msg) from error
    if result.returncode != 0:
        said = result.stderr.decode("utf-8", errors="replace").strip()
        msg = f"the tag's signature is not from a key in {SIGNERS_FILE}: {shown(said)}"
        raise RefusedError(msg)


def preflight(tag: str, sha: str, repo: str, root: Path, api: Callable[[str], object]) -> None:
    """Refuse unless this tag may be released. Everything local is checked before GitHub."""
    if not COMMIT.fullmatch(sha):
        msg = f"{shown(sha)} is not a full commit id"
        raise RefusedError(msg)
    if not REPOSITORY.fullmatch(repo):
        msg = f"{shown(repo)} is not a repository as owner/name"
        raise RefusedError(msg)
    version = workspace_version(root)
    if tag != f"v{version}":
        msg = f"the tag {shown(tag)} is not v plus the workspace version, {version}"
        raise RefusedError(msg)
    signers = read_signers(root)

    object_sha = tag_object_sha(tag, api(f"repos/{repo}/git/ref/tags/{tag}"))
    answer, payload, signature = signed_material(
        api(f"repos/{repo}/git/tags/{object_sha}"), object_sha
    )
    check_headers(payload, tag, sha)
    check_answer_agrees(answer, tag, sha)
    try:
        signed = payload.encode("utf-8")
    except UnicodeEncodeError as error:
        msg = "the tag object's bytes are not valid text"
        raise RefusedError(msg) from error
    verify_signature(signed, signature, signers)


def main(argv: list[str] | None = None) -> int:
    """Check a tag. Print a refusal as a GitHub annotation, and return 1 for it."""
    parser = argparse.ArgumentParser(description="Prove a tag before releasing it.")
    parser.add_argument("--tag", required=True, help="the tag's name")
    parser.add_argument("--sha", required=True, help="the commit it must point at")
    parser.add_argument("--repo", required=True, help="owner/name")
    args = parser.parse_args(argv)
    try:
        preflight(args.tag, args.sha, args.repo, ROOT, gh_api)
    except RefusedError as refusal:
        print(f"::error title=Release preflight::{refusal}")
        return 1
    except OSError as error:
        print(f"::error title=Release preflight::{shown(error)}")
        return 1
    print(f"{args.tag} is signed by a release key and points at {args.sha}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
