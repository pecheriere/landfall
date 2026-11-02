"""What the tests of release_preflight.py share: real keys, and a fake GitHub."""

import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

import release_preflight
from release_preflight import RefusedError

REPOSITORY_ROOT = Path(__file__).resolve().parents[2]
TAG = "v1.2.3"
SHA = "a" * 40
OTHER_SHA = "b" * 40
TAG_OBJECT_SHA = "c" * 40
REPO = "owner/landfall"
KEY_TYPE = b"ssh-ed25519"
P = 2**255 - 19
LINE_SEPARATOR = chr(0x2028)

# Public keys from RFC 8032's test vectors, so neither is anybody's.
RFC_KEY_1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
RFC_KEY_2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")

# y = 2 is not the y of any point on the curve.
NOT_ON_THE_CURVE = (2).to_bytes(32, "little")

# Every point of small order, in its canonical encoding: for each, anyone can forge a signature.
# The two y of order 8 are libsodium's, whose list this is, and a test multiplies them out.
ORDER_8_Y_1 = 2707385501144840649318225287225658788936804267575313519463743609750303402022
ORDER_8_Y_2 = 55188659117513257062467267217118295137698188065244968500265048394206261417927
SIGN_BIT = 1 << 255
SMALL_ORDER = {
    "the identity (order 1)": 1,
    "y = -1 (order 2)": P - 1,
    "y = 0 (order 4)": 0,
    "y = 0, the other x (order 4)": SIGN_BIT,
    "order 8": ORDER_8_Y_1,
    "order 8, the other x": ORDER_8_Y_1 | SIGN_BIT,
    "order 8, the other y": ORDER_8_Y_2,
    "order 8, the other y and x": ORDER_8_Y_2 | SIGN_BIT,
}


def wire(key: bytes, *, key_type: bytes = KEY_TYPE, key_length: int | None = None) -> bytes:
    """Return a public key in the SSH wire format."""
    length = len(key) if key_length is None else key_length
    return len(key_type).to_bytes(4, "big") + key_type + length.to_bytes(4, "big") + key


def line(key: bytes = RFC_KEY_1) -> str:
    """Return a signers line for an Ed25519 public key."""
    return f"ssh-ed25519 {base64.b64encode(wire(key)).decode()}"


def little(value: int) -> bytes:
    """Return 32 little-endian bytes, as Ed25519 encodes a point."""
    return value.to_bytes(32, "little")


def payload_for(*, tag: str = TAG, sha: str = SHA, kind: str = "commit") -> bytes:
    """Return the bytes of a tag object, up to its signature."""
    return (
        f"object {sha}\ntype {kind}\ntag {tag}\n"
        "tagger Example <example@example.invalid> 1767225600 +0000\n\nrelease\n"
    ).encode()


class Keys:
    """Throwaway keys from `ssh-keygen`, and signatures from them."""

    def __init__(self, directory: Path) -> None:
        """Make the keys. Nothing outlives the test's directory."""
        self.directory = directory
        self.first = self.generate("first")
        self.second = self.generate("second")
        self.stranger = self.generate("stranger")

    def generate(self, name: str) -> Path:
        """Make one key with no passphrase, and return the private key's path."""
        path = self.directory / name
        subprocess.run(
            ["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", str(path)],
            check=True,
        )
        return path

    @staticmethod
    def public(key: Path) -> str:
        """Return a key's signers line, with `ssh-keygen`'s trailing comment dropped if any."""
        fields = key.with_suffix(".pub").read_text(encoding="utf-8").split()
        return f"{fields[0]} {fields[1]}"

    def sign(self, key: Path, payload: bytes, namespace: str = "git") -> str:
        """Return an armored signature, as `git tag -s` makes with an SSH key."""
        message = self.directory / "message"
        message.write_bytes(payload)
        signature = message.with_name("message.sig")
        signature.unlink(missing_ok=True)
        subprocess.run(
            ["ssh-keygen", "-q", "-Y", "sign", "-n", namespace, "-f", str(key), str(message)],
            check=True,
            capture_output=True,
        )
        return signature.read_text(encoding="utf-8")


class FakeGitHub:
    """Answers `gh api` with what it was given, and refuses as a 404 does for anything else."""

    def __init__(self, ref: object, tag_object: object) -> None:
        """Hold the answers for the ref and the tag object."""
        self.answers = {
            f"repos/{REPO}/git/ref/tags/{TAG}": ref,
            f"repos/{REPO}/git/tags/{TAG_OBJECT_SHA}": tag_object,
        }
        self.calls: list[str] = []

    def __call__(self, path: str) -> object:
        """Answer one path."""
        self.calls.append(path)
        if path not in self.answers:
            message = f"gh api {path} failed"
            raise RefusedError(message)
        return self.answers[path]


def annotated_ref(sha: str = TAG_OBJECT_SHA) -> dict[str, object]:
    """Return GitHub's answer for a ref that points at a tag object."""
    return {"ref": f"refs/tags/{TAG}", "object": {"sha": sha, "type": "tag"}}


def tag_answer(
    payload: bytes,
    signature: str | None,
    *,
    tag: str = TAG,
    sha: str = SHA,
) -> dict[str, object]:
    """Return GitHub's answer for a tag object. `verified` is GitHub's opinion, so is left false."""
    return {
        "sha": TAG_OBJECT_SHA,
        "tag": tag,
        "object": {"sha": sha, "type": "commit"},
        "verification": {
            "verified": False,
            "reason": "unknown_key",
            "payload": payload.decode(),
            "signature": signature,
        },
    }


class RepositoryLayout(unittest.TestCase):
    """A test with a `Cargo.toml` and signers file of its own, and throwaway keys."""

    keys: Keys

    @classmethod
    def setUpClass(cls) -> None:
        """Make the keys once: each takes a moment, and none changes."""
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.keys = Keys(Path(directory.name))

    def setUp(self) -> None:
        """Lay out a repository at 1.2.3, trusting the first key."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.write_version("1.2.3")
        self.write_signers(Keys.public(self.keys.first))

    def write_version(self, version: str) -> None:
        """Set the workspace version."""
        (self.root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{version}"\n', encoding="utf-8"
        )

    def write_signers(self, *lines: str) -> None:
        """Set the signers file."""
        path = self.root / "crates" / "cli" / "assets" / "release-signers"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("".join(f"{item}\n" for item in lines), encoding="utf-8")

    def preflight(self, api: object, tag: str = TAG, sha: str = SHA) -> None:
        """Run the whole check."""
        release_preflight.preflight(tag, sha, REPO, self.root, api)

    def signed(self, key: Path, payload: bytes | None = None, **fields: str) -> FakeGitHub:
        """Return a GitHub holding a tag object signed by this key."""
        body = payload if payload is not None else payload_for()
        return FakeGitHub(annotated_ref(), tag_answer(body, self.keys.sign(key, body), **fields))


def fake_command(directory: Path, name: str, script: str) -> None:
    """Put a shell script in a directory, as a command of this name."""
    directory.mkdir(exist_ok=True)
    path = directory / name
    path.write_text(f"#!/bin/sh\n{script}\n", encoding="utf-8")
    path.chmod(0o755)


def fake_gh(directory: Path, ref: object, tag_object: object) -> None:
    """Put a `gh` in a directory that answers these two paths from files, and fails otherwise."""
    directory.mkdir(exist_ok=True)
    (directory / "ref.json").write_text(json.dumps(ref), encoding="utf-8")
    (directory / "tag.json").write_text(json.dumps(tag_object), encoding="utf-8")
    fake_command(
        directory,
        "gh",
        f'test "$*" = "api --method GET repos/{REPO}/git/ref/tags/{TAG}" '
        f'&& exec cat "{directory}/ref.json"\n'
        f'test "$*" = "api --method GET repos/{REPO}/git/tags/{TAG_OBJECT_SHA}" '
        f'&& exec cat "{directory}/tag.json"\n'
        "echo not found >&2\nexit 1",
    )
