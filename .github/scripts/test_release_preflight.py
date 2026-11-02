"""Unit tests for release_preflight.py, with real `ssh-keygen` signatures and a fake GitHub."""

import base64
import contextlib
import io
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import assemble_release
import release_preflight
from release_preflight import RefusedError, parse_signers

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


class VersionTests(RepositoryLayout):
    """The tag is the workspace's version."""

    def test_tag_must_match_workspace_version(self) -> None:
        """A tag that isn't `v` plus the version stops before GitHub is asked anything."""
        for tag in ("v1.2.4", "1.2.3", "v1.2.3-rc.1", "V1.2.3", "v1.2.3\n", "vv1.2.3"):
            with self.subTest(tag=tag):
                github = self.signed(self.keys.first)
                with self.assertRaisesRegex(RefusedError, "version"):
                    self.preflight(github, tag=tag)
                self.assertEqual(github.calls, [])

    def test_a_prerelease_tag_matches_a_prerelease_version(self) -> None:
        """The first tag is meant to be a release candidate."""
        self.write_version("1.2.3-rc.1")
        tag = "v1.2.3-rc.1"
        payload = payload_for(tag=tag)
        answer = tag_answer(payload, self.keys.sign(self.keys.first, payload), tag=tag)
        github = FakeGitHub(annotated_ref(), answer)
        ref = {"ref": f"refs/tags/{tag}", "object": {"sha": TAG_OBJECT_SHA, "type": "tag"}}
        github.answers[f"repos/{REPO}/git/ref/tags/{tag}"] = ref
        self.preflight(github, tag=tag)

    def test_an_unusable_cargo_toml_is_refused(self) -> None:
        """No version, or one that couldn't be a release, or no file, is a refusal."""
        for text in (
            "not toml = = =",
            "[workspace]\n",
            "[workspace.package]\nversion = 1\n",
            '[workspace.package]\nversion = "../1.2.3"\n',
        ):
            with self.subTest(text=text):
                (self.root / "Cargo.toml").write_text(text, encoding="utf-8")
                with self.assertRaisesRegex(RefusedError, "Cargo.toml"):
                    self.preflight(self.signed(self.keys.first))
        (self.root / "Cargo.toml").unlink()
        with self.assertRaisesRegex(RefusedError, "Cargo.toml"):
            self.preflight(self.signed(self.keys.first))

    def test_a_bad_commit_or_repository_stops_before_github(self) -> None:
        """Each would become part of a path or a comparison, so each is checked first."""
        github = self.signed(self.keys.first)
        for sha in ("", "A" * 40, "a" * 39, "a" * 64, f"{'a' * 40}\n", "HEAD"):
            with self.subTest(sha=sha), self.assertRaisesRegex(RefusedError, "commit"):
                release_preflight.preflight(TAG, sha, REPO, self.root, github)
        for repo in ("", "owner", "owner/../x", "a/b/c", "--repo/x", "owner/x y"):
            with self.subTest(repo=repo), self.assertRaisesRegex(RefusedError, "repository"):
                release_preflight.preflight(TAG, SHA, repo, self.root, github)
        self.assertEqual(github.calls, [])

    def test_the_version_pattern_is_the_one_assemble_uses(self) -> None:
        """The scripts run under `python3 -I`, so neither can import the other."""
        self.assertEqual(release_preflight.VERSION.pattern, assemble_release.VERSION.pattern)
        self.assertEqual(release_preflight.REPOSITORY.pattern, assemble_release.REPOSITORY.pattern)


class SignerTests(unittest.TestCase):
    """What may be in the file of trusted keys."""

    def test_signer_table(self) -> None:
        """Only whole lines of a good Ed25519 key, at least one of them."""
        good = line()
        second = line(RFC_KEY_2)
        cases = {
            "empty": ("", None),
            "only blank lines": ("\n\n  \n", None),
            "comment only": ("# nothing yet\n", None),
            "a non-ed25519 key": (f"ssh-rsa {good.split()[1]}\n", None),
            "bad base64": ("ssh-ed25519 !!!!\n", None),
            "a wrong length": (
                f"ssh-ed25519 {base64.b64encode(wire(RFC_KEY_1[:-1])).decode()}\n",
                None,
            ),
            "a trailing comment": (f"{good} someone@example.invalid\n", None),
            "one key": (f"{good}\n", [good]),
            "two keys with comment lines": (
                f"# the old key\n{good}\n\n# the new key\n{second}\n",
                [good, second],
            ),
            "no final end of line": (good, [good]),
        }
        for name, (text, expected) in cases.items():
            with self.subTest(name=name):
                if expected is None:
                    with self.assertRaises(RefusedError):
                        parse_signers(text)
                else:
                    self.assertEqual(parse_signers(text), expected)

    def test_lines_that_only_nearly_hold_a_key_are_refused(self) -> None:
        """Each spelling here is one that some other parser might read differently."""
        good = line()
        encoded = good.split()[1]
        for name, text in {
            "the type alone": "ssh-ed25519\n",
            "the key alone": f"{encoded}\n",
            "a leading space": f" {good}\n",
            "two spaces": f"ssh-ed25519  {encoded}\n",
            "a tab": f"ssh-ed25519\t{encoded}\n",
            "a trailing space": f"{good} \n",
            "a carriage return": f"{good}\r\n",
            "a comment after a key on the line": f"{good} # the key\n",
            "a form feed between lines": f"{good}\f{good}\n",
            "a line separator between lines": f"{good}{LINE_SEPARATOR}{good}\n",
            "a type in another case": f"SSH-ED25519 {encoded}\n",
            "the same key twice": f"{good}\n{good}\n",
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                parse_signers(text)

    def test_wire_formats_that_are_not_an_ed25519_key_are_refused(self) -> None:
        """The field names a type, and the bytes must say the same, in the same layout."""
        bad_type = wire(RFC_KEY_1, key_type=b"ssh-ed25518")
        bad_key_length = wire(RFC_KEY_1, key_length=31)
        for name, raw in {
            "another type in the bytes": bad_type,
            "a key length that lies": bad_key_length,
            "too long": wire(RFC_KEY_1) + b"\0",
            "too short": wire(RFC_KEY_1)[:-1],
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                parse_signers(f"ssh-ed25519 {base64.b64encode(raw).decode()}\n")

    def test_base64_with_anything_more_is_refused(self) -> None:
        """51 bytes fill their last group exactly, so nothing else can spell the same key."""
        encoded = line().split()[1]
        for name, spelled in {
            "stray padding": f"{encoded}=",
            "a character outside the alphabet": f"{encoded[:10]}!{encoded[10:]}",
            "the URL-safe alphabet": encoded.replace("A", "-"),
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                parse_signers(f"ssh-ed25519 {spelled}\n")

    def test_keys_of_small_order_are_refused(self) -> None:
        """A signature on such a key can be forged with no secret: issue 36."""
        for name, encoded in SMALL_ORDER.items():
            with (
                self.subTest(name=name),
                self.assertRaisesRegex(RefusedError, "weak|small order|canonical"),
            ):
                parse_signers(f"{line(little(encoded))}\n")

    def test_every_listed_small_order_point_is_one(self) -> None:
        """The list above is checked against the arithmetic, or it proves little."""
        for name, encoded in SMALL_ORDER.items():
            with self.subTest(name=name):
                self.assertEqual(
                    release_preflight.key_fault(little(encoded)),
                    "a point of small order",
                )

    def test_keys_that_are_not_canonical_are_refused(self) -> None:
        """A y of p or more is another spelling of a smaller y; so is a sign on x = 0."""
        for name, value in {
            "y = p": P,
            "y = p + 1": P + 1,
            "y = 2^255 - 1": 2**255 - 1,
            "a sign bit on x = 0 at y = 1": 1 | SIGN_BIT,
            "a sign bit on x = 0 at y = -1": (P - 1) | SIGN_BIT,
        }.items():
            with self.subTest(name=name), self.assertRaisesRegex(RefusedError, "canonical"):
                parse_signers(f"{line(little(value))}\n")

    def test_a_key_not_on_the_curve_is_refused(self) -> None:
        """Half of all 32-byte strings aren't a point at all."""
        with self.assertRaisesRegex(RefusedError, "not a point"):
            parse_signers(f"{line(NOT_ON_THE_CURVE)}\n")

    def test_a_key_from_ssh_keygen_passes(self) -> None:
        """Strictness that refused a real key would be no use to anyone."""
        with tempfile.TemporaryDirectory() as directory:
            keys = Keys(Path(directory))
            public = Keys.public(keys.first)
        self.assertEqual(parse_signers(f"{public}\n"), [public])

    def test_the_signers_file_in_this_repository_is_well_formed(self) -> None:
        """It holds comments until the owner supplies a key, and good keys after."""
        path = REPOSITORY_ROOT / "crates" / "cli" / "assets" / "release-signers"
        text = path.read_text(encoding="utf-8")
        if any(item.strip() and not item.startswith("#") for item in text.split("\n")):
            self.assertTrue(parse_signers(text))
        else:
            self.assertIn("#", text)


class TagSignatureTests(RepositoryLayout):
    """The tag object as GitHub answers it, proved with `ssh-keygen`."""

    def trust_both(self) -> None:
        """Trust the first and second keys, as during a rotation."""
        self.write_signers(
            "# the old key",
            Keys.public(self.keys.first),
            Keys.public(self.keys.second),
        )

    def test_tag_signature_table(self) -> None:
        """Signed by a listed key passes, and nothing else does."""
        keys = self.keys
        payload = payload_for()
        unsigned = FakeGitHub(annotated_ref(), tag_answer(payload, None))
        lightweight = FakeGitHub(
            {"ref": f"refs/tags/{TAG}", "object": {"sha": SHA, "type": "commit"}},
            tag_answer(payload, keys.sign(keys.first, payload)),
        )
        cases: dict[str, tuple[FakeGitHub, str | None]] = {
            "signed by a listed key": (self.signed(keys.first), None),
            "signed by the second of two listed keys": (self.signed(keys.second), None),
            "signed by an unlisted key": (self.signed(keys.stranger), "signature"),
            "unsigned": (unsigned, "not signed"),
            "lightweight": (lightweight, "lightweight"),
            "naming another tag": (
                self.signed(keys.first, payload_for(tag="v1.2.2")),
                "v1.2.2",
            ),
            "naming another commit": (
                self.signed(keys.first, payload_for(sha=OTHER_SHA)),
                OTHER_SHA,
            ),
        }
        self.trust_both()
        for name, (github, expected) in cases.items():
            with self.subTest(name=name):
                if expected is None:
                    self.preflight(github)
                else:
                    with self.assertRaisesRegex(RefusedError, expected):
                        self.preflight(github)

    def test_a_tag_made_by_git_passes(self) -> None:
        """The fixture `git tag -s` wrote for `landfall-core`, cut where GitHub cuts it."""
        fixtures = REPOSITORY_ROOT / "crates" / "core" / "tests" / "fixtures" / "tag"
        raw = (fixtures / "valid.tag").read_text(encoding="utf-8")
        payload, armor, rest = raw.partition("-----BEGIN SSH SIGNATURE-----")
        commit = payload.split("\n")[0].removeprefix("object ")
        self.write_signers(" ".join((fixtures / "signer.pub").read_text("utf-8").split()[:2]))
        answer = tag_answer(payload.encode(), armor + rest, sha=commit)
        self.preflight(FakeGitHub(annotated_ref(), answer), sha=commit)

    def test_github_saying_verified_is_not_believed(self) -> None:
        """An unlisted key that GitHub knows and shows as verified is still unlisted."""
        github = self.signed(self.keys.stranger)
        tag_object = github.answers[f"repos/{REPO}/git/tags/{TAG_OBJECT_SHA}"]
        tag_object["verification"]["verified"] = True
        tag_object["verification"]["reason"] = "valid"
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signature_for_other_bytes_is_refused(self) -> None:
        """A listed key's real signature, moved onto a changed message."""
        payload = payload_for()
        signature = self.keys.sign(self.keys.first, payload)
        changed = payload + b"and more\n"
        github = FakeGitHub(annotated_ref(), tag_answer(changed, signature))
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signature_in_another_namespace_is_refused(self) -> None:
        """A key's signature on a file isn't its signature on a tag."""
        payload = payload_for()
        signature = self.keys.sign(self.keys.first, payload, namespace="file")
        github = FakeGitHub(annotated_ref(), tag_answer(payload, signature))
        with self.assertRaisesRegex(RefusedError, "signature"):
            self.preflight(github)

    def test_a_signed_tag_of_something_other_than_a_commit_is_refused(self) -> None:
        """A tag of a tag or of a tree isn't a release of this commit."""
        for kind in ("tag", "tree"):
            with self.subTest(kind=kind):
                github = self.signed(self.keys.first, payload_for(kind=kind))
                with self.assertRaisesRegex(RefusedError, kind):
                    self.preflight(github)

    def test_the_payload_is_what_counts_and_not_the_message(self) -> None:
        """The right headers in the message, under wrong real ones, don't help."""
        fake = (
            f"object {OTHER_SHA}\ntype commit\ntag v1.2.2\n"
            "tagger Example <example@example.invalid> 1767225600 +0000\n\n"
            f"object {SHA}\ntype commit\ntag {TAG}\n"
        ).encode()
        with self.assertRaisesRegex(RefusedError, "v1.2.2"):
            self.preflight(self.signed(self.keys.first, fake))

    def test_repeated_or_missing_headers_are_refused(self) -> None:
        """A signed object two readers could read two ways isn't a proof of either."""
        for name, payload in {
            "a second object": (f"object {OTHER_SHA}\n{payload_for().decode()}").encode(),
            "a second tag": (f"tag v9.9.9\n{payload_for().decode()}").encode(),
            "no object": b"type commit\ntag v1.2.3\n\nrelease\n",
            "no type": f"object {SHA}\ntag v1.2.3\n\nrelease\n".encode(),
            "no tag": f"object {SHA}\ntype commit\n\nrelease\n".encode(),
            "a header with no value": f"object {SHA}\ntype commit\ntag v1.2.3\nx\n\n".encode(),
            "nothing": b"",
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(self.signed(self.keys.first, payload))

    def test_a_tag_object_answer_disagreeing_with_its_payload_is_refused(self) -> None:
        """The signed bytes decide, but an answer at odds with them is not a GitHub to trust."""
        for name, fields in {
            "another tag": {"tag": "v9.9.9"},
            "another object": {"sha": OTHER_SHA},
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(self.signed(self.keys.first, **fields))

    def test_a_tag_object_answer_for_another_object_is_refused(self) -> None:
        """Asked for one object, an answer about another."""
        github = self.signed(self.keys.first)
        github.answers[f"repos/{REPO}/git/tags/{TAG_OBJECT_SHA}"]["sha"] = OTHER_SHA
        with self.assertRaises(RefusedError):
            self.preflight(github)

    def test_openpgp_signature_is_refused_by_name(self) -> None:
        """A tag signed the other way is a mistake worth a sentence, not a verify failure."""
        armor = "-----BEGIN PGP SIGNATURE-----\n\nAA==\n-----END PGP SIGNATURE-----\n"
        github = FakeGitHub(annotated_ref(), tag_answer(payload_for(), armor))
        with self.assertRaisesRegex(RefusedError, "SSH"):
            self.preflight(github)

    def test_strange_answers_are_refused(self) -> None:
        """Anything that isn't what GitHub answers, in any position, is a refusal."""
        good_tag = tag_answer(payload_for(), self.keys.sign(self.keys.first, payload_for()))
        for name, github in {
            "a list for the ref": FakeGitHub([annotated_ref()], good_tag),
            "another ref": FakeGitHub(
                {"ref": "refs/tags/other", "object": {"sha": TAG_OBJECT_SHA, "type": "tag"}},
                good_tag,
            ),
            "a ref with no object": FakeGitHub({"ref": f"refs/tags/{TAG}"}, good_tag),
            "a tag object that is a list": FakeGitHub(annotated_ref(), []),
            "no verification": FakeGitHub(
                annotated_ref(),
                {key: value for key, value in good_tag.items() if key != "verification"},
            ),
            "a numeric payload": FakeGitHub(
                annotated_ref(),
                {**good_tag, "verification": {"payload": 1, "signature": "x"}},
            ),
            "a numeric signature": FakeGitHub(
                annotated_ref(),
                {**good_tag, "verification": {"payload": "x", "signature": 1}},
            ),
            "a lone surrogate in the message": FakeGitHub(
                annotated_ref(),
                {
                    **good_tag,
                    "verification": {
                        "payload": payload_for().decode() + "\ud800",
                        "signature": good_tag["verification"]["signature"],
                    },
                },
            ),
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                self.preflight(github)

    def test_a_ref_that_points_at_no_tag_object_stops_there(self) -> None:
        """Its sha would become part of a path, so nothing else is asked with one that's strange."""
        for name, target in {
            "a path for a sha": {"sha": "../../x", "type": "tag"},
            "an uppercase sha": {"sha": TAG_OBJECT_SHA.upper(), "type": "tag"},
            "a numeric sha": {"sha": 1, "type": "tag"},
            "a tree": {"sha": TAG_OBJECT_SHA, "type": "tree"},
            "no type": {"sha": TAG_OBJECT_SHA},
        }.items():
            with self.subTest(name=name):
                github = FakeGitHub({"ref": f"refs/tags/{TAG}", "object": target}, {})
                with self.assertRaisesRegex(RefusedError, "tag object"):
                    self.preflight(github)
                self.assertEqual(len(github.calls), 1)

    def test_a_404_is_a_refusal(self) -> None:
        """A tag GitHub doesn't know is not one to publish."""
        github = FakeGitHub(annotated_ref(), {})
        github.answers = {}
        with self.assertRaisesRegex(RefusedError, "gh api"):
            self.preflight(github)

    def test_no_signers_stops_before_github(self) -> None:
        """A build that trusts no key has nothing to prove the tag with."""
        self.write_signers("# nothing yet")
        github = self.signed(self.keys.first)
        with self.assertRaisesRegex(RefusedError, "key"):
            self.preflight(github)
        self.assertEqual(github.calls, [])

    def test_a_missing_signers_file_is_refused(self) -> None:
        """The same, with no file."""
        (self.root / "crates" / "cli" / "assets" / "release-signers").unlink()
        with self.assertRaisesRegex(RefusedError, "release-signers"):
            self.preflight(self.signed(self.keys.first))

    def test_ssh_keygen_gets_no_token_and_no_shell(self) -> None:
        """It needs neither, and what it reads arrives as a file or on stdin."""
        github = self.signed(self.keys.first)
        run = subprocess.run
        seen: list[tuple[list[str], dict[str, object]]] = []

        def spy(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
            seen.append((args, kwargs))
            return run(args, **kwargs)

        with (
            mock.patch.dict(os.environ, {"GH_TOKEN": "secret"}),
            mock.patch.object(release_preflight.subprocess, "run", spy),
        ):
            self.preflight(github)
        self.assertEqual(len(seen), 1)
        args, kwargs = seen[0]
        self.assertEqual(
            args[:7],
            ["ssh-keygen", "-Y", "verify", "-n", "git", "-I", "landfall-release"],
        )
        self.assertNotIn("shell", kwargs)
        self.assertNotIn("GH_TOKEN", kwargs["env"])
        self.assertEqual(kwargs["input"], payload_for())


class GhApiTests(unittest.TestCase):
    """How GitHub's answer is read, with `subprocess.run` answering for `gh`."""

    def answer(self, stdout: bytes, returncode: int = 0) -> object:
        """Call `gh_api` with this as the command's result."""
        result = subprocess.CompletedProcess([], returncode, stdout=stdout, stderr=b"gh says no")
        with mock.patch.object(release_preflight.subprocess, "run", return_value=result) as run:
            answer = release_preflight.gh_api("repos/owner/landfall/git/ref/tags/v1.2.3")
        self.assertEqual(
            run.call_args.args[0],
            ["gh", "api", "--method", "GET", "repos/owner/landfall/git/ref/tags/v1.2.3"],
        )
        return answer

    def test_an_answer_is_parsed(self) -> None:
        """The usual case."""
        self.assertEqual(self.answer(b'{"a": 1}'), {"a": 1})

    def test_failure_is_a_refusal(self) -> None:
        """Whatever `gh` said, and without repeating it unsafely."""
        with self.assertRaisesRegex(RefusedError, "gh says no"):
            self.answer(b"", returncode=1)

    def test_an_oversized_answer_is_refused_before_parsing(self) -> None:
        """Everything fetched is hostile."""
        with self.assertRaisesRegex(RefusedError, "bytes"):
            self.answer(b" " * (release_preflight.MAX_ANSWER_BYTES + 1))

    def test_answers_that_are_not_json_are_refused(self) -> None:
        """Including JSON a stricter reader wouldn't take."""
        for raw in (
            b"not json",
            b"\xff\xfe",
            b'{"a": NaN}',
            b'{"a": 1, "a": 2}',
            b"[" * 100_000,
        ):
            with self.subTest(raw=raw[:20]), self.assertRaises(RefusedError):
                self.answer(raw)

    def test_a_missing_gh_is_a_refusal(self) -> None:
        """Neither a missing command nor a hung one is a traceback."""
        for error in (FileNotFoundError("gh"), subprocess.TimeoutExpired("gh", 1)):
            with (
                self.subTest(error=error),
                mock.patch.object(release_preflight.subprocess, "run", side_effect=error),
                self.assertRaises(RefusedError),
            ):
                release_preflight.gh_api("repos/owner/landfall/git/ref/tags/v1.2.3")


class MainTests(RepositoryLayout):
    """The command line, end to end, with a `gh` on PATH that answers from files."""

    def install_gh(self, ref: object, tag_object: object) -> None:
        """Put a fake `gh` first on PATH for this test."""
        directory = self.root / "fake-bin"
        directory.mkdir()
        (directory / "ref.json").write_text(json.dumps(ref), encoding="utf-8")
        (directory / "tag.json").write_text(json.dumps(tag_object), encoding="utf-8")
        script = directory / "gh"
        script.write_text(
            "#!/bin/sh\n"
            'test "$1 $2 $3 $4" = "api --method GET '
            f'repos/{REPO}/git/ref/tags/{TAG}" && exec cat "{directory}/ref.json"\n'
            'test "$1 $2 $3 $4" = "api --method GET '
            f'repos/{REPO}/git/tags/{TAG_OBJECT_SHA}" && exec cat "{directory}/tag.json"\n'
            "echo not found >&2\nexit 1\n",
            encoding="utf-8",
        )
        script.chmod(0o755)
        patch = mock.patch.dict(os.environ, {"PATH": f"{directory}:{os.environ['PATH']}"})
        patch.start()
        self.addCleanup(patch.stop)
        root = mock.patch.object(release_preflight, "ROOT", self.root)
        root.start()
        self.addCleanup(root.stop)

    def run_main(self, tag: str = TAG) -> tuple[int, str]:
        """Run `main`. Return its exit status and what it printed."""
        printed = io.StringIO()
        with contextlib.redirect_stdout(printed):
            status = release_preflight.main(["--tag", tag, "--sha", SHA, "--repo", REPO])
        return status, printed.getvalue()

    def test_a_good_tag_exits_zero(self) -> None:
        """Through `gh`, `ssh-keygen` and the files, all real but the first."""
        payload = payload_for()
        answer = tag_answer(payload, self.keys.sign(self.keys.first, payload))
        self.install_gh(annotated_ref(), answer)
        status, printed = self.run_main()
        self.assertEqual(status, 0, printed)
        self.assertNotIn("::error", printed)

    def test_a_bad_tag_exits_one_with_an_annotation(self) -> None:
        """An unlisted key, and the reason in the form GitHub shows."""
        payload = payload_for()
        answer = tag_answer(payload, self.keys.sign(self.keys.stranger, payload))
        self.install_gh(annotated_ref(), answer)
        status, printed = self.run_main()
        self.assertEqual(status, 1)
        self.assertTrue(printed.startswith("::error title=Release preflight::"), printed)

    def test_a_hostile_name_prints_on_one_line(self) -> None:
        """What a signed object or GitHub says can't be allowed to start a workflow command."""
        payload = payload_for(tag=f"x{LINE_SEPARATOR}::warning::forged")
        answer = tag_answer(payload, self.keys.sign(self.keys.first, payload))
        self.install_gh(annotated_ref(), answer)
        status, printed = self.run_main()
        self.assertEqual(status, 1)
        self.assertEqual(printed.count("\n"), 1, printed)
        self.assertTrue(printed.isascii(), printed)


if __name__ == "__main__":
    unittest.main()
