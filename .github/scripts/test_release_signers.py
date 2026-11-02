"""Unit tests for what release_preflight.py accepts as a signers file."""

import base64
import tempfile
import unittest
from pathlib import Path

import release_preflight
from release_preflight import RefusedError, parse_signers
from release_preflight_support import (
    LINE_SEPARATOR,
    NOT_ON_THE_CURVE,
    REPOSITORY_ROOT,
    RFC_KEY_1,
    RFC_KEY_2,
    SIGN_BIT,
    SMALL_ORDER,
    Keys,
    P,
    RepositoryLayout,
    line,
    little,
    wire,
)


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

    def test_blank_means_empty_and_a_comment_starts_the_line(self) -> None:
        """The one rule, for the Rust parser too: what else looks blank or commented is refused."""
        good = line()
        for name, stray in {
            "spaces": "   ",
            "a tab": "\t",
            "an indented comment": " # old",
            "a file separator, which strip() takes for space": chr(0x1C),
            "a no-break space": chr(0xA0),
        }.items():
            with self.subTest(name=name), self.assertRaises(RefusedError):
                parse_signers(f"{good}\n{stray}\n")
        self.assertEqual(parse_signers(f"#\n#c\n\n{good}\n\n"), [good])

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
        text = path.read_bytes().decode("utf-8")
        if any(item and not item.startswith("#") for item in text.split("\n")):
            self.assertTrue(parse_signers(text))
        else:
            self.assertIn("#", text)


class SignersFileTests(RepositoryLayout):
    """The file as a whole preflight reads it, byte for byte."""

    def test_a_carriage_return_anywhere_is_refused(self) -> None:
        """An editor can show such a file unlike how it's read, and this is the root of trust."""
        key = Keys.public(self.keys.first)
        stranger = Keys.public(self.keys.stranger)
        signers = self.root / "crates" / "cli" / "assets" / "release-signers"
        for name, text in {
            "a line ending in CRLF": f"{key}\r\n",
            "a key after a CR on a comment line": f"# old\r{key}\n",
            "two keys with a CR between": f"{stranger}\r{key}\n",
            "a CR in a comment, beside a good key": f"# old\r{stranger}\n{key}\n",
            "a blank line of a CR, beside a good key": f"{key}\n\r\n",
        }.items():
            with self.subTest(name=name):
                signers.write_bytes(text.encode())
                github = self.signed(self.keys.first)
                with self.assertRaisesRegex(RefusedError, "carriage return"):
                    self.preflight(github)
                self.assertEqual(github.calls, [])

    def test_bytes_that_are_not_text_are_refused(self) -> None:
        """A file that can't be decoded holds nothing that could be read the same way twice."""
        signers = self.root / "crates" / "cli" / "assets" / "release-signers"
        signers.write_bytes(b"# \xff\n" + Keys.public(self.keys.first).encode() + b"\n")
        with self.assertRaisesRegex(RefusedError, "release-signers"):
            self.preflight(self.signed(self.keys.first))


if __name__ == "__main__":
    unittest.main()
