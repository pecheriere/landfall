"""Which key `scripts/release-tag` signs with, and whether the SSH agent offers it.

The same fakes as `test_release_tag.py`: no real git, agent or terminal.
"""

import subprocess
import tempfile
import unittest
from pathlib import Path

from release_tag_loader import release_tag
from test_release_tag import (
    KEY,
    NEW_KEY,
    SHA,
    SIGNERS,
    TAG,
    TAG_ARGS,
    FakeRun,
    FakeTerminal,
    done,
    trusted_file,
)

AGENT = ("ssh-add", "-L")
OTHER = "ssh-ed25519 " + "C" * 68


class SigningKeyTests(unittest.TestCase):
    """The default key, an explicit one, and the agent that has to hold it."""

    def setUp(self) -> None:
        """Answer as a commit ready to tag, with an agent that holds KEY."""
        self.fake = FakeRun()
        self.owner = FakeTerminal(self.fake)
        self.trusted = trusted_file(self, f"# mine\n{KEY}\n")

    def release(self, **options: object) -> str:
        """Run the whole command against the fakes."""
        request = release_tag.Request("1.2.3", SHA, self.trusted, **options)
        return release_tag.release_tag(request, self.fake, self.owner.terminal())

    def refused(self, reason: str, **options: object) -> None:
        """Assert it refuses for this reason, before asking and before any tag."""
        with self.assertRaisesRegex(release_tag.RefusedError, reason):
            self.release(**options)
        self.assertNotIn(TAG_ARGS, self.fake.calls)
        self.assertEqual([k for k, _ in self.owner.events if k == "ask"], [])

    def key_file(self, text: str) -> Path:
        """Write a public key file for one test, and return its path."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        path = Path(directory.name) / "key.pub"
        path.write_text(text, encoding="utf-8")
        return path

    def test_a_trusted_file_with_one_key_signs_by_default(self) -> None:
        """Git gets the key itself, not the file, so its comment lines can't matter."""
        self.trusted = trusted_file(self, f"# one\n# two\n{KEY}\n# three\n")
        self.release()
        self.assertEqual(self.fake.signing_keys, [f"key::{KEY}"])
        self.assertIn(AGENT, self.fake.calls)

    def test_two_trusted_keys_refuse_without_a_signing_key(self) -> None:
        """During a rotation the file can't say which one signs."""
        self.trusted = trusted_file(self, f"{KEY}\n{NEW_KEY}\n")
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n{NEW_KEY}\n")
        self.refused("holds 2 keys.*--signing-key")
        self.assertEqual(self.fake.signing_keys, [])

    def test_two_trusted_keys_sign_with_the_one_named(self) -> None:
        """A path to a file holding that key."""
        self.trusted = trusted_file(self, f"{KEY}\n{NEW_KEY}\n")
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n{NEW_KEY}\n")
        self.fake.answers[AGENT] = done(f"{NEW_KEY}\n")
        path = self.key_file(f"{NEW_KEY} release\n")
        self.release(signing_key=str(path))
        self.assertEqual(self.fake.signing_keys, [f"key::{NEW_KEY}"])

    def test_a_key_in_the_agent_among_others_is_found(self) -> None:
        """By type and base64, whatever the comment."""
        self.fake.answers[AGENT] = done(f"{OTHER} other\n{KEY} release key\n")
        self.release()
        self.assertIn(TAG_ARGS, self.fake.calls)

    def test_a_key_the_agent_lacks_is_refused_with_its_fingerprint(self) -> None:
        """Before the version is asked, and without saying where the agent socket is."""
        self.fake.answers[AGENT] = done(f"{OTHER} other\n")
        self.refused("SSH_AUTH_SOCK.*SHA256:")
        self.assertIsNone(self.owner.calls_when_asked)

    def test_no_agent_is_refused_the_same_way(self) -> None:
        """`ssh-add -L` exits 2 with no agent to talk to."""
        self.fake.answers[AGENT] = done(
            returncode=2, stderr="Could not open a connection to your authentication agent."
        )
        self.refused("SSH_AUTH_SOCK")

    def test_an_agent_with_no_identities_is_refused_the_same_way(self) -> None:
        """`ssh-add -L` exits 1 and prints a sentence, not a key."""
        self.fake.answers[AGENT] = done("The agent has no identities.\n", returncode=1)
        self.refused("SSH_AUTH_SOCK")

    def test_an_agent_that_cannot_run_or_answer_is_refused_the_same_way(self) -> None:
        """No `ssh-add` on PATH, or no answer in time."""

        def failing(args: object) -> subprocess.CompletedProcess:
            if tuple(args) == AGENT:  # type: ignore[call-overload]
                message = "ssh-add could not run"
                raise release_tag.RefusedError(message)
            return self.fake(args)  # type: ignore[arg-type]

        request = release_tag.Request("1.2.3", SHA, self.trusted)
        with self.assertRaisesRegex(release_tag.RefusedError, "SSH_AUTH_SOCK"):
            release_tag.release_tag(request, failing, self.owner.terminal())

    def test_an_explicit_path_is_used_and_its_key_checked_in_the_agent(self) -> None:
        """Git gets the key the file holds, which the agent must hold too."""
        path = self.key_file(f"{OTHER} mine\n")
        self.refused("SSH_AUTH_SOCK", signing_key=str(path))
        self.setUp()
        self.fake.answers[AGENT] = done(f"{OTHER}\n")
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n")
        with self.assertRaisesRegex(release_tag.RefusedError, "isn't signed by a key"):
            self.fake.verified[f"refs/tags/{TAG}"] = done(returncode=1, stderr="no principal")
            self.release(signing_key=str(path))
        self.assertEqual(self.fake.signing_keys, [f"key::{OTHER}"])

    def test_a_key_value_is_parsed_for_the_agent_check(self) -> None:
        """`key::` then the key, with its space; git gets it re-rendered without any comment."""
        self.release(signing_key=f"key::{KEY} a comment")
        self.assertEqual(self.fake.signing_keys, [f"key::{KEY}"])
        self.setUp()
        self.refused("SSH_AUTH_SOCK", signing_key=f"key::{OTHER}")

    def test_a_file_that_isnt_one_key_is_refused(self) -> None:
        """Two keys, none, or text that isn't a key."""
        for text in (
            f"{KEY}\n{NEW_KEY}\n",
            "# only a comment\n",
            "not a key\n",
            "ssh-ed25519 !!!\n",
        ):
            with self.subTest(text=text):
                self.setUp()
                self.refused("exactly one public key", signing_key=str(self.key_file(text)))

    def test_a_missing_file_or_a_bad_key_value_is_refused(self) -> None:
        """Nothing is guessed."""
        self.refused("can't be read", signing_key="/nonexistent/release.pub")
        self.setUp()
        self.refused("isn't an SSH public key", signing_key="key::garbage")
