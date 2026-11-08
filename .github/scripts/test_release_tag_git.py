"""`scripts/release-tag` against real git: tags signed by throwaway keys in a throwaway repository.

The repository reads none of this machine's git configuration.
"""

import os
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from release_preflight_support import Keys
from release_tag_loader import release_tag

TAG = "v1.2.3"
OTHER_SHA = "d" * 40


class SignedTagTests(unittest.TestCase):
    """`verify_tag` against a real tag, signed by a throwaway key in a throwaway repository."""

    keys: Keys

    @classmethod
    def setUpClass(cls) -> None:
        """Make the keys once."""
        directory = tempfile.TemporaryDirectory()
        cls.addClassCleanup(directory.cleanup)
        cls.keys = Keys(Path(directory.name))

    def setUp(self) -> None:
        """Make a repository with one commit, reading none of this machine's git configuration."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.env = {
            "PATH": os.environ["PATH"],
            "HOME": str(self.root),
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_AUTHOR_NAME": "Example",
            "GIT_AUTHOR_EMAIL": "example@example.invalid",
            "GIT_COMMITTER_NAME": "Example",
            "GIT_COMMITTER_EMAIL": "example@example.invalid",
        }
        self.git("init", "--quiet")
        tree = self.git("mktree", stdin="").strip()
        self.sha = self.git("commit-tree", tree, "-m", "first").strip()

    def git(self, *args: str, stdin: str | None = None) -> str:
        """Run git in the throwaway repository, and return what it printed."""
        return subprocess.run(
            ["git", "-C", str(self.root), *args],
            input=stdin,
            capture_output=True,
            text=True,
            check=True,
            env=self.env,
        ).stdout

    def in_repository(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        """Run the script's git commands in the throwaway repository."""
        return subprocess.run(
            ["git", "-C", str(self.root), *args[1:]],
            capture_output=True,
            text=True,
            check=False,
            env=self.env,
        )

    def sign_with(self, key: Path, tag: str = TAG) -> None:
        """Make a tag as the script does, signed by this key, at `self.sha`."""
        self.git(
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={key}",
            "tag",
            "--sign",
            "--message",
            tag,
            tag,
            self.sha,
        )

    def test_a_tag_signed_by_a_listed_key_passes(self) -> None:
        """Through `git verify-tag` and an allowed-signers file of the signers' keys."""
        self.sign_with(self.keys.first)
        keys = [Keys.public(self.keys.second), Keys.public(self.keys.first)]
        release_tag.verify_tag(self.in_repository, TAG, self.sha, keys)

    def test_a_tag_signed_by_another_key_is_refused(self) -> None:
        """What `--signing-key` is for."""
        self.sign_with(self.keys.stranger)
        with self.assertRaisesRegex(release_tag.RefusedError, "isn't signed by a key"):
            release_tag.verify_tag(
                self.in_repository, TAG, self.sha, [Keys.public(self.keys.first)]
            )

    def commit_with_signers(
        self, signers: str, parent: str | None = None, message: str = "a commit"
    ) -> str:
        """Make a commit whose only file is the signers file, and return it."""
        blob = self.git("hash-object", "-w", "--stdin", stdin=signers).strip()
        tree = self.git("mktree", stdin=f"100644 blob {blob}\trelease-signers\n").strip()
        for name in ("assets", "cli", "crates"):
            tree = self.git("mktree", stdin=f"040000 tree {tree}\t{name}\n").strip()
        parents = ["-p", parent] if parent else []
        return self.git("commit-tree", tree, *parents, "-m", message).strip()

    def test_a_key_added_in_the_repository_cant_certify_a_tag_or_hide_itself(self) -> None:
        """The reviewers' case, with real git and real keys.

        A commit adds the stranger's key to the signers file, and the stranger signs a higher tag
        at it, so by the repository's own file that tag looks like the last release. The helper
        picks the genuine older tag, names the stranger's, shows the commit that added the key and
        the line it added, and refuses because the keys aren't the ones the owner trusts.
        """
        first = Keys.public(self.keys.first)
        stranger = Keys.public(self.keys.stranger)
        released = self.commit_with_signers(f"{first}\n", message="release 1.2.2")
        added = self.commit_with_signers(f"{first}\n{stranger}\n", released, "tidy the assets")
        head = self.commit_with_signers(f"{first}\n{stranger}\n", added, "bump to 1.3.0")
        self.sha = released
        self.sign_with(self.keys.first, "v1.2.2")
        self.sha = added
        self.sign_with(self.keys.stranger, "v1.2.9")

        previous, unverified = release_tag.previous_release(self.in_repository, head, [first])
        self.assertEqual((previous, unverified), ("v1.2.2", ["v1.2.9"]))

        said: list[str] = []
        state = release_tag.Ready(
            "v1.3.0", head, "42", [first, stranger], [first], previous, unverified
        )
        with self.assertRaisesRegex(release_tag.RefusedError, "aren't the keys you trust"):
            release_tag.show(state, self.in_repository, said.append)
        shown = "\n".join(said)
        self.assertIn("v1.2.9", shown.split("\n")[1])
        self.assertIn("tidy the assets", shown)
        self.assertIn(f"+{stranger}", shown)
        self.assertIn(release_tag.fingerprint(stranger), shown)

    def test_with_no_trusted_tag_there_is_no_previous_release(self) -> None:
        """A tag only the stranger signed is named, and doesn't count."""
        first = Keys.public(self.keys.first)
        head = self.commit_with_signers(f"{first}\n")
        self.sha = head
        self.sign_with(self.keys.stranger, "v1.2.9")
        self.git("tag", "v1.3.0", head)
        found = release_tag.previous_release(self.in_repository, head, [first])
        self.assertEqual(found, (None, ["v1.3.0", "v1.2.9"]))

    def test_fingerprints_are_the_ones_ssh_keygen_shows(self) -> None:
        """What the owner compares with SECURITY.md has to be in the same form."""
        for key in (self.keys.first, self.keys.second):
            listed = subprocess.run(
                ["ssh-keygen", "-l", "-f", str(key.with_suffix(".pub"))],
                capture_output=True,
                text=True,
                check=True,
            ).stdout.split()[1]
            with self.subTest(key=key.name):
                self.assertEqual(release_tag.fingerprint(Keys.public(key)), listed)
        self.assertIn("not a key", release_tag.fingerprint("ssh-ed25519"))

    def test_a_tag_of_another_commit_is_refused(self) -> None:
        """The tag must name the commit whose dry run passed."""
        self.sign_with(self.keys.first)
        with self.assertRaisesRegex(release_tag.RefusedError, "doesn't name"):
            release_tag.verify_tag(
                self.in_repository, TAG, OTHER_SHA, [Keys.public(self.keys.first)]
            )


if __name__ == "__main__":
    unittest.main()
