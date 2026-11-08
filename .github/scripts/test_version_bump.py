"""`version_bump.py`, which decides whether a push to main gets the release dry run."""

import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import version_bump
from release_preflight_support import fake_command

SCRIPT = Path(__file__).resolve().parent / "version_bump.py"
BEFORE = "a" * 40
TIMEOUT_SECONDS = 60


def manifest(version: str) -> str:
    """Return a workspace `Cargo.toml` at this version."""
    return f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n'


class DecisionTests(unittest.TestCase):
    """The comparison, with no process."""

    def test_a_changed_version_builds(self) -> None:
        """Any change, a release candidate included."""
        self.assertTrue(version_bump.changed(manifest("1.2.3"), manifest("1.2.4-rc.1")))

    def test_an_unchanged_version_does_not(self) -> None:
        """Whatever else in the file changed."""
        before = manifest("1.2.3")
        after = before + '\n[workspace.dependencies]\nserde = "1"\n'
        self.assertFalse(version_bump.changed(before, after))

    def test_a_manifest_with_no_version_is_refused(self) -> None:
        """Failing the job is better than skipping a build that was wanted."""
        for text in ("[workspace]\n", "not toml [", "[workspace.package]\nversion = 1\n"):
            with self.subTest(text=text), self.assertRaises(version_bump.RefusedError):
                version_bump.changed(text, manifest("1.2.3"))

    def test_only_a_full_commit_reaches_git(self) -> None:
        """`github.event.before` comes from the event, so it is checked before it's an argument."""
        for before in ("", "HEAD", "a" * 39, "A" * 40, f"--output={'a' * 40}"):
            with self.subTest(before=before), self.assertRaises(version_bump.RefusedError):
                version_bump.manifest_at(before, Path())


class ProcessTests(unittest.TestCase):
    """The script as the workflow runs it, under `python3 -I`, with a `git` that answers instead."""

    def setUp(self) -> None:
        """Lay out a repository at 1.2.3 with the script in it, and a `git` that shows a file."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        scripts = self.root / ".github" / "scripts"
        scripts.mkdir(parents=True)
        shutil.copyfile(SCRIPT, scripts / SCRIPT.name)
        (self.root / "Cargo.toml").write_text(manifest("1.2.3"), encoding="utf-8")
        self.bin = self.root / "fake-bin"
        self.before = self.root / "before.toml"
        fake_command(
            self.bin,
            "git",
            f'test "$*" = "show {BEFORE}:Cargo.toml" && exec cat "{self.before}"\n'
            "echo unknown revision >&2\nexit 128",
        )
        self.output = self.root / "output"

    def run_script(self, before: str = BEFORE) -> subprocess.CompletedProcess:
        """Run the copy against the fake `git`."""
        return subprocess.run(
            [
                sys.executable,
                "-I",
                str(self.root / ".github" / "scripts" / SCRIPT.name),
                "--before",
                before,
                "--output",
                str(self.output),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
            env={**os.environ, "PATH": f"{self.bin}:{os.environ['PATH']}"},
        )

    def test_a_bump_appends_build_true(self) -> None:
        """Appended, as `$GITHUB_OUTPUT` may already hold other outputs."""
        self.before.write_text(manifest("1.2.2"), encoding="utf-8")
        self.output.write_text("other=1\n", encoding="utf-8")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "other=1\nbuild=true\n")

    def test_no_bump_appends_build_false(self) -> None:
        """The run then stops after `version`."""
        self.before.write_text(manifest("1.2.3"), encoding="utf-8")
        result = self.run_script()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(self.output.read_text(encoding="utf-8"), "build=false\n")

    def test_an_unreadable_before_fails_and_writes_nothing(self) -> None:
        """An annotation on stdout, and no answer the workflow could read as one."""
        result = self.run_script(before="b" * 40)
        self.assertEqual(result.returncode, 1)
        self.assertIn("::error title=Release dry run::", result.stdout)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
