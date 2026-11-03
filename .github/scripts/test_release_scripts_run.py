"""Run the release scripts as the workflow does: real processes, under `python3 -I`.

The exit status is all a workflow reads, and `-I` is what they run under, so calling `main` from
a test proves neither. A `gh` on PATH answers instead of GitHub, so nothing here needs a network.
"""

import inspect
import json
import os
import shutil
import subprocess
import sys
import tempfile
import tomllib
import unittest
from pathlib import Path

import assemble_release
import release_preflight
from release_preflight_support import (
    LINE_SEPARATOR,
    REPO,
    REPOSITORY_ROOT,
    SHA,
    TAG,
    Keys,
    RepositoryLayout,
    annotated_ref,
    fake_command,
    fake_gh,
    payload_for,
    tag_answer,
)
from test_assemble_release import BINARIES, INPUTS, OTHERS, bundle, sha256, statement

SCRIPTS = REPOSITORY_ROOT / ".github" / "scripts"
PREFLIGHT = SCRIPTS / "release_preflight.py"
ASSEMBLE = SCRIPTS / "assemble_release.py"
TIMEOUT_SECONDS = 60


def run_script(script: Path, *args: str, path: str | None = None) -> subprocess.CompletedProcess:
    """Run a script in the mode the workflow does, in its own working directory."""
    return subprocess.run(
        [sys.executable, "-I", str(script), *args],
        capture_output=True,
        text=True,
        check=False,
        timeout=TIMEOUT_SECONDS,
        cwd=script.parent,
        env={**os.environ, "PATH": path if path is not None else os.environ["PATH"]},
    )


class PreflightProcessTests(RepositoryLayout):
    """`release_preflight.py` run from a repository's own layout, where `ROOT` finds its files."""

    def setUp(self) -> None:
        """Copy the script to where it lies in a repository, and make a place for a fake `gh`."""
        super().setUp()
        scripts = self.root / ".github" / "scripts"
        scripts.mkdir(parents=True)
        self.script = scripts / PREFLIGHT.name
        shutil.copyfile(PREFLIGHT, self.script)
        self.bin = self.root / "fake-bin"
        self.path = f"{self.bin}:{os.environ['PATH']}"

    def run_preflight(self, tag: str = TAG) -> subprocess.CompletedProcess:
        """Run the copy with this tag."""
        return run_script(self.script, "--tag", tag, "--sha", SHA, "--repo", REPO, path=self.path)

    def answer_with(self, key: Path) -> None:
        """Have the fake `gh` hold a tag object signed by this key."""
        payload = payload_for()
        answer = tag_answer(payload, self.keys.sign(key, payload))
        fake_gh(self.bin, annotated_ref(), answer)

    def test_a_tag_signed_by_a_listed_key_exits_zero(self) -> None:
        """All real but `gh`, and `ROOT` finds the `Cargo.toml` and signers beside the copy."""
        self.answer_with(self.keys.first)
        result = self.run_preflight()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("::error", result.stdout)

    def test_a_tag_signed_by_another_key_exits_one_with_an_annotation(self) -> None:
        """The one integer the workflow reads, and the reason in the form GitHub shows."""
        self.answer_with(self.keys.stranger)
        result = self.run_preflight()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("::error title=Release preflight::"))
        self.assertEqual(result.stderr, "")

    def test_a_key_after_a_carriage_return_exits_one(self) -> None:
        """A key on a comment line, by the real path, which once passed."""
        self.answer_with(self.keys.first)
        signers = self.root / "crates" / "cli" / "assets" / "release-signers"
        signers.write_bytes(f"# old\r{Keys.public(self.keys.first)}\n".encode())
        result = self.run_preflight()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)

    def test_a_gh_killed_by_a_signal_exits_one(self) -> None:
        """Not an answer, whatever the process printed first."""
        fake_command(self.bin, "gh", "echo '{}'\nkill -9 $$")
        result = self.run_preflight()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("::error title=Release preflight::gh api"))

    def test_a_hostile_name_prints_on_one_line(self) -> None:
        """What a signed object says can't be allowed to start a workflow command."""
        payload = payload_for(tag=f"x{LINE_SEPARATOR}::warning::forged")
        answer = tag_answer(payload, self.keys.sign(self.keys.first, payload))
        fake_gh(self.bin, annotated_ref(), answer)
        result = self.run_preflight()
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertEqual(result.stdout.count("\n"), 1, result.stdout)
        self.assertTrue(result.stdout.isascii(), result.stdout)


class RealPreflightTests(unittest.TestCase):
    """The script where it really lies, reading this repository's own files."""

    def test_the_real_script_gets_past_the_version_and_stops_with_no_network(self) -> None:
        """No key yet, so it stops at the signers. With a key, the fake `gh` stops it instead."""
        with (REPOSITORY_ROOT / "Cargo.toml").open("rb") as file:
            version = tomllib.load(file)["workspace"]["package"]["version"]
        bin_directory = Path(self.enterContext(tempfile.TemporaryDirectory()))
        fake_command(bin_directory, "gh", "echo 'not found' >&2\nexit 1")
        result = run_script(
            PREFLIGHT,
            "--tag",
            f"v{version}",
            "--sha",
            SHA,
            "--repo",
            REPO,
            path=f"{bin_directory}:{os.environ['PATH']}",
        )
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertRegex(
            result.stdout, r"^::error title=Release preflight::.*(holds no key|gh api)"
        )
        self.assertNotIn("Cargo.toml", result.stdout)


class AssembleProcessTests(unittest.TestCase):
    """`assemble_release.py` where it really lies: its `ROOT` finds this repository's licences."""

    def setUp(self) -> None:
        """Make a directory of one file, and the bundle that names it."""
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))
        self.out = self.tmp / "out"
        self.out.mkdir()
        (self.out / "one").write_bytes(b"first")
        subjects = [{"name": "one", "digest": {"sha256": sha256(b"first")}}]
        self.bundle_path = self.tmp / "bundle.json"
        self.bundle_path.write_text(json.dumps(bundle(statement(subjects))) + "\n", "utf-8")

    def check_bundle(self, out: Path) -> subprocess.CompletedProcess:
        """Run `check-bundle` on this directory."""
        return run_script(
            ASSEMBLE, "check-bundle", "--bundle", str(self.bundle_path), "--out", str(out)
        )

    def assemble(self, version: str, out: Path) -> subprocess.CompletedProcess:
        """Run `assemble` with inputs laid out as the build jobs leave them."""
        for name in INPUTS:
            path = self.tmp / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(b"binary")
        return run_script(
            ASSEMBLE,
            "assemble",
            "--dist",
            str(self.tmp / "dist"),
            "--macos",
            str(self.tmp / "macos"),
            "--version",
            version,
            "--repo",
            REPO,
            "--out",
            str(out),
        )

    def assert_refused(self, result: subprocess.CompletedProcess) -> None:
        """Want exit 1 and one annotation, with no traceback."""
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith("::error title=Release files::"), result.stdout)
        self.assertEqual(result.stderr, "")

    def test_a_good_bundle_exits_zero(self) -> None:
        """Naming every file."""
        result = self.check_bundle(self.out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_a_bundle_missing_a_file_exits_one(self) -> None:
        """The other direction."""
        (self.out / "two").write_bytes(b"second")
        self.assert_refused(self.check_bundle(self.out))

    def test_assemble_exits_zero_and_takes_this_repositorys_licences(self) -> None:
        """`ROOT` is the repository, as the licences' bytes show."""
        out = self.tmp / "assembled"
        result = self.assemble("1.2.3", out)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual({path.name for path in out.iterdir()}, {*BINARIES, *OTHERS})
        for name in ("LICENSE-MIT", "LICENSE-APACHE"):
            self.assertEqual((out / name).read_bytes(), (REPOSITORY_ROOT / name).read_bytes())

    def test_a_bad_version_exits_one(self) -> None:
        """Before anything is written."""
        out = self.tmp / "assembled"
        self.assert_refused(self.assemble("nope", out))
        self.assertFalse(out.exists())

    def test_an_output_that_is_a_file_exits_one_with_an_annotation(self) -> None:
        """A local failure is a sentence, not a traceback, in both commands."""
        afile = self.tmp / "afile"
        afile.write_bytes(b"x")
        self.assert_refused(self.assemble("1.2.3", afile))
        self.assert_refused(self.check_bundle(afile))


class SharedCodeTests(unittest.TestCase):
    """The scripts run under `python3 -I`, so neither can import the other: keep them equal."""

    def test_the_patterns_are_the_same(self) -> None:
        """What one lets into a name, the other lets into a tag."""
        self.assertEqual(release_preflight.VERSION.pattern, assemble_release.VERSION.pattern)
        self.assertEqual(release_preflight.REPOSITORY.pattern, assemble_release.REPOSITORY.pattern)

    def test_the_helpers_are_the_same(self) -> None:
        """A fix to one is a fix to both."""
        self.assertEqual(release_preflight.MAX_SHOWN, assemble_release.MAX_SHOWN)
        for name in ("shown", "refuse_repeats", "refuse_constant"):
            with self.subTest(name=name):
                self.assertEqual(
                    inspect.getsource(getattr(release_preflight, name)),
                    inspect.getsource(getattr(assemble_release, name)),
                )


if __name__ == "__main__":
    unittest.main()
