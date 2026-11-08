"""`homebrew_tap.py`: what reaches the tap, and how, with a fake `gh` answering from a table."""

import base64
import json
import os
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

import homebrew_tap

REPO = "owner/landfall"
TAP = "owner/homebrew-tap"
VERSION = "1.2.3"
TAG = "v1.2.3"
BRANCH = "landfall-1.2.3"
MAIN_SHA = "a" * 40
BLOB_SHA = "b" * 40
PULL = "https://github.com/owner/homebrew-tap/pull/7"
FORMULA = b'class Landfall < Formula\n  desc "x"\nend\n'
SCRIPT = Path(__file__).resolve().parent / "homebrew_tap.py"
TIMEOUT_SECONDS = 60

PULLS = ("gh", "pr", "list", "--repo", TAP, "--head", BRANCH, "--state", "all", "--json", "url")
REFS = ("gh", "api", f"repos/{TAP}/git/matching-refs/heads/{BRANCH}")
MAIN = ("gh", "api", f"repos/{TAP}/git/ref/heads/main")
TREE = ("gh", "api", f"repos/{TAP}/git/trees/{MAIN_SHA}?recursive=1")
CREATE = (
    "gh",
    "api",
    "--method",
    "POST",
    f"repos/{TAP}/git/refs",
    "-f",
    f"ref=refs/heads/{BRANCH}",
    "-f",
    f"sha={MAIN_SHA}",
)
PUT = (
    "gh",
    "api",
    "--method",
    "PUT",
    f"repos/{TAP}/contents/Formula/landfall.rb",
    "-f",
    f"message=landfall {VERSION}",
    "-f",
    f"content={base64.b64encode(FORMULA).decode()}",
    "-f",
    f"branch={BRANCH}",
)
MERGE = ("gh", "pr", "merge", PULL, "--repo", TAP, "--auto", "--squash")


def done(stdout: str = "", returncode: int = 0) -> subprocess.CompletedProcess:
    """Return a finished command's result."""
    return subprocess.CompletedProcess([], returncode, stdout, "")


def tree(*entries: dict[str, object], truncated: bool = False) -> str:
    """Return GitHub's answer for a tree."""
    return json.dumps({"sha": MAIN_SHA, "tree": list(entries), "truncated": truncated})


class FakeGh:
    """Answers as a tap with a formula already in it and nothing for this version."""

    def __init__(self) -> None:
        """Set the table."""
        self.calls: list[tuple[str, ...]] = []
        self.answers = {
            PULLS: done("[]"),
            REFS: done(json.dumps([{"ref": f"refs/heads/{BRANCH}0"}])),
            MAIN: done(json.dumps({"object": {"sha": MAIN_SHA, "type": "commit"}})),
            TREE: done(
                tree(
                    {"path": "Formula", "type": "tree", "sha": "c" * 40},
                    {"path": "Formula/landfall.rb", "type": "blob", "sha": BLOB_SHA},
                )
            ),
            CREATE: done("{}"),
            (*PUT, "-f", f"sha={BLOB_SHA}"): done("{}"),
            PUT: done("{}"),
            MERGE: done(),
        }

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        """Answer one command; `gh pr create` by its fixed start."""
        call = tuple(args)
        self.calls.append(call)
        if call[:3] == ("gh", "pr", "create"):
            return done(f"{PULL}\n")
        if call not in self.answers:
            message = f"unexpected command: {call}"
            raise AssertionError(message)
        return self.answers[call]


class ProposeTests(unittest.TestCase):
    """The pull request, through the API alone."""

    def setUp(self) -> None:
        """Answer as a tap with an older formula."""
        self.gh = FakeGh()

    def propose(self, version: str = VERSION, repo: str = REPO) -> str:
        """Propose FORMULA."""
        return homebrew_tap.propose(FORMULA, version, repo, self.gh)

    def test_a_new_version_gets_a_branch_a_file_a_pull_request_and_auto_merge(self) -> None:
        """In that order, replacing the formula by its blob, and squash-merged when green."""
        said = self.propose()
        self.assertIn(PULL, said)
        writes = [c for c in self.gh.calls if c[:2] != ("gh", "api") or "--method" in c]
        self.assertEqual(writes[0], PULLS)
        self.assertEqual(writes[1:3], [CREATE, (*PUT, "-f", f"sha={BLOB_SHA}")])
        create = writes[3]
        self.assertEqual(
            create[:9], ("gh", "pr", "create", "--repo", TAP, "--base", "main", "--head", BRANCH)
        )
        self.assertIn(f"https://github.com/{REPO}/releases/tag/{TAG}", create[-1])
        self.assertEqual(writes[4:], [MERGE])

    def test_a_tap_with_no_formula_gets_one_with_no_blob(self) -> None:
        """The contents API creates the file when no sha is sent."""
        self.gh.answers[TREE] = done(tree({"path": "README.md", "type": "blob", "sha": "d" * 40}))
        self.propose()
        self.assertIn(PUT, self.gh.calls)

    def test_an_existing_pull_request_or_branch_stops_cleanly(self) -> None:
        """An earlier run got there: say so, write nothing."""
        self.gh.answers[PULLS] = done(json.dumps([{"url": PULL}]))
        self.assertIn("already exists", self.propose())
        self.assertEqual(self.gh.calls, [PULLS])
        self.setUp()
        self.gh.answers[REFS] = done(json.dumps([{"ref": f"refs/heads/{BRANCH}"}]))
        self.assertIn("already exists", self.propose())
        self.assertEqual(self.gh.calls, [PULLS, REFS])

    def test_a_prerelease_or_a_strange_version_or_repo_is_refused_before_any_call(self) -> None:
        """Release candidates never reach the tap, and every value is checked first."""
        for version, repo in (
            ("1.2.3-rc.1", REPO),
            ("1.2", REPO),
            ("1.2.3 --admin", REPO),
            (VERSION, "owner"),
            (VERSION, "-owner/landfall"),
        ):
            with self.subTest(version=version, repo=repo):
                self.setUp()
                with self.assertRaises(homebrew_tap.RefusedError):
                    self.propose(version, repo)
                self.assertEqual(self.gh.calls, [])

    def test_answers_that_cant_be_trusted_stop_before_any_write(self) -> None:
        """A main that isn't a commit, a tree read in part, a formula that isn't a file."""
        for key, answer in (
            (MAIN, done(json.dumps({"object": {"sha": "main"}}))),
            (TREE, done(tree(truncated=True))),
            (TREE, done(tree({"path": "Formula/landfall.rb", "type": "tree", "sha": BLOB_SHA}))),
            (PULLS, done("{}")),
            (REFS, done("not json")),
        ):
            with self.subTest(key=key[2], answer=answer.stdout):
                self.setUp()
                self.gh.answers[key] = answer
                with self.assertRaises(homebrew_tap.RefusedError):
                    self.propose()
                self.assertNotIn(CREATE, self.gh.calls)

    def test_a_create_that_prints_no_pull_request_is_refused(self) -> None:
        """Auto-merge goes to the URL it printed, so that must be one."""
        gh = self.gh

        def odd(args: Sequence[str]) -> subprocess.CompletedProcess:
            if tuple(args[:3]) == ("gh", "pr", "create"):
                return done("https://example.com/pull/7\n")
            return gh(args)

        with self.assertRaisesRegex(homebrew_tap.RefusedError, "didn't print"):
            homebrew_tap.propose(FORMULA, VERSION, REPO, odd)
        self.assertNotIn(MERGE, gh.calls)


class CheckTests(unittest.TestCase):
    """The checks that run before the tap's token is in reach."""

    def setUp(self) -> None:
        """Lay out a checkout at 1.2.3."""
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        (self.root / "Cargo.toml").write_text(
            f'[workspace.package]\nversion = "{VERSION}"\n', encoding="utf-8"
        )
        self.release = {"tagName": TAG, "isDraft": False, "isPrerelease": False}

    def test_a_published_stable_release_of_the_version_passes(self) -> None:
        """And gives the version."""
        self.assertEqual(homebrew_tap.check(TAG, self.release, self.root), VERSION)

    def test_anything_else_is_refused(self) -> None:
        """Another version, a candidate, a draft, a prerelease or another tag's release."""
        for tag, change in (
            ("v1.2.4", {}),
            ("1.2.3", {}),
            ("v1.2.3-rc.1", {}),
            (TAG, {"isDraft": True}),
            (TAG, {"isPrerelease": True}),
            (TAG, {"isPrerelease": None}),
            (TAG, {"tagName": "v1.2.4"}),
        ):
            with self.subTest(tag=tag, change=change):
                release = {**self.release, **change}
                with self.assertRaises(homebrew_tap.RefusedError):
                    homebrew_tap.check(tag, release, self.root)

    def test_a_formula_that_isnt_landfalls_is_refused(self) -> None:
        """Before it can be sent anywhere."""
        path = self.root / "landfall.rb"
        path.write_bytes(b"class Other < Formula\nend\n")
        with self.assertRaises(homebrew_tap.RefusedError):
            homebrew_tap.read_formula(path)
        path.write_bytes(FORMULA)
        self.assertEqual(homebrew_tap.read_formula(path), FORMULA)

    def test_check_runs_under_isolation_and_appends_the_version(self) -> None:
        """As the workflow runs it, from a copy in a repository's layout."""
        scripts = self.root / ".github" / "scripts"
        scripts.mkdir(parents=True)
        (scripts / SCRIPT.name).write_bytes(SCRIPT.read_bytes())
        release = self.root / "release.json"
        release.write_text(json.dumps(self.release), encoding="utf-8")
        output = self.root / "output"
        result = subprocess.run(
            [
                sys.executable,
                "-I",
                str(scripts / SCRIPT.name),
                "check",
                "--tag",
                TAG,
                "--release",
                str(release),
                "--output",
                str(output),
            ],
            capture_output=True,
            text=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
            env={"PATH": os.environ["PATH"]},
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(output.read_text(encoding="utf-8"), f"version={VERSION}\n")


if __name__ == "__main__":
    unittest.main()
