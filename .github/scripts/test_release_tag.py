"""`scripts/release-tag`, the owner's one command for each release.

Every `git` and `gh` call goes through a fake that answers from a table, and a fake terminal stands
in for the owner, so nothing here touches a network, a terminal or a real repository.
`test_release_tag_git.py` signs and checks tags in a throwaway one.
"""

import json
import os
import re
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from release_tag_loader import SCRIPT, release_tag

REPO = "owner/landfall"
SHA = "c" * 40
OTHER_SHA = "d" * 40
VERSION = "1.2.3"
TAG = "v1.2.3"
PREVIOUS = "v1.2.2"
RUN_ID = 42
KEY = "ssh-ed25519 " + "A" * 68
NEW_KEY = "ssh-ed25519 " + "B" * 68
SIGNERS = "crates/cli/assets/release-signers"
RUNS_PATH = f"repos/{REPO}/actions/workflows/release.yml/runs"
JOBS_PATH = f"repos/{REPO}/actions/runs/{RUN_ID}/jobs"
TAG_ARGS = ("git", "tag", "--sign", "--message", TAG, TAG, SHA)
PUSH_ARGS = ("git", "push", "origin", f"refs/tags/{TAG}")
TAG_LIST = (
    "git",
    "-c",
    "versionsort.suffix=-",
    "tag",
    "--merged",
    SHA,
    "--list",
    "v[0-9]*",
    "--sort=-v:refname",
    "--format=%(refname:strip=2) %(objecttype)",
)
LOG = ("git", "log", "--format=%H %G? %an %s", "--stat", f"{PREVIOUS}..{SHA}")
TRUST_CODE = (
    "crates/origin/Cargo.toml",
    "crates/origin/src/",
    "crates/origin/assets/",
    "crates/core/src/tag.rs",
    "crates/core/src/release.rs",
    "crates/core/src/config/",
    "crates/agent/src/daemon.rs",
    "crates/agent/src/daemon/verifier.rs",
    "crates/agent/src/daemon/judge.rs",
    "crates/cli/src/verify.rs",
    "crates/cli/src/host.rs",
    "crates/cli/src/host/",
    "crates/cli/src/project.rs",
    "crates/cli/src/agent_release.rs",
    "crates/cli/assets/",
)
SENSITIVE = (
    SIGNERS,
    ".github/",
    "scripts/release-tag",
    "Cargo.toml",
    "Cargo.lock",
    *TRUST_CODE,
)
INCLUDE = re.compile(r'include_(?:bytes|str)!\(\s*"([^"]+)"\s*\)')
TEST_MODULE = re.compile(r"#\[cfg\(test\)\]\s*mod\s+\w+\s*\{")
CHECKOUT = "/nonexistent/landfall-checkout"
TOPLEVEL = ("git", "rev-parse", "--show-toplevel")
DIFF = ("git", "diff", "--no-ext-diff", "--no-color", PREVIOUS, SHA, "--", *SENSITIVE)


def manifest(version: str) -> str:
    """Return a workspace `Cargo.toml` at this version."""
    return f'[workspace]\nmembers = []\n\n[workspace.package]\nversion = "{version}"\n'


def a_run(**changes: object) -> dict[str, object]:
    """Return GitHub's entry for a green dry run of SHA on main, with these changes."""
    run: dict[str, object] = {
        "id": RUN_ID,
        "head_sha": SHA,
        "head_branch": "main",
        "event": "push",
        "path": ".github/workflows/release.yml",
        "status": "completed",
        "conclusion": "success",
    }
    run.update(changes)
    return run


def good_jobs() -> list[dict[str, object]]:
    """Return the jobs of a full, green dry run."""
    names = {
        "version": "success",
        "on-main": "success",
        "crate-age": "success",
        "ci / check": "success",
        "ci / crate-age": "skipped",
        "build-linux": "success",
        "build-macos": "success",
        "smoke (ubuntu-24.04, 1, linux_amd64/landfall)": "success",
        "smoke (ubuntu-24.04-arm, 1, linux_arm64/landfall)": "success",
        "smoke (macos-26, 2, landfall)": "success",
        "preflight": "skipped",
        "publish": "skipped",
    }
    return [{"name": name, "conclusion": result} for name, result in names.items()]


def without_test_modules(source: str) -> str:
    """Return Rust source without its inline `#[cfg(test)] mod … { … }` blocks.

    Braces are counted, so a brace inside a string in a test module could end it early, which
    checks more, not less. If a cut never balances, the whole file is kept, as production code
    could follow what looked like a test module.
    """
    whole = source
    while found := TEST_MODULE.search(source):
        depth, end = 1, found.end()
        while depth and end < len(source):
            depth += {"{": 1, "}": -1}.get(source[end], 0)
            end += 1
        if depth:
            return whole
        source = source[: found.start()] + source[end:]
    return source


def done(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    """Return a finished command's result."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeRun:
    """Answers each command from a table, records it, and fails anything it wasn't given."""

    def __init__(self) -> None:
        """Answer as a clean checkout whose main is a bumped, dry-run commit after v1.2.2."""
        self.calls: list[tuple[str, ...]] = []
        # What each `-c user.signingkey=…` handed to git was; calls are recorded without it.
        self.signing_keys: list[str] = []
        # `git verify-tag` by the ref it checks; the allowed-signers path differs each time.
        self.verified = {f"refs/tags/{TAG}": done(), f"refs/tags/{PREVIOUS}": done()}
        self.answers: dict[tuple[str, ...], subprocess.CompletedProcess] = {
            TOPLEVEL: done(f"{CHECKOUT}\n"),
            ("git", "status", "--porcelain", "--untracked-files=normal"): done(),
            ("git", "remote", "get-url", "origin"): done(f"git@github.com:{REPO}.git\n"),
            (
                "git",
                "fetch",
                "--no-tags",
                "origin",
                "+refs/heads/main:refs/remotes/origin/main",
                "refs/tags/v*:refs/tags/v*",
            ): done(),
            ("git", "rev-parse", "--verify", "refs/remotes/origin/main^{commit}"): done(f"{SHA}\n"),
            ("git", "show", f"{SHA}:Cargo.toml"): done(manifest(VERSION)),
            ("git", "show", f"{SHA}:{SIGNERS}"): done(f"# a key\n{KEY}\n"),
            ("git", "rev-parse", "--quiet", "--verify", f"refs/tags/{TAG}"): done(returncode=1),
            ("git", "ls-remote", "--tags", "origin", f"refs/tags/{TAG}"): done(),
            TAG_LIST: done(f"{PREVIOUS} tag\nv1.2.1 tag\n"),
            LOG: done(f"{SHA} G Owner bump to 1.2.3\n Cargo.toml | 2 +-\n"),
            DIFF: done("diff --git a/Cargo.toml b/Cargo.toml\n"),
            TAG_ARGS: done(),
            ("git", "rev-parse", "--verify", f"refs/tags/{TAG}^{{commit}}"): done(f"{SHA}\n"),
            ("git", "tag", "--delete", TAG): done(),
            PUSH_ARGS: done(),
            ("ssh-add", "-L"): done(f"{KEY} comment\n"),
            ("git", "config", "--get", "gpg.ssh.program"): done(returncode=1),
        }
        self.runs([a_run()])
        self.jobs(good_jobs())

    def runs(self, runs: list[dict[str, object]]) -> None:
        """Have GitHub list these runs for SHA."""
        args = ("gh", "api", "--method", "GET", RUNS_PATH)
        args += ("-f", f"head_sha={SHA}", "-f", "per_page=100")
        self.answers[args] = done(json.dumps({"total_count": len(runs), "workflow_runs": runs}))

    def jobs(self, jobs: list[dict[str, object]]) -> None:
        """Have GitHub list these jobs for the run."""
        args = ("gh", "api", "--method", "GET", JOBS_PATH, "-f", "filter=latest")
        args += ("-f", "per_page=100")
        self.answers[args] = done(json.dumps({"total_count": len(jobs), "jobs": jobs}))

    def __call__(self, args: Sequence[str]) -> subprocess.CompletedProcess:
        """Answer one command."""
        call = tuple(args)
        if (
            call[1:5:2] == ("-c", "-c")
            and call[2] == "gpg.format=ssh"
            and "user.signingkey=" in call[4]
        ):
            self.signing_keys.append(call[4].removeprefix("user.signingkey="))
            call = (call[0], *call[5:])
        self.calls.append(call)
        if "verify-tag" in call:
            return self.verified.get(call[-1], done(returncode=1, stderr="no such tag"))
        if call not in self.answers:
            message = f"unexpected command: {call}"
            raise AssertionError(message)
        return self.answers[call]


def trusted_file(case: unittest.TestCase, text: str, mode: int = 0o600) -> Path:
    """Write an owner's trusted signers file for one test, and return its path."""
    directory = tempfile.TemporaryDirectory()
    case.addCleanup(directory.cleanup)
    path = Path(directory.name) / "release-signers"
    path.write_text(text, encoding="utf-8")
    path.chmod(mode)
    return path


class FakeTerminal:
    """The owner: what was shown, in order, and what they type when asked."""

    def __init__(self, fake: FakeRun) -> None:
        """Type the right version on a terminal."""
        self.fake = fake
        self.events: list[tuple[str, str]] = []
        self.typed: str | None = VERSION
        self.tty = True
        self.calls_when_asked: int | None = None

    def say(self, text: str) -> None:
        """Record what was shown."""
        self.events.append(("say", text))

    def ask(self, prompt: str) -> str:
        """Record the question, and how far the commands had got, then type."""
        self.events.append(("ask", prompt))
        self.calls_when_asked = len(self.fake.calls)
        if self.typed is None:
            raise EOFError
        return self.typed

    def shown(self) -> str:
        """Return all that was shown."""
        return "\n".join(text for kind, text in self.events if kind == "say")

    def terminal(self) -> object:
        """Return the script's `Terminal` over this."""
        return release_tag.Terminal(say=self.say, ask=self.ask, is_tty=lambda: self.tty)


class FlowTests(unittest.TestCase):
    """What it checks, in what order, and what it does once everything holds."""

    def setUp(self) -> None:
        """Answer as a clean checkout, ready to tag, with the owner at a terminal."""
        self.fake = FakeRun()
        self.owner = FakeTerminal(self.fake)
        self.trusted = trusted_file(self, f"# mine\n{KEY}\n")

    def release(self, version: str = VERSION, commit: str = SHA, **options: object) -> str:
        """Run the whole command against the fakes."""
        request = release_tag.Request(version, commit, self.trusted, **options)
        return release_tag.release_tag(request, self.fake, self.owner.terminal())

    def refused(self, reason: str, version: str = VERSION, **options: object) -> None:
        """Assert it refuses for this reason, and never made a tag."""
        with self.assertRaisesRegex(release_tag.RefusedError, reason):
            self.release(version, **options)
        self.assertNotIn(TAG_ARGS, self.fake.calls)

    def test_a_ready_commit_is_shown_confirmed_tagged_and_the_push_printed(self) -> None:
        """Shown first, then asked, then signed and checked, and left for the owner to push."""
        said = self.release()
        shown = self.owner.shown()
        for piece in (SHA, f"dry run {RUN_ID}", PREVIOUS, "bump to 1.2.3", "diff --git"):
            with self.subTest(piece=piece):
                self.assertIn(piece, shown)
        self.assertEqual([kind for kind, _ in self.owner.events].count("ask"), 1)
        self.assertIn(f"Type {VERSION} to sign {TAG} at {SHA}", dict(self.owner.events)["ask"])
        self.assertLess(self.owner.calls_when_asked, self.fake.calls.index(TAG_ARGS) + 1)
        self.assertNotIn(TAG_ARGS, self.fake.calls[: self.owner.calls_when_asked])
        verify = [c for c in self.fake.calls if "verify-tag" in c and c[-1] == f"refs/tags/{TAG}"]
        self.assertEqual(len(verify), 1)
        self.assertLess(self.fake.calls.index(TAG_ARGS), self.fake.calls.index(verify[0]))
        self.assertNotIn(PUSH_ARGS, self.fake.calls)
        self.assertIn(" ".join(PUSH_ARGS), said)

    def test_push_says_what_it_pushes_and_then_pushes_only_the_tag(self) -> None:
        """The commit and the run, before the push, which goes by the tag's full ref."""
        self.release(push=True)
        self.assertEqual(self.fake.calls[-1], PUSH_ARGS)
        last = self.owner.events[-1][1]
        self.assertIn(SHA, last)
        self.assertIn(str(RUN_ID), last)
        self.assertIn("Pushing", last)

    def test_no_terminal_is_refused_before_anything_runs(self) -> None:
        """So an agent can't drive it: there is no flag that skips the question."""
        self.owner.tty = False
        self.refused("isn't a terminal")
        self.assertEqual(self.fake.calls, [])

    def test_a_wrong_answer_or_none_signs_nothing(self) -> None:
        """Anything but the version, and an end of input."""
        for typed in ("y", "yes", "1.2.4", "", None):
            with self.subTest(typed=typed):
                self.setUp()
                self.owner.typed = typed
                self.refused("typed|no confirmation")

    def test_main_past_the_commit_named_is_refused(self) -> None:
        """Something landed after the bump the owner reviewed."""
        self.refused("not " + OTHER_SHA, commit=OTHER_SHA)
        self.assertEqual([k for k, _ in self.owner.events], [])

    def test_a_commit_that_isnt_a_full_id_is_refused_before_anything_runs(self) -> None:
        """Not a branch, not a short id, not an option."""
        for commit in ("main", SHA[:12], "--push", SHA.upper()):
            with self.subTest(commit=commit):
                self.setUp()
                self.refused("not a full commit id", commit=commit)
                self.assertEqual(self.fake.calls, [])

    def test_a_signing_key_is_given_to_git_for_the_tag_alone(self) -> None:
        """As `-c user.signingkey`, one argument, whatever it holds."""
        key = f"key::{KEY}"
        self.release(signing_key=key)
        self.assertEqual(self.fake.signing_keys, [f"key::{KEY}"])

    def test_a_key_with_a_control_character_is_refused(self) -> None:
        """A newline in a config value is never what was meant."""
        self.refused("control character", signing_key="key::a\nb")
        self.assertEqual(self.fake.calls, [])

    def test_a_version_a_release_cant_have_is_refused_before_anything_runs(self) -> None:
        """Including one that would read as an option."""
        for version in ("v1.2.3", "1.2", "--push", "1.2.3+build", ""):
            with self.subTest(version=version):
                self.setUp()
                self.refused("not a version", version)
                self.assertEqual(self.fake.calls, [])

    def test_a_dirty_checkout_is_refused(self) -> None:
        """Before anything is fetched."""
        self.fake.answers[("git", "status", "--porcelain", "--untracked-files=normal")] = done(
            "?? stray\n"
        )
        self.refused("changes or untracked files")
        self.assertEqual(len(self.fake.calls), 2)

    def test_an_origin_that_isnt_github_is_refused(self) -> None:
        """Its runs are what the tag rests on."""
        self.fake.answers[("git", "remote", "get-url", "origin")] = done("/srv/mirror.git\n")
        self.refused("not a GitHub repository")

    def test_a_commit_at_another_version_is_refused(self) -> None:
        """The tag must be `v` plus the commit's version, or preflight spends the number."""
        self.fake.answers[("git", "show", f"{SHA}:Cargo.toml")] = done(manifest("1.2.4"))
        self.refused("is at version 1.2.4, not 1.2.3")

    def test_a_signers_file_with_no_key_is_refused(self) -> None:
        """Preflight would refuse every tag."""
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done("# none yet\n\n")
        self.refused("holds no key")

    def test_a_tag_that_exists_here_or_on_origin_is_refused(self) -> None:
        """A tag can't be moved, and a number can't be used twice."""
        self.fake.answers[("git", "rev-parse", "--quiet", "--verify", f"refs/tags/{TAG}")] = done(
            f"{SHA}\n"
        )
        self.refused("already exists here")
        self.setUp()
        self.fake.answers[("git", "ls-remote", "--tags", "origin", f"refs/tags/{TAG}")] = done(
            f"{SHA}\trefs/tags/{TAG}\n"
        )
        self.refused("already exists on origin")

    def test_no_green_dry_run_of_this_commit_is_refused(self) -> None:
        """Another commit, another branch, a pull request, a failure, or one still running."""
        for change in (
            {"head_sha": OTHER_SHA},
            {"head_branch": "feature"},
            {"event": "pull_request"},
            {"conclusion": "failure"},
            {"status": "in_progress", "conclusion": None},
            {"path": ".github/workflows/ci.yml"},
            {"id": "42; rm -rf /"},
        ):
            with self.subTest(change=change):
                self.setUp()
                self.fake.runs([a_run(**change)])
                self.refused("no Release run")

    def test_a_manual_run_counts(self) -> None:
        """For a commit with no bump of its own, where the automatic run built nothing."""
        self.fake.runs([a_run(event="workflow_dispatch")])
        self.release()
        self.assertIn(TAG_ARGS, self.fake.calls)

    def test_a_run_that_skipped_the_build_is_refused(self) -> None:
        """A push to main that didn't change the version succeeds having built nothing."""
        jobs = [
            {
                "name": job["name"],
                "conclusion": "success" if job["name"] == "version" else "skipped",
            }
            for job in good_jobs()
        ]
        self.fake.jobs(jobs)
        self.refused("built nothing")

    def test_what_git_prints_is_shown_with_its_controls_escaped(self) -> None:
        """A commit subject can't move the cursor or erase what was shown."""
        self.fake.answers[LOG] = done(f"{SHA} G Owner tidy\x1b[1A\x1b[2K\u202e\n")
        self.release()
        shown = self.owner.shown()
        self.assertIn("tidy\\x1b[1A\\x1b[2K\\u202e", shown)
        self.assertNotIn("\x1b", shown)

    def test_a_trusted_file_that_isnt_the_owners_alone_is_refused_before_anything_runs(
        self,
    ) -> None:
        """Missing, writable by others, a link, empty, or holding something else."""
        good = trusted_file(self, f"{KEY}\n")
        link = good.with_name("link")
        link.symlink_to(good)
        for path, reason in (
            (good.with_name("absent"), "no trusted signers file"),
            (trusted_file(self, f"{KEY}\n", 0o620), "written by others"),
            (trusted_file(self, f"{KEY}\n", 0o602), "written by others"),
            (link, "a link"),
            (trusted_file(self, "# none\n\n"), "holds no key"),
            (trusted_file(self, f"{KEY} comment\n"), "isn't ssh-ed25519"),
        ):
            with self.subTest(reason=reason, path=path.name):
                self.setUp()
                self.trusted = path
                self.refused(reason)
                self.assertEqual(self.fake.calls, [TOPLEVEL])

    def test_a_trusted_file_inside_the_checkout_is_refused(self) -> None:
        """The repository's own signers file can't be what it is compared with."""
        self.fake.answers[TOPLEVEL] = done(f"{self.trusted.parent}\n")
        self.refused("inside the checkout")
        self.assertEqual(self.fake.calls, [TOPLEVEL])

    def test_a_tag_that_fails_its_check_is_deleted(self) -> None:
        """Signed by a key preflight would refuse: deleted here, before it can spend a number."""
        self.fake.verified[f"refs/tags/{TAG}"] = done(returncode=1, stderr="no principal matched")
        self.refused_after_signing()

    def refused_after_signing(self) -> None:
        """Assert the tag was made, then deleted, and never pushed."""
        with self.assertRaisesRegex(release_tag.RefusedError, "isn't signed by a key"):
            self.release(push=True)
        self.assertEqual(self.fake.calls[-1], ("git", "tag", "--delete", TAG))
        self.assertNotIn(PUSH_ARGS, self.fake.calls)


class TrustTests(unittest.TestCase):
    """The repository's signers against the owner's own, and tags no trusted key signed."""

    def setUp(self) -> None:
        """Answer as a commit that adds a key the owner doesn't hold."""
        self.fake = FakeRun()
        self.owner = FakeTerminal(self.fake)
        self.trusted = trusted_file(self, f"{KEY}\n")
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n{NEW_KEY}\n")

    def release(self) -> str:
        """Run the whole command against the fakes."""
        request = release_tag.Request(VERSION, SHA, self.trusted)
        return release_tag.release_tag(request, self.fake, self.owner.terminal())

    def test_keys_the_owner_doesnt_trust_are_refused_with_both_sets_shown(self) -> None:
        """Adding a key keeps the owner's signature valid, so only this check would notice."""
        with self.assertRaisesRegex(release_tag.RefusedError, "update your trusted signers"):
            self.release()
        self.assertNotIn(TAG_ARGS, self.fake.calls)
        self.assertIsNone(self.owner.calls_when_asked)
        shown = self.owner.shown()
        self.assertIn(release_tag.fingerprint(NEW_KEY), shown)
        self.assertEqual(shown.count(release_tag.fingerprint(KEY)), 2)

    def test_a_removed_key_is_refused_too(self) -> None:
        """Exactly the trusted set, either way."""
        self.trusted = trusted_file(self, f"{KEY}\n{NEW_KEY}\n")
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n")
        with self.assertRaisesRegex(release_tag.RefusedError, "aren't the keys you trust"):
            self.release()

    def test_tags_above_the_last_trusted_release_are_named(self) -> None:
        """A lightweight one, and one no trusted key signed, whatever their numbers."""
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n")
        self.fake.answers[TAG_LIST] = done(f"v1.2.9 commit\nv1.2.8\x1b[2K tag\n{PREVIOUS} tag\n")
        self.release()
        shown = self.owner.shown()
        self.assertIn("WARNING", shown)
        self.assertIn("v1.2.9, v1.2.8\\x1b[2K", shown)
        self.assertIn(f"Since {PREVIOUS}", shown)

    def test_with_no_trusted_release_behind_it_the_signers_are_shown_whole(self) -> None:
        """And `.github/` and `Cargo.lock` by name only, as whole they can't be read."""
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n")
        self.fake.verified[f"refs/tags/{PREVIOUS}"] = done(returncode=1)
        self.fake.answers[("git", "log", "--format=%H %G? %an %s", "--stat", SHA)] = done("all\n")
        diff = ("git", "diff", "--no-ext-diff", "--no-color")
        listed = (
            *diff,
            "--stat",
            release_tag.EMPTY_TREE,
            SHA,
            "--",
            ".github/",
            "Cargo.lock",
            *TRUST_CODE,
        )
        self.fake.answers[listed] = done(" .github/workflows/release.yml | 400 +++\n")
        whole = (*diff, release_tag.EMPTY_TREE, SHA, "--", "scripts/release-tag", "Cargo.toml")
        self.fake.answers[whole] = done("+[workspace]\n")
        self.release()
        shown = self.owner.shown()
        self.assertIn("no release behind it is signed by a key you trust", shown)
        self.assertIn(release_tag.fingerprint(KEY), shown)
        self.assertIn("release.yml | 400", shown)
        self.assertIn("+[workspace]", shown)
        self.assertIn(TAG_ARGS, self.fake.calls)


class ReadingTests(unittest.TestCase):
    """The pieces that read what git and GitHub say."""

    def test_the_code_that_decides_trust_is_shown_and_exists(self) -> None:
        """Each path is the script's, and a file or folder here, so a rename can't drop one."""
        self.assertEqual(release_tag.SENSITIVE, SENSITIVE)
        root = SCRIPT.parents[1]
        for path in SENSITIVE:
            with self.subTest(path=path):
                self.assertTrue((root / path).exists(), path)

    def test_test_modules_are_cut_whole_and_nothing_else(self) -> None:
        """Nested braces included, and what follows the module kept."""
        source = (
            'const A: &str = include_str!("a");\n#[cfg(test)]\nmod tests {\n'
            '    fn f() { if x { include_str!("b"); } }\n}\nconst C: &str = include_str!("c");\n'
        )
        self.assertEqual(INCLUDE.findall(without_test_modules(source)), ["a", "c"])
        # A `{` in a test module's string leaves the count open: then nothing is cut at all.
        unbalanced = (
            '#[cfg(test)]\nmod tests {\n    const S: &str = "{";\n}\n'
            'const P: &str = include_str!("p");\n'
        )
        self.assertEqual(INCLUDE.findall(without_test_modules(unbalanced)), ["p"])

    def test_every_file_built_into_a_verifying_crate_is_shown(self) -> None:
        """A new embedded key or trust root can't arrive unseen, as a line in `--stat`."""
        root = SCRIPT.parents[1]
        found = []
        for crate in ("origin", "core", "cli", "agent"):
            for source in sorted((root / "crates" / crate / "src").rglob("*.rs")):
                parts = source.relative_to(root).parts
                if "tests" in parts or source.name in {"tests.rs", "test_support.rs"}:
                    continue
                found.extend(
                    (source.parent / name).resolve().relative_to(root).as_posix()
                    for name in INCLUDE.findall(
                        without_test_modules(source.read_text(encoding="utf-8"))
                    )
                )
        self.assertIn("crates/origin/assets/sigstore-root.json", found)
        self.assertIn("crates/cli/assets/release-signers", found)
        for path in found:
            with self.subTest(path=path):
                self.assertTrue(
                    any(
                        path == entry or (entry.endswith("/") and path.startswith(entry))
                        for entry in SENSITIVE
                    ),
                    path,
                )

    def test_a_trusted_file_owned_by_someone_else_is_refused(self) -> None:
        """Root or the owner only: anyone else could change what's trusted."""
        if os.getuid() == 0:
            self.skipTest("running as root, whose files are always accepted")
        path = trusted_file(self, f"{KEY}\n")
        checkout = Path(CHECKOUT)
        self.assertEqual(release_tag.read_trusted(path, checkout, os.getuid()), [KEY])
        with self.assertRaisesRegex(release_tag.RefusedError, "belongs to someone else"):
            release_tag.read_trusted(path, checkout, os.getuid() + 1)

    def test_a_trusted_path_that_isnt_a_file_is_refused(self) -> None:
        """A folder, and a pipe, which is opened without waiting for a writer."""
        directory = trusted_file(self, f"{KEY}\n").parent
        pipe = directory / "pipe"
        os.mkfifo(pipe, 0o600)
        for path in (directory, pipe):
            with self.subTest(path=path.name), self.assertRaises(release_tag.RefusedError):
                release_tag.read_trusted(path, Path(CHECKOUT), os.getuid())

    def test_controls_are_escaped_and_text_is_kept(self) -> None:
        """C0 but newline and tab, DEL, C1 and bidi controls; anything else as it is."""
        self.assertEqual(
            release_tag.print_safe("a\x1b[2Kb\x07\x7f\x9b\u202e\u2066c\n\td é"),
            "a\\x1b[2Kb\\x07\\x7f\\x9b\\u202e\\u2066c\n\td é",
        )

    def test_the_trusted_file_defaults_under_the_owners_config(self) -> None:
        """`$XDG_CONFIG_HOME` if set, else `~/.config`."""
        home = Path("/home/owner")
        self.assertEqual(
            release_tag.default_trusted_signers({}, home),
            home / ".config" / "landfall" / "release-signers",
        )
        self.assertEqual(
            release_tag.default_trusted_signers({"XDG_CONFIG_HOME": "/cfg"}, home),
            Path("/cfg/landfall/release-signers"),
        )

    def test_origin_urls(self) -> None:
        """HTTPS and SSH, with or without `.git`; nothing else."""
        for url in (
            f"https://github.com/{REPO}",
            f"https://github.com/{REPO}.git",
            f"git@github.com:{REPO}.git",
            f"ssh://git@github.com/{REPO}.git\n",
        ):
            with self.subTest(url=url):
                self.assertEqual(release_tag.repository_of(url), REPO)
        for url in (
            "https://example.com/owner/landfall",
            "https://github.com/owner",
            "https://github.com/owner/landfall/extra",
            "git@github.com:-owner/landfall",
        ):
            with self.subTest(url=url), self.assertRaises(release_tag.RefusedError):
                release_tag.repository_of(url)

    def test_a_full_green_dry_run_has_no_fault(self) -> None:
        """Every job that builds or checks passed, and the two that want a tag skipped."""
        self.assertEqual(
            release_tag.jobs_faults(release_tag.job_results({"jobs": good_jobs()})), []
        )

    def test_each_kind_of_fault_is_named(self) -> None:
        """A failed job, a missing smoke runner, no CI, and a job a dry run never runs."""
        for name, result, said in (
            ("build-macos", "failure", "didn't pass: build-macos"),
            ("smoke (macos-26, 2, landfall)", "skipped", "passed on 2 runners"),
            ("ci / check", "skipped", "no job of `ci`"),
            ("publish", "success", "`publish` ran"),
        ):
            with self.subTest(name=name):
                jobs = [
                    {**job, "conclusion": result} if job["name"] == name else job
                    for job in good_jobs()
                ]
                faults = release_tag.jobs_faults(release_tag.job_results({"jobs": jobs}))
                self.assertTrue(any(said in fault for fault in faults), faults)

    def test_answers_of_the_wrong_shape_are_refused(self) -> None:
        """Rather than read as no runs, or as no faults."""
        for answer in ([], {"jobs": {}}, {"jobs": [{"conclusion": "success"}]}):
            with self.subTest(answer=answer), self.assertRaises(release_tag.RefusedError):
                release_tag.job_results(answer)
        with self.assertRaises(release_tag.RefusedError):
            release_tag.dry_runs({"runs": []}, SHA)


if __name__ == "__main__":
    unittest.main()
