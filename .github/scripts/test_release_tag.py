"""`scripts/release-tag`, the owner's one command for each release.

Every `git` and `gh` call goes through a fake that answers from a table, and a fake terminal stands
in for the owner, so nothing here touches a network, a terminal or a real repository but the last
tests, which sign and check a tag in a throwaway one.
"""

import importlib.machinery
import importlib.util
import json
import os
import subprocess
import tempfile
import unittest
from collections.abc import Sequence
from pathlib import Path

from release_preflight_support import Keys

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "release-tag"
_loader = importlib.machinery.SourceFileLoader("release_tag", str(SCRIPT))
_spec = importlib.util.spec_from_loader("release_tag", _loader)
if _spec is None:
    message = f"can't load {SCRIPT}"
    raise ImportError(message)
release_tag = importlib.util.module_from_spec(_spec)
_loader.exec_module(release_tag)

REPO = "owner/landfall"
SHA = "c" * 40
OTHER_SHA = "d" * 40
PREVIOUS_SHA = "e" * 40
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
SENSITIVE = (SIGNERS, ".github/", "scripts/release-tag", "Cargo.toml", "Cargo.lock")
DIFF = ("git", "diff", "--no-ext-diff", "--no-color", PREVIOUS, SHA, "--", *SENSITIVE)
SIGNERS_SAME = ("git", "diff", "--quiet", PREVIOUS, SHA, "--", SIGNERS)


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


def done(stdout: str = "", returncode: int = 0, stderr: str = "") -> subprocess.CompletedProcess:
    """Return a finished command's result."""
    return subprocess.CompletedProcess([], returncode, stdout, stderr)


class FakeRun:
    """Answers each command from a table, records it, and fails anything it wasn't given."""

    def __init__(self) -> None:
        """Answer as a clean checkout whose main is a bumped, dry-run commit after v1.2.2."""
        self.calls: list[tuple[str, ...]] = []
        # `git verify-tag` by the ref it checks; the allowed-signers path differs each time.
        self.verified = {f"refs/tags/{TAG}": done(), f"refs/tags/{PREVIOUS}": done()}
        self.answers: dict[tuple[str, ...], subprocess.CompletedProcess] = {
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
            ("git", "rev-parse", "--verify", f"refs/tags/{PREVIOUS}^{{commit}}"): done(
                f"{PREVIOUS_SHA}\n"
            ),
            ("git", "show", f"{PREVIOUS_SHA}:{SIGNERS}"): done(f"{KEY}\n"),
            ("git", "show", f"{PREVIOUS}:{SIGNERS}"): done(f"{KEY}\n"),
            LOG: done(f"{SHA} G Owner bump to 1.2.3\n Cargo.toml | 2 +-\n"),
            DIFF: done("diff --git a/Cargo.toml b/Cargo.toml\n"),
            SIGNERS_SAME: done(),
            TAG_ARGS: done(),
            ("git", "rev-parse", "--verify", f"refs/tags/{TAG}^{{commit}}"): done(f"{SHA}\n"),
            ("git", "tag", "--delete", TAG): done(),
            PUSH_ARGS: done(),
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
        self.calls.append(call)
        if "verify-tag" in call:
            return self.verified.get(call[-1], done(returncode=1, stderr="no such tag"))
        if call not in self.answers:
            message = f"unexpected command: {call}"
            raise AssertionError(message)
        return self.answers[call]


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

    def release(self, version: str = VERSION, commit: str = SHA, **options: object) -> str:
        """Run the whole command against the fakes."""
        request = release_tag.Request(version, commit, **options)
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
        key = "key::ssh-ed25519 AAAA with spaces"
        self.fake.answers[("git", "-c", f"user.signingkey={key}", *TAG_ARGS[1:])] = done()
        self.release(signing_key=key)
        self.assertIn(("git", "-c", f"user.signingkey={key}", *TAG_ARGS[1:]), self.fake.calls)

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
        self.assertEqual(len(self.fake.calls), 1)

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


class SignersChangeTests(unittest.TestCase):
    """A change to who may sign releases, which is never signed in passing."""

    def setUp(self) -> None:
        """Answer as a commit that adds a key since the last release."""
        self.fake = FakeRun()
        self.owner = FakeTerminal(self.fake)
        self.fake.answers[("git", "show", f"{SHA}:{SIGNERS}")] = done(f"{KEY}\n{NEW_KEY}\n")
        self.fake.answers[SIGNERS_SAME] = done(returncode=1)

    def release(self, **options: object) -> str:
        """Run the whole command against the fakes."""
        request = release_tag.Request(VERSION, SHA, **options)
        return release_tag.release_tag(request, self.fake, self.owner.terminal())

    def test_an_added_key_is_refused_without_the_flag(self) -> None:
        """Adding a key keeps the owner's signature valid, so only this check would notice."""
        with self.assertRaisesRegex(release_tag.RefusedError, "--signers-change"):
            self.release()
        self.assertNotIn(TAG_ARGS, self.fake.calls)
        self.assertIsNone(self.owner.calls_when_asked)

    def test_with_the_flag_both_sets_of_fingerprints_are_shown_before_asking(self) -> None:
        """Old and new, to compare with SECURITY.md and a copy got some other way."""
        self.release(signers_change=True)
        shown = self.owner.shown()
        old = release_tag.fingerprint(KEY)
        new = release_tag.fingerprint(NEW_KEY)
        self.assertIn(f"Signers at {PREVIOUS}: {old}", shown)
        self.assertIn(f"Signers at {SHA}: {old}, {new}", shown)
        self.assertIn("SECURITY.md", shown)
        self.assertEqual(self.owner.events[-2][0], "ask")
        self.assertIn(TAG_ARGS, self.fake.calls)

    def test_with_no_signed_release_behind_it_everything_counts_as_a_change(self) -> None:
        """An unsigned or lightweight `v*` tag can't stand in for the last release."""
        listed = f"v1.2.9 commit\nv1.2.8 tag\n{PREVIOUS} tag\n"
        self.fake.answers[TAG_LIST] = done(listed)
        self.fake.answers[("git", "rev-parse", "--verify", "refs/tags/v1.2.8^{commit}")] = done(
            f"{OTHER_SHA}\n"
        )
        self.fake.answers[("git", "show", f"{OTHER_SHA}:{SIGNERS}")] = done(f"{KEY}\n")
        self.fake.verified[f"refs/tags/{PREVIOUS}"] = done(returncode=1)
        self.fake.answers[("git", "log", "--format=%H %G? %an %s", "--stat", SHA)] = done("all\n")
        everything = (
            "git",
            "diff",
            "--no-ext-diff",
            "--no-color",
            release_tag.EMPTY_TREE,
            SHA,
            "--",
            *SENSITIVE,
        )
        self.fake.answers[everything] = done("")
        with self.assertRaisesRegex(release_tag.RefusedError, "changed since the start"):
            self.release()
        self.assertIn("no earlier release tag is signed", self.owner.shown())
        self.assertNotIn(("git", "show", "refs/tags/v1.2.9^{commit}"), self.fake.calls)


class ReadingTests(unittest.TestCase):
    """The pieces that read what git and GitHub say."""

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

    def sign_with(self, key: Path) -> None:
        """Make the tag as the script does, signed by this key."""
        self.git(
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={key}",
            "tag",
            "--sign",
            "--message",
            TAG,
            TAG,
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

    def commit_with_signers(self, signers: str, parent: str | None = None) -> str:
        """Make a commit whose only file is the signers file, and return it."""
        blob = self.git("hash-object", "-w", "--stdin", stdin=signers).strip()
        tree = self.git("mktree", stdin=f"100644 blob {blob}\trelease-signers\n").strip()
        for name in ("assets", "cli", "crates"):
            tree = self.git("mktree", stdin=f"040000 tree {tree}\t{name}\n").strip()
        parents = ["-p", parent] if parent else []
        return self.git("commit-tree", tree, *parents, "-m", "a commit").strip()

    def test_the_previous_release_is_the_highest_tag_a_release_key_signed(self) -> None:
        """Not a lightweight tag, nor one another key signed, whatever its number."""
        first = f"{Keys.public(self.keys.first)}\n"
        released = self.commit_with_signers(first)
        head = self.commit_with_signers(first, parent=released)
        self.sha = released
        self.sign_with(self.keys.first)
        self.git("tag", "v1.2.9", released)
        self.git(
            "-c",
            "gpg.format=ssh",
            "-c",
            f"user.signingkey={self.keys.stranger}",
            "tag",
            "--sign",
            "--message",
            "v1.2.8",
            "v1.2.8",
            released,
        )
        self.assertEqual(release_tag.previous_release(self.in_repository, head), TAG)
        self.git("tag", "--delete", TAG)
        self.assertIsNone(release_tag.previous_release(self.in_repository, head))

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
