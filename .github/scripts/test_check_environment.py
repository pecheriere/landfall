"""Unit tests for check_environment.py, on sample answers shaped as GitHub's API documents them."""

import copy
import inspect
import json
import subprocess
import sys
import unittest
from pathlib import Path

import assemble_release
import check_environment

SCRIPT = Path(__file__).with_name("check_environment.py")
TIMEOUT_SECONDS = 60
REVIEWERS = {
    "id": 1,
    "node_id": "x",
    "prevent_self_review": False,
    "type": "required_reviewers",
    "reviewers": [{"type": "User", "reviewer": {"login": "someone", "id": 1}}],
}
WAIT_TIMER = {"id": 2, "node_id": "y", "type": "wait_timer", "wait_timer": 30}
BRANCH_POLICY = {"id": 3, "node_id": "z", "type": "branch_policy"}
GOOD = {
    "id": 1,
    "node_id": "n",
    "name": "release",
    "url": "https://api.github.invalid/environments/release",
    "html_url": "https://github.invalid/environments/release",
    "created_at": "2026-11-02T00:00:00Z",
    "updated_at": "2026-11-02T00:00:00Z",
    "can_admins_bypass": False,
    "protection_rules": [REVIEWERS, BRANCH_POLICY],
    "deployment_branch_policy": {"protected_branches": False, "custom_branch_policies": True},
}


def good_with(**changes: object) -> dict[str, object]:
    """Return a copy of the good answer with these keys replaced."""
    return {**copy.deepcopy(GOOD), **changes}


def reviewers_with(**changes: object) -> dict[str, object]:
    """Return the good answer with these keys replaced in its reviewers rule."""
    return good_with(protection_rules=[{**REVIEWERS, **changes}, BRANCH_POLICY])


class EnvironmentTests(unittest.TestCase):
    """What the guard wants of the `release` environment."""

    def test_environment_table(self) -> None:
        """A good answer passes, and each fault is refused by name."""
        cases: dict[str, tuple[dict[str, object], str | None]] = {
            "a good answer": (good_with(), None),
            "a wait timer beside the reviewers": (
                good_with(protection_rules=[REVIEWERS, WAIT_TIMER, BRANCH_POLICY]),
                None,
            ),
            "no rules": (good_with(protection_rules=[]), "required_reviewers"),
            "only a wait timer": (good_with(protection_rules=[WAIT_TIMER]), "required_reviewers"),
            "empty reviewers": (reviewers_with(reviewers=[]), "reviewers"),
            "prevent_self_review true": (
                reviewers_with(prevent_self_review=True),
                "prevent_self_review",
            ),
            "a null deployment_branch_policy": (
                good_with(deployment_branch_policy=None),
                "deployment_branch_policy",
            ),
        }
        for name, (answer, fault) in cases.items():
            with self.subTest(name=name):
                faults = check_environment.faults(answer)
                if fault is None:
                    self.assertEqual(faults, [])
                else:
                    self.assertEqual(len(faults), 1, faults)
                    self.assertIn(fault, faults[0])

    def test_every_fault_is_named(self) -> None:
        """One run shows everything to fix, as the guard costs a whole dispatch to run."""
        answer = good_with(
            protection_rules=[{**REVIEWERS, "reviewers": [], "prevent_self_review": True}],
            deployment_branch_policy=None,
        )
        self.assertEqual(len(check_environment.faults(answer)), 3)

    def test_what_is_missing_or_of_another_type_is_refused(self) -> None:
        """A guard that can't read a setting doesn't get to assume it's fine."""
        without_policy = good_with()
        del without_policy["deployment_branch_policy"]
        without_rules = good_with()
        del without_rules["protection_rules"]
        no_self_review_key = {k: v for k, v in REVIEWERS.items() if k != "prevent_self_review"}
        for name, answer in {
            "no deployment_branch_policy": without_policy,
            "a branch policy of another type": good_with(deployment_branch_policy="yes"),
            "no protection_rules": without_rules,
            "protection_rules of another type": good_with(protection_rules={}),
            "a rule of another type": good_with(protection_rules=["required_reviewers"]),
            "no prevent_self_review": good_with(protection_rules=[no_self_review_key]),
            "a prevent_self_review of another type": reviewers_with(prevent_self_review="false"),
            "reviewers of another type": reviewers_with(reviewers="someone"),
            "another environment": good_with(name="staging"),
        }.items():
            with self.subTest(name=name):
                self.assertTrue(check_environment.faults(answer))

    def test_two_reviewer_rules_must_both_be_good(self) -> None:
        """GitHub has one, so a second isn't something to read generously."""
        bad = {**REVIEWERS, "prevent_self_review": True}
        answer = good_with(protection_rules=[REVIEWERS, bad])
        self.assertTrue(check_environment.faults(answer))

    def test_a_long_or_hostile_name_prints_safely(self) -> None:
        """What GitHub answers doesn't get to start a workflow command, or fill a log."""
        faults = check_environment.faults(good_with(name=f"x\n::error::{'y' * 500}"))
        self.assertEqual(len(faults), 1)
        self.assertNotIn("\n", faults[0])
        self.assertLess(len(faults[0]), 300)


class ProcessTests(unittest.TestCase):
    """The script as the workflow runs it, with GitHub's answer on stdin."""

    def run_script(self, stdin: bytes) -> subprocess.CompletedProcess:
        """Run it under `python3 -I` with this as its input."""
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT)],
            input=stdin,
            capture_output=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )

    def test_a_good_answer_exits_zero(self) -> None:
        """Nothing to report."""
        result = self.run_script(json.dumps(GOOD).encode())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(b"::error", result.stdout)

    def test_a_bad_answer_exits_one_with_each_fault_an_annotation(self) -> None:
        """Each fault on its own line, in the form GitHub shows."""
        answer = good_with(protection_rules=[], deployment_branch_policy=None)
        result = self.run_script(json.dumps(answer).encode())
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2, lines)
        for line in lines:
            self.assertTrue(line.startswith("::error title=Release environment::"), line)
        self.assertEqual(result.stderr, b"")

    def test_malformed_answers_are_refused(self) -> None:
        """Including none at all, as a `gh api` that failed in a pipe would leave."""
        good = json.dumps(GOOD).encode()
        for name, raw in {
            "nothing": b"",
            "not JSON": b"<html>",
            "not text": b"\xff\xfe",
            "not an object": b"[]",
            "NaN in a good answer": good.replace(b'"id": 1', b'"id": NaN', 1),
            "a repeated key in a good answer": b'{"name": "x", ' + good[1:],
            "deep nesting": b"[" * 100_000,
            "a good answer, too long": good.ljust(1024 * 1024 + 1),
        }.items():
            with self.subTest(name=name):
                result = self.run_script(raw)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertTrue(result.stdout.startswith(b"::error title=Release environment::"))
                self.assertEqual(result.stderr, b"")

    def test_a_good_answer_at_the_limit_passes(self) -> None:
        """1 MiB is written out here, so changing the cap takes two edits."""
        result = self.run_script(json.dumps(GOOD).encode().ljust(1024 * 1024))
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


class SharedCodeTests(unittest.TestCase):
    """The scripts run under `python3 -I`, so none can import another: keep them equal."""

    def test_the_helpers_are_the_same(self) -> None:
        """A fix to one is a fix to all."""
        self.assertEqual(check_environment.MAX_SHOWN, assemble_release.MAX_SHOWN)
        for name in ("shown", "refuse_repeats", "refuse_constant"):
            with self.subTest(name=name):
                self.assertEqual(
                    inspect.getsource(getattr(check_environment, name)),
                    inspect.getsource(getattr(assemble_release, name)),
                )


if __name__ == "__main__":
    unittest.main()
