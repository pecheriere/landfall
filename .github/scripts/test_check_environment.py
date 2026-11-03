"""Unit tests for check_environment.py, on sample answers shaped as GitHub's API documents them."""

import copy
import inspect
import json
import subprocess
import sys
import tempfile
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
POLICY = {"id": 1, "node_id": "p", "name": "v[0-9]*", "type": "tag"}
POLICIES = {"total_count": 1, "branch_policies": [POLICY]}


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
            "an empty deployment_branch_policy": (
                good_with(deployment_branch_policy={}),
                "custom_branch_policies",
            ),
            "both policy settings false": (
                good_with(
                    deployment_branch_policy={
                        "protected_branches": False,
                        "custom_branch_policies": False,
                    }
                ),
                "custom_branch_policies",
            ),
            "protected branches only": (
                good_with(
                    deployment_branch_policy={
                        "protected_branches": True,
                        "custom_branch_policies": False,
                    }
                ),
                "protected_branches",
            ),
            "can_admins_bypass true": (good_with(can_admins_bypass=True), "can_admins_bypass"),
        }
        for name, (answer, fault) in cases.items():
            with self.subTest(name=name):
                faults = check_environment.faults(answer, POLICIES)
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
            can_admins_bypass=True,
        )
        self.assertEqual(len(check_environment.faults(answer, {"branch_policies": []})), 5)

    def test_what_is_missing_or_of_another_type_is_refused(self) -> None:
        """A guard that can't read a setting doesn't get to assume it's fine."""
        without_policy = good_with()
        del without_policy["deployment_branch_policy"]
        without_rules = good_with()
        del without_rules["protection_rules"]
        no_self_review_key = {k: v for k, v in REVIEWERS.items() if k != "prevent_self_review"}
        without_bypass = good_with()
        del without_bypass["can_admins_bypass"]
        for name, answer in {
            "no deployment_branch_policy": without_policy,
            "a branch policy of another type": good_with(deployment_branch_policy="yes"),
            "no protection_rules": without_rules,
            "protection_rules of another type": good_with(protection_rules={}),
            "a rule of another type": good_with(protection_rules=["required_reviewers"]),
            "no prevent_self_review": good_with(protection_rules=[no_self_review_key]),
            "a prevent_self_review of another type": reviewers_with(prevent_self_review="false"),
            "reviewers of another type": reviewers_with(reviewers="someone"),
            "a reviewer that is null": reviewers_with(reviewers=[None]),
            "a reviewer with nobody in it": reviewers_with(reviewers=[{"type": "User"}]),
            "one good reviewer and one null": reviewers_with(
                reviewers=[{"type": "User", "reviewer": {"id": 1}}, None]
            ),
            "another environment": good_with(name="staging"),
            "no can_admins_bypass": without_bypass,
            "a can_admins_bypass of another type": good_with(can_admins_bypass="false"),
            "a protected_branches of another type": good_with(
                deployment_branch_policy={
                    "protected_branches": 0,
                    "custom_branch_policies": True,
                }
            ),
            "a custom_branch_policies of another type": good_with(
                deployment_branch_policy={
                    "protected_branches": False,
                    "custom_branch_policies": 1,
                }
            ),
        }.items():
            with self.subTest(name=name):
                self.assertTrue(check_environment.faults(answer, POLICIES))

    def test_the_policy_list_must_be_one_tag_policy_for_release_tags(self) -> None:
        """So that a manual run shows a policy that wouldn't let this tag through, or lets more."""
        branch = {**POLICY, "name": "main", "type": "branch"}
        for name, policies in {
            "missing": None,
            "not an object": [],
            "no list": {"total_count": 1},
            "a list of another type": {"total_count": 1, "branch_policies": "v[0-9]*"},
            "empty": {"total_count": 0, "branch_policies": []},
            "a branch by this name": {
                "total_count": 1,
                "branch_policies": [{**POLICY, "type": "branch"}],
            },
            "another pattern": {
                "total_count": 1,
                "branch_policies": [{**POLICY, "name": "*"}],
            },
            "a policy of another type": {"total_count": 1, "branch_policies": ["v[0-9]*"]},
            "a branch beside it": {"total_count": 2, "branch_policies": [POLICY, branch]},
            "more than the page shows": {"total_count": 31, "branch_policies": [POLICY]},
            "more than its count says": {"total_count": 1, "branch_policies": [POLICY, branch]},
        }.items():
            with self.subTest(name=name):
                faults = check_environment.faults(good_with(), policies)
                self.assertEqual(len(faults), 1, faults)
                self.assertIn("v[0-9]*", faults[0])

    def test_two_reviewer_rules_must_both_be_good(self) -> None:
        """GitHub has one, so a second isn't something to read generously."""
        bad = {**REVIEWERS, "prevent_self_review": True}
        answer = good_with(protection_rules=[REVIEWERS, bad])
        self.assertTrue(check_environment.faults(answer, POLICIES))

    def test_a_long_or_hostile_name_prints_safely(self) -> None:
        """What GitHub answers doesn't get to start a workflow command, or fill a log."""
        answer = good_with(name=f"x\n::error::{'y' * 500}")
        faults = check_environment.faults(answer, POLICIES)
        self.assertEqual(len(faults), 1)
        self.assertNotIn("\n", faults[0])
        self.assertLess(len(faults[0]), 300)


class ProcessTests(unittest.TestCase):
    """The script as the workflow runs it, with GitHub's two answers in files."""

    def setUp(self) -> None:
        """Make a directory for the answers."""
        self.tmp = Path(self.enterContext(tempfile.TemporaryDirectory()))

    def run_script(
        self, environment: bytes, policies: bytes | None = None
    ) -> subprocess.CompletedProcess:
        """Run it under `python3 -I`, with these as its answers, by default a good list."""
        first = self.tmp / "environment.json"
        second = self.tmp / "policies.json"
        first.write_bytes(environment)
        second.write_bytes(json.dumps(POLICIES).encode() if policies is None else policies)
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), str(first), str(second)],
            capture_output=True,
            check=False,
            timeout=TIMEOUT_SECONDS,
        )

    def assert_refused(self, result: subprocess.CompletedProcess, piece: str = "") -> None:
        """Want exit 1, with annotations and no traceback."""
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertTrue(result.stdout.startswith(b"::error title=Release environment::"))
        self.assertIn(piece.encode(), result.stdout)
        self.assertEqual(result.stderr, b"")

    def test_good_answers_exit_zero(self) -> None:
        """Nothing to report."""
        result = self.run_script(json.dumps(GOOD).encode())
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn(b"::error", result.stdout)

    def test_a_bad_answer_exits_one_with_each_fault_an_annotation(self) -> None:
        """Each fault on its own line, in the form GitHub shows."""
        answer = good_with(protection_rules=[], deployment_branch_policy=None)
        result = self.run_script(json.dumps(answer).encode())
        self.assert_refused(result)
        lines = result.stdout.decode().splitlines()
        self.assertEqual(len(lines), 2, lines)
        for line in lines:
            self.assertTrue(line.startswith("::error title=Release environment::"), line)

    def test_malformed_answers_are_refused_in_either_place(self) -> None:
        """Including none at all, as a `gh api` that failed would leave."""
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
            with self.subTest(name=name, where="environment"):
                self.assert_refused(self.run_script(raw))
        good_list = json.dumps(POLICIES).encode()
        for name, raw in {
            "nothing": b"",
            "not JSON": b"<html>",
            "NaN in a good list": good_list[:-1] + b', "x": NaN}',
            "a repeated key in a good list": b'{"total_count": 9, ' + good_list[1:],
            "a good list, too long": good_list.ljust(1024 * 1024 + 1),
        }.items():
            with self.subTest(name=name, where="policies"):
                self.assert_refused(self.run_script(good, raw), "deployment-branch-policies")

    def test_a_missing_file_is_refused(self) -> None:
        """Neither answer may be assumed."""
        good = self.tmp / "good.json"
        good.write_bytes(json.dumps(GOOD).encode())
        missing = self.tmp / "missing.json"
        for name, argv in {
            "environment": [missing, good],
            "policies": [good, missing],
        }.items():
            with self.subTest(name=name):
                result = subprocess.run(
                    [sys.executable, "-I", str(SCRIPT), *map(str, argv)],
                    capture_output=True,
                    check=False,
                    timeout=TIMEOUT_SECONDS,
                )
                self.assert_refused(result)

    def test_good_answers_at_the_limit_pass(self) -> None:
        """1 MiB is written out here, so changing the cap takes two edits."""
        result = self.run_script(
            json.dumps(GOOD).encode().ljust(1024 * 1024),
            json.dumps(POLICIES).encode().ljust(1024 * 1024),
        )
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
