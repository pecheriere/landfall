"""What homebrew.yml must keep doing: the tap's token in one step, and nothing of the tap's run.

Read from the workflow's text, as `test_release_workflow.py` reads `release.yml`, so it holds what's
written here and can't say what GitHub will do with it.
"""

import re
import unittest
from pathlib import Path

from workflow_text import block, job, job_names, significant, step_label, steps

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "homebrew.yml"
CONDITION = (
    "github.ref_type == 'tag' && !contains(github.ref_name, '-') && "
    "(github.event_name != 'release' || !github.event.release.prerelease)"
)
CHECKOUT = "actions/checkout"
TAP_GH_LINE = "GH_TOKEN: ${{ secrets.HOMEBREW_TAP_TOKEN }}"
RUN = re.compile(r"\s*(?:- )?run:")
FORBIDDEN_KEY = re.compile(r"\s*(?:- )?(?:ref|repository|token|ssh-key|defaults):")
JOB_STEPS = {
    "formula": [
        CHECKOUT,
        "Require a published, stable release of the workspace version at this tag",
        "Download the formula and its attestation",
        "Verify the formula against the release's attestation",
        "actions/upload-artifact",
    ],
    "tap": [
        CHECKOUT,
        "actions/download-artifact",
        "Open the tap's pull request, to merge once its checks pass",
    ],
}


class HomebrewWorkflowTests(unittest.TestCase):
    """A test of the real file."""

    def setUp(self) -> None:
        """Read it."""
        self.lines = significant(WORKFLOW.read_text(encoding="utf-8"))
        self.formula = job(self.lines, "formula")
        self.tap = job(self.lines, "tap")

    def test_the_triggers_are_a_published_release_and_a_dispatch(self) -> None:
        """`release.yml` dispatches it, as a release its token publishes starts nothing."""
        trigger = self.lines[self.lines.index("on:") + 1 : self.lines.index("permissions: {}")]
        self.assertEqual(
            [line.strip() for line in trigger],
            ["release:", "types: [published]", "workflow_dispatch:"],
        )

    def test_the_jobs_are_exactly_these_and_the_tap_waits_for_the_check(self) -> None:
        """The secret's job runs only once the formula is checked."""
        self.assertEqual(job_names(self.lines), {"formula", "tap"})
        self.assertIn("    needs: formula", self.tap)

    def test_only_a_stable_tag_runs_it(self) -> None:
        """A tag with no suffix, and no release marked as a prerelease: candidates never go."""
        joined = " ".join(
            line.strip()
            for line in self.formula[
                self.formula.index("    if: >-") + 1 : self.formula.index(
                    "    runs-on: ubuntu-latest"
                )
            ]
        )
        self.assertEqual(joined, CONDITION)

    def test_the_secret_is_in_one_step_of_the_tap_job(self) -> None:
        """Not in the job that reads the release, and not in the job's environment."""
        self.assertEqual([line.strip() for line in self.lines if "secrets." in line], [TAP_GH_LINE])
        holding = [step for step in steps(self.tap) if TAP_GH_LINE in "\n".join(step)]
        self.assertEqual([step_label(step) for step in holding], [JOB_STEPS["tap"][-1]])
        self.assertNotIn("    env:", self.tap)

    def test_only_the_tap_job_is_in_the_environment(self) -> None:
        """The environment holds the token, with a tag rule only."""
        self.assertIn("    environment: homebrew-tap", self.tap)
        self.assertEqual(
            [line for line in self.lines if "environment:" in line],
            ["    environment: homebrew-tap"],
        )

    def test_nothing_of_the_tap_is_checked_out_or_run(self) -> None:
        """Each checkout is this repository's own, at the run's commit, keeping no credentials."""
        self.assertEqual([line for line in self.lines if FORBIDDEN_KEY.match(line)], [])
        for name in ("formula", "tap"):
            checkouts = [s for s in steps(job(self.lines, name)) if CHECKOUT in "\n".join(s)]
            with self.subTest(job=name):
                self.assertEqual(len(checkouts), 1)
                self.assertEqual(
                    checkouts[0][1:], ["        with:", "          persist-credentials: false"]
                )
        uses = [line.strip() for line in self.lines if "uses:" in line]
        self.assertFalse([line for line in uses if "homebrew" in line], uses)

    def test_permissions_are_the_least_each_needs(self) -> None:
        """None at the top, and reading this repository in each job."""
        self.assertIn("permissions: {}", self.lines)
        for name in ("formula", "tap"):
            with self.subTest(job=name):
                self.assertEqual(block(job(self.lines, name), "permissions"), ["contents: read"])

    def test_each_job_has_exactly_its_steps(self) -> None:
        """A step added before the pull request could change what's proposed."""
        for name, expected in JOB_STEPS.items():
            with self.subTest(job=name):
                self.assertEqual([step_label(s) for s in steps(job(self.lines, name))], expected)

    def test_the_formula_is_verified_against_this_tag_and_commit(self) -> None:
        """The flags the tap's README uses, with the release's own bundle."""
        step = "\n".join(steps(self.formula)[3])
        for flag in (
            "gh attestation verify formula/landfall.rb",
            '--bundle "formula/landfall-$VERSION.sigstore.json"',
            '--repo "$GITHUB_REPOSITORY"',
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
            '--source-ref "refs/tags/$GITHUB_REF_NAME"',
            '--source-digest "$GITHUB_SHA"',
            "--deny-self-hosted-runners",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, step)

    def test_the_scripts_are_run_as_written(self) -> None:
        """Dropping an argument from these is dropping a check."""
        check = "\n".join(steps(self.formula)[1])
        self.assertIn("--json tagName,isDraft,isPrerelease", check)
        self.assertIn('homebrew_tap.py check --tag "$GITHUB_REF_NAME"', check)
        self.assertIn('--release "$RUNNER_TEMP/release.json" --output "$GITHUB_OUTPUT"', check)
        propose = steps(self.tap)[-1]
        self.assertEqual(
            propose[-3:],
            [
                "        run: >-",
                (
                    "          python3 -I .github/scripts/homebrew_tap.py propose "
                    "--formula formula/landfall.rb"
                ),
                '          --version "$VERSION" --repo "$GITHUB_REPOSITORY"',
            ],
        )

    def test_the_formula_crosses_by_artifact_id(self) -> None:
        """A name can be rebound by anything else in the run holding a runtime token."""
        download = "\n".join(steps(self.tap)[1])
        self.assertIn("artifact-ids: ${{ needs.formula.outputs.artifact-id }}", download)
        self.assertEqual(
            block(self.formula, "outputs"),
            [
                "version: ${{ steps.check.outputs.version }}",
                "artifact-id: ${{ steps.upload.outputs.artifact-id }}",
            ],
        )

    def test_no_expression_reaches_a_shell(self) -> None:
        """A value goes through `env`, so that it can't be read as part of a script."""
        for name in ("formula", "tap"):
            for step in steps(job(self.lines, name)):
                run = [i for i, line in enumerate(step) if RUN.match(line)]
                if run:
                    with self.subTest(job=name, step=step[0]):
                        self.assertNotIn("${{", "\n".join(step[run[0] :]))


if __name__ == "__main__":
    unittest.main()
