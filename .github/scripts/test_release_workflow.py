"""What release.yml must keep doing, whatever a later edit does to it.

A manual run skips `publish`, so a change that dropped the approval or the tag proof would still
show green there: this holds those properties instead. The standard library has no YAML parser, so
jobs and steps are read by their indentation, as in `test_buildkit_pin.py`, and anything that isn't
the expected shape fails. It reads the workflow's text, so it holds what's written here and can't
say what GitHub will do with it.
"""

import re
import unittest
from pathlib import Path

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "release.yml"
JOB_INDENT = 2
STEP_INDENT = 6
# Any way of asking for a cache. `cache-binary: false` is how buildx is told not to keep one.
CACHE = re.compile(r"cache", re.IGNORECASE)
NO_CACHE_SETTING = "cache-binary: false"
PUBLISH_NEEDS = {
    "on-main",
    "crate-age",
    "ci",
    "preflight",
    "environment-guard",
    "build-linux",
    "build-macos",
    "smoke",
}
ATTEMPT_CHECK = '[ "$GITHUB_RUN_ATTEMPT" != 1 ]'
TAG_EVENT = "if: github.event_name == 'push'"
RUN = re.compile(r"\s*(?:- )?run:")


def indent_of(line: str) -> int:
    """Return how far a line is indented."""
    return len(line) - len(line.lstrip())


def strip_comment(line: str) -> str:
    """Return a line without a comment after a space, in a value that holds no `#` itself."""
    return line.split(" # ", 1)[0].rstrip()


def significant(text: str) -> list[str]:
    """Return the lines that hold something, without comments."""
    return [
        strip_comment(line)
        for line in text.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]


def job(lines: list[str], name: str) -> list[str]:
    """Return the lines under one job, which must exist."""
    start = lines.index(f"{' ' * JOB_INDENT}{name}:") + 1
    end = start
    while end < len(lines) and indent_of(lines[end]) > JOB_INDENT:
        end += 1
    return lines[start:end]


def steps(job_lines: list[str]) -> list[list[str]]:
    """Return a job's steps, each as its lines."""
    start = job_lines.index(f"{' ' * (STEP_INDENT - 2)}steps:") + 1
    found: list[list[str]] = []
    for line in job_lines[start:]:
        if line.startswith(f"{' ' * STEP_INDENT}- "):
            found.append([])
        if indent_of(line) < STEP_INDENT:
            break
        found[-1].append(line)
    return found


def block(job_lines: list[str], key: str) -> list[str]:
    """Return the stripped lines of a mapping or list directly under a job's key."""
    outer = f"{' ' * (STEP_INDENT - 2)}{key}:"
    start = job_lines.index(outer) + 1
    found = []
    for line in job_lines[start:]:
        if indent_of(line) <= STEP_INDENT - 2:
            break
        found.append(line.strip())
    return found


def step_index(step_list: list[list[str]], piece: str) -> int:
    """Return the index of the one step holding this text."""
    matching = [i for i, step in enumerate(step_list) if piece in "\n".join(step)]
    if len(matching) != 1:
        message = f"{piece!r} is in {len(matching)} steps, where one was wanted"
        raise AssertionError(message)
    return matching[0]


class WorkflowCase(unittest.TestCase):
    """A test of the real file."""

    def setUp(self) -> None:
        """Read it."""
        self.lines = significant(WORKFLOW.read_text(encoding="utf-8"))
        self.publish = job(self.lines, "publish")
        self.publish_steps = steps(self.publish)


class PublishGateTests(WorkflowCase):
    """What stands between a tag and anything public."""

    def test_publish_needs_every_check(self) -> None:
        """Losing one would still look right on a manual run, where `publish` is skipped."""
        self.assertEqual(set(block(self.publish, "needs")), {f"- {n}" for n in PUBLISH_NEEDS})

    def test_publish_runs_only_on_a_tag_push_and_in_the_environment(self) -> None:
        """The environment is where the person is, and a push is only ever a tag here."""
        self.assertIn(f"    {TAG_EVENT}", self.publish)
        self.assertIn("    environment: release", self.publish)

    def test_a_push_can_only_be_a_tag(self) -> None:
        """A branch push here would be read as a release."""
        trigger = self.lines[self.lines.index("on:") + 1 :]
        trigger = trigger[: trigger.index("permissions:")]
        self.assertEqual(
            [line.strip() for line in trigger],
            ["push:", "tags: ['v[0-9]*']", "workflow_dispatch:"],
        )

    def test_permissions_are_the_least_each_needs(self) -> None:
        """Read-only at the top, and write only in `publish`."""
        top = self.lines.index("permissions:")
        self.assertEqual(self.lines[top + 1], "  contents: read")
        self.assertEqual(self.lines[top + 2], "jobs:")
        self.assertEqual(
            set(block(self.publish, "permissions")),
            {
                "contents: write",
                "packages: write",
                "id-token: write",
                "attestations: write",
            },
        )
        for name in (
            "on-main",
            "crate-age",
            "preflight",
            "build-linux",
            "build-macos",
            "smoke",
        ):
            with self.subTest(job=name):
                self.assertNotIn("    permissions:", job(self.lines, name))
        guard = set(block(job(self.lines, "environment-guard"), "permissions"))
        self.assertEqual(guard, {"actions: read", "contents: read"})

    def test_a_second_attempt_is_refused_first_and_early(self) -> None:
        """First in `publish`, and first in `preflight` so a re-run stops in seconds."""
        for name, job_steps in {
            "publish": self.publish_steps,
            "preflight": steps(job(self.lines, "preflight")),
        }.items():
            with self.subTest(job=name):
                first = "\n".join(job_steps[0])
                self.assertIn(ATTEMPT_CHECK, first)
                self.assertIn("exit 1", first)

    def test_preflight_runs_on_a_tag_and_proves_it(self) -> None:
        """Skipped on a manual run, which has no tag, and given the run's own values."""
        preflight = job(self.lines, "preflight")
        self.assertIn(f"    {TAG_EVENT}", preflight)
        self.assertIn("    needs: on-main", preflight)
        text = "\n".join(preflight)
        self.assertIn(".github/scripts/release_preflight.py", text)
        self.assertIn(
            '--tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" --repo "$GITHUB_REPOSITORY"', text
        )

    def test_the_guard_reads_both_answers_and_no_condition_can_skip_it(self) -> None:
        """A skipped guard would skip `publish`, but this says what was meant."""
        guard = job(self.lines, "environment-guard")
        self.assertFalse([line for line in guard if line.startswith("    if:")])
        text = "\n".join(guard)
        self.assertIn('"repos/$GITHUB_REPOSITORY/environments/release"', text)
        self.assertIn(
            '"repos/$GITHUB_REPOSITORY/environments/release/deployment-branch-policies"', text
        )
        self.assertIn('> "$RUNNER_TEMP/environment.json"', text)
        self.assertIn('> "$RUNNER_TEMP/policies.json"', text)
        self.assertIn('check_environment.py "$RUNNER_TEMP/environment.json"', text)
        self.assertIn('"$RUNNER_TEMP/policies.json"\n', text + "\n")

    def test_crate_age_checks_the_whole_lock_file(self) -> None:
        """A spent tag can't be the base: what it refused would pass, as unchanged, next time."""
        text = "\n".join(job(self.lines, "crate-age"))
        self.assertIn("crate_age.py --no-base", text)
        self.assertNotIn("--base", text.replace("--no-base", ""))


class PublishOrderTests(WorkflowCase):
    """The steps of `publish`, whose order is what makes a failure cheap."""

    def test_the_order_of_the_steps(self) -> None:
        """Verify before anything exists to see, draft before the image, and public last."""
        pieces = [
            ATTEMPT_CHECK,
            "actions/checkout@",
            "${{ needs.build-linux.outputs.artifact-id }}",
            "${{ needs.build-macos.outputs.artifact-id }}",
            ".github/scripts/check_binaries.py dist",
            "assemble_release.py assemble",
            "subject-path: out/*",
            "assemble_release.py check-bundle",
            "gh attestation verify",
            "gh release create",
            "docker/login-action@",
            "docker/build-push-action@",
            "subject-digest:",
            "draft=false",
        ]
        indexes = [step_index(self.publish_steps, piece) for piece in pieces]
        self.assertEqual(indexes, sorted(indexes), list(zip(pieces, indexes, strict=True)))

    def test_every_file_is_verified_against_this_commit_and_tag(self) -> None:
        """Each flag is part of what's being proved, and none has a default that would do."""
        step = "\n".join(
            self.publish_steps[step_index(self.publish_steps, "gh attestation verify")]
        )
        for flag in (
            "for file in out/*; do",
            'gh attestation verify "$file" --bundle "$BUNDLE"',
            '--repo "$GITHUB_REPOSITORY"',
            '--signer-workflow "$GITHUB_REPOSITORY/.github/workflows/release.yml"',
            '--source-ref "refs/tags/$GITHUB_REF_NAME"',
            '--source-digest "$GITHUB_SHA"',
            "--deny-self-hosted-runners",
        ):
            with self.subTest(flag=flag):
                self.assertIn(flag, step)

    def test_the_release_starts_as_a_draft_of_this_tag(self) -> None:
        """A draft is the part that can be abandoned, and a tag it didn't verify isn't this one."""
        step = "\n".join(self.publish_steps[step_index(self.publish_steps, "gh release create")])
        self.assertRegex(
            step,
            r'gh release create "\$GITHUB_REF_NAME" out/\* --draft --verify-tag --generate-notes',
        )
        self.assertIn("flags=(--prerelease --latest=false)", step)

    def test_only_the_draft_this_run_made_is_published(self) -> None:
        """Found by the URL `gh` printed for it: a draft planted for the tag isn't this one."""
        draft = "\n".join(self.publish_steps[step_index(self.publish_steps, "gh release create")])
        self.assertIn("id: draft", draft)
        self.assertIn('url=$(gh release create "$GITHUB_REF_NAME"', draft)
        self.assertIn(".html_url == $url", draft)
        final = "\n".join(self.publish_steps[-1])
        self.assertIn("RELEASE_ID: ${{ steps.draft.outputs.id }}", final)
        self.assertIn('"repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"', final)
        self.assertIn("-F draft=false", final)
        self.assertNotIn("gh release edit", "\n".join(self.lines))

    def test_the_image_attestation_records_no_storage(self) -> None:
        """That needs an organisation and a permission `publish` doesn't have."""
        step = self.publish_steps[step_index(self.publish_steps, "subject-digest:")]
        self.assertIn("          push-to-registry: true", step)
        self.assertIn("          create-storage-record: false", step)

    def test_the_files_are_attested_in_this_workflow(self) -> None:
        """The verifier refuses a reusable workflow's identity."""
        step = self.publish_steps[step_index(self.publish_steps, "subject-path: out/*")]
        self.assertTrue(step[0].strip().startswith("- id: attest"), step)
        self.assertIn("actions/attest-build-provenance@", step[1])

    def test_the_binaries_are_checked_again_with_their_mode_restored(self) -> None:
        """`check_binaries.py` wants 0755, which an artifact loses, on what's to be attested."""
        step = "\n".join(
            self.publish_steps[step_index(self.publish_steps, "check_binaries.py dist")]
        )
        self.assertLess(step.index("chmod 0755"), step.index("check_binaries.py dist"))


class ArtifactTests(WorkflowCase):
    """The bytes `publish` attests are the ones `smoke` ran and the build jobs made."""

    def test_each_build_exports_its_artifacts_id(self) -> None:
        """An id can't be rebound: overwriting by name gives a new one, and removes the old."""
        for name in ("build-linux", "build-macos"):
            with self.subTest(job=name):
                build = job(self.lines, name)
                self.assertEqual(
                    block(build, "outputs"),
                    ["artifact-id: ${{ steps.upload.outputs.artifact-id }}"],
                )
                upload = steps(build)[step_index(steps(build), "actions/upload-artifact@")]
                self.assertEqual(upload[0].strip(), "- id: upload")
                self.assertIn("          retention-days: 7", upload)
                self.assertIn("          if-no-files-found: error", upload)

    def test_every_download_is_by_id(self) -> None:
        """A name can be rebound by anything else in the run holding a runtime token."""
        for name in ("smoke", "publish"):
            job_steps = steps(job(self.lines, name))
            downloads = [s for s in job_steps if "actions/download-artifact@" in "\n".join(s)]
            self.assertTrue(downloads, name)
            for download in downloads:
                with self.subTest(job=name):
                    text = "\n".join(download)
                    self.assertIn("artifact-ids:", text)
                    self.assertNotIn(" name:", text)

    def test_smoke_runs_the_ids_each_build_exported(self) -> None:
        """Each row of the matrix, by the right build's id."""
        smoke = job(self.lines, "smoke")
        text = "\n".join(smoke)
        self.assertEqual(text.count("artifact-id: ${{ needs.build-linux.outputs.artifact-id }}"), 2)
        self.assertEqual(text.count("artifact-id: ${{ needs.build-macos.outputs.artifact-id }}"), 1)
        self.assertIn("artifact-ids: ${{ matrix.artifact-id }}", text)


class HygieneTests(WorkflowCase):
    """What holds for the whole file."""

    def test_no_cache_where_release_files_are_made(self) -> None:
        """The build jobs and `publish` make what's attested, so nothing restored may reach them."""
        for name in ("build-linux", "build-macos", "publish"):
            lines = [
                line
                for line in job(self.lines, name)
                if CACHE.search(line) and line.strip() != NO_CACHE_SETTING
            ]
            with self.subTest(job=name):
                self.assertEqual(lines, [])

    def test_every_checkout_keeps_no_credentials(self) -> None:
        """Anything run later in the job could otherwise read the token from the clone."""
        checkouts = [
            step
            for name in ("preflight", "environment-guard", "build-linux", "build-macos", "publish")
            for step in steps(job(self.lines, name))
            if "actions/checkout@" in "\n".join(step)
        ]
        self.assertEqual(len(checkouts), 5)
        for step in checkouts:
            self.assertIn("          persist-credentials: false", step)

    def test_no_expression_reaches_a_shell(self) -> None:
        """A value goes through `env`, so that it can't be read as part of a script."""
        for name in ("preflight", "environment-guard", "build-linux", "smoke", "publish"):
            for step in steps(job(self.lines, name)):
                run = [i for i, line in enumerate(step) if RUN.match(line)]
                if run:
                    with self.subTest(job=name, step=step[0]):
                        self.assertNotIn("${{", "\n".join(step[run[0] :]))


class ReadingTests(unittest.TestCase):
    """The reader must find what's there, or the tests above prove nothing."""

    TEXT = """on:
jobs:
  first:
    needs:
      - a
      - b
    steps:
      - name: One # a comment
        run: |
          echo one
      - run: echo two
  second:
    steps:
      - run: echo three
"""

    def test_jobs_and_steps_are_read_by_indentation(self) -> None:
        """Each step whole, and a job stopping where the next starts."""
        lines = significant(self.TEXT)
        first = job(lines, "first")
        self.assertEqual(block(first, "needs"), ["- a", "- b"])
        self.assertEqual(
            steps(first),
            [
                ["      - name: One", "        run: |", "          echo one"],
                ["      - run: echo two"],
            ],
        )
        self.assertEqual(steps(job(lines, "second")), [["      - run: echo three"]])

    def test_a_job_that_is_not_there_fails(self) -> None:
        """A renamed job isn't a job that passes."""
        with self.assertRaises(ValueError):
            job(significant(self.TEXT), "third")

    def test_a_piece_in_no_step_or_two_fails(self) -> None:
        """The order test can't pass by finding nothing."""
        step_list = steps(job(significant(self.TEXT), "first"))
        with self.assertRaises(AssertionError):
            step_index(step_list, "absent")
        with self.assertRaises(AssertionError):
            step_index(step_list, "echo")


if __name__ == "__main__":
    unittest.main()
