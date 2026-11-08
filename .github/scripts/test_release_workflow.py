"""What release.yml must keep doing, whatever a later edit does to it.

A dry run skips `publish`, so a change that dropped the tag proof, or let a push to main reach
`publish`, would still show green there: this holds those properties instead. The standard
library has no YAML parser, so jobs and steps are read by their indentation, as in
`test_buildkit_pin.py`, and anything that isn't the expected shape fails. It reads the workflow's
text, so it holds what's written here and can't say what GitHub will do with it.

A text test can't be complete: someone can always write something it didn't think of. A person
reading a diff of `release.yml` is the last line, and this doesn't replace them.
"""

import re
import unittest
from pathlib import Path

from workflow_text import block, job, job_names, needed, significant, step_index, step_label, steps

WORKFLOW = Path(__file__).resolve().parents[1] / "workflows" / "release.yml"
# Any way of asking for a cache. `cache-binary: false` is how buildx is told not to keep one.
CACHE = re.compile(r"cache", re.IGNORECASE)
NO_CACHE_SETTING = "cache-binary: false"
PUBLISH_NEEDS = {
    "version",
    "on-main",
    "crate-age",
    "ci",
    "preflight",
    "build-linux",
    "build-macos",
    "smoke",
}
ATTEMPT_CHECK = '[ "$GITHUB_RUN_ATTEMPT" != 1 ]'
TAG_EVENT = "if: github.event_name == 'push' && github.ref_type == 'tag'"
BUILD_CONDITION = "if: needs.version.outputs.build == 'true'"
RUN = re.compile(r"\s*(?:- )?run:")
CONDITION = re.compile(r"\s*(?:- )?if:")
WRITE = re.compile(r":\s*write\b|write-all")
JOBS = PUBLISH_NEEDS | {"publish"}
FORBIDDEN_KEY = re.compile(r"\s*(?:- )?(?:ref|repository|run-id|digest-mismatch|defaults):")
LOGIN_LINE = "          password: ${{ secrets.GITHUB_TOKEN }}"
CHECKOUT = "actions/checkout"
DOWNLOAD = "actions/download-artifact"
UPLOAD = "actions/upload-artifact"
BUILDX = "docker/setup-buildx-action"
BUILD = "docker/build-push-action"
ATTEST = "actions/attest-build-provenance"
SECOND_ATTEMPT = "Refuse a second attempt"
# Each job's steps, by action without its pin or by name, so that a step added anywhere fails.
JOB_STEPS = {
    "version": [
        CHECKOUT,
        "Build on a tag, a manual run, or a push to main that changes the version",
    ],
    "on-main": [CHECKOUT, "Require the commit to be on main"],
    "crate-age": [CHECKOUT, "Refuse crate versions published less than 7 days ago"],
    "preflight": [SECOND_ATTEMPT, CHECKOUT, "Prove the tag"],
    "build-linux": [CHECKOUT, BUILDX, BUILD, "Check the static binaries", UPLOAD],
    "build-macos": [
        CHECKOUT,
        "dtolnay/rust-toolchain",
        "cargo build --release --locked -p landfall-cli --target aarch64-apple-darwin",
        UPLOAD,
    ],
    "smoke": [DOWNLOAD, "Run each native binary, and on a tag compare its version with the tag"],
    "publish": [
        SECOND_ATTEMPT,
        CHECKOUT,
        DOWNLOAD,
        DOWNLOAD,
        "Check the static binaries again",
        "Assemble the release's files",
        ATTEST,
        "Check the attestation's shape against the files",
        "Verify every file against that attestation",
        "Upload the files as a draft release",
        BUILDX,
        "docker/login-action",
        "Name the image after this repository",
        "docker/metadata-action",
        BUILD,
        ATTEST,
        "Publish the draft, and read it back",
    ],
}
PUBLISH_WRITES = (
    "contents: write",
    "packages: write",
    "id-token: write",
    "attestations: write",
)


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

    def test_publish_runs_only_on_a_tag_push(self) -> None:
        """A push to main is a push too, and a manual run can be started on a tag."""
        self.assertIn(f"    {TAG_EVENT}", self.publish)

    def test_no_job_waits_for_an_approval(self) -> None:
        """The signed tag is the gate: a stolen token can approve a deployment through the API."""
        self.assertEqual([line for line in self.lines if "environment:" in line], [])

    def test_a_push_is_to_main_or_a_tag(self) -> None:
        """Main for the dry run, a tag for a release, and no other branch."""
        trigger = self.lines[self.lines.index("on:") + 1 :]
        trigger = trigger[: trigger.index("permissions:")]
        self.assertEqual(
            [line.strip() for line in trigger],
            ["push:", "branches: [main]", "tags: ['v[0-9]*']", "workflow_dispatch:"],
        )

    def test_a_push_to_main_never_reaches_what_a_tag_does(self) -> None:
        """`preflight` and `publish` want a tag push, and only `publish` attests."""
        self.assertIn(f"    {TAG_EVENT}", job(self.lines, "preflight"))
        attesting = [
            name
            for name in JOBS - {"ci"}
            if f"{ATTEST}@" in "\n".join(job(self.lines, name))
            or "id-token" in "\n".join(job(self.lines, name))
        ]
        self.assertEqual(attesting, ["publish"])
        smoke = "\n".join(job(self.lines, "smoke"))
        self.assertIn('if [ "$GITHUB_REF_TYPE" = tag ]; then', smoke)

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
            "version",
            "on-main",
            "crate-age",
            "preflight",
            "build-linux",
            "build-macos",
            "smoke",
        ):
            with self.subTest(job=name):
                self.assertNotIn("    permissions:", job(self.lines, name))

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

    def test_only_a_version_change_on_main_builds_with_no_tag(self) -> None:
        """`on-main` is what everything else needs, so its condition decides the whole run."""
        on_main = job(self.lines, "on-main")
        self.assertIn("    needs: version", on_main)
        self.assertIn(f"    {BUILD_CONDITION}", on_main)
        self.assertEqual(
            block(job(self.lines, "version"), "outputs"),
            ["build: ${{ steps.decide.outputs.build }}"],
        )
        for name in JOBS - {"version", "on-main"}:
            with self.subTest(job=name):
                self.assertIn("on-main", needed(self.lines, name))

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
        # Not by `tag_name`, which on a draft can be a placeholder.
        self.assertIn("'.[] | select(.draft and .html_url == $url) | .id')", draft)
        self.assertIn('if ! [[ "$matches" =~ ^[0-9]+$ ]]; then', draft)
        self.assertIn('echo "id=$matches" >> "$GITHUB_OUTPUT"', draft)
        final = "\n".join(self.publish_steps[-1])
        self.assertIn("RELEASE_ID: ${{ steps.draft.outputs.id }}", final)
        self.assertIn('"repos/$GITHUB_REPOSITORY/releases/$RELEASE_ID"', final)
        self.assertNotIn("gh release edit", "\n".join(self.lines))

    def test_the_listing_is_polled_within_a_bound(self) -> None:
        """A new draft can take a moment to be listed, and a tag run has only the one attempt."""
        draft = "\n".join(self.publish_steps[step_index(self.publish_steps, "gh release create")])
        self.assertIn("for _ in {1..24}; do", draft)
        self.assertIn("sleep 5", draft)
        self.assertLess(draft.index("for _ in"), draft.index("repos/$GITHUB_REPOSITORY/releases"))

    def test_publishing_sends_the_tag_and_reads_the_result_back(self) -> None:
        """Without the tag the API can drop it, and a green step isn't a release a host can find."""
        final = "\n".join(self.publish_steps[-1])
        self.assertIn('-f tag_name="$GITHUB_REF_NAME" -F draft=false', final)
        self.assertIn('"repos/$GITHUB_REPOSITORY/releases/tags/$GITHUB_REF_NAME"', final)
        self.assertIn(
            "'.draft == false and .tag_name == $tag and .immutable == true'",
            final,
        )
        self.assertIn("for _ in {1..5}; do", final)
        self.assertIn("for _ in {1..12}; do", final)
        self.assertLess(final.index("{1..5}"), final.index("draft=false"))
        self.assertLess(final.index("draft=false"), final.index("{1..12}"))
        self.assertIn("It may already be public: check it by hand.", final)
        self.assertLess(final.index("draft=false"), final.index("releases/tags/"))
        self.assertEqual(final.count("exit 0"), 1)
        self.assertTrue(final.endswith("exit 1"), final)

    def test_the_commands_that_decide_are_held_exactly(self) -> None:
        """Dropping a flag or an argument from these is dropping a check."""
        for piece, expected in {
            "assemble_release.py assemble": [
                "      - name: Assemble the release's files",
                "        run: >-",
                "          python3 -I .github/scripts/assemble_release.py assemble",
                '          --dist dist --macos macos --version "${GITHUB_REF_NAME#v}"',
                '          --repo "$GITHUB_REPOSITORY" --out out',
            ],
            "assemble_release.py check-bundle": [
                "      - name: Check the attestation's shape against the files",
                "        env:",
                "          BUNDLE: ${{ steps.attest.outputs.bundle-path }}",
                (
                    "        run: python3 -I .github/scripts/assemble_release.py check-bundle "
                    '--bundle "$BUNDLE" --out out'
                ),
            ],
            "check_binaries.py dist": [
                "      - name: Check the static binaries again",
                "        run: |",
                "          chmod 0755 dist/linux_arm64/* dist/linux_amd64/*",
                "          python3 -I .github/scripts/check_binaries.py dist",
            ],
        }.items():
            with self.subTest(piece=piece):
                step = self.publish_steps[step_index(self.publish_steps, piece)]
                self.assertEqual(step, expected)

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
                self.assertIn("          retention-days: 1", upload)
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
            for name in JOBS - {"ci", "smoke"}
            for step in steps(job(self.lines, name))
            if "actions/checkout@" in "\n".join(step)
        ]
        self.assertEqual(len(checkouts), 7)
        for step in checkouts:
            self.assertIn("          persist-credentials: false", step)

    def test_no_expression_reaches_a_shell(self) -> None:
        """A value goes through `env`, so that it can't be read as part of a script."""
        for name in JOBS - {"ci"}:
            for step in steps(job(self.lines, name)):
                run = [i for i, line in enumerate(step) if RUN.match(line)]
                if run:
                    with self.subTest(job=name, step=step[0]):
                        self.assertNotIn("${{", "\n".join(step[run[0] :]))


class WholeFileTests(WorkflowCase):
    """Rules no edit gets round by being in a job or a step nobody listed."""

    def test_the_jobs_are_exactly_these(self) -> None:
        """A new job has none of the gates `publish` has, whatever it's given."""
        self.assertEqual(job_names(self.lines), JOBS)

    def test_only_publish_can_write(self) -> None:
        """Four lines, all in that job, and no broader form anywhere."""
        writing = [line.strip() for line in self.lines if WRITE.search(line)]
        self.assertEqual(sorted(writing), sorted(PUBLISH_WRITES))
        self.assertEqual(
            sorted(line.strip() for line in self.publish if WRITE.search(line)),
            sorted(PUBLISH_WRITES),
        )

    def test_nothing_may_fail_quietly(self) -> None:
        """`continue-on-error` is the first thing a flake tempts someone to reach for."""
        self.assertEqual([line for line in self.lines if "continue-on-error" in line], [])
        self.assertEqual([line for line in self.lines if "set +e" in line], [])

    def test_the_conditions_are_exactly_these(self) -> None:
        """An `if:` on any job or step is a way of not running it."""
        found = [line for line in self.lines if CONDITION.match(line)]
        self.assertEqual(
            found,
            [
                f"    {BUILD_CONDITION}",
                f"    {TAG_EVENT}",
                f"    {TAG_EVENT}",
            ],
        )

    def test_a_failure_is_swallowed_only_where_it_is_then_refused(self) -> None:
        """A failed listing: the next lines refuse an empty answer."""
        found = [line.strip() for line in self.lines if "||" in line]
        self.assertEqual(
            found,
            [
                'if [ "$GITHUB_EVENT_NAME" != push ] || [ "$GITHUB_REF_TYPE" = tag ]; then',
                """'.[] | select(.draft and .html_url == $url) | .id') || matches=\"\"""",
            ],
        )

    def test_ci_is_only_the_reusable_workflow(self) -> None:
        """A job here that merely ran `true` would pass for all of CI."""
        self.assertEqual(
            job(self.lines, "ci"),
            [
                "    needs: on-main",
                "    uses: $/.github/workflows/ci.yml",
                "    permissions:",
                "      contents: read",
            ],
        )

    def test_on_main_is_this_check(self) -> None:
        """Its whole history is what makes `origin/main` something to ask about."""
        on_main = steps(job(self.lines, "on-main"))
        self.assertEqual(len(on_main), 2)
        self.assertIn("          fetch-depth: 0", on_main[0])
        self.assertEqual(
            on_main[1],
            [
                "      - name: Require the commit to be on main",
                '        run: git merge-base --is-ancestor "$GITHUB_SHA" origin/main',
            ],
        )

    def test_smoke_is_these_runners_and_this_comparison(self) -> None:
        """Native arm64 is why it exists, and the tag comparison is what a tag run adds."""
        smoke = job(self.lines, "smoke")
        self.assertEqual(
            smoke[smoke.index("    strategy:") : smoke.index("    runs-on: ${{ matrix.runner }}")],
            [
                "    strategy:",
                "      fail-fast: false",
                "      matrix:",
                "        include:",
                "          - runner: ubuntu-24.04",
                "            artifact-id: ${{ needs.build-linux.outputs.artifact-id }}",
                "            binaries: linux_amd64/landfall linux_amd64/landfall-agent",
                "          - runner: ubuntu-24.04-arm",
                "            artifact-id: ${{ needs.build-linux.outputs.artifact-id }}",
                "            binaries: linux_arm64/landfall linux_arm64/landfall-agent",
                "          - runner: macos-26",
                "            artifact-id: ${{ needs.build-macos.outputs.artifact-id }}",
                "            binaries: landfall",
            ],
        )
        self.assertEqual(
            steps(smoke)[-1],
            [
                (
                    "      - name: Run each native binary, and on a tag compare its version "
                    "with the tag"
                ),
                "        shell: bash",
                "        env:",
                "          BINARIES: ${{ matrix.binaries }}",
                "        run: |",
                "          for binary in $BINARIES; do",
                '            chmod +x "binaries/$binary"',
                '            actual=$("binaries/$binary" --version)',
                '            echo "$binary: $actual"',
                '            if [ "$GITHUB_REF_TYPE" = tag ]; then',
                '              test "$actual" = "${binary##*/} ${GITHUB_REF_NAME#v}"',
                "            fi",
                "          done",
            ],
        )

    def test_the_checks_that_run_a_script_are_held_exactly(self) -> None:
        """Across the other jobs, for the same reason as `publish`'s."""
        for name, expected in {
            "crate-age": [
                "      - name: Refuse crate versions published less than 7 days ago",
                "        run: python3 -I .github/scripts/crate_age.py --no-base",
            ],
            "preflight": [
                "      - name: Prove the tag",
                "        env:",
                "          GH_TOKEN: ${{ github.token }}",
                "        run: >-",
                "          python3 -I .github/scripts/release_preflight.py",
                (
                    '          --tag "$GITHUB_REF_NAME" --sha "$GITHUB_SHA" '
                    '--repo "$GITHUB_REPOSITORY"'
                ),
            ],
        }.items():
            with self.subTest(job=name):
                self.assertEqual(steps(job(self.lines, name))[-1], expected)

    def test_the_build_decision_and_the_verify_step_are_held_whole(self) -> None:
        """What decides a dry run, and the gate a text test can most cheaply protect."""
        version = steps(job(self.lines, "version"))
        self.assertIn("          fetch-depth: 0", version[0])
        self.assertEqual(
            version[-1],
            [
                "      - id: decide",
                (
                    "        name: Build on a tag, a manual run, or a push to main that changes "
                    "the version"
                ),
                "        shell: bash",
                "        env:",
                "          BEFORE: ${{ github.event.before }}",
                "        run: |",
                (
                    '          if [ "$GITHUB_EVENT_NAME" != push ] || '
                    '[ "$GITHUB_REF_TYPE" = tag ]; then'
                ),
                '            echo "build=true" >> "$GITHUB_OUTPUT"',
                "          else",
                (
                    "            python3 -I .github/scripts/version_bump.py "
                    '--before "$BEFORE" --output "$GITHUB_OUTPUT"'
                ),
                "          fi",
            ],
        )
        self.assertEqual(
            self.publish_steps[step_index(self.publish_steps, "gh attestation verify")],
            [
                "      - name: Verify every file against that attestation",
                "        shell: bash",
                "        env:",
                "          BUNDLE: ${{ steps.attest.outputs.bundle-path }}",
                "          GH_TOKEN: ${{ github.token }}",
                "        run: |",
                "          for file in out/*; do",
                '            gh attestation verify "$file" --bundle "$BUNDLE" \\',
                '              --repo "$GITHUB_REPOSITORY" \\',
                (
                    '              --signer-workflow "$GITHUB_REPOSITORY/.github/workflows/'
                    'release.yml" \\'
                ),
                '              --source-ref "refs/tags/$GITHUB_REF_NAME" \\',
                '              --source-digest "$GITHUB_SHA" \\',
                "              --deny-self-hosted-runners",
                "          done",
                '          cp "$BUNDLE" "out/landfall-${GITHUB_REF_NAME#v}.sigstore.json"',
            ],
        )

    def test_each_job_has_exactly_its_steps(self) -> None:
        """A step added before the attest or the upload could overwrite what's been checked."""
        for name, expected in JOB_STEPS.items():
            with self.subTest(job=name):
                self.assertEqual([step_label(s) for s in steps(job(self.lines, name))], expected)

    def test_nothing_chooses_other_bytes_or_other_rules(self) -> None:
        """Another commit, another repository, another run, an ignored digest or a shell's `-e`."""
        self.assertEqual([line for line in self.lines if FORBIDDEN_KEY.match(line)], [])

    def test_the_only_secret_is_the_runs_own_token_for_the_login(self) -> None:
        """A personal token in this job would outlive the run and reach further than it."""
        self.assertEqual([line for line in self.lines if "secrets." in line], [LOGIN_LINE])

    def test_every_shell_is_plain_bash(self) -> None:
        """Which GitHub runs with `-e` and `pipefail`. `bash {0}` would drop both."""
        shells = {line.strip() for line in self.lines if line.strip().startswith("shell:")}
        self.assertEqual(shells, {"shell: bash"})

    def test_the_builds_run_where_they_should(self) -> None:
        """A self-hosted build wouldn't be noticed: the attestation sees only `publish`'s runner."""
        self.assertIn("    runs-on: ubuntu-latest", job(self.lines, "build-linux"))
        self.assertIn("    runs-on: macos-26", job(self.lines, "build-macos"))

    def test_the_builds_are_held_exactly(self) -> None:
        """Locked, from the pinned toolchain, with nothing but the files coming out."""
        linux = steps(job(self.lines, "build-linux"))
        build = linux[step_index(linux, "docker/build-push-action@")]
        self.assertEqual(
            [build[0], *build[2:]],
            [
                "      - name: Build the static binaries",
                "        with:",
                "          context: .",
                "          target: binaries",
                "          platforms: linux/arm64,linux/amd64",
                "          outputs: type=local,dest=dist",
                "          provenance: false",
                "          sbom: false",
                "          push: false",
            ],
        )
        self.assertEqual(
            linux[step_index(linux, "check_binaries.py")],
            [
                "      - name: Check the static binaries",
                "        run: python3 -I .github/scripts/check_binaries.py dist",
            ],
        )
        macos = job(self.lines, "build-macos")
        self.assertIn(
            "      - run: cargo build --release --locked -p landfall-cli "
            "--target aarch64-apple-darwin",
            macos,
        )
        self.assertIn("      RUSTUP_TOOLCHAIN: 1.99.0", macos)
        self.assertIn("          path: target/aarch64-apple-darwin/release/landfall", macos)


if __name__ == "__main__":
    unittest.main()
