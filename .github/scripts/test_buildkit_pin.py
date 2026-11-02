"""Every workflow's BuildKit is the one .github/buildkit/Dockerfile pins.

Dependabot can't read a workflow's `driver-opts`, so it bumps that Dockerfile and the
pull request fails here until the workflows follow. This also refuses the usual ways of
building round the pin. The standard library has no YAML parser, so a step is read by its
indentation, and whatever can't be read as the expected shape is a failure. It reads the
text of a workflow, so it can't see a builder chosen some way nobody wrote down here.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PIN_FILE = ROOT / ".github" / "buildkit" / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"
# These two must build through the pinned BuildKit; that the search finds them proves it works.
MUST_USE_BUILDX = ("ci.yml", "release.yml")

# GitHub ignores case in an action's name, so these do too.
BUILDX_STEP = re.compile(
    r"""^\s*(?:-\s+)?uses:\s*["']?docker/setup-buildx-action@""", re.IGNORECASE
)
BUILD_STEP = re.compile(r"""^\s*(?:-\s+)?uses:\s*["']?docker/build-push-action@""", re.IGNORECASE)
ANY_MENTION = re.compile(r"docker/(?:setup-buildx|build-push)-action", re.IGNORECASE)
# A build this file can't see the builder of: `docker build`, `docker buildx build`, `bake`,
# `create`. A job name such as docker-build doesn't match, as there is no space in it.
OWN_BUILDER = re.compile(r"\bdocker\s+(?:buildx\s+)?(?:build|bake|create)\b")
# Each would choose another builder or client than the pin.
REFUSED_BUILDX_INPUTS = ("version", "driver", "endpoint")
STEP_START = re.compile(r"^(\s*)-\s")
DIGEST_PINNED = re.compile(r"^moby/buildkit:v[0-9][^@\s]*@sha256:[0-9a-f]{64}$")

REFERENCE = "moby/buildkit:v1.2.3@sha256:" + "a" * 64


def indent_of(line: str) -> int:
    """Return how far a line is indented."""
    return len(line) - len(line.lstrip())


def significant(text: str) -> list[str]:
    """Return the lines of a YAML file that hold something."""
    return [
        line for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")
    ]


def step_at(lines: list[str], index: int) -> list[str]:
    """Return the lines of the step that holds the line at `index`."""
    start = index
    while start > 0 and not STEP_START.match(lines[start]):
        start -= 1
    step_indent = indent_of(lines[start])
    end = index + 1
    while end < len(lines) and indent_of(lines[end]) > step_indent:
        end += 1
    return lines[start:end]


def steps_matching(lines: list[str], pattern: re.Pattern[str]) -> list[list[str]]:
    """Return the lines of each step whose `uses:` matches."""
    return [step_at(lines, i) for i, line in enumerate(lines) if pattern.match(line)]


def buildx_steps(text: str) -> list[list[str]]:
    """Return the lines of each `docker/setup-buildx-action` step of a workflow."""
    return steps_matching(significant(text), BUILDX_STEP)


def jobs(lines: list[str]) -> list[list[str]]:
    """Split a workflow's lines by job. Without a `jobs:` key, all of them are one."""
    if "jobs:" not in lines:
        return [lines]
    body = lines[lines.index("jobs:") + 1 :]
    if not body:
        return []
    found: list[list[str]] = []
    for line in body:
        if indent_of(line) == indent_of(body[0]):
            found.append([])
        found[-1].append(line)
    return found


def with_block(step: list[str]) -> list[str]:
    """Return the lines under a step's own `with:`, so not those under its `env:`."""
    for index, line in enumerate(step):
        if line.strip() == "with:":
            block = []
            for following in step[index + 1 :]:
                if indent_of(following) <= indent_of(line):
                    break
                block.append(following)
            return block
    return []


def strip_comment(value: str) -> str:
    """Remove a trailing YAML comment and any surrounding quotes from a value."""
    return value.split(" #", 1)[0].strip().strip("\"'")


def step_input(step: list[str], name: str) -> str | None:
    """Return one `with:` input of a step, joining a block value's lines, or None if absent."""
    inputs = with_block(step)
    for index, line in enumerate(inputs):
        stripped = line.strip()
        if not stripped.startswith(f"{name}:"):
            continue
        value = strip_comment(stripped.removeprefix(f"{name}:"))
        if value not in {"|", ">", "|-", ">-"}:
            return value
        block = []
        for following in inputs[index + 1 :]:
            if indent_of(following) <= indent_of(line):
                break
            block.append(strip_comment(following))
        return "\n".join(block)
    return None


def buildx_step_problems(step: list[str], reference: str) -> list[str]:
    """Say what is wrong with one buildx step."""
    found = []
    options = step_input(step, "driver-opts")
    if options != f"image={reference}":
        found.append(f"driver-opts is {options!r}, wanted image={reference}")
    cache_binary = step_input(step, "cache-binary")
    if cache_binary != "false":
        found.append(f"cache-binary is {cache_binary!r}, wanted false")
    found.extend(
        f"{name} is set, which would not be the pinned builder"
        for name in REFUSED_BUILDX_INPUTS
        if step_input(step, name) is not None
    )
    return found


def job_build_problems(job: list[str]) -> list[str]:
    """Say which of a job's builds doesn't come after a buildx step, or names its own builder."""
    found = []
    seen_buildx = False
    for index, line in enumerate(job):
        seen_buildx = seen_buildx or bool(BUILDX_STEP.match(line))
        if not BUILD_STEP.match(line):
            continue
        if not seen_buildx:
            found.append("a build-push-action step has no setup-buildx-action before it in its job")
        if step_input(step_at(job, index), "builder") is not None:
            found.append("a build-push-action step names its own builder")
    return found


def problems(text: str, reference: str) -> list[str]:
    """Say what is wrong with a workflow's text."""
    lines = significant(text)
    found = [
        f"can't read this as a step: {line.strip()}"
        for line in lines
        if ANY_MENTION.search(line) and not BUILDX_STEP.match(line) and not BUILD_STEP.match(line)
    ]
    found.extend(
        f"builds outside the pinned builder: {line.strip()}"
        for line in lines
        if OWN_BUILDER.search(line)
    )
    for step in buildx_steps(text):
        found.extend(buildx_step_problems(step, reference))
    for job in jobs(lines):
        found.extend(job_build_problems(job))
    return found


def pinned_reference(dockerfile: str) -> str:
    """Return the image of the pin file's one `FROM` line."""
    references = re.findall(r"^FROM[ \t]+(\S+)[ \t]*$", dockerfile, re.MULTILINE)
    if len(references) != 1:
        message = f"expected one FROM line, found {references}"
        raise ValueError(message)
    return references[0]


class RepositoryTests(unittest.TestCase):
    """The repository's own files."""

    def test_buildkit_pin_is_the_same_everywhere(self) -> None:
        """Every buildx step in every workflow names the pin file's reference."""
        reference = pinned_reference(PIN_FILE.read_text(encoding="utf-8"))
        self.assertRegex(reference, DIGEST_PINNED)
        found = {}
        for workflow in sorted(WORKFLOWS.glob("*.y*ml")):
            text = workflow.read_text(encoding="utf-8")
            found[workflow.name] = len(buildx_steps(text))
            self.assertEqual(problems(text, reference), [], workflow.name)
        for name in MUST_USE_BUILDX:
            self.assertGreater(found[name], 0, f"{name} has no buildx step to check")


class ReadingTests(unittest.TestCase):
    """The reader above must fail on a workflow that doesn't pin, or the test proves nothing."""

    def test_a_pinned_step_passes(self) -> None:
        """Both inputs present and right."""
        text = f"""
steps:
  - uses: actions/checkout@abc # v1
  - uses: docker/setup-buildx-action@abc # v4
    with:
      driver-opts: image={REFERENCE}
      cache-binary: false
  - run: true
"""
        self.assertEqual(len(buildx_steps(text)), 1)
        self.assertEqual(problems(text, REFERENCE), [])

    def test_a_block_value_and_a_step_named_first_pass(self) -> None:
        """`driver-opts` is a list input, so a block is a fair way to write it."""
        text = f"""
steps:
  - name: Set up
    uses: docker/setup-buildx-action@abc
    with:
      cache-binary: "false"
      driver-opts: |
        image={REFERENCE}
"""
        self.assertEqual(problems(text, REFERENCE), [])

    def test_a_step_without_them_fails(self) -> None:
        """The state the workflows were in before the pin, with both inputs reported."""
        text = """
steps:
  - uses: docker/setup-buildx-action@abc # v4
  - uses: docker/build-push-action@abc
    with:
      driver-opts: this is another step's
      cache-binary: false
"""
        self.assertEqual(len(problems(text, REFERENCE)), 2)

    def test_a_different_image_fails(self) -> None:
        """A step a Dependabot bump left behind."""
        other = "moby/buildkit:v1.2.4@sha256:" + "b" * 64
        text = f"""
steps:
  - uses: docker/setup-buildx-action@abc
    with:
      driver-opts: image={other}
      cache-binary: false
"""
        self.assertEqual(len(problems(text, REFERENCE)), 1)

    def test_a_second_driver_option_fails(self) -> None:
        """Exactly the reference: another option could change what the builder is."""
        text = f"""
steps:
  - uses: docker/setup-buildx-action@abc
    with:
      driver-opts: |
        image={REFERENCE}
        network=host
      cache-binary: false
"""
        self.assertEqual(len(problems(text, REFERENCE)), 1)

    def test_cache_binary_left_on_fails(self) -> None:
        """A cached buildx client could reach the release build."""
        text = f"""
steps:
  - uses: docker/setup-buildx-action@abc
    with:
      driver-opts: image={REFERENCE}
      cache-binary: true
"""
        self.assertEqual(len(problems(text, REFERENCE)), 1)

    def test_each_of_several_steps_is_read(self) -> None:
        """A good first step doesn't excuse a later one, in another job."""
        text = f"""
jobs:
  one:
    steps:
      - uses: docker/setup-buildx-action@abc
        with:
          driver-opts: image={REFERENCE}
          cache-binary: false
  two:
    steps:
      - uses: docker/setup-buildx-action@abc
"""
        self.assertEqual(len(buildx_steps(text)), 2)
        self.assertEqual(len(problems(text, REFERENCE)), 2)

    def test_another_spelling_of_the_action_is_read(self) -> None:
        """GitHub ignores case in an action's name, so a change of case isn't a way round."""
        text = """
steps:
  - uses: Docker/Setup-Buildx-Action@abc
"""
        self.assertEqual(len(problems(text, REFERENCE)), 2)

    def test_a_flow_style_step_is_refused(self) -> None:
        """The reader can't read one, so it says so rather than pass it by."""
        text = "steps:\n  - {uses: docker/setup-buildx-action@abc}\n"
        self.assertIn("can't read this as a step", " ".join(problems(text, REFERENCE)))

    def test_inputs_outside_with_do_not_count(self) -> None:
        """An action only reads its `with:`, so the same lines under `env:` pin nothing."""
        text = f"""
steps:
  - uses: docker/setup-buildx-action@abc
    env:
      driver-opts: image={REFERENCE}
      cache-binary: false
"""
        self.assertEqual(len(problems(text, REFERENCE)), 2)

    def test_inputs_that_choose_another_builder_are_refused(self) -> None:
        """`version` would also download a client, which `cache-binary` only matters beside."""
        for name in ("version: latest", "driver: docker", "endpoint: tcp://elsewhere:1234"):
            with self.subTest(name=name):
                text = f"""
steps:
  - uses: docker/setup-buildx-action@abc
    with:
      driver-opts: image={REFERENCE}
      cache-binary: false
      {name}
"""
                self.assertEqual(len(problems(text, REFERENCE)), 1)

    def test_a_build_without_a_buildx_step_in_its_job_is_refused(self) -> None:
        """The one likeliest to happen by accident: it builds on whatever the runner has."""
        text = f"""
jobs:
  one:
    steps:
      - uses: docker/setup-buildx-action@abc
        with:
          driver-opts: image={REFERENCE}
          cache-binary: false
  two:
    steps:
      - uses: docker/build-push-action@abc
"""
        self.assertIn("no setup-buildx-action", " ".join(problems(text, REFERENCE)))

    def test_a_build_before_the_buildx_step_is_refused(self) -> None:
        """Steps run in order, so a pin set up afterwards doesn't reach it."""
        text = f"""
jobs:
  one:
    steps:
      - uses: docker/build-push-action@abc
      - uses: docker/setup-buildx-action@abc
        with:
          driver-opts: image={REFERENCE}
          cache-binary: false
"""
        self.assertIn("no setup-buildx-action", " ".join(problems(text, REFERENCE)))

    def test_a_build_after_the_buildx_step_passes(self) -> None:
        """What `ci.yml` and `release.yml` do."""
        text = f"""
jobs:
  one:
    steps:
      - uses: docker/setup-buildx-action@abc
        with:
          driver-opts: image={REFERENCE}
          cache-binary: false
      - uses: docker/build-push-action@abc
        with:
          context: .
"""
        self.assertEqual(problems(text, REFERENCE), [])

    def test_a_build_naming_its_own_builder_is_refused(self) -> None:
        """That is how a step would leave the pinned builder behind."""
        text = f"""
jobs:
  one:
    steps:
      - uses: docker/setup-buildx-action@abc
        with:
          driver-opts: image={REFERENCE}
          cache-binary: false
      - uses: docker/build-push-action@abc
        with:
          builder: other
"""
        self.assertIn("its own builder", " ".join(problems(text, REFERENCE)))

    def test_a_build_or_builder_in_a_run_step_is_refused(self) -> None:
        """None of these goes through the steps read above."""
        for command in ("docker build .", "docker buildx build .", "docker buildx create --use"):
            with self.subTest(command=command):
                text = f"steps:\n  - run: {command}\n"
                self.assertEqual(len(problems(text, REFERENCE)), 1)

    def test_a_job_called_docker_build_is_not_a_build(self) -> None:
        """`ci.yml` has one, and a run step can mention Docker."""
        text = "jobs:\n  docker-build:\n    steps:\n      - run: docker version\n"
        self.assertEqual(problems(text, REFERENCE), [])

    def test_two_from_lines_are_refused(self) -> None:
        """Which of two would be the pin isn't something to guess."""
        with self.assertRaises(ValueError):
            pinned_reference(f"FROM {REFERENCE}\nFROM {REFERENCE}\n")


if __name__ == "__main__":
    unittest.main()
