"""Every workflow's BuildKit is the one .github/buildkit/Dockerfile pins.

Dependabot can't read a workflow's `driver-opts`, so it bumps that Dockerfile and the
pull request fails here until the workflows follow. The standard library has no YAML
parser, so a step is read by its indentation, and whatever can't be read as the expected
shape is a failure.
"""

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent.parent
PIN_FILE = ROOT / ".github" / "buildkit" / "Dockerfile"
WORKFLOWS = ROOT / ".github" / "workflows"
# These two must build through the pinned BuildKit; that the search finds them proves it works.
MUST_USE_BUILDX = ("ci.yml", "release.yml")

BUILDX_STEP = re.compile(r"""^\s*(?:-\s+)?uses:\s*["']?docker/setup-buildx-action@""")
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


def buildx_steps(text: str) -> list[list[str]]:
    """Return the lines of each `docker/setup-buildx-action` step of a workflow."""
    lines = significant(text)
    steps = []
    for index, line in enumerate(lines):
        if not BUILDX_STEP.match(line):
            continue
        start = index
        while start > 0 and not STEP_START.match(lines[start]):
            start -= 1
        step_indent = indent_of(lines[start])
        end = index + 1
        while end < len(lines) and indent_of(lines[end]) > step_indent:
            end += 1
        steps.append(lines[start:end])
    return steps


def strip_comment(value: str) -> str:
    """Remove a trailing YAML comment and any surrounding quotes from a value."""
    return value.split(" #", 1)[0].strip().strip("\"'")


def step_input(step: list[str], name: str) -> str | None:
    """Return one `with:` input of a step, joining a block value's lines, or None if absent."""
    for index, line in enumerate(step):
        stripped = line.strip()
        if not stripped.startswith(f"{name}:"):
            continue
        value = strip_comment(stripped.removeprefix(f"{name}:"))
        if value not in {"|", ">", "|-", ">-"}:
            return value
        block = []
        for following in step[index + 1 :]:
            if indent_of(following) <= indent_of(line):
                break
            block.append(strip_comment(following))
        return "\n".join(block)
    return None


def problems(text: str, reference: str) -> list[str]:
    """Say what is wrong with each buildx step of a workflow's text."""
    found = []
    for step in buildx_steps(text):
        options = step_input(step, "driver-opts")
        if options != f"image={reference}":
            found.append(f"driver-opts is {options!r}, wanted image={reference}")
        cache_binary = step_input(step, "cache-binary")
        if cache_binary != "false":
            found.append(f"cache-binary is {cache_binary!r}, wanted false")
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

    def test_two_from_lines_are_refused(self) -> None:
        """Which of two would be the pin isn't something to guess."""
        with self.assertRaises(ValueError):
            pinned_reference(f"FROM {REFERENCE}\nFROM {REFERENCE}\n")


if __name__ == "__main__":
    unittest.main()
