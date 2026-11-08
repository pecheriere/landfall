"""Read a workflow's jobs and steps from its text, for the tests that hold what a workflow does.

The standard library has no YAML parser, so jobs and steps are read by their indentation, and
anything that isn't the expected shape fails. `test_workflow_text.py` checks the reader itself.
"""

import re

JOB_INDENT = 2
STEP_INDENT = 6
USES = re.compile(r"\s*(?:- )?uses: ([^@\s]+)")
NAME = re.compile(r"\s*(?:- )?name: (.+)")


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


def job_names(lines: list[str]) -> set[str]:
    """Return the names of every job."""
    start = lines.index("jobs:") + 1
    return {
        line.strip().removesuffix(":") for line in lines[start:] if indent_of(line) == JOB_INDENT
    }


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


def needs_of(job_lines: list[str]) -> set[str]:
    """Return the jobs a job names in `needs`, in either form, or none."""
    prefix = f"{' ' * (STEP_INDENT - 2)}needs:"
    line = next((line for line in job_lines if line.startswith(prefix)), None)
    if line is None:
        return set()
    value = line.removeprefix(prefix).strip()
    if not value:
        return {item.removeprefix("- ") for item in block(job_lines, "needs")}
    return {item.strip() for item in value.strip("[]").split(",")}


def needed(lines: list[str], name: str) -> set[str]:
    """Return every job a job waits for, directly or through another."""
    found: set[str] = set()
    pending = [name]
    while pending:
        for other in needs_of(job(lines, pending.pop())) - found:
            found.add(other)
            pending.append(other)
    return found


def step_label(step: list[str]) -> str:
    """Return what a step is: its action without the pin, its name, or else its command."""
    for pattern in (USES, NAME):
        for line in step:
            found = pattern.match(line)
            if found:
                return found.group(1)
    return step[0].strip().removeprefix("- run: ")


def step_index(step_list: list[list[str]], piece: str) -> int:
    """Return the index of the one step holding this text."""
    matching = [i for i, step in enumerate(step_list) if piece in "\n".join(step)]
    if len(matching) != 1:
        message = f"{piece!r} is in {len(matching)} steps, where one was wanted"
        raise AssertionError(message)
    return matching[0]
