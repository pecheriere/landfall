"""Fail unless at least so many tests passed, by what `cargo test` printed.

A filter matching nothing passes, so a job selecting tests by name counts them. It goes by the
`test result:` lines, and not by a line for each test: libtest writes `test x ... ` and `ok`
separately, and what a test's child prints goes straight to the same stream, so that any of it can
land between the two. Removing or renaming a test means changing the number, which is the point.

This runs under `python3 -I`, which keeps a script's directory off the import path, so it stands
alone.

Usage: count_passed.py LOG MINIMUM
"""

import argparse
import re
import sys
from pathlib import Path

RESULT = re.compile(r"test result: ok\. (\d+) passed")


def passed(log: str) -> int:
    """How many tests the log's `test result:` lines say passed."""
    return sum(int(count) for count in RESULT.findall(log))


def main() -> int:
    """Check the log named on the command line, and say what it found."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("log", type=Path)
    parser.add_argument("minimum", type=int)
    args = parser.parse_args()

    count = passed(args.log.read_text(encoding="utf-8", errors="replace"))
    if count < args.minimum:
        print(f"{count} tests passed, and at least {args.minimum} should have", file=sys.stderr)
        return 1
    print(f"{count} tests passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
