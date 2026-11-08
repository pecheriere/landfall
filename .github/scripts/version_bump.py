"""Say whether a push to main changed the workspace's version, for the release dry run.

A commit that bumps `workspace.package.version` is one the owner is about to tag, so the release
workflow builds it in full on the push, and the owner tags a commit that already passed. Every
other push to main skips the build. Appends `build=true` or `build=false` to the output file, which
is `$GITHUB_OUTPUT` in the workflow.

It compares the version in `Cargo.toml` at the commit before the push with the one in the checkout.
Anything it can't read fails the job, rather than skipping a build that might have been wanted.
No value reaches a shell: `git` gets an argument list, and the commit was checked against a
pattern first.

Usage: version_bump.py --before COMMIT --output FILE
"""

import argparse
import re
import subprocess
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMMIT = re.compile(r"[0-9a-f]{40}")
COMMAND_TIMEOUT_SECONDS = 60
MAX_SHOWN = 200


class RefusedError(Exception):
    """The versions could not be compared, for the reason given."""


def shown(value: object) -> str:
    """Return a value safe to print on one line of a GitHub annotation, and not too long."""
    text = ascii(str(value))[1:-1]
    return text if len(text) <= MAX_SHOWN else f"{text[:MAX_SHOWN]}..."


def version_of(text: str, where: str) -> str:
    """Return `workspace.package.version` from a `Cargo.toml`'s text."""
    try:
        version = tomllib.loads(text)["workspace"]["package"]["version"]
    except (tomllib.TOMLDecodeError, KeyError, TypeError) as error:
        msg = f"Cargo.toml at {where} has no readable workspace.package.version: {shown(error)}"
        raise RefusedError(msg) from error
    if not isinstance(version, str):
        msg = f"Cargo.toml at {where} has a version that isn't a string: {shown(version)}"
        raise RefusedError(msg)
    return version


def manifest_at(commit: str, root: Path) -> str:
    """Return `Cargo.toml` as it was at a commit."""
    if not COMMIT.fullmatch(commit):
        msg = f"{shown(commit)} is not a full commit id"
        raise RefusedError(msg)
    try:
        result = subprocess.run(
            ["git", "show", f"{commit}:Cargo.toml"],
            capture_output=True,
            text=True,
            check=False,
            timeout=COMMAND_TIMEOUT_SECONDS,
            cwd=root,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        msg = f"git could not run: {shown(error)}"
        raise RefusedError(msg) from error
    if result.returncode != 0:
        msg = f"git could not read Cargo.toml at {commit}: {shown(result.stderr.strip())}"
        raise RefusedError(msg)
    return result.stdout


def changed(before: str, after: str) -> bool:
    """Return whether the two manifests' workspace versions differ."""
    return version_of(before, "the commit before") != version_of(after, "this commit")


def main(argv: list[str] | None = None) -> int:
    """Append the answer to the output file, or print a refusal as a GitHub annotation."""
    parser = argparse.ArgumentParser(description="Did this push change the version?")
    parser.add_argument("--before", required=True, help="the commit main pointed at before")
    parser.add_argument("--output", required=True, type=Path, help="where to append the answer")
    args = parser.parse_args(argv)
    try:
        before = manifest_at(args.before, ROOT)
        after = (ROOT / "Cargo.toml").read_text(encoding="utf-8")
        build = changed(before, after)
        with args.output.open("a", encoding="utf-8") as output:
            output.write(f"build={'true' if build else 'false'}\n")
    except RefusedError as refusal:
        print(f"::error title=Release dry run::{refusal}")
        return 1
    except OSError as error:
        print(f"::error title=Release dry run::{shown(error)}")
        return 1
    print("The version changed: building in full." if build else "The version is unchanged.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
