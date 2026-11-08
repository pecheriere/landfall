"""Propose a release's Homebrew formula to the tap, for `homebrew.yml`.

`check` runs with no secret. It refuses unless the run is on a tag that is `v` plus the workspace
version at that tag, with no prerelease suffix, and the release GitHub holds for it is published and
not a prerelease. It writes the version and tag to the output file, `$GITHUB_OUTPUT` in the
workflow.

`propose` runs with the tap's token. Through the GitHub API alone, with no checkout of the tap and
none of its code run, it makes a branch `landfall-<version>` from the tap's `main`, writes the
formula to `Formula/landfall.rb` on it, opens a pull request and asks GitHub to squash-merge it once
the tap's checks pass. The tap's own CI is what decides: it verifies the formula's attestation and
the signed tag against its own copy of the key. A branch or pull request that already exists means
an earlier run got there: it says so and stops, with success.

No value reaches a shell: `gh` gets argument lists, and every value from outside is checked against
a pattern first.

Usage:
  homebrew_tap.py check --tag TAG --release FILE --output FILE
  homebrew_tap.py propose --formula FILE --version VERSION --repo OWNER/NAME
"""

import argparse
import base64
import json
import re
import subprocess
import sys
import tomllib
from collections.abc import Callable, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# A release the tap takes: no prerelease suffix, as release candidates never reach `brew upgrade`.
STABLE_VERSION = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.+$)[A-Za-z0-9._-]+")
COMMIT = re.compile(r"[0-9a-f]{40}")
PULL_URL = re.compile(r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9._-]+/pull/[0-9]+")
TAP_NAME = "homebrew-tap"
FORMULA_PATH = "Formula/landfall.rb"
TAP_BASE = "main"
MAX_FORMULA_BYTES = 64 * 1024
COMMAND_TIMEOUT_SECONDS = 60
MAX_SHOWN = 200

Run = Callable[[Sequence[str]], subprocess.CompletedProcess]


class RefusedError(Exception):
    """The formula must not go to the tap, for the reason given."""


def shown(value: object) -> str:
    """Return a value safe to print on one line of a GitHub annotation, and not too long."""
    text = ascii(str(value))[1:-1]
    return text if len(text) <= MAX_SHOWN else f"{text[:MAX_SHOWN]}..."


def run_command(args: Sequence[str]) -> subprocess.CompletedProcess:
    """Run a command with an argument list, never a shell."""
    try:
        return subprocess.run(
            list(args), capture_output=True, text=True, check=False, timeout=COMMAND_TIMEOUT_SECONDS
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        msg = f"{args[0]} could not run: {shown(error)}"
        raise RefusedError(msg) from error


def output_of(run: Run, args: Sequence[str]) -> str:
    """Return what a command printed, refusing if it failed."""
    result = run(args)
    if result.returncode != 0:
        msg = f"`{' '.join(args[:4])} ...` failed: {shown(result.stderr.strip())}"
        raise RefusedError(msg)
    return result.stdout


def json_of(run: Run, args: Sequence[str]) -> object:
    """Return a command's JSON answer."""
    text = output_of(run, args)
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        msg = f"`{' '.join(args[:4])} ...` didn't answer JSON: {shown(error)}"
        raise RefusedError(msg) from error


def workspace_version(root: Path) -> str:
    """Return `workspace.package.version` in the checkout's `Cargo.toml`."""
    try:
        with (root / "Cargo.toml").open("rb") as file:
            version = tomllib.load(file)["workspace"]["package"]["version"]
    except (OSError, ValueError, KeyError, TypeError) as error:
        msg = f"Cargo.toml has no readable workspace.package.version: {shown(error)}"
        raise RefusedError(msg) from error
    if not isinstance(version, str):
        msg = f"Cargo.toml's version isn't a string: {shown(version)}"
        raise RefusedError(msg)
    return version


def check(tag: str, release: object, root: Path) -> str:
    """Return the version this tag releases to the tap, or refuse."""
    version = tag.removeprefix("v")
    if not tag.startswith("v") or not STABLE_VERSION.fullmatch(version):
        msg = f"{shown(tag)} isn't the tag of a stable release, which is all the tap takes"
        raise RefusedError(msg)
    found = workspace_version(root)
    if found != version:
        msg = f"the tag {tag} isn't v plus the workspace version at it, {shown(found)}"
        raise RefusedError(msg)
    if not isinstance(release, dict) or release.get("tagName") != tag:
        msg = f"GitHub's release for {tag} isn't one for that tag"
        raise RefusedError(msg)
    if release.get("isDraft") is not False or release.get("isPrerelease") is not False:
        msg = f"the release at {tag} is a draft or a prerelease, which the tap never takes"
        raise RefusedError(msg)
    return version


def tap_of(repo: str) -> str:
    """Return the tap shared by this owner's projects."""
    if not REPOSITORY.fullmatch(repo):
        msg = f"{shown(repo)} is not a repository as owner/name"
        raise RefusedError(msg)
    return f"{repo.split('/', 1)[0]}/{TAP_NAME}"


def read_formula(path: Path) -> bytes:
    """Return the formula's bytes, which must be small text that names a Landfall formula."""
    content = path.read_bytes()
    if len(content) > MAX_FORMULA_BYTES or not content.startswith(b"class Landfall < Formula\n"):
        msg = f"{path} isn't landfall's formula"
        raise RefusedError(msg)
    return content


def existing(run: Run, tap: str, branch: str) -> str | None:
    """Say what an earlier run left for this branch, a pull request or the branch, if anything."""
    pulls = json_of(
        run,
        ["gh", "pr", "list", "--repo", tap, "--head", branch, "--state", "all", "--json", "url"],
    )
    if not isinstance(pulls, list):
        msg = "GitHub's list of pull requests isn't one"
        raise RefusedError(msg)
    if pulls:
        first = pulls[0].get("url") if isinstance(pulls[0], dict) else pulls[0]
        return f"a pull request for {branch} already exists: {shown(first)}"
    refs = json_of(run, ["gh", "api", f"repos/{tap}/git/matching-refs/heads/{branch}"])
    if not isinstance(refs, list):
        msg = "GitHub's list of refs isn't one"
        raise RefusedError(msg)
    if any(isinstance(ref, dict) and ref.get("ref") == f"refs/heads/{branch}" for ref in refs):
        return f"the branch {branch} already exists in {tap}, with no pull request"
    return None


def base_commit(run: Run, tap: str) -> str:
    """Return the commit the tap's main points at."""
    answer = json_of(run, ["gh", "api", f"repos/{tap}/git/ref/heads/{TAP_BASE}"])
    sha = answer.get("object", {}).get("sha") if isinstance(answer, dict) else None
    if not isinstance(sha, str) or not COMMIT.fullmatch(sha):
        msg = f"the tap's {TAP_BASE} isn't a commit: {shown(sha)}"
        raise RefusedError(msg)
    return sha


def formula_blob(run: Run, tap: str, commit: str) -> str | None:
    """Return the blob the formula is at that commit, as the contents API wants it, or None."""
    answer = json_of(run, ["gh", "api", f"repos/{tap}/git/trees/{commit}?recursive=1"])
    if not isinstance(answer, dict) or answer.get("truncated") is not False:
        msg = "the tap's tree couldn't be read whole"
        raise RefusedError(msg)
    for entry in answer.get("tree", []):
        if isinstance(entry, dict) and entry.get("path") == FORMULA_PATH:
            sha = entry.get("sha")
            if entry.get("type") != "blob" or not isinstance(sha, str) or not COMMIT.fullmatch(sha):
                msg = f"{FORMULA_PATH} in the tap isn't a file"
                raise RefusedError(msg)
            return sha
    return None


def propose(formula: bytes, version: str, repo: str, run: Run) -> str:
    """Open the tap's pull request for this formula, or say what an earlier run left."""
    if not STABLE_VERSION.fullmatch(version):
        msg = f"{shown(version)} isn't a stable version"
        raise RefusedError(msg)
    tap = tap_of(repo)
    branch = f"landfall-{version}"
    earlier = existing(run, tap, branch)
    if earlier is not None:
        return f"Nothing to do: {earlier}."
    commit = base_commit(run, tap)
    blob = formula_blob(run, tap, commit)
    output_of(
        run,
        [
            "gh",
            "api",
            "--method",
            "POST",
            f"repos/{tap}/git/refs",
            "-f",
            f"ref=refs/heads/{branch}",
            "-f",
            f"sha={commit}",
        ],
    )
    put = [
        "gh",
        "api",
        "--method",
        "PUT",
        f"repos/{tap}/contents/{FORMULA_PATH}",
        "-f",
        f"message=landfall {version}",
        "-f",
        f"content={base64.b64encode(formula).decode('ascii')}",
        "-f",
        f"branch={branch}",
    ]
    output_of(run, [*put, "-f", f"sha={blob}"] if blob is not None else put)
    release = f"https://github.com/{repo}/releases/tag/v{version}"
    url = output_of(
        run,
        [
            "gh",
            "pr",
            "create",
            "--repo",
            tap,
            "--base",
            TAP_BASE,
            "--head",
            branch,
            "--title",
            f"landfall {version}",
            "--body",
            (
                f"The formula attached to {release}, whose attestation landfall's Homebrew "
                "workflow verified. The tap's checks verify it again, and the release's signed "
                "tag against the tap's own copy of the key, before this merges."
            ),
        ],
    ).strip()
    if not PULL_URL.fullmatch(url):
        msg = f"gh pr create didn't print a pull request's URL: {shown(url)}"
        raise RefusedError(msg)
    output_of(run, ["gh", "pr", "merge", url, "--repo", tap, "--auto", "--squash"])
    return f"Opened {url}, to merge once the tap's checks pass."


def main(argv: list[str] | None = None) -> int:
    """Run one subcommand. Print a refusal as a GitHub annotation, and return 1 for it."""
    parser = argparse.ArgumentParser(description="Propose a release's formula to the tap.")
    commands = parser.add_subparsers(dest="command", required=True)
    checking = commands.add_parser("check")
    checking.add_argument("--tag", required=True)
    checking.add_argument("--release", required=True, type=Path, help="gh release view's JSON")
    checking.add_argument("--output", required=True, type=Path)
    proposing = commands.add_parser("propose")
    proposing.add_argument("--formula", required=True, type=Path)
    proposing.add_argument("--version", required=True)
    proposing.add_argument("--repo", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "check":
            version = check(args.tag, json.loads(args.release.read_text(encoding="utf-8")), ROOT)
            with args.output.open("a", encoding="utf-8") as output:
                output.write(f"version={version}\n")
            print(f"{args.tag} is a stable release of {version}.")
        else:
            print(propose(read_formula(args.formula), args.version, args.repo, run_command))
    except RefusedError as refusal:
        print(f"::error title=Homebrew::{refusal}")
        return 1
    except (OSError, json.JSONDecodeError) as error:
        print(f"::error title=Homebrew::{shown(error)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
