"""Assemble the files of a release, and check an attestation's shape against them.

`assemble` gathers what the build jobs produced under the exact names a release has, which are the
names the CLI asks for and the attestation vouches for, and writes `SHA256SUMS` and the Homebrew
formula beside them. It starts on nothing but a complete set of inputs and an empty directory,
because the workflow attests every file it finds there.

`check-bundle` reads a bundle's shape only. **It checks no signature and no identity**: `gh
attestation verify` does that, next, and this is here so that a bundle the verifier could never
accept, or one that doesn't cover exactly these files, fails with a sentence before anything is
public.

This runs under `python3 -I`, which keeps a script's directory off the import path, so it stands
alone. `test_release_scripts_run.py` keeps what it shares with `release_preflight.py` equal.

Usage:
    assemble_release.py assemble --dist DIR --macos DIR --version V --repo OWNER/NAME --out DIR
    assemble_release.py check-bundle --bundle FILE --out DIR
"""

import argparse
import base64
import hashlib
import json
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]

# What may reach a file name, a URL and a Ruby string. SemVer with no build metadata, in ASCII.
VERSION = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9]*[A-Za-z-][0-9A-Za-z-]*))*)?"
)
REPOSITORY = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]*/(?!\.+$)[A-Za-z0-9._-]+")

BINARY_MODE = 0o755
TEXT_MODE = 0o644
LICENCES = ("LICENSE-MIT", "LICENSE-APACHE")
SUMS = "SHA256SUMS"
FORMULA = "landfall.rb"

# The same limit as `MAX_BUNDLE_BYTES` in `landfall-origin`.
MAX_BUNDLE_BYTES = 4 * 1024 * 1024
BUNDLE_MEDIA_TYPE = "application/vnd.dev.sigstore.bundle.v0.3+json"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
SLSA_PROVENANCE = "https://slsa.dev/provenance/v1"

MAX_SHOWN = 200

FORMULA_TEMPLATE = """\
class Landfall < Formula
  desc "Continuous delivery for self-hosters"
  homepage "https://github.com/{repo}"
  version "{version}"
  license any_of: ["MIT", "Apache-2.0"]

  on_macos do
    depends_on arch: :arm64
    url "{base}/{darwin_arm64}"
    sha256 "{darwin_arm64_sha256}"
  end

  on_linux do
    on_arm do
      url "{base}/{linux_arm64}"
      sha256 "{linux_arm64_sha256}"
    end
    on_intel do
      url "{base}/{linux_amd64}"
      sha256 "{linux_amd64_sha256}"
    end
  end

  def install
    bin.install Dir["landfall-*"].first => "landfall"
  end

  test do
    assert_match version.to_s, shell_output("#{{bin}}/landfall --version")
  end
end
"""


class RefusedError(Exception):
    """A file must not be published, for the reason given."""


def shown(value: object) -> str:
    """Return a value safe to print on one line of a GitHub annotation, and not too long."""
    text = ascii(str(value))[1:-1]
    return text if len(text) <= MAX_SHOWN else f"{text[:MAX_SHOWN]}..."


@dataclass(frozen=True)
class Release:
    """A version and the repository it comes from, both checked."""

    version: str
    repo: str

    def __post_init__(self) -> None:
        """Refuse anything that couldn't safely become part of a name, a URL or a formula."""
        if not VERSION.fullmatch(self.version):
            msg = f"{shown(self.version)} is not a version a release can have"
            raise RefusedError(msg)
        if not REPOSITORY.fullmatch(self.repo):
            msg = f"{shown(self.repo)} is not a repository as owner/name"
            raise RefusedError(msg)

    def binary(self, program: str, platform: str) -> str:
        """Return a binary's name in the release."""
        return f"{program}-{self.version}-{platform}"


def sha256_of(path: Path) -> str:
    """Return a file's SHA-256 in hex."""
    with path.open("rb") as file:
        return hashlib.file_digest(file, "sha256").hexdigest()


def binary_sources(dist: Path, macos: Path, release: Release) -> dict[str, tuple[Path, Path]]:
    """Map each binary's name in the release to a build job's directory and a path in it."""
    sources = {
        release.binary("landfall", "darwin-arm64"): (macos, Path("landfall")),
    }
    for directory, platform in (("linux_arm64", "linux-arm64"), ("linux_amd64", "linux-amd64")):
        for program in ("landfall-agent", "landfall"):
            sources[release.binary(program, platform)] = (dist, Path(directory, program))
    return sources


def check_input(base: Path, relative: Path) -> None:
    """Refuse an input that isn't a file with something in it, or is reached through a link."""
    path = base
    for part in ("", *relative.parts):
        path = path / part
        if path.is_symlink():
            msg = f"{shown(path)} is a link, not a regular file or a directory"
            raise RefusedError(msg)
    if not path.exists():
        msg = f"{shown(path)} is missing"
        raise RefusedError(msg)
    if not path.is_file():
        msg = f"{shown(path)} is not a regular file"
        raise RefusedError(msg)
    if path.stat().st_size == 0:
        msg = f"{shown(path)} is empty"
        raise RefusedError(msg)


def prepare_output(out: Path) -> None:
    """Make the output directory, which must hold nothing: all it holds gets attested."""
    if out.is_symlink():
        msg = f"{shown(out)} is a link, and files written through it would land elsewhere"
        raise RefusedError(msg)
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        msg = f"{shown(out)} is not empty, and everything in it would be attested"
        raise RefusedError(msg)


def write_text(path: Path, text: str) -> None:
    """Write a generated file, with its mode whatever the umask."""
    path.write_text(text, encoding="utf-8", newline="\n")
    path.chmod(TEXT_MODE)


def formula(release: Release, out: Path) -> str:
    """Return the Homebrew formula, pinning each platform's file by URL and hash."""
    names = {
        "darwin_arm64": release.binary("landfall", "darwin-arm64"),
        "linux_arm64": release.binary("landfall", "linux-arm64"),
        "linux_amd64": release.binary("landfall", "linux-amd64"),
    }
    hashes = {f"{key}_sha256": sha256_of(out / name) for key, name in names.items()}
    base = f"https://github.com/{release.repo}/releases/download/v{release.version}"
    return FORMULA_TEMPLATE.format(
        repo=release.repo, version=release.version, base=base, **names, **hashes
    )


def sums(out: Path) -> str:
    """Return `SHA256SUMS` for what's in the directory, sorted by name."""
    return "".join(f"{sha256_of(path)}  {path.name}\n" for path in sorted(out.iterdir()))


def assemble(dist: Path, macos: Path, release: Release, out: Path, root: Path) -> None:
    """Write a release's files. All the inputs are checked before anything is written."""
    sources = binary_sources(dist, macos, release)
    for base, relative in sources.values():
        check_input(base, relative)
    for name in LICENCES:
        check_input(root, Path(name))
    prepare_output(out)
    for name, (base, relative) in sources.items():
        shutil.copyfile(base / relative, out / name)
        (out / name).chmod(BINARY_MODE)
    for name in LICENCES:
        shutil.copyfile(root / name, out / name)
        (out / name).chmod(TEXT_MODE)
    write_text(out / FORMULA, formula(release, out))
    # Last, because it covers the formula, and sums() would list itself if it already existed.
    write_text(out / SUMS, sums(out))


def refuse_repeats(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    """Build an object, refusing a repeated key: two readers can take different ones."""
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            msg = f"repeated key {shown(key)}"
            raise ValueError(msg)
        result[key] = value
    return result


def refuse_constant(name: str) -> None:
    """Refuse NaN and Infinity, which aren't JSON."""
    msg = f"{name} is not JSON"
    raise ValueError(msg)


def strict_json(raw: bytes, what: str) -> dict[str, Any]:
    """Parse a JSON object, refusing what a stricter reader wouldn't take."""
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=refuse_repeats,
            parse_constant=refuse_constant,
        )
    except (ValueError, RecursionError) as error:
        msg = f"{what} is not valid: {shown(error)}"
        raise RefusedError(msg) from error
    if not isinstance(value, dict):
        msg = f"{what} is not an object"
        raise RefusedError(msg)
    return value


def section(parent: dict[str, Any], key: str, what: str) -> dict[str, Any]:
    """Return a part of a document that must be a non-empty object."""
    value = parent.get(key)
    if not isinstance(value, dict) or not value:
        msg = f"{what} has no {key}"
        raise RefusedError(msg)
    return value


def read_bundle(path: Path) -> dict[str, Any]:
    """Read a bundle: one JSON line and an end of line, within the verifier's limit."""
    try:
        with path.open("rb") as file:
            raw = file.read(MAX_BUNDLE_BYTES + 1)
    except OSError as error:
        msg = f"the bundle {shown(path)} could not be read: {shown(error.strerror)}"
        raise RefusedError(msg) from error
    if len(raw) > MAX_BUNDLE_BYTES:
        msg = f"the bundle is more than the {MAX_BUNDLE_BYTES} bytes accepted"
        raise RefusedError(msg)
    if not raw.endswith(b"\n") or raw.count(b"\n") != 1:
        msg = "the bundle is not one JSON line and an end of line"
        raise RefusedError(msg)
    return strict_json(raw, "the bundle")


def check_shape(bundle: dict[str, Any]) -> None:
    """Check what the verifier will want of a bundle, other than its statement."""
    if bundle.get("mediaType") != BUNDLE_MEDIA_TYPE:
        msg = f"the bundle has media type {shown(bundle.get('mediaType'))}, and only v0.3 will do"
        raise RefusedError(msg)
    material = section(bundle, "verificationMaterial", "the bundle")
    entries = material.get("tlogEntries")
    if not isinstance(entries, list) or len(entries) != 1:
        count = len(entries) if isinstance(entries, list) else 0
        msg = f"the bundle has {count} tlog entries, where it needs exactly one"
        raise RefusedError(msg)
    if not isinstance(entries[0], dict):
        msg = "the bundle's tlog entry is not an object"
        raise RefusedError(msg)
    section(entries[0], "inclusionProof", "the bundle's tlog entry")
    section(entries[0], "inclusionPromise", "the bundle's tlog entry")


def read_statement(bundle: dict[str, Any]) -> dict[str, Any]:
    """Return the statement in a bundle's envelope, wanting provenance."""
    envelope = section(bundle, "dsseEnvelope", "the bundle")
    if envelope.get("payloadType") != DSSE_PAYLOAD_TYPE:
        msg = f"the envelope has payload type {shown(envelope.get('payloadType'))}"
        raise RefusedError(msg)
    payload = envelope.get("payload")
    if not isinstance(payload, str):
        msg = "the envelope has no payload"
        raise RefusedError(msg)
    try:
        raw = base64.b64decode(payload, validate=True)
    except ValueError as error:
        msg = "the envelope's payload is not base64"
        raise RefusedError(msg) from error
    statement = strict_json(raw, "the statement")
    if statement.get("_type") != STATEMENT_TYPE:
        msg = f"the statement has type {shown(statement.get('_type'))}"
        raise RefusedError(msg)
    if statement.get("predicateType") != SLSA_PROVENANCE:
        msg = (
            f"the statement has predicate type {shown(statement.get('predicateType'))}, "
            f"not {SLSA_PROVENANCE}"
        )
        raise RefusedError(msg)
    return statement


def named_subject(subject: object) -> tuple[str, str]:
    """Return one subject's name and digest, which must be a sha256 and nothing else."""
    if not isinstance(subject, dict) or not isinstance(subject.get("name"), str):
        msg = "the statement has a subject with no name"
        raise RefusedError(msg)
    name = subject["name"]
    digest = subject.get("digest")
    if (
        not isinstance(digest, dict)
        or set(digest) != {"sha256"}
        or not isinstance(digest["sha256"], str)
    ):
        msg = f"the subject {shown(name)} does not have one sha256 digest"
        raise RefusedError(msg)
    return name, digest["sha256"]


def subject_digests(statement: dict[str, Any]) -> dict[str, str]:
    """Return a statement's subjects by name, refusing a name given twice."""
    subjects = statement.get("subject")
    if not isinstance(subjects, list):
        msg = "the statement has no list of subjects"
        raise RefusedError(msg)
    digests: dict[str, str] = {}
    for subject in subjects:
        name, digest = named_subject(subject)
        if name in digests:
            msg = f"the statement names the subject {shown(name)} twice"
            raise RefusedError(msg)
        digests[name] = digest
    return digests


def file_digests(directory: Path) -> dict[str, str]:
    """Return the digest of each file directly in a directory, which holds nothing else."""
    try:
        entries = sorted(directory.iterdir())
    except OSError as error:
        msg = f"{shown(directory)} could not be read: {shown(error.strerror)}"
        raise RefusedError(msg) from error
    if not entries:
        msg = f"{shown(directory)} holds no files"
        raise RefusedError(msg)
    for entry in entries:
        if entry.is_symlink() or not entry.is_file():
            msg = f"{shown(entry)} is not a regular file"
            raise RefusedError(msg)
    return {entry.name: sha256_of(entry) for entry in entries}


def listed(names: set[str]) -> str:
    """Return names for a message, safe and in a stable order."""
    return shown(", ".join(sorted(names)))


def check_subjects(subjects: dict[str, str], files: dict[str, str]) -> None:
    """Want the subjects to be exactly these files, by basename and digest."""
    missing = files.keys() - subjects.keys()
    if missing:
        msg = f"the statement does not name: {listed(set(missing))}"
        raise RefusedError(msg)
    extra = subjects.keys() - files.keys()
    if extra:
        msg = f"the statement names what is not here: {listed(set(extra))}"
        raise RefusedError(msg)
    wrong = {name for name, digest in files.items() if subjects[name] != digest}
    if wrong:
        msg = f"the statement has the wrong digest for: {listed(wrong)}"
        raise RefusedError(msg)


def check_bundle(bundle_path: Path, out: Path) -> None:
    """Check a bundle's shape against a directory. This checks no signature and no identity."""
    files = file_digests(out)
    bundle = read_bundle(bundle_path)
    check_shape(bundle)
    check_subjects(subject_digests(read_statement(bundle)), files)


def parse_arguments(argv: list[str] | None) -> argparse.Namespace:
    """Read the command line."""
    parser = argparse.ArgumentParser(description="Assemble a release's files, or check a bundle.")
    commands = parser.add_subparsers(dest="command", required=True)
    assembling = commands.add_parser("assemble", help="write a release's files")
    assembling.add_argument("--dist", type=Path, required=True, help="the Linux build's output")
    assembling.add_argument("--macos", type=Path, required=True, help="holds the macOS `landfall`")
    assembling.add_argument("--version", required=True, help="the version, with no leading v")
    assembling.add_argument("--repo", required=True, help="owner/name")
    assembling.add_argument("--out", type=Path, required=True, help="an empty or new directory")
    checking = commands.add_parser("check-bundle", help="check a bundle's shape, not its signature")
    checking.add_argument("--bundle", type=Path, required=True, help="the Sigstore bundle")
    checking.add_argument("--out", type=Path, required=True, help="the files it should name")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    """Run a command. Print a refusal as a GitHub annotation, and return 1 for it."""
    args = parse_arguments(argv)
    try:
        if args.command == "assemble":
            release = Release(args.version, args.repo)
            assemble(args.dist, args.macos, release, args.out, ROOT)
        else:
            check_bundle(args.bundle, args.out)
    except RefusedError as refusal:
        print(f"::error title=Release files::{refusal}")
        return 1
    except OSError as error:
        print(f"::error title=Release files::{shown(error)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
