"""Fail if the Dockerfile's `binaries` stage produced anything but what a host can run.

For each binary, on each Linux platform: it is an ELF for the architecture its directory
names, it needs no loader (no PT_INTERP, so it is static), every load segment on arm64 suits
a kernel with 16 KiB pages (which won't load one aligned to less, and fails only there), and
it is within its size budget. A file nobody expected, or one missing, also fails, so that a
build producing nothing can't pass for lack of anything to check.

The headers are read here, in the standard library, so the check doesn't depend on which
`readelf` a machine has, and it trusts nothing they say.

Usage: check_binaries.py DIST
"""

import argparse
import struct
import sys
from pathlib import Path

MIB = 1024 * 1024

# Each is the larger platform's measured size (amd64, on 2026-11-02) times 1.25, rounded up to a
# MiB. Raising one is a decision: find out what grew first. A budget per name, because the server
# is meant to be larger than the agent.
MAX_BYTES = {
    "landfall-agent": 15 * MIB,  # 12515680 bytes
    "landfall": 12 * MIB,  # 9991464 bytes
    "landfall-server": 19 * MIB,  # 15246880 bytes
}

# e_machine for the directories `docker buildx --output type=local` writes.
MACHINES = {"linux_arm64": 0xB7, "linux_amd64": 0x3E}
ARM64_DIRECTORY = "linux_arm64"
MIN_ARM64_ALIGN = 0x4000

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
PT_LOAD = 1
PT_INTERP = 3

# Offsets within the ELF64 header, and the shape of one program header.
ELF_HEADER_SIZE = 64
EI_CLASS = 4
EI_DATA = 5
E_MACHINE = struct.Struct("<H")
E_MACHINE_OFFSET = 18
E_PHOFF = struct.Struct("<Q")
E_PHOFF_OFFSET = 32
E_PHENTSIZE_PHNUM = struct.Struct("<HH")
E_PHENTSIZE_OFFSET = 54
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")


def check_segments(table: bytes, *, needs_16k_pages: bool) -> list[str]:
    """Check a binary's program header table, with one failure for each kind of fault."""
    types_and_aligns = [
        (p_type, p_align) for p_type, _, _, _, _, _, _, p_align in PROGRAM_HEADER.iter_unpack(table)
    ]
    load_aligns = [p_align for p_type, p_align in types_and_aligns if p_type == PT_LOAD]
    failures = []
    if any(p_type == PT_INTERP for p_type, _ in types_and_aligns):
        failures.append("has PT_INTERP, so it needs a loader and is not static")
    if not load_aligns:
        failures.append("has no PT_LOAD segment")
    elif needs_16k_pages and min(load_aligns) < MIN_ARM64_ALIGN:
        failures.append(
            f"has a PT_LOAD with p_align {min(load_aligns):#x}, below the {MIN_ARM64_ALIGN:#x} "
            "a kernel with 16 KiB pages needs"
        )
    return failures


def identity_failure(header: bytes) -> str | None:
    """Say why a file's first bytes aren't an ELF this check can read, if they aren't."""
    if not header.startswith(ELF_MAGIC):
        return "is not an ELF"
    if len(header) < ELF_HEADER_SIZE:
        return "is truncated: it has no complete ELF header"
    if header[EI_CLASS] != ELFCLASS64:
        return "is not a 64-bit ELF"
    if header[EI_DATA] != ELFDATA2LSB:
        return "is not a little-endian ELF"
    return None


def check_elf(path: Path, directory: str, size: int) -> list[str]:
    """Check an ELF's identity, then its program headers, reading only the bytes those need."""
    with path.open("rb") as file:
        header = file.read(ELF_HEADER_SIZE)
        failure = identity_failure(header)
        if failure is not None:
            return [failure]

        failures = []
        (machine,) = E_MACHINE.unpack_from(header, E_MACHINE_OFFSET)
        if machine != MACHINES[directory]:
            failures.append(
                f"has e_machine {machine:#x}, where {directory} needs {MACHINES[directory]:#x}"
            )

        (phoff,) = E_PHOFF.unpack_from(header, E_PHOFF_OFFSET)
        phentsize, phnum = E_PHENTSIZE_PHNUM.unpack_from(header, E_PHENTSIZE_OFFSET)
        if phentsize != PROGRAM_HEADER.size:
            failures.append(f"has program header size {phentsize}, not {PROGRAM_HEADER.size}")
            return failures
        table_size = phentsize * phnum
        if phoff + table_size > size:
            failures.append("is truncated: its program headers run past the end of the file")
            return failures

        file.seek(phoff)
        table = file.read(table_size)
    return failures + check_segments(table, needs_16k_pages=directory == ARM64_DIRECTORY)


def check_file(path: Path, directory: str) -> list[str]:
    """Check one expected binary, without following a link or opening anything but a file."""
    if path.is_symlink() or not path.is_file():
        return ["is not a regular file"]
    try:
        size = path.stat().st_size
        failures = check_elf(path, directory, size)
    except OSError as error:
        return [f"could not be read: {error.strerror}"]
    budget = MAX_BYTES[path.name]
    if size > budget:
        failures.append(f"is {size} bytes, over its budget of {budget}")
    return failures


def shown(name: str) -> str:
    """Return a file name safe to print on one line of a GitHub annotation."""
    return ascii(name)[1:-1]


def check_dist(dist: Path) -> list[str]:
    """Return every failure in a `docker buildx --output type=local` directory."""
    failures = [
        f"{shown(entry.name)} is not a platform directory this check knows"
        for entry in (sorted(dist.iterdir()) if dist.is_dir() else [])
        if entry.name not in MACHINES
    ]
    for directory in MACHINES:
        platform = dist / directory
        if not platform.is_dir():
            failures.append(f"{directory} is missing")
            continue
        present = {entry.name for entry in platform.iterdir()}
        for name in sorted(present | MAX_BYTES.keys()):
            label = f"{directory}/{shown(name)}"
            if name not in MAX_BYTES:
                failures.append(f"{label} is an unknown binary name")
            elif name not in present:
                failures.append(f"{label} is missing")
            else:
                failures.extend(
                    f"{label} {failure}" for failure in check_file(platform / name, directory)
                )
    return failures


def main(argv: list[str] | None = None) -> int:
    """Print each failure as a GitHub annotation. Return 1 if there is any."""
    parser = argparse.ArgumentParser(description="Check the binaries a build produced.")
    parser.add_argument("dist", type=Path, help="the build's output directory")
    args = parser.parse_args(argv)
    failures = check_dist(args.dist)
    for failure in failures:
        print(f"::error title=Binaries::{failure}")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
