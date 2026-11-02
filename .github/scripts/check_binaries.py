"""Fail if the Dockerfile's `binaries` stage produced anything but what a host can run.

For each binary, on each Linux platform, this wants a static position-independent executable,
and nothing else that merely starts like one:

- an ELF for the architecture its directory names, with the type and flags of a PIE, an entry
  point in code that is really in the file, and every load segment within the file, so a
  truncated download or a shared library fails;
- no loader and no libraries (no PT_INTERP, no DT_NEEDED), no text relocations, a stack it says
  isn't executable, and no load segment both writable and executable;
- on arm64, load segments that suit a kernel with 16 KiB pages, which fails only there;
- mode 0755, and within its size budget.

A file nobody expected, or one missing, also fails, so that a build producing nothing can't pass
for lack of anything to check. CI runs only the amd64 files, so on arm64 this is the only gate.

The headers are read here, in the standard library, so the check doesn't depend on which
`readelf` a machine has, and it trusts nothing they say.

Usage: check_binaries.py DIST
"""

import argparse
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

MIB = 1024 * 1024

# Each is the larger platform's measured size (amd64, on 2026-11-02, as PIE) times 1.25, rounded
# up to a MiB. Raising one is a decision: find out what grew first, and change the measured size
# in test_check_binaries.py as well. A budget per name, because the server is meant to be larger
# than the agent.
MAX_BYTES = {
    "landfall-agent": 16 * MIB,  # 12893624 bytes
    "landfall": 13 * MIB,  # 10331888 bytes
    "landfall-server": 19 * MIB,  # 15721088 bytes
}

BINARY_MODE = 0o755

# e_machine for the directories `docker buildx --output type=local` writes.
MACHINES = {"linux_arm64": 0xB7, "linux_amd64": 0x3E}
ARM64_DIRECTORY = "linux_arm64"
MIN_ARM64_ALIGN = 0x4000

ELF_MAGIC = b"\x7fELF"
ELFCLASS64 = 2
ELFDATA2LSB = 1
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_GNU_STACK = 0x6474E551
PF_X = 1
PF_W = 2
DT_NULL = 0
DT_NEEDED = 1
DT_TEXTREL = 22
DT_FLAGS = 30
DF_TEXTREL = 0x4
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_PIE = 0x08000000

ELF_HEADER_SIZE = 64
EI_CLASS = 4
EI_DATA = 5
# From e_type to e_shstrndx, which follow the 16 bytes of e_ident.
ELF_HEADER_FIELDS = struct.Struct("<HHIQQQIHHHHHH")
E_IDENT_SIZE = 16
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
DYNAMIC_ENTRY = struct.Struct("<QQ")


@dataclass(frozen=True)
class Header:
    """The fields of an ELF64 header this check uses."""

    e_type: int
    machine: int
    entry: int
    phoff: int
    shoff: int
    phentsize: int
    phnum: int
    shentsize: int
    shnum: int


@dataclass(frozen=True)
class Segment:
    """One program header."""

    p_type: int
    flags: int
    offset: int
    vaddr: int
    filesz: int
    memsz: int
    align: int


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


def parse_header(raw: bytes) -> Header:
    """Read the fields of a complete ELF64 header."""
    (e_type, machine, _, entry, phoff, shoff, _, _, phentsize, phnum, shentsize, shnum, _) = (
        ELF_HEADER_FIELDS.unpack_from(raw, E_IDENT_SIZE)
    )
    return Header(e_type, machine, entry, phoff, shoff, phentsize, phnum, shentsize, shnum)


def table_failure(header: Header, size: int) -> str | None:
    """Say why the program and section header tables can't be what the header says, if so."""
    if header.phentsize != PROGRAM_HEADER.size:
        return f"has program header size {header.phentsize}, not {PROGRAM_HEADER.size}"
    if header.phoff + header.phentsize * header.phnum > size:
        return "is truncated: its program headers run past the end of the file"
    if header.shoff + header.shentsize * header.shnum > size:
        return "is truncated: its section headers run past the end of the file"
    return None


def read_segments(file: BinaryIO, header: Header) -> list[Segment]:
    """Read a program header table already known to lie within the file."""
    file.seek(header.phoff)
    table = file.read(header.phentsize * header.phnum)
    return [
        Segment(p_type, flags, offset, vaddr, filesz, memsz, align)
        for p_type, flags, offset, vaddr, _, filesz, memsz, align in PROGRAM_HEADER.iter_unpack(
            table
        )
    ]


def segment_lies_within(segment: Segment, size: int) -> bool:
    """Say if a segment's bytes are all in a file of this size."""
    return segment.offset + segment.filesz <= size


def page_failure(loads: list[Segment]) -> str | None:
    """Say why these load segments wouldn't map on a kernel with 16 KiB pages, if so."""
    bad = [s.align for s in loads if s.align < MIN_ARM64_ALIGN or s.align & (s.align - 1)]
    if bad:
        return (
            f"has a PT_LOAD with p_align {min(bad):#x}, where a kernel with 16 KiB pages needs a "
            f"power of two of at least {MIN_ARM64_ALIGN:#x}"
        )
    if any((s.vaddr - s.offset) % MIN_ARM64_ALIGN for s in loads):
        return "has a PT_LOAD whose address and offset differ within a 16 KiB page"
    return None


def has_entry_in_code(loads: list[Segment], entry: int) -> bool:
    """Say if the entry point falls in bytes that are in the file and may be executed."""
    return any(s.flags & PF_X and s.vaddr <= entry < s.vaddr + s.filesz for s in loads)


def stack_failure(segments: list[Segment]) -> str | None:
    """Say why the stack may be executable, if so: a kernel makes it so if nothing says not."""
    stacks = [s for s in segments if s.p_type == PT_GNU_STACK]
    if not stacks:
        return "has no PT_GNU_STACK, so its stack is executable"
    if any(s.flags & PF_X for s in stacks):
        return "has a PT_GNU_STACK with PF_X, so its stack is executable"
    return None


def check_segments(segments: list[Segment], header: Header, *, needs_16k_pages: bool) -> list[str]:
    """Check what a program header table says, with one failure for each kind of fault."""
    failures = []
    if any(s.p_type == PT_INTERP for s in segments):
        failures.append("has PT_INTERP, so it needs a loader and is not static")
    stack = stack_failure(segments)
    if stack is not None:
        failures.append(stack)
    loads = [s for s in segments if s.p_type == PT_LOAD]
    if not loads:
        failures.append("has no PT_LOAD segment")
        return failures
    if any(s.flags & PF_W and s.flags & PF_X for s in loads):
        failures.append("has a PT_LOAD that is both writable and executable")
    if any(s.filesz > s.memsz for s in loads):
        failures.append("has a PT_LOAD with more bytes in the file than in memory")
    if not has_entry_in_code(loads, header.entry):
        failures.append(f"has entry point {header.entry:#x}, which is in no code in the file")
    page = page_failure(loads) if needs_16k_pages else None
    if page is not None:
        failures.append(page)
    return failures


def check_dynamic(raw: bytes) -> list[str]:
    """Check a PT_DYNAMIC segment's entries, as far as the DT_NULL that ends them."""
    tags: dict[int, int] = {}
    needed = 0
    terminated = False
    for tag, value in DYNAMIC_ENTRY.iter_unpack(raw[: len(raw) - len(raw) % DYNAMIC_ENTRY.size]):
        if tag == DT_NULL:
            terminated = True
            break
        needed += tag == DT_NEEDED
        tags[tag] = value
    failures = []
    if not terminated:
        failures.append("has a PT_DYNAMIC with no DT_NULL")
    if needed:
        failures.append(f"has {needed} DT_NEEDED, so it needs libraries and is not static")
    if DT_TEXTREL in tags or tags.get(DT_FLAGS, 0) & DF_TEXTREL:
        failures.append("has text relocations")
    if not tags.get(DT_FLAGS_1, 0) & DF_1_PIE:
        failures.append("has no DF_1_PIE, so it is a shared library and not a PIE")
    return failures


def check_elf(path: Path, directory: str, size: int) -> list[str]:
    """Check an ELF's identity, headers and dynamic section, reading only the bytes those need.

    A file over its budget could claim any amount of dynamic section, within what it holds, so
    that one isn't read: being over budget already refuses it.
    """
    with path.open("rb") as file:
        raw = file.read(ELF_HEADER_SIZE)
        failure = identity_failure(raw)
        if failure is not None:
            return [failure]
        header = parse_header(raw)

        failures = []
        if header.machine != MACHINES[directory]:
            failures.append(
                f"has e_machine {header.machine:#x}, where {directory} needs "
                f"{MACHINES[directory]:#x}"
            )
        if header.e_type != ET_DYN:
            failures.append(f"has e_type {header.e_type}, not ET_DYN ({ET_DYN}): it is not a PIE")
        failure = table_failure(header, size)
        if failure is not None:
            return [*failures, failure]

        segments = read_segments(file, header)
        checked = [s for s in segments if s.p_type in {PT_LOAD, PT_DYNAMIC}]
        if not all(segment_lies_within(s, size) for s in checked):
            return [*failures, "is truncated: a segment runs past the end of the file"]
        failures += check_segments(segments, header, needs_16k_pages=directory == ARM64_DIRECTORY)

        dynamic = [s for s in segments if s.p_type == PT_DYNAMIC]
        if len(dynamic) != 1:
            failures.append(f"has {len(dynamic)} PT_DYNAMIC segments, where a PIE has one")
            return failures
        if size > MAX_BYTES[path.name]:
            return failures
        file.seek(dynamic[0].offset)
        return failures + check_dynamic(file.read(dynamic[0].filesz))


def check_file(path: Path, directory: str) -> list[str]:
    """Check one expected binary, without following a link or opening anything but a file."""
    if path.is_symlink() or not path.is_file():
        return ["is not a regular file"]
    try:
        status = path.stat()
        failures = check_elf(path, directory, status.st_size)
    except OSError as error:
        return [f"could not be read: {error.strerror}"]
    mode = stat.S_IMODE(status.st_mode)
    if mode != BINARY_MODE:
        failures.append(f"has mode {mode:o}, not {BINARY_MODE:o}")
    budget = MAX_BYTES[path.name]
    if status.st_size > budget:
        failures.append(f"is {status.st_size} bytes, over its budget of {budget}")
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
        if platform.is_symlink():
            failures.append(f"{directory} is a link, not a directory")
            continue
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
