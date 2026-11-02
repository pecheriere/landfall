"""Unit tests for check_binaries.py, on small ELF files built here."""

import contextlib
import io
import math
import os
import shutil
import struct
import tempfile
import unittest
from dataclasses import dataclass
from pathlib import Path
from unittest import mock

import check_binaries

AMD64 = 0x3E
ARM64 = 0xB7
ET_REL = 1
ET_EXEC = 2
ET_CORE = 4
ET_DYN = 3
PT_LOAD = 1
PT_DYNAMIC = 2
PT_INTERP = 3
PT_TLS = 7
PT_GNU_STACK = 0x6474E551
PF_RX = 5
PF_RW = 6
PF_RWX = 7
ALIGN_4K = 0x1000
ALIGN_16K = 0x4000
ALIGN_64K = 0x10000
DT_NULL = 0
DT_NEEDED = 1
DT_TEXTREL = 22
DT_FLAGS = 30
DF_TEXTREL = 0x4
DF_BIND_NOW = 0x8
DT_FLAGS_1 = 0x6FFFFFFB
DF_1_NOW = 0x1
DF_1_PIE = 0x08000000

ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
EI_CLASS = 4
EI_DATA = 5
E_TYPE_OFFSET = 16
E_PHOFF_OFFSET = 32
E_SHOFF_OFFSET = 40
E_PHENTSIZE_OFFSET = 54
E_PHNUM_OFFSET = 56
E_SHENTSIZE_OFFSET = 58
E_SHNUM_OFFSET = 60
P_OFFSET_OFFSET = 8
P_FILESZ_OFFSET = 32
# The PT_DYNAMIC `elf` adds, with the one load segment and its PT_GNU_STACK before it.
DYNAMIC_PROGRAM_HEADER = ELF_HEADER_SIZE + 2 * PROGRAM_HEADER_SIZE
DYNAMIC_ENTRY_SIZE = 16
MACHINES = {"linux_arm64": ARM64, "linux_amd64": AMD64}
NAMES = ("landfall", "landfall-agent", "landfall-server")

# The size of each binary on the larger platform when its budget was set. Here as well as beside
# the budget, so raising a budget takes a second, deliberate edit.
MEASURED_BYTES = {
    "landfall-agent": 12893624,
    "landfall": 10331888,
    "landfall-server": 15721088,
}

STATIC_PIE = ((DT_FLAGS_1, DF_1_PIE),)


@dataclass(frozen=True)
class Seg:
    """One segment of a test file. With `filesz` None, it covers the whole file."""

    p_type: int = PT_LOAD
    flags: int = PF_RX
    offset: int = 0
    vaddr: int = 0
    filesz: int | None = None
    memsz: int | None = None
    align: int = ALIGN_64K


# What every real binary has, so what `elf` adds to its segments unless they name their own.
NO_EXEC_STACK = Seg(PT_GNU_STACK, PF_RW, filesz=0, align=16)


def elf(
    machine: int,
    segments: tuple[Seg, ...] = (Seg(),),
    dynamic: tuple[tuple[int, int], ...] | None = STATIC_PIE,
    phoff: int = ELF_HEADER_SIZE,
    padding: bytes = b"",
) -> bytes:
    """Build a small file: the header, a gap, the program headers, the dynamic section, padding.

    By default this is what a static PIE looks like, with its entry point at the end of the
    header. `dynamic` is its dynamic entries before the DT_NULL, added as a PT_DYNAMIC after
    `segments`; None leaves that segment out. The gap up to `phoff` is 0xCC, which reads as
    nothing this check accepts. Without a PT_GNU_STACK in `segments`, a good one is added, last.
    """
    stack = () if any(s.p_type == PT_GNU_STACK for s in segments) else (NO_EXEC_STACK,)
    return _elf(machine, (*segments, *stack), dynamic, phoff, padding)


def _elf(
    machine: int,
    segments: tuple[Seg, ...],
    dynamic: tuple[tuple[int, int], ...] | None,
    phoff: int,
    padding: bytes,
) -> bytes:
    """Lay out exactly the segments given."""
    count = len(segments) + (dynamic is not None)
    table_end = phoff + PROGRAM_HEADER_SIZE * count
    tail = b""
    if dynamic is not None:
        tail = b"".join(struct.pack("<QQ", *entry) for entry in (*dynamic, (DT_NULL, 0)))
    total = table_end + len(tail) + len(padding)
    table = b""
    for seg in segments:
        filesz = total if seg.filesz is None else seg.filesz
        memsz = filesz if seg.memsz is None else seg.memsz
        table += struct.pack(
            "<IIQQQQQQ", seg.p_type, seg.flags, seg.offset, seg.vaddr, 0, filesz, memsz, seg.align
        )
    if dynamic is not None:
        table += struct.pack(
            "<IIQQQQQQ", PT_DYNAMIC, PF_RW, table_end, table_end, 0, len(tail), len(tail), 8
        )
    ident = b"\x7fELF" + bytes([2, 1, 1]) + bytes(9)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        ET_DYN,
        machine,
        1,
        ELF_HEADER_SIZE,
        phoff,
        0,
        0,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        count,
        0,
        0,
        0,
    )
    return header + b"\xcc" * (phoff - ELF_HEADER_SIZE) + table + tail + padding


def with_bytes(content: bytes, offset: int, packed: bytes) -> bytes:
    """Return `content` with `packed` written over the bytes at `offset`."""
    return content[:offset] + packed + content[offset + len(packed) :]


def with_e_type(content: bytes, e_type: int) -> bytes:
    """Return an ELF of another type."""
    return with_bytes(content, E_TYPE_OFFSET, struct.pack("<H", e_type))


class DistTestCase(unittest.TestCase):
    """Each test gets a complete, valid dist directory and breaks one thing in it."""

    def setUp(self) -> None:
        """Fill a temporary dist with a good file for each binary on each platform."""
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.dist = Path(temporary.name)
        for directory, machine in MACHINES.items():
            (self.dist / directory).mkdir()
            for name in NAMES:
                self.write(directory, name, elf(machine))

    def write(self, directory: str, name: str, content: bytes) -> None:
        """Replace or add one executable file in the dist."""
        path = self.dist / directory / name
        path.write_bytes(content)
        path.chmod(0o755)

    def assert_one_failure(self, *fragments: str) -> None:
        """Check the dist fails once, and that the failure says every one of `fragments`."""
        failures = check_binaries.check_dist(self.dist)
        self.assertEqual(len(failures), 1, failures)
        for fragment in fragments:
            self.assertIn(fragment, failures[0])

    def assert_passes(self) -> None:
        """Check the dist has nothing wrong with it."""
        self.assertEqual(check_binaries.check_dist(self.dist), [])


class AcceptedTests(DistTestCase):
    """What must pass."""

    def test_accepts_a_static_binary(self) -> None:
        """Static PIEs of the right architecture, within budget, pass."""
        self.assert_passes()

    def test_main_returns_0_and_prints_nothing_for_a_good_dist(self) -> None:
        """A good dist exits 0, which is what CI goes by."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(check_binaries.main([str(self.dist)]), 0)
        self.assertEqual(out.getvalue(), "")


class StaticLinkingTests(DistTestCase):
    """A binary that needs a loader or a library fails on a host without it."""

    def test_dynamic_binary_is_refused(self) -> None:
        """A PT_INTERP segment names a loader, so the binary isn't static."""
        segments = (Seg(PT_INTERP, align=1), Seg())
        self.write("linux_amd64", "landfall-agent", elf(AMD64, segments))
        self.assert_one_failure("linux_amd64/landfall-agent", "PT_INTERP")

    def test_needed_library_without_an_interpreter_is_refused(self) -> None:
        """No PT_INTERP doesn't make a file static, if it lists libraries it must find."""
        needed = ((DT_NEEDED, 1), (DT_FLAGS_1, DF_1_PIE))
        self.write("linux_amd64", "landfall-agent", elf(AMD64, dynamic=needed))
        self.assert_one_failure("linux_amd64/landfall-agent", "DT_NEEDED")

    def test_entries_after_dt_null_are_not_read(self) -> None:
        """The loader stops at DT_NULL, so a later DT_NEEDED asks for nothing."""
        entry = struct.pack("<QQ", DT_NEEDED, 1)
        content = elf(AMD64, padding=entry)
        size = 2 * DYNAMIC_ENTRY_SIZE + len(entry)
        at = DYNAMIC_PROGRAM_HEADER + P_FILESZ_OFFSET
        self.write("linux_amd64", "landfall", with_bytes(content, at, struct.pack("<Q", size)))
        self.assert_passes()


class PieTests(DistTestCase):
    """The agent is root-equivalent: it must not sit at a fixed address."""

    def test_a_non_pie_executable_is_refused(self) -> None:
        """ET_EXEC loads at the address it was linked for, which is what the Dockerfile avoids."""
        self.write("linux_amd64", "landfall-agent", with_e_type(elf(AMD64), ET_EXEC))
        self.assert_one_failure("linux_amd64/landfall-agent", "e_type 2", "not a PIE")

    def test_object_files_and_core_dumps_are_refused(self) -> None:
        """Neither runs, whatever else its headers say."""
        for e_type in (ET_REL, ET_CORE):
            with self.subTest(e_type=e_type):
                self.write("linux_arm64", "landfall", with_e_type(elf(ARM64), e_type))
                self.assert_one_failure("linux_arm64/landfall", f"e_type {e_type}")

    def test_a_shared_library_is_refused(self) -> None:
        """ET_DYN with no DF_1_PIE, and no libraries of its own, is still a library."""
        self.write("linux_arm64", "landfall", elf(ARM64, dynamic=()))
        self.assert_one_failure("linux_arm64/landfall", "DF_1_PIE")

    def test_other_dt_flags_1_bits_are_not_pie(self) -> None:
        """DF_1_NOW alone is what many a library has."""
        self.write("linux_arm64", "landfall", elf(ARM64, dynamic=((DT_FLAGS_1, DF_1_NOW),)))
        self.assert_one_failure("linux_arm64/landfall", "DF_1_PIE")

    def test_no_dynamic_segment_is_refused(self) -> None:
        """A PIE relocates itself, which it can't do without one."""
        self.write("linux_amd64", "landfall", elf(AMD64, dynamic=None))
        self.assert_one_failure("linux_amd64/landfall", "0 PT_DYNAMIC")

    def test_two_dynamic_segments_are_refused(self) -> None:
        """Which of two would count isn't something to guess."""
        second = Seg(PT_DYNAMIC, PF_RW, filesz=0, align=8)
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(), second)))
        self.assert_one_failure("linux_amd64/landfall", "2 PT_DYNAMIC")

    def test_text_relocations_are_refused_by_either_marker(self) -> None:
        """A text relocation needs writable code, which is what PIE hardening is meant to avoid."""
        for marker in ((DT_TEXTREL, 0), (DT_FLAGS, DF_TEXTREL)):
            with self.subTest(marker=marker):
                dynamic = (marker, (DT_FLAGS_1, DF_1_PIE))
                self.write("linux_amd64", "landfall", elf(AMD64, dynamic=dynamic))
                self.assert_one_failure("linux_amd64/landfall", "text relocations")

    def test_other_dt_flags_bits_are_not_text_relocations(self) -> None:
        """DF_BIND_NOW is what a hardened binary has."""
        dynamic = ((DT_FLAGS, DF_BIND_NOW), (DT_FLAGS_1, DF_1_PIE))
        self.write("linux_amd64", "landfall", elf(AMD64, dynamic=dynamic))
        self.assert_passes()

    def test_unterminated_dynamic_section_is_refused(self) -> None:
        """Nothing says where it ends, so nothing more can be said about it."""
        content = elf(AMD64)
        last_entry = len(content) - DYNAMIC_ENTRY_SIZE
        unterminated = with_bytes(content, last_entry, struct.pack("<QQ", 0x7000, 0))
        self.write("linux_amd64", "landfall", unterminated)
        self.assert_one_failure("linux_amd64/landfall", "DT_NULL")

    def test_dynamic_section_is_read_from_where_its_header_says(self) -> None:
        """A section right after the table can't tell that from reading straight on."""
        entry = struct.pack("<QQ", DT_NEEDED, 1)
        content = elf(AMD64, padding=entry)
        moved = with_bytes(
            content,
            DYNAMIC_PROGRAM_HEADER + P_OFFSET_OFFSET,
            struct.pack("<Q", len(content) - len(entry)),
        )
        at = DYNAMIC_PROGRAM_HEADER + P_FILESZ_OFFSET
        moved = with_bytes(moved, at, struct.pack("<Q", len(entry)))
        self.write("linux_amd64", "landfall", moved)
        self.assertIn("DT_NEEDED", " ".join(check_binaries.check_dist(self.dist)))


class DynamicReadTests(DistTestCase):
    """The dynamic section is what its header says, no more and no less."""

    def with_dynamic_size(self, content: bytes, size: int) -> bytes:
        """Return a file whose PT_DYNAMIC claims this size."""
        at = DYNAMIC_PROGRAM_HEADER + P_FILESZ_OFFSET
        return with_bytes(content, at, struct.pack("<Q", size))

    def test_a_dt_null_past_the_end_of_the_section_does_not_end_it(self) -> None:
        """What follows the segment isn't part of it, even if it would look right."""
        one_entry = self.with_dynamic_size(elf(AMD64), DYNAMIC_ENTRY_SIZE)
        self.write("linux_amd64", "landfall", one_entry)
        self.assert_one_failure("linux_amd64/landfall", "DT_NULL")

    def test_a_size_that_is_not_a_multiple_of_an_entry_does_not_crash(self) -> None:
        """The odd bytes at the end are ignored, as they are no entry."""
        odd = self.with_dynamic_size(elf(AMD64, padding=bytes(8)), 2 * DYNAMIC_ENTRY_SIZE + 8)
        self.write("linux_amd64", "landfall", odd)
        self.assert_passes()

    def test_a_file_over_budget_has_its_dynamic_section_left_unread(self) -> None:
        """It could claim gigabytes, and the budget has already refused it."""
        needed = ((DT_NEEDED, 1), (DT_FLAGS_1, DF_1_PIE))
        content = elf(AMD64, dynamic=needed)
        with mock.patch.dict(check_binaries.MAX_BYTES, {"landfall": len(content) - 1}):
            self.write("linux_amd64", "landfall", content)
            self.write("linux_arm64", "landfall", elf(ARM64))
            failures = [f for f in check_binaries.check_dist(self.dist) if "amd64" in f]
        self.assertEqual(len(failures), 1, failures)
        self.assertIn("over its budget", failures[0])


class HardeningTests(DistTestCase):
    """The stack and writable code: a PIE that gives these up has given up much of the point."""

    def test_an_executable_stack_is_refused(self) -> None:
        """An assembly object with no note can bring this in without anyone asking."""
        stack = Seg(PT_GNU_STACK, PF_RWX, filesz=0, align=16)
        self.write("linux_amd64", "landfall-agent", elf(AMD64, (Seg(), stack)))
        self.assert_one_failure("linux_amd64/landfall-agent", "PT_GNU_STACK", "executable")

    def test_a_missing_stack_header_is_refused(self) -> None:
        """Without one, a kernel gives the file an executable stack."""
        raw = _elf(AMD64, (Seg(),), STATIC_PIE, ELF_HEADER_SIZE, b"")
        self.write("linux_amd64", "landfall-agent", raw)
        self.assert_one_failure("linux_amd64/landfall-agent", "no PT_GNU_STACK")

    def test_a_writable_executable_load_segment_is_refused(self) -> None:
        """Code that can be written to is what W^X is meant to rule out."""
        self.write("linux_amd64", "landfall-agent", elf(AMD64, (Seg(flags=PF_RWX),)))
        self.assert_one_failure("linux_amd64/landfall-agent", "writable and executable")

    def test_one_writable_executable_segment_among_good_ones_is_refused(self) -> None:
        """Every load segment counts, and a real binary has four."""
        bad = Seg(flags=PF_RWX, filesz=0)
        self.write("linux_amd64", "landfall-agent", elf(AMD64, (Seg(), bad)))
        self.assert_one_failure("linux_amd64/landfall-agent", "writable and executable")

    def test_a_writable_segment_beside_the_code_is_fine(self) -> None:
        """Data has to live somewhere, and each real binary has two such segments."""
        data = Seg(flags=PF_RW, filesz=0)
        self.write("linux_amd64", "landfall-agent", elf(AMD64, (Seg(), data)))
        self.assert_passes()


class ArchitectureTests(DistTestCase):
    """A file must be built for the platform its directory names."""

    def test_wrong_architecture_for_its_directory_is_refused(self) -> None:
        """Both ways round: this is the mistake a swapped matrix entry would make."""
        one_segment_in_either = (Seg(),)
        for directory, machine in (("linux_arm64", AMD64), ("linux_amd64", ARM64)):
            with self.subTest(directory=directory):
                self.write(directory, "landfall", elf(machine, one_segment_in_either))
                self.assert_one_failure(f"{directory}/landfall", "e_machine")
                self.write(directory, "landfall", elf(MACHINES[directory]))

    def test_32_bit_is_refused(self) -> None:
        """Neither platform here is 32-bit, and the offsets would mean something else."""
        self.write("linux_amd64", "landfall", with_bytes(elf(AMD64), EI_CLASS, b"\x01"))
        self.assert_one_failure("linux_amd64/landfall", "64-bit")

    def test_big_endian_is_refused(self) -> None:
        """Neither platform here is big-endian."""
        self.write("linux_arm64", "landfall", with_bytes(elf(ARM64), EI_DATA, b"\x02"))
        self.assert_one_failure("linux_arm64/landfall", "little-endian")


class PageSizeTests(DistTestCase):
    """An arm64 kernel with 16 KiB pages can't load segments aligned to 4 KiB."""

    def test_arm64_load_segments_must_suit_16k_pages(self) -> None:
        """Refused below 16 KiB, accepted from it up, and amd64 is unaffected."""
        name = "landfall-agent"
        for refused in (ALIGN_4K, 0x2000):
            self.write("linux_arm64", name, elf(ARM64, (Seg(align=refused),)))
            self.assert_one_failure("linux_arm64/landfall-agent", "p_align", f"{refused:#x}")

        for accepted in (ALIGN_16K, ALIGN_64K):
            self.write("linux_arm64", name, elf(ARM64, (Seg(align=accepted),)))
            self.assert_passes()

        self.write("linux_amd64", name, elf(AMD64, (Seg(align=ALIGN_4K),)))
        self.assert_passes()

    def test_an_alignment_that_is_not_a_power_of_two_is_refused(self) -> None:
        """Both of these are above a smaller minimum, and neither means anything."""
        for refused in (ALIGN_16K - 1, ALIGN_16K + 1):
            self.write("linux_arm64", "landfall", elf(ARM64, (Seg(align=refused),)))
            self.assert_one_failure("linux_arm64/landfall", "power of two", f"{refused:#x}")

    def test_address_and_offset_must_agree_within_16k(self) -> None:
        """What the kernel really maps by: the alignment field alone doesn't make this so."""
        odd = Seg(flags=PF_RW, offset=ALIGN_4K, vaddr=ALIGN_16K, filesz=0)
        room = bytes(2 * ALIGN_4K)
        self.write("linux_arm64", "landfall", elf(ARM64, (Seg(), odd), padding=room))
        self.assert_one_failure("linux_arm64/landfall", "16 KiB page")
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(), odd), padding=room))
        self.write("linux_arm64", "landfall", elf(ARM64))
        self.assert_passes()

    def test_address_and_offset_a_whole_16k_apart_are_fine(self) -> None:
        """The one page size this is about, so nothing larger may be asked for."""
        data = Seg(flags=PF_RW, offset=0, vaddr=ALIGN_16K, filesz=0)
        self.write("linux_arm64", "landfall", elf(ARM64, (Seg(), data)))
        self.assert_passes()

    def test_only_load_segments_need_the_alignment(self) -> None:
        """A real static binary has a TLS segment with a small alignment, and that is fine."""
        self.write("linux_arm64", "landfall", elf(ARM64, (Seg(), Seg(PT_TLS, align=8))))
        self.assert_passes()

    def test_one_bad_load_segment_among_good_ones_is_refused(self) -> None:
        """Every load segment counts, not only the first."""
        bad = Seg(flags=PF_RW, filesz=0, align=ALIGN_4K)
        self.write("linux_arm64", "landfall", elf(ARM64, (Seg(), bad)))
        self.assert_one_failure("linux_arm64/landfall", "p_align", "0x1000")

    def test_several_bad_load_segments_are_one_failure_with_the_smallest_alignment(self) -> None:
        """A real binary has four load segments, and four like lines say nothing more."""
        segments = (Seg(align=ALIGN_4K), Seg(filesz=0, align=0x200), Seg(filesz=0, align=ALIGN_4K))
        self.write("linux_arm64", "landfall", elf(ARM64, segments))
        self.assert_one_failure("linux_arm64/landfall", "0x200")


class BudgetTests(DistTestCase):
    """Each binary has its own size budget."""

    def test_over_budget_is_refused_by_name(self) -> None:
        """A size within the server's budget is still over the agent's."""
        padded = elf(AMD64, padding=bytes(2000))
        budgets = {
            "landfall-agent": len(padded) - 1,
            "landfall": len(padded) - 1,
            "landfall-server": len(padded),
        }
        with mock.patch.dict(check_binaries.MAX_BYTES, budgets):
            self.write("linux_amd64", "landfall-agent", padded)
            self.assert_one_failure(
                "linux_amd64/landfall-agent", str(len(padded)), str(len(padded) - 1)
            )
            self.write("linux_amd64", "landfall-agent", elf(AMD64))
            self.write("linux_amd64", "landfall-server", padded)
            self.assert_passes()

    def test_a_size_equal_to_the_budget_passes(self) -> None:
        """The budget is a maximum, not a limit to stay below."""
        content = elf(AMD64)
        with mock.patch.dict(check_binaries.MAX_BYTES, {"landfall": len(content)}):
            self.write("linux_amd64", "landfall", content)
            self.write("linux_arm64", "landfall", elf(ARM64))
            self.assert_passes()

    def test_every_budget_is_its_measured_size_with_a_quarter_to_spare(self) -> None:
        """Raising a budget is a decision, so it can't happen in one line nobody looks at."""
        wanted = {
            name: math.ceil(size * 1.25 / check_binaries.MIB) * check_binaries.MIB
            for name, size in MEASURED_BYTES.items()
        }
        self.assertEqual(check_binaries.MAX_BYTES, wanted)


class ModeTests(DistTestCase):
    """What the mode says decides if it runs, and as whom."""

    def test_a_file_that_is_not_executable_is_refused(self) -> None:
        """amd64 would fail at CI's run step, and arm64 wouldn't fail anywhere."""
        (self.dist / "linux_arm64" / "landfall").chmod(0o644)
        self.assert_one_failure("linux_arm64/landfall", "mode 644")

    def test_a_setuid_file_is_refused(self) -> None:
        """Nothing here is meant to take on another user."""
        (self.dist / "linux_arm64" / "landfall").chmod(0o4755)
        self.assert_one_failure("linux_arm64/landfall", "mode 4755")


class LayoutTests(DistTestCase):
    """The dist must hold exactly the expected files, so a missing one can't pass unseen."""

    def test_unknown_binary_name_is_refused(self) -> None:
        """A stray file would otherwise be published or ignored without anyone deciding."""
        self.write("linux_amd64", "landfall-extra", elf(AMD64))
        self.assert_one_failure("linux_amd64/landfall-extra", "unknown")

    def test_a_name_with_a_newline_stays_on_one_line(self) -> None:
        """A line of its own would be a GitHub annotation of the file name's choosing."""
        self.write("linux_amd64", "x\n::error::y", elf(AMD64))
        self.assert_one_failure("linux_amd64/x\\n::error::y", "unknown")

    def test_a_directory_name_with_a_newline_stays_on_one_line(self) -> None:
        """The same goes for what sits beside the platform directories."""
        (self.dist / "x\n::error::y").mkdir()
        self.assert_one_failure("x\\n::error::y", "not a platform")

    def test_missing_binary_is_refused(self) -> None:
        """A build that produced nothing must not pass because there was nothing to check."""
        (self.dist / "linux_arm64" / "landfall").unlink()
        self.assert_one_failure("linux_arm64/landfall", "missing")

    def test_missing_directory_is_refused(self) -> None:
        """An empty dist has no files to fail on, and must fail anyway."""
        shutil.rmtree(self.dist / "linux_amd64")
        self.assert_one_failure("linux_amd64", "missing")

    def test_missing_dist_is_refused_for_both_platforms(self) -> None:
        """A wrong path is a failure, not a pass."""
        failures = check_binaries.check_dist(self.dist / "nowhere")
        self.assertEqual(len(failures), 2, failures)

    def test_a_link_is_not_followed(self) -> None:
        """What gets published is the file itself, so a link isn't one."""
        link = self.dist / "linux_amd64" / "landfall"
        link.unlink()
        link.symlink_to(self.dist / "linux_amd64" / "landfall-agent")
        self.assert_one_failure("linux_amd64/landfall", "not a regular file")

    def test_a_platform_directory_that_is_a_link_is_refused(self) -> None:
        """Its files would be somewhere else, so they aren't what this build wrote."""
        platform = self.dist / "linux_amd64"
        shutil.rmtree(platform)
        platform.symlink_to(self.dist / "linux_arm64")
        self.assert_one_failure("linux_amd64", "a link")

    def test_another_platform_directory_is_refused(self) -> None:
        """Files for a platform this check knows nothing about have been checked by nobody."""
        (self.dist / "linux_riscv64").mkdir()
        self.assert_one_failure("linux_riscv64", "not a platform")

    def test_a_fifo_is_refused_without_blocking(self) -> None:
        """Opening a FIFO would wait for a writer for ever."""
        fifo = self.dist / "linux_amd64" / "landfall"
        fifo.unlink()
        os.mkfifo(fifo)
        self.assert_one_failure("linux_amd64/landfall", "not a regular file")

    def test_a_file_that_cannot_be_read_is_named_not_raised(self) -> None:
        """The operating system's refusal is a failure of this file, not of the whole run."""
        refusal = PermissionError(13, "Permission denied")
        with mock.patch.object(Path, "open", side_effect=refusal):
            failures = check_binaries.check_dist(self.dist)
        self.assertEqual(len(failures), 2 * len(NAMES), failures)
        self.assertIn("could not be read: Permission denied", failures[0])


class MalformedTests(DistTestCase):
    """Whatever is in a file, the check names it and carries on."""

    def test_not_an_elf_is_refused(self) -> None:
        """A shell script or an archive isn't a binary that runs."""
        self.write("linux_amd64", "landfall", b"#!/bin/sh\nexit 0\n" * 10)
        self.assert_one_failure("linux_amd64/landfall", "not an ELF")

    def test_empty_file_is_refused(self) -> None:
        """The smallest truncation of all."""
        self.write("linux_amd64", "landfall", b"")
        self.assert_one_failure("linux_amd64/landfall", "not an ELF")

    def test_truncated_header_does_not_crash(self) -> None:
        """Every prefix of a good file is refused with a message, not an exception."""
        content = elf(AMD64)
        for length in range(len(content)):
            with self.subTest(length=length):
                self.write("linux_amd64", "landfall", content[:length])
                self.assert_one_failure("linux_amd64/landfall")

    def test_a_binary_cut_after_its_headers_is_refused(self) -> None:
        """What a dropped download looks like: the headers are intact, the code is gone."""
        whole = elf(AMD64, padding=bytes(8192))
        self.write("linux_amd64", "landfall", whole[:4096])
        self.assert_one_failure("linux_amd64/landfall", "truncated", "segment")

    def test_a_binary_cut_inside_its_section_headers_is_refused(self) -> None:
        """Those are at the very end, so this is the last thing to go, and it is still cut."""
        content = elf(AMD64, padding=bytes(1000))
        content = with_bytes(content, E_SHOFF_OFFSET, struct.pack("<Q", len(content) - 100))
        content = with_bytes(content, E_SHENTSIZE_OFFSET, struct.pack("<H", 64))
        content = with_bytes(content, E_SHNUM_OFFSET, struct.pack("<H", 2))
        self.write("linux_amd64", "landfall", content)
        self.assert_one_failure("linux_amd64/landfall", "truncated", "section")

    def test_a_section_table_ending_exactly_at_the_end_of_the_file_is_fine(self) -> None:
        """Which is where a real binary's ends."""
        content = elf(AMD64, padding=bytes(1000))
        content = with_bytes(content, E_SHOFF_OFFSET, struct.pack("<Q", len(content) - 128))
        content = with_bytes(content, E_SHENTSIZE_OFFSET, struct.pack("<H", 64))
        content = with_bytes(content, E_SHNUM_OFFSET, struct.pack("<H", 2))
        self.write("linux_amd64", "landfall", content)
        self.assert_passes()

    def test_a_segment_claiming_more_than_the_file_is_refused(self) -> None:
        """A valid header with a load segment 1 GiB past the end."""
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(filesz=1 << 30),)))
        self.assert_one_failure("linux_amd64/landfall", "truncated", "segment")

    def test_a_dynamic_section_past_the_end_is_refused(self) -> None:
        """It would be read by offset, so an offset out of the file is refused first."""
        at = DYNAMIC_PROGRAM_HEADER + P_OFFSET_OFFSET
        content = with_bytes(elf(AMD64), at, struct.pack("<Q", 2**64 - 1))
        self.write("linux_amd64", "landfall", content)
        self.assert_one_failure("linux_amd64/landfall", "truncated", "segment")

    def test_a_header_only_file_is_refused(self) -> None:
        """Every field is in order, and there is no code at the entry point."""
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(filesz=0, memsz=0x1000),)))
        self.assert_one_failure("linux_amd64/landfall", "entry point")

    def test_an_entry_point_in_data_is_refused(self) -> None:
        """Bytes it may not execute are no better than none."""
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(flags=PF_RW),)))
        self.assert_one_failure("linux_amd64/landfall", "entry point")

    def test_an_entry_point_past_its_segment_is_refused(self) -> None:
        """The entry is at the end of the header; a segment that stops there doesn't hold it."""
        segment = Seg(filesz=ELF_HEADER_SIZE, memsz=ALIGN_64K)
        self.write("linux_amd64", "landfall", elf(AMD64, (segment,)))
        self.assert_one_failure("linux_amd64/landfall", "entry point")

    def test_an_entry_point_before_its_segment_is_refused(self) -> None:
        """The segment starts after the address the entry point names."""
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(vaddr=ALIGN_64K),)))
        self.assert_one_failure("linux_amd64/landfall", "entry point")

    def test_an_entry_point_in_the_first_byte_of_its_segment_is_accepted(self) -> None:
        """The start of a segment is in it."""
        segment = Seg(offset=ELF_HEADER_SIZE, vaddr=ELF_HEADER_SIZE, filesz=1)
        self.write("linux_amd64", "landfall", elf(AMD64, (segment,)))
        self.assert_passes()

    def test_more_bytes_in_the_file_than_in_memory_is_refused(self) -> None:
        """The kernel refuses this, so it must not get as far as a host."""
        self.write("linux_amd64", "landfall", elf(AMD64, (Seg(memsz=1),)))
        self.assert_one_failure("linux_amd64/landfall", "than in memory")

    def test_program_headers_past_the_end_of_the_file_are_refused(self) -> None:
        """Offsets in the header are read from the file, so they can say anything."""
        content = elf(AMD64)
        huge_offset = with_bytes(content, E_PHOFF_OFFSET, struct.pack("<Q", 2**64 - 1))
        huge_count = with_bytes(content, E_PHNUM_OFFSET, struct.pack("<H", 0xFFFF))
        for broken in (huge_offset, huge_count):
            self.write("linux_amd64", "landfall", broken)
            self.assert_one_failure("linux_amd64/landfall", "truncated")

    def test_program_headers_are_read_from_where_the_header_says(self) -> None:
        """They aren't always right after the header, and what is there instead doesn't count."""
        self.write("linux_amd64", "landfall", elf(AMD64, phoff=0x100))
        self.assert_passes()
        segments = (Seg(PT_INTERP, align=1), Seg())
        self.write("linux_amd64", "landfall", elf(AMD64, segments, phoff=0x100))
        self.assert_one_failure("linux_amd64/landfall", "PT_INTERP")

    def test_an_unexpected_program_header_size_is_refused(self) -> None:
        """The entries would be read at the wrong offsets."""
        content = with_bytes(elf(AMD64), E_PHENTSIZE_OFFSET, struct.pack("<H", 32))
        self.write("linux_amd64", "landfall", content)
        self.assert_one_failure("linux_amd64/landfall", "program header size")

    def test_no_load_segment_is_refused(self) -> None:
        """A file with nothing to load can't run, and has nothing to check for alignment."""
        self.write("linux_arm64", "landfall", elf(ARM64, ()))
        self.assert_one_failure("linux_arm64/landfall", "no PT_LOAD")


class MainTests(DistTestCase):
    """The command line CI runs."""

    def test_main_names_each_failure_and_returns_1(self) -> None:
        """Every failure is shown, not only the first."""
        self.write("linux_amd64", "landfall", elf(ARM64))
        self.write("linux_arm64", "landfall-agent", b"not an elf")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(check_binaries.main([str(self.dist)]), 1)
        self.assertIn("linux_amd64/landfall", out.getvalue())
        self.assertIn("linux_arm64/landfall-agent", out.getvalue())

    def test_one_file_with_two_faults_reports_both(self) -> None:
        """Fixing one and rerunning to find the next is a wasted build."""
        segments = (Seg(PT_INTERP, align=1), Seg(align=ALIGN_4K))
        self.write("linux_arm64", "landfall", elf(ARM64, segments))
        failures = check_binaries.check_dist(self.dist)
        self.assertEqual(len(failures), 2, failures)

    def test_main_needs_exactly_one_argument(self) -> None:
        """Usage errors are exit 2, as argparse has it, not a pass."""
        with (
            contextlib.redirect_stderr(io.StringIO()),
            self.assertRaises(SystemExit) as raised,
        ):
            check_binaries.main([])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
