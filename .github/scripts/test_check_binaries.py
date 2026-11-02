"""Unit tests for check_binaries.py, on small ELF headers built here."""

import contextlib
import io
import os
import struct
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import check_binaries

AMD64 = 0x3E
ARM64 = 0xB7
PT_LOAD = 1
PT_INTERP = 3
PT_TLS = 7
ALIGN_4K = 0x1000
ALIGN_16K = 0x4000
ALIGN_64K = 0x10000

ELF_HEADER_SIZE = 64
PROGRAM_HEADER_SIZE = 56
MACHINES = {"linux_arm64": ARM64, "linux_amd64": AMD64}
NAMES = ("landfall", "landfall-agent", "landfall-server")


def program_header(p_type: int, p_align: int) -> bytes:
    """Build one ELF64 program header; only its type and alignment matter here."""
    return struct.pack("<IIQQQQQQ", p_type, 5, 0, 0, 0, 0, 0, p_align)


def elf(
    machine: int,
    segments: tuple[tuple[int, int], ...] = ((PT_LOAD, ALIGN_64K),),
    *,
    elf_class: int = 2,
    data: int = 1,
) -> bytes:
    """Build a little ELF64 file: the header, then a (type, p_align) program header for each."""
    ident = b"\x7fELF" + bytes([elf_class, data, 1]) + bytes(9)
    header = ident + struct.pack(
        "<HHIQQQIHHHHHH",
        3,
        machine,
        1,
        0,
        ELF_HEADER_SIZE,
        0,
        0,
        ELF_HEADER_SIZE,
        PROGRAM_HEADER_SIZE,
        len(segments),
        0,
        0,
        0,
    )
    return header + b"".join(program_header(*segment) for segment in segments)


def with_header_field(content: bytes, offset: int, packed: bytes) -> bytes:
    """Return `content` with `packed` written over the bytes at `offset`."""
    return content[:offset] + packed + content[offset + len(packed) :]


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
                (self.dist / directory / name).write_bytes(elf(machine))

    def write(self, directory: str, name: str, content: bytes) -> None:
        """Replace or add one file in the dist."""
        (self.dist / directory / name).write_bytes(content)

    def assert_one_failure(self, *fragments: str) -> None:
        """Check the dist fails once, and that the failure says every one of `fragments`."""
        failures = check_binaries.check_dist(self.dist)
        self.assertEqual(len(failures), 1, failures)
        for fragment in fragments:
            self.assertIn(fragment, failures[0])


class AcceptedTests(DistTestCase):
    """What must pass."""

    def test_accepts_a_static_binary(self) -> None:
        """Static binaries of the right architecture, within budget, pass."""
        self.assertEqual(check_binaries.check_dist(self.dist), [])

    def test_main_returns_0_and_prints_nothing_for_a_good_dist(self) -> None:
        """A good dist exits 0, which is what CI goes by."""
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(check_binaries.main([str(self.dist)]), 0)
        self.assertEqual(out.getvalue(), "")


class StaticLinkingTests(DistTestCase):
    """A binary that needs a loader fails on a host without that loader."""

    def test_dynamic_binary_is_refused(self) -> None:
        """A PT_INTERP segment names a loader, so the binary isn't static."""
        segments = ((PT_INTERP, 1), (PT_LOAD, ALIGN_64K))
        self.write("linux_amd64", "landfall-agent", elf(AMD64, segments))
        self.assert_one_failure("linux_amd64/landfall-agent", "PT_INTERP")


class ArchitectureTests(DistTestCase):
    """A file must be built for the platform its directory names."""

    def test_wrong_architecture_for_its_directory_is_refused(self) -> None:
        """Both ways round: this is the mistake a swapped matrix entry would make."""
        for directory, machine in (("linux_arm64", AMD64), ("linux_amd64", ARM64)):
            with self.subTest(directory=directory):
                self.write(directory, "landfall", elf(machine))
                self.assert_one_failure(f"{directory}/landfall", "e_machine")
                self.write(directory, "landfall", elf(MACHINES[directory]))

    def test_32_bit_is_refused(self) -> None:
        """Neither platform here is 32-bit, and the offsets below would mean something else."""
        self.write("linux_amd64", "landfall", elf(AMD64, elf_class=1))
        self.assert_one_failure("linux_amd64/landfall", "64-bit")

    def test_big_endian_is_refused(self) -> None:
        """Neither platform here is big-endian."""
        self.write("linux_arm64", "landfall", elf(ARM64, data=2))
        self.assert_one_failure("linux_arm64/landfall", "little-endian")


class PageSizeTests(DistTestCase):
    """An arm64 kernel with 16 KiB pages can't load segments aligned to 4 KiB."""

    def test_arm64_load_segments_must_suit_16k_pages(self) -> None:
        """Refused at 4 KiB, accepted from 16 KiB up, and amd64 is unaffected."""
        name = "landfall-agent"
        self.write("linux_arm64", name, elf(ARM64, ((PT_LOAD, ALIGN_4K),)))
        self.assert_one_failure("linux_arm64/landfall-agent", "p_align", "0x1000")

        for accepted in (ALIGN_16K, ALIGN_64K):
            self.write("linux_arm64", name, elf(ARM64, ((PT_LOAD, accepted),)))
            self.assertEqual(check_binaries.check_dist(self.dist), [])

        self.write("linux_amd64", name, elf(AMD64, ((PT_LOAD, ALIGN_4K),)))
        self.assertEqual(check_binaries.check_dist(self.dist), [])

    def test_only_load_segments_need_the_alignment(self) -> None:
        """A real static binary has a TLS segment with a small alignment, and that is fine."""
        segments = ((PT_LOAD, ALIGN_64K), (PT_TLS, 8))
        self.write("linux_arm64", "landfall", elf(ARM64, segments))
        self.assertEqual(check_binaries.check_dist(self.dist), [])

    def test_one_bad_load_segment_among_good_ones_is_refused(self) -> None:
        """Every load segment counts, not only the first."""
        segments = ((PT_LOAD, ALIGN_64K), (PT_LOAD, ALIGN_4K))
        self.write("linux_arm64", "landfall", elf(ARM64, segments))
        self.assert_one_failure("linux_arm64/landfall", "p_align")


class FaultCountTests(DistTestCase):
    """A fault is reported once, however many segments have it."""

    def test_several_bad_load_segments_are_one_failure_with_the_smallest_alignment(self) -> None:
        """A real binary has four load segments, and four like lines say nothing more."""
        segments = ((PT_LOAD, ALIGN_4K), (PT_LOAD, 0x200), (PT_LOAD, ALIGN_4K))
        self.write("linux_arm64", "landfall", elf(ARM64, segments))
        self.assert_one_failure("linux_arm64/landfall", "0x200")


class BudgetTests(DistTestCase):
    """Each binary has its own size budget."""

    def test_over_budget_is_refused_by_name(self) -> None:
        """A size within the server's budget is still over the agent's."""
        budgets = {"landfall-agent": 1000, "landfall": 1000, "landfall-server": 5000}
        padded = elf(AMD64) + bytes(2000)
        with mock.patch.dict(check_binaries.MAX_BYTES, budgets):
            self.write("linux_amd64", "landfall-agent", padded)
            self.assert_one_failure("linux_amd64/landfall-agent", "2120", "1000")
            self.write("linux_amd64", "landfall-agent", elf(AMD64))
            self.write("linux_amd64", "landfall-server", padded)
            self.assertEqual(check_binaries.check_dist(self.dist), [])

    def test_a_size_equal_to_the_budget_passes(self) -> None:
        """The budget is a maximum, not a limit to stay below."""
        content = elf(AMD64)
        with mock.patch.dict(check_binaries.MAX_BYTES, {"landfall": len(content)}):
            self.write("linux_amd64", "landfall", content)
            self.write("linux_arm64", "landfall", elf(ARM64))
            self.assertEqual(check_binaries.check_dist(self.dist), [])

    def test_every_binary_has_a_budget(self) -> None:
        """A name missing here would read as an unknown binary on every build."""
        self.assertEqual(sorted(check_binaries.MAX_BYTES), sorted(NAMES))


class LayoutTests(DistTestCase):
    """The dist must hold exactly the expected files, so a missing one can't pass unseen."""

    def test_unknown_binary_name_is_refused(self) -> None:
        """A stray file would otherwise be published or ignored without anyone deciding."""
        self.write("linux_amd64", "landfall-extra", elf(AMD64))
        self.assert_one_failure("linux_amd64/landfall-extra", "unknown")

    def test_missing_binary_is_refused(self) -> None:
        """A build that produced nothing must not pass because there was nothing to check."""
        (self.dist / "linux_arm64" / "landfall").unlink()
        self.assert_one_failure("linux_arm64/landfall", "missing")

    def test_missing_directory_is_refused(self) -> None:
        """An empty dist has no files to fail on, and must fail anyway."""
        for name in NAMES:
            (self.dist / "linux_amd64" / name).unlink()
        (self.dist / "linux_amd64").rmdir()
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

    def test_program_headers_past_the_end_of_the_file_are_refused(self) -> None:
        """Offsets in the header are read from the file, so they can say anything."""
        content = elf(AMD64)
        huge_offset = with_header_field(content, 32, struct.pack("<Q", 2**64 - 1))
        huge_count = with_header_field(content, 56, struct.pack("<H", 0xFFFF))
        for broken in (huge_offset, huge_count):
            self.write("linux_amd64", "landfall", broken)
            self.assert_one_failure("linux_amd64/landfall", "truncated")

    def test_an_unexpected_program_header_size_is_refused(self) -> None:
        """The entries would be read at the wrong offsets."""
        content = with_header_field(elf(AMD64), 54, struct.pack("<H", 32))
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
        self.write("linux_arm64", "landfall", elf(ARM64, ((PT_INTERP, 1), (PT_LOAD, ALIGN_4K))))
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
