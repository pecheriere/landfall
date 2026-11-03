"""Counting what `cargo test` says passed, on the kind of log CI really gets."""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "count_passed.py"

# A script's line landing between `test x ... ` and `ok`, which counting lines would miss: a whole
# run of 25 that passed, as it read 24 that way. Other test targets print a line of their own.
LOG = """\
running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 224 filtered out; finished in 0.00s

running 3 tests
test install::docker_one ... ok
test interrupts::docker_two ... landfall: step 3: state
ok
landfall: step 4: config
test connection::docker_three ... ok

test result: ok. 25 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 134.66s

running 0 tests

test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 0.00s
"""


def count(log: str, minimum: int) -> subprocess.CompletedProcess[str]:
    """Run the script on `log`, as CI does."""
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "log.txt"
        path.write_text(log, encoding="utf-8")
        return subprocess.run(
            [sys.executable, "-I", str(SCRIPT), str(path), str(minimum)],
            capture_output=True,
            text=True,
            check=False,
        )


class CountPassed(unittest.TestCase):
    """What it counts, and what it refuses."""

    def test_a_line_landing_inside_a_tests_own_line_changes_nothing(self) -> None:
        """The log that read 24 by its lines is 25."""
        ran = count(LOG, 25)
        self.assertEqual(ran.returncode, 0, ran.stderr)
        self.assertIn("25 tests passed", ran.stdout)

    def test_too_few_fail(self) -> None:
        """One short fails, saying how many there were."""
        ran = count(LOG, 26)
        self.assertEqual(ran.returncode, 1)
        self.assertIn("25 tests passed", ran.stderr)

    def test_results_of_several_targets_are_added_up(self) -> None:
        """Each test target has its own line."""
        log = "test result: ok. 2 passed; 0 failed\ntest result: ok. 3 passed; 0 failed\n"
        self.assertEqual(count(log, 5).returncode, 0)
        self.assertEqual(count(log, 6).returncode, 1)

    def test_a_filter_that_matches_nothing_fails(self) -> None:
        """No test run is what the count is there for."""
        self.assertEqual(count("test result: ok. 0 passed; 0 failed\n", 1).returncode, 1)

    def test_a_failed_run_counts_nothing(self) -> None:
        """`pipefail` stops the job first, and this doesn't rely on that."""
        log = "test result: FAILED. 24 passed; 1 failed; 0 ignored\n"
        self.assertEqual(count(log, 1).returncode, 1)

    def test_bytes_that_are_not_text_do_not_stop_it(self) -> None:
        """A script can print anything."""
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "log.txt"
            path.write_bytes(b"\xff\xfe\ntest result: ok. 1 passed\n")
            ran = subprocess.run(
                [sys.executable, "-I", str(SCRIPT), str(path), "1"],
                capture_output=True,
                check=False,
            )
        self.assertEqual(ran.returncode, 0)


if __name__ == "__main__":
    unittest.main()
