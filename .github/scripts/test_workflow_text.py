"""The reader must find what's there, or the workflow tests prove nothing."""

import unittest

from workflow_text import block, job, needed, needs_of, significant, step_index, steps


class ReadingTests(unittest.TestCase):
    """The reader must find what's there, or the tests above prove nothing."""

    TEXT = """on:
jobs:
  first:
    needs:
      - a
      - b
    steps:
      - name: One # a comment
        run: |
          echo one
      - run: echo two
  second:
    steps:
      - run: echo three
"""

    def test_needs_are_read_in_each_form_and_through_each_other(self) -> None:
        """A list, a single name and a flow list, and what those need in turn."""
        lines = significant(
            "jobs:\n  a:\n    steps:\n  b:\n    needs: a\n  c:\n    needs: [b, a]\n"
            "  d:\n    needs:\n      - c\n"
        )
        self.assertEqual(needs_of(job(lines, "a")), set())
        self.assertEqual(needs_of(job(lines, "c")), {"a", "b"})
        self.assertEqual(needed(lines, "d"), {"a", "b", "c"})

    def test_jobs_and_steps_are_read_by_indentation(self) -> None:
        """Each step whole, and a job stopping where the next starts."""
        lines = significant(self.TEXT)
        first = job(lines, "first")
        self.assertEqual(block(first, "needs"), ["- a", "- b"])
        self.assertEqual(
            steps(first),
            [
                ["      - name: One", "        run: |", "          echo one"],
                ["      - run: echo two"],
            ],
        )
        self.assertEqual(steps(job(lines, "second")), [["      - run: echo three"]])

    def test_a_job_that_is_not_there_fails(self) -> None:
        """A renamed job isn't a job that passes."""
        with self.assertRaises(ValueError):
            job(significant(self.TEXT), "third")

    def test_a_piece_in_no_step_or_two_fails(self) -> None:
        """The order test can't pass by finding nothing."""
        step_list = steps(job(significant(self.TEXT), "first"))
        with self.assertRaises(AssertionError):
            step_index(step_list, "absent")
        with self.assertRaises(AssertionError):
            step_index(step_list, "echo")


if __name__ == "__main__":
    unittest.main()
