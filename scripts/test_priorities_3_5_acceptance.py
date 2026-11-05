#!/usr/bin/env python3
"""Behavioral controls for the completed terminal-suite evidence boundary."""

import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location(
    "release_acceptance", Path(__file__).with_name("priorities_3_5_acceptance.py")
)
acceptance = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(acceptance)


class LegacyOutputTests(unittest.TestCase):
    def output(self, passes=83, summary=None, extra=()):
        return "\n".join(
            ["mock provider: started"]
            + [f"PASS observed check {index}" for index in range(passes)]
            + list(extra)
            + [summary or f"Results: {passes} passed, 0 failed, 0 not run", ""]
        )

    def validate(self, output, name="terminal-original", minimum=83):
        return acceptance.validate_output(
            {"validator": "legacy", "name": name, "minimum": minimum}, output
        )

    def test_accepts_complete_expanded_terminal_suite(self):
        result = self.validate(self.output(passes=628))
        self.assertEqual(result["passed"], 628)
        self.assertEqual(len(result["checks"]), 628)

    def test_accepts_complete_composer_and_effort_summary_formats(self):
        cases = (
            ("composer-original", 25, 56, "== Results: 56 passed, 0 failed =="),
            ("effort-original", 41, 41, "Results: 41 passed"),
        )
        for name, minimum, passed, summary in cases:
            with self.subTest(name=name):
                result = self.validate(self.output(passed, summary), name, minimum)
                self.assertEqual(result["passed"], passed)

    def test_rejects_nonzero_not_run_summary(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(summary="Results: 83 passed, 0 failed, 1 not run"))

    def test_rejects_not_run_record_even_when_summary_claims_zero(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("  NOTRUN prerequisite was unavailable",)))

    def test_rejects_summary_claiming_more_passes_than_observed(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(summary="Results: 628 passed, 0 failed, 0 not run"))

    def test_rejects_more_pass_records_than_summary_claims(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(passes=84, summary="Results: 83 passed, 0 failed"))

    def test_rejects_duplicate_summaries(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("Results: 83 passed, 0 failed, 0 not run",)))

    def test_rejects_contradictory_summaries(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("Results: 82 passed, 1 failed, 0 not run",)))

    def test_rejects_additional_malformed_summary(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("Results: malformed",)))

    def test_rejects_not_run_record_without_description(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("NOTRUN",)))

    def test_rejects_failed_summary(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(summary="Results: 83 passed, 1 failed, 0 not run"))

    def test_rejects_failed_record_even_when_summary_claims_zero(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("  FAIL observed failure",)))

    def test_rejects_suite_below_its_coverage_floor(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(passes=82))

    def test_rejects_reused_unrelated_mock_provider(self):
        with self.assertRaises(acceptance.EvidenceError):
            self.validate(self.output(extra=("mock provider: already running",)))


if __name__ == "__main__":
    unittest.main()
