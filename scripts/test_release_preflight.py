"""A blocked fixture must never be reported as a verified release."""

import errno
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import release_preflight as preflight


class PreflightContracts(unittest.TestCase):
    def test_restrictions_are_reported_and_other_checks_still_run(self):
        visited = []

        def blocked():
            raise PermissionError(errno.EPERM, "fixture socket denied")

        report = preflight.check_environment((
            ("socket", blocked), ("next", lambda: visited.append(True)),
        ))
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["checks"][0]["status"], "blocked")
        self.assertIn("fixture socket denied", report["checks"][0]["reason"])
        self.assertEqual(report["checks"][1]["status"], "passed")
        self.assertEqual(visited, [True])

    def test_success_only_claims_environment_readiness(self):
        report = preflight.check_environment((("fixture", lambda: None),))
        self.assertEqual(report["status"], "ready")
        self.assertEqual(report["scope"], "test_environment_only")
        self.assertNotIn("release_ready", report)

    def test_empty_checks_cannot_pass(self):
        self.assertEqual(preflight.check_environment(())["status"], "blocked")

    def test_unexpected_programming_errors_fail_instead_of_becoming_skips(self):
        def broken():
            raise ValueError("bug in a check")
        with self.assertRaisesRegex(ValueError, "bug in a check"):
            preflight.check_environment((("broken", broken),))

    def test_storage_probe_cleans_its_files(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(tempfile, "tempdir", directory):
                preflight.temporary_storage()
            self.assertEqual(list(Path(directory).iterdir()), [])

    def test_blocked_preflight_has_nonzero_exit_status(self):
        with patch.object(preflight, "check_environment", return_value={"status": "blocked"}):
            with patch("builtins.print"):
                self.assertEqual(preflight.main(), 2)


if __name__ == "__main__":
    unittest.main()
