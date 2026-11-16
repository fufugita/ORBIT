"""Release coverage must reject missing, skipped, failed, and ambiguous results."""

import json
import unittest

from check_release_test_log import REQUIRED, check_log


def successful_log():
    return "\n".join(f"test {name} ... ok" for name in REQUIRED)


def isolation_receipt(name, **changes):
    report = {
        "schema": "orbit.context-session-isolation/v1",
        "status": "TEST_PASSED",
        "test_filter": name,
        "test_started": True,
        "harness": {"status": "ok", "passed": 1, "failed": 0, "ignored": 0},
        "binary_metadata_and_hash_unchanged": True,
        "host_managed_path_metadata_unchanged": True,
        "owned_fixture_removed": True,
    }
    report.update(changes)
    return "ORBIT_CONTEXT_SESSION_ISOLATION " + json.dumps(report)


def with_isolated_result(name, receipt=None, ending="ok"):
    if receipt is None:
        receipt = isolation_receipt(name)
    return successful_log().replace(
        f"test {name} ... ok", f"test {name} ... {receipt}\n{ending}"
    )


class ReleaseTestLogContracts(unittest.TestCase):
    def test_all_required_results_pass_with_normal_cargo_noise(self):
        check_log("Compiling orbit\nrunning tests\n" + successful_log() +
                  "\ntest other::test ... ok\ntest result: ok\n")

    def test_colored_results_pass(self):
        check_log(successful_log().replace(" ... ok", " ... \x1b[32mok\x1b[0m"))

    def test_missing_required_test_fails(self):
        for name in REQUIRED:
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, "missing"):
                check_log(successful_log().replace(f"test {name} ... ok", ""))

    def test_ignored_failed_and_filtered_results_do_not_count(self):
        for status in ("ignored", "ignored, no terminal", "FAILED", "filtered out"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                check_log(successful_log().replace(" ... ok", f" ... {status}", 1))

    def test_conflicting_or_duplicate_results_cannot_hide_a_failed_run(self):
        for status in ("ok", "FAILED", "ignored"):
            with self.subTest(status=status), self.assertRaises(ValueError):
                check_log(successful_log() + f"\ntest {REQUIRED[0]} ... {status}")

    def test_empty_log_and_summary_only_fail(self):
        for text in ("", "test result: ok. 100 passed; 0 failed", "running 0 tests"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                check_log(text)

    def test_serial_isolation_receipt_precedes_the_final_libtest_ok(self):
        text = successful_log()
        for name in REQUIRED[:3]:
            text = text.replace(f"test {name} ... ok",
                                f"test {name} ... {isolation_receipt(name)}\nok")
        check_log(text)
        check_log(text.replace("\nok", "\n\x1b[32mok\x1b[0m"))

    def test_isolation_receipt_alone_does_not_establish_a_pass(self):
        for ending in ("", "FAILED", "ignored", "test unrelated ... ok",
                       "test result: ok. 1 passed; 0 failed; 0 ignored;"):
            with self.subTest(ending=ending), self.assertRaises(ValueError):
                check_log(with_isolated_result(REQUIRED[0], ending=ending))

    def test_isolation_report_must_match_the_test_and_all_safety_checks(self):
        changes = (
            {"schema": "other/v1"}, {"status": "NOTRUN"},
            {"status": "TEST_FAILED"}, {"status": "INFRA_FAILURE"},
            {"test_filter": REQUIRED[1]}, {"test_started": False},
            {"binary_metadata_and_hash_unchanged": False},
            {"host_managed_path_metadata_unchanged": False},
            {"owned_fixture_removed": False},
            {"harness": {"status": "ok", "passed": 0, "failed": 0, "ignored": 1}},
            {"harness": {"status": "FAILED", "passed": 1, "failed": 1, "ignored": 0}},
        )
        for change in changes:
            with self.subTest(change=change), self.assertRaises(ValueError):
                check_log(with_isolated_result(
                    REQUIRED[0], isolation_receipt(REQUIRED[0], **change)))

    def test_malformed_isolation_reports_fail_closed(self):
        for payload in ("{", "[]", "null", "{}", '"TEST_PASSED"'):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                check_log(with_isolated_result(
                    REQUIRED[0], "ORBIT_CONTEXT_SESSION_ISOLATION " + payload))

    def test_duplicate_isolated_passes_are_rejected(self):
        name = REQUIRED[0]
        with self.assertRaises(ValueError):
            check_log(with_isolated_result(name) +
                      f"\ntest {name} ... {isolation_receipt(name)}\nok")

    def test_an_unrelated_ok_cannot_complete_an_interrupted_result(self):
        name = REQUIRED[0]
        with self.assertRaises(ValueError):
            check_log(with_isolated_result(
                name, ending="test unrelated ... diagnostic\nok"))

    def test_isolation_reports_do_not_replace_confinement_results(self):
        name = REQUIRED[3]
        with self.assertRaises(ValueError):
            check_log(with_isolated_result(name))


if __name__ == "__main__":
    unittest.main()
