#!/usr/bin/env python3
"""Require the release's terminal and confinement tests in a successful Cargo log.

The caller must also require Cargo's zero exit status and set
ORBIT_REQUIRE_SANDBOX=1 and ORBIT_REQUIRE_CONTEXT_SESSION_ISOLATION=1 so
unavailable confinement or isolation cannot return a passing skip. Isolated
terminal receipts are emitted directly between the libtest prefix and its
final status when tests run serially; both the receipt and final ok are required.
This checks coverage, not source review or release approval.
"""

import argparse
import json
from pathlib import Path
import re


REQUIRED = (
    "frontend_manual_baselines::real_terminal_compact_reaches_checked_cells_and_exact_durable_summary",
    "frontend_manual_baselines::real_terminal_escape_after_observed_post_retains_uncertain_original_and_cells",
    "frontend_manual_baselines::real_terminal_clear_shows_fresh_known_zero_and_preserves_old_source_bytes",
    "sandbox::tests::an_added_tool_runs_by_name_and_writes_only_where_allowed",
    "sandbox::tests::confined_command_runs_and_writes_only_where_allowed",
    "sandbox::tests::network_is_unshared_by_default",
)


ISOLATION_PREFIX = "ORBIT_CONTEXT_SESSION_ISOLATION "


def isolation_passed(status, name):
    try:
        report = json.loads(status.removeprefix(ISOLATION_PREFIX))
    except ValueError:
        return False
    return (
        isinstance(report, dict)
        and report.get("schema") == "orbit.context-session-isolation/v1"
        and report.get("test_filter") == name
        and report.get("status") == "TEST_PASSED"
        and report.get("harness") == {
            "status": "ok", "passed": 1, "failed": 0, "ignored": 0
        }
        and all(report.get(key) is True for key in (
            "test_started", "binary_metadata_and_hash_unchanged",
            "host_managed_path_metadata_unchanged", "owned_fixture_removed",
        ))
    )


def check_log(text):
    results = {name: [] for name in REQUIRED}
    pending = None
    for line in re.sub(r"\x1b\[[0-9;]*m", "", text).splitlines():
        line = line.strip()
        if pending is not None:
            # Only the next line can close the serial libtest result. Never
            # borrow an ok from another test or accept the receipt by itself.
            results[pending].append("ok" if line == "ok" else "missing final ok")
            pending = None
            if line == "ok":
                continue
        match = re.fullmatch(r"test (\S+) \.\.\. (.+)", line)
        if match and match[1] in results:
            name, status = match.groups()
            if name in REQUIRED[:3] and status.startswith(ISOLATION_PREFIX):
                if isolation_passed(status, name):
                    pending = name
                else:
                    results[name].append("invalid isolation receipt")
            else:
                results[name].append(status)
    if pending is not None:
        results[pending].append("missing final ok")
    invalid = {name: statuses for name, statuses in results.items() if statuses != ["ok"]}
    if invalid:
        details = "; ".join(f"{name}: {', '.join(statuses) or 'missing'}"
                            for name, statuses in invalid.items())
        raise ValueError("Required release tests did not pass exactly once: " + details)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        check_log(args.log.read_text())
    except (OSError, ValueError) as error:
        parser.exit(1, f"{error}\n")
    print(f"All {len(REQUIRED)} required terminal and sandbox tests reported ok.")


if __name__ == "__main__":
    main()
