#!/usr/bin/env python3
"""Run counted checks without treating an empty test selection as success."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def resource_gate():
    memory = dict(
        line.split(":", 1) for line in Path("/proc/meminfo").read_text().splitlines()
    )
    available = int(memory["MemAvailable"].split()[0]) * 1024
    pressure = Path("/proc/pressure/memory").read_text()
    full = next(line for line in pressure.splitlines() if line.startswith("full "))
    avg10 = float(dict(item.split("=", 1) for item in full.split()[1:])["avg10"])
    if available < 3 * 1024**3 or avg10 >= 5:
        raise ValueError(f"resource gate failed: available={available}, full avg10={avg10}")
    print(f"resource gate passed: available={available}, full avg10={avg10}", flush=True)


def run_command(command):
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        raise ValueError("a command is required after --")
    child = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    lines = []
    for raw in iter(child.stdout.readline, b""):
        line = raw.decode("utf-8", errors="replace")
        sys.stdout.write(line)
        sys.stdout.flush()
        lines.append(line)
    return child.wait(), "".join(lines)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate receipt key: {key}")
        result[key] = value
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_subparsers(dest="mode", required=True)
    modes.add_parser("gate")
    cargo = modes.add_parser("cargo")
    cargo.add_argument("--min-tests", type=int, required=True)
    cargo.add_argument("command", nargs=argparse.REMAINDER)
    script = modes.add_parser("script")
    script.add_argument("--receipt", type=Path)
    script.add_argument("--scenario", action="append", default=[])
    script.add_argument("--min-checks", type=int)
    script.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    resource_gate()
    if args.mode == "gate":
        return 0
    if args.mode == "script" and args.receipt:
        # Remove stale evidence before launch: the child must create this run's receipt.
        args.receipt.unlink(missing_ok=True)
    code, output = run_command(args.command)
    if code:
        return code if code > 0 else 128 - code
    if args.mode == "cargo":
        summaries = re.findall(
            r"test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored;", output
        )
        passed = sum(int(item[1]) for item in summaries)
        if args.min_tests < 1 or not summaries or passed < args.min_tests:
            raise ValueError(f"only {passed} tests executed; require {args.min_tests}")
        if any(status != "ok" or int(failed) for status, _, failed, _ in summaries):
            raise ValueError("test summaries contain failures")
        print(f"counted acceptance: {passed} passed tests", flush=True)
    else:
        if args.receipt:
            receipt = json.loads(args.receipt.read_text(), object_pairs_hook=unique_object)
        else:
            markers = [line.removeprefix("ORBIT_CHECK_RECEIPT ") for line in output.splitlines()
                       if line.startswith("ORBIT_CHECK_RECEIPT ")]
            if len(markers) != 1:
                raise ValueError("require exactly one fresh ORBIT_CHECK_RECEIPT JSON marker")
            receipt = json.loads(markers[0], object_pairs_hook=unique_object)
        if not isinstance(receipt, dict):
            raise ValueError("receipt must be an object")
        scenarios = receipt.get("scenarios", {})
        if not isinstance(scenarios, dict) or not scenarios:
            raise ValueError("receipt must contain distinct named scenarios")
        if args.min_checks is not None and (args.min_checks < 1 or len(scenarios) < args.min_checks):
            raise ValueError(f"only {len(scenarios)} scenarios; require {args.min_checks}")
        if args.min_checks is None and not args.scenario:
            raise ValueError("require --min-checks or --scenario")
        for name in set(scenarios) | set(args.scenario):
            if not isinstance(name, str) or not name or len(name) > 128:
                raise ValueError("scenario names must be nonempty and bounded")
            result = scenarios.get(name)
            if not isinstance(result, dict) or result.get("passed") is not True:
                raise ValueError(f"missing or failed scenario: {name}")
            if type(result.get("assertions")) is not int or result["assertions"] < 1:
                raise ValueError(f"scenario has no assertions: {name}")
            if result.get("ignored") or result.get("skipped"):
                raise ValueError(f"scenario was not executed: {name}")
        print(f"counted acceptance: {len(scenarios)} scenario receipts", flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, StopIteration) as error:
        print(f"verification failed: {error}", file=sys.stderr)
        sys.exit(1)
