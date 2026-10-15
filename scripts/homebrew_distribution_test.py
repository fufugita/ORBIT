#!/usr/bin/env python3
"""Validate an ORBIT tap with Homebrew itself; never installs or upgrades packages."""

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def run(brew, *arguments):
    environment = os.environ.copy()
    environment["HOMEBREW_NO_AUTO_UPDATE"] = "1"
    environment["HOMEBREW_NO_ANALYTICS"] = "1"
    result = subprocess.run(
        [str(brew), *arguments],
        check=True,
        capture_output=True,
        text=True,
        env=environment,
        timeout=120,
    )
    return result.stdout


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--brew", type=Path, help="Homebrew executable, including a disposable installation")
    parser.add_argument("--formula", default="fufugita/orbit/orbit", help="Formula in the installed tap")
    parser.add_argument(
        "--installed",
        action="store_true",
        help="Also run the formula's actual installed-binary tests (run inside scripts/in-jail.sh)",
    )
    options = parser.parse_args()
    brew = options.brew or shutil.which("brew")
    if not brew:
        parser.error("Homebrew is unavailable; supply --brew or install Homebrew before running this check")
    brew = Path(brew).resolve(strict=True)

    metadata = json.loads(run(brew, "info", "--json=v2", "--formula", options.formula))
    formulae = metadata.get("formulae", [])
    if len(formulae) != 1:
        raise AssertionError("expected exactly one formula")
    formula = formulae[0]
    if formula.get("name") != "orbit":
        raise AssertionError("Homebrew resolved a different formula")
    if formula.get("full_name") != "fufugita/orbit/orbit":
        raise AssertionError("Homebrew resolved a different tap")
    if formula.get("versions", {}).get("stable") is not None:
        raise AssertionError("HEAD-only installation must not advertise an unpublished stable release")
    head = formula.get("urls", {}).get("head", {})
    if head.get("url") != "https://github.com/fufugita/ORBIT.git" or head.get("branch") != "main":
        raise AssertionError("development source is not the public main branch")
    head_dependencies = formula.get("head_dependencies", {})
    if "rust" not in head_dependencies.get("build_dependencies", []):
        raise AssertionError("the HEAD source install must declare its Rust build dependency")
    requirements = formula.get("requirements", [])
    if not any(
        requirement.get("name") == "linux"
        and "head" in requirement.get("specs", [])
        and not requirement.get("contexts")
        for requirement in requirements
    ):
        raise AssertionError("formula must require Linux throughout its HEAD installation")

    checks = ["real_homebrew_formula_metadata"]
    if options.installed:
        if not formula.get("installed"):
            raise AssertionError("--installed requires an installed formula; this script does not install it")
        run(brew, "test", options.formula)
        checks.append("real_homebrew_installed_binary_tests")
    print(json.dumps({"status": "passed", "checks": checks}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, subprocess.SubprocessError, ValueError) as error:
        print(f"Homebrew distribution check failed: {error}", file=sys.stderr)
        if isinstance(error, subprocess.CalledProcessError) and error.stderr:
            print(error.stderr.rstrip(), file=sys.stderr)
        raise SystemExit(1)
