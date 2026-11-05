#!/usr/bin/env python3
"""Preserve the selected Homebrew launcher's installation-prefix semantics."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


SCRIPT = Path(__file__).with_name("homebrew_distribution_test.py")


def metadata(installed):
    return {"formulae": [{
        "name": "orbit", "full_name": "fufugita/orbit/orbit",
        "versions": {"stable": None},
        "urls": {"head": {"url": "https://github.com/fufugita/ORBIT.git", "branch": "main"}},
        "head_dependencies": {"build_dependencies": ["rust"]},
        "requirements": [{"name": "linux", "specs": ["head"], "contexts": []}],
        "installed": installed,
    }]}


class SelectedLauncherTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="orbit brew launcher ")
        self.addCleanup(temporary.cleanup)
        self.prefix = Path(temporary.name) / ".linuxbrew"
        self.real = self.prefix / "Homebrew/bin/brew"
        self.real.parent.mkdir(parents=True)
        (self.prefix / "bin").mkdir()
        (self.prefix / "Cellar/orbit/HEAD-fixture").mkdir(parents=True)
        installed = json.dumps(metadata([{"version": "HEAD-fixture"}]))
        empty = json.dumps(metadata([]))
        # Like Homebrew's launcher, $0 selects the prefix independently of the
        # executable's final symlink target. The resolved prefix has no Cellar.
        self.real.write_text(f'''#!/bin/sh
set -eu
prefix=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)
case "$1" in
  info)
    if [ -d "$prefix/Cellar/orbit/HEAD-fixture" ]; then
      printf '%s\\n' '{installed}'
    else
      printf '%s\\n' '{empty}'
    fi
    ;;
  test) test -d "$prefix/Cellar/orbit/HEAD-fixture" ;;
  *) exit 2 ;;
esac
''')
        self.real.chmod(0o755)
        self.selected = self.prefix / "bin/brew"
        self.selected.symlink_to(Path("../Homebrew/bin/brew"))

    def validate(self, executable):
        return subprocess.run(
            [sys.executable, str(SCRIPT), "--brew", str(executable), "--installed"],
            stdin=subprocess.DEVNULL, capture_output=True, text=True, timeout=10,
            env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"},
        )

    def test_selected_symlink_uses_its_installed_prefix(self):
        result = self.validate(self.selected)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {
            "status": "passed",
            "checks": ["real_homebrew_formula_metadata", "real_homebrew_installed_binary_tests"],
        })

    def test_explicit_resolved_launcher_with_empty_prefix_is_rejected(self):
        result = self.validate(self.real)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("--installed requires an installed formula", result.stderr)

    def test_nonexecutable_target_is_rejected(self):
        self.real.chmod(0o644)
        result = self.validate(self.selected)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Homebrew", result.stderr)


if __name__ == "__main__":
    unittest.main()
