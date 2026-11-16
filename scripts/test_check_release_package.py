"""Packaging must not replace the binaries that passed installed acceptance."""

import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from check_release_package import check_package, RECEIPT_PREFIX
from package_install_bundle import package


class CandidateIdentityContracts(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="orbit-candidate-identity-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.inputs = {}
        for name in ("orbit", "orbit-web"):
            path = self.root / name
            path.write_bytes((name + " accepted executable bytes").encode())
            path.chmod(0o700)
            self.inputs[name] = path
        self.receipt = {
            "binary_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest()
                              for name, path in self.inputs.items()},
            "version": "0.2.1", "target": "x86_64-unknown-linux-gnu",
            "scenarios": {f"scenario-{i}": {"passed": True, "assertions": 1} for i in range(12)},
        }
        self.log = self.root / "installed-release.log"
        self.write_log()
        self.output = self.root / "package"
        self.archive = package(self.inputs["orbit"], self.inputs["orbit-web"],
                               self.receipt["version"], self.receipt["target"], self.output)

    def write_log(self):
        self.log.write_text("PASS fixture\n" + RECEIPT_PREFIX + json.dumps(self.receipt) + "\n")

    def rewrite_archive(self, transform):
        with tarfile.open(self.archive, "r:gz") as bundle:
            entries = [(member.name, bundle.extractfile(member).read()) for member in bundle]
        with tarfile.open(self.archive, "w:gz") as bundle:
            for name, data in transform(entries):
                item = tarfile.TarInfo(name)
                item.size = len(data)
                bundle.addfile(item, io.BytesIO(data))
        digest = hashlib.sha256(self.archive.read_bytes()).hexdigest()
        self.archive.with_name(self.archive.name + ".sha256").write_text(
            f"{digest}  {self.archive.name}\n")

    def test_exact_installed_bytes_and_unsigned_manifest_pass(self):
        manifest = check_package(self.log, self.output)
        self.assertEqual(manifest["signature"], "absent")
        self.assertEqual(manifest["components"]["orbit"]["sha256"],
                         self.receipt["binary_sha256"]["orbit"])

    def test_rebuild_after_acceptance_cannot_publish_different_bytes(self):
        self.inputs["orbit"].write_bytes(b"different executable with the same source version")
        changed = self.root / "rebuilt-package"
        package(self.inputs["orbit"], self.inputs["orbit-web"],
                self.receipt["version"], self.receipt["target"], changed)
        with self.assertRaisesRegex(ValueError, "installed-tested"):
            check_package(self.log, changed)

    def test_matching_archive_checksum_cannot_hide_a_lying_component_manifest(self):
        self.rewrite_archive(lambda entries: [(name, data + b"changed" if name == "orbit" else data)
                                              for name, data in entries])
        with self.assertRaisesRegex(ValueError, "manifest does not describe"):
            check_package(self.log, self.output)

    def test_missing_or_duplicate_receipts_are_rejected(self):
        for text in ("PASS fixture only\n", self.log.read_text() * 2):
            with self.subTest(text=text):
                self.log.write_text(text)
                with self.assertRaisesRegex(ValueError, "exactly one installed"):
                    check_package(self.log, self.output)

    def test_failed_or_empty_scenarios_cannot_be_an_acceptance_receipt(self):
        for scenarios in ({}, {"only-one": {"passed": True, "assertions": 1}},
                          {**self.receipt["scenarios"], "failure": {"passed": False, "assertions": 1}}):
            with self.subTest(scenarios=scenarios):
                self.receipt["scenarios"] = scenarios
                self.write_log()
                with self.assertRaisesRegex(ValueError, "scenarios did not pass"):
                    check_package(self.log, self.output)

    def test_receipt_version_and_target_must_describe_the_candidate(self):
        for key, value in (("version", "0.2.2"), ("target", "aarch64-unknown-linux-gnu")):
            with self.subTest(key=key):
                original = self.receipt[key]
                self.receipt[key] = value
                self.write_log()
                with self.assertRaisesRegex(ValueError, "does not match"):
                    check_package(self.log, self.output)
                self.receipt[key] = original

    def test_duplicate_archive_members_are_rejected(self):
        self.rewrite_archive(lambda entries: entries + [entries[0]])
        with self.assertRaisesRegex(ValueError, "duplicate archive member"):
            check_package(self.log, self.output)

    def test_wrong_archive_checksum_is_rejected(self):
        self.archive.with_name(self.archive.name + ".sha256").write_text("0" * 64 + "\n")
        with self.assertRaisesRegex(ValueError, "checksum does not match"):
            check_package(self.log, self.output)

    def test_additional_candidate_archives_are_rejected(self):
        (self.output / "extra.tar.gz").write_bytes(b"unreviewed")
        with self.assertRaisesRegex(ValueError, "exactly one candidate"):
            check_package(self.log, self.output)


if __name__ == "__main__":
    unittest.main()
