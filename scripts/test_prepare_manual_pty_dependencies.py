#!/usr/bin/env python3
"""Offline filesystem and supply-chain controls for terminal fixture preparation."""

import hashlib
import importlib.util
import io
import json
from pathlib import Path
import shutil
import stat
import tempfile
import unittest
from unittest import mock
import zipfile


SPEC = importlib.util.spec_from_file_location(
    "prepare_manual_pty_dependencies", Path(__file__).with_name("prepare_manual_pty_dependencies.py")
)
preparation = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(preparation)


class FixturePreparationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # CI prepares this exact pinned tree explicitly before these offline controls.
        # Repacking its independently verified sources avoids storing vendor code in Git.
        preparation.verify_tree(preparation.DEFAULT_OUTPUT)
        manifest = json.loads((preparation.DEFAULT_OUTPUT / "manifest.json").read_text())
        cls.sources = {entry["path"]: (preparation.DEFAULT_OUTPUT / entry["path"]).read_bytes()
                       for entry in manifest["files"]}
        cls.cache = tempfile.TemporaryDirectory(prefix="orbit-pty-unit-wheels-")
        cls.addClassCleanup(cls.cache.cleanup)
        cls.wheels = []
        for original in preparation.WHEELS:
            wheel = dict(original)
            path = Path(cls.cache.name) / wheel["filename"]
            with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                for name, data in sorted(cls.sources.items()):
                    if name.startswith(wheel["package"] + "/"):
                        archive.writestr(name, data)
            wheel["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
            cls.wheels.append(wheel)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-pty-prepare-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.destination = self.root / "fixture"
        self.wheel_dir = self.root / "wheels"
        self.wheel_dir.mkdir(mode=0o700)
        self.pins = [dict(wheel) for wheel in self.wheels]
        for wheel in self.pins:
            shutil.copyfile(Path(self.cache.name) / wheel["filename"], self.wheel_dir / wheel["filename"])
        self.pin_patch = mock.patch.object(preparation, "WHEELS", tuple(self.pins))
        self.pin_patch.start()
        self.addCleanup(self.pin_patch.stop)
        self.network = mock.patch.object(preparation.urllib.request, "urlopen",
                                         side_effect=AssertionError("offline control attempted network access"))
        self.urlopen = self.network.start()
        self.addCleanup(self.network.stop)

    def prepare(self):
        return preparation.prepare(self.destination, self.wheel_dir)

    def replace_wheel_members(self, changes=(), addition=None):
        wheel = self.pins[0]
        path = self.wheel_dir / wheel["filename"]
        with zipfile.ZipFile(path) as archive:
            entries = [(entry, archive.read(entry)) for entry in archive.infolist()]
        updated = dict(changes)
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            for entry, data in entries:
                archive.writestr(entry, updated.get(entry.filename, data))
            if addition:
                archive.writestr(*addition)
        wheel["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()

    def test_prepares_exact_private_fixture_without_importing_packages(self):
        with mock.patch.dict("sys.modules", {"pyte": None, "wcwidth": None}):
            self.assertEqual(self.prepare(), "prepared")
        manifest = self.destination / "manifest.json"
        self.assertEqual(hashlib.sha256(manifest.read_bytes()).hexdigest(), preparation.MANIFEST_SHA256)
        actual = {path.relative_to(self.destination).as_posix()
                  for path in self.destination.rglob("*") if path.is_file()}
        self.assertEqual(actual, set(self.sources) | {"manifest.json"})
        for path in [self.destination, *self.destination.rglob("*")]:
            with self.subTest(path=path.relative_to(self.destination)):
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700 if path.is_dir() else 0o400)
        self.urlopen.assert_not_called()

    def test_valid_existing_tree_is_reused_without_wheels_or_writes(self):
        self.prepare()
        before = {str(path): path.stat() for path in [self.destination, *self.destination.rglob("*")]}
        with mock.patch.object(preparation, "wheel_bytes", side_effect=AssertionError("unexpected wheel read")):
            self.assertEqual(preparation.prepare(self.destination, self.root / "missing"), "reused")
        for name, expected in before.items():
            actual = Path(name).stat()
            self.assertEqual((actual.st_dev, actual.st_ino, actual.st_size, actual.st_mtime_ns, actual.st_ctime_ns),
                             (expected.st_dev, expected.st_ino, expected.st_size, expected.st_mtime_ns, expected.st_ctime_ns))

    def test_rejects_corrupted_wheel_before_publication(self):
        path = self.wheel_dir / self.pins[0]["filename"]
        data = path.read_bytes()
        path.write_bytes(data[:-1] + bytes([data[-1] ^ 1]))
        with self.assertRaisesRegex(preparation.PreparationError, "SHA256"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_missing_offline_wheel_never_falls_back_to_network(self):
        (self.wheel_dir / self.pins[0]["filename"]).unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.urlopen.assert_not_called()
        self.assertFalse(self.destination.exists())

    def test_rejects_changed_modules_even_with_a_matching_wheel_hash(self):
        name = next(name for name in self.sources if name.startswith("pyte/"))
        self.replace_wheel_members(changes=((name, self.sources[name] + b"\n# modified\n"),))
        with self.assertRaises(preparation.PreparationError):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_rejects_path_traversal_member(self):
        self.replace_wheel_members(addition=("pyte/../escaped.py", b"unexpected"))
        with self.assertRaisesRegex(preparation.PreparationError, "unsafe member"):
            self.prepare()
        self.assertFalse((self.root / "escaped.py").exists())
        self.assertFalse(self.destination.exists())

    def test_rejects_symlink_python_member(self):
        entry = zipfile.ZipInfo("pyte/linked.py")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        self.replace_wheel_members(addition=(entry, b"../outside"))
        with self.assertRaisesRegex(preparation.PreparationError, "regular file"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_rejects_symlink_wheel_file(self):
        path = self.wheel_dir / self.pins[0]["filename"]
        original = self.root / "original.whl"
        path.rename(original)
        path.symlink_to(original)
        with self.assertRaisesRegex(preparation.PreparationError, "no symlinks"):
            self.prepare()

    def test_rejects_invalid_existing_manifest_without_replacing_it(self):
        self.destination.mkdir(mode=0o700)
        path = self.destination / "manifest.json"
        path.write_bytes(b"{}\n")
        path.chmod(0o400)
        before = path.stat()
        with self.assertRaises(preparation.PreparationError):
            self.prepare()
        self.assertEqual(path.read_bytes(), b"{}\n")
        self.assertEqual(path.stat().st_ino, before.st_ino)

    def test_rejects_extra_files_in_existing_tree(self):
        self.prepare()
        extra = self.destination / "unexpected.py"
        extra.write_bytes(b"unexpected\n")
        extra.chmod(0o400)
        with self.assertRaises(preparation.PreparationError):
            self.prepare()
        self.assertTrue(extra.exists())

    def test_rejects_unsafe_existing_modes_without_repairing_them(self):
        self.prepare()
        self.destination.chmod(0o755)
        with self.assertRaises(preparation.PreparationError):
            self.prepare()
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o755)

    def test_rejects_symlink_destination_and_ancestor(self):
        outside = self.root / "outside"
        outside.mkdir(mode=0o700)
        for destination in (self.root / "linked", self.root / "linked" / "fixture"):
            with self.subTest(destination=destination):
                link = self.root / "linked"
                if not link.is_symlink():
                    link.symlink_to(outside, target_is_directory=True)
                with self.assertRaisesRegex(preparation.PreparationError, "no symlinks"):
                    preparation.prepare(destination, self.wheel_dir)
                self.assertEqual(list(outside.iterdir()), [])

    def test_rejects_parent_writable_by_other_users(self):
        self.root.chmod(0o777)
        self.addCleanup(self.root.chmod, 0o700)
        with self.assertRaisesRegex(preparation.PreparationError, "parent must be owned"):
            self.prepare()
        self.assertFalse(self.destination.exists())

    def test_publication_does_not_replace_concurrently_created_empty_tree(self):
        publish = preparation.publish_directory

        def create_before_publish(parent_fd, source, destination):
            self.destination.mkdir(mode=0o700)
            publish(parent_fd, source, destination)

        with mock.patch.object(preparation, "publish_directory", side_effect=create_before_publish):
            with self.assertRaises(preparation.PreparationError):
                self.prepare()
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(list(self.destination.iterdir()), [])
        self.assertEqual(list(self.root.glob(".orbit-manual-pty-*")), [])


if __name__ == "__main__":
    unittest.main()
