#!/usr/bin/env python3
"""Explicitly prepare the terminal harness's existing pinned Python fixture."""

import argparse
import ctypes
import errno
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import tempfile
import urllib.parse
import urllib.request
import zipfile


sys.dont_write_bytecode = True
REPO = Path(__file__).resolve().parents[1]
MANIFEST_SHA256 = "08384617c293016b1d5a30652fcb9c696164085f7e535e0e65087c10ca727b57"
DEFAULT_OUTPUT = REPO / "target" / ("orbit-manual-pty-python-" + MANIFEST_SHA256[:12])
MAX_WHEEL = 2 * 1024 * 1024
MAX_MODULE = 512 * 1024
WHEELS = (
    {
        "package": "pyte",
        "filename": "pyte-0.8.2-py3-none-any.whl",
        "url": "https://files.pythonhosted.org/packages/59/d0/bb522283b90853afbf506cd5b71c650cf708829914efd0003d615cf426cd/pyte-0.8.2-py3-none-any.whl",
        "sha256": "85db42a35798a5aafa96ac4d8da78b090b2c933248819157fc0e6f78876a0135",
    },
    {
        "package": "wcwidth",
        "filename": "wcwidth-0.8.2-py3-none-any.whl",
        "url": "https://files.pythonhosted.org/packages/96/42/3e5985a0a7e57de470b320c6d6a1a67c844f6737a587f3d44dd13d1819e7/wcwidth-0.8.2-py3-none-any.whl",
        "sha256": "d63947694a0539a1d51e01eda7caf800c291020e6cdd7e28ad7b14dd33ad4f85",
    },
)


class PreparationError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise PreparationError(message)


def canonical_path(value):
    path = Path(value)
    require(path.is_absolute() and ".." not in path.parts
            and path.resolve(strict=False) == path, "paths must be absolute and contain no symlinks")
    return path


def checked_bytes(path, limit):
    path = canonical_path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1
                and 0 < before.st_size <= limit, "wheel must be a bounded regular single-link file")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    signature = lambda item: (item.st_dev, item.st_ino, item.st_size, item.st_mtime_ns, item.st_ctime_ns)
    require(len(data) == before.st_size and signature(before) == signature(after)
            and signature(before) == signature(path.lstat()), "wheel changed while reading")
    return data


def wheel_bytes(wheel, wheel_dir):
    if wheel_dir is not None:
        data = checked_bytes(canonical_path(wheel_dir) / wheel["filename"], MAX_WHEEL)
    else:
        with urllib.request.urlopen(wheel["url"], timeout=30) as response:
            location = urllib.parse.urlsplit(response.geturl())
            require(location.scheme == "https" and location.hostname == "files.pythonhosted.org",
                    "wheel download left the official artifact host")
            data = response.read(MAX_WHEEL + 1)
    require(0 < len(data) <= MAX_WHEEL
            and hashlib.sha256(data).hexdigest() == wheel["sha256"], "wheel SHA256 does not match its pin")
    return data


def verified_modules(wheel_dir):
    modules = {}
    for wheel in WHEELS:
        with zipfile.ZipFile(io.BytesIO(wheel_bytes(wheel, wheel_dir))) as archive:
            entries = archive.infolist()
            require(len(entries) <= 512, "wheel has too many members")
            names = set()
            for entry in entries:
                name = entry.filename
                path = PurePosixPath(name)
                require(name not in names and not path.is_absolute() and "\\" not in name
                        and all(part not in ("", ".", "..") for part in name.rstrip("/").split("/")),
                        "wheel has duplicate or unsafe member paths")
                names.add(name)
                if entry.is_dir() or not name.startswith(wheel["package"] + "/") or not name.endswith(".py"):
                    continue
                kind = stat.S_IFMT(entry.external_attr >> 16)
                require(kind in (0, stat.S_IFREG) and 0 <= entry.file_size <= MAX_MODULE
                        and name not in modules, "wheel Python member is not a bounded regular file")
                modules[name] = archive.read(entry)
                require(len(modules) <= 56 and sum(map(len, modules.values())) <= 1844069,
                        "wheel Python content exceeds the fixture bounds")
    manifest = {
        "schema": "orbit.manual-pty-test-dependencies/v1",
        "packages": {"pyte": "0.8.2", "wcwidth": "0.8.2"},
        "files": [{"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
                  for name, data in sorted(modules.items())],
    }
    encoded = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    require(len(modules) == 56 and sum(map(len, modules.values())) == 1844069
            and hashlib.sha256(encoded).hexdigest() == MANIFEST_SHA256,
            "official wheels do not reproduce the pinned terminal fixture")
    return modules, encoded


def verify_tree(path):
    # Reuse the independent runtime guard without loading either downloaded package.
    spec = importlib.util.spec_from_file_location(
        "manual_pty_guard", REPO / "scripts/fixtures/context_manual_pty.py"
    )
    guard = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(guard)
    try:
        guard.dependencies(path, MANIFEST_SHA256, os.geteuid(), load=False)
    except (guard.Failed, guard.NotRun, OSError, ValueError, KeyError, TypeError) as error:
        raise PreparationError(f"existing or staged fixture is invalid: {error}") from error


def publish_directory(parent_fd, source, destination):
    # Linux's no-replace rename preserves even a concurrently created empty directory.
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameat2
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(parent_fd, os.fsencode(source), parent_fd, os.fsencode(destination), 1):
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise FileExistsError(code, os.strerror(code), destination)
        raise OSError(code, os.strerror(code), destination)


def prepare(destination=DEFAULT_OUTPUT, wheel_dir=None):
    destination = canonical_path(destination)
    require(bool(destination.name), "fixture destination must name a directory")
    parent = destination.parent
    if not parent.exists():
        canonical_path(parent.parent)
        parent.mkdir(mode=0o700)
    parent = canonical_path(parent)
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    staging = None
    try:
        identity = os.fstat(descriptor)
        require(identity.st_uid == os.geteuid(), "fixture parent must be owned by the current user")
        if os.path.lexists(destination):
            verify_tree(destination)
            return "reused"
        require(not identity.st_mode & 0o022,
                "fixture parent must be owned and not writable by other users")
        modules, manifest = verified_modules(wheel_dir)
        staging = Path(tempfile.mkdtemp(prefix=".orbit-manual-pty-", dir=parent))
        for name, data in [*modules.items(), ("manifest.json", manifest)]:
            target = staging / name
            directory = staging
            for part in PurePosixPath(name).parts[:-1]:
                directory /= part
                directory.mkdir(mode=0o700, exist_ok=True)
            with target.open("xb") as stream:
                os.fchmod(stream.fileno(), 0o400)
                stream.write(data)
                stream.flush()
                os.fsync(stream.fileno())
        verify_tree(staging)
        current = parent.lstat()
        require((identity.st_dev, identity.st_ino) == (current.st_dev, current.st_ino)
                and canonical_path(parent) == parent, "fixture parent changed during preparation")
        try:
            publish_directory(descriptor, staging.name, destination.name)
        except FileExistsError:
            verify_tree(destination)
            return "reused"
        staging = None
        os.fsync(descriptor)
        verify_tree(destination)
        return "prepared"
    finally:
        if staging is not None:
            shutil.rmtree(staging)
        os.close(descriptor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wheel-dir", type=Path, help="use the pinned local wheels without network access")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    os.umask(0o077)
    status = prepare(args.output, args.wheel_dir)
    print(json.dumps({"status": status, "path": str(args.output), "manifest_sha256": MANIFEST_SHA256,
                      "python_modules": 56, "module_bytes": 1844069}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (OSError, ValueError, KeyError, TypeError, AttributeError, zipfile.BadZipFile) as error:
        print(f"terminal dependency preparation failed: {error}", file=sys.stderr)
        raise SystemExit(1)
