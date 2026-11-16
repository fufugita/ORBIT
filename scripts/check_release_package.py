#!/usr/bin/env python3
"""Require packaged bytes to match the successful installed-release receipt.

The caller must also require the installed acceptance command's zero exit status.
This binds the final archive to the binaries tested there; it is not release
approval, a signature, or evidence of provider connectivity.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import tarfile

from package_install_bundle import MAX_BINARY, TARGET, VERSION, file_stamp


RECEIPT_PREFIX = "ORBIT_CHECK_RECEIPT "
COMPONENTS = {"orbit", "orbit-web"}
MAX_LOG = 4 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024


def require(condition, reason):
    if not condition:
        raise ValueError(reason)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "duplicate JSON key")
        result[key] = value
    return result


def receipt_from(log):
    with Path(log).open("rb") as stream:
        data = stream.read(MAX_LOG + 1)
    require(len(data) <= MAX_LOG, "installed acceptance log exceeds its bound")
    receipts = [line.removeprefix(RECEIPT_PREFIX) for line in data.decode().splitlines()
                if line.startswith(RECEIPT_PREFIX)]
    require(len(receipts) == 1, "exactly one installed acceptance receipt is required")
    receipt = json.loads(receipts[0], object_pairs_hook=unique_object)
    require(isinstance(receipt, dict), "invalid installed acceptance receipt")
    hashes = receipt.get("binary_sha256")
    require(isinstance(hashes, dict) and set(hashes) == COMPONENTS
            and all(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value)
                    for value in hashes.values()), "invalid accepted component hashes")
    scenarios = receipt.get("scenarios")
    require(isinstance(scenarios, dict) and len(scenarios) >= 12
            and all(isinstance(value, dict) and value.get("passed") is True
                    and type(value.get("assertions")) is int and value["assertions"] > 0
                    for value in scenarios.values()), "installed acceptance scenarios did not pass")
    require(isinstance(receipt.get("version"), str) and VERSION.fullmatch(receipt["version"])
            and isinstance(receipt.get("target"), str) and TARGET.fullmatch(receipt["target"]),
            "invalid accepted version or target")
    return receipt


def check_package(log, directory):
    receipt = receipt_from(log)
    archives = list(Path(directory).glob("*.tar.gz"))
    require(len(archives) == 1, "exactly one candidate archive is required")
    archive = archives[0]
    require(archive.name == f"orbit-{receipt['version']}-{receipt['target']}.tar.gz",
            "archive name does not match installed acceptance")
    descriptor = os.open(archive, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_ARCHIVE,
                "candidate archive must be a bounded regular file")
        digest = hashlib.sha256()
        size = 0
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
            require(size <= MAX_ARCHIVE, "candidate archive exceeds its bound")
        checksum = archive.with_name(archive.name + ".sha256")
        with checksum.open("rb") as checksum_stream:
            checksum_bytes = checksum_stream.read(513)
        require(checksum_bytes == f"{digest.hexdigest()}  {archive.name}\n".encode(),
                "candidate archive checksum does not match")
        stream.seek(0)
        actual = {}
        manifest = None
        with tarfile.open(fileobj=stream, mode="r:gz") as bundle:
            seen = set()
            for member in bundle:
                require(member.name in COMPONENTS | {"manifest.json"} and member.name not in seen
                        and member.isfile(), "unexpected or duplicate archive member")
                seen.add(member.name)
                limit = 64 * 1024 if member.name == "manifest.json" else MAX_BINARY
                require(0 < member.size <= limit, "archive member exceeds its bound")
                with bundle.extractfile(member) as item:
                    if member.name == "manifest.json":
                        manifest = json.loads(item.read(limit + 1), object_pairs_hook=unique_object)
                    else:
                        hashed, size = hashlib.sha256(), 0
                        for chunk in iter(lambda: item.read(1024 * 1024), b""):
                            hashed.update(chunk)
                            size += len(chunk)
                        require(size == member.size, "incomplete archived component")
                        actual[member.name] = {"sha256": hashed.hexdigest(), "size": size}
        require(seen == COMPONENTS | {"manifest.json"}, "candidate archive is incomplete")
        require(file_stamp(os.fstat(stream.fileno())) == file_stamp(before)
                and file_stamp(archive.lstat()) == file_stamp(before),
                "candidate archive changed during verification")
    require(isinstance(manifest, dict) and manifest.get("schema_version") == 1
            and manifest.get("version") == receipt["version"]
            and manifest.get("target") == receipt["target"]
            and manifest.get("signature") == "absent", "candidate manifest identity does not match")
    require(manifest.get("components") == actual, "candidate manifest does not describe archived bytes")
    require({name: value["sha256"] for name, value in actual.items()} == receipt["binary_sha256"],
            "packaged bytes differ from the installed-tested binaries")
    return manifest


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance-log", required=True, type=Path)
    parser.add_argument("--package-dir", required=True, type=Path)
    args = parser.parse_args()
    try:
        check_package(args.acceptance_log, args.package_dir)
    except (OSError, ValueError, UnicodeError, tarfile.TarError) as error:
        parser.exit(1, f"candidate identity: {error}\n")
    print("Candidate archive and checksum match the installed-tested component bytes.")


if __name__ == "__main__":
    main()
