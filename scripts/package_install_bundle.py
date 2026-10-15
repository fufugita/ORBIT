#!/usr/bin/env python3
"""Create an unsigned, checksum-verified two-component installation archive."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import re
import stat
import tarfile

MAX_BINARY = 256 * 1024 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]*)?\Z")
TARGET = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{2,95}\Z")


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def package(orbit, web, version, target, output):
    if (len(version)>64 or not VERSION.fullmatch(version)) or not TARGET.fullmatch(target):
        raise ValueError("invalid version or target")
    components = {}
    files = {}
    for name, path in (("orbit", orbit), ("orbit-web", web)):
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_BINARY or not info.st_mode & 0o111:
                raise ValueError("components must be regular executable files of at most 256 MiB")
            with os.fdopen(os.dup(fd), "rb") as stream:
                data = stream.read(MAX_BINARY + 1)
            if len(data) != info.st_size or file_stamp(os.fstat(fd)) != file_stamp(info):
                raise ValueError("component changed during packaging")
            files[name] = data
            components[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
        finally:
            os.close(fd)
    manifest = {"schema_version": 1, "version": version, "target": target,
                "components": components, "signature": "absent"}
    files["manifest.json"] = (json.dumps(manifest, sort_keys=True, separators=(",", ":")) + "\n").encode()
    output = Path(output)
    output.mkdir(parents=True, exist_ok=True)
    archive = output / f"orbit-{version}-{target}.tar.gz"
    if archive.exists() or archive.is_symlink():
        raise ValueError("archive already exists; use a fresh output directory")
    # Stable headers describe actual bytes; no dependency/license/signature claims.
    with archive.open("xb") as stream:
        import gzip
        with gzip.GzipFile(filename="", mode="wb", fileobj=stream, mtime=0) as zipped:
            with tarfile.open(fileobj=zipped, mode="w", format=tarfile.USTAR_FORMAT) as tar:
                for name, data in sorted(files.items()):
                    item = tarfile.TarInfo(name)
                    item.size, item.mode, item.mtime = len(data), (0o755 if name != "manifest.json" else 0o600), 0
                    tar.addfile(item, io.BytesIO(data))
        stream.flush()
        os.fsync(stream.fileno())
    if archive.stat().st_size > 512 * 1024 * 1024:
        raise ValueError("archive exceeds the installer limit of 512 MiB")
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    checksum = archive.with_name(archive.name + ".sha256")
    with checksum.open("x") as stream:
        stream.write(f"{digest}  {archive.name}\n")
        stream.flush()
        os.fsync(stream.fileno())
    directory = os.open(output, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)
    return archive


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--orbit", required=True, type=Path)
    parser.add_argument("--orbit-web", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    try:
        print(package(args.orbit, args.orbit_web, args.version, args.target, args.output))
    except (OSError, ValueError) as error:
        parser.exit(1, f"package: {error}\n")


if __name__ == "__main__":
    main()
