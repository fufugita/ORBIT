#!/usr/bin/env bash
# Install a checked ORBIT bundle. Invoke with bash, including when using a pipe:
#   curl -fsSL <installer-url> | bash -s -- --version 0.2.0 --dir "$HOME/.local/bin"
# Release: Python 3.11+, curl and sha256sum/shasum. Source builds are explicit.
set -Eeuo pipefail
command -v python3 >/dev/null 2>&1 || { printf '%s\n' 'install: Python 3.11 or newer is required' >&2; exit 1; }
exec python3 - "$@" <<'PY'
import argparse
import ctypes
import errno
import fcntl
import hashlib
import gzip
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse

MAX_BINARY = 256 * 1024 * 1024
MAX_ARCHIVE = 512 * 1024 * 1024
VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9][A-Za-z0-9.-]*)?\Z")
TARGETS = {("Linux", "x86_64"): "x86_64-unknown-linux-gnu", ("Linux", "aarch64"): "aarch64-unknown-linux-gnu"}
UID = os.geteuid()
SYSTEM_ROOT_UID = os.stat("/", follow_symlinks=False).st_uid


def file_stamp(info):
    return (info.st_dev, info.st_ino, info.st_mode, info.st_nlink, info.st_uid,
            info.st_size, info.st_mtime_ns, info.st_ctime_ns)


def fail(message):
    raise ValueError(message)


def synced(fd):
    os.fsync(fd)


def secure_dir(path, create=False, private=False, source=False):
    """Open every component without following symlinks; destination must be owned."""
    absolute = os.path.abspath(path)
    parts = Path(absolute).parts
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for index, part in enumerate(parts[1:]):
            if part in ("", ".", ".."): fail("unsafe installation path")
            if create:
                try:
                    os.mkdir(part, 0o700, dir_fd=fd)
                    synced(fd)
                except FileExistsError:
                    pass
            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            final = index == len(parts) - 2
            component_path = str(Path(*parts[:index + 2]))
            trusted_sticky_parent = not final and component_path in ("/tmp", "/var/tmp") and info.st_uid == SYSTEM_ROOT_UID and bool(info.st_mode & stat.S_ISVTX)
            source_group = source and info.st_uid == UID and not info.st_mode & 0o002
            if info.st_mode & 0o022 and not (trusted_sticky_parent or source_group):
                fail("installation path contains a directory writable by other users")
            if final:
                if info.st_uid != UID or info.st_mode & 0o022 and not source_group:
                    fail("destination must be owned by you and not writable by other users; choose a fresh --dir")
                if private and info.st_mode & 0o077:
                    fail("managed installation directories must be private")
        return fd
    except BaseException:
        os.close(fd)
        raise


def child_dir(parent, name):
    try:
        os.mkdir(name, 0o700, dir_fd=parent)
        synced(parent)
    except FileExistsError:
        pass
    fd = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=parent)
    info = os.fstat(fd)
    if info.st_uid != UID or info.st_mode & 0o077:
        os.close(fd)
        fail("managed directory must be private and owned by you")
    return fd


def regular_bytes(parent, name, limit, executable=False, source=False):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=parent)
    try:
        before = os.fstat(fd)
        if not stat.S_ISREG(before.st_mode) or before.st_uid != UID or before.st_nlink != 1 or before.st_size > limit:
            fail("unsafe or oversized managed file")
        if executable and not before.st_mode & 0o111: fail("installed component is not executable")
        if before.st_mode & (0o002 if source else 0o022): fail("file is writable outside its allowed ownership boundary")
        with os.fdopen(os.dup(fd), "rb") as stream:
            data = stream.read(limit + 1)
        if len(data) > limit or len(data) != before.st_size or file_stamp(os.fstat(fd)) != file_stamp(before):
            fail("managed file changed during verification")
        return data
    finally:
        os.close(fd)


def put(parent, name, data, mode=0o600):
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode, dir_fd=parent)
    try:
        with os.fdopen(os.dup(fd), "wb") as stream:
            stream.write(data)
            stream.flush()
            synced(stream.fileno())
    finally:
        os.close(fd)


def run(argv, timeout=120, **kwargs):
    process = subprocess.Popen(argv, **kwargs)
    try:
        code = process.wait(timeout=timeout)
        if code: fail("command failed; prior installation retained")
    except BaseException:
        if process.poll() is None:
            process.kill()
            process.wait()
        raise


def download(url, path, limit):
    # Size is bounded by curl and checked before any parser reads the download.
    run(["curl", "--fail", "--silent", "--show-error", "--location", "--proto", "=https,http", "--proto-redir", "=https,http", "--connect-timeout", "10", "--max-time", "90", "--max-filesize", str(limit), "--output", str(path), url], timeout=100)
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > limit: fail("download exceeds its allowed size")


def read_manifest(raw, version, target):
    if len(raw) > 16 * 1024: fail("manifest exceeds 16 KiB")
    def unique(pairs):
        out = {}
        for key, value in pairs:
            if key in out: fail("manifest contains duplicate fields")
            out[key] = value
        return out
    doc = json.loads(raw, object_pairs_hook=unique)
    if not isinstance(doc, dict) or set(doc) != {"schema_version", "version", "target", "components", "signature"}:
        fail("invalid bundle manifest fields")
    if type(doc["schema_version"]) is not int or doc["schema_version"] != 1 or doc["version"] != version or doc["target"] != target:
        fail("bundle version or target does not match the request")
    if doc["signature"] != "absent": fail("unsupported bundle signature declaration")
    components = doc["components"]
    if not isinstance(components, dict) or set(components) != {"orbit", "orbit-web"}: fail("bundle must contain both matching components")
    for item in components.values():
        if not isinstance(item, dict) or set(item) != {"size", "sha256"} or type(item["size"]) is not int or not 0 < item["size"] <= MAX_BINARY or not isinstance(item["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"]):
            fail("invalid component size or hash")
    return doc


def verified_archive(path, version, target):
    files = {}
    # Parse only fixed regular USTAR headers. Generic tar readers process PAX/GNU
    # metadata before yielding a member, which could bypass the member bounds.
    with gzip.open(path, "rb") as archive:
        while True:
            header = archive.read(512)
            if len(header) != 512: fail("incomplete archive header")
            if not header.strip(b"\0"):
                padding = archive.read(20 * 1024 + 1)
                if len(padding) > 20 * 1024 or padding.strip(b"\0"):
                    fail("unexpected trailing archive data")
                break
            item = tarfile.TarInfo.frombuf(header, "utf-8", "strict")
            if len(files) >= 3 or item.name not in {"orbit", "orbit-web", "manifest.json"} or item.name in files or item.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or item.linkname:
                fail("unsafe, duplicate or unexpected archive member")
            limit = 16 * 1024 if item.name == "manifest.json" else MAX_BINARY
            if not 0 < item.size <= limit or item.mode & 0o7000: fail("unsafe member size or permissions")
            data = archive.read(item.size)
            if len(data) != item.size: fail("incomplete archive component")
            padding_size = (-item.size) % 512
            padding = archive.read(padding_size)
            if len(padding) != padding_size or padding.strip(b"\0"): fail("invalid member padding")
            files[item.name] = data
    if set(files) != {"orbit", "orbit-web", "manifest.json"}: fail("bundle is missing a component")
    doc = read_manifest(files["manifest.json"], version, target)
    for name, fact in doc["components"].items():
        if len(files[name]) != fact["size"] or hashlib.sha256(files[name]).hexdigest() != fact["sha256"]:
            fail("component checksum or size mismatch")
    return files


def source_bundle(args, stage, target):
    import tomllib
    if not args.source: fail("source mode requires --source CHECKOUT")
    checkout = Path(os.path.abspath(args.source))
    fd = secure_dir(checkout, source=True)
    try:
        manifest_raw = regular_bytes(fd, "Cargo.toml", 128 * 1024, source=True)
        regular_bytes(fd, "Cargo.lock", 16 * 1024 * 1024, source=True)
    finally:
        os.close(fd)
    manifest = tomllib.loads(manifest_raw.decode())
    if manifest.get("workspace", {}).get("package", {}).get("version") != args.version:
        fail("requested version does not match the supplied checkout")
    if manifest.get("workspace", {}).get("package", {}).get("rust-version") != "1.99":
        fail("source checkout must require Rust 1.99")
    if not shutil.which("cargo") or not shutil.which("rustc"): fail("source mode requires Cargo and Rust 1.99")
    env = os.environ.copy()
    env["RUSTUP_TOOLCHAIN"] = "1.99.0"
    env["CARGO_BUILD_JOBS"] = "1"
    result = subprocess.run(["rustc", "--version"], check=True, capture_output=True, text=True, timeout=15, env=env)
    if not re.match(r"rustc 1\.99\.", result.stdout): fail("source mode requires Rust 1.99")
    build = stage / "build"
    run(["cargo", "build", "--locked", "--release", "--manifest-path", str(checkout / "Cargo.toml"), "--target", target, "--target-dir", str(build), "-p", "orbit-cli", "--bin", "orbit", "-p", "orbit-web", "--bin", "orbit-web"], timeout=3600, cwd=checkout, env=env)
    files, components = {}, {}
    component_dir = build / target / "release"
    component_fd = secure_dir(component_dir)
    try:
        for name in ("orbit", "orbit-web"):
            data = regular_bytes(component_fd, name, MAX_BINARY, executable=True)
            if not data: fail("built component is empty")
            files[name] = data
            components[name] = {"sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}
    finally:
        os.close(component_fd)
    files["manifest.json"] = (json.dumps({"schema_version": 1, "version": args.version, "target": target, "components": components, "signature": "absent"}, sort_keys=True, separators=(",", ":")) + "\n").encode()
    return files


def launcher(name):
    return ("#!/bin/sh\n# ORBIT managed bundle launcher v1\n" + 'orbit_bin_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P) || exit 1\n' + f'exec "$orbit_bin_dir/.orbit/current/{name}" "$@"\n').encode()


def validate_current(managed, versions):
    try:
        info = os.stat("current", dir_fd=managed, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if not stat.S_ISLNK(info.st_mode) or info.st_uid != UID: fail("unsafe managed current pointer")
    link = os.readlink("current", dir_fd=managed)
    if not re.fullmatch(r"versions/[A-Za-z0-9][A-Za-z0-9_.+-]{1,220}", link): fail("unsafe managed current target")
    fd = os.open(link.split("/")[1], os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=versions)
    try:
        info = os.fstat(fd)
        if info.st_uid != UID or info.st_mode & 0o077: fail("unsafe current bundle directory")
        raw = regular_bytes(fd, "manifest.json", 16 * 1024)
        minimal = json.loads(raw)
        doc = read_manifest(raw, minimal["version"], minimal["target"])
        for name, fact in doc["components"].items():
            data = regular_bytes(fd, name, MAX_BINARY, executable=True)
            if len(data) != fact["size"] or hashlib.sha256(data).hexdigest() != fact["sha256"]: fail("current bundle is corrupt; choose a fresh --dir")
    finally:
        os.close(fd)
    return link


def publish_version(source, versions, name):
    # Linux-native no-replace rename keeps an existing immutable version intact.
    library = ctypes.CDLL(None, use_errno=True)
    rename = getattr(library, "renameat2", None)
    if rename is None: fail("atomic no-replace publication is unavailable on this platform")
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    if rename(-100, os.fsencode(source), versions, os.fsencode(name), 1) != 0:
        code = ctypes.get_errno()
        if code == errno.ENOSYS: fail("atomic no-replace publication is unavailable on this kernel")
        raise OSError(code, os.strerror(code))


def main():
    if sys.version_info < (3, 11): fail("Python 3.11 or newer is required")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description="Install a verified ORBIT CLI and browser bundle. Release checksums verify transport integrity, not publisher identity.")
    parser.add_argument("--method", choices=("release", "source"), default="release")
    parser.add_argument("--version", required=True)
    parser.add_argument("--dir", default=os.environ.get("ORBIT_INSTALL_DIR", str(Path.home() / ".local/bin")))
    parser.add_argument("--source")
    parser.add_argument("--base-url", default="https://github.com/fufugita/ORBIT/releases/download")
    args = parser.parse_args()
    if len(args.version)>64 or not VERSION.fullmatch(args.version): fail("version must be an exact release version, without a leading v")
    if args.method == "release" and args.source: fail("--source requires --method source")
    target = TARGETS.get((platform.system(), platform.machine()))
    if target is None: fail("no validated installer contract for this platform; Linux native targets only")
    parsed = urllib.parse.urlsplit(args.base_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        fail("base URL must be absolute HTTP(S), without credentials, query or fragment")
    if args.method == "release" and (not shutil.which("curl") or not (shutil.which("sha256sum") or shutil.which("shasum"))):
        fail("release mode requires curl and sha256sum or shasum; Rust is unnecessary")
    destination = Path(os.path.abspath(args.dir))
    dest = secure_dir(destination, create=True)
    managed = versions = lock = None
    stage = None
    published = False
    try:
        # Refuse unrelated executables before creating managed installation state.
        for name in ("orbit", "orbit-web"):
            try:
                if regular_bytes(dest, name, 1024) != launcher(name): fail("unmanaged executable exists; choose a fresh --dir")
            except FileNotFoundError:
                pass
        managed = child_dir(dest, ".orbit")
        versions = child_dir(managed, "versions")
        lock = os.open("install.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600, dir_fd=managed)
        info = os.fstat(lock)
        if not stat.S_ISREG(info.st_mode) or info.st_uid != UID or info.st_nlink != 1 or info.st_mode & 0o077: fail("unsafe install lock")
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            fail("another installation is in progress; retry after it finishes")
        previous = validate_current(managed, versions)
        stage = Path(tempfile.mkdtemp(prefix=".stage-", dir=destination / ".orbit"))
        if args.method == "release":
            asset = f"orbit-{args.version}-{target}.tar.gz"
            url = f"{args.base_url.rstrip('/')}/v{args.version}/{asset}"
            archive, checksum = stage / asset, stage / (asset + ".sha256")
            download(url + ".sha256", checksum, 1024)
            line = checksum.read_text("ascii")
            match = re.fullmatch(r"([0-9a-fA-F]{64})  " + re.escape(asset) + r"\n?", line)
            if not match: fail("missing or invalid mandatory archive checksum")
            download(url, archive, MAX_ARCHIVE)
            command = ["sha256sum", str(archive)] if shutil.which("sha256sum") else ["shasum", "-a", "256", str(archive)]
            actual = subprocess.run(command, check=True, capture_output=True, text=True, timeout=30).stdout.split()[0]
            if actual.lower() != match[1].lower(): fail("archive checksum mismatch; prior installation retained")
            files = verified_archive(archive, args.version, target)
        else:
            files = source_bundle(args, stage, target)
        content_id = hashlib.sha256(files["manifest.json"]).hexdigest()[:24]
        bundle = f"{args.version}-{target}-{content_id}"
        temporary = stage / "bundle"
        temporary.mkdir(mode=0o700)
        bundle_fd = secure_dir(temporary, private=True)
        try:
            for name, data in files.items(): put(bundle_fd, name, data, 0o500 if name != "manifest.json" else 0o400)
            synced(bundle_fd)
        finally:
            os.close(bundle_fd)
        try:
            publish_version(temporary, versions, bundle)
            synced(versions)
        except OSError as error:
            if error.errno != errno.EEXIST: raise
            existing = os.open(bundle, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=versions)
            try:
                info = os.fstat(existing)
                if info.st_uid != UID or info.st_mode & 0o077: fail("unsafe existing version directory")
                for name, data in files.items():
                    if regular_bytes(existing, name, MAX_BINARY if name != "manifest.json" else 16 * 1024, name != "manifest.json") != data:
                        fail("existing immutable version differs; prior installation retained")
            finally:
                os.close(existing)
        for name in ("orbit", "orbit-web"):
            try:
                if regular_bytes(dest, name, 1024) != launcher(name): fail("unmanaged executable appeared during installation")
            except FileNotFoundError:
                temp_name = f".launcher-{os.getpid()}-{name}"
                put(dest, temp_name, launcher(name), 0o700)
                try:
                    os.link(temp_name, name, src_dir_fd=dest, dst_dir_fd=dest, follow_symlinks=False)
                finally:
                    os.unlink(temp_name, dir_fd=dest)
                synced(dest)
        pointer = f".current-{os.getpid()}"
        os.symlink(f"versions/{bundle}", pointer, dir_fd=managed)
        try:
            # Revalidate the expected old pointer immediately before one atomic switch.
            if validate_current(managed, versions) != previous: fail("current bundle changed during installation")
            os.replace(pointer, "current", src_dir_fd=managed, dst_dir_fd=managed)
            published = True
            synced(managed)
        finally:
            try: os.unlink(pointer, dir_fd=managed)
            except FileNotFoundError: pass
        print(f"Installed ORBIT {args.version} ({target}) into {destination}")
        print("Both components use one managed bundle. Next: orbit setup; orbit doctor.")
    except BaseException as error:
        if published:
            raise ValueError("bundle publication occurred, but durability is uncertain; inspect --dir before retrying") from error
        raise
    finally:
        if stage is not None: shutil.rmtree(stage, ignore_errors=True)
        for fd in (lock, versions, managed, dest):
            if fd is not None: os.close(fd)


def interrupted(_signal, _frame):
    raise InterruptedError("installation interrupted; prior current bundle retained")


signal.signal(signal.SIGTERM, interrupted)
try:
    main()
except (OSError, ValueError, KeyError, TypeError, json.JSONDecodeError, tarfile.TarError, EOFError, subprocess.SubprocessError, KeyboardInterrupt) as error:
    print(f"install: {error}", file=sys.stderr)
    sys.exit(1)
PY
