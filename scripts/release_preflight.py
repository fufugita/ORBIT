#!/usr/bin/env python3
"""Check whether this host can execute release tests; this is not a test result."""

import json
import os
from pathlib import Path
import select
import shutil
import socket
import subprocess
import tempfile


def temporary_storage():
    with tempfile.TemporaryDirectory(prefix="orbit-release-preflight-") as directory:
        root = Path(directory)
        original = root / "original"
        with original.open("xb") as stream:
            stream.write(b"release fixture\n")
            stream.flush()
            os.fsync(stream.fileno())
        published = root / "published"
        original.replace(published)
        if published.read_bytes() != b"release fixture\n":
            raise RuntimeError("temporary fixture did not survive publication")


def loopback_tcp():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.settimeout(2)
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        with socket.create_connection(server.getsockname(), timeout=2) as client:
            accepted, _ = server.accept()
            with accepted:
                accepted.settimeout(2)
                client.sendall(b"x")
                if accepted.recv(1) != b"x":
                    raise RuntimeError("local TCP fixture did not receive its byte")


def unix_socket():
    with tempfile.TemporaryDirectory(prefix="orbit-release-socket-") as directory:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
            server.bind(str(Path(directory) / "fixture.sock"))
            server.listen(1)


def terminal():
    master, slave = os.openpty()
    try:
        os.write(slave, b"x")
        if not select.select([master], [], [], 2)[0] or os.read(master, 1) != b"x":
            raise RuntimeError("PTY fixture did not deliver its output")
    finally:
        os.close(master)
        os.close(slave)


def node_compiler_child():
    node = shutil.which("node")
    if not node:
        raise RuntimeError("Node.js is required by the npm distribution contracts")
    result = subprocess.run([
        node, "--input-type=module", "-e",
        "import {spawnSync} from 'node:child_process'; "
        "const r=spawnSync('cc',['--version'],{encoding:'utf8',timeout:5000}); "
        "if(r.error || r.status!==0){console.error(r.error?.message || r.stderr);process.exit(1)}",
    ], capture_output=True, text=True, timeout=10)
    if result.returncode:
        raise RuntimeError("Node cannot launch the C fixture compiler: " + result.stderr.strip()[:500])


CHECKS = (
    ("temporary_storage", temporary_storage),
    ("loopback_tcp", loopback_tcp),
    ("unix_socket", unix_socket),
    ("pty", terminal),
    ("node_compiler_child", node_compiler_child),
)


def check_environment(checks=CHECKS):
    results = []
    for name, check in checks:
        try:
            check()
        except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
            results.append({"id": name, "status": "blocked", "reason": str(error)})
        else:
            results.append({"id": name, "status": "passed"})
    ready = bool(results) and all(item["status"] == "passed" for item in results)
    return {"schema": "orbit.release-preflight/v1", "scope": "test_environment_only",
            "status": "ready" if ready else "blocked", "checks": results}


def main():
    report = check_environment()
    print(json.dumps(report, indent=2))
    return 0 if report["status"] == "ready" else 2


if __name__ == "__main__":
    raise SystemExit(main())
