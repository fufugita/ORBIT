#!/usr/bin/env python3
"""Collect completed priorities 3-5 checks against one frozen source/binary set.

Run inside scripts/in-jail.sh, with an explicit private directory below /tmp:
  ... python3 scripts/priorities_3_5_acceptance.py --stage workflows \
      --evidence-dir /tmp/orbit-final-evidence --binary target/debug/orbit \
      --web-binary target/debug/orbit-web
Repeat with --stage regression. Closure additionally requires --verification,
--review (repeatable), and --review-manifest. All are explicit existing private
files. See --help for the manifest contract. No build command is run here.
"""

import argparse
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import socket
import stat
import subprocess
import sys
import time
import uuid

REPO = Path(__file__).resolve().parents[1]
VERIFY = REPO / "scripts/verify_priority_checks.py"
MAX_LOG = 128 * 1024 * 1024
MAX_JSON = 16 * 1024 * 1024
MAX_DOCUMENT = 1024 * 1024
DIGEST = re.compile(r"[0-9a-f]{64}\Z")
NAME = re.compile(r"[a-z0-9][a-z0-9_.-]{0,180}\Z")
ENVIRONMENT = {"RUSTUP_TOOLCHAIN": "1.94.0", "CARGO_BUILD_JOBS": "1",
               "RUST_TEST_THREADS": "1", "CARGO_TERM_COLOR": "never",
               "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
               "ORBIT_PTY_ALLOW_KILL_TESTS": "1", "TERM": "xterm-256color", "COLORTERM": "truecolor"}
ENVIRONMENT_POLICY = {"set": ENVIRONMENT, "unset": ["NO_COLOR"], "unset_prefixes": ["ORBIT_"]}
GROUPS = ("mcp_policy", "local_owner", "lsp_diagnostics", "signed_packages", "browser_integration")


class EvidenceError(ValueError):
    """A required observed result or its frozen identity is unavailable."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def sha(data):
    return hashlib.sha256(data).hexdigest()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON field")
        result[key] = value
    return result


def parse_json(data):
    return json.loads(data, object_pairs_hook=unique_object,
                      parse_constant=lambda _: (_ for _ in ()).throw(EvidenceError("nonfinite JSON number")))


def exact_keys(value, keys, label):
    if not isinstance(value, dict) or set(value) != set(keys):
        raise EvidenceError(f"{label} has missing or unknown fields")


def ordinary_path(value, absolute=False):
    raw = os.fspath(value)
    if not raw or len(raw) > 4096 or any(ord(c) < 32 or ord(c) == 127 for c in raw):
        raise EvidenceError("artifact path must be nonempty and printable")
    if any(part in (".", "..") for part in raw.split("/")):
        raise EvidenceError("artifact path contains a non-normal component")
    path = Path(raw)
    if absolute and not path.is_absolute():
        raise EvidenceError("evidence/document paths must be absolute")
    if path.is_absolute() and (path.anchor != "/" or raw != str(path)):
        raise EvidenceError("artifact path must use an exact normal absolute spelling")
    if not path.is_absolute():
        path = REPO / path
    return path


def no_symlinks(path):
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise EvidenceError("artifact path contains a symlink")


def read_regular(path, limit, private=False, executable=False):
    path = ordinary_path(path, absolute=True)
    no_symlinks(path)
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        before = os.fstat(file.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
            raise EvidenceError("artifact must be a regular single-link file")
        if private and (before.st_uid != os.geteuid() or before.st_mode & 0o077):
            raise EvidenceError("evidence/document file must be owned and private (0600)")
        if executable and (before.st_uid != os.geteuid() or not before.st_mode & 0o111):
            raise EvidenceError("binary must be an owned regular executable")
        if before.st_size > limit:
            raise EvidenceError("artifact exceeds its size bound")
        data = file.read(limit + 1)
        after = os.fstat(file.fileno())
    current = path.lstat()
    no_symlinks(path)
    signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if len(data) > limit or signature(before) != signature(after) or signature(after) != signature(current):
        raise EvidenceError("artifact changed while reading")
    return data, before


def binary_identity(path):
    # Cargo normally hardlinks a top-level executable to its hashed artifact.
    # Stream that potentially large immutable input instead of allocating it.
    no_symlinks(path)
    digest = hashlib.sha256()
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as file:
        before = os.fstat(file.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
                or not before.st_mode & 0o111 or before.st_mode & 0o022
                or not 0 < before.st_size <= 512 * 1024 * 1024):
            raise EvidenceError("binary must be a bounded owned executable without group/world writes")
        total = 0
        while chunk := file.read(1024 * 1024):
            total += len(chunk)
            if total > 512 * 1024 * 1024:
                raise EvidenceError("binary exceeds 512 MiB")
            digest.update(chunk)
        after = os.fstat(file.fileno())
    current = path.lstat()
    no_symlinks(path)
    signature = lambda info: (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns, info.st_ctime_ns)
    if total != before.st_size or signature(before) != signature(after) or signature(after) != signature(current):
        raise EvidenceError("binary changed while fingerprinting")
    return {"path": str(path), "sha256": digest.hexdigest(), "size": total,
            "mode": stat.S_IMODE(before.st_mode)}


def require_jail():
    mapping = Path("/proc/self/uid_map").read_text().split()
    owner = next(line for line in Path("/proc/1/status").read_text().splitlines()
                 if line.startswith("Uid:")).split()[1]
    if (len(mapping) != 3 or mapping[0] != str(os.geteuid())
            or mapping[2] != "1" or owner != str(os.geteuid())):
        raise EvidenceError("run the collector in scripts/in-jail.sh (mapped user + PID namespace)")


class Store:
    def __init__(self, path):
        self.path = ordinary_path(path, absolute=True)
        if Path("/tmp") not in self.path.parents or REPO == self.path or REPO in self.path.parents:
            raise EvidenceError("--evidence-dir must be a private destination below /tmp, outside the checkout")
        no_symlinks(self.path.parent)
        try:
            self.path.mkdir(mode=0o700)
        except FileExistsError:
            pass
        no_symlinks(self.path)
        self.fd = os.open(self.path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        self.identity = os.fstat(self.fd)
        if self.identity.st_uid != os.geteuid() or self.identity.st_mode & 0o077:
            raise EvidenceError("evidence directory must be owned and private (0700)")
        self.lock = os.open(".collector.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK,
                            0o600, dir_fd=self.fd)
        info = os.fstat(self.lock)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or info.st_uid != os.geteuid() or info.st_mode & 0o077):
            raise EvidenceError("collector lock is unsafe")
        try:
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise EvidenceError("another collector owns this evidence directory") from error
        self.check()

    def check(self):
        current = self.path.lstat()
        if (stat.S_ISLNK(current.st_mode) or current.st_dev != self.identity.st_dev
                or current.st_ino != self.identity.st_ino or current.st_uid != os.geteuid()
                or current.st_mode & 0o077):
            raise EvidenceError("evidence directory changed")

    def name(self, name):
        if not NAME.fullmatch(name):
            raise EvidenceError("unsafe evidence filename")
        self.check()
        return name

    def read(self, name, limit=MAX_JSON):
        return read_regular(self.path / self.name(name), limit, private=True)[0]

    def exists(self, name):
        try:
            os.stat(self.name(name), dir_fd=self.fd, follow_symlinks=False)
            return True
        except FileNotFoundError:
            return False

    def create(self, name):
        descriptor = os.open(self.name(name), os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                             0o600, dir_fd=self.fd)
        return os.fdopen(descriptor, "wb")

    def write(self, name, value):
        self.name(name)
        if self.exists(name):
            raise EvidenceError("completed evidence already exists; it will not be overwritten")
        temporary = "pending-" + uuid.uuid4().hex + ".json"
        with self.create(temporary) as file:
            file.write(canonical(value) + b"\n")
            file.flush()
            os.fsync(file.fileno())
        self.check()
        # Holding the collector lock serializes all compliant evidence writers.
        os.link(temporary, name, src_dir_fd=self.fd, dst_dir_fd=self.fd, follow_symlinks=False)
        os.unlink(temporary, dir_fd=self.fd)
        os.fsync(self.fd)
        self.check()


def fingerprint(binaries):
    listing = subprocess.run(
        ["git", "-c", "core.fsmonitor=false", "ls-files", "--cached", "--others", "--exclude-standard", "-z"],
        cwd=REPO, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30,
    ).stdout
    paths = sorted(set(os.fsdecode(path) for path in listing.split(b"\0") if path))
    if not paths or len(paths) > 50000:
        raise EvidenceError("source inventory is missing or unexpectedly large")
    files = {}
    for relative in paths:
        path = ordinary_path(relative)
        if REPO not in path.parents:
            raise EvidenceError("source inventory escaped the checkout")
        try:
            info = path.lstat()
        except FileNotFoundError:
            files[relative] = {"type": "absent"}
            continue
        if stat.S_ISLNK(info.st_mode):
            files[relative] = {"type": "symlink", "sha256": sha(os.fsencode(os.readlink(path)))}
        elif stat.S_ISREG(info.st_mode):
            data, info = read_regular(path, 64 * 1024 * 1024)
            files[relative] = {"type": "file", "sha256": sha(data), "size": len(data),
                               "mode": stat.S_IMODE(info.st_mode)}
        else:
            raise EvidenceError("source inventory contains a special file")
    outputs = {}
    for name, path in binaries.items():
        outputs[name] = binary_identity(path)
    return {"schema": "orbit.priorities35.fingerprint/v1", "root": str(REPO),
            "source": {"sha256": sha(canonical(files)), "files": files}, "binaries": outputs}


def assert_frozen(baseline, binaries):
    if fingerprint(binaries) != baseline:
        raise EvidenceError("source or binary drift invalidates prior evidence; freeze/rebuild and use a fresh evidence directory")


def cargo_job(name, package, targets, minimum, group=None):
    args = ["cargo", "test", "--locked", "--offline"]
    if package is None:
        args += ["--workspace"]
    else:
        for member in ([package] if isinstance(package, str) else package):
            args += ["-p", member]
    for target in targets:
        args += ["--test", target]
    args += ["--", "--test-threads=1"]
    return {"name": name, "command": [sys.executable, str(VERIFY), "cargo", "--min-tests", str(minimum), "--", *args],
            "validator": "cargo", "minimum": minimum, "group": group, "timeout": 7200,
            "allow_ignored": package is None,
            "expected_suites": dict(zip(targets, [28, 15] if targets == ["p35_daemon", "p35_attach"] else [minimum] * len(targets)))}


def script_job(name, script, count, arguments=(), group=None):
    executable = "node" if script.endswith(".mjs") else sys.executable
    return {"name": name, "command": [sys.executable, str(VERIFY), "script", "--min-checks", str(count), "--",
                                         executable, str(REPO / script), *map(str, arguments)],
            "validator": "receipt", "minimum": count, "group": group, "timeout": 900,
            "allow_ignored": False}


def jobs_for(stage, binaries, store):
    cli, web, mock = (str(binaries[key]) for key in ("cli", "web", "mock"))
    if stage == "workflows":
        return [
            cargo_job("mcp-policy", "orbit-cli", ["p35_mcp_policy"], 28, "mcp_policy"),
            cargo_job("owned-session", "orbit-cli", ["p35_daemon", "p35_attach"], 43, "local_owner"),
            script_job("daemon-attach-cli", "scripts/daemon_attach_test.py", 12, ["--binary", cli], "local_owner"),
            cargo_job("lsp-diagnostics", "orbit-cli", ["p35_lsp"], 44, "lsp_diagnostics"),
            cargo_job("lsp-integration", "orbit-cli", ["p35_integration"], 26, "lsp_diagnostics"),
            cargo_job("signed-packages", "orbit-cli", ["p35_signed_packages"], 30, "signed_packages"),
            cargo_job("browser-mcp-backend", "orbit-cli", ["p35_browser_mcp"], 9, "browser_integration"),
            script_job("browser-mcp-cli", "scripts/browser_mcp_test.py", 8, ["--binary", cli], "browser_integration"),
            script_job("browser-harness", "scripts/web_harness_test.py", 13,
                       ["--binary", web, "--cli", cli, "--mock", mock, "--home", store.path / ("web-home-" + uuid.uuid4().hex)], "browser_integration"),
            script_job("browser-controls-dom", "scripts/browser_controls_test.mjs", 18, group="browser_integration"),
        ]
    if stage == "regression":
        frontend = cargo_job("frontend-regression", ["orbit-cli", "orbit-hud-tui", "orbit-web"], [], 454)
        return [
            cargo_job("workspace-regression", None, [], 1128), frontend,
            {"name": "format", "command": ["cargo", "fmt", "--all", "--", "--check"], "validator": "exit", "minimum": 1, "timeout": 600, "group": None},
            {"name": "workspace-clippy", "command": ["cargo", "clippy", "--locked", "--offline", "--workspace", "--all-targets", "--", "-D", "warnings"], "validator": "exit", "minimum": 1, "timeout": 7200, "group": None},
            {"name": "terminal-original", "command": [sys.executable, str(REPO / "scripts/pty_tui_test.py"), "--binary", cli, "--mock", mock,
                                                        "--home", str(store.path / ("terminal-home-" + uuid.uuid4().hex)), "--gate", "http://127.0.0.1:0"],
             "validator": "legacy", "minimum": 83, "timeout": 1200, "group": None},
            {"name": "composer-original", "command": [sys.executable, str(REPO / "scripts/composer_pty_test.py"), "--binary", cli],
             "validator": "legacy", "minimum": 25, "timeout": 600, "group": None},
            {"name": "effort-original", "command": [sys.executable, str(REPO / "scripts/effort_pty_test.py"), "--binary", cli],
             "validator": "legacy", "minimum": 41, "timeout": 900, "group": None},
        ]
    raise EvidenceError("unknown executable stage")


def validate_output(spec, output):
    if spec["validator"] in ("cargo", "receipt") and not output.startswith("resource gate passed:"):
        raise EvidenceError("counted command lacks its fresh successful resource gate")
    if spec["validator"] == "cargo":
        matches = re.findall(r"^test result: (\w+)\. (\d+) passed; (\d+) failed; (\d+) ignored; (\d+) measured; (\d+) filtered out;", output, re.M)
        if not matches or any(status != "ok" or int(failed) or int(filtered) for status, _, failed, _, _, filtered in matches):
            raise EvidenceError("complete Cargo results are missing, failed or filtered")
        suites = {}
        current = None
        for line in output.splitlines():
            running = re.search(r"Running tests/([A-Za-z0-9_-]+)\.rs ", line)
            if running:
                current = running.group(1)
            summary = re.match(r"test result: (\w+)\. (\d+) passed;", line)
            if summary and current:
                if current in suites and spec.get("expected_suites"):
                    raise EvidenceError("duplicate required single-package Cargo target summary")
                suites.setdefault(current, []).append(int(summary.group(2)))
                current = None
        if any(sum(suites.get(name, [])) < floor for name, floor in spec.get("expected_suites", {}).items()):
            raise EvidenceError("a required complete Cargo target has insufficient actual tests")
        passed = sum(int(row[1]) for row in matches)
        ignored = sum(int(row[3]) for row in matches)
        if passed < spec["minimum"] or (ignored and not spec.get("allow_ignored")):
            raise EvidenceError("insufficient executed tests or ignored required cases")
        return {"passed": passed, "ignored": ignored, "summaries": len(matches), "target_counts": suites}
    if spec["validator"] == "receipt":
        markers = [line[len("ORBIT_CHECK_RECEIPT "):] for line in output.splitlines() if line.startswith("ORBIT_CHECK_RECEIPT ")]
        if len(markers) != 1:
            raise EvidenceError("require exactly one observed scenario receipt")
        result = parse_json(markers[0])
        if not isinstance(result, dict) or not isinstance(result.get("scenarios"), dict):
            raise EvidenceError("scenario receipt is malformed")
        scenarios = result["scenarios"]
        if len(scenarios) < spec["minimum"]:
            raise EvidenceError("insufficient actual scenario receipts")
        for name, check in scenarios.items():
            if (not isinstance(name, str) or not 0 < len(name) <= 128 or not isinstance(check, dict)
                    or check.get("passed") is not True or type(check.get("assertions")) is not int
                    or check["assertions"] < 1 or check.get("ignored") or check.get("skipped")):
                raise EvidenceError("scenario is missing assertions, failed or skipped")
        return {"passed": len(scenarios), "assertions": sum(check["assertions"] for check in scenarios.values()), "scenarios": sorted(scenarios)}
    if spec["validator"] == "legacy":
        results = re.findall(r"^(?:== )?Results: (\d+) passed(?:, (\d+) failed)?(?: ==)?\s*$", output, re.M)
        if len(results) != 1 or int(results[0][0]) != spec["minimum"] or int(results[0][1] or 0):
            raise EvidenceError("original terminal/composer/effort Results count changed or failed")
        names = re.findall(r"^\s*PASS\s+(.+)$", output, re.M)
        if len(names) != spec["minimum"] or re.search(r"^\s*FAIL\s", output, re.M):
            raise EvidenceError("original Results summary is not backed by successful checks")
        if spec["name"] == "terminal-original" and ("mock provider: started" not in output or "mock provider: already running" in output):
            raise EvidenceError("original terminal suite reused an unrelated mock provider")
        return {"passed": len(names), "checks": names}
    return {"passed": 1, "observed_exit_zero": True}


def observe_process(command, log, environment, timeout):
    process = subprocess.Popen(command, cwd=REPO, env=environment, stdin=subprocess.DEVNULL,
                               stdout=log, stderr=subprocess.STDOUT)
    deadline = time.monotonic() + timeout
    failure = None
    try:
        while process.poll() is None:
            if time.monotonic() >= deadline:
                failure = "command timed out"
                break
            if os.fstat(log.fileno()).st_size > MAX_LOG:
                failure = "command log exceeds 128 MiB"
                break
            time.sleep(0.2)
    except BaseException:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
        raise
    if failure:
        process.terminate()
        try:
            process.wait(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=3)
    return process.wait(), failure


def run_job(spec, stage, baseline, binaries, store, environment):
    assert_frozen(baseline, binaries)
    if spec["name"] == "terminal-original":
        spec = {**spec, "command": list(spec["command"])}
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        spec["command"][spec["command"].index("--gate") + 1] = f"http://127.0.0.1:{port}"
    identity = stage + "-" + spec["name"] + "-" + uuid.uuid4().hex
    log_name, result_name = identity + ".log", identity + ".json"
    record = {"schema": "orbit.priorities35.command/v1", "name": spec["name"], "stage": stage,
              "command": spec["command"], "cwd": str(REPO), "environment": ENVIRONMENT_POLICY,
              "fingerprint_sha256": sha(canonical(baseline)), "started_ns": time.time_ns(),
              "completed_ns": None, "exit_code": None, "observed_completed": False,
              "status": "failed", "log": log_name, "log_sha256": None, "result": None,
              "gate_log": None, "gate_sha256": None, "error": None}
    print(f"START {stage}/{spec['name']}", flush=True)
    try:
        # verify_priority_checks performs its own fresh gate for counted commands.
        if spec["validator"] in ("legacy", "exit"):
            gate_name = identity + "-gate.log"
            with store.create(gate_name) as gate:
                code, reason = observe_process([sys.executable, str(VERIFY), "gate"], gate, environment, 30)
                gate.flush()
                os.fsync(gate.fileno())
            record["gate_log"] = gate_name
            record["gate_sha256"] = sha(store.read(gate_name, MAX_LOG))
            if code or reason:
                raise EvidenceError("fresh resource gate refused this command")
        with store.create(log_name) as log:
            code, reason = observe_process(spec["command"], log, environment, spec["timeout"])
            log.flush()
            os.fsync(log.fileno())
        record.update(completed_ns=time.time_ns(), exit_code=code, observed_completed=True)
        data = store.read(log_name, MAX_LOG)
        record["log_sha256"] = sha(data)
        if code or reason:
            raise EvidenceError(reason or f"command exited {code}")
        record["result"] = validate_output(spec, data.decode("utf-8", errors="replace"))
        assert_frozen(baseline, binaries)
        record["status"] = "passed"
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        record["error"] = str(error)
        store.write(result_name, record)
        raise EvidenceError(f"{stage}/{spec['name']} failed; inspect private {result_name}") from error
    store.write(result_name, record)
    print(f"PASS {stage}/{spec['name']}: {record['result']['passed']} observed checks", flush=True)
    return result_name


def completed_job(spec, stage, baseline, store):
    prefix = stage + "-" + spec["name"] + "-"
    candidates = []
    for name in os.listdir(store.fd):
        if not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}\.json", name):
            continue
        record = parse_json(store.read(name))
        if isinstance(record, dict) and record.get("status") == "passed":
            checked = check_record(name, spec, stage, baseline, store)
            candidates.append((checked["completed_ns"], name))
    if candidates:
        name = max(candidates)[1]
        print(f"REUSE {stage}/{spec['name']}: verified completed command and log", flush=True)
        return name
    return None


def check_record(name, spec, stage, baseline, store):
    record = parse_json(store.read(name))
    expected = {"schema", "name", "stage", "command", "cwd", "environment", "fingerprint_sha256",
                "started_ns", "completed_ns", "exit_code", "observed_completed", "status", "log", "log_sha256",
                "result", "gate_log", "gate_sha256", "error"}
    exact_keys(record, expected, "command evidence")
    if (record["schema"] != "orbit.priorities35.command/v1" or record["status"] != "passed"
            or record["observed_completed"] is not True or type(record["exit_code"]) is not int or record["exit_code"] != 0
            or record["fingerprint_sha256"] != sha(canonical(baseline)) or record["error"] is not None
            or record["name"] != spec["name"] or record["stage"] != stage or record["cwd"] != str(REPO)
            or record["environment"] != ENVIRONMENT_POLICY or not same_command(record["command"], spec["command"])
            or type(record["started_ns"]) is not int or type(record["completed_ns"]) is not int
            or not 0 < record["started_ns"] <= record["completed_ns"] <= time.time_ns()):
        raise EvidenceError("command evidence is stale, incomplete or belongs to another invocation")
    data, log_info = read_regular(store.path / store.name(record["log"]), MAX_LOG, private=True)
    if not record["started_ns"] <= log_info.st_mtime_ns <= record["completed_ns"]:
        raise EvidenceError("command log was not written during its observed invocation")
    if sha(data) != record["log_sha256"] or validate_output(spec, data.decode("utf-8", errors="replace")) != record["result"]:
        raise EvidenceError("command log is missing, altered or disagrees with its result")
    if spec["validator"] in ("legacy", "exit"):
        gate = store.read(record["gate_log"], MAX_LOG)
        if sha(gate) != record["gate_sha256"] or not gate.startswith(b"resource gate passed:"):
            raise EvidenceError("completed command lacks its fresh successful resource gate")
    return record


def same_command(saved, current):
    # The one-use private fixture homes differ when reconstructing specifications.
    if not isinstance(saved, list) or len(saved) != len(current):
        return False
    for index, (left, right) in enumerate(zip(saved, current)):
        if index and current[index - 1] == "--home":
            if not isinstance(left, str) or Path(left).parent != Path(right).parent:
                return False
            prefix = "web-home-" if "web-home-" in right else "terminal-home-"
            if not re.fullmatch(re.escape(prefix) + r"[0-9a-f]{32}", Path(left).name):
                return False
        elif index and current[index - 1] == "--gate":
            match = re.fullmatch(r"http://127\.0\.0\.1:([0-9]{1,5})", left) if isinstance(left, str) else None
            if not match or not 1 <= int(match.group(1)) <= 65535:
                return False
        elif left != right:
            return False
    return True


def load_stage(stage, baseline, binaries, store):
    receipt = parse_json(store.read(stage + ".json"))
    exact_keys(receipt, {"schema", "stage", "status", "fingerprint_sha256", "completed_ns", "commands", "groups"}, "stage evidence")
    specs = jobs_for(stage, binaries, store)
    if (receipt["schema"] != "orbit.priorities35.stage/v1" or receipt["stage"] != stage
            or receipt["status"] != "passed" or receipt["fingerprint_sha256"] != sha(canonical(baseline))
            or type(receipt["completed_ns"]) is not int or not 0 < receipt["completed_ns"] <= time.time_ns()
            or not isinstance(receipt["commands"], list) or len(receipt["commands"]) != len(specs)
            or len(set(receipt["commands"])) != len(specs)):
        raise EvidenceError("stage evidence is missing, stale or incomplete")
    records = [check_record(name, spec, stage, baseline, store) for name, spec in zip(receipt["commands"], specs)]
    previous = 0
    for record in records:
        if record["started_ns"] < previous or record["completed_ns"] > receipt["completed_ns"]:
            raise EvidenceError("stage command completion ordering is invalid")
        previous = record["completed_ns"]
    if receipt["groups"] != make_groups(stage, specs, records):
        raise EvidenceError("stage groups disagree with observed command results")
    return receipt


def make_groups(stage, specs, records):
    result = {}
    for name in (GROUPS if stage == "workflows" else [spec["name"] for spec in specs]):
        members = [record for spec, record in zip(specs, records)
                   if (spec.get("group") if stage == "workflows" else spec["name"]) == name]
        if not members or any(record["status"] != "passed" for record in members):
            raise EvidenceError("workflow group lacks actual completed checks")
        result[name] = {"passed": True, "assertions": sum(record["result"]["passed"] for record in members),
                        "commands": [record["name"] for record in members]}
    return result


def passed_document(path):
    data, _ = read_regular(path, MAX_DOCUMENT, private=True)
    text = data.decode("utf-8")
    if not text.startswith("---\n") or "\n---\n" not in text[4:]:
        raise EvidenceError("final review/verification must have explicit YAML frontmatter")
    header = text[4:].split("\n---\n", 1)[0]
    if len(header) > 16384:
        raise EvidenceError("document frontmatter is too large")
    fields = {}
    for line in header.splitlines():
        match = re.fullmatch(r"([A-Za-z_][A-Za-z0-9_-]*):\s*(.*?)\s*", line)
        if match:
            key, value = match.groups()
            if key in fields:
                raise EvidenceError("duplicate frontmatter key")
            fields[key] = value
    if fields.get("status") not in ("passed", "'passed'", '"passed"'):
        raise EvidenceError("final review/verification status must explicitly be passed")
    return sha(data)


def close_stages(args, baseline, binaries, store):
    workflows = load_stage("workflows", baseline, binaries, store)
    regression = load_stage("regression", baseline, binaries, store)
    verification = ordinary_path(args.verification, absolute=True)
    reviews = [ordinary_path(path, absolute=True) for path in args.review]
    if not reviews or len(reviews) > 32 or len(set(reviews)) != len(reviews):
        raise EvidenceError("closure requires distinct explicit final review paths")
    manifest_path = ordinary_path(args.review_manifest, absolute=True)
    if verification in reviews or manifest_path == verification or manifest_path in reviews:
        raise EvidenceError("verification, independent reviews and manifest must be distinct artifacts")
    manifest_data, _ = read_regular(manifest_path, 256 * 1024, private=True)
    manifest = parse_json(manifest_data)
    exact_keys(manifest, {"schema", "status", "fingerprint_sha256", "verification", "reviews",
                          "baseline_preserved", "artifact_hygiene_passed"}, "final review manifest")
    if (manifest["schema"] != "orbit.priorities35.review/v1" or manifest["status"] != "passed"
            or manifest["fingerprint_sha256"] != sha(canonical(baseline))
            or manifest["baseline_preserved"] is not True or manifest["artifact_hygiene_passed"] is not True):
        raise EvidenceError("final review manifest does not attest the current frozen source and completed audits")
    exact_keys(manifest["verification"], {"path", "sha256"}, "verification identity")
    if manifest["verification"] != {"path": str(verification), "sha256": passed_document(verification)}:
        raise EvidenceError("final verification path/hash/status does not match")
    if not isinstance(manifest["reviews"], list) or len(manifest["reviews"]) != len(reviews):
        raise EvidenceError("final independent review identities do not match")
    for review, entry in zip(reviews, manifest["reviews"]):
        exact_keys(entry, {"path", "sha256", "status", "unresolved_findings"}, "review identity")
        if (entry["path"] != str(review) or entry["sha256"] != passed_document(review)
                or entry["status"] != "passed" or type(entry["unresolved_findings"]) is not int
                or entry["unresolved_findings"] != 0):
            raise EvidenceError("final independent review has stale evidence or unresolved findings")
    assert_frozen(baseline, binaries)
    return {"schema": "orbit.priorities35.closure/v1", "stage": "closure", "status": "passed",
            "fingerprint_sha256": sha(canonical(baseline)), "completed_ns": time.time_ns(),
            "workflow_receipt_sha256": sha(store.read("workflows.json")),
            "regression_receipt_sha256": sha(store.read("regression.json")),
            "review_manifest": {"path": str(manifest_path), "sha256": sha(manifest_data)},
            "verification": manifest["verification"], "reviews": manifest["reviews"],
            "groups": workflows["groups"], "regression": regression["groups"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""Closure manifest (produced by root only after actual final reviews/audits):
  {"schema":"orbit.priorities35.review/v1","status":"passed",
   "fingerprint_sha256":"<digest printed by workflows>",
   "verification":{"path":"/absolute/VERIFICATION.md","sha256":"<exact SHA256>"},
   "reviews":[{"path":"/absolute/FINAL-REVIEW.md","sha256":"<exact SHA256>",
               "status":"passed","unresolved_findings":0}],
   "baseline_preserved":true,"artifact_hygiene_passed":true}
Every review and verification document must be an owned private regular file,
with top-level YAML frontmatter status: passed. No document or pass manifest is
created by the collector. Existing older review documents may be linked by the
combined final review. Closure requires matching completed workflows/regression
receipts, exact log/document hashes and the unchanged source/CLI/web/mock set.
""")
    parser.add_argument("--stage", choices=("workflows", "regression", "closure"), required=True)
    parser.add_argument("--evidence-dir", required=True)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--web-binary", required=True)
    parser.add_argument("--mock-binary")
    parser.add_argument("--verification")
    parser.add_argument("--review", action="append", default=[])
    parser.add_argument("--review-manifest")
    args = parser.parse_args()
    if args.stage == "closure":
        if not args.verification or not args.review or not args.review_manifest:
            parser.error("closure requires --verification, --review and --review-manifest")
    elif args.verification or args.review or args.review_manifest:
        parser.error("review/verification inputs are accepted only by closure")
    require_jail()
    binaries = {"cli": ordinary_path(args.binary), "web": ordinary_path(args.web_binary)}
    binaries["mock"] = ordinary_path(args.mock_binary) if args.mock_binary else binaries["cli"].with_name("orbit-mock-provider")
    environment = {key: value for key, value in os.environ.items() if key != "NO_COLOR" and not key.startswith("ORBIT_")}
    environment.update(ENVIRONMENT)
    store = Store(args.evidence_dir)
    baseline = fingerprint(binaries)
    if store.exists("fingerprint.json"):
        if parse_json(store.read("fingerprint.json")) != baseline:
            raise EvidenceError("source/binary fingerprint drift; completed evidence cannot be reused")
    elif args.stage != "workflows":
        raise EvidenceError("workflows must create the frozen fingerprint before later stages")
    else:
        store.write("fingerprint.json", baseline)
    print("FINGERPRINT_SHA256 " + sha(canonical(baseline)), flush=True)
    if args.stage == "closure":
        receipt = close_stages(args, baseline, binaries, store)
        if store.exists("closure.json"):
            old = parse_json(store.read("closure.json"))
            if {k: v for k, v in old.items() if k != "completed_ns"} != {k: v for k, v in receipt.items() if k != "completed_ns"}:
                raise EvidenceError("closure inputs changed; previous closure is stale")
        else:
            store.write("closure.json", receipt)
    elif store.exists(args.stage + ".json"):
        receipt = load_stage(args.stage, baseline, binaries, store)
        print("Reusing this collector's verified completed stage; no unchanged broad checks repeated", flush=True)
    else:
        if args.stage == "regression":
            load_stage("workflows", baseline, binaries, store)
        specs = jobs_for(args.stage, binaries, store)
        names = []
        for spec in specs:
            existing = completed_job(spec, args.stage, baseline, store)
            names.append(existing or run_job(spec, args.stage, baseline, binaries, store, environment))
        records = [check_record(name, spec, args.stage, baseline, store) for name, spec in zip(names, specs)]
        assert_frozen(baseline, binaries)
        receipt = {"schema": "orbit.priorities35.stage/v1", "stage": args.stage, "status": "passed",
                   "fingerprint_sha256": sha(canonical(baseline)), "completed_ns": time.time_ns(),
                   "commands": names, "groups": make_groups(args.stage, specs, records)}
        store.write(args.stage + ".json", receipt)
    print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": receipt["groups"]}, sort_keys=True), flush=True)
    print("Completed evidence: " + str(store.path / (args.stage + ".json")), flush=True)
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError, KeyError, UnicodeError, subprocess.SubprocessError) as error:
        print("acceptance failed: " + str(error), file=sys.stderr)
        sys.exit(1)
