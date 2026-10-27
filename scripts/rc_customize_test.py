#!/usr/bin/env python3
"""Actual checked customization commands and files; run through in-jail.sh."""
import argparse
from contextlib import AbstractContextManager
import copy
import fcntl
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import select
from pathlib import Path
import subprocess
import shutil
import stat
import sys
import time
import tempfile
import threading


CUSTOMIZATION_PATHS = frozenset({"customization.json", "tui.toml", ".customization.lock"})
SESSION_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
JSON_LIMIT = 4096


def _require(condition, message):
    if not condition:
        raise ValueError(message)


def _unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON key")
        value[key] = item
    return value


def _reject_json_constant(value):
    raise ValueError("non-standard JSON constant")


def _strict_json(raw, label, maximum=JSON_LIMIT):
    _require(isinstance(raw, bytes), label + " must be bytes")
    _require(len(raw) <= maximum, label + " exceeds its byte limit")
    try:
        text = raw.decode("utf-8", errors="strict")
        value = json.loads(text, object_pairs_hook=_unique_object,
                           parse_constant=_reject_json_constant)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ValueError(label + " is not strict UTF-8 JSON") from exc
    return value


def _exact_keys(value, expected, label):
    _require(type(value) is dict, label + " must be an object")
    _require(set(value) == set(expected), label + " has missing or unknown keys")


def _exact_zero(value, label):
    _require(type(value) is int and value == 0, label + " must be JSON integer zero")


def _valid_session_id(value):
    return type(value) is str and SESSION_ID_RE.fullmatch(value) is not None


def _validate_session_value(value, session_id, record, gate, workspace):
    _require(_valid_session_id(session_id), "invalid session id")
    _exact_keys(value, {
        "schema", "session_id", "model", "gate", "provider", "workspace",
        "selection_origin", "transcript", "turns", "input_tokens",
        "output_tokens", "cost_microcents", "accounting_watermark", "updated_at",
    }, "session")
    _require("effort" not in value, "optional effort must be omitted")
    _require(value["schema"] == "orbit.session/v1", "wrong session schema")
    _require(value["session_id"] == session_id, "session id mismatch")
    _require(value["provider"] == "fixture", "wrong provider")
    _require(value["model"] == "local", "wrong model")
    _require(value["gate"] == gate, "wrong gate")
    _require(value["workspace"] == str(Path(workspace).resolve()), "wrong workspace")
    _require(value["selection_origin"] == record["origin"], "wrong selection origin")
    _require(type(value["transcript"]) is list and value["transcript"] == [], "session transcript is not empty")
    for key in ("turns", "input_tokens", "output_tokens", "cost_microcents"):
        _exact_zero(value[key], "session." + key)
    stamp = value["updated_at"]
    _require(type(stamp) is str and re.fullmatch(r"(?:0|[1-9][0-9]*)", stamp, flags=re.ASCII) is not None,
             "updated_at is not canonical ASCII base-10")
    _require(int(stamp) <= 18446744073709551615, "updated_at exceeds u64")
    watermark = value["accounting_watermark"]
    _exact_keys(watermark, {
        "owner_session_id", "child_id", "revision", "known_input_tokens",
        "known_output_tokens", "known_ordinary_microcents",
        "known_housekeeping_microcents", "full_cost_status",
    }, "accounting watermark")
    _require(watermark["owner_session_id"] == session_id, "watermark owner mismatch")
    _require(watermark["child_id"] is None, "root watermark has a child id")
    for key in ("revision", "known_input_tokens", "known_output_tokens",
                "known_ordinary_microcents", "known_housekeeping_microcents"):
        _exact_zero(watermark[key], "watermark." + key)
    _require(watermark["full_cost_status"] == "known", "watermark cost status is not known")
    return value


def _fresh_accounting(session_id):
    return {
        "version": 1,
        "owner": session_id,
        "entries": [{
            "namespace": {"kind": "owner"},
            "revision": 0,
            "baseline": "fresh_known_zero",
            "totals": {
                "ordinary": {"input_tokens": 0, "output_tokens": 0, "cost_microcents": 0},
                "housekeeping": {"input_tokens": 0, "output_tokens": 0, "cost_microcents": 0},
                "knownness": "known",
            },
            "pending": None,
            "last": None,
            "known_priced_subtotals": {
                "ordinary_microcents": 0,
                "housekeeping_microcents": 0,
            },
        }],
    }


def _validate_accounting_value(value, session_id):
    _exact_keys(value, {"version", "owner", "entries"}, "accounting container")
    _require(type(value["version"]) is int and value["version"] == 1, "wrong accounting version")
    _require(value["owner"] == session_id, "accounting owner mismatch")
    _require(type(value["entries"]) is list and len(value["entries"]) == 1,
             "accounting entry count mismatch")
    entry = value["entries"][0]
    _exact_keys(entry, {
        "namespace", "revision", "baseline", "totals", "pending", "last",
        "known_priced_subtotals",
    }, "accounting entry")
    _exact_keys(entry["namespace"], {"kind"}, "accounting namespace")
    _require(entry["namespace"]["kind"] == "owner", "accounting namespace is not owner")
    _exact_zero(entry["revision"], "accounting revision")
    _require(entry["baseline"] == "fresh_known_zero", "wrong accounting baseline")
    _require(entry["pending"] is None and entry["last"] is None,
             "fresh accounting must have null pending and last")
    totals = entry["totals"]
    _exact_keys(totals, {"ordinary", "housekeeping", "knownness"}, "accounting totals")
    for category in ("ordinary", "housekeeping"):
        item = totals[category]
        _exact_keys(item, {"input_tokens", "output_tokens", "cost_microcents"},
                    "accounting " + category)
        for key in ("input_tokens", "output_tokens", "cost_microcents"):
            _exact_zero(item[key], category + "." + key)
    _require(totals["knownness"] == "known", "accounting knownness is not known")
    priced = entry["known_priced_subtotals"]
    _exact_keys(priced, {"ordinary_microcents", "housekeeping_microcents"},
                "known priced subtotals")
    for key in ("ordinary_microcents", "housekeeping_microcents"):
        _exact_zero(priced[key], "priced." + key)
    return value


def _validate_lease_value(value, record):
    _exact_keys(value, {"session_id", "kind", "pid"}, "session lease")
    _require(value["session_id"] == record["session_id"], "lease session id mismatch")
    _require(value["kind"] == "chat", "lease kind is not chat")
    _require(type(value["pid"]) is int and value["pid"] == record["pid"],
             "lease pid mismatch")
    return value


def _open_nofollow_path(path, flags):
    absolute = Path(os.path.abspath(os.fspath(path)))
    parts = absolute.parts
    _require(len(parts) >= 2 and parts[0] == os.sep,
             "artifact path must be absolute")
    directory_flags = (os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
                       | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0))
    parent_fd = os.open(parts[0], directory_flags)
    try:
        for component in parts[1:-1]:
            next_fd = os.open(component, directory_flags, dir_fd=parent_fd)
            os.close(parent_fd)
            parent_fd = next_fd
        return os.open(parts[-1], flags | getattr(os, "O_NOFOLLOW", 0), dir_fd=parent_fd)
    finally:
        os.close(parent_fd)


def _reject_tree_links(snapshot, label):
    _require(not any(item["kind"] in {"symlink", "special"} for item in snapshot.values()),
             label + " contains a symlink or special file")


def _read_regular(path, label, mode=0o600, maximum=JSON_LIMIT, empty=False):
    try:
        before = os.lstat(path)
    except OSError as exc:
        raise ValueError(label + " is missing") from exc
    _require(stat.S_ISREG(before.st_mode), label + " is not a regular non-symlink file")
    _require(stat.S_IMODE(before.st_mode) == mode, label + " has the wrong mode")
    _require(before.st_uid == os.getuid(), label + " has the wrong owner")
    _require(before.st_nlink == 1, label + " is hard-linked")
    if maximum is not None:
        _require(before.st_size <= maximum, label + " exceeds its byte limit")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = _open_nofollow_path(path, flags)
    except OSError as exc:
        raise ValueError(label + " cannot be safely opened") from exc
    try:
        current = os.fstat(fd)
        _require((current.st_dev, current.st_ino) == (before.st_dev, before.st_ino),
                 label + " changed while opening")
        _require(stat.S_ISREG(current.st_mode) and current.st_nlink == 1,
                 label + " changed into an unsafe file")
        _require(stat.S_IMODE(current.st_mode) == mode and current.st_uid == os.getuid(),
                 label + " changed mode or owner while opening")
        if maximum is not None:
            _require(current.st_size <= maximum, label + " grew beyond its byte limit")
        chunks = []
        total = 0
        while True:
            size = 65536 if maximum is None else min(65536, maximum + 1 - total)
            if size <= 0:
                raise ValueError(label + " exceeds its byte limit")
            chunk = os.read(fd, size)
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if maximum is not None and total > maximum:
                raise ValueError(label + " exceeds its byte limit")
        raw = b"".join(chunks)
        after = os.fstat(fd)
        _require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                  after.st_ctime_ns, stat.S_IMODE(after.st_mode), after.st_uid, after.st_nlink)
                 == (current.st_dev, current.st_ino, current.st_size, current.st_mtime_ns,
                     current.st_ctime_ns, stat.S_IMODE(current.st_mode), current.st_uid,
                     current.st_nlink), label + " changed while reading")
    finally:
        os.close(fd)
    if empty:
        _require(raw == b"", label + " must be empty")
    return raw, before


def _validate_session_file(path, record, gate, workspace):
    expected = Path(path).parent / (record["session_id"] + ".json")
    _require(Path(path) == expected and Path(path).parent.name == "sessions",
             "session file path is not bound to its id")
    raw, _ = _read_regular(path, "session JSON")
    value = _strict_json(raw, "session JSON")
    return _validate_session_value(value, record["session_id"], record, gate, workspace)


def _validate_accounting_file(path, session_id):
    expected = Path(path).parent / "accounting.json"
    _require(Path(path) == expected and Path(path).parent.name == session_id
             and Path(path).parent.parent.name == "context-history",
             "accounting file path is not bound to its owner")
    raw, _ = _read_regular(path, "accounting JSON")
    return _validate_accounting_value(_strict_json(raw, "accounting JSON"), session_id)


def _validate_lease_file(path, record, live):
    expected = Path(path).parent / (record["session_id"] + ".lock")
    _require(Path(path) == expected and Path(path).parent.name == ".leases"
             and Path(path).parent.parent.name == "sessions",
             "lease path is not bound to its session")
    raw, metadata = _read_regular(path, "session lease")
    value = _validate_lease_value(_strict_json(raw, "session lease"), record)
    proc = record["process"]
    _require(type(record["pid"]) is int and record["pid"] == proc.pid,
             "lease record PID is not the exact child PID")
    if live:
        _require(proc.poll() is None, "lease process exited before live check")
        identity = (metadata.st_dev, metadata.st_ino)
        prior = record.get("lease_identity")
        _require(prior is None or prior == identity, "lease inode changed while child was live")
        record["lease_identity"] = identity
    else:
        _require(proc.poll() is not None, "lease process is still alive at release check")
        _require(record.get("lease_identity") == (metadata.st_dev, metadata.st_ino),
                 "released lease inode was replaced")
    flags = os.O_RDWR | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        opened = os.fstat(fd)
        _require((opened.st_dev, opened.st_ino) == (metadata.st_dev, metadata.st_ino),
                 "lease changed while checking its lock")
        _require(proc.poll() is None if live else proc.poll() is not None,
                 "lease process state changed during lock check")
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            _require(live, "released lease is still held")
        else:
            try:
                _require(not live, "live lease is not held by its child")
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)
    return value


def _tree_snapshot(root):
    root = Path(root)
    result = {}
    pending = [(root, "")]
    while pending:
        directory, prefix = pending.pop()
        entries = sorted(os.scandir(directory), key=lambda item: item.name, reverse=True)
        for item in entries:
            relative = item.name if not prefix else prefix + "/" + item.name
            path = root / relative
            st = os.lstat(path)
            mode = stat.S_IMODE(st.st_mode)
            if stat.S_ISDIR(st.st_mode):
                result[relative] = {"kind": "dir", "mode": mode, "uid": st.st_uid}
                pending.append((path, relative))
            elif stat.S_ISREG(st.st_mode):
                _require(st.st_nlink == 1, "hard-linked file in fixture tree: " + relative)
                digest = hashlib.sha256()
                flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
                fd = _open_nofollow_path(path, flags)
                try:
                    current = os.fstat(fd)
                    _require((current.st_dev, current.st_ino) == (st.st_dev, st.st_ino),
                             "file changed while snapshotting: " + relative)
                    total = 0
                    while True:
                        chunk = os.read(fd, 65536)
                        if not chunk:
                            break
                        total += len(chunk)
                        _require(total <= 64 * 1024 * 1024, "fixture file exceeds snapshot bound")
                        digest.update(chunk)
                    after = os.fstat(fd)
                    _require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                              after.st_ctime_ns, stat.S_IMODE(after.st_mode), after.st_uid,
                              after.st_nlink)
                             == (current.st_dev, current.st_ino, current.st_size,
                                 current.st_mtime_ns, current.st_ctime_ns,
                                 stat.S_IMODE(current.st_mode), current.st_uid, current.st_nlink),
                             "file changed while hashing: " + relative)
                finally:
                    os.close(fd)
                result[relative] = {
                    "kind": "file", "mode": mode, "uid": st.st_uid, "nlink": st.st_nlink,
                    "size": total, "sha256": digest.hexdigest(),
                }
            elif stat.S_ISLNK(st.st_mode):
                result[relative] = {
                    "kind": "symlink", "mode": mode, "uid": st.st_uid,
                    "target": os.readlink(path),
                }
            else:
                result[relative] = {
                    "kind": "special", "mode": mode, "uid": st.st_uid,
                    "nlink": st.st_nlink, "rdev": st.st_rdev,
                }
    return result


def _project_subtree(snapshot):
    return {path: value for path, value in snapshot.items()
            if path == "projects" or path.startswith("projects/")}


def _protected_snapshot(root):
    return {path: value for path, value in _tree_snapshot(root).items()
            if path not in CUSTOMIZATION_PATHS}


def _expected_artifacts(records):
    pty = [record for record in records if record["launch_mode"] == "pty"]
    plain = [record for record in records if record["launch_mode"] == "plain"]
    _require(len(pty) <= 4 and len(plain) <= 1, "too many observed chat launches")
    _require(len(pty) + len(plain) == len(records), "unknown chat launch mode")
    ids = [record["session_id"] for record in records]
    pids = [record["pid"] for record in records]
    _require(len(ids) == len(set(ids)) and len(pids) == len(set(pids)),
             "duplicate session id or child pid")
    directories = set()
    files = {}
    for record in records:
        sid = record["session_id"]
        _require(_valid_session_id(sid), "invalid session id")
        _require(type(record["pid"]) is int and record["pid"] > 0, "invalid child pid")
        _require(record["origin"] == ("flag" if record["launch_mode"] == "pty" else "role"),
                 "launch has an unexpected origin")
        _require(record["transcript"] is (record["launch_mode"] == "pty"),
                 "launch has an unexpected transcript policy")
        directories.update({
            "sessions", "sessions/.leases", "context-history",
            "context-history/" + sid, "context-history/" + sid + "/archives",
        })
        files.update({
            "sessions/" + sid + ".json": "session",
            "sessions/.leases/" + sid + ".lock": "lease",
            "context-history/" + sid + "/accounting.json": "accounting",
            "context-history/" + sid + "/.history.lock": "history_lock",
        })
        if record["transcript"]:
            directories.add("projects")
            files["projects/" + sid + ".jsonl"] = "transcript"
    return directories, files


def _validate_artifact_tree(root, baseline, records):
    root_stat = os.lstat(root)
    _require(stat.S_ISDIR(root_stat.st_mode) and stat.S_IMODE(root_stat.st_mode) == 0o700
             and root_stat.st_uid == os.getuid(), "fixture home has unsafe type, mode or owner")
    current = _tree_snapshot(root)
    _reject_tree_links(current, "fixture home")
    directories, files = _expected_artifacts(records)
    mutable = {path for path in CUSTOMIZATION_PATHS if path in current}
    expected_paths = set(baseline) | directories | set(files) | mutable
    _require(set(current) == expected_paths,
             ("unallowlisted or missing fixture path",
              sorted(set(current) - expected_paths), sorted(expected_paths - set(current)))
             )
    for path, expected in baseline.items():
        if path not in CUSTOMIZATION_PATHS:
            _require(current.get(path) == expected, "protected baseline changed: " + path)
    for path in mutable:
        item = current[path]
        _require(item["kind"] == "file" and item["uid"] == os.getuid()
                 and item["nlink"] == 1 and item["mode"] in {0o600, 0o644},
                 "unsafe mutable customization path: " + path)
    for path in directories:
        item = current[path]
        _require(item["kind"] == "dir" and item["mode"] == 0o700
                 and item["uid"] == os.getuid(),
                 "unsafe artifact directory: " + path)
    for path, kind in files.items():
        item = current[path]
        _require(item["kind"] == "file" and item["mode"] == 0o600
                 and item["uid"] == os.getuid() and item["nlink"] == 1,
                 "unsafe artifact file: " + path)
        if kind in {"history_lock", "transcript"}:
            _require(item["size"] == 0, "unexpected bytes in " + kind)
    for record in records:
        if record["launch_mode"] == "plain":
            _require(_project_subtree(current) == record["projects_before"],
                     "plain REPL changed its projects subtree")
    return current




def _fixture_session_value(session_id, origin, gate, workspace):
    return {
        "schema": "orbit.session/v1",
        "session_id": session_id,
        "model": "local",
        "gate": gate,
        "provider": "fixture",
        "workspace": str(Path(workspace).resolve()),
        "selection_origin": origin,
        "transcript": [],
        "turns": 0,
        "input_tokens": 0,
        "output_tokens": 0,
        "cost_microcents": 0,
        "accounting_watermark": {
            "owner_session_id": session_id,
            "child_id": None,
            "revision": 0,
            "known_input_tokens": 0,
            "known_output_tokens": 0,
            "known_ordinary_microcents": 0,
            "known_housekeeping_microcents": 0,
            "full_cost_status": "known",
        },
        "updated_at": "1700000000",
    }


def _set_nested(value, path, replacement):
    current = value
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = replacement


def _write_private(path, data, mode=0o600):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.write_bytes(data)
    path.chmod(mode)


def _oracle_rejects(label, operation):
    try:
        operation()
    except (ValueError, OSError):
        return
    raise AssertionError("oracle accepted invalid case: " + label)


def _seed_plain_artifact_tree(root, record, gate, workspace):
    directories, files = _expected_artifacts([record])
    for relative in sorted(directories, key=lambda item: item.count("/")):
        path = Path(root) / relative
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
        path.chmod(0o700)
    session = _fixture_session_value(record["session_id"], "role", gate, workspace)
    payloads = {
        "session": json.dumps(session, separators=(",", ":")).encode(),
        "lease": json.dumps({"session_id": record["session_id"], "kind": "chat",
                             "pid": record["pid"]}, separators=(",", ":")).encode(),
        "accounting": json.dumps(_fresh_accounting(record["session_id"]),
                                  separators=(",", ":")).encode(),
        "history_lock": b"",
    }
    for relative, kind in files.items():
        _write_private(Path(root) / relative, payloads[kind])


def _run_oracle_regressions():
    session_id = "oracle_session-1"
    gate = "http://127.0.0.1:43210"
    workspace = "."
    record = {"session_id": session_id, "origin": "flag"}
    session = _fixture_session_value(session_id, "flag", gate, workspace)
    _validate_session_value(session, session_id, record, gate, workspace)
    accounting = _fresh_accounting(session_id)
    _validate_accounting_value(accounting, session_id)
    accepted = 2

    for label, mutation in [
        ("session schema", lambda value: value.update(schema="other")),
        ("session identity", lambda value: value.update(session_id="other")),
        ("provider", lambda value: value.update(provider="real")),
        ("model", lambda value: value.update(model="other")),
        ("gate", lambda value: value.update(gate="http://other")),
        ("workspace", lambda value: value.update(workspace="/other")),
        ("selection origin", lambda value: value.update(selection_origin="role")),
        ("optional effort", lambda value: value.update(effort=None)),
        ("transcript", lambda value: value.update(transcript=[{}])),
        ("leading-zero timestamp", lambda value: value.update(updated_at="01700000000")),
        ("signed timestamp", lambda value: value.update(updated_at="+1")),
        ("whitespace timestamp", lambda value: value.update(updated_at=" 1")),
        ("u64 overflow timestamp", lambda value: value.update(updated_at="18446744073709551616")),
        ("watermark owner", lambda value: value["accounting_watermark"].update(owner_session_id="other")),
        ("watermark child", lambda value: value["accounting_watermark"].update(child_id="child")),
        ("watermark cost status", lambda value: value["accounting_watermark"].update(full_cost_status="unknown")),
        ("watermark missing key", lambda value: value["accounting_watermark"].pop("child_id")),
        ("watermark extra key", lambda value: value["accounting_watermark"].update(extra=0)),
    ]:
        candidate = copy.deepcopy(session)
        mutation(candidate)
        _oracle_rejects(label, lambda candidate=candidate: _validate_session_value(
            candidate, session_id, record, gate, workspace))
        accepted += 1

    session_numeric_paths = [(key,) for key in ("turns", "input_tokens", "output_tokens", "cost_microcents")]
    session_numeric_paths += [("accounting_watermark", key) for key in (
        "revision", "known_input_tokens", "known_output_tokens",
        "known_ordinary_microcents", "known_housekeeping_microcents")]
    for path in session_numeric_paths:
        for invalid in (True, 1):
            candidate = copy.deepcopy(session)
            _set_nested(candidate, path, invalid)
            _oracle_rejects("invalid session numeric " + ".".join(path) + "=" + repr(invalid),
                            lambda candidate=candidate: _validate_session_value(
                                candidate, session_id, record, gate, workspace))
            accepted += 1

    for label, raw in [
        ("duplicate JSON key", b'{"x":0,"x":1}'),
        ("invalid UTF-8", b'{"x":"\xff"}'),
        ("malformed JSON", b'{"x":'),
        ("oversized JSON", b" " * (JSON_LIMIT + 1)),
        ("nonstandard JSON constant", b'{"x":NaN}'),
    ]:
        _oracle_rejects(label, lambda raw=raw: _strict_json(raw, label))
        accepted += 1

    session_mutations = [
        ("unknown session key", lambda value: value.update(extra=1)),
        ("missing session key", lambda value: value.pop("provider")),
    ]
    for label, mutation in session_mutations:
        candidate = copy.deepcopy(session)
        mutation(candidate)
        _oracle_rejects(label, lambda candidate=candidate: _validate_session_value(
            candidate, session_id, record, gate, workspace))
        accepted += 1

    accounting_mutations = [
        ("wrong accounting version type", lambda value: value.update(version=True)),
        ("wrong accounting version integer", lambda value: value.update(version=2)),
        ("wrong accounting baseline", lambda value: value["entries"][0].update(baseline="legacy_unknown")),
        ("missing accounting revision", lambda value: value["entries"][0].pop("revision")),
        ("missing accounting totals", lambda value: value["entries"][0].pop("totals")),
        ("unknown totals field", lambda value: value["entries"][0]["totals"].update(receipt={})),
        ("accounting usage metadata", lambda value: value["entries"][0].update(usage={})),
        ("wrong accounting owner", lambda value: value.update(owner="other")),
        ("missing accounting key", lambda value: value.pop("entries")),
        ("unknown accounting key", lambda value: value.update(extra=0)),
        ("extra accounting entry", lambda value: value["entries"].append(copy.deepcopy(value["entries"][0]))),
        ("missing pending", lambda value: value["entries"][0].pop("pending")),
        ("non-null pending", lambda value: value["entries"][0].update(pending={})),
        ("missing last", lambda value: value["entries"][0].pop("last")),
        ("non-null last", lambda value: value["entries"][0].update(last={})),
        ("refusal metadata", lambda value: value["entries"][0].update(refusals=[])),
        ("child namespace", lambda value: value["entries"][0].update(namespace={"kind":"child","id":"x"})),
        ("unknown namespace field", lambda value: value["entries"][0]["namespace"].update(extra=0)),
        ("knownness", lambda value: value["entries"][0]["totals"].update(knownness="unknown")),
        ("priced subtotal missing", lambda value: value["entries"][0]["known_priced_subtotals"].pop("ordinary_microcents")),
        ("priced subtotal nonzero", lambda value: value["entries"][0]["known_priced_subtotals"].update(ordinary_microcents=1)),
        ("unknown priced subtotal", lambda value: value["entries"][0]["known_priced_subtotals"].update(extra=0)),
        ("extra entry container", lambda value: value.update(extra=[])),
    ]
    for label, mutation in accounting_mutations:
        candidate = copy.deepcopy(accounting)
        mutation(candidate)
        _oracle_rejects(label, lambda candidate=candidate: _validate_accounting_value(candidate, session_id))
        accepted += 1
    accounting_numeric_paths = [("version",), ("entries", 0, "revision")]
    for category in ("ordinary", "housekeeping"):
        accounting_numeric_paths.extend(("entries", 0, "totals", category, key)
                                        for key in ("input_tokens", "output_tokens", "cost_microcents"))
    accounting_numeric_paths.extend(("entries", 0, "known_priced_subtotals", key)
                                    for key in ("ordinary_microcents", "housekeeping_microcents"))
    for path in accounting_numeric_paths:
        invalid_values = (True,) if path == ("version",) else (True, 1)
        for invalid in invalid_values:
            candidate = copy.deepcopy(accounting)
            _set_nested(candidate, path, invalid)
            _oracle_rejects("invalid accounting numeric " + ".".join(map(str, path)) + "=" + repr(invalid),
                            lambda candidate=candidate: _validate_accounting_value(candidate, session_id))
            accepted += 1

    with tempfile.TemporaryDirectory(prefix="orbit-file-oracle-") as temporary:
        root = Path(temporary)
        sid_dir = root / "sessions"
        sid_dir.mkdir(mode=0o700)
        session_path = sid_dir / (session_id + ".json")
        _write_private(session_path, json.dumps(session, separators=(",", ":")).encode())
        _validate_session_file(session_path, record, gate, workspace)
        accepted += 1
        _oracle_rejects("session file path binding", lambda: _validate_session_file(
            sid_dir / "other.json", record, gate, workspace))
        accepted += 1
        session_path.write_bytes(b" " * (JSON_LIMIT + 1))
        session_path.chmod(0o600)
        _oracle_rejects("session file byte limit", lambda: _validate_session_file(
            session_path, record, gate, workspace))
        accepted += 1
        accounting_path = root / "context-history" / session_id / "accounting.json"
        _write_private(accounting_path, json.dumps(accounting, separators=(",", ":")).encode())
        _validate_accounting_file(accounting_path, session_id)
        accepted += 1
        accounting_path.write_bytes(b" " * (JSON_LIMIT + 1))
        accounting_path.chmod(0o600)
        _oracle_rejects("accounting file byte limit", lambda: _validate_accounting_file(
            accounting_path, session_id))
        accepted += 1
        accounting_path.write_bytes(json.dumps(accounting, separators=(",", ":")).encode())
        accounting_path.chmod(0o644)
        _oracle_rejects("accounting file mode", lambda: _validate_accounting_file(
            accounting_path, session_id))
        accepted += 1
        accounting_path.chmod(0o600)
        linked = sid_dir / "linked.json"
        linked.symlink_to(session_path)
        _oracle_rejects("symlink is not a session file", lambda: _read_regular(linked, "linked session"))
        accepted += 1
        hard = sid_dir / "hard.json"
        os.link(accounting_path, hard)
        _oracle_rejects("hard-linked accounting file", lambda: _read_regular(hard, "hard accounting"))
        accepted += 1

    class ProcessState:
        def __init__(self, state, pid=0):
            self.state = state
            self.pid = pid
        def poll(self):
            return self.state

    lease_dir = Path(tempfile.mkdtemp(prefix="orbit-lease-oracle-"))
    try:
        (lease_dir / "sessions" / ".leases").mkdir(mode=0o700, parents=True)
        lease_path = lease_dir / "sessions" / ".leases" / (session_id + ".lock")
        _write_private(lease_path, b"")
        child_code = ("import fcntl,sys; f=open(sys.argv[1],'r+b'); "
                      "fcntl.flock(f,fcntl.LOCK_EX); print('ready',flush=True); sys.stdin.read(1)")
        proc = subprocess.Popen([sys.executable, "-u", "-c", child_code, str(lease_path)],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                text=True, close_fds=True)
        try:
            ready, _, _ = select.select([proc.stdout], [], [], 5)
            _require(bool(ready) and proc.stdout.readline().strip() == "ready",
                     "lease oracle child did not acquire its owned lock")
            _write_private(lease_path, json.dumps({"session_id":session_id,"kind":"chat","pid":proc.pid},
                                                   separators=(",", ":")).encode())
            lease_record = {"session_id":session_id,"pid":proc.pid,"process":proc}
            _validate_lease_file(lease_path, lease_record, live=True)
            accepted += 1
            _oracle_rejects("lease path binding", lambda: _validate_lease_file(
                lease_path.parent / "other.lock", lease_record, live=True))
            accepted += 1
            wrong_process_pid = {**lease_record, "pid": proc.pid + 1}
            _write_private(lease_path, json.dumps({"session_id":session_id,"kind":"chat",
                                                   "pid":proc.pid+1}, separators=(",", ":")).encode())
            _oracle_rejects("lease record PID is not its exact child PID",
                            lambda: _validate_lease_file(lease_path, wrong_process_pid, live=True))
            _write_private(lease_path, json.dumps({"session_id":session_id,"kind":"chat",
                                                   "pid":proc.pid}, separators=(",", ":")).encode())
            accepted += 1
            lease_path.chmod(0o644)
            _oracle_rejects("lease file mode", lambda: _validate_lease_file(lease_path, lease_record, live=True))
            lease_path.chmod(0o600)
            accepted += 1
            wrong_cases = [
                ("lease id", {"session_id":"other","kind":"chat","pid":proc.pid}),
                ("lease kind", {"session_id":session_id,"kind":"worker","pid":proc.pid}),
                ("lease pid", {"session_id":session_id,"kind":"chat","pid":proc.pid+1}),
                ("lease boolean pid", {"session_id":session_id,"kind":"chat","pid":True}),
                ("lease extra key", {"session_id":session_id,"kind":"chat","pid":proc.pid,"extra":0}),
            ]
            for label, value in wrong_cases:
                _oracle_rejects(label, lambda value=value: _validate_lease_value(value, lease_record))
                accepted += 1
            proc.stdin.write("x")
            proc.stdin.flush()
            proc.stdin.close()
            proc.wait(timeout=5)
            _validate_lease_file(lease_path, lease_record, live=False)
            accepted += 1
            held_fd = os.open(lease_path, os.O_RDWR | getattr(os, "O_NOFOLLOW", 0))
            fcntl.flock(held_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _oracle_rejects("held-after-exit lease", lambda: _validate_lease_file(lease_path, lease_record, live=False))
            accepted += 1
            fcntl.flock(held_fd, fcntl.LOCK_UN)
            os.close(held_fd)
            old_fd = os.open(lease_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
            replacement = lease_path.with_suffix(".replacement")
            _write_private(replacement, lease_path.read_bytes())
            os.replace(replacement, lease_path)
            _oracle_rejects("replaced released lease inode", lambda: _validate_lease_file(lease_path, lease_record, live=False))
            accepted += 1
            os.close(old_fd)
        finally:
            if proc.poll() is None:
                try:
                    proc.stdin.close()
                except (AttributeError, OSError, ValueError):
                    pass
                proc.terminate()
                try:
                    proc.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    proc.communicate(timeout=3)
    finally:
        shutil.rmtree(lease_dir)

    with tempfile.TemporaryDirectory(prefix="orbit-unlocked-lease-oracle-") as temporary:
        unlocked = Path(temporary) / "sessions" / ".leases" / (session_id + ".lock")
        _write_private(unlocked, json.dumps({"session_id":session_id,"kind":"chat","pid":12345},
                                            separators=(",", ":")).encode())
        _oracle_rejects("unlocked live lease", lambda: _validate_lease_file(
            unlocked, {"session_id":session_id,"pid":12345,"process":ProcessState(None,12345)}, live=True))
        accepted += 1

    with tempfile.TemporaryDirectory(prefix="orbit-parent-symlink-oracle-") as temporary:
        root = Path(temporary)
        outside = root / "outside"
        outside.mkdir(mode=0o700)
        target = outside / "accounting.json"
        _write_private(target, json.dumps(accounting, separators=(",", ":")).encode())
        home = root / "home"
        home.mkdir(mode=0o700)
        (home / "context-history").symlink_to(outside, target_is_directory=True)
        _oracle_rejects("parent symlink is never opened", lambda: _read_regular(
            home / "context-history" / "accounting.json", "symlinked parent"))
        accepted += 1

    for label, raw in [("duplicate lease key", b'{"session_id":"x","session_id":"y","kind":"chat","pid":1}')]:
        _oracle_rejects(label, lambda raw=raw: _strict_json(raw, label))
        accepted += 1

    plain_record = {"session_id":"plain_oracle","pid":424242,"process":ProcessState(0),
                    "launch_mode":"plain","origin":"role","transcript":False,
                    "projects_before":{}}
    with tempfile.TemporaryDirectory(prefix="orbit-tree-oracle-") as temporary:
        root = Path(temporary)
        _seed_plain_artifact_tree(root, plain_record, gate, workspace)
        _validate_artifact_tree(root, {}, [plain_record])
        accepted += 1
        (root / "projects").mkdir(mode=0o700)
        _oracle_rejects("plain launch empty projects directory", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "projects").rmdir()
        (root / "unexpected-empty").mkdir(mode=0o700)
        _oracle_rejects("unexpected empty directory", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "unexpected-empty").rmdir()
        (root / "unexpected-link").symlink_to(root / "sessions")
        _oracle_rejects("symlink in artifact tree", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "unexpected-link").unlink()
        os.link(root / "sessions" / (plain_record["session_id"] + ".json"), root / "hardlink")
        _oracle_rejects("hard link in artifact tree", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "hardlink").unlink()
        os.mkfifo(root / "special")
        _oracle_rejects("special file in artifact tree", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "special").unlink()
        accounting_file = root / "context-history" / plain_record["session_id"] / "accounting.json"
        accounting_file.chmod(0o644)
        _oracle_rejects("wrong artifact file mode", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        accounting_file.chmod(0o600)
        owner_dir = root / "context-history" / plain_record["session_id"]
        owner_dir.chmod(0o755)
        _oracle_rejects("wrong artifact directory mode", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        owner_dir.chmod(0o700)
        (root / "unrelated-file").write_bytes(b"")
        _oracle_rejects("unrelated file", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        (root / "unrelated-file").unlink()
        (root / "sessions" / "unexpected-empty").mkdir(mode=0o700)
        _oracle_rejects("unexpected nested empty directory", lambda: _validate_artifact_tree(root, {}, [plain_record]))
        accepted += 9

    for invalid_id in ("", "contains/slash", "nonascii-ñ", "x" * 129):
        _oracle_rejects("invalid session ID " + repr(invalid_id),
                        lambda invalid_id=invalid_id: _require(_valid_session_id(invalid_id), "invalid id"))
        accepted += 1

    _oracle_rejects("more than four PTY records", lambda: _expected_artifacts([
        {"session_id":"pt"+str(i),"pid":i+1,"launch_mode":"pty","origin":"flag","transcript":True}
        for i in range(5)]))
    _oracle_rejects("more than one plain record", lambda: _expected_artifacts([
        {"session_id":"pl"+str(i),"pid":i+1,"launch_mode":"plain","origin":"role","transcript":False}
        for i in range(2)]))
    _oracle_rejects("duplicate launch session id", lambda: _expected_artifacts([
        {"session_id":"same","pid":1,"launch_mode":"pty","origin":"flag","transcript":True},
        {"session_id":"same","pid":2,"launch_mode":"pty","origin":"flag","transcript":True}]))
    _oracle_rejects("duplicate launch PID", lambda: _expected_artifacts([
        {"session_id":"first","pid":1,"launch_mode":"pty","origin":"flag","transcript":True},
        {"session_id":"second","pid":1,"launch_mode":"pty","origin":"flag","transcript":True}]))
    accepted += 4
    print("PASS strict_session_accounting_lease_and_filesystem_oracles ({} assertions)".format(accepted), flush=True)
    return accepted


class Fixture(AbstractContextManager):
    def __init__(self, binary):
        self.binary = str(Path(binary).resolve())
        self.tmp = tempfile.TemporaryDirectory(prefix="orbit-customization-release-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.work = self.root / "workspace"
        self.work.mkdir(mode=0o700)
        self.calls = []
        self.sessions = []
        self.chat_records = []
        self.records_by_pid = {}
        calls = self.calls

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                self.send_response(500)
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("ORBIT_")}
        self.env.update(ORBIT_HOME=str(self.home), ORBIT_GATE_TOKEN="customization-fixture-only",
                        ORBIT_GATE_URL=f"http://127.0.0.1:{self.server.server_port}")
        self.run("init", "--no-provider")
        self.home.chmod(0o700)
        (self.home / "providers.toml").write_text(
            f'[[provider]]\nname="fixture"\nurl="{self.env["ORBIT_GATE_URL"]}"\nenv="ORBIT_GATE_TOKEN"\n'
            '[[provider.models]]\nid="local"\n[roles]\nmain="fixture/local"\n')
        (self.home / "providers.toml").chmod(0o600)
        self.protected = _protected_snapshot(self.home)

    def __exit__(self, exc_type, exc, tb):
        cleanup_errors = []
        for session in reversed(self.sessions):
            if session.master is not None:
                try:
                    session.terminate()
                except Exception as error:
                    cleanup_errors.append("PTY cleanup: " + repr(error))
        for record in reversed(self.chat_records):
            process = record["process"]
            try:
                if record["launch_mode"] == "plain":
                    self._reap_plain(process)
                elif process.poll() is None:
                    process.terminate()
                    process.wait(timeout=3)
                _require(process.poll() is not None, "owned chat child remained alive during cleanup")
                if record["observed"] and process.poll() is not None:
                    self.finish_launch(record)
            except Exception as error:
                cleanup_errors.append("chat cleanup: " + repr(error))
        try:
            self.server.shutdown()
            self.server.server_close()
            self.thread.join(timeout=3)
            if self.thread.is_alive():
                cleanup_errors.append("provider fixture thread remained alive")
        finally:
            fixture_root = self.root
            self.tmp.cleanup()
            if fixture_root.exists():
                cleanup_errors.append("synthetic fixture directory remained after cleanup")
        if cleanup_errors:
            summary = "fixture cleanup failed: " + "; ".join(cleanup_errors)
            if exc_type is None:
                raise AssertionError(summary)
            print("CLEANUP_FAILURE " + summary, file=sys.stderr, flush=True)
        return False

    def run(self, *words, success=True, home=None, stdin=None):
        selected = home or self.home
        result = subprocess.run([self.binary, *words, "--home", str(selected)],
                                env={**self.env, "ORBIT_HOME": str(selected)}, cwd=self.work,
                                input=stdin, text=True, capture_output=True, timeout=20)
        if success:
            assert result.returncode == 0, (words, result.returncode, result.stdout, result.stderr)
        else:
            assert result.returncode != 0, (words, result.stdout, result.stderr)
        return result

    def command(self, *words, success=True, home=None):
        result = self.run("customize", *words, "--json", success=success, home=home)
        if success:
            value = json.loads(result.stdout)
            assert (value["schema"], value["command"], value["status"]) == ("orbit.cli/v1", "customize", "ok"), value
            return value
        return result

    def profile(self, home=None):
        return self.command("show", home=home)["profile"]["profile"]

    def customization_snapshot(self):
        snapshot = {}
        for name in CUSTOMIZATION_PATHS:
            path = self.home / name
            try:
                before = os.lstat(path)
            except FileNotFoundError:
                snapshot[name] = None
                continue
            _require(stat.S_ISREG(before.st_mode), "customization path is not a regular file: " + name)
            _require(before.st_uid == os.getuid() and before.st_nlink == 1,
                     "customization path has unsafe ownership or links: " + name)
            fd = _open_nofollow_path(path, os.O_RDONLY | getattr(os, "O_CLOEXEC", 0))
            try:
                opened = os.fstat(fd)
                _require((opened.st_dev, opened.st_ino) == (before.st_dev, before.st_ino),
                         "customization path changed while snapshotting: " + name)
                _require(stat.S_IMODE(opened.st_mode) == stat.S_IMODE(before.st_mode)
                         and opened.st_uid == os.getuid() and opened.st_nlink == 1,
                         "customization mode or ownership changed while snapshotting: " + name)
                content = bytearray()
                while True:
                    chunk = os.read(fd, 65536)
                    if not chunk:
                        break
                    content.extend(chunk)
                    _require(len(content) <= 4 * 1024 * 1024,
                             "customization file exceeds snapshot limit: " + name)
                after = os.fstat(fd)
                _require((after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                          after.st_ctime_ns, stat.S_IMODE(after.st_mode), after.st_uid,
                          after.st_nlink)
                         == (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns,
                             opened.st_ctime_ns, stat.S_IMODE(opened.st_mode), opened.st_uid,
                             opened.st_nlink),
                         "customization file changed while snapshotting: " + name)
            finally:
                os.close(fd)
            snapshot[name] = (stat.S_IMODE(before.st_mode), bytes(content))
        return snapshot

    def assert_customization_unchanged(self, expected, label):
        actual = self.customization_snapshot()
        _require(actual == expected, label + " changed customization files")

    def launch_snapshot(self, launch_mode):
        _require(launch_mode in {"pty", "plain"}, "unknown launch mode")
        tree = _tree_snapshot(self.home)
        ids = {
            match.group(1) for path in tree
            if (match := re.fullmatch(r"sessions/([A-Za-z0-9_-]{1,128})\.json", path))
        }
        return {
            "customization": self.customization_snapshot(),
            "session_ids": ids,
            "projects": _project_subtree(tree),
        }

    def register_launch(self, process, launch_mode, before):
        _require(process is not None and type(process.pid) is int and process.pid > 0,
                 "launch has no exact child process")
        _require(all(item["pid"] != process.pid for item in self.chat_records),
                 "duplicate child PID")
        record = {
            "process": process,
            "pid": process.pid,
            "launch_mode": launch_mode,
            "origin": "flag" if launch_mode == "pty" else "role",
            "transcript": launch_mode == "pty",
            "before_ids": set(before["session_ids"]),
            "customization_before": before["customization"],
            "projects_before": before["projects"],
            "observed": False,
            "finished": False,
        }
        self.chat_records.append(record)
        self.records_by_pid[process.pid] = record
        return record

    def record_for(self, process):
        record = self.records_by_pid.get(process.pid)
        _require(record is not None and record["process"] is process,
                 "process is not the tracked chat child")
        return record

    def observe_launch(self, record):
        process = record["process"]
        _require(process.poll() is None, "chat child exited before startup observation")
        current = _tree_snapshot(self.home)
        _reject_tree_links(current, "fixture home before artifact reads")
        current_ids = {
            match.group(1) for path in current
            if (match := re.fullmatch(r"sessions/([A-Za-z0-9_-]{1,128})\.json", path))
        }
        new_ids = current_ids - record["before_ids"]
        _require(len(new_ids) == 1, "launch did not create exactly one new session")
        session_id = next(iter(new_ids))
        _require(session_id not in {item.get("session_id") for item in self.chat_records if item is not record},
                 "session ID is reused by another launch")
        record["session_id"] = session_id
        record["observed"] = True
        session_path = self.home / "sessions" / (session_id + ".json")
        _validate_session_file(session_path, record, self.env["ORBIT_GATE_URL"], self.work)
        _validate_accounting_file(
            self.home / "context-history" / session_id / "accounting.json", session_id)
        _read_regular(self.home / "context-history" / session_id / ".history.lock",
                      "history lock", empty=True)
        if record["transcript"]:
            _read_regular(self.home / "projects" / (session_id + ".jsonl"),
                          "zero-turn TUI transcript", empty=True)
        _validate_lease_file(self.home / "sessions" / ".leases" / (session_id + ".lock"),
                             record, live=True)
        self.assert_customization_unchanged(record["customization_before"], "chat startup")
        observed = [item for item in self.chat_records if item["observed"]]
        _validate_artifact_tree(self.home, self.protected, observed)
        return record

    def observe_pty(self, session):
        record = self.record_for(session.proc)
        if not record["observed"]:
            self.observe_launch(record)
        return record

    def finish_launch(self, record):
        if record["finished"]:
            return
        if not record["observed"]:
            _require(record["process"].poll() is not None,
                     "unobserved chat process is still running during cleanup")
            record["finished"] = True
            return
        _require(record["process"].poll() is not None,
                 "chat child still runs during lease release check")
        sid = record["session_id"]
        _validate_session_file(self.home / "sessions" / (sid + ".json"), record,
                               self.env["ORBIT_GATE_URL"], self.work)
        _validate_accounting_file(self.home / "context-history" / sid / "accounting.json", sid)
        _read_regular(self.home / "context-history" / sid / ".history.lock",
                      "history lock", empty=True)
        if record["transcript"]:
            _read_regular(self.home / "projects" / (sid + ".jsonl"),
                          "zero-turn TUI transcript", empty=True)
        _validate_lease_file(self.home / "sessions" / ".leases" / (sid + ".lock"), record, live=False)
        observed = [item for item in self.chat_records if item["observed"]]
        _validate_artifact_tree(self.home, self.protected, observed)
        record["finished"] = True

    def run_safe_chat(self, *words, stdin):
        before = self.launch_snapshot("plain")
        command = [self.binary, *words, "--home", str(self.home)]
        process = subprocess.Popen(
            command,
            env={**self.env, "ORBIT_HOME": str(self.home)},
            cwd=self.work,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            close_fds=True,
        )
        record = self.register_launch(process, "plain", before)
        try:
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                _require(process.poll() is None, "plain chat exited before session persistence")
                current = _tree_snapshot(self.home)
                current_ids = {
                    match.group(1) for path in current
                    if (match := re.fullmatch(r"sessions/([A-Za-z0-9_-]{1,128})\.json", path))
                }
                if len(current_ids - record["before_ids"]) == 1:
                    self.observe_launch(record)
                    break
                time.sleep(0.02)
            _require(record["observed"], "plain chat never persisted a session record")
            self.assert_customization_unchanged(record["customization_before"],
                                                 "plain chat startup before input")
            stdout, stderr = process.communicate(stdin, timeout=20)
            _require(process.returncode == 0,
                     "plain safe chat failed: " + repr((process.returncode, stdout, stderr)))
            self.finish_launch(record)
            self.assert_customization_unchanged(record["customization_before"],
                                                 "plain safe chat shutdown")
            return subprocess.CompletedProcess(command, process.returncode, stdout, stderr)
        except BaseException:
            self._reap_plain(process)
            if record["observed"] and process.poll() is not None:
                try:
                    self.finish_launch(record)
                except Exception:
                    pass
            raise

    @staticmethod
    def _reap_plain(process):
        try:
            if process.stdin is not None and not process.stdin.closed:
                process.stdin.close()
        except (OSError, ValueError):
            pass
        process.stdin = None
        if process.poll() is None:
            process.terminate()
        try:
            process.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            process.kill()
            process.communicate(timeout=3)

    def protected_tree(self):
        return _protected_snapshot(self.home)

    def unchanged(self, allow_new_sessions=False):
        self.preservation_error = None
        try:
            if self.calls:
                raise ValueError("unexpected provider call")
            observed = [item for item in self.chat_records if item["observed"]]
            if self.chat_records and not allow_new_sessions:
                raise ValueError("chat launch artifacts were not allowed")
            _validate_artifact_tree(self.home, self.protected, observed)
            for record in observed:
                sid = record["session_id"]
                _validate_session_file(self.home / "sessions" / (sid + ".json"), record,
                                       self.env["ORBIT_GATE_URL"], self.work)
                _validate_accounting_file(self.home / "context-history" / sid / "accounting.json", sid)
                _read_regular(self.home / "context-history" / sid / ".history.lock",
                              "history lock", empty=True)
                _validate_lease_file(self.home / "sessions" / ".leases" / (sid + ".lock"),
                                     record, live=record["process"].poll() is None)
            return True
        except (ValueError, OSError, AssertionError) as exc:
            self.preservation_error = str(exc)
            return False

    def stored(self):
        path = self.home / "customization.json"
        return path.read_bytes() if path.exists() else None

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    oracle_assertions = _run_oracle_regressions()
    scenarios = {"strict_session_accounting_lease_and_filesystem_oracles":
                 {"passed": True, "assertions": oracle_assertions}}

    def checked(name, *conditions):
        assert conditions and all(conditions), name
        scenarios[name] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + name, flush=True)

    with Fixture(args.binary) as f:
        original = f.profile()
        checked("show_and_capabilities_are_offline_readonly_and_explain_terminal_font",
                f.stored() is None, f.unchanged(),
                "terminal" in f.command("capabilities")["profile"]["capabilities"]["terminal_font"].lower())
        for key, value in [("theme", "paper"), ("density", "compact"), ("glyphs", "ascii"),
                           ("reduced_motion", "true"), ("browser.font_family", "monospace"),
                           ("browser.font_size_px", "18")]:
            f.command("set", key, value)
        changed = f.profile()
        checked("full_settings_persist_across_fresh_cli_processes_without_provider_work",
                changed["theme"] == "paper", changed["density"] == "compact", changed["glyphs"] == "ascii",
                changed["reduced_motion"] is True, changed["browser"] == {"font_family": "monospace", "font_size_px": 18.0},
                f.unchanged(), (f.home / "customization.json").stat().st_mode & 0o777 == 0o600)
        f.command("set", "colors.accent", "#123456")
        f.command("set", "token_overrides.magenta", "#654321")
        colors = f.profile()["token_overrides"]
        checked("legacy_color_alias_and_canonical_role_have_one_effective_value",
                colors.get("magenta") == "#654321", "accent" not in colors, f.unchanged())
        before = f.stored()
        for key, value in [("unknown", "bad"), ("theme", "missing"), ("browser.font_size_px", "99"),
                           ("reduced_motion", "yes"), ("colors.ink", "#wrong")]:
            f.command("set", key, value, success=False)
            assert f.stored() == before
        checked("invalid_keys_values_and_complete_candidates_preserve_exact_bytes", f.stored() == before, f.unchanged())
        exported = f.work / "portable.json"
        f.command("export", "portable.json")
        export_bytes = exported.read_bytes()
        parsed = json.loads(export_bytes)
        f.command("validate", "portable.json")
        f.command("export", "portable.json", success=False)
        checked("portable_export_is_private_valid_and_never_overwrites_existing_file",
                parsed == f.profile(), exported.read_bytes() == export_bytes,
                exported.stat().st_mode & 0o777 == 0o600,
                str(f.home) not in export_bytes.decode(), str(f.work) not in export_bytes.decode(), f.unchanged())
        before = f.stored()
        malformed = f.work / "invalid.json"
        malformed.write_text('{"schema_version":1,broken')
        f.command("validate", "invalid.json", success=False)
        f.command("import", "invalid.json", success=False)
        extra = copy.deepcopy(parsed)
        extra["panes"] = [{"id": "proof", "title": "Proof", "surfaces": ["terminal"],
                           "source": {"kind": "text", "text": "inert"},
                           "actions": [{"kind": "refresh", "unexpected": "must refuse"}]}]
        malformed.write_text(json.dumps(extra))
        f.command("import", "invalid.json", success=False)
        checked("malformed_import_and_unknown_unit_action_fields_are_strictly_rejected",
                f.stored() == before, f.unchanged())
        f.command("reset", "theme")
        reset_one = f.profile()
        checked("key_reset_preserves_other_customization_and_unrelated_configuration",
                reset_one["theme"] == original["theme"], reset_one["density"] == "compact",
                reset_one["token_overrides"] == colors, f.unchanged())
        second = f.root / "other-home"
        f.run("init", "--no-provider", home=second)
        second.chmod(0o700)
        f.command("import", "portable.json", home=second)
        checked("portable_export_import_into_fresh_home_has_exact_profile_parity",
                f.profile(home=second) == parsed, not f.calls, f.unchanged())
        f.command("set", "layout.preset", "review")
        layout = f.profile()["layout"]
        checked("named_layout_is_persisted_as_valid_split_tree", layout["preset"] == "review",
                layout["tree"]["kind"] == "split", f.unchanged())
        before = f.stored()
        link = f.work / "link.json"
        link.symlink_to(exported)
        f.command("import", "link.json", success=False)
        hard = f.work / "hard.json"
        os.link(exported, hard)
        f.command("import", "hard.json", success=False)
        hard.unlink()
        checked("symlink_and_hardlinked_imports_preserve_configuration", f.stored() == before,
                exported.read_bytes() == export_bytes, f.unchanged())
        legacy = b'[color]\nmode="mono"\n[unrelated]\nkeep="exact legacy bytes"\n'
        (f.home / "tui.toml").write_bytes(legacy)
        (f.home / "tui.toml").chmod(0o644)
        f.command("reset")
        checked("full_reset_returns_to_owned_0644_legacy_and_preserves_unrelated_bytes",
                f.stored() is None, f.profile()["color_mode"] == "mono",
                (f.home / "tui.toml").read_bytes() == legacy, f.unchanged())
        broken = b"[invalid legacy\n"
        (f.home / "tui.toml").write_bytes(broken)
        f.command("set", "theme", "paper", success=False)
        f.command("reset", success=False)
        checked("malformed_legacy_is_visible_and_never_silently_rewritten",
                (f.home / "tui.toml").read_bytes() == broken, f.stored() is None, f.unchanged())
        (f.home / "tui.toml").write_bytes(legacy)
        bad_profile = b'{"malformed":'
        (f.home / "customization.json").write_bytes(bad_profile)
        (f.home / "customization.json").chmod(0o600)
        f.command("show", success=False)
        f.command("theme", "paper", success=False)
        checked("malformed_profile_refuses_show_and_change_without_implicit_fallback",
                f.stored() == bad_profile, (f.home / "tui.toml").read_bytes() == legacy, f.unchanged())
        safe = f.run_safe_chat("--no-tui", "--safe-customization", "--bare",
                               stdin="/theme paper\n/customize reset\nexit\n")
        checked("plain_safe_defaults_refuse_theme_and_reset_preserving_all_existing_state",
                f.stored() == bad_profile, (f.home / "tui.toml").read_bytes() == legacy,
                "Session-only defaults cannot write customization" in safe.stderr,
                len(f.chat_records) == 1, f.chat_records[0]["launch_mode"] == "plain",
                f.chat_records[0]["origin"] == "role", f.chat_records[0]["finished"],
                f.unchanged(allow_new_sessions=True), not f.calls)
    print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
