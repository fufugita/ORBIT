#!/usr/bin/env python3
"""Small deterministic LSP stdio peer with observable launch and frame traffic."""
import json
import os
import subprocess
import sys
import time

if len(sys.argv) > 1 and sys.argv[1] == "--supervise":
    # The PID jail's command is not an init reaper. Emulate normal init only
    # for this private probe subtree: adopt and reap DEAD children, never kill
    # live helpers or change the application's process settings.
    import ctypes
    if len(sys.argv) < 4 or sys.argv[2] != "--":
        sys.exit(2)
    libc = ctypes.CDLL(None, use_errno=True)
    if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER (Linux)
        sys.exit(2)
    command = subprocess.Popen(sys.argv[3:])
    outcome = None
    while outcome is None:
        while True:
            try:
                pid, status = os.waitpid(-1, os.WNOHANG)
            except ChildProcessError:
                break
            if pid == 0:
                break
            if pid == command.pid:
                outcome = os.waitstatus_to_exitcode(status)
                command.returncode = outcome
        time.sleep(0.005)
    sys.exit(outcome)

mode, log_path = sys.argv[1:3]


def record(value):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps(value) + "\n")
        log.flush()


def launch_helper():
    helper = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"], stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    with open(f"/proc/{helper.pid}/status", encoding="utf-8") as status:
        fields = dict(line.split(":", 1) for line in status if line.startswith(("State:", "PPid:")))
    record({"helper": helper.pid, "helper_parent": int(fields["PPid"]), "helper_state": fields["State"].strip(), "helper_group": os.getpgid(helper.pid)})
    return helper


def send(value):
    data = json.dumps(value, ensure_ascii=False).encode()
    sys.stdout.buffer.write(b"Content-Length: " + str(len(data)).encode() + b"\r\n\r\n" + data)
    sys.stdout.buffer.flush()


def receive():
    length = None
    while True:
        line = sys.stdin.buffer.readline()
        if not line:
            return None
        if line == b"\r\n":
            break
        if line.lower().startswith(b"content-length:"):
            length = int(line.split(b":", 1)[1])
    return json.loads(sys.stdin.buffer.read(length))


record({"spawn": os.getpid()})
if mode == "initialize_silent":
    time.sleep(30)

uri = None
version = None
while True:
    message = receive()
    if message is None:
        break
    record(message)
    method = message.get("method")
    if method == "initialize":
        if mode in ("helper_early_exit", "helper_timeout", "helper_cancel"):
            helper = launch_helper()
        if mode == "bad_frame":
            sys.stdout.buffer.write(b"Content-Length: nope\r\n\r\n{}")
            sys.stdout.buffer.flush()
            time.sleep(30)
        if mode == "oversize":
            sys.stdout.buffer.write(b"Content-Length: 9999999\r\n\r\n")
            sys.stdout.buffer.flush()
            time.sleep(30)
        if mode == "bad_utf8":
            sys.stdout.buffer.write(b"Content-Length: 1\r\n\r\n\xff")
            sys.stdout.buffer.flush()
            time.sleep(30)
        capabilities = {"positionEncoding": "utf-8" if mode == "utf8" else "utf-16"}
        if not mode.startswith("push"):
            capabilities["diagnosticProvider"] = {"interFileDependencies": False, "workspaceDiagnostics": False}
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"capabilities": capabilities}})
        if mode == "open_unread":
            time.sleep(30)
    elif method == "textDocument/didOpen":
        doc = message["params"]["textDocument"]
        uri, version = doc["uri"], doc["version"]
        if mode == "helper_early_exit":
            sys.exit(0)
        if mode.startswith("push"):
            params = {"uri": uri, "diagnostics": [] if mode == "push_empty" else [{"range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}, "message": "push issue", "severity": 2}]}
            if mode != "push_unversioned":
                params["version"] = version + (1 if mode == "push_stale" else 0)
            if mode == "push_wrong_uri":
                params["uri"] = uri + ".other"
            send({"jsonrpc": "2.0", "method": "textDocument/publishDiagnostics", "params": params})
        if mode == "server_action":
            send({"jsonrpc": "2.0", "id": 99, "method": "workspace/applyEdit", "params": {"edit": {"changes": {uri: [{"newText": "overwritten"}]}}}})
    elif method == "textDocument/diagnostic":
        if mode in ("silent", "helper_timeout", "helper_cancel"):
            time.sleep(30)
        item = {"range": {"start": {"line": 0, "character": 0}, "end": {"line": 0, "character": 1}}, "message": "pull issue", "severity": 1, "code": "E1", "source": "fixture"}
        if mode == "secret":
            item["message"] = "API_KEY=abcdefghijklmnopqrstuvwxyz1234567890\u001b[31m"
        if mode == "large_message":
            item["message"] = "x" * 200000
        if mode == "two_tokens":
            item["message"] = "ghp_abcdefghijklmnopQRSTUVWX0123456789 ghp_ZYXWVUTSRQponmlkjihg9876543210abcd"
            item["code"] = item["message"]
            item["source"] = item["message"]
        if mode == "short_prefix":
            item["message"] = "ghp_short ghp_abcdefghijklmnopQRSTUVWX0123456789"
        if mode == "invalid_range":
            item["range"]["start"]["line"] = -1
        items = [] if mode == "empty" else [item]
        if mode == "many":
            items *= 130
        result = {"kind": "full", "items": items}
        if mode == "malformed_result":
            result["items"] = {"not": "an array"}
        send({"jsonrpc": "2.0", "id": message["id"] + (10 if mode == "wrong_id" else 0), "result": result})
    elif method == "shutdown":
        if mode == "helper_exit":
            helper = launch_helper()
        if mode == "close_silent":
            time.sleep(30)
        send({"jsonrpc": "2.0", "id": message["id"], "result": None})
    elif method == "exit":
        break
