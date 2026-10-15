#!/usr/bin/env python3
"""Local captured provider for owned-session acceptance; no external network."""
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

root = Path(sys.argv[1])
calls_lock = threading.Lock()


class Provider(BaseHTTPRequestHandler):
    def do_POST(self):
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 4 * 1024 * 1024:
            self.send_error(413)
            return
        body = json.loads(self.rfile.read(size))
        with calls_lock:
            with (root / "calls.jsonl").open("a") as calls:
                calls.write(json.dumps(body) + "\n")
                calls.flush()
                os.fsync(calls.fileno())
        mode_path = root / "mode.json"
        mode = json.loads(mode_path.read_text()) if mode_path.exists() else {}
        if mode.get("disconnect"):
            self.connection.close()
            return
        if mode.get("blocked"):
            deadline = time.monotonic() + 15
            while not (root / "release").exists() and time.monotonic() < deadline:
                time.sleep(0.01)
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.end_headers()
        try:
            messages = body.get("messages", [])
            latest_user = max((index for index, message in enumerate(messages) if message.get("role") == "user"), default=-1)
            if mode.get("tool") and not any(m.get("role") == "tool" for m in messages[latest_user + 1:]):
                delta = {"tool_calls": [{"index": 0, "id": "fixture-call", "type": "function", "function": {"name": mode["tool"], "arguments": json.dumps(mode.get("arguments", {}))}}]}
                events = [{"choices": [{"index": 0, "delta": delta, "finish_reason": "tool_calls"}]}]
            else:
                events = [{"choices": [{"index": 0, "delta": {"content": text}, "finish_reason": None}]} for text in mode.get("chunks", [mode.get("reply", "owned fixture reply")])]
                events.append({"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 2, "completion_tokens": 3}})
            for index, event in enumerate(events):
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
                self.wfile.flush()
                if mode.get("pause_after") == index:
                    deadline = time.monotonic() + 15
                    while not (root / "stream_release").exists() and time.monotonic() < deadline:
                        time.sleep(0.01)
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass

    def log_message(self, *_):
        pass


server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
ready_fd, ready_temp = tempfile.mkstemp(prefix=".ready-", suffix=".json", dir=root)
try:
    with os.fdopen(ready_fd, "w", encoding="utf-8") as ready:
        os.fchmod(ready.fileno(), 0o600)
        ready.write(json.dumps({"gate": f"http://127.0.0.1:{server.server_port}"}))
        ready.flush()
        os.fsync(ready.fileno())
    os.replace(ready_temp, root / "ready.json")
finally:
    Path(ready_temp).unlink(missing_ok=True)
server.serve_forever()
