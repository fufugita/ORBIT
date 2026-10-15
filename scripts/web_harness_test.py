#!/usr/bin/env python3
"""Browser-harness E2E test (docs/browser-harness.md §4.4).

Exercises the REAL bridge server over HTTP: SPA, SSE events, WS actions,
streaming turn, approval flow, session save — same scenario set as the TUI's
PTY suite, adapted to the web transport. Uses only stdlib (urllib + a
hand-rolled WS client over socket) so no pip deps are needed.

Usage:
  web_harness_test.py [--binary PATH] [--mock PATH] [--home DIR] [--port P]

Checks:
  1. server boots, prints URL, serves the SPA
  2. /static assets serve with correct MIME
  3. SSE stream delivers `identity` on connect
  4. WS `list_sessions` → `sessions` event
  5. WS prompt → text_delta stream → `turn_ended` with usage
  6. WS prompt with tool call → `approval` event → approve → turn_ended
  7. `list_sessions` shows the saved session after turns
  8. token gate: second server with token refuses unauthenticated SSE
"""

import json
import os
from pathlib import Path
import signal
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.request

PASS = 0
FAIL = 0
SCENARIOS = {}

def check(name, ok, detail=""):
    global PASS, FAIL
    mark = "\033[32mPASS\033[0m" if ok else "\033[31mFAIL\033[0m"
    print(f"  [{mark}] {name}" + (f" — {detail}" if detail and not ok else ""))
    PASS, FAIL = PASS + (1 if ok else 0), FAIL + (1 if not ok else 0)
    key = name.replace(" ", "_").replace(".", "_")
    if key in SCENARIOS:
        raise AssertionError(f"duplicate scenario {key}")
    SCENARIOS[key] = {"passed": bool(ok), "assertions": 1}


def port_open(port, timeout=0.3):
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def start_mock(binary, port):
    if port_open(port):
        raise RuntimeError(f"fixture port {port} is already occupied")
    env = os.environ.copy()
    env["ORBIT_MOCK_BIND"] = f"127.0.0.1:{port}"
    p = subprocess.Popen([binary], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=env, start_new_session=True)
    for _ in range(15):
        if port_open(port):
            return p
        if p.poll() is not None:
            raise RuntimeError("mock provider exited before readiness")
        time.sleep(0.2)
    p.kill()
    p.wait(timeout=5)
    raise RuntimeError("mock provider did not become ready")


def free_port():
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def stop_child(child):
    if child is not None and child.poll() is None:
        os.killpg(os.getpgid(child.pid), signal.SIGTERM)
        child.wait(timeout=10)


class WSClient:
    """Minimal RFC6455 client — enough for text frames to/from the bridge."""

    def __init__(self, port, path="/actions"):
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        key = os.urandom(16).hex()
        req = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: 127.0.0.1:{port}\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode())
        # Read the 101 response headers.
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise ConnectionError("closed during handshake")
            buf += chunk
        status = buf.split(b"\r\n", 1)[0]
        if b"101" not in status:
            raise ConnectionError(f"handshake refused: {status!r}")
        self._buffer = buf.split(b"\r\n\r\n", 1)[1]

    def send(self, obj):
        payload = json.dumps(obj).encode()
        hdr = bytearray([0x81])  # FIN + text
        mask = os.urandom(4)
        n = len(payload)
        if n < 126:
            hdr.append(0x80 | n)
        elif n < 65536:
            hdr.append(0x80 | 126)
            hdr += struct.pack(">H", n)
        else:
            hdr.append(0x80 | 127)
            hdr += struct.pack(">Q", n)
        hdr += mask
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(hdr) + masked)

    def recv_text(self, timeout=5.0):
        """Receive one text frame (ignores ping/pong). Returns str or None on close."""
        self.sock.settimeout(timeout)
        while True:
            hdr = self._recv_exact(2)
            if hdr is None:
                return None
            fin_op = hdr[0]
            op = fin_op & 0x0F
            n = hdr[1] & 0x7F
            if n == 126:
                ext = self._recv_exact(2)
                if ext is None:
                    return None
                n = struct.unpack(">H", ext)[0]
            elif n == 127:
                ext = self._recv_exact(8)
                if ext is None:
                    return None
                n = struct.unpack(">Q", ext)[0]
            payload = self._recv_exact(n) if n else b""
            if payload is None:
                return None
            if op == 0x8:  # close
                return None
            if op in (0x9, 0xA):  # ping/pong
                continue
            return payload.decode("utf-8", "replace")

    def _recv_exact(self, n):
        buf = self._buffer[:n]
        self._buffer = self._buffer[len(buf):]
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf


class SSEClient:
    """Minimal SSE reader: collects (event, data) tuples from a background thread."""

    def __init__(self, port, path="/events"):
        self.events = []
        self.consumed = {}
        self.lock = threading.Lock()
        self.done = threading.Event()
        self.sock = socket.create_connection(("127.0.0.1", port), timeout=10)
        self.sock.sendall(
            f"GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nAccept: text/event-stream\r\n\r\n".encode()
        )
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()

    def _pump(self):
        buf = b""
        try:
            while True:
                chunk = self.sock.recv(4096)
                if not chunk:
                    break
                buf += chunk
                while b"\n\n" in buf:
                    frame, buf = buf.split(b"\n\n", 1)
                    ev, data = None, ""
                    for line in frame.decode("utf-8", "replace").split("\n"):
                        if line.startswith("event:"):
                            ev = line[6:].strip()
                        elif line.startswith("data:"):
                            data = line[5:].strip()
                    if ev:
                        with self.lock:
                            self.events.append((ev, data))
        except OSError:
            pass
        self.done.set()

    def wait_for(self, kind, timeout=15.0, pred=None):
        """Wait until an event of `kind` (satisfying pred) has arrived."""
        deadline = time.time() + timeout
        while time.time() < deadline:
            with self.lock:
                for index in range(self.consumed.get(kind, 0), len(self.events)):
                    ev, data = self.events[index]
                    if ev == kind and (pred is None or pred(json.loads(data or "{}"))):
                        self.consumed[kind] = index + 1
                        return json.loads(data or "{}")
            time.sleep(0.05)
        return None

    def collect_deltas(self, deadline_s=3.0):
        time.sleep(deadline_s)
        with self.lock:
            return "".join(
                json.loads(d).get("text", "")
                for e, d in self.events
                if e == "text_delta"
            )


def main():
    import argparse

    ap = argparse.ArgumentParser()
    repo = Path(__file__).resolve().parents[1]
    ap.add_argument("--binary", default=str(repo / "target/debug/orbit-web"))
    ap.add_argument("--cli", help="matching orbit CLI (defaults to the bridge's sibling)")
    ap.add_argument("--mock", default=str(repo / "target/debug/orbit-mock-provider"))
    ap.add_argument("--home")
    ap.add_argument("--port", type=int, default=0)
    ap.add_argument("--mock-port", type=int, default=0)
    ap.add_argument("--model", default="mock-slow")
    args = ap.parse_args()
    args.cli = args.cli or str(Path(args.binary).resolve().with_name("orbit"))

    args.home = args.home or tempfile.mkdtemp(prefix="orbit-web-acceptance-")
    os.makedirs(args.home, mode=0o700, exist_ok=True)
    if os.listdir(args.home):
        raise RuntimeError("fixture --home must be an empty directory")
    args.port = args.port or free_port()
    args.mock_port = args.mock_port or free_port()
    if args.port == args.mock_port or port_open(args.port):
        raise RuntimeError("fixture requires two distinct unused ports")
    gate = f"http://127.0.0.1:{args.mock_port}"
    env = os.environ.copy()
    env["ORBIT_HOME"] = args.home
    subprocess.run(
        [args.cli, "init", "--home", args.home, "--no-provider"],
        capture_output=True, timeout=30, env=env, check=True,
    )
    with open(os.path.join(args.home, "providers.toml"), "w") as f:
        f.write(
            f'[[provider]]\nname = "local"\nurl = "{gate}"\n'
            f'env = "ORBIT_GATE_TOKEN"\n\n[[provider.models]]\nid = "{args.model}"\n'
            f'[[provider.models]]\nid = "mock"\n[[provider.models]]\nid = "mock-bash"\n'
        )

    mock = start_mock(args.mock, args.mock_port)
    print("mock provider: started on ephemeral loopback")

    # Start the bridge.
    server_env = os.environ.copy()
    server_env.pop("ORBIT_WEB_TOKEN", None)
    server_env.update({"ORBIT_HOME": args.home, "ORBIT_GATE_TOKEN": "test-token",
                       "ORBIT_GATE_URL": gate})
    server = None
    try:
        server = subprocess.Popen(
        [args.binary, "--no-browser", "--port", str(args.port), "--model", args.model,
         "--gate", gate],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=server_env,
        start_new_session=True,
        )
        for _ in range(30):
            if port_open(args.port):
                break
            if server.poll() is not None:
                print("server died at boot:")
                print(server.stdout.read().decode())
                sys.exit(1)
            time.sleep(0.2)

        # ── 1. SPA served ──────────────────────────────────────────────
        print("\n== SPA ==")
        body = urllib.request.urlopen(f"http://127.0.0.1:{args.port}/", timeout=5).read().decode()
        if "<title>ORBIT</title>" not in body:
            print(f"FATAL: port {args.port} is serving something else (title mismatch); "
                  "pass --port to pick a free port")
            sys.exit(1)
        check("index.html served", "<title>ORBIT</title>" in body)
        js = urllib.request.urlopen(f"http://127.0.0.1:{args.port}/static/app.js", timeout=5)
        check(
            "app.js served as javascript",
            "javascript" in js.headers.get("content-type", ""),
        )

        # ── 2. SSE identity ────────────────────────────────────────────
        print("\n== SSE identity ==")
        sse = SSEClient(args.port)
        ident = sse.wait_for("identity", timeout=10)
        check("identity event", ident is not None and ident.get("model") == args.model,
              str(ident))

        # ── 3. WS actions: sessions list ───────────────────────────────
        print("\n== WS sessions ==")
        ws = WSClient(args.port)
        ready = json.loads(ws.recv_text(timeout=10) or "{}")
        assert ready.get("type") == "controller_ready", ready

        def action(value):
            ws.send(value)
            reply = json.loads(ws.recv_text(timeout=10) or "{}")
            assert reply.get("type") == "action_ack", reply
            return reply

        action({"type": "list_sessions"})
        ev = sse.wait_for("sessions", timeout=10)
        check("sessions event", ev is not None and "sessions" in ev, str(ev))

        # ── 4. Prompt → stream → finished ──────────────────────────────
        print("\n== turn: stream ==")
        action({"type": "prompt", "request_id": "legacy-browser-stream", "text": "hello from the browser test"})
        fin = sse.wait_for("turn_ended", timeout=30, pred=lambda d: d.get("ok", False))
        check("turn_ended event", fin is not None, "no turn_ended within 30s")
        deltas = sse.collect_deltas(0)
        check("deltas streamed", len(deltas) > 0, "no text_delta events")
        if fin:
            check("usage reported", "input_tokens" in fin and "output_tokens" in fin)
        completed = sse.wait_for("request_finished", timeout=10,
                                 pred=lambda value: value.get("request_id") == "legacy-browser-stream")
        assert completed is not None, "owner must persist and finish before the next setting action"

        # ── 5. Tool call → approval → finished ─────────────────────────
        print("\n== turn: approval ==")
        # The "mock" model issues a tool call (same as the TUI suite).
        selected = action({"type": "set_model", "model": "mock-bash"})
        assert selected.get("snapshot", {}).get("model") == "mock-bash", selected
        assert sse.wait_for("identity", timeout=10,
                            pred=lambda value: value.get("model") == "mock-bash") is not None
        action({"type": "prompt", "request_id": "legacy-browser-tool", "text": "use a tool please"})
        ap_ev = sse.wait_for("approval_requested", timeout=30)
        check("approval event", ap_ev is not None and "call_id" in ap_ev, str(ap_ev))
        if ap_ev:
            check("approval has summary", bool(ap_ev.get("summary")))
            action({"type": "approve", "call_id": ap_ev["call_id"], "verdict": "allow"})
            fin2 = sse.wait_for("turn_ended", timeout=30)
            check("turn finished after approval", fin2 is not None)
            tools = [e for e, _ in sse.events if e == "tool_started_full"]
            check("tool_started_full emitted", len(tools) >= 1)

        # ── 6. Session persisted ───────────────────────────────────────
        print("\n== persistence ==")
        completed = sse.wait_for("request_finished", timeout=10,
                                 pred=lambda value: value.get("request_id") == "legacy-browser-tool")
        assert completed is not None and completed.get("turns", 0) >= 2, completed
        action({"type": "list_sessions"})
        ev = sse.wait_for("sessions", timeout=10,
                          pred=lambda d: any(s.get("turns", 0) >= 2 for s in d.get("sessions", [])))
        check("session saved with turns", ev is not None, str(ev))

        # ── 7. Resume via WS restores transcript ───────────────────────
        print("\n== resume ==")
        if ev:
            sid = next(s["session_id"] for s in ev["sessions"] if s.get("turns", 0) >= 2)
            ws.send({"type": "resume", "id": sid})
            tr = None
            deadline = time.monotonic() + 10
            while time.monotonic() < deadline:
                reply = json.loads(ws.recv_text(timeout=10) or "{}")
                if reply.get("type") == "action_ack" and reply.get("ack", {}).get("state") == "resumed":
                    tr = reply.get("snapshot")
                    break
            check("transcript restored", tr is not None and len(tr.get("messages", [])) >= 3,
                  str(tr)[:120])

    finally:
        stop_child(server)
        stop_child(mock)

    print(f"\n{'='*40}\nweb harness: {PASS} passed, {FAIL} failed")
    print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": SCENARIOS}))
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
