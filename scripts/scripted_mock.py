#!/usr/bin/env python3
"""Scripted mock provider for ORBIT scenario tests.

Plays back a scripted multi-round tool conversation over the OpenAI or
Anthropic wire shape, logging every request so tests can assert on the
system prompt, tools, history and sampling parameters.

Usage:
  scripted_mock.py --port 18890 --script s.json --log req.jsonl
  scripted_mock.py --port 0 --bind-out port.txt --script s.json --log req.jsonl
  scripted_mock.py --port 18900 --wire anthropic --script s.json --log req.jsonl

Script format (JSON):

  {
    "main": [ <step>, ... ],          # the default conversation
    "<Key>": [ <step>, ... ]          # matched when the first user message
                                      # starts with <Key> (longest match wins)
  }

A step is one response, consumed in order per request to its
conversation:

  {"tools": [{"name": "Glob", "args": {"pattern": "*.py"}}, ...]}
        respond with tool calls, stop reason "tool_use"
  {"text": "done"}
        respond with text, stop reason "end_turn"
  {"thinking": true, "ptok": 100, "tools": [...]}
        (anthropic) emit a signed thinking block first; report <ptok>
        input tokens in message_start
  {"status": 400, "body": "{\"error\":...}"}
        fail with this HTTP status (and body); 500/502/503/504/529 are
  {"stall_ms": 10000}
        send response headers, then send NOTHING for this long (a
        stalled stream — the client's idle timeout must fire)
  {"stall_ms": 10000, "stall_bytes": "data: {...}\n\n"}
        send headers, send stall_bytes once, then go silent
        retryable from the client's point of view
  {"status": 529}
        fail with this status and an empty body

Each request is appended to --log as one JSON line:
  {"ts": ..., "wire": "openai"|"anthropic", "path": ..., "body": {...}}

Exit: SIGTERM/SIGINT shut down cleanly.
"""

import argparse
import json
import os
import signal
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _sse(chunk: dict) -> bytes:
    return b"data: " + json.dumps(chunk, ensure_ascii=False).encode() + b"\n\n"


def _sig(n: int) -> str:
    return f"sig-main-{n}"


class Conversation:
    """One scripted conversation and its step cursor."""

    def __init__(self, steps):
        self.steps = steps
        self.cursor = 0

    def next_step(self):
        if self.cursor >= len(self.steps):
            step = {"text": "(scripted mock: steps exhausted)"}
        else:
            step = self.steps[self.cursor]
        self.cursor += 1
        return step


def pick_conversation(body: dict, scripts: dict, live: dict) -> Conversation:
    """Choose the script for a request: longest key that prefixes the
    first user message, else 'main'. Conversations persist across
    requests so each script step is consumed once."""
    first_user = ""
    for msg in body.get("messages", []):
        role = msg.get("role", "")
        content = msg.get("content", "")
        if isinstance(content, list):
            content = " ".join(
                c.get("text", "") for c in content if isinstance(c, dict)
            )
        if role == "user":
            first_user = content
            break
        # Anthropic wire: assistant-first histories still match on the
        # first user turn, so keep scanning.
    best = None
    for key in scripts:
        if key == "main":
            continue
        if first_user.startswith(key) and (best is None or len(key) > len(best)):
            best = key
    key = best if best is not None else "main"
    if key not in live:
        live[key] = Conversation(scripts[key])
    return live[key]


class Handler(BaseHTTPRequestHandler):
    _call_seq = 0
    protocol_version = "HTTP/1.1"
    scripts: dict = {}
    wire: str = "openai"
    log_path: str = None
    log_lock = threading.Lock()
    live: dict = {}

    def log_message(self, fmt, *args):  # silence default stderr noise
        pass

    # -- helpers ---------------------------------------------------------

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        self._log_request(raw)
        if not raw:
            return {}
        try:
            return json.loads(raw)
        except json.JSONDecodeError:
            return {"_raw": raw.decode("utf-8", "replace")}

    def _log_request(self, raw: bytes):
        if not Handler.log_path:
            return
        entry = {
            "ts": time.time(),
            "wire": Handler.wire,
            "path": self.path,
            "body": json.loads(raw) if raw else None,
        }
        with Handler.log_lock:
            with open(Handler.log_path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")

    def _fail(self, status: int, body: str):
        raw = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _sse_headers(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-cache")
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def _chunk(self, data: bytes):
        """Write one chunk of a chunked response."""
        self.wfile.write(f"{len(data):X}\r\n".encode() + data + b"\r\n")

    def _end_chunks(self):
        self.wfile.write(b"0\r\n\r\n")

    # -- OpenAI wire -----------------------------------------------------

    def _openai_step(self, step: dict):
        """Stream one assistant response in the OpenAI chat-completions
        SSE shape. Tool calls stream as incremental function arguments."""
        self._sse_headers()
        tool_calls = step.get("tools")
        text = step.get("text")
        if tool_calls:
            for i, call in enumerate(tool_calls):
                args = json.dumps(call.get("args", {}), ensure_ascii=False)
                # Globally-unique call ids (real providers never reuse
                # a tool-call id across rounds).
                Handler._call_seq += 1
                call_id = f"call_{Handler._call_seq}"
                first = {
                    "choices": [{"index": 0, "delta": {"tool_calls": [{
                        "index": i,
                        "id": call_id,
                        "type": "function",
                        "function": {"name": call["name"], "arguments": ""},
                    }]}}]
                }
                self._chunk(_sse(first))
                # stream the arguments in two halves so the client must
                # accumulate them
                mid = max(1, len(args) // 2)
                for part in (args[:mid], args[mid:]):
                    self._chunk(_sse({"choices": [{"index": 0, "delta": {
                        "tool_calls": [{"index": i, "function": {"arguments": part}}]
                    }}]}))
            self._chunk(_sse({"choices": [{"index": 0, "delta": {},
                                           "finish_reason": "tool_calls"}]}))
        else:
            if text:
                self._chunk(_sse({"choices": [{"index": 0, "delta": {
                    "content": text}}]}))
            self._chunk(_sse({"choices": [{"index": 0, "delta": {},
                                           "finish_reason": "stop"}]}))
        self._chunk(b"data: [DONE]\n\n")
        self._end_chunks()

    # -- Anthropic wire --------------------------------------------------

    def _anthropic_step(self, step: dict):
        """Stream one assistant response in the Anthropic messages SSE
        shape, including thinking blocks with signatures when asked."""
        self._sse_headers()
        ptok = step.get("ptok", 0)
        blocks = []
        if step.get("thinking"):
            blocks.append(("thinking", True))
        tool_calls = step.get("tools")
        if tool_calls:
            for i, call in enumerate(tool_calls):
                blocks.append(("tool_use", i, call))
        text = step.get("text")
        if text:
            blocks.append(("text", text))

        stop_reason = "tool_use" if tool_calls else "end_turn"

        # message_start carries usage on current models.
        msg = {
            "id": "msg_mock",
            "type": "message",
            "role": "assistant",
            "model": "mock",
            "content": [],
            "stop_reason": None,
            "usage": {"input_tokens": ptok, "output_tokens": 0},
        }
        self._chunk(_sse({"type": "message_start", "message": msg}))

        for b in blocks:
            if b[0] == "thinking":
                self._chunk(_sse({"type": "content_block_start", "index": 0,
                                  "content_block": {"type": "thinking",
                                                    "thinking": ""}}))
                self._chunk(_sse({"type": "content_block_delta", "index": 0,
                                  "delta": {"type": "thinking_delta",
                                            "thinking": "plan: find files"}}))
                self._chunk(_sse({"type": "content_block_delta", "index": 0,
                                  "delta": {"type": "signature_delta",
                                            "signature": _sig(0)}}))
                self._chunk(_sse({"type": "content_block_stop", "index": 0}))
            elif b[0] == "tool_use":
                _, i, call = b
                self._chunk(_sse({"type": "content_block_start", "index": i + 1,
                                  "content_block": {"type": "tool_use",
                                                    "id": f"toolu_{i}",
                                                    "name": call["name"],
                                                    "input": {}}}))
                args = json.dumps(call.get("args", {}), ensure_ascii=False)
                self._chunk(_sse({"type": "content_block_delta", "index": i + 1,
                                  "delta": {"type": "input_json_delta",
                                            "partial_json": args}}))
                self._chunk(_sse({"type": "content_block_stop", "index": i + 1}))
            else:
                self._chunk(_sse({"type": "content_block_start", "index": 0,
                                  "content_block": {"type": "text",
                                                    "text": ""}}))
                self._chunk(_sse({"type": "content_block_delta", "index": 0,
                                  "delta": {"type": "text_delta",
                                            "text": b[1]}}))
                self._chunk(_sse({"type": "content_block_stop", "index": 0}))

        self._chunk(_sse({"type": "message_delta",
                          "delta": {"stop_reason": stop_reason},
                          "usage": {"output_tokens": 16}}))
        self._chunk(_sse({"type": "message_stop"}))
        self._end_chunks()

    # -- routing ---------------------------------------------------------

    def do_POST(self):
        body = self._read_body()
        conv = pick_conversation(body, Handler.scripts, Handler.live)
        step = conv.next_step()

        if "status" in step:
            self._fail(step["status"], step.get("body") or "")
            return

        if "stall_ms" in step:
            # E5: a stalled stream. Headers (200) go out, optional
            # stall_bytes, then silence for stall_ms — the client must
            # time out between chunks and retry.
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            if step.get("stall_bytes"):
                self.wfile.write(step["stall_bytes"].encode())
                self.wfile.flush()
            time.sleep(step["stall_ms"] / 1000.0)
            return

        if Handler.wire == "anthropic" or self.path.endswith("/v1/messages"):
            self._anthropic_step(step)
        else:
            self._openai_step(step)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=18890)
    ap.add_argument("--bind-out", help="write the actually-bound port here")
    ap.add_argument("--script", required=True)
    ap.add_argument("--log", required=True)
    ap.add_argument("--wire", choices=["openai", "anthropic"], default="openai")
    args = ap.parse_args()

    with open(args.script, encoding="utf-8") as f:
        Handler.scripts = json.load(f)
    Handler.wire = args.wire
    Handler.log_path = args.log
    # start each run fresh
    open(args.log, "w").close()

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    port = srv.server_address[1]
    if args.bind_out:
        with open(args.bind_out, "w") as f:
            f.write(str(port))
    print(f"scripted mock ({args.wire}) on 127.0.0.1:{port}", flush=True)

    stop = threading.Event()

    def bye(*_):
        stop.set()

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)

    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    stop.wait()
    srv.shutdown()
    return 0


if __name__ == "__main__":
    sys.exit(main())
