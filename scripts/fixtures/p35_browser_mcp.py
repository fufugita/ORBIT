#!/usr/bin/env python3
"""Bounded synthetic browser stdio fixture. It does not launch a browser."""

import argparse
import json
import os
from pathlib import Path
import sys
from html.parser import HTMLParser

MAX_FRAME_BYTES = 1024 * 1024
EXPOSED = ("browser_navigate", "browser_snapshot", "browser_click", "browser_close")


class PageText(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hidden = 0
        self.parts = []

    def handle_starttag(self, tag, _attrs):
        if tag in ("script", "style"):
            self.hidden += 1

    def handle_endtag(self, tag):
        if tag in ("script", "style"):
            self.hidden = max(0, self.hidden - 1)

    def handle_data(self, data):
        if not self.hidden and data.strip():
            self.parts.append(data.strip())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--log", type=Path, required=True)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--page", type=Path, required=True)
    parser.add_argument("--expected-url")
    args = parser.parse_args()
    page = args.page.resolve(strict=True)
    expected_url = args.expected_url or page.as_uri()
    raw_page = page.read_text(encoding="utf-8")
    if len(raw_page.encode()) > 64 * 1024:
        raise ValueError("fixture page exceeds 64 KiB")
    parsed = PageText()
    parsed.feed(raw_page)
    state = {"url": None, "counter": 0, "closed": False, "pid": os.getpid()}

    def log(entry):
        with args.log.open("a", encoding="utf-8") as capture:
            capture.write(json.dumps(entry) + "\n")
            capture.flush()
            os.fsync(capture.fileno())

    def save_state():
        tmp = args.state.with_suffix(".tmp")
        with tmp.open("w", encoding="utf-8") as saved:
            json.dump(state, saved)
            saved.flush()
            os.fsync(saved.fileno())
        tmp.replace(args.state)

    log({"kind": "spawn", "pid": os.getpid()})
    save_state()
    try:
        while True:
            line = sys.stdin.buffer.readline(MAX_FRAME_BYTES + 1)
            if not line:
                break
            if len(line) > MAX_FRAME_BYTES:
                raise ValueError("fixture request exceeds frame limit")
            request = json.loads(line)
            log(request)
            if "id" not in request:
                continue
            reply = {"jsonrpc": "2.0", "id": request["id"]}
            method = request.get("method")
            if method == "initialize":
                reply["result"] = {
                    "protocolVersion": request.get("params", {}).get("protocolVersion", "2025-06-18"),
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "synthetic-local-browser", "version": "1"},
                }
            elif method == "tools/list":
                # An extra advertised identity lets acceptance prove exact exposure.
                reply["result"] = {"tools": [
                    {"name": name, "description": "Local synthetic browser fixture",
                     "inputSchema": {"type": "object"}}
                    for name in (*EXPOSED, "browser_evaluate")
                ]}
            elif method == "tools/call":
                params = request.get("params", {})
                name = params.get("name")
                inputs = params.get("arguments", {})
                error = None
                if name == "browser_navigate":
                    if inputs.get("url") != expected_url:
                        error = "fixture only navigates its configured local page"
                    else:
                        state.update(url=expected_url, counter=0, closed=False)
                elif name == "browser_snapshot":
                    if not state["url"] or state["closed"]:
                        error = "fixture has no open page"
                elif name == "browser_click":
                    if not state["url"] or state["closed"] or inputs.get("ref") != "increment":
                        error = "fixture requires an open page and the exact increment reference"
                    else:
                        state["counter"] += 1
                elif name == "browser_close":
                    state["closed"] = True
                    state["url"] = None
                else:
                    error = "unexposed synthetic operation"
                save_state()
                if error:
                    reply["result"] = {"isError": True, "content": [{"type": "text", "text": error}]}
                else:
                    text = f"Synthetic local snapshot. Count: {state['counter']}. Closed: {state['closed']}."
                    if name == "browser_snapshot":
                        text += '\nbutton "Increment" [ref=increment]\n' + "\n".join(parsed.parts)
                    reply["result"] = {
                        "content": [{"type": "text", "text": text}],
                        "structuredContent": {"url": state["url"], "counter": state["counter"], "closed": state["closed"]},
                    }
            elif method == "ping":
                reply["result"] = {}
            else:
                reply["error"] = {"code": -32601, "message": "unsupported fixture request"}
            print(json.dumps(reply), flush=True)
    finally:
        state["process_exited"] = True
        save_state()
        log({"kind": "process_exit", "pid": os.getpid()})


if __name__ == "__main__":
    main()
