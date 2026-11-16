#!/usr/bin/env python3
"""A scripted LSP stdio peer for navigation requests.

argv: MODE LOG WORKSPACE. Every frame received is appended to LOG. MODE
"loading" answers the first two requests with an error, as a server does
while it indexes; "no_references" leaves that capability out.
"""
import json
import pathlib
import sys

mode, log_path, workspace = sys.argv[1:4]
root = pathlib.Path(workspace)


def record(value):
    with open(log_path, "a", encoding="utf-8") as log:
        log.write(json.dumps(value) + "\n")


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


def at(path, line, character):
    return {
        "uri": (root / path).as_uri() if not str(path).startswith("/") else pathlib.Path(path).as_uri(),
        "range": {"start": {"line": line, "character": character}, "end": {"line": line, "character": character + 4}},
    }


asked = 0
while True:
    message = receive()
    if message is None:
        break
    record(message)
    method = message.get("method")
    if "id" not in message:
        continue
    if method == "initialize":
        capabilities = {
            "positionEncoding": "utf-8" if mode == "utf8" else "utf-16",
            "definitionProvider": True,
            "hoverProvider": True,
            "documentSymbolProvider": {"label": "fixture"},
            "workspaceSymbolProvider": True,
        }
        if mode != "no_references":
            capabilities["referencesProvider"] = True
        send({"jsonrpc": "2.0", "id": message["id"], "result": {"capabilities": capabilities}})
        continue
    if method == "shutdown":
        send({"jsonrpc": "2.0", "id": message["id"], "result": None})
        continue
    asked += 1
    if mode == "loading" and asked <= 2:
        send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32801, "message": "content modified"}})
        continue
    if mode == "nothing":
        send({"jsonrpc": "2.0", "id": message["id"], "result": None})
        continue
    if method == "textDocument/definition":
        result = [{"targetUri": (root / "lib.rs").as_uri(),
                   "targetRange": {"start": {"line": 4, "character": 0}, "end": {"line": 9, "character": 1}},
                   "targetSelectionRange": {"start": {"line": 4, "character": 7}, "end": {"line": 4, "character": 12}}}]
    elif method == "textDocument/references":
        result = [at("file.rs", 0, 3), at("lib.rs", 4, 7), at(".env", 0, 0), at("/etc/hostname", 0, 0)]
    elif method == "textDocument/hover":
        result = {"contents": {"kind": "markdown", "value": "```rust\nfn start(port: u16)\n```\nStarts the server."}}
    elif method == "textDocument/documentSymbol":
        span = {"start": {"line": 0, "character": 0}, "end": {"line": 9, "character": 1}}
        result = [{"name": "Server", "kind": 23, "range": span,
                   "selectionRange": {"start": {"line": 0, "character": 7}, "end": {"line": 0, "character": 13}},
                   "children": [{"name": "port", "kind": 8, "range": span,
                                 "selectionRange": {"start": {"line": 1, "character": 4}, "end": {"line": 1, "character": 8}}}]},
                  {"name": "main", "kind": 12, "range": span,
                   "selectionRange": {"start": {"line": 5, "character": 3}, "end": {"line": 5, "character": 7}}}]
    elif method == "workspace/symbol":
        result = [{"name": "start", "kind": 12, "containerName": "server", "location": at("lib.rs", 4, 7)}]
    else:
        send({"jsonrpc": "2.0", "id": message["id"], "error": {"code": -32601, "message": "unknown"}})
        continue
    send({"jsonrpc": "2.0", "id": message["id"], "result": result})
