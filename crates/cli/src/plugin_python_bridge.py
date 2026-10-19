#!/usr/bin/env python3
"""Persistent stdio MCP host for explicitly enabled native Python plugins."""

from __future__ import annotations

import argparse
import asyncio
import concurrent.futures
import contextvars
import dataclasses
import importlib.util
import inspect
import io
import json
import os
from pathlib import Path
import re
import secrets
import socket
import sys
import threading
import time
import types
from typing import Any, Callable


MAX_FRAME_BYTES = 1024 * 1024
MAX_ERROR_CHARS = 2048
MAX_REGISTRATIONS = 512
DEFAULT_BUDGET_MS = 30_000
MAX_BUDGET_MS = 120_000
CONTROL_SCHEMA = "orbit.plugin.control/v1"
_CURRENT_INVOCATION: contextvars.ContextVar[Invocation | None] = contextvars.ContextVar(
    "orbit_plugin_invocation", default=None
)


class BridgeError(Exception):
    def __init__(self, message: str, code: int = -32000):
        super().__init__(message)
        self.code = code


def _json_bytes(value: Any) -> bytes:
    return json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":")).encode("utf-8")


def _reject_constant(_: str) -> None:
    raise ValueError("non-finite JSON number")


def _read_frame(stream: Any) -> dict[str, Any] | None:
    line = stream.readline(MAX_FRAME_BYTES + 1)
    if not line:
        return None
    if len(line) > MAX_FRAME_BYTES or not line.endswith(b"\n"):
        raise BridgeError("protocol frame is oversized or incomplete", -32700)
    try:
        value = json.loads(line, parse_constant=_reject_constant)
    except (ValueError, UnicodeError) as exc:
        raise BridgeError("invalid JSON protocol frame", -32700) from exc
    if not isinstance(value, dict):
        raise BridgeError("protocol frame must be an object", -32600)
    return value


def _write_frame(stream: Any, raw: bytes) -> None:
    remaining = memoryview(raw + b"\n")
    while remaining:
        count = stream.write(remaining)
        if count is None or count <= 0:
            raise BridgeError("protocol output closed")
        remaining = remaining[count:]
    stream.flush()


def _private_directory(root: Path, relative: str) -> Path:
    current = root
    for segment in relative.split("/"):
        current = current / segment
        try:
            current.mkdir(mode=0o700)
        except FileExistsError:
            pass
        if current.is_symlink() or not current.is_dir():
            raise BridgeError("private runtime directory is not an owned directory")
        if root not in current.resolve().parents:
            raise BridgeError("private runtime directory escapes plugin data")
    return current


def _short_string(value: Any, field: str, limit: int = 128) -> str:
    if not isinstance(value, str) or not value or len(value) > limit or any(ord(c) < 32 for c in value):
        raise BridgeError(f"invalid {field}", -32602)
    return value


def tool_error(message: Any, **extra: Any) -> str:
    text = str(message)
    if len(text) > MAX_ERROR_CHARS:
        text = text[:MAX_ERROR_CHARS] + "… [truncated]"
    return json.dumps({"error": text, **extra}, ensure_ascii=False, allow_nan=False)


def tool_result(data: Any = None, **kwargs: Any) -> str:
    return json.dumps(data if data is not None else kwargs, ensure_ascii=False, allow_nan=False)


class DiagnosticWriter(io.TextIOBase):
    def __init__(self, stream: Any):
        self.stream = stream
        self.remaining = 64 * 1024
        self.lock = threading.Lock()
        self.redactions: list[str] = []

    def write(self, text: str) -> int:
        original_length = len(text)
        for secret in self.redactions:
            text = text.replace(secret, "[redacted]")
        with self.lock:
            if self.remaining > 0:
                encoded = text.encode("utf-8", errors="replace")[: self.remaining]
                self.remaining -= len(encoded)
                self.stream.write(encoded.decode("utf-8", errors="ignore"))
                self.stream.flush()
        return original_length

    def flush(self) -> None:
        self.stream.flush()

    def fileno(self) -> int:
        return 2


@dataclasses.dataclass
class Invocation:
    identity: str | None
    deadline: float
    host_bound: bool
    cancelled: threading.Event = dataclasses.field(default_factory=threading.Event)

    def budget_ms(self) -> int:
        if self.cancelled.is_set():
            raise BridgeError("plugin invocation was cancelled", -32800)
        budget = int((self.deadline - time.monotonic()) * 1000)
        if budget <= 0:
            raise BridgeError("plugin invocation deadline expired", -32800)
        return budget


class ControlChannel:
    def __init__(self, fd: int, plugin_id: str, source_digest: str):
        self.socket = socket.socket(fileno=fd)
        if self.socket.family != socket.AF_UNIX or self.socket.type != socket.SOCK_STREAM:
            raise BridgeError("control descriptor must be a Unix stream socket")
        self.socket.settimeout(5)
        self.stream = self.socket.makefile("rwb")
        packet = _read_frame(self.stream)
        if not packet or packet.get("schema") != CONTROL_SCHEMA:
            raise BridgeError("invalid control handshake")
        if packet.get("plugin_id") != plugin_id or packet.get("source_digest") != source_digest:
            raise BridgeError("control handshake identity mismatch")
        self.token = _short_string(packet.get("token"), "control credential", 512)
        if not re.fullmatch(r"[A-Za-z0-9_.~-]{32,512}", self.token):
            raise BridgeError("control credential must be a bounded opaque ASCII token")
        self.generation = _short_string(packet.get("generation"), "control generation")
        self.lock = threading.Lock()
        self.closed = False
        self.sequence = 0
        self._write({"schema": CONTROL_SCHEMA, "ready": True, "generation": self.generation})

    def _write(self, value: Any) -> None:
        raw = _json_bytes(value)
        if len(raw) + 1 > MAX_FRAME_BYTES:
            raise BridgeError("control frame exceeds size limit")
        _write_frame(self.stream, raw)

    def dispatch(self, tool_name: str, arguments: dict[str, Any], invocation: Invocation) -> str:
        if not invocation.host_bound or not invocation.identity:
            raise BridgeError("nested host dispatch requires host invocation metadata")
        with self.lock:
            if self.closed:
                raise BridgeError("control channel is closed")
            budget = invocation.budget_ms()
            self.socket.settimeout(min(budget / 1000, MAX_BUDGET_MS / 1000))
            self.sequence += 1
            request_id = f"host-{self.sequence}"
            self._write({"jsonrpc": "2.0", "id": request_id, "method": "orbit/host.dispatch", "params": {
                "token": self.token, "generation": self.generation,
                "invocation_id": invocation.identity, "operation": "dispatch_tool",
                "tool_name": tool_name, "arguments": arguments, "remaining_budget_ms": budget,
            }})
            try:
                response = _read_frame(self.stream)
            except (OSError, BridgeError):
                self.closed = True
                raise BridgeError("nested host response failed; outcome may be uncertain") from None
            invocation.budget_ms()
            if not response or response.get("jsonrpc") != "2.0" or response.get("id") != request_id:
                self.closed = True
                raise BridgeError("invalid nested host response")
            if "error" in response:
                raise BridgeError("nested host dispatch failed")
            result = response.get("result")
            if not isinstance(result, dict) or "value" not in result:
                raise BridgeError("nested host response lacks a value")
            value = result["value"]
            return value if isinstance(value, str) else tool_result(value)

    def close(self) -> None:
        self.closed = True
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.stream.close()
        self.socket.close()


@dataclasses.dataclass
class Registration:
    kind: str
    key: str
    callback: Callable[..., Any]
    metadata: dict[str, Any]
    owner: PluginContext
    identifier: str
    active: bool = True

    @property
    def plugin_key(self) -> str:
        return self.owner.plugin_id

    def dispose(self) -> None:
        self.active = False


class PluginContext:
    def __init__(self, runtime: Runtime):
        self.runtime = runtime
        self.plugin_id = runtime.plugin_id
        self.registrations: list[Registration] = []
        self.lock = threading.RLock()

    def _register(self, kind: str, name: str, callback: Callable[..., Any], **metadata: Any) -> Registration:
        _short_string(name, "registration name")
        if not callable(callback):
            raise BridgeError("registered callback must be callable")
        with self.lock:
            if len(self.registrations) >= MAX_REGISTRATIONS:
                raise BridgeError("plugin registration limit exceeded")
            if kind != "hook" and any(r.active and r.kind == kind and r.key == name for r in self.registrations):
                raise BridgeError(f"duplicate {kind} registration: {name}")
            _json_bytes(metadata)
            item = Registration(kind, name, callback, metadata, self, f"{kind}:{len(self.registrations) + 1}")
            self.registrations.append(item)
            return item

    def register_tool(self, name: str, toolset: str, schema: dict[str, Any], handler: Callable[..., Any],
                      check_fn: Callable[..., Any] | None = None, requires_env: list[str] | None = None,
                      is_async: bool = False, description: str = "", emoji: str = "", override: bool = False) -> Registration:
        if not isinstance(schema, dict) or schema.get("name", name) != name:
            raise BridgeError("invalid tool schema identity")
        if not isinstance(schema.get("parameters", {}), dict):
            raise BridgeError("tool parameters schema must be an object")
        if check_fn is not None and not callable(check_fn):
            raise BridgeError("tool availability check must be callable")
        if requires_env is not None and (not isinstance(requires_env, list) or
                                          any(not isinstance(v, str) or not v for v in requires_env)):
            raise BridgeError("requires_env must contain environment variable names")
        item = self._register("tool", name, handler, toolset=toolset, schema=schema,
                              requires_env=requires_env or [], is_async=bool(is_async),
                              description=description, emoji=emoji, override=bool(override))
        item.check_fn = check_fn
        return item

    def register_command(self, name: str, handler: Callable[..., Any], description: str = "",
                         args_hint: str = "", argument_mode: str | None = None) -> Registration:
        return self._register("command", name.lower().strip().lstrip("/").replace(" ", "-"), handler,
                              description=description, args_hint=args_hint, argument_mode=argument_mode)

    def register_hook(self, hook_name: str, callback: Callable[..., Any]) -> Registration:
        return self._register("hook", hook_name, callback)

    def dispatch_tool(self, tool_name: str, args: dict[str, Any], **kwargs: Any) -> str:
        if kwargs:
            raise BridgeError("nested host keyword overrides require an explicit port")
        _short_string(tool_name, "nested host tool name")
        if not isinstance(args, dict):
            raise BridgeError("nested host arguments must be an object")
        invocation = _CURRENT_INVOCATION.get()
        if self.runtime.control is None or invocation is None:
            raise BridgeError("nested host dispatch requires an authenticated control channel")
        return self.runtime.control.dispatch(tool_name, args, invocation)

    def describe(self) -> list[dict[str, Any]]:
        with self.lock:
            return [{"id": r.identifier, "kind": r.kind, "name": r.key, **r.metadata}
                    for r in self.registrations if r.active]

    def resolve(self, identifier: str, kind: str) -> Registration:
        with self.lock:
            item = next((r for r in self.registrations if r.active and r.identifier == identifier and r.kind == kind), None)
        if item is None:
            raise BridgeError("unknown or inactive runtime registration", -32602)
        return item

    def __getattr__(self, name: str) -> Any:
        if name.startswith("_"):
            raise AttributeError(name)
        raise BridgeError(f"native host API '{name}' requires a concrete port adapter")


def _accepted_kwargs(callback: Callable[..., Any], values: dict[str, Any]) -> dict[str, Any]:
    try:
        parameters = inspect.signature(callback).parameters
    except (TypeError, ValueError):
        return values
    if any(p.kind == inspect.Parameter.VAR_KEYWORD for p in parameters.values()):
        return values
    kinds = (inspect.Parameter.POSITIONAL_OR_KEYWORD, inspect.Parameter.KEYWORD_ONLY)
    return {k: v for k, v in values.items() if k in parameters and parameters[k].kind in kinds}


class Runtime:
    def __init__(self, arguments: argparse.Namespace, output: Any):
        self.root = Path(arguments.root).resolve(strict=True)
        self.data = Path(arguments.data).resolve(strict=True)
        if (not self.root.is_dir() or not self.data.is_dir() or self.root == self.data
                or self.root in self.data.parents or self.data in self.root.parents):
            raise BridgeError("plugin root and private data must be separate directories")
        self.plugin_id = _short_string(arguments.plugin_id, "plugin id", 64)
        if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]*", self.plugin_id):
            raise BridgeError("invalid plugin identifier")
        self.source_digest = arguments.source_digest
        if not re.fullmatch(r"[0-9a-f]{64}", self.source_digest):
            raise BridgeError("invalid source digest")
        self.output = output
        self.write_lock = threading.Lock()
        self.pending_lock = threading.Lock()
        self.pending: dict[Any, tuple[concurrent.futures.Future[Any], Invocation]] = {}
        self.callback_active = False
        self.control = ControlChannel(arguments.control_fd, self.plugin_id, self.source_digest) if arguments.control_fd is not None else None
        self.generation = self.control.generation if self.control else secrets.token_hex(16)
        self.context = PluginContext(self)
        self.loop = asyncio.new_event_loop()
        self.worker = threading.Thread(target=self._run_loop, name="plugin-callbacks", daemon=True)
        self.stopping = False

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_forever()
        finally:
            tasks = asyncio.all_tasks(self.loop)
            for task in tasks:
                task.cancel()
            if tasks:
                self.loop.run_until_complete(asyncio.wait(tasks, timeout=0.1))
            self.loop.close()

    def load(self) -> None:
        sys.dont_write_bytecode = True
        helpers = types.ModuleType("tools.registry")
        helpers.tool_error = tool_error
        helpers.tool_result = tool_result
        package = types.ModuleType("tools")
        package.__path__ = []
        package.registry = helpers
        sys.modules["tools"] = package
        sys.modules["tools.registry"] = helpers
        for key, relative in (("HOME", "home"), ("XDG_CONFIG_HOME", "home/config"),
                              ("XDG_CACHE_HOME", "home/cache"), ("XDG_DATA_HOME", "home/data"),
                              ("XDG_STATE_HOME", "home/state")):
            directory = _private_directory(self.data, relative)
            os.environ[key] = str(directory)
        os.environ["HERMES_HOME"] = str(self.data)
        os.environ["PLUGIN_ROOT"] = str(self.root)
        os.environ["PLUGIN_DATA"] = str(self.data)
        entry = self.root / "__init__.py"
        if not entry.is_file() or entry.is_symlink():
            raise BridgeError("native plugin requires a regular __init__.py")
        spec = importlib.util.spec_from_file_location(
            "orbit_native_plugin", entry, submodule_search_locations=[str(self.root)]
        )
        if spec is None or spec.loader is None:
            raise BridgeError("cannot create native plugin import")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module
        spec.loader.exec_module(module)
        register = getattr(module, "register", None)
        if not callable(register):
            raise BridgeError("native plugin must export register(ctx)")
        result = register(self.context)
        if inspect.isawaitable(result):
            result.close()
            raise BridgeError("async register(ctx) requires an explicit port")
        self.worker.start()

    def send(self, value: Any) -> None:
        raw = _json_bytes(value)
        if self.control is not None:
            raw = raw.replace(self.control.token.encode("ascii"), b"[redacted]")
        if len(raw) + 1 > MAX_FRAME_BYTES:
            raise BridgeError("plugin response exceeds frame size limit")
        with self.write_lock:
            _write_frame(self.output, raw)

    def error(self, request_id: Any, exception: BaseException) -> None:
        message = str(exception)
        if self.control is not None:
            message = message.replace(self.control.token, "[redacted]")
        self.send({"jsonrpc": "2.0", "id": request_id, "error": {
            "code": exception.code if isinstance(exception, BridgeError) else -32000,
            "message": message[:MAX_ERROR_CHARS],
        }})

    def describe(self) -> dict[str, Any]:
        return {"generation": self.generation, "plugin_id": self.plugin_id,
                "source_digest": self.source_digest, "registrations": self.context.describe(),
                "readiness": "ready", "capabilities": ["tools", "commands", "hooks"]}

    def invocation(self, params: dict[str, Any], private: bool) -> Invocation:
        envelope = params.get("_meta", {})
        if not isinstance(envelope, dict):
            raise BridgeError("invalid invocation metadata", -32602)
        metadata = params if private else envelope.get("orbit", {})
        if not isinstance(metadata, dict):
            raise BridgeError("invalid invocation metadata", -32602)
        supplied = bool(metadata)
        if supplied and metadata.get("generation") != self.generation:
            raise BridgeError("runtime generation mismatch", -32602)
        identity = _short_string(metadata.get("invocation_id"), "invocation id") if supplied else None
        budget = metadata.get("remaining_budget_ms", DEFAULT_BUDGET_MS)
        if not isinstance(budget, int) or isinstance(budget, bool) or budget <= 0:
            raise BridgeError("invalid invocation budget", -32602)
        return Invocation(identity, time.monotonic() + min(budget, MAX_BUDGET_MS) / 1000,
                          supplied and self.control is not None)

    async def resolve_result(self, value: Any, invocation: Invocation) -> Any:
        if not inspect.isawaitable(value):
            return value
        try:
            return await asyncio.wait_for(value, invocation.budget_ms() / 1000)
        except TimeoutError as exc:
            raise BridgeError("plugin invocation deadline expired", -32800) from exc

    async def perform(self, method: str, params: dict[str, Any], invocation: Invocation) -> Any:
        with self.pending_lock:
            self.callback_active = True
        current = _CURRENT_INVOCATION.set(invocation)
        try:
            invocation.budget_ms()
            if method == "tools/call":
                name = _short_string(params.get("name"), "tool name")
                item = next((r for r in self.context.registrations if r.active and r.kind == "tool" and r.key == name), None)
                if item is None:
                    raise BridgeError("unknown plugin tool", -32602)
                missing = [n for n in item.metadata["requires_env"] if not os.environ.get(n)]
                if missing:
                    raise BridgeError("plugin tool requires environment variables: " + ", ".join(missing))
                check = getattr(item, "check_fn", None)
                if check is not None:
                    available = check()
                    available = await self.resolve_result(available, invocation)
                    if not available:
                        raise BridgeError("plugin tool is unavailable")
                arguments = params.get("arguments", {})
                if not isinstance(arguments, dict):
                    raise BridgeError("tool arguments must be an object", -32602)
                value = item.callback(arguments)
                value = await self.resolve_result(value, invocation)
                if not isinstance(value, str):
                    raise BridgeError("native tool handler must return a JSON string")
                invocation.budget_ms()
                try:
                    parsed = json.loads(value)
                except ValueError:
                    parsed = None
                return {"content": [{"type": "text", "text": value}],
                        "isError": isinstance(parsed, dict) and "error" in parsed}
            kind = params.get("kind")
            if kind not in ("command", "hook"):
                raise BridgeError("unsupported native invocation kind", -32602)
            item = self.context.resolve(_short_string(params.get("registration_id"), "registration id"), kind)
            args, kwargs = params.get("args", []), params.get("kwargs", {})
            if not isinstance(args, list) or not isinstance(kwargs, dict):
                raise BridgeError("native invocation requires args array and kwargs object", -32602)
            if kind == "command" and (len(args) != 1 or not isinstance(args[0], str) or kwargs):
                raise BridgeError("command invocation requires one raw argument string", -32602)
            if kind == "hook" and args:
                raise BridgeError("hook invocation accepts keyword arguments only", -32602)
            try:
                value = item.callback(*args, **_accepted_kwargs(item.callback, kwargs))
                value = await self.resolve_result(value, invocation)
            except (Exception, SystemExit) as exc:
                if kind == "hook" and item.key == "pre_tool_call":
                    return {"value": {"action": "block", "message": "native pre_tool_call callback failed"}}
                raise BridgeError("native callback failed: " + type(exc).__name__) from exc
            invocation.budget_ms()
            return {"value": value}
        finally:
            _CURRENT_INVOCATION.reset(current)
            with self.pending_lock:
                self.callback_active = False

    def complete(self, request_id: Any, future: concurrent.futures.Future[Any]) -> None:
        with self.pending_lock:
            entry = self.pending.pop(request_id, None)
        if entry is None:
            return
        try:
            self.send({"jsonrpc": "2.0", "id": request_id, "result": future.result()})
        except concurrent.futures.CancelledError:
            self.error(request_id, BridgeError("plugin request cancelled", -32800))
        except (Exception, SystemExit) as exc:
            self.error(request_id, exc)

    def handle(self, request: dict[str, Any]) -> None:
        request_id = request.get("id")
        if request.get("jsonrpc") != "2.0" or not isinstance(request.get("method"), str):
            raise BridgeError("invalid JSON-RPC request", -32600)
        if request_id is not None and (isinstance(request_id, bool) or not isinstance(request_id, (str, int))):
            raise BridgeError("invalid JSON-RPC request id", -32600)
        method = request["method"]
        params = request.get("params", {})
        if not isinstance(params, dict):
            raise BridgeError("JSON-RPC params must be an object", -32602)
        if method == "notifications/cancelled":
            with self.pending_lock:
                entry = self.pending.get(params.get("requestId"))
            if entry is not None:
                entry[1].cancelled.set()
                entry[0].cancel()
            return
        if request_id is None:
            return
        if method == "initialize":
            version = params.get("protocolVersion")
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {
                "protocolVersion": version if version in ("2024-11-05", "2025-06-18") else "2025-06-18",
                "capabilities": {"tools": {}, "experimental": {"com.orbit.plugin": {"version": 1}}},
                "serverInfo": {"name": "orbit-plugin-runtime", "version": "1"},
            }})
        elif method == "tools/list":
            tools = [{"name": r.key, "description": r.metadata["schema"].get("description", ""),
                      "inputSchema": r.metadata["schema"].get("parameters", {"type": "object"})}
                     for r in self.context.registrations if r.active and r.kind == "tool"]
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {"tools": tools}})
        elif method == "orbit/plugin.describe":
            self.send({"jsonrpc": "2.0", "id": request_id, "result": self.describe()})
        elif method == "orbit/plugin.shutdown":
            self.stopping = True
            self.send({"jsonrpc": "2.0", "id": request_id, "result": {
                "completed": not self.pending and not self.callback_active,
            }})
        elif method in ("tools/call", "orbit/plugin.invoke"):
            invocation = self.invocation(params, method == "orbit/plugin.invoke")
            with self.pending_lock:
                if self.pending or self.callback_active:
                    raise BridgeError("plugin runtime is occupied; reentrant calls are not permitted", -32002)
                future = asyncio.run_coroutine_threadsafe(self.perform(method, params, invocation), self.loop)
                self.pending[request_id] = (future, invocation)
            future.add_done_callback(lambda done: self.complete(request_id, done))
        else:
            raise BridgeError("unknown runtime method", -32601)

    def stop(self) -> None:
        with self.pending_lock:
            active = list(self.pending.values())
            self.pending.clear()
        for future, invocation in active:
            invocation.cancelled.set()
            future.cancel()
        if self.control is not None:
            self.control.close()
        if self.worker.is_alive():
            self.loop.call_soon_threadsafe(self.loop.stop)
            self.worker.join(timeout=0.2)
        elif not self.loop.is_closed():
            self.loop.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True)
    parser.add_argument("--data", required=True)
    parser.add_argument("--plugin-id", required=True)
    parser.add_argument("--source-digest", required=True)
    parser.add_argument("--control-fd", type=int)
    arguments = parser.parse_args()
    if arguments.control_fd is not None and arguments.control_fd < 3:
        parser.error("control descriptor must be inherited separately from stdio")
    output = os.fdopen(os.dup(1), "wb", buffering=0)
    os.dup2(2, 1)
    diagnostics = DiagnosticWriter(sys.stderr)
    sys.stdout = diagnostics
    sys.stderr = diagnostics
    runtime = None
    try:
        runtime = Runtime(arguments, output)
        if runtime.control is not None:
            diagnostics.redactions.append(runtime.control.token)
        runtime.load()
        while not runtime.stopping:
            try:
                request = _read_frame(sys.stdin.buffer)
                if request is None:
                    break
                try:
                    runtime.handle(request)
                except (Exception, SystemExit) as exc:
                    runtime.error(request.get("id"), exc)
            except BridgeError as exc:
                runtime.error(None, exc)
                break
    except (Exception, SystemExit) as exc:
        diagnostics.write("Native plugin startup failed: " + type(exc).__name__ + ": " + str(exc)[:MAX_ERROR_CHARS] + "\n")
        return 78
    finally:
        if runtime is not None:
            runtime.stop()
        output.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
