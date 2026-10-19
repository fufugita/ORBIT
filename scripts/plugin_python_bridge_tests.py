#!/usr/bin/env python3
"""Standalone process checks for the native plugin stdio bridge."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import selectors
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest


BRIDGE = Path(__file__).resolve().parents[1] / "crates/cli/src/plugin_python_bridge.py"
FIXTURE = '''import asyncio
import json
import os
from tools.registry import tool_result, tool_error

print("plugin import diagnostic")
os.write(1, b"direct descriptor diagnostic\\n")

def register(ctx):
    state = {"count": 0}
    def counter(args):
        state["count"] += 1
        return tool_result(count=state["count"], pid=os.getpid())
    async def async_counter(args):
        await asyncio.sleep(0)
        state["count"] += 1
        return tool_result(count=state["count"], loop=id(asyncio.get_running_loop()))
    async def slow(args):
        await asyncio.sleep(60)
        return tool_result(unexpected=True)
    def nested(args):
        return ctx.dispatch_tool(args.get("name", "read_file"), args.get("arguments", {}))
    def environment(args):
        return tool_result({"home": os.environ["HOME"], "data": os.environ["HERMES_HOME"]})
    def helper_semantics(args):
        return tool_result({
            "positional": json.loads(tool_result({"selected": "positional"}, ignored=True)),
            "named_data": json.loads(tool_result(data="selected", ignored=True)),
            "empty_data": json.loads(tool_result({}, ignored=True)),
            "kwargs": json.loads(tool_result(home="private", selected=True)),
            "null_data": json.loads(tool_result(data=None, selected=True)),
        })
    def unavailable(args):
        raise AssertionError("unavailable tool executed")
    def source_error(args):
        return tool_error("example error", kind="fixture")
    async def command(raw_args):
        await asyncio.sleep(0)
        return "echo: " + raw_args
    def narrow_hook(tool_name, args):
        if args.get("block"):
            return {"action": "block", "message": "fixture refused " + tool_name}
        return None
    def raising_hook(**kwargs):
        raise ValueError("fixture gate failed")
    for name, handler in (("counter", counter), ("async_counter", async_counter),
                          ("slow", slow), ("nested", nested), ("environment", environment),
                          ("source_error", source_error), ("helper_semantics", helper_semantics)):
        ctx.register_tool(name=name, toolset="fixture", schema={"name": name,
            "description": "Protocol fixture " + name,
            "parameters": {"type": "object", "properties": {}}}, handler=handler)
    ctx.register_tool(name="unavailable", toolset="fixture", schema={"name": "unavailable",
        "parameters": {"type": "object"}}, handler=unavailable,
        requires_env=["ORBIT_BRIDGE_FIXTURE_MISSING"])
    ctx.register_command("Echo", command, description="Echo arguments")
    ctx.register_hook("pre_tool_call", narrow_hook)
    ctx.register_hook("pre_tool_call", raising_hook)
'''
DIGEST = hashlib.sha256(FIXTURE.encode()).hexdigest()


class HostChannel:
    def __init__(self, sock: socket.socket, bad_identity: bool = False):
        self.socket = sock
        self.socket.settimeout(4)
        self.token = "native-fixture-" + "7" * 48
        self.generation = "fixture-generation-1"
        self.bad_identity = bad_identity
        self.requests: list[dict] = []
        self.failures: list[str] = []
        self.ready = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)
        self.thread.start()

    def run(self):
        try:
            with self.socket.makefile("rwb") as stream:
                packet = {"schema": "orbit.plugin.control/v1", "token": self.token,
                          "generation": self.generation, "plugin_id": "wrong" if self.bad_identity else "fixture",
                          "source_digest": DIGEST}
                stream.write(json.dumps(packet).encode() + b"\n")
                stream.flush()
                response = stream.readline(1024 * 1024 + 1)
                if self.bad_identity:
                    if response:
                        self.failures.append("mismatched identity was accepted")
                    self.ready.set()
                    return
                handshake = json.loads(response)
                if handshake != {"schema": "orbit.plugin.control/v1", "ready": True,
                                 "generation": self.generation}:
                    raise AssertionError("incorrect control handshake")
                self.ready.set()
                while True:
                    raw = stream.readline(1024 * 1024 + 1)
                    if not raw:
                        return
                    request = json.loads(raw)
                    params = request["params"]
                    if (request["method"] != "orbit/host.dispatch" or params["token"] != self.token
                            or params["generation"] != self.generation or params["operation"] != "dispatch_tool"
                            or params["remaining_budget_ms"] <= 0):
                        raise AssertionError("incorrect authenticated host request")
                    self.requests.append(request)
                    stream.write(json.dumps({"jsonrpc": "2.0", "id": request["id"],
                                             "result": {"value": json.dumps({"result": "nested read ok"})}}).encode() + b"\n")
                    stream.flush()
        except (Exception, SystemExit) as exc:
            self.failures.append(type(exc).__name__ + ": " + str(exc))
            self.ready.set()

    def close(self):
        try:
            self.socket.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.socket.close()
        self.thread.join(timeout=1)


class BridgeProcess:
    def __init__(self, *, control=False, bad_identity=False, source=FIXTURE):
        self.temporary = tempfile.TemporaryDirectory(prefix="orbit-native-bridge-")
        self.base = Path(self.temporary.name)
        self.root = self.base / "package"
        self.root.mkdir()
        self.data = self.base / "data"
        self.data.mkdir(mode=0o700)
        self.project = self.base / "project"
        self.project.mkdir()
        (self.root / "__init__.py").write_text(source)
        self.original_source = source.encode()
        self.errors = tempfile.TemporaryFile()
        self.host = None
        self.responses = {}
        self.sequence = 0
        self.stdout_raw = bytearray()
        command = [sys.executable, "-I", "-B", str(BRIDGE), "--root", str(self.root),
                   "--data", str(self.data), "--plugin-id", "fixture", "--source-digest", DIGEST]
        child_socket = None
        descriptors = ()
        if control:
            parent_socket, child_socket = socket.socketpair()
            descriptors = (child_socket.fileno(),)
            command += ["--control-fd", str(child_socket.fileno())]
            self.host = HostChannel(parent_socket, bad_identity=bad_identity)
        self.process = subprocess.Popen(command, cwd=self.project,
                                        env={"PATH": os.defpath, "HOME": str(self.base / "initial-home"),
                                             "PYTHONUTF8": "1"},
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                        stderr=self.errors, pass_fds=descriptors, bufsize=0)
        if child_socket is not None:
            child_socket.close()
        self.selector = selectors.DefaultSelector()
        self.selector.register(self.process.stdout, selectors.EVENT_READ)
        if self.host is not None and not self.host.ready.wait(4):
            raise AssertionError("control handshake timed out")

    def send(self, method, params=None, *, notification=False):
        self.sequence += 1
        packet = {"jsonrpc": "2.0", "method": method, "params": {} if params is None else params}
        if not notification:
            packet["id"] = self.sequence
        self.process.stdin.write(json.dumps(packet).encode() + b"\n")
        self.process.stdin.flush()
        return self.sequence

    def receive(self, identity, timeout=5):
        deadline = time.monotonic() + timeout
        while identity not in self.responses:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not self.selector.select(remaining):
                raise AssertionError("bridge response timed out")
            raw = self.process.stdout.readline(1024 * 1024 + 1)
            self.stdout_raw.extend(raw)
            if not raw or len(raw) > 1024 * 1024:
                raise AssertionError("bridge exited or emitted an invalid frame")
            response = json.loads(raw)
            if response.get("jsonrpc") != "2.0":
                raise AssertionError("response is not JSON-RPC")
            self.responses[response.get("id")] = response
        return self.responses.pop(identity)

    def request(self, method, params=None):
        return self.receive(self.send(method, params))

    def result(self, method, params=None):
        response = self.request(method, params)
        if "error" in response:
            raise AssertionError(response["error"])
        return response["result"]

    def describe(self):
        return self.result("orbit/plugin.describe")

    def metadata(self, *, budget=3000, identity="invocation-1"):
        return {"generation": self.describe()["generation"], "invocation_id": identity,
                "remaining_budget_ms": budget}

    def call(self, name, arguments=None, metadata=None):
        params = {"name": name, "arguments": {} if arguments is None else arguments}
        if metadata is not None:
            params["_meta"] = {"orbit": metadata}
        return self.result("tools/call", params)

    def invoke(self, registration, *, args=None, kwargs=None):
        return self.result("orbit/plugin.invoke", {
            **self.metadata(), "registration_id": registration["id"], "kind": registration["kind"],
            "args": [] if args is None else args, "kwargs": {} if kwargs is None else kwargs,
        })

    def diagnostics(self):
        self.errors.seek(0)
        return self.errors.read().decode(errors="replace")

    def close(self):
        try:
            if self.process.poll() is None:
                try:
                    self.request("orbit/plugin.shutdown")
                except (BrokenPipeError, AssertionError, OSError):
                    pass
                try:
                    self.process.stdin.close()
                except OSError:
                    pass
                try:
                    self.process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    self.process.kill()
                    self.process.wait(timeout=3)
            if (self.root / "__init__.py").read_bytes() != self.original_source:
                raise AssertionError("plugin source was modified")
            if list(self.root.rglob("*.pyc")):
                raise AssertionError("plugin activation wrote bytecode into its package")
        finally:
            if self.host is not None:
                self.host.close()
            self.selector.close()
            if not self.process.stdin.closed:
                self.process.stdin.close()
            self.process.stdout.close()
            self.errors.close()
            self.temporary.cleanup()


class NativeBridgeChecks(unittest.TestCase):
    def make_bridge(self, **kwargs):
        process = BridgeProcess(**kwargs)
        self.addCleanup(process.close)
        return process

    def test_initialize_and_original_schema(self):
        bridge = self.make_bridge()
        result = bridge.result("initialize", {"protocolVersion": "2024-11-05"})
        self.assertEqual(result["protocolVersion"], "2024-11-05")
        self.assertEqual(result["capabilities"]["experimental"]["com.orbit.plugin"], {"version": 1})
        tools = bridge.result("tools/list")["tools"]
        self.assertEqual(len(tools), 8)
        self.assertEqual(next(t for t in tools if t["name"] == "counter")["inputSchema"],
                         {"type": "object", "properties": {}})

    def test_stateful_tool_and_persistent_async_loop(self):
        bridge = self.make_bridge()
        first = json.loads(bridge.call("counter")["content"][0]["text"])
        second = json.loads(bridge.call("counter")["content"][0]["text"])
        third = json.loads(bridge.call("async_counter")["content"][0]["text"])
        fourth = json.loads(bridge.call("async_counter")["content"][0]["text"])
        self.assertEqual((first["count"], second["count"], third["count"], fourth["count"]), (1, 2, 3, 4))
        self.assertEqual(first["pid"], second["pid"])
        self.assertEqual(third["loop"], fourth["loop"])

    def test_native_command_preserves_argument_text(self):
        bridge = self.make_bridge()
        command = next(r for r in bridge.describe()["registrations"] if r["kind"] == "command")
        text = "literal $(touch should-not-exist); quoted 'text'"
        self.assertEqual(bridge.invoke(command, args=[text])["value"], "echo: " + text)
        self.assertFalse((bridge.project / "should-not-exist").exists())

    def test_hook_kwargs_and_pre_tool_error_fail_closed(self):
        bridge = self.make_bridge()
        hooks = [r for r in bridge.describe()["registrations"] if r["kind"] == "hook"]
        first = bridge.invoke(hooks[0], kwargs={"tool_name": "write_file", "args": {"block": True},
                                               "future_additive_key": "ignored by narrow signature"})
        self.assertEqual(first["value"], {"action": "block", "message": "fixture refused write_file"})
        self.assertIsNone(bridge.invoke(hooks[0], kwargs={"tool_name": "read_file", "args": {}})["value"])
        self.assertEqual(bridge.invoke(hooks[1], kwargs={})["value"]["action"], "block")

    def test_source_correct_error_helper(self):
        bridge = self.make_bridge()
        result = bridge.call("source_error")
        self.assertTrue(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"]), {"error": "example error", "kind": "fixture"})

    def test_result_helper_data_precedes_keyword_fields(self):
        bridge = self.make_bridge()
        result = bridge.call("helper_semantics")
        self.assertFalse(result["isError"])
        self.assertEqual(json.loads(result["content"][0]["text"]), {
            "positional": {"selected": "positional"}, "named_data": "selected", "empty_data": {},
            "kwargs": {"home": "private", "selected": True}, "null_data": {"selected": True},
        })

    def test_missing_environment_blocks_handler(self):
        bridge = self.make_bridge()
        response = bridge.request("tools/call", {"name": "unavailable", "arguments": {}})
        self.assertIn("ORBIT_BRIDGE_FIXTURE_MISSING", response["error"]["message"])
        self.assertNotIn("unavailable tool executed", response["error"]["message"])

    def test_direct_stdout_isolated_and_home_private(self):
        bridge = self.make_bridge()
        result = json.loads(bridge.call("environment")["content"][0]["text"])
        self.assertEqual(Path(result["home"]), bridge.data / "home")
        self.assertEqual(Path(result["data"]), bridge.data)
        self.assertIn("plugin import diagnostic", bridge.diagnostics())
        self.assertIn("direct descriptor diagnostic", bridge.diagnostics())
        self.assertNotIn(b"diagnostic", bridge.stdout_raw)

    def test_nested_dispatch_requires_control(self):
        bridge = self.make_bridge()
        response = bridge.request("tools/call", {"name": "nested", "arguments": {}})
        self.assertIn("authenticated control channel", response["error"]["message"])

    def test_authenticated_nested_dispatch_preserves_identity(self):
        bridge = self.make_bridge(control=True)
        result = bridge.call("nested", {"arguments": {"path": "demo.txt"}}, bridge.metadata())
        self.assertEqual(json.loads(result["content"][0]["text"]), {"result": "nested read ok"})
        self.assertEqual(len(bridge.host.requests), 1)
        params = bridge.host.requests[0]["params"]
        self.assertEqual(params["invocation_id"], "invocation-1")
        self.assertEqual(params["arguments"], {"path": "demo.txt"})
        self.assertEqual(bridge.host.failures, [])
        self.assertNotIn(bridge.host.token.encode(), bridge.stdout_raw)
        self.assertNotIn(bridge.host.token, bridge.diagnostics())

    def test_control_without_active_host_metadata_rejects_nested_call(self):
        bridge = self.make_bridge(control=True)
        response = bridge.request("tools/call", {"name": "nested", "arguments": {}})
        self.assertIn("host invocation metadata", response["error"]["message"])
        self.assertEqual(bridge.host.requests, [])

    def test_forged_generation_rejected_before_callback(self):
        bridge = self.make_bridge(control=True)
        metadata = {**bridge.metadata(), "generation": "wrong"}
        response = bridge.request("tools/call", {"name": "counter", "arguments": {}, "_meta": {"orbit": metadata}})
        self.assertEqual(response["error"]["code"], -32602)
        self.assertEqual(json.loads(bridge.call("counter")["content"][0]["text"])["count"], 1)

    def test_control_handshake_rejects_wrong_plugin(self):
        bridge = self.make_bridge(control=True, bad_identity=True)
        self.assertEqual(bridge.process.wait(timeout=3), 78)
        self.assertIn("identity mismatch", bridge.diagnostics())
        self.assertNotIn(bridge.host.token, bridge.diagnostics())

    def test_async_deadline_is_bounded(self):
        bridge = self.make_bridge()
        started = time.monotonic()
        response = bridge.request("tools/call", {"name": "slow", "arguments": {},
                                  "_meta": {"orbit": bridge.metadata(budget=20)}})
        self.assertEqual(response["error"]["code"], -32800)
        self.assertLess(time.monotonic() - started, 2)

    def test_cancelled_call_and_occupied_runtime(self):
        bridge = self.make_bridge()
        slow = bridge.send("tools/call", {"name": "slow", "arguments": {}})
        busy = bridge.request("tools/call", {"name": "counter", "arguments": {}})
        self.assertEqual(busy["error"]["code"], -32002)
        bridge.send("notifications/cancelled", {"requestId": slow}, notification=True)
        self.assertEqual(bridge.receive(slow)["error"]["code"], -32800)
        self.assertEqual(len(bridge.result("tools/list")["tools"]), 8)

    def test_unknown_registration_and_method_rejected(self):
        bridge = self.make_bridge()
        response = bridge.request("orbit/plugin.invoke", {**bridge.metadata(), "kind": "hook",
                                  "registration_id": "hook:9999", "kwargs": {}})
        self.assertEqual(response["error"]["code"], -32602)
        self.assertEqual(bridge.request("orbit/plugin.unknown")["error"]["code"], -32601)

    def test_unsupported_host_api_has_concrete_error(self):
        bridge = self.make_bridge(source="def register(ctx):\n    ctx.register_unsupported_provider(object())\n")
        self.assertEqual(bridge.process.wait(timeout=3), 78)
        self.assertIn("register_unsupported_provider", bridge.diagnostics())
        self.assertIn("concrete port adapter", bridge.diagnostics())

    def test_invalid_json_is_bounded_and_process_exits(self):
        bridge = self.make_bridge()
        bridge.process.stdin.write(b"{invalid-json}\n")
        bridge.process.stdin.flush()
        response = bridge.receive(None)
        self.assertEqual(response["error"]["code"], -32700)
        self.assertEqual(bridge.process.wait(timeout=3), 0)


def main():
    global BRIDGE
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bridge", type=Path, default=BRIDGE)
    parser.add_argument("--case", help="Run a named boundary check")
    options = parser.parse_args()
    BRIDGE = options.bridge.resolve(strict=True)
    loader = unittest.TestLoader()
    suite = (loader.loadTestsFromName(options.case, NativeBridgeChecks) if options.case
             else loader.loadTestsFromTestCase(NativeBridgeChecks))
    if suite.countTestCases() == 0:
        parser.error("no bridge checks selected")
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    print(json.dumps({"checks": result.testsRun, "failures": len(result.failures),
                      "errors": len(result.errors), "passed": result.wasSuccessful(),
                      "coverage": "synthetic stdio/control boundaries; no real-plugin claim"}))
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    raise SystemExit(main())
