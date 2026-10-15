#!/usr/bin/env python3
"""Drive ORBIT's browser MCP workflow against local captured fixtures.

Run through scripts/in-jail.sh. Synthetic receipts prove dispatch and policy;
they do not establish native browser rendering or external server compatibility.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import threading
import time


TOOLS = ["browser_navigate", "browser_snapshot", "browser_click", "browser_close"]
SAMPLE_SECRET = "abcdefghijklmnopqrstuvwxyz"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="target/debug/orbit")
    parser.add_argument("--real-config", type=Path,
                        help="optional existing-executable mcp.json with one server and the four exact browser tools")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve(strict=True))
    fixtures = Path(__file__).resolve().parent / "fixtures"
    scenarios = {}

    def checked(name, *conditions):
        assert conditions and all(conditions), name
        scenarios[name] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + name, flush=True)

    def run_case(root, name, policy, steps, server_name="browser", neighbor=False,
                 real_config=None):
        case = root / name
        case.mkdir(mode=0o700)
        home, work = case / "home", case / "workspace"
        work.mkdir(mode=0o700)
        page = case / "page.html"
        shutil.copyfile(fixtures / "p35_browser.html", page)
        requests = []
        errors = []

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    assert 0 < size <= 4 * 1024 * 1024
                    body = json.loads(self.rfile.read(size))
                    requests.append(body)
                    messages = body.get("messages", [])
                    results = [m for m in messages if m.get("role") == "tool"]
                    index = len(results)
                    if index < len(steps):
                        tool, inputs = steps[index]
                        inputs = dict(inputs)
                        if tool == "browser_navigate":
                            inputs["url"] = page.as_uri()
                        if real_config and tool == "browser_click":
                            snapshot = json.loads(results[-1]["content"])["result"]
                            match = re.search(r'button[^\n]*Increment[^\n]*\[ref=([^\]]+)\]', snapshot)
                            assert match, "real snapshot did not expose Increment button reference"
                            advertised = next(item["function"] for item in body["tools"]
                                              if item["function"]["name"] == f"mcp__{server_name}__{tool}")
                            properties = advertised["parameters"]["properties"]
                            reference_key = "target" if "target" in properties else "ref"
                            assert reference_key in properties, "browser click schema has no supported reference field"
                            inputs.pop("ref", None)
                            inputs[reference_key] = match[1]
                        delta = {"tool_calls": [{"index": 0, "id": f"browser-{index}",
                                 "type": "function", "function": {
                                     "name": f"mcp__{server_name}__{tool}",
                                     "arguments": json.dumps(inputs)}}]}
                        finish = "tool_calls"
                    else:
                        delta, finish = {"content": "Local browser workflow finished."}, "stop"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/event-stream")
                    self.end_headers()
                    event = {"choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}
                    self.wfile.write(("data: " + json.dumps(event) + "\n\ndata: [DONE]\n\n").encode())
                    self.wfile.flush()
                except Exception as error:
                    errors.append(repr(error))
                    self.close_connection = True

            def log_message(self, *_args):
                pass

        provider = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        thread = threading.Thread(target=provider.serve_forever, daemon=True)
        thread.start()
        env = os.environ.copy()
        for key in list(env):
            if key.startswith("ORBIT_"):
                env.pop(key)
        env.update(ORBIT_HOME=str(home), ORBIT_GATE_TOKEN="local_browser_fixture_auth")
        gate = f"http://127.0.0.1:{provider.server_port}"
        env["ORBIT_GATE_URL"] = gate
        try:
            initialized = subprocess.run([binary, "init", "--home", str(home), "--no-provider"],
                                         cwd=work, env=env, capture_output=True, text=True, timeout=15)
            assert initialized.returncode == 0, initialized.stderr
            (home / "providers.toml").write_text(
                '[[provider]]\nname="local"\n'
                f'url="{gate}"\nenv="ORBIT_GATE_TOKEN"\n'
                '[[provider.models]]\nid="fixture-model"\n', encoding="utf-8")

            def server_config(suffix=""):
                return {"command": "python3", "args": [str(fixtures / "p35_browser_mcp.py"),
                        "--log", str(case / ("calls" + suffix + ".jsonl")),
                        "--state", str(case / ("state" + suffix + ".json")),
                        "--page", str(page)], "tools": TOOLS,
                        "timeout_ms": 1500, "initialize_timeout_ms": 1500}

            config = real_config or {"servers": {server_name: server_config()}}
            if real_config:
                entry = config["servers"][server_name]
                isolated_env = {}
                for key in ["HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME", "TMPDIR"]:
                    directory = case / ("browser-" + key.lower())
                    directory.mkdir(mode=0o700)
                    isolated_env[key] = str(directory)
                entry["env"] = {**entry.get("env", {}), **isolated_env}
            if neighbor:
                config["servers"]["browser"] = server_config("-neighbor")
            (home / "mcp.json").write_text(json.dumps(config), encoding="utf-8")
            (home / "settings.toml").write_text("[permissions]\n" + policy, encoding="utf-8")
            result = subprocess.run(
                [binary, "-p", "Exercise only the configured local browser workflow.",
                 "--home", str(home), "--model", "fixture-model", "--provider", "local",
                 "--gate", gate, "--auto-tools",
                 "--max-turns", "12", "--output-format", "stream-json"],
                cwd=work, env=env, input="", capture_output=True, text=True, timeout=45)
            assert not errors, errors
            assert result.returncode in [0, 2], (name, result.returncode, result.stdout, result.stderr)
            assert len(requests) == len(steps) + 1, (name, requests, result.stdout, result.stderr)
            captures = case / "calls.jsonl"
            events = [json.loads(line) for line in captures.read_text().splitlines()] if captures.exists() else []
            calls = [event for event in events if event.get("method") == "tools/call"]
            results = [json.loads(m["content"]) for m in requests[-1]["messages"]
                       if m.get("role") == "tool"]
            assert len(results) == len(steps), (name, results)
            state_path = case / "state.json"
            state = json.loads(state_path.read_text()) if state_path.exists() else None
            # EOF exits the configured process after the CLI exits. Namespace
            # PID 1 may own its final reap; a zombie has no executable work or
            # descriptors. Require the fixture's exit marker as well.
            if state and not real_config:
                deadline = time.monotonic() + 3
                while True:
                    try:
                        if os.waitpid(state["pid"], os.WNOHANG)[0]:
                            break
                    except ChildProcessError:
                        pass
                    try:
                        os.kill(state["pid"], 0)
                    except ProcessLookupError:
                        break
                    status_path = Path(f"/proc/{state['pid']}/status")
                    try:
                        status = status_path.read_text()
                    except FileNotFoundError:
                        break
                    if any(line.startswith("State:") and "Z (zombie)" in line
                           for line in status.splitlines()):
                        break
                    if time.monotonic() >= deadline:
                        raise AssertionError("browser fixture child remained active after CLI exit")
                    time.sleep(0.025)
                state = json.loads(state_path.read_text())
                assert state.get("process_exited") is True, state
            return calls, results, state, requests
        finally:
            provider.shutdown()
            provider.server_close()
            thread.join(timeout=2)

    with tempfile.TemporaryDirectory(prefix="orbit-browser-cli-") as tmp:
        root = Path(tmp)
        workflow = [("browser_navigate", {}), ("browser_snapshot", {}),
                    ("browser_click", {"ref": "increment", "element": "Increment button"}), ("browser_snapshot", {}),
                    ("browser_close", {})]
        calls, results, state, requests = run_case(root, "workflow", 'allow=["mcp__browser__*"]\n', workflow)
        checked("navigation_snapshot_action_close", [c["params"]["name"] for c in calls] ==
                [step[0] for step in workflow], all(r.get("ok") is True for r in results),
                "Count: 1" in results[3]["result"], state["counter"] == 1,
                state["closed"] is True, state["url"] is None)
        checked("untrusted_snapshot_is_scanned", "Untrusted page text" in results[1]["result"],
                SAMPLE_SECRET not in json.dumps(results), results[1]["redactions"] >= 2,
                SAMPLE_SECRET not in json.dumps(requests))
        exposed = {t["function"]["name"] for t in requests[0].get("tools", [])
                   if t["function"]["name"].startswith("mcp__")}
        checked("exact_browser_catalog", exposed == {f"mcp__browser__{tool}" for tool in TOOLS})

        calls, results, _, _ = run_case(root, "hidden", 'allow=["mcp__browser__*"]\n', [("browser_evaluate", {})])
        checked("hidden_tool_is_refused", calls == [], results[0]["ok"] is False)
        calls, results, _, _ = run_case(root, "ask", 'ask=["mcp__browser__*"]\n', [("browser_navigate", {})])
        checked("explicit_ask_beats_headless_auto_tools", calls == [], results[0]["ok"] is False)
        calls, results, _, _ = run_case(root, "deny", 'deny=["mcp__browser__*"]\n', [("browser_navigate", {})])
        checked("deny_prevents_browser_call", calls == [], results[0]["ok"] is False)
        calls, results, _, _ = run_case(root, "broader-ask",
                'ask=["mcp__browser__*"]\nallow=["mcp__browser__browser_navigate"]\n',
                [("browser_navigate", {})])
        checked("exact_allow_preserves_broader_ask", calls == [], results[0]["ok"] is False)
        calls, results, _, _ = run_case(root, "separator-neighbor",
                'deny=["mcp__browser__*"]\nallow=["mcp__browser__local__*"]\n',
                [("browser_navigate", {})], server_name="browser__local", neighbor=True)
        checked("separator_neighbor_permission_isolation", len(calls) == 1,
                calls[0]["params"]["name"] == "browser_navigate", results[0]["ok"] is True)

        browsers = [name for name in ["chromium", "chromium-browser", "google-chrome", "firefox"]
                    if shutil.which(name)]
        servers = [name for name in ["playwright-mcp", "mcp-server-playwright"] if shutil.which(name)]
        if args.real_config:
            config = json.loads(args.real_config.read_text())
            assert set(config) == {"servers"} and len(config["servers"]) == 1
            server, entry = next(iter(config["servers"].items()))
            assert set(entry.get("tools", [])) == set(TOOLS), "real probe requires exact four-tool exposure"
            command = entry["command"]
            assert Path(command).name not in ["npx", "bunx", "uvx"], "automatic package runners are excluded"
            assert shutil.which(command), "configured real server executable is unavailable"
            calls, results, _, _ = run_case(root, "real-server", f'allow=[{json.dumps("mcp__" + server + "__*")}]\n',
                                           workflow, server_name=server, real_config=config)
            assert all(result.get("ok") is True for result in results), results
            assert "Count: 1" in results[3]["result"], ("native page action did not update the DOM", results)
            assert SAMPLE_SECRET not in json.dumps(results), "real browser output was not scanned"
            checked("existing_native_browser_mcp_workflow", len(results) == len(workflow),
                    all(result.get("ok") is True for result in results),
                    "Count: 1" in results[3]["result"],
                    SAMPLE_SECRET not in json.dumps(results), results[1]["redactions"] >= 2)
            print("REAL_BROWSER_COMPATIBILITY " + json.dumps({"status": "passed", "server": server,
                  "executable": Path(command).name, "operations": [step[0] for step in workflow],
                  "version": None, "version_observation": "not exposed by the public dispatch result",
                  "coverage": "configured executable and local page only"}), flush=True)
        else:
            print("REAL_BROWSER_COMPATIBILITY " + json.dumps({"status": "unavailable",
                  "reason": "no operator-configured existing real-server configuration supplied",
                  "existing_browser_executables": browsers, "existing_server_executables": servers,
                  "synthetic_results_establish_real_compatibility": False}), flush=True)
        print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}), flush=True)


if __name__ == "__main__":
    main()
