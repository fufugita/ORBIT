#!/usr/bin/env python3
"""Check effort controls and saved selections against a local request fixture.

Run through scripts/in-jail.sh. No production provider is contacted.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import time

from pty_tui_test import PtySession, pyte


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if pyte is None:
        raise SystemExit("pyte is required for exact terminal screen assertions")
    requests = []
    checks = 0

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            requests.append(body)
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            events = [
                {"choices": [{"index": 0, "delta": {"content": "effort fixture reply"}, "finish_reason": None}]},
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 2, "completion_tokens": 3}},
            ]
            for event in events:
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = None
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-effort-pty-") as tmp:
            root = Path(tmp)
            home, workspace = root / "home", root / "workspace"
            workspace.mkdir()
            subprocess.run([binary, "init", "--home", str(home), "--no-provider"], cwd=workspace, check=True, capture_output=True, timeout=30)
            gate = f"http://127.0.0.1:{server.server_port}"
            long_effort = "effort_" + "x" * 53 + "_END"
            unicode_effort = "界" * 16
            choices = json.dumps(["low", "high", "false", long_effort, unicode_effort], ensure_ascii=False)
            (home / "providers.toml").write_text(
                f'[[provider]]\nname = "fixture"\nurl = "{gate}"\nenv = "ORBIT_GATE_TOKEN"\n'
                f'[[provider.models]]\nid = "a"\nsupported_efforts = {choices}\ndefault_effort = "low"\n'
                '[[provider.models]]\nid = "b"\nsupported_efforts = ["medium"]\ndefault_effort = "medium"\n'
                '[[provider.models]]\nid = "unknown"\n'
                '[[provider.models]]\nid = "vendor/reasoner"\nsupported_efforts = ["low"]\ndefault_effort = "low"\n'
                f'[[provider]]\nname = "other"\nurl = "{gate}"\nenv = "ORBIT_GATE_TOKEN"\n'
                '[[provider.models]]\nid = "a"\nsupported_efforts = ["medium"]\ndefault_effort = "medium"\n'
                '[roles]\nmain = "fixture/vendor/reasoner"\ncompaction = "fixture/b"\n'
            )
            saved = home / "sessions"
            saved.mkdir(exist_ok=True, mode=0o700)
            sid = "effort-fixture"
            path = saved / f"{sid}.json"
            path.write_text(json.dumps({
                "schema": "orbit.session/v1", "session_id": sid,
                "model": "a", "gate": gate, "provider": "fixture",
                "effort": {"mode": "value", "value": "high"},
                "transcript": [], "turns": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_microcents": 0,
                "updated_at": "2026-01-01T00:00:00Z",
            }))
            path.chmod(0o600)
            env = {"ORBIT_GATE_TOKEN": "fixture", "ORBIT_HOME": str(home), "ORBIT_EFFORT": "high"}

            def check(label, predicate):
                nonlocal checks
                deadline = time.monotonic() + 8
                while time.monotonic() < deadline:
                    if session:
                        session.read(0.15)
                    if predicate():
                        checks += 1
                        print(f"PASS {label}", flush=True)
                        return
                summary = [{"model": r.get("model"), "effort": r.get("reasoning_effort")} for r in requests]
                raise AssertionError(f"{label}\n{session.screen_text() if session else ''}\nrequest controls: {summary}")

            def screen_has(text):
                return text in session.screen_text()

            def configured(model, effort):
                return screen_has(f"Configured effort for fixture/{model}: {json.dumps(effort, ensure_ascii=False)}")

            def command(text):
                session.type(text)
                session.key("enter")
                session.read(0.35)

            def turn(label, model, effort):
                count = len(requests)
                command(label)
                check(label + " reaches the selected request field", lambda: len(requests) == count + 1 and requests[-1].get("model") == model and requests[-1].get("reasoning_effort") == effort)
                check(label + " finishes", lambda: screen_has("effort fixture reply"))
                session.read(0.5)

            session = PtySession([binary, "--effort", "default", "--home", str(home), "--model", "fixture/a", "--resume", sid], env=env, cwd=workspace, rows=40, cols=160)
            check("terminal boots with effort flag before the other flags", lambda: screen_has("ORBIT"))
            command("/effort")
            check("startup reset beats saved and environment values", lambda: configured("a", "low"))
            check("query sends no provider request", lambda: not requests)
            check("64-byte choice and Unicode choices stay visible in the 60-cell pane", lambda: screen_has("effort_") and screen_has("_END") and screen_has(unicode_effort))
            session.type("/eff")
            check("effort appears in completion", lambda: screen_has("/effort") and screen_has("request effort"))
            session.key("esc")
            session.write(b"\x7f" * 20)
            session.read(0.3)
            command('/effort "false"')
            check("quoted boolean-like level remains a named choice", lambda: configured("a", "false") and json.loads(path.read_text()).get("effort") == {"mode": "value", "value": "false"})
            command("/effort false")
            check("boolean type is rejected without coercing the named level", lambda: not requests and json.loads(path.read_text()).get("effort") == {"mode": "value", "value": "false"})
            check("type rejection explains the required request type", lambda: screen_has("Effort unchanged:") and screen_has("reasoning_effort") and screen_has("requires a") and screen_has("named level"))
            check("idle type rejection creates no failed-turn or resend notice", lambda: not screen_has("This turn failed") and not screen_has("resends it"))
            turn("typed level fixture prompt", "a", "false")
            command("/effort high")
            check("explicit effort is visible", lambda: configured("a", "high"))
            check("setting sends no extra provider request", lambda: len(requests) == 1)
            turn("first fixture prompt", "a", "high")
            count = len(requests)
            command("/compact")
            check("manual compaction uses its role model and default", lambda: len(requests) == count + 1 and requests[-1].get("model") == "b" and requests[-1].get("reasoning_effort") == "medium")
            check("manual compaction preserves the session choice", lambda: json.loads(path.read_text()).get("effort") == {"mode": "value", "value": "high"} and "context compacted" in json.loads(path.read_text())["transcript"][0]["content"])
            command("/model b")
            check("incompatible model switch is rejected", lambda: screen_has("Model unchanged:"))
            check("rejected switch preserves saved model and effort", lambda: json.loads(path.read_text()).get("model") == "a" and json.loads(path.read_text()).get("effort") == {"mode": "value", "value": "high"})
            check("rejected switch explains the incompatibility and reset", lambda: screen_has("not supported by model b") and screen_has("Use /effort default before switching."))
            check("idle model rejection creates no failed-turn or resend notice", lambda: not screen_has("This turn failed") and not screen_has("resends it"))
            command("/effort default")
            command("/model b")
            command("/effort")
            check("reset then model switch uses the new model default", lambda: configured("b", "medium"))
            turn("second fixture prompt", "b", "medium")
            command("/effort unsupported")
            check("invalid effort preserves the active selection", lambda: screen_has("Effort unchanged:") and json.loads(path.read_text()).get("effort") == {"mode": "default"})
            check("unsupported effort reason stays visible without a failed-turn notice", lambda: screen_has("effort unsupported is not supported by model b") and not screen_has("This turn failed") and not screen_has("resends it"))
            command("/model unknown")
            command("/effort")
            check("unknown capabilities are explained", lambda: screen_has("Supported: unknown.") and screen_has("Declare supported_efforts"))
            command("/effort high")
            check("unknown explicit selection is rejected without a request", lambda: len(requests) == 4 and json.loads(path.read_text()).get("effort") == {"mode": "default"})
            turn("omitted fixture prompt", "unknown", None)
            # Restore a separately saved explicit selection and prove it reaches
            # the provider after hot resume, rather than borrowing live defaults.
            restore_id = "effort-restore"
            restored = json.loads(path.read_text())
            restored.update(session_id=restore_id, model="a", effort={"mode": "value", "value": "high"})
            restore_path = saved / f"{restore_id}.json"
            restore_path.write_text(json.dumps(restored))
            restore_path.chmod(0o600)
            command(f"/resume {restore_id}")
            command("/effort")
            check("hot resume restores model and explicit effort together", lambda: configured("a", "high"))
            turn("resumed fixture prompt", "a", "high")
            command("/effort default")
            check("explicit reset persists independently of wire value", lambda: json.loads(restore_path.read_text()).get("effort") == {"mode": "default"})
            session.terminate()
            session = None
            # Headless startup exercises flag/env/saved precedence and positional
            # parsing without relying on the screen's prior transcript notices.
            result = subprocess.run([binary, "--effort", "default", "-p", "headless effort fixture", "--home", str(home), "--model", "fixture/a", "--resume", restore_id], env={**os.environ, **env}, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("headless leading flag uses the prompt and reset", lambda: result.returncode == 0 and requests[-1].get("reasoning_effort") == "low" and any(m.get("content") == "headless effort fixture" for m in requests[-1].get("messages", [])))
            count = len(requests)
            bad = subprocess.run([binary, "-p", "invalid effort fixture", "--home", str(home), "--model", "b", "--effort", "high"], env={**os.environ, **env}, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("invalid startup fails before provider dispatch", lambda: bad.returncode != 0 and len(requests) == count and "not supported" in bad.stderr)
            clean_env = {k: v for k, v in os.environ.items() if k not in ("ORBIT_EFFORT", "ORBIT_MODEL", "ORBIT_ACTIVE_MODEL")}
            clean_env.update(ORBIT_GATE_TOKEN="fixture", ORBIT_HOME=str(home))
            result = subprocess.run([binary, "-p", "- inspect this module", "--home", str(home), "--model", "fixture/a", "--effort", "default"], env=clean_env, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("dash-leading prompt is preserved", lambda: result.returncode == 0 and any(m.get("content") == "- inspect this module" for m in requests[-1].get("messages", [])))
            result = subprocess.run([binary, "-p", "--effort", "--home", str(home), "--model", "fixture/a"], env=clean_env, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("prompt resembling a flag is not interpreted as an option", lambda: result.returncode == 0 and requests[-1].get("reasoning_effort") == "low" and any(m.get("content") == "--effort" for m in requests[-1].get("messages", [])))
            restored.update(effort={"mode": "value", "value": "high"})
            restore_path.write_text(json.dumps(restored))
            restore_path.chmod(0o600)
            result = subprocess.run([binary, "-p", "duplicate owner fixture", "--home", str(home), "--provider", "other", "--model", "a", "--resume", restore_id], env=clean_env, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("startup provider change drops another owner's saved effort", lambda: result.returncode == 0 and requests[-1].get("reasoning_effort") == "medium" and json.loads(restore_path.read_text()).get("provider") == "other" and "effort" not in json.loads(restore_path.read_text()))
            restored.update(session_id="owned-resume", provider="other", effort={"mode": "value", "value": "medium"})
            (saved / "owned-resume.json").write_text(json.dumps(restored))
            (saved / "owned-resume.json").chmod(0o600)
            result = subprocess.run([binary, "--no-tui", "--home", str(home), "--model", "a", "--provider", "fixture"], input="/resume owned-resume\nplain owned resume fixture\nexit\n", env=clean_env, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("plain hot resume retains the saved provider's effort", lambda: result.returncode == 0 and requests[-1].get("reasoning_effort") == "medium" and json.loads((saved / "owned-resume.json").read_text()).get("provider") == "other")
            result = subprocess.run([binary, "--no-tui", "--home", str(home)], input="slash model fixture\nexit\n", env=clean_env, cwd=workspace, capture_output=True, text=True, timeout=30)
            check("default role startup preserves slash-containing model ID", lambda: result.returncode == 0 and requests[-1].get("model") == "vendor/reasoner" and requests[-1].get("reasoning_effort") == "low")
            print(f"Results: {checks} passed", flush=True)
    finally:
        if session:
            session.terminate()
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
