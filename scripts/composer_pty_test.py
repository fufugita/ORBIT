#!/usr/bin/env python3
"""Exercise draft-only file completion and history search in the real terminal UI.

Run through scripts/in-jail.sh when testing a desktop checkout. The provider
fixture counts requests: choosing a suggestion must never dispatch a turn.
"""

import argparse
from contextlib import ExitStack
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
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

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            requests.append(self.path)
            self.send_response(418)
            self.end_headers()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    session = None
    checks = 0
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-composer-pty-") as tmp, ExitStack() as cleanup:
            root = Path(tmp)
            home, workspace = root / "home", root / "workspace"
            workspace.mkdir()
            (workspace / "visible.rs").write_text("pub fn visible() {}\n")
            (workspace / "ignored.rs").write_text("ignored\n")
            (workspace / ".gitignore").write_text("ignored.rs\n")
            (workspace / ".env").write_text("fixture only\n")
            (workspace / "space dir").mkdir()
            (workspace / "space dir" / "nested file.txt").write_text("nested\n")
            subprocess.run(
                [binary, "init", "--home", str(home), "--no-provider"],
                cwd=workspace, check=True, capture_output=True, timeout=30,
            )
            gate = f"http://127.0.0.1:{server.server_port}"
            (home / "providers.toml").write_text(
                f'[[provider]]\nname = "fixture"\nurl = "{gate}"\n'
                'env = "ORBIT_GATE_TOKEN"\n[[provider.models]]\nid = "fixture"\n'
            )
            saved = home / "sessions"
            saved.mkdir(exist_ok=True, mode=0o700)
            sid = "composer-fixture"
            (saved / f"{sid}.json").write_text(json.dumps({
                "schema": "orbit.session/v1", "session_id": sid,
                "model": "fixture", "gate": gate, "provider": "fixture",
                "transcript": [], "turns": 0, "input_tokens": 0,
                "output_tokens": 0, "cost_microcents": 0,
                "updated_at": "2026-01-01T00:00:00Z",
            }))
            (saved / f"{sid}.json").chmod(0o600)
            history_entries = [
                "alpha newest request", "older alpha request", "separate beta request",
                '["first","second"]', "[]",
            ]
            (saved / f"{sid}.history").write_text("\n".join(history_entries) + "\n")
            session = PtySession(
                [binary, "--home", str(home), "--model", "fixture", "--resume", sid],
                env={"ORBIT_GATE_TOKEN": "fixture", "ORBIT_HOME": str(home)},
                cwd=workspace, rows=32, cols=120,
            )
            cleanup.callback(session.terminate)

            def expect(label, predicate):
                nonlocal checks
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    session.read(0.15)
                    if predicate(session.screen_text()):
                        checks += 1
                        print(f"PASS {label}", flush=True)
                        return
                raise AssertionError(f"{label}\n{session.screen_text()}")

            def draft_only(label):
                nonlocal checks
                session.read(0.5)
                assert not requests, f"{label} dispatched {requests}"
                assert session.proc.poll() is None, f"{label} exited the UI"
                checks += 1
                print(f"PASS {label} stays in the draft", flush=True)

            def clear_draft():
                session.write(b"\x7f" * 80)
                session.read(0.3)

            def picker_open(screen):
                # The Changes placeholder also says "Files ORBIT edits".
                # Match the popup header, not that unrelated sentence.
                return bool(re.search(r"[┃│]\s+Files(?:\s{2,}|[┃│])", screen))

            expect("terminal UI boots", lambda screen: "ORBIT" in screen)
            session.type("@vis")
            expect("file picker lists matching file", lambda screen: picker_open(screen) and "visible.rs" in screen)
            session.key("tab")
            expect("Tab inserts the file mention", lambda screen: '@"visible.rs"' in screen and not picker_open(screen))
            draft_only("file Tab acceptance")
            clear_draft()
            session.type("@vis")
            expect("file picker reopens", lambda screen: picker_open(screen))
            session.key("enter")
            expect("Enter inserts without sending", lambda screen: '@"visible.rs"' in screen and not picker_open(screen))
            draft_only("file Enter acceptance")
            clear_draft()
            session.type("@"); session.read(0.3)
            expect("ignored and sensitive paths are hidden", lambda screen: picker_open(screen) and "ignored.rs" not in screen and ".env" not in screen)
            session.key("esc")
            expect("Escape closes only the picker", lambda screen: not picker_open(screen))
            clear_draft()
            session.type('@"space')
            expect("quoted directory appears", lambda screen: picker_open(screen) and "space dir" in screen)
            session.key("tab")
            expect("directory selection continues completion", lambda screen: picker_open(screen) and "nested file.txt" in screen)
            session.key("tab")
            expect("quoted nested path inserts", lambda screen: '@"space dir/nested file.txt"' in screen and not picker_open(screen))
            draft_only("nested file acceptance")
            clear_draft()
            session.type("unsent draft")
            session.write(b"\x12")  # Ctrl-R starts reverse search.
            session.type("alpha")
            expect("history searches newest matching entry", lambda screen: "History search: alpha" in screen and "alpha newest request" in screen)
            session.write(b"\x12")
            expect("Ctrl-R cycles older matching entry", lambda screen: "older alpha request" in screen)
            session.key("esc")
            expect("history cancel restores original draft", lambda screen: "History search:" not in screen and "unsent draft" in screen)
            draft_only("history cancellation")
            session.write(b"\x12"); session.type("beta")
            expect("history search finds another query", lambda screen: "separate beta request" in screen)
            session.key("enter")
            expect("history Enter accepts the draft", lambda screen: "History search:" not in screen and "separate beta request" in screen)
            draft_only("history Enter acceptance")
            session.write(b"\x12"); session.type("not-in-history")
            expect("unmatched history query is visible", lambda screen: "no match" in screen)
            session.key("esc")
            expect("unmatched search cancels before a new search", lambda screen: "History search:" not in screen and "separate beta request" in screen)
            session.write(b"\x12"); session.type("first")
            expect("legacy JSON prompt stays a single draft", lambda screen: '["first","second"]' in screen)
            session.key("enter")
            draft_only("legacy JSON history acceptance")
            cleanup.close()
            persisted = json.loads((saved / f"{sid}.history").read_text())
            assert persisted["schema"] == "orbit.composer-history/v1"
            assert persisted["entries"] == history_entries
            checks += 1
            print("PASS legacy history migrates to a tagged file without changing prompts", flush=True)
            print(f"Results: {checks} passed", flush=True)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
