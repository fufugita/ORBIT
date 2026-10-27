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
import unicodedata
from wcwidth import wcswidth

from pty_tui_test import PtySession, pyte


def visible_screen_text(screen):
    """Render pyte cells without assuming every blank is a wide-cell stub."""
    if screen is None:
        return ""
    lines = []
    for y in range(screen.lines):
        row = screen.buffer[y]
        visible = []
        skip_stub = False
        for x in range(screen.columns):
            if skip_stub:
                skip_stub = False
                continue
            cell = row[x].data
            if not cell:
                visible.append(" ")
                continue
            visible.append(cell)
            skip_stub = wcswidth(cell) == 2
        lines.append("".join(visible).rstrip())
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if pyte is None:
        raise SystemExit("pyte is required for exact terminal screen assertions")
    unicode_screen = pyte.Screen(12, 1)
    pyte.ByteStream(unicode_screen).feed("界🇧🇷".encode("utf-8"))
    assert visible_screen_text(unicode_screen).strip() == "界🇧🇷"

    requests = []
    hold_next_response = [False]
    response_gate = threading.Event()
    response_gate.set()
    response_started = threading.Event()
    response_finished = threading.Event()
    assistant_reply = "Unicode: e\u0301 界 🇧🇷 ☀️ 👨‍👩‍👧‍👦\n| item | value |\n|---|---|\n| ready | yes |"

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            raw_body = self.rfile.read(length)
            try:
                body = json.loads(raw_body)
            except (UnicodeDecodeError, json.JSONDecodeError):
                body = {"_raw": raw_body.decode("utf-8", errors="replace")}
            requests.append({"path": self.path, "body": body})
            held = hold_next_response[0]
            hold_next_response[0] = False
            response_started.set()
            if held and not response_gate.wait(timeout=15):
                response_finished.set()
                self.send_error(504, "synthetic response gate timed out")
                return
            events = [
                {"choices": [{"index": 0, "delta": {"content": assistant_reply}, "finish_reason": None}]},
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 2, "completion_tokens": 12}},
            ]
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                for event in events:
                    self.wfile.write(("data: " + json.dumps(event, ensure_ascii=False) + "\n\n").encode())
                self.wfile.write(b"data: [DONE]\n\n")
                self.wfile.flush()
            finally:
                response_finished.set()

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
                [binary, "chat", "--home", str(home), "--model", "fixture",
                 "--resume", sid, "--adopt-workspace"],
                # Exercise the TUI's Unicode canvas past the bridge's
                # intentional default emoji-to-ASCII compatibility mapping.
                env={
                    "ORBIT_GATE_TOKEN": "fixture",
                    "ORBIT_HOME": str(home),
                    "ORBIT_ASCII_EMOJI": "0",
                },
                cwd=workspace, rows=32, cols=120,
            )
            # pyte's Screen.display indexes empty cells before checking for a
            # wide-cell stub; flags can leave independent empty continuation
            # cells. Keep cell bounds, but render those cells as blanks here.
            session.screen_text = lambda: visible_screen_text(session.screen)
            cleanup.callback(session.terminate)
            # Release any held request before terminating the TUI if an
            # assertion fails while the event barrier is active.
            cleanup.callback(response_gate.set)

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
                assert not requests, f"{label} unexpectedly dispatched {len(requests)} provider request(s)"
                assert session.proc.poll() is None, (
                    f"{label} exited the UI (status {session.proc.returncode})\n"
                    f"{session.screen_text()}"
                )
                checks += 1
                print(f"PASS {label} stays in the draft", flush=True)

            def clear_draft():
                # Deletion is cursor-relative. Tests deliberately leave the
                # caret in the middle, so move it to the logical-line end first.
                session.key("end")
                session.write(b"\x7f" * 80)
                session.read(0.3)

            def picker_open(screen):
                # The Changes placeholder also says "Files ORBIT edits".
                # Match the popup header, not that unrelated sentence.
                return bool(re.search(r"[┃│]\s+Files(?:\s{2,}|[┃│])", screen))

            def user_texts(value):
                found = []
                if isinstance(value, dict):
                    if value.get("role") == "user":
                        content = value.get("content")
                        if isinstance(content, str):
                            found.append(content)
                        elif isinstance(content, list):
                            found.extend(
                                block["text"]
                                for block in content
                                if isinstance(block, dict)
                                and isinstance(block.get("text"), str)
                            )
                    for child in value.values():
                        found.extend(user_texts(child))
                elif isinstance(value, list):
                    for child in value:
                        found.extend(user_texts(child))
                return found

            def screen_has_text(screen, text):
                # Terminal emulators can NFC-compose a base and combining mark
                # into one cell. Compare visible text canonically while keeping
                # provider request payload checks exact below.
                return unicodedata.normalize("NFC", text) in unicodedata.normalize("NFC", screen)

            def bounded_region(value, start_marker, end_marker):
                if isinstance(value, bytes):
                    start_marker = start_marker.encode("utf-8")
                    end_marker = end_marker.encode("utf-8")
                start = value.find(start_marker)
                if start < 0:
                    return None
                start += len(start_marker)
                end = value.find(end_marker, start)
                return value[start:end] if end >= 0 else None

            def terminal_has_grapheme(text, raw_offset, start_marker, end_marker):
                # Bound both observation paths to one transcript span. pyte
                # models cell layout but drops VS16/ZWJ continuations, so the
                # matching raw bytes are also checked after the event offset.
                screen_region = bounded_region(
                    session.screen_text(), start_marker, end_marker
                )
                raw_region = bounded_region(
                    bytes(session.raw_log[raw_offset:]), start_marker, end_marker
                )
                return (
                    screen_region is not None
                    and (
                        screen_has_text(screen_region, text)
                        or (
                            raw_region is not None
                            and text.encode("utf-8") in raw_region
                        )
                    )
                )

            def submitted_user_has_graphemes(screen, graphemes, raw_offset):
                # A retained draft can contain the same text as the submitted
                # turn. Require one frame with the user row above the empty,
                # live-turn composer before accepting screen or raw evidence.
                lines = screen.splitlines()
                composer_row = next(
                    (
                        index
                        for index, line in enumerate(lines)
                        if "Add to the queue, or wait for ORBIT" in line
                    ),
                    None,
                )
                if composer_row is None:
                    return False
                transcript_rows = lines[:composer_row]
                if not any(
                    "›" in line and "pasted⇥" in line
                    for line in transcript_rows
                ):
                    return False
                transcript_text = "\n".join(transcript_rows)
                raw_region = bounded_region(
                    bytes(session.raw_log[raw_offset:]),
                    "pasted",
                    "Add to the queue, or wait for ORBIT",
                )
                return all(
                    screen_has_text(transcript_text, grapheme)
                    or (
                        raw_region is not None
                        and grapheme.encode("utf-8") in raw_region
                    )
                    for grapheme in graphemes
                )

            expect("terminal UI boots", lambda screen: "ORBIT" in screen)
            adopted = json.loads((saved / f"{sid}.json").read_text())
            assert adopted["workspace"] == str(workspace.resolve()), adopted
            checks += 1
            print("PASS legacy fixture session is explicitly bound to its workspace", flush=True)
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
            expect("reverse history-search prompt opens", lambda screen: "History search:" in screen)
            session.type("alpha")
            expect("history searches newest matching entry", lambda screen: "History search: alpha" in screen and "alpha newest request" in screen)
            session.write(b"\x12")
            expect("Ctrl-R cycles older matching entry", lambda screen: "older alpha request" in screen)
            session.key("esc")
            expect("history cancel restores original draft", lambda screen: "History search:" not in screen and "unsent draft" in screen)
            draft_only("history cancellation")
            session.write(b"\x12")
            expect("next history-search prompt opens", lambda screen: "History search:" in screen)
            session.type("beta")
            expect("history search finds another query", lambda screen: "separate beta request" in screen)
            session.key("enter")
            expect("history Enter accepts the draft", lambda screen: "History search:" not in screen and "separate beta request" in screen)
            draft_only("history Enter acceptance")
            session.write(b"\x12")
            expect("unmatched-query history search opens", lambda screen: "History search:" in screen)
            session.type("not-in-history")
            expect("unmatched history query is visible", lambda screen: "no match" in screen)
            session.key("esc")
            expect("unmatched search cancels before a new search", lambda screen: "History search:" not in screen and "separate beta request" in screen)
            session.write(b"\x12")
            expect("Unicode history-search prompt opens", lambda screen: "History search:" in screen)
            session.type("e\u0301")
            expect(
                "history search accepts a combining grapheme",
                lambda screen: "History search:" in screen and screen_has_text(screen, "(no match) e\u0301"),
            )
            session.key("backspace")
            expect(
                "history-search Backspace removes the whole grapheme",
                lambda screen: "History search:" in screen
                and "search: " in screen
                and "search: e" not in screen
                and not screen_has_text(screen, "(no match) e\u0301"),
            )
            session.key("esc")
            draft_only("history-search grapheme cancellation restores the prior draft")
            session.write(b"\x12"); session.type("first")
            expect("legacy JSON prompt stays a single draft", lambda screen: '["first","second"]' in screen)
            session.key("enter")
            draft_only("legacy JSON history acceptance")

            clear_draft()
            session.type("abcd")
            session.key("left")
            session.key("left")
            session.type("界")
            expect("middle-cursor insertion keeps wide grapheme intact", lambda screen: "ab界cd" in screen)
            session.key("home")
            session.type("e\u0301")
            expect("logical-line start inserts a complete combining grapheme", lambda screen: screen_has_text(screen, "e\u0301ab界cd"))
            session.key("end")
            session.key("backspace")
            expect("Backspace at the cursor removes a whole grapheme", lambda screen: screen_has_text(screen, "e\u0301ab界c"))
            session.key("home")
            for _ in range(4):
                session.key("right")
            session.key("backspace")
            expect("Backspace removes a wide grapheme at a middle cursor", lambda screen: screen_has_text(screen, "e\u0301abc"))
            session.key("home")
            session.key("delete")
            expect("Delete at the cursor removes a whole combining grapheme", lambda screen: "abc" in screen)
            draft_only("cursor editing stays in the draft")

            clear_draft()
            session.write(b"\x1b[200~ \t\n \x1b[201~")
            session.key("enter")
            draft_only("whitespace-only bracketed paste does not dispatch")

            clear_draft()
            pasted_prompt = "  pasted\te\u0301 界 🇧🇷 ☀️ 👨‍👩‍👧‍👦\n日本語 /help  "
            session.write(b"\x1b[200~" + pasted_prompt.encode("utf-8") + b"\x1b[201~")
            expect(
                "literal multiline paste remains visible as one draft",
                lambda screen: "pasted" in screen and "日本語" in screen and "⏎" in screen,
            )
            hold_next_response[0] = True
            response_started.clear()
            response_finished.clear()
            response_gate.clear()
            user_transcript_output_offset = len(session.raw_log)
            session.key("enter")
            expect("one request is captured after explicit paste submit", lambda _screen: len(requests) == 1)
            assert response_started.wait(timeout=5), "mock did not start the held response"
            assert not response_finished.is_set(), "mock response was not held"
            assert len(requests) == 1, f"expected one provider request, got {len(requests)}"
            expect(
                "transcript displays a pasted tab as a safe marker",
                lambda screen: screen_has_text(screen, "pasted⇥"),
            )
            assert not any(ch in session.screen_text() for ch in "\t\r\x1b\x7f\u0085"), (
                "raw control character reached the emulated terminal screen"
            )
            submitted = user_texts(requests[0]["body"])
            assert submitted.count(pasted_prompt) == 1, submitted
            checks += 1
            print("PASS exact edge whitespace and newline reach one user request", flush=True)
            expect(
                "submitted user transcript emits complete Unicode graphemes",
                lambda screen: submitted_user_has_graphemes(
                    screen,
                    ("e\u0301", "界", "🇧🇷", "☀️", "👨‍👩‍👧‍👦"),
                    user_transcript_output_offset,
                ),
            )

            busy_side_effect = workspace / "busy-side-effect"
            # The PTY runs with cwd=workspace, so this short relative path
            # keeps the complete retained command visible beside its toast.
            busy_command = "!touch busy-side-effect"
            session.type(busy_command)
            session.key("enter")
            busy_samples = {"first": None, "toast": None, "last": None}

            def busy_rejection_visible(screen):
                sample = {
                    "toast": "wait for the active work to finish" in screen,
                    "draft": busy_command in screen,
                    "footer": "⏎ queue" in screen,
                    "bottom": "\n".join(screen.splitlines()[-7:]),
                }
                busy_samples["first"] = busy_samples["first"] or sample
                busy_samples["last"] = sample
                if sample["toast"]:
                    busy_samples["toast"] = sample
                return sample["toast"] and sample["draft"] and sample["footer"]

            try:
                expect(
                    "busy shell command is rejected with a visible toast and retained draft",
                    busy_rejection_visible,
                )
            except AssertionError as error:
                raise AssertionError(f"{error}\nBusy rejection samples: {busy_samples}") from error
            assert not busy_side_effect.exists(), "busy command created its side-effect sentinel"
            assert not response_finished.is_set(), "busy check ran after the held response settled"
            checks += 1
            print("PASS busy shell rejection preserves the draft without dispatch", flush=True)

            clear_draft()
            long_unicode_draft = "界" * 24
            session.type(long_unicode_draft)
            resize_output_offset = len(session.raw_log)
            session.resize(rows=16, cols=48)
            expect(
                "narrow resize redraws the long Unicode draft in a fresh 48-column frame",
                lambda screen: len(session.raw_log) > resize_output_offset
                and session.screen.columns == 48
                and screen.count("界") >= 5,
            )
            clear_draft()
            expect(
                "previous busy toast is gone before the fresh narrow-width case",
                lambda screen: "wait for the active work to finish" not in screen,
            )
            narrow_marker = "🧭"
            narrow_busy_draft = f"!touch busy-side-effect # {long_unicode_draft}{narrow_marker}"
            narrow_busy_output_offset = len(session.raw_log)
            session.type(narrow_busy_draft)
            session.key("enter")
            expect(
                "fresh 48-column busy toast and current Unicode draft render together",
                lambda screen: "wait for the active work" in screen
                and narrow_marker in screen
                and "⏎ queue" in screen
                and session.screen.columns == 48
                and len(session.raw_log) > narrow_busy_output_offset,
            )
            assert not busy_side_effect.exists(), "busy command sentinel appeared before release"
            assert not response_finished.is_set(), "mock released before the narrow toast assertion"
            assert len(requests) == 1, f"busy resize rejection caused another provider request: {len(requests)}"
            toast_seen_at = time.monotonic()
            assistant_output_offset = len(session.raw_log)
            response_gate.set()
            expect(
                "synthetic Unicode response and Markdown table render after release",
                lambda screen: "Unicode:" in screen and "ready" in screen and "yes" in screen,
            )
            assert response_finished.wait(timeout=5), "mock response did not finish"
            assert len(requests) == 1, f"busy rejection caused another provider request: {len(requests)}"
            screen = session.screen_text()
            for cluster in ("e\u0301", "界", "🇧🇷", "☀️", "👨‍👩‍👧‍👦"):
                if not terminal_has_grapheme(
                    cluster, assistant_output_offset, "Unicode:", "item"
                ):
                    raw_region = bounded_region(
                        bytes(session.raw_log[assistant_output_offset:]),
                        "Unicode:",
                        "item",
                    )
                    screen_region = bounded_region(screen, "Unicode:", "item")
                    raise AssertionError(
                        f"assistant grapheme missing {cluster!r}; "
                        f"screen_region={screen_region!r}; "
                        f"raw_region={raw_region!r}\n{screen}"
                    )
            checks += 1
            print("PASS synthetic assistant reply preserves complete Unicode graphemes", flush=True)
            while time.monotonic() - toast_seen_at < 3.2:
                session.read(0.1)
            screen = session.screen_text()
            assert "wait for the active work" not in screen, screen
            assert screen.count("界") >= 5, screen
            assert not busy_side_effect.exists(), "busy command created its side-effect sentinel"
            checks += 1
            print("PASS busy toast expires on idle redraw while Unicode draft remains", flush=True)
            session.key("home")
            expect(
                "expired toast leaves the guarded command draft recoverable at its start",
                lambda screen: "!touch busy-side-effect #" in screen,
            )
            session.key("end")
            expect(
                "expired toast leaves the Unicode command draft recoverable at its end",
                lambda screen: screen.count("界") >= 5 and narrow_marker in screen,
            )
            assert not busy_side_effect.exists(), "busy command created its side-effect sentinel"
            wide_resize_output_offset = len(session.raw_log)
            session.resize(rows=32, cols=120)
            expect(
                "wide resize redraws the retained Unicode draft end",
                lambda screen: len(session.raw_log) > wide_resize_output_offset
                and session.screen.columns == 120
                and screen.count("界") >= 5
                and narrow_marker in screen,
            )
            cleanup.close()
            persisted = json.loads((saved / f"{sid}.history").read_text())
            assert persisted["schema"] == "orbit.composer-history/v1"
            assert persisted["entries"] == [pasted_prompt, *history_entries]
            checks += 1
            print("PASS legacy history migrates, preserves prompts, and records the submitted prompt", flush=True)
            print(f"Results: {checks} passed", flush=True)
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
