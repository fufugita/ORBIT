#!/usr/bin/env python3
"""The Council pane in the real terminal UI: its look and its pace.

A state file named by ORBIT_COUNCIL_STATE stands in for the engine and a local
fixture stands in for the provider, so nothing outside this machine is
contacted. Run through scripts/in-jail.sh when testing a desktop checkout.

The pane follows the standalone MAGI pane: a header with a subtitle and the
local time, four seat cards (name plate, lab, model, a body, a verdict), a strip
for the majority, the winner and the judge, and a footer for the phase and the
record. It redraws eight times a second while a council runs and twice a second
at rest.
"""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import re
import subprocess
import tempfile
import threading
import time

from pty_tui_test import PtySession, pyte

MODELS = ["claude-haiku-5-5", "claude-deepseek-v4-pro", "claude-glm-5.3-flash", "claude-minimax-m3"]
NAMES = ["KARINA", "GISELLE", "WINTER", "NINGNING"]
VOTES = ["APPROVE", "REJECT", "APPROVE", "CONDITIONAL"]
FINAL = "Adopt SQLite in WAL mode as the authoritative state store; keep JSON for exports."
FRAME_END = b"\x1b[?2026l"  # one drawn frame is one synchronized update


def state(phase, now, note="", seats=(), winner=None):
    out = {"ts": now, "phase": phase, "note": note, "seats": list(seats)}
    if winner:
        out["winner"] = winner
    return out


def seat(index, status, verdict):
    return {"model": MODELS[index], "status": status, "verdict": verdict}


def history_rows(now):
    rows = []
    for age_hours, verdicts, final in [(30, ["APPROVE", "APPROVE", "REJECT", "CONDITIONAL"], "Keep the JSON store."),
                                       (3, VOTES, "FINAL: " + FINAL)]:
        top = max(set(verdicts), key=verdicts.count)
        rows.append({
            "ts": now - age_hours * 3600, "final": final, "mode": "TRIAL",
            "answers": {n: f"VERDICT: {v}\nCONFIDENCE: {70 + 5 * i}" for i, (n, v) in enumerate(zip(NAMES, verdicts))},
            "models": dict(zip(NAMES, MODELS)),
            "winner": {"seats": [n for n, v in zip(NAMES, verdicts) if v == top], "verdict": top, "tie": False},
        })
    return "\n".join(json.dumps(r) for r in rows) + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    if pyte is None:
        raise SystemExit("pyte is required for exact terminal screen assertions")

    class Provider(BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            for event in [
                {"choices": [{"index": 0, "delta": {"content": "council fixture reply"}, "finish_reason": None}]},
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                 "usage": {"prompt_tokens": 2, "completion_tokens": 3}},
            ]:
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    session = None
    checks = 0
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-council-pty-") as tmp:
            root = Path(tmp)
            home, workspace = root / "home", root / "workspace"
            workspace.mkdir()
            subprocess.run([binary, "init", "--home", str(home), "--no-provider"], cwd=workspace, check=True,
                           capture_output=True, timeout=30)
            (home / "providers.toml").write_text(
                f'[[provider]]\nname = "fixture"\nurl = "http://127.0.0.1:{server.server_port}"\n'
                'env = "ORBIT_GATE_TOKEN"\n[[provider.models]]\nid = "a"\n')
            feed = root / "feed"
            feed.mkdir()
            feed_state = feed / "state.json"
            (feed / "history.jsonl").write_text(history_rows(time.time()))

            def publish(phase, **kw):
                feed_state.write_text(json.dumps(state(phase, time.time(), **kw)))

            def squeezed():
                # A wide glyph leaves an empty cell behind it; compare without the blanks.
                return re.sub(r"\s+", "", session.screen_text())

            def check(label, predicate, seconds=10):
                nonlocal checks
                deadline = time.monotonic() + seconds
                while time.monotonic() < deadline:
                    session.read(0.2)
                    if predicate():
                        checks += 1
                        print(f"PASS {label}", flush=True)
                        return
                raise AssertionError(f"{label}\n{session.screen_text()}")

            def frames_in(seconds):
                session.read(0.3)
                before = session.raw_log.count(FRAME_END)
                end = time.monotonic() + seconds
                while time.monotonic() < end:
                    session.read(0.1)
                return session.raw_log.count(FRAME_END) - before

            publish("IDLE")
            env = {"ORBIT_GATE_TOKEN": "fixture", "ORBIT_HOME": str(home), "ORBIT_COUNCIL_STATE": str(feed_state)}
            session = PtySession([binary, "--home", str(home), "--model", "fixture/a"], env=env, cwd=workspace,
                                 rows=50, cols=200)
            ok, _ = session.wait_for("ORBIT", timeout=20)
            assert ok, session.screen_text()
            session.type("hello")
            session.key("enter")
            check("a turn leaves the welcome screen", lambda: "council fixture reply" in session.screen_text(), 20)
            # Arrange mode: v splits, 9 picks the Council, i returns to typing.
            for key in (b"\x1b", b"v", b"9", b"i"):
                session.write(key)
                session.read(0.5)
            check("the Council pane is on screen", lambda: "▲MAGI◢" in squeezed())

            # --- at rest -------------------------------------------------------
            check("the header names the pane and carries its subtitle", lambda: "에스파의사결정기구" in squeezed())
            def header():
                return next((row for row in session.screen_text().splitlines() if "M A G I" in row), "")

            check("the header shows a clock, not a placeholder",
                  lambda: re.search(r"\b\d\d:\d\d\b", header()) is not None and "00:00Z" not in header())
            clock = re.search(r"\b(\d\d):(\d\d)\b", header())
            minutes_now = time.localtime().tm_hour * 60 + time.localtime().tm_min
            shown = int(clock.group(1)) * 60 + int(clock.group(2))
            assert min((shown - minutes_now) % 1440, (minutes_now - shown) % 1440) <= 2, (header(), minutes_now)
            checks += 1
            print("PASS the time shown is the local time", flush=True)
            check("an idle card names the seat's role in Hangul", lambda: "총괄" in squeezed() and "반론" in squeezed())
            check("an idle card crowns the seats that won the last council", lambda: session.screen_text().count("♛") == 2)
            check("the strip keeps the last winner and conclusion",
                  lambda: "승자▏KARINA·WINTER→APPROVE" in squeezed() and "AdoptSQLite" in squeezed())
            idle = frames_in(3)
            assert 3 <= idle <= 10, f"at rest the pane redraws about twice a second, drew {idle} frames in 3 s"
            checks += 1
            print(f"PASS at rest the pane draws {idle} frames in 3 s (about two a second)", flush=True)

            # --- a council in flight -------------------------------------------
            publish("DELIBERATING", seats=[seat(0, "online", "APPROVE"), seat(1, "computing", None),
                                           seat(2, "online", "CONDITIONAL"), seat(3, "computing", None)])
            check("a card shows the model's short name", lambda: "haiku-5" in squeezed() and "glm-5.3" in squeezed())
            check("the strip counts the answers and the votes", lambda: "심의▏2/4응답·표2" in squeezed())
            check("the seats still deliberating say so", lambda: squeezed().count("심의중") >= 2)
            running = frames_in(3)
            assert running >= 14, f"while a council runs the pane redraws about eight times a second, drew {running} frames in 3 s"
            assert running > 2 * idle, (running, idle)
            checks += 1
            print(f"PASS in flight the pane draws {running} frames in 3 s (about eight a second)", flush=True)

            # --- the verdict ---------------------------------------------------
            publish("VERDICT", note="FINAL: " + FINAL,
                    seats=[dict(seat(i, "reported", VOTES[i])) for i in range(4)],
                    winner={"seats": ["KARINA", "WINTER"], "verdict": "APPROVE", "count": 2, "tie": False})
            check("the majority is named", lambda: "다수결▏승인YES·2/4" in squeezed())
            check("the winners are named", lambda: "승자▏KARINA·WINTER" in squeezed())
            check("the judge's conclusion is shown", lambda: "nævis▏AdoptSQLite" in squeezed())
            check("each seat carries its vote in its footer", lambda: "│YES││NO││YES││HOLD│" in squeezed())

            def stamped():
                # The seal is drawn in quadrant blocks, big enough to fill most of a card.
                blocks = sum(session.screen_text().count(ch) for ch in "▗▖▘▝▀▄▌▐▙▛▜▟█")
                return blocks >= 120

            check("a seat that voted wears a large stamp of its verdict", stamped)
            check("the footer names the phase and the record",
                  lambda: "PHASE결론도달VERDICT" in squeezed() and "기록2/2·3h전" in squeezed())

            # --- a triage verdict has its moment, then the pane settles --------
            feed_state.write_text(json.dumps(state("TRIAGED", time.time(), note="QUICK")))
            check("a fresh triage verdict is shown", lambda: "선별▏→QUICK" in squeezed())
            feed_state.write_text(json.dumps(state("TRIAGED", time.time() - 25, note="QUICK")))
            check("a triage verdict older than twenty seconds has settled to idle",
                  lambda: "PHASE대기" in squeezed() and "선별▏→QUICK" not in squeezed())
        print(f"\ncouncil pty test: {checks} checks passed")
    finally:
        if session is not None:
            session.terminate()
        server.shutdown()


if __name__ == "__main__":
    main()
