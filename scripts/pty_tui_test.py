#!/usr/bin/env python3
"""PTY test harness for the ORBIT Rust ratatui TUI (front-end for orbit chat).

Spawns the real `orbit` binary in a PTY and drives it with keystrokes,
verifying: boot-to-typing focus, streaming (mock provider), slash commands
(/help /model /clear /usage), tool approval (y/n), Ctrl+C cancel, Ctrl+D quit,
SIGHUP, resize — and a clean exit with the terminal state restored.

Usage:
  pty_tui_test.py [--binary PATH] [--mock PATH] [--home DIR] [--model MODEL]
                  [--provider PROVIDER] [--gate URL] [--token TOKEN]
"""

import argparse
import fcntl
import os
import pty
import re
import select
import signal
import struct
import subprocess
import sys
import termios
import time

PASS = 0
FAIL = 0


def check(name: str, cond: bool, detail: str = ""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  PASS  {name}")
    else:
        FAIL += 1
        print(f"  FAIL  {name} {detail}")


class PtySession:
    def __init__(self, cmd, env=None, timeout=30, rows=30, cols=100):
        self.timeout = timeout
        self.master, self.slave = pty.openpty()
        # Set the PTY window size BEFORE spawning so the TUI gets a real
        # WindowSizeMsg (otherwise w=0 h=0 → viewport is 0-sized → no render).
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        full_env = os.environ.copy()
        full_env["TERM"] = "xterm-256color"
        full_env["COLORTERM"] = "truecolor"
        if env:
            full_env.update(env)
        self.proc = subprocess.Popen(
            cmd,
            stdin=self.slave,
            stdout=self.slave,
            stderr=self.slave,
            env=full_env,
            close_fds=True,
            start_new_session=True,
        )
        os.close(self.slave)
        # Every byte ever read, never stripped — for control-sequence asserts.
        self.raw_log = b""

    def read(self, timeout=2.0):
        """Read available output, waiting up to timeout.

        All bytes are also appended to self.raw_log (never stripped) so
        tests can assert on control sequences (mouse capture, OSC 52…).
        """
        out = b""
        end = time.time() + timeout
        while time.time() < end:
            r, _, _ = select.select([self.master], [], [], 0.2)
            if r:
                try:
                    chunk = os.read(self.master, 4096)
                except OSError:
                    break
                if not chunk:
                    break
                out += chunk
                self.raw_log += chunk
            elif out:
                break
        return out.decode("utf-8", errors="replace")

    ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]")

    def clean(self, s):
        """Strip ANSI escapes AND cursor-move sequences so text is contiguous."""
        s = re.sub(r"\x1b\[[0-9;?]*[a-zA-Z]", "", s)
        # Also drop OSC (title) sequences and BEL/other controls that can
        # interleave between characters.
        s = re.sub(r"\x1b\][^\x07]*(\x07|\x1b\\)", "", s)
        return s

    def wait_for(self, text, timeout=20):
        """Wait for text to appear (ANSI-stripped) in output.
        Returns (matched, cleaned_buf) — the buffer is CLEANED so callers
        can substring-match without re-stripping."""
        buf = ""
        end = time.time() + timeout
        while time.time() < end:
            buf += self.read(0.5)
            if text in self.clean(buf):
                return True, self.clean(buf)
        return False, self.clean(buf)

    def wait_for_re(self, pattern, timeout=20):
        """Wait for a regex to match (ANSI-stripped) in output.
        Returns (match, cleaned_buf)."""
        rx = re.compile(pattern)
        buf = ""
        end = time.time() + timeout
        while time.time() < end:
            buf += self.read(0.5)
            m = rx.search(self.clean(buf))
            if m:
                return m, self.clean(buf)
        return None, self.clean(buf)

    def write(self, data):
        os.write(self.master, data)

    def key(self, name):
        mapping = {
            "enter": b"\r",
            "tab": b"\t",
            "esc": b"\x1b",
            "ctrl+c": b"\x03",
            "ctrl+d": b"\x04",
            "backspace": b"\x7f",
            "up": b"\x1b[A",
            "down": b"\x1b[B",
            "left": b"\x1b[D",
            "right": b"\x1b[C",
            "shift+enter": b"\x1b[13;2u",
            "shift+tab": b"\x1b[Z",
        }
        if name not in mapping:
            self.write(name.encode())
            return
        self.write(mapping[name])

    def type(self, text):
        for ch in text:
            self.write(ch.encode())
            time.sleep(0.005)

    def resize(self, rows, cols):
        fcntl.ioctl(self.master, termios.TIOCSWINSZ, struct.pack("HHHH", rows, cols, 0, 0))
        os.kill(self.proc.pid, signal.SIGWINCH)

    def terminate(self):
        try:
            os.kill(self.proc.pid, signal.SIGTERM)
            self.proc.wait(timeout=3)
        except Exception:
            self.proc.kill()
            self.proc.wait()
        os.close(self.master)


def _port_open(port, timeout=0.5):
    import socket
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=timeout):
            return True
    except OSError:
        return False


def start_mock(binary, port):
    """Start the mock provider if not already listening; returns Popen or None.
    Verifies the port actually opens after spawn (the mock can fail to bind
    or die silently), and retries once."""
    if _port_open(port):
        return None  # already running
    env = os.environ.copy()
    env["ORBIT_MOCK_BIND"] = f"127.0.0.1:{port}"
    logf = open("/tmp/orbit-mock.log", "a")
    logf.write(f"\n--- mock start {time.strftime('%H:%M:%S')} ---\n")
    logf.flush()
    p = subprocess.Popen(
        [binary],
        stdout=logf,
        stderr=logf,
        env=env,
        start_new_session=True,
    )
    # Wait until the port opens (up to 3s), not a fixed sleep.
    for _ in range(15):
        if _port_open(port, timeout=0.3):
            return p
        if p.poll() is not None:
            break
        time.sleep(0.2)
    # First attempt failed — try once more.
    p.kill()
    p.wait()
    p = subprocess.Popen(
        [binary],
        stdout=logf,
        stderr=logf,
        env=env,
        start_new_session=True,
    )
    for _ in range(15):
        if _port_open(port, timeout=0.3):
            return p
        if p.poll() is not None:
            break
        time.sleep(0.2)
    return p


def make_providers(home, provider, gate, model):
    os.makedirs(home, exist_ok=True)
    # Register the boot model AND the "mock" model: the /model test switches
    # to "mock" (tool-call provider), so it must resolve through
    # providers.toml — otherwise dispatch falls back to the default gate
    # (4001) and the turn dies with a 401 before any tool call / approval.
    with open(os.path.join(home, "providers.toml"), "w") as f:
        f.write(f'[[provider]]\nname = "{provider}"\nurl = "{gate}"\nenv = "ORBIT_GATE_TOKEN"\n\n[[provider.models]]\nid = "{model}"\n[[provider.models]]\nid = "mock"\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="/media/hanu/HANU/ORBIT/target/debug/orbit")
    ap.add_argument("--mock", default="/media/hanu/HANU/ORBIT/target/debug/orbit-mock-provider")
    ap.add_argument("--home", default="/tmp/orbit-pty-home")
    ap.add_argument("--model", default="mock-slow")
    ap.add_argument("--provider", default="local")
    ap.add_argument("--gate", default="http://127.0.0.1:8088")
    ap.add_argument("--token", default="test-token")
    args = ap.parse_args()

    # Fresh ORBIT home.
    subprocess.run(["rm", "-rf", args.home], check=False)
    init_env = os.environ.copy()
    init_env["ORBIT_HOME"] = args.home
    subprocess.run(
        [args.binary, "init", "--home", args.home, "--no-provider"],
        capture_output=True, timeout=30, env=init_env,
    )
    make_providers(args.home, args.provider, args.gate, args.model)

    # Ensure the mock server is up.
    mock_proc = start_mock(args.mock, 8088)
    if mock_proc is None:
        print("mock provider: already running")
    else:
        print("mock provider: started")

    env = {"ORBIT_HOME": args.home, "ORBIT_GATE_TOKEN": args.token}

    # ── 1. Boot → type immediately (Center focus) ──────────────────────────
    print("\n== Boot + focus test ==")
    s = PtySession(
        [args.binary, "--home", args.home, "--model", args.model],
        env=env, timeout=20, rows=30, cols=110,
    )
    ok, buf = s.wait_for("ORBIT", timeout=15)
    check("boots to TUI", ok, buf[-500:])
    time.sleep(0.8)
    try:
        # Read DURING typing: ratatui redraws only changed cells, so
        # each keystroke's frame lands between the writes; a read after
        # all keystrokes sees only the cursor blink.
        b2 = ""
        for ch in "hello":
            s.write(ch.encode())
            time.sleep(0.05)
            b2 += s.read(0.3)
        b2 += s.read(0.5)
        # The TUI draws whole frames each tick — a multi-char phrase is
        # spread across frames (chars re-render as overlays). Assert all
        # letters appear IN ORDER in the cleaned buffer, not contiguously.
        c = s.clean(b2)
        # The whole buffer: the cursor blink + splash reveal rewrite cells
        # continuously, so the tail window alone can miss the text.
        check("types into composer on boot (default focus)",
              "h" in c and "e" in c and "l" in c and "l" in c and "o" in c,
              b2[-2000:])
    except Exception as e:
        check("types into composer on boot (default focus)", False, str(e))

    # ── 2. Stream a response (mock-slow), proving the prompt was sent ──────
    s.key("enter")
    clean = ""
    end = time.time() + 20
    while time.time() < end:
        clean += s.read(0.5)
        if "Hello from the slow stream" in clean:
            break
        time.sleep(0.2)
    check("sends prompt + streams response", "Hello from the slow stream" in clean, clean[-300:])

    # ── 3. Slash commands (REPL parity in the TUI) ─────────────────────────
    # After the slow-stream turn, the TUI is idle and ready for commands.
    # Do NOT send Ctrl+C here — two presses within 120 ticks would quit the
    # whole session and the rest of the matrix would operate on a dead proc.
    s.read(0.5)

    s.type("/help")
    s.key("enter")
    ok, buf = s.wait_for("commands:", timeout=10)
    check("/help renders command list", ok, buf[-300:])
    time.sleep(0.5)

    # /model <M> switches the model; status bar should show new model.
    s.type("/model mock")
    s.key("enter")
    ok, buf = s.wait_for("model → mock", timeout=10)
    check("/model switches model", "model → mock" in buf, buf[-200:])
    time.sleep(0.3)

    # /clear clears the transcript; /usage shows counters.
    s.type("/clear")
    s.key("enter")
    time.sleep(0.4)
    s.type("/usage")
    s.key("enter")
    ok, buf = s.wait_for("turns", timeout=10)
    check("/usage shows counters", "turns" in buf and "in " in buf, buf[-200:])
    time.sleep(0.3)

    # Unknown command → error line.
    s.type("/bogus")
    s.key("enter")
    ok, buf = s.wait_for("unknown command", timeout=10)
    check("/bogus shows unknown command", "unknown command" in buf, buf[-200:])
    time.sleep(0.3)

    # ── 4. Tool approval modal (y allows, turn completes) ──────────────────
    # The `mock` model (no "slow") triggers a calculator tool call on the
    # first round, then returns "hello world" after the tool result.
    # Ensure the mock is still up (it can die mid-test); restart if needed.
    print(f"  [health] before approval: port8088={_port_open(8088)} mock_alive={mock_proc is not None and mock_proc.poll() is None}")
    if not _port_open(8088):
        if mock_proc is not None:
            mock_proc.kill()
            mock_proc.wait()
        mock_proc = start_mock(args.mock, 8088)
        print("mock provider: restarted for approval test")
    s.type("compute 2+2")
    s.key("enter")
    # The approval MODAL has a distinctive title "? Approval Required".
    # Do NOT wait for "calculator" — that string appears in the transcript's
    # [tool] line BEFORE the ApprovalRequested message is reduced, so 'y'
    # could arrive while pending_approvals is still empty and get typed into
    # the composer instead of resolving the modal (race).
    ok, buf = s.wait_for("Allow calculator", timeout=15)
    check("approval modal appears (title)", ok, buf[-300:])
    print(f"  [health] after modal: port8088={_port_open(8088)} mock_alive={mock_proc is not None and mock_proc.poll() is None}")
    if ok:
        s.key("y")  # allow
        # The second round streams "hello world". With the bordered panes
        # the text fits fully; match the stable prefix either way.
        ok2, buf2 = s.wait_for("hello worl", timeout=45)
        check("approval 'y' allows tool -> second round text", ok2, buf2[-300:])

    # ── 5. Ctrl+C cancel mid-stream (graceful, TUI stays up) ───────────────
    # The model is currently "mock" (tool-call provider) — a prompt would
    # trigger an approval modal, not a stream. Switch back to "mock-slow"
    # (streams text in 200ms chunks) so Ctrl+C cancels a real stream.
    s.type("/model mock-slow")
    s.key("enter")
    time.sleep(0.5)
    s.type("cancel me")
    s.key("enter")
    time.sleep(0.4)  # let the slow stream start (200ms per chunk)
    s.key("ctrl+c")
    ok, buf = s.wait_for("cancelled", timeout=10)
    check("ctrl+c cancels gracefully", ok, buf[-200:])

    # ── 6. /sessions + /resume round-trip ──────────────────────────────────
    # A completed turn (the tool turn above) saved a session file.
    # The worker emits "session_id model=X turns=X" as a SystemMessage.
    # Use ordered letters for frame-interleaved matching.
    s.type("/sessions")
    s.key("enter")
    ok, buf = s.wait_for("model", timeout=10)
    # Ordered letter check — frame interleaving may split "model=X"
    has_ordered = ("m" in buf and "o" in buf and "d" in buf and
                   "e" in buf and "l" in buf and "t" in buf and
                   "u" in buf and "r" in buf and "n" in buf and "s" in buf)
    check("/sessions lists saved session", ok and has_ordered, buf[-300:])
    time.sleep(0.3)

    # ── 7. Ctrl+D quit → clean exit ────────────────────────────────────────
    s.key("ctrl+d")
    # Ctrl+D opens quit confirmation modal — press 'y' to confirm.
    time.sleep(0.5)
    s.key("y")
    time.sleep(1.0)
    exited = s.proc.poll() is not None
    check("ctrl+d quits", exited, f"still running; exit code={s.proc.returncode}")
    if not exited:
        s.terminate()
    try:
        s.proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        s.proc.kill()
        s.proc.wait()

    # ── 7b. Tab burst → focus cycles one-by-one (regression) ───────────────
    # Rapid Tab presses must cycle focus through every pane without skipping.
    # The baseline bug: pane_block blends PANE_DIM→accent over 4 phases, and
    # phase 0 renders at the dim color (indistinguishable from unfocused).
    # A burst restarts the blend at phase 0 every time, so intermediate panes
    # are invisible. This test asserts ≥6 of 8 expected focus markers appear
    # in order — fewer means a pane was skipped.
    print("\n== Tab burst focus test ==")
    sb = PtySession(
        [args.binary, "--home", args.home, "--model", args.model],
        env=env, timeout=20, rows=30, cols=110,
    )
    ok, _ = sb.wait_for("ORBIT", timeout=15)
    check("boots TUI for tab burst test", ok)
    if ok:
        time.sleep(0.8)
        # Send 8 Tabs in one write (worst case: crossterm coalesces them).
        sb.write(b"\t" * 8)
        time.sleep(1.5)
        raw = sb.read(2.0)
        buf = sb.clean(raw)
        # Count ordered ▶ markers. Focus cycle from Center is:
        # Right(▶ Tasks) → Status(no marker) → Left(▶ Sessions) → Center(no marker) → repeat
        # So 8 Tabs should produce: Tasks, Sessions, Tasks, Sessions, Tasks, Sessions, Tasks, Sessions
        # We look for ▶ Tasks and ▶ Sessions appearing in alternating order.
        import re as _re
        # New design (§6.1): focused pane header = heavy rule ━, unfocused =
        # light rule ─. Each focus change rewrites the affected header rows,
        # emitting ━ segments. Count focus-rule writes across the burst:
        # ≥6 means the focus cycled through panes repeatedly without a
        # single keypress getting lost (each of the 8 tabs produces at
        # least one header rewrite for the newly-focused pane).
        # Focus-chip design: the focused pane's title is a FILLED chip —
        # fg canvas-ink, bg magenta, bold. ratatui emits fg+bg as one
        # combined SGR (…38;2;16;14;22;48;2;227;86;208m), so the marker is
        # the bg-magenta field followed by the title word. Each Tab moves
        # focus → the newly focused pane's title chip redraws. Count chip
        # writes across the burst: ≥4 means focus cycled R,L,R,L without
        # a lost keypress.
        markers = _re.findall(r"48;2;227;86;208m[ ]?[A-Za-z]+", raw)
        has_alternation = len(markers) >= 4
        check("tab burst cycles focus one-by-one",
              has_alternation,
              f"focus-rule writes={len(markers)} (need ≥4: R,L,R,L — Center has no header)")
        sb.key("ctrl+d")
        time.sleep(0.5)
        sb.key("y")
        try:
            sb.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            sb.terminate()

    # ── Mouse selection test (per-pane isolation) ────────────────────────────────
    print("\n== Mouse selection test ==")
    sb = PtySession(
        [args.binary, "--home", args.home, "--model", args.model],
        env=env, timeout=20, rows=30, cols=110,
    )
    ok, bootbuf = sb.wait_for("ORBIT", timeout=15)
    check("boots TUI for mouse test", ok)
    if ok:
        time.sleep(0.8)
        # The boot path must own the mouse (TerminalGuard::enter enables
        # SGR capture). Regression guard: the enable sequences must be in
        # the boot stream — not only echo, the app consuming mouse events
        # depends on it.
        has_enable = any(x in sb.raw_log for x in (b"?1000h", b"?1006h", b"?1002h"))
        check("mouse capture enabled at boot", has_enable,
              "no mouse-enable sequence in boot stream")
        # Type a prompt so the transcript has content, then drag across it.
        sb.type("hello world test")
        sb.key("enter")
        # Wait for the stream to finish so the transcript has text to
        # select (dragging during streaming selects empty rows).
        end = time.time() + 25
        while time.time() < end:
            r = sb.read(0.3)
            if "done" in sb.clean(r).lower():
                break
        time.sleep(1.0)
        # Drag from (col 30, row 3) to (col 55, row 5) inside the center
        # pane. Rows are 1-based screen rows; the header row (row 1) means
        # transcript content starts one row lower than the pre-header
        # layout (the old coordinates 2-4 now hit the pane border).
        # SGR mouse: ESC [ < button ; col ; row M/A
        def sgr(button, col, row, release=False):
            m = "m" if release else "M"
            sb.write(f"\x1b[<{button};{col};{row}{m}".encode())
        sgr(0, 30, 3)           # button 0 = left press (transcript row 3)
        sgr(32, 40, 4)          # drag (button 32 = left held)
        sgr(32, 55, 5)          # drag
        sgr(0, 55, 5, True)     # release
        time.sleep(1.0)
        raw = sb.read(2.0)
        # OSC 52 should appear (selection copy).
        has_osc52 = "\x1b]52;c;" in raw
        check("selection copies via OSC 52", has_osc52,
              "no OSC 52 sequence after drag-release")
        sb.key("ctrl+d")
        time.sleep(0.5)

    # ── 8. SIGHUP → clean exit ─────────────────────────────────────────────


    print("\n== SIGHUP test ==")
    s5 = PtySession(
        [args.binary, "--home", args.home, "--model", args.model],
        env=env, timeout=20, rows=30, cols=100,
    )
    ok, _ = s5.wait_for("ORBIT", timeout=15)
    check("boots TUI for SIGHUP test", ok)
    if ok:
        os.kill(s5.proc.pid, signal.SIGHUP)
        time.sleep(1.5)
        exited = s5.proc.poll() is not None
        check("SIGHUP exits cleanly", exited, "still running")
        if not exited:
            s5.terminate()

    # ── 9. Resize → no crash ───────────────────────────────────────────────
    print("\n== Resize test ==")
    s4 = PtySession(
        [args.binary, "--home", args.home, "--model", args.model],
        env=env, timeout=20, rows=30, cols=100,
    )
    ok, _ = s4.wait_for("ORBIT", timeout=15)
    check("boots TUI for resize test", ok)
    if ok:
        s4.resize(24, 80)
        time.sleep(1.0)
        s4.resize(40, 120)
        time.sleep(1.0)
        buf = s4.read(2.0)
        check("resize survives", s4.proc.poll() is None, buf[-200:])
        s4.key("ctrl+d")
        time.sleep(1.0)
        try:
            s4.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            s4.terminate()

    # Cleanup the mock only if we started it.
    if mock_proc is not None:
        mock_proc.terminate()
        mock_proc.wait(timeout=3)

    print(f"\n== Results: {PASS} passed, {FAIL} failed ==")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()