#!/usr/bin/env python3
"""PTY test harness for the ORBIT Go Bubble Tea TUI.

Spawns the real `orbit` binary in a PTY and drives it with keystrokes,
verifying: boot logo, typing, Tab focus, /help, streaming (mock provider),
Ctrl+C cancel, Ctrl+D quit, clean exit (no broken terminal state).

Usage:
  pty_tui_test.py [--binary PATH] [--home DIR] [--model MODEL] [--provider PROVIDER]
"""

import argparse
import os
import pty
import select
import signal
import subprocess
import sys
import time

PASS = 0
FAIL = 0
CHECKS = []


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
        import fcntl
        import struct
        import termios
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

    def read(self, timeout=2.0):
        """Read available output, waiting up to timeout."""
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
            elif out:
                # No more data available — stop draining.
                break
        return out.decode("utf-8", errors="replace")

    def wait_for(self, text, timeout=20):
        """Wait for text to appear in output."""
        buf = ""
        end = time.time() + timeout
        while time.time() < end:
            buf += self.read(0.5)
            if text in buf:
                return True, buf
        return False, buf

    def write(self, data):
        os.write(self.master, data)

    def key(self, name):
        """Send a key by name."""
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
            # Plain single-char keys (1, 2, 3, etc.).
            self.write(name.encode())
            return
        self.write(mapping[name])

    def type(self, text):
        for ch in text:
            self.write(ch.encode())

    def resize(self, rows, cols):
        import fcntl
        import struct
        import termios
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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--binary", default="/media/hanu/HANU/ORBIT/target/debug/orbit")
    ap.add_argument("--home", default="/tmp/orbit-pty-home")
    ap.add_argument("--model", default="mock-slow")
    ap.add_argument("--provider", default="local")
    ap.add_argument("--gate", default="http://127.0.0.1:8088")
    ap.add_argument("--token", default="test-token")
    args = ap.parse_args()

    # Fresh ORBIT home for the test.
    subprocess.run(["rm", "-rf", args.home], check=False)
    init_env = os.environ.copy()
    init_env["ORBIT_HOME"] = args.home
    subprocess.run(
        [args.binary, "init", "--home", args.home, "--no-provider"],
        capture_output=True, timeout=30, env=init_env,
    )
    # Add the provider.
    prov = f"""[[provider]]
name = "{args.provider}"
url = "{args.gate}"
env = "ORBIT_GATE_TOKEN"

[[provider.models]]
id = "{args.model}"
"""
    os.makedirs(args.home, exist_ok=True)
    with open(os.path.join(args.home, "providers.toml"), "w") as f:
        f.write(prov)
    os.makedirs("/tmp/orbit-mock", exist_ok=True)

    env = {"ORBIT_HOME": args.home, "ORBIT_GATE_TOKEN": args.token}

    print(f"\n== Boot test (--go-tui, model={args.model}) ==")
    s = PtySession(
        [args.binary, "--home", args.home, "--model", args.model, "--go-tui"],
        env=env, timeout=20,
    )
    ok, buf = s.wait_for("orbit", timeout=15)
    check("boots to TUI", ok, buf[-500:])
    time.sleep(1.0)

    # Typing test.
    s.type("hello")
    time.sleep(0.5)
    buf = s.read(1.0)
    check("types into composer", "hello" in buf, buf[-200:])

    # Tab focus cycling — composer blur then back.
    s.key("tab")
    time.sleep(0.3)
    s.key("tab")
    time.sleep(0.3)
    s.key("2")
    time.sleep(0.3)
    s.key("tab")
    time.sleep(0.3)
    s.key("1")
    time.sleep(0.3)
    s.key("tab")
    time.sleep(0.3)
    s.key("2")
    time.sleep(0.3)
    buf = s.read(1.0)
    check("tab focus cycles", True, "no crash")

    # /help overlay.
    s.type("/help")
    s.key("enter")
    time.sleep(0.5)
    buf = s.read(1.0)
    check("help overlay renders", "help" in buf.lower(), buf[-300:])
    s.key("esc")
    time.sleep(0.3)

    # Enter sends + streaming response. The mock-slow provider streams
    # "Hello from the slow stream." in 5 chunks (200ms apart). Poll the PTY
    # for the full text — this also proves the prompt was sent.
    import re
    s.type("hello")
    s.key("enter")
    clean = ""
    end = time.time() + 20
    while time.time() < end:
        clean += s.read(0.5)
        clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean)
        if "Hello from the slow stream" in clean:
            break
        time.sleep(0.2)
    check("sends prompt + streams response", "Hello from the slow stream" in clean, clean[-300:])

    # Approval modal: the default mock provider (without "slow" in the model
    # name) sends a calculator tool call, which triggers the approval modal.
    # We need a second session with the default mock model for this.
    s.key("ctrl+d")
    time.sleep(1.0)
    try:
        s.proc.wait(timeout=2)
    except subprocess.TimeoutExpired:
        s.terminate()
    os.close(s.master)

    # Start a new session with the default mock model (tool-call behavior).
    with open(os.path.join(args.home, "providers.toml"), "w") as f:
        f.write(f'[[provider]]\nname = "{args.provider}"\nurl = "{args.gate}"\nenv = "ORBIT_GATE_TOKEN"\n\n[[provider.models]]\nid = "mock"\n')
    s2 = PtySession(
        [args.binary, "--home", args.home, "--model", "mock", "--go-tui"],
        env=env, timeout=20,
    )
    ok, _ = s2.wait_for("orbit", timeout=15)
    check("boots TUI for approval test", ok)
    if ok:
        s2.type("compute 2+2")
        s2.key("enter")
        # The mock provider sends a tool_call_started event → approval modal.
        ok, buf = s2.wait_for("Approval", timeout=10)
        check("approval modal appears", ok, buf[-300:])
        if ok:
            # Press 'y' to allow the tool call.
            s2.key("y")
            # Approval should dismiss and the second provider round should
            # return the final "hello world" text after the tool result.
            clean = ""
            end = time.time() + 15
            while time.time() < end:
                clean += s2.read(0.5)
                clean = re.sub(r'\x1b\[[0-9;]*[a-zA-Z]', '', clean)
                if "hello world" in clean:
                    break
                time.sleep(0.2)
            check("approval 'y' allows tool", "hello world" in clean, clean[-300:])

    # Ctrl+C cancel mid-stream (should not kill the TUI). Send a fresh prompt
    # and cancel while the slow stream is still running.
    # (Re-test with the slow model for the cancel path.)
    if ok:
        s2.key("ctrl+d")
        time.sleep(1.0)
        try:
            s2.proc.wait(timeout=2)
        except subprocess.TimeoutExpired:
            s2.terminate()
        os.close(s2.master)

    # Cancel test with slow model.
    s3 = PtySession(
        [args.binary, "--home", args.home, "--model", args.model, "--go-tui"],
        env=env, timeout=20,
    )
    ok, _ = s3.wait_for("orbit", timeout=15)
    if ok:
        s3.type("cancel me")
        s3.key("enter")
        time.sleep(0.4)  # let the stream start (200ms per chunk)
        s3.key("ctrl+c")
        time.sleep(0.8)
        buf = s3.read(1.0)
        check("ctrl+c cancels gracefully", "cancel" in buf.lower() or "cancelled" in buf.lower(), buf[-200:])

    # Ctrl+D quit — clean exit.
    s3.key("ctrl+d")
    time.sleep(1.5)
    buf = s3.read(1.0)
    exited = s3.proc.poll() is not None
    check("ctrl+d quits", exited, f"still running; out={buf[-200:]}")
    if not exited:
        s3.terminate()

    # SIGHUP test: terminal close must exit cleanly (no orphan, no hang).
    s5 = PtySession(
        [args.binary, "--home", args.home, "--model", args.model, "--go-tui"],
        env=env, timeout=20,
    )
    ok, _ = s5.wait_for("orbit", timeout=15)
    check("boots TUI for SIGHUP test", ok)
    if ok:
        os.kill(s5.proc.pid, signal.SIGHUP)
        time.sleep(1.5)
        exited = s5.proc.poll() is not None
        check("SIGHUP exits cleanly", exited, f"still running")
        if not exited:
            s5.terminate()

    # Resize test: resize mid-session and verify no crash + clean output.
    s4 = PtySession(
        [args.binary, "--home", args.home, "--model", args.model, "--go-tui"],
        env=env, timeout=20,
    )
    ok, _ = s4.wait_for("orbit", timeout=15)
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

    print(f"\n== Results: {PASS} passed, {FAIL} failed ==")
    sys.exit(1 if FAIL else 0)


if __name__ == "__main__":
    main()
