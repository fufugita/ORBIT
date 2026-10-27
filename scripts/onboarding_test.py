#!/usr/bin/env python3
"""Current-binary provider onboarding acceptance; run inside scripts/in-jail.sh.

Each receipt names an executed workflow, with fresh private homes and a local
HTTP fixture. This script never builds or invokes an installed orbit binary.
"""
import argparse
import errno
import fcntl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import re
import select
import shlex
import signal
import socket
import stat
import struct
import subprocess
import tempfile
import termios
import threading
import time
import tomllib
import unicodedata
from urllib.parse import parse_qs, urlsplit


# Longer than the terminal reader's former 256-byte allocation: both success
# and cancellation exercise the full-bound hidden buffer, without echo.
SECRET = "skP7319Q-synthetic-private-onboarding-" + "k" * 1024 + "-736490152"
OVERRIDE = "ovR6258Z-synthetic-explicit-env-override-825194"
OLD_ENV = "oldN481K-synthetic-old-reference-must-not-serve-972846"
MODEL = "family/vendor/raw-model"
PROMPTS = {
    "provider": b"Provider (name or number): ",
    "name": b"Provider name", "replace": b"Replace this existing provider?",
    "kind": b"Adapter kind (openai-compatible/anthropic/ollama)",
    "url": b"Base URL", "auth": b"Authentication method: ",
    "env": b"Credential ENV name", "key": b"API key (hidden): ",
    "source": b"Model source (manual/discover)", "models": b"Raw model IDs (comma-separated): ",
    "schema": b"Discovery schema (generic/openrouter)",
    "select": b"Select model numbers (comma-separated), next, prev, filter TEXT, manual, or cancel",
    "partial": b"Catalog is incomplete. Use partial results?",
    "default": b"Set main default? (yes/no): ", "main": b"Main model ID: ",
    "replace_main": b"Replace main default?", "confirm": b"Save provider configuration?",
}


def advertised(model=MODEL, context=32000, output=4000):
    return {"id": model, "context_length": context,
            "top_provider": {"max_completion_tokens": output}}


class ProviderServer:
    """Owned numeric-loopback service with finite requests and joined workers."""
    def __init__(self, calls):
        self.calls = calls
        self.routes = {}
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.active = 0
        self.errors = []
        owner = self

        class Provider(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def setup(self):
                super().setup()
                self.connection.settimeout(2)

            def do_GET(self):
                owner.respond(self, "GET")

            def do_POST(self):
                owner.respond(self, "POST")

            def log_message(self, *_):
                pass

        class OwnedServer(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True

        self.server = OwnedServer(("127.0.0.1", 0), Provider)
        self.origin = f"http://127.0.0.1:{self.server.server_port}"
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05})

    def __enter__(self):
        try:
            self.thread.start()
        except BaseException:
            self.server.server_close()
            raise
        return self

    def __exit__(self, *_):
        self.stopping.set()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        assert not self.thread.is_alive(), "local fixture server did not stop"
        assert self.active == 0, "fixture request worker did not stop"
        assert not self.errors, "fixture request worker failed"

    def route(self, path, body=None, status=200, headers=None, delay=0):
        assert path.startswith("/") and 0 <= delay <= 3
        encoded = json.dumps(body).encode() if isinstance(body, (dict, list)) else body
        if encoded is None:
            encoded = b""
        if isinstance(encoded, str):
            encoded = encoded.encode()
        assert len(encoded) <= 4 * 1024 * 1024 + 1024
        with self.lock:
            self.routes[path] = (status, encoded, headers or {}, delay)

    def reset(self):
        self.wait_idle()
        with self.lock:
            self.routes.clear()

    def wait_idle(self, timeout=4):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                if self.active == 0:
                    return
            time.sleep(0.01)
        raise AssertionError("fixture request worker exceeded its deadline")

    def wait_call(self, after, method="GET", timeout=3):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            with self.lock:
                matches = [call for call in self.calls[after:] if call["method"] == method]
            if matches:
                return matches[0]
            time.sleep(0.01)
        raise AssertionError("owned provider did not receive the expected request")

    def respond(self, handler, method):
        with self.lock:
            self.active += 1
        try:
            body = None
            if method == "POST":
                size = int(handler.headers.get("Content-Length", "0"))
                assert 0 < size <= 128 * 1024, "fixture request body bound"
                raw = handler.rfile.read(size)
                assert len(raw) == size, "truncated fixture request"
                body = json.loads(raw)
            call = {"method": method, "path": handler.path,
                    "auth": handler.headers.get("Authorization"),
                    "api_key": handler.headers.get("x-api-key"),
                    "anthropic_version": handler.headers.get("anthropic-version"),
                    "response_started": False}
            if body is not None:
                call["body"] = body
            with self.lock:
                self.calls.append(call)
                route = self.routes.get(handler.path)
            if route is not None:
                status, content, headers, delay = route
            elif method == "GET" and urlsplit(handler.path).path in ("/v1/models", "/tenant/v1/models"):
                status, content, headers, delay = 200, json.dumps({"data": [advertised()]}).encode(), {}, 0
            elif method == "GET":
                status, content, headers, delay = 404, b'{"error":"unknown fixture path"}', {}, 0
            else:
                events = [
                    {"choices": [{"index": 0, "delta": {"content": "onboarding fixture reply"}, "finish_reason": None}]},
                    {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": 2, "completion_tokens": 3}},
                ]
                content = b"".join(("data: " + json.dumps(event) + "\n\n").encode() for event in events)
                content += b"data: [DONE]\n\n"
                status, headers, delay = 200, {"Content-Type": "text/event-stream"}, 0
            if self.stopping.wait(delay):
                return
            with self.lock:
                call["response_started"] = True
            handler.send_response(status)
            handler.send_header("Content-Type", headers.get("Content-Type", "application/json"))
            handler.send_header("Content-Length", str(len(content)))
            handler.send_header("Connection", "close")
            for name, value in headers.items():
                if name.lower() not in ("content-type", "content-length", "connection"):
                    handler.send_header(name, value)
            handler.end_headers()
            handler.wfile.write(content)
            handler.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, TimeoutError, OSError):
            # Cancellation deliberately closes a real in-flight HTTP connection.
            pass
        except Exception as error:
            with self.lock:
                self.errors.append(type(error).__name__)
        finally:
            handler.close_connection = True
            with self.lock:
                self.active -= 1


def snapshot(home):
    return {str(path.relative_to(home)): path.read_bytes()
            for path in sorted(home.rglob("*")) if path.is_file() and not path.is_symlink()}


def identity(home):
    return {name: data for name, data in snapshot(home).items()
            if name.startswith(("trust/", "ledger/")) or name == "pib.json"}


def immutable_identity(home):
    return {name: data for name, data in snapshot(home).items()
            if name.startswith("trust/") or name == "pib.json"}


def private_write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(text.encode() if isinstance(text, str) else text)
    path.chmod(0o600)


class Terminal:
    def __init__(self, fixture, home, args=("setup",), extra_env=None, size=(100, 32)):
        self.fixture = fixture
        self.master, self.slave = pty.openpty()
        self.initial = termios.tcgetattr(self.slave)
        self.resize(*size)
        self.output = bytearray()
        self.cursor = 0
        self.process = subprocess.Popen(
            [str(fixture.binary), "--home", str(home), *args],
            cwd=fixture.work, env=fixture.env(home, extra_env),
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            start_new_session=True, close_fds=True,
        )

    def resize(self, columns, rows):
        assert 0 <= columns <= 300 and 0 <= rows <= 120
        fcntl.ioctl(self.slave, termios.TIOCSWINSZ,
                    struct.pack("HHHH", rows, columns, 0, 0))
        if hasattr(self, "process") and self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGWINCH)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            os.killpg(self.process.pid, signal.SIGKILL)
            self.process.wait(timeout=3)
        os.close(self.master)
        os.close(self.slave)

    def read(self, duration=0.1):
        ready, _, _ = select.select([self.master], [], [], duration)
        if ready:
            try:
                data = os.read(self.master, 16384)
            except OSError as error:
                if error.errno == errno.EIO:
                    return
                raise
            self.output.extend(data)
            assert len(self.output) <= 256 * 1024, "unbounded terminal output"

    def expect(self, prompt, timeout=12):
        wanted = PROMPTS.get(prompt, prompt)
        if isinstance(wanted, str):
            wanted = wanted.encode()
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            found = self.output.find(wanted, self.cursor)
            if found >= 0:
                self.cursor = found + len(wanted)
                return
            if self.process.poll() is not None:
                self.read(0)
                raise AssertionError("current binary exited before the expected onboarding prompt")
            self.read()
        raise AssertionError("onboarding prompt deadline exceeded")

    def send(self, value):
        raw = value if isinstance(value, bytes) else value.encode() + b"\n"
        offset = 0
        deadline = time.monotonic() + 5
        while offset < len(raw):
            assert time.monotonic() < deadline, "terminal write deadline exceeded"
            _, ready, _ = select.select([], [self.master], [], 0.1)
            if ready:
                offset += os.write(self.master, raw[offset:offset + 1024])

    def answer(self, prompt, value):
        self.expect(prompt)
        self.send(value)

    def finish(self, success=True):
        deadline = time.monotonic() + 15
        while self.process.poll() is None and time.monotonic() < deadline:
            self.read()
        assert self.process.poll() is not None, "onboarding child did not terminate"
        for _ in range(3):
            self.read(0.02)
        code = self.process.wait(timeout=1)
        assert (code == 0) == success, "unexpected onboarding exit status"
        assert termios.tcgetattr(self.slave) == self.initial, "terminal attributes were not restored"
        self.fixture.assert_no_secrets(self.output)
        return bytes(self.output)


class Fixture:
    def __init__(self, binary, root, calls, endpoint, server):
        self.binary, self.root, self.calls, self.endpoint = binary, root, calls, endpoint
        self.server = server
        self.work = root / "workspace"
        self.work.mkdir(mode=0o700)
        self.serial = 0

    def home(self):
        self.serial += 1
        return self.root / f"orbit-home-{self.serial}"

    def env(self, home, extra=None):
        # An allowlist excludes gateway, model, proxy, harness, and credential ENV.
        result = {"PATH": os.defpath, "HOME": str(self.root), "ORBIT_HOME": str(home),
                  "XDG_CONFIG_HOME": str(self.root / "xdg"), "LANG": "C.UTF-8",
                  "TERM": "xterm-256color", "NO_COLOR": "1", "RUST_BACKTRACE": "0"}
        if extra:
            for name, value in extra.items():
                if value is None:
                    result.pop(name, None)
                else:
                    result[name] = value
        return result

    @staticmethod
    def assert_no_secrets(value):
        data = value.encode() if isinstance(value, str) else bytes(value)
        for secret in (SECRET, OVERRIDE, OLD_ENV):
            assert secret.encode() not in data and secret[:8].encode() not in data, "synthetic credential or identifying prefix leaked"

    def run(self, home, *args, success=True, extra_env=None, input_text=""):
        result = subprocess.run([str(self.binary), "--home", str(home), *args],
                                cwd=self.work, env=self.env(home, extra_env), input=input_text,
                                text=True, capture_output=True, timeout=30)
        if success is None:
            assert result.returncode in (0, 1), "unexpected diagnostic exit status"
        else:
            assert (result.returncode == 0) == success, "unexpected redirected-command exit status"
        self.assert_no_secrets(result.stdout + result.stderr)
        assert len((result.stdout + result.stderr).encode()) <= 256 * 1024
        return result

    def config(self, home):
        return tomllib.loads((home / "providers.toml").read_text())

    def assert_public_private(self, home):
        for name, data in snapshot(home).items():
            if not name.startswith("auth/"):
                self.assert_no_secrets(data)
        for path in (home / "auth").rglob("*"):
            assert not path.is_symlink(), "private auth symlink"
            assert stat.S_IMODE(path.stat().st_mode) == (0o700 if path.is_dir() else 0o600)

    def through_auth(self, session, name="fixture", auth="key", replacement=False,
                     endpoint=None, env_name="FIXTURE_PROVIDER_KEY", kind="openai-compatible"):
        session.answer("provider", "custom")
        session.answer("name", name)
        if replacement:
            session.answer("replace", "yes")
        session.answer("kind", kind)
        session.answer("url", endpoint or self.endpoint)
        session.answer("auth", auth)
        if auth in ("env", "key-env"):
            session.answer("env", env_name)
        if auth in ("key", "key-env"):
            session.answer("key", SECRET)

    def through_models(self, session, name="fixture", auth="key", replacement=False,
                       model=MODEL, endpoint=None, env_name="FIXTURE_PROVIDER_KEY"):
        self.through_auth(session, name, auth, replacement, endpoint, env_name)
        session.answer("source", "manual")
        session.answer("models", model)

    def discovery_start(self, session, name="fixture", auth="key", replacement=False,
                        endpoint=None, env_name="FIXTURE_PROVIDER_KEY", kind="openai-compatible",
                        schema="openrouter"):
        self.through_auth(session, name, auth, replacement, endpoint, env_name, kind)
        session.answer("source", "discover")
        if kind == "openai-compatible":
            session.answer("schema", schema)

    def discovery_wizard(self, home, name="fixture", auth="key", args=("setup",),
                         replacement=False, endpoint=None, env_name="FIXTURE_PROVIDER_KEY",
                         kind="openai-compatible", schema="openrouter", choices=("1",),
                         default=True, main=MODEL, replace_main=False, extra_env=None,
                         partial=None, manual_fallback=None):
        before = len(self.calls)
        baseline = snapshot(home) if home.exists() else None
        with Terminal(self, home, args, extra_env) as session:
            self.discovery_start(session, name, auth, replacement, endpoint, env_name, kind, schema)
            if partial is not None:
                session.answer("partial", "yes" if partial else "no")
            if manual_fallback is None:
                for choice in choices:
                    session.answer("select", choice)
            else:
                session.answer("models", manual_fallback)
            session.answer("default", "yes" if default else "no")
            if default:
                session.answer("main", main)
            if replace_main:
                session.answer("replace_main", "yes")
            session.expect("confirm")
            if baseline is None:
                assert not home.exists(), "discovery published before confirmation"
            else:
                assert snapshot(home) == baseline, "discovery changed existing files before confirmation"
            session.send("yes")
            output = session.finish()
        self.server.wait_idle()
        self.assert_public_private(home)
        return output, self.calls[before:]

    def wizard(self, home, name="fixture", auth="key", args=("setup",), replacement=False,
               model=MODEL, default=True, replace_main=False, extra_env=None):
        before = len(self.calls)
        with Terminal(self, home, args, extra_env) as session:
            self.through_models(session, name, auth, replacement, model)
            session.answer("default", "yes" if default else "no")
            if default:
                session.answer("main", model.split(",")[0])
            if replace_main:
                session.answer("replace_main", "yes")
            session.answer("confirm", "yes")
            output = session.finish()
        assert len(self.calls) == before, "manual setup contacted a provider"
        return output

    def request(self, home, extra_env=None, model=MODEL, select_model=False):
        before = len(self.calls)
        args = ["-p", "onboarding restart fixture", "--max-turns", "1"]
        if select_model:
            args += ["--model", "fixture/" + model]
        self.run(home, *args, extra_env=extra_env)
        new = self.calls[before:]
        assert len(new) == 1 and new[0]["method"] == "POST", "expected one actual provider request"
        assert new[0]["body"].get("model") == model, "raw default model changed on dispatch"
        return new[0]

    def assert_ledger_continuation(self, home, before):
        old = {name: data for name, data in before.items()
               if name.startswith("ledger/segments/") and name.endswith(".log")}
        new = {name: data for name, data in snapshot(home).items()
               if name.startswith("ledger/segments/") and name.endswith(".log")}
        assert old and all(name in new and new[name].startswith(data) for name, data in old.items()), "request rewrote prior ledger frames"
        assert sum(map(len, new.values())) > sum(map(len, old.values())), "actual request did not continue the ledger"
        request_count = len(self.calls)
        report = json.loads(self.run(home, "doctor", "--json", success=None).stdout)["report"]
        assert any(check["id"] == "ledger" and check["status"] == "ready" for check in report["checks"]), "continued ledger did not validate"
        assert len(self.calls) == request_count, "ledger diagnostics contacted a provider"


def manual_cases(f, passed):
    home = f.home()
    output = f.wizard(home, auth="env", model=MODEL + ",second/raw")
    cfg = f.config(home)
    assert cfg["roles"]["main"] == "fixture/" + MODEL
    assert [m["id"] for m in cfg["provider"][0]["models"]] == [MODEL, "second/raw"]
    assert b"missing" in output and not (home / "auth").exists()
    passed("fresh_terminal_custom_env_and_raw_models")

    old_identity = identity(home)
    f.wizard(home, auth="env", replacement=True, default=False)
    assert identity(home) == old_identity
    assert len(f.config(home)["provider"][0]["models"]) == 2
    passed("repeated_terminal_setup_preserves_identity_and_models")

    add_home = f.home()
    f.wizard(add_home, auth="none", args=("provider", "add"))
    assert f.config(add_home)["roles"]["main"] == "fixture/" + MODEL
    passed("provider_add_reaches_shared_wizard")

    for args in [("setup",), ("setup", "--json"), ("--json", "setup")]:
        redirected = f.home()
        result = f.run(redirected, *args)
        assert "Authentication (" not in result.stdout + result.stderr
        assert (redirected / "pib.json").exists()
    passed("redirected_and_json_setup_are_prompt_free")

    for args in [("setup", "--unknown"), ("setup", "--no-provider", "--no-provider"),
                 ("setup", "--interactive-provider", "--no-provider"),
                 ("setup", "--interactive-provider", "--dry-run"),
                 ("setup", "--interactive-provider", "--json"),
                 ("setup", "--api-key", SECRET)]:
        untouched = f.home()
        f.run(untouched, *args, success=False)
        assert not untouched.exists()
    passed("invalid_or_conflicting_modes_refuse_before_home")


def private_cases(f, passed):
    relative_home = Path(".orbit-relative")
    f.wizard(relative_home)
    home = f.work / relative_home
    assert home.is_dir(), "relative --home did not resolve within the owned workspace"
    f.assert_public_private(home)
    assert f.request(home)["auth"] == "Bearer " + SECRET
    passed("hidden_key_is_private_and_default_auth_survives_restart")

    reference = f.config(home)["provider"][0]["env"]
    records = {k: v for k, v in snapshot(home).items() if k.startswith("auth/")}
    assert f.request(home, {reference: OVERRIDE})["auth"] == "Bearer " + OVERRIDE
    assert f.request(home)["auth"] == "Bearer " + SECRET
    assert {k: v for k, v in snapshot(home).items() if k.startswith("auth/")} == records
    passed("exact_declared_env_override_precedes_saved_key_without_rewriting_it")

    replace = f.home()
    f.wizard(replace, auth="env", extra_env={"FIXTURE_PROVIDER_KEY": OLD_ENV})
    old_identity = identity(replace)
    f.wizard(replace, replacement=True, default=False, extra_env={"FIXTURE_PROVIDER_KEY": OLD_ENV})
    assert f.config(replace)["provider"][0]["env"].startswith("ORBIT_AUTH_")
    # Setup preserves the complete ledger; a later real request must append it.
    assert identity(replace) == old_identity
    immutable = immutable_identity(replace)
    before_request = snapshot(replace)
    assert f.request(replace, {"FIXTURE_PROVIDER_KEY": OLD_ENV})["auth"] == "Bearer " + SECRET
    assert immutable_identity(replace) == immutable
    f.assert_ledger_continuation(replace, before_request)
    passed("fresh_private_reference_replaces_old_populated_env_binding")

    noauth = f.home()
    f.wizard(noauth, auth="none", extra_env={"ORBIT_GATE_TOKEN": OLD_ENV, "OPENAI_API_KEY": OVERRIDE})
    assert f.request(noauth, {"ORBIT_GATE_TOKEN": OLD_ENV, "OPENAI_API_KEY": OVERRIDE})["auth"] is None
    assert not (noauth / "auth").exists()
    passed("explicit_no_auth_ignores_ambient_gateway_credentials")

    preserved = f.home()
    f.wizard(preserved, auth="none", model="old/raw")
    text = (preserved / "providers.toml").read_text()
    text += '\n[unrelated]\nkeep="preserved"\n'
    text = text.replace('main = "fixture/old/raw"', 'main = "fixture/old/raw"\nsubagent = "fixture/old/raw"')
    private_write(preserved / "providers.toml", text)
    old_identity = identity(preserved)
    f.wizard(preserved, name="second", auth="none", replace_main=True)
    cfg = f.config(preserved)
    assert cfg["roles"]["main"] == "second/" + MODEL and cfg["roles"]["subagent"] == "fixture/old/raw"
    assert cfg["unrelated"]["keep"] == "preserved" and cfg["provider"][0]["models"][0]["id"] == "old/raw"
    assert identity(preserved) == old_identity
    assert f.request(preserved)["auth"] is None
    passed("explicit_default_replacement_preserves_other_provider_roles_and_identity")

    missing = f.home()
    f.wizard(missing, auth="env")
    before = len(f.calls)
    f.run(missing, "-p", "must not dispatch", "--max-turns", "1", success=False)
    assert len(f.calls) == before and not (missing / "auth").exists()
    passed("missing_declared_env_refuses_before_request_after_restart")

    wire = f.home()
    f.wizard(wire, auth="none")
    model = f.config(wire)["provider"][0]["models"][0]
    assert "supported_efforts" not in model and "default_effort" not in model
    request = f.request(wire)
    assert "reasoning_effort" not in request["body"] and "reasoning" not in request["body"]
    passed("manual_unknown_effort_stays_unknown_and_omitted_on_wire")

    env_home = f.home()
    f.wizard(env_home, auth="env", extra_env={"FIXTURE_PROVIDER_KEY": OVERRIDE})
    assert not (env_home / "auth").exists()
    assert f.request(env_home, {"FIXTURE_PROVIDER_KEY": OVERRIDE})["auth"] == "Bearer " + OVERRIDE
    passed("env_reference_and_default_are_used_without_repeated_provider_flags")


def preservation_cases(f, passed):
    untouched = f.home()
    with Terminal(f, untouched) as session:
        session.expect("provider")
        session.send(b"\x03")
        session.finish(False)
    assert not untouched.exists()
    passed("ctrl_c_at_first_prompt_preserves_home_absence")

    def at_hidden(session):
        session.answer("provider", "custom")
        session.answer("name", "fixture")
        session.answer("kind", "openai-compatible")
        session.answer("url", f.endpoint)
        session.answer("auth", "key")
        session.expect("key")

    hidden = f.home()
    with Terminal(f, hidden) as session:
        at_hidden(session)
        session.send(SECRET.encode()[:768] + b"\x03")
        output = session.finish(False)
        assert SECRET.encode()[:768] not in output, "long partial hidden key echoed"
    assert not hidden.exists()
    passed("ctrl_c_during_hidden_key_restores_terminal_without_publication")

    existing = f.home()
    f.wizard(existing)
    before = snapshot(existing)
    with Terminal(f, existing) as session:
        session.answer("provider", "custom")
        session.answer("name", "second")
        session.answer("kind", "openai-compatible")
        session.answer("url", f.endpoint)
        session.answer("auth", "key")
        session.expect("key")
        session.send(b"\x04")
        session.finish(False)
    assert snapshot(existing) == before
    passed("eof_during_hidden_key_preserves_existing_identity_config_and_records")

    with Terminal(f, existing) as session:
        f.through_models(session, name="second")
        session.answer("default", "no")
        session.answer("confirm", "no")
        session.finish(False)
    assert snapshot(existing) == before
    passed("final_decline_after_private_key_preserves_exact_existing_bytes")

    with Terminal(f, existing) as session:
        session.answer("provider", "custom")
        session.answer("name", "fixture")
        session.answer("replace", "no")
        session.finish(False)
    assert snapshot(existing) == before
    passed("provider_replacement_decline_does_not_read_secret_or_rebind")

    with Terminal(f, existing) as session:
        f.through_models(session, name="second", auth="none")
        session.answer("default", "yes")
        session.answer("main", MODEL)
        session.answer("replace_main", "no")
        session.finish(False)
    assert snapshot(existing) == before
    passed("default_replacement_decline_preserves_exact_existing_bytes")

    with Terminal(f, existing) as session:
        f.through_models(session, name="second")
        session.answer("default", "no")
        session.expect("confirm")
        config = existing / "providers.toml"
        private_write(config, config.read_bytes() + b'\n[concurrent]\nkeep = true\n')
        concurrent = snapshot(existing)
        session.send("yes")
        session.finish(False)
    assert snapshot(existing) == concurrent
    passed("concurrent_revision_change_refuses_before_new_private_record")

    signaled = f.home()
    with Terminal(f, signaled) as session:
        at_hidden(session)
        os.kill(session.process.pid, signal.SIGTERM)
        session.finish(False)
    assert not signaled.exists()
    passed("sigterm_during_hidden_input_restores_terminal_and_cancels")

    for endpoint in ["relative/path", "https://example.invalid?api_key=synthetic", "https://user:password@example.invalid"]:
        invalid = f.home()
        with Terminal(f, invalid) as session:
            session.answer("provider", "custom")
            session.answer("name", "fixture")
            session.answer("kind", "openai-compatible")
            session.answer("url", endpoint)
            session.answer(b"Correct this field: ", "cancel")
            output = session.finish(False)
        assert not invalid.exists() and PROMPTS["key"] not in output
    passed("invalid_endpoint_refuses_before_hidden_input_and_home_creation")

    invalid_model = f.home()
    with Terminal(f, invalid_model) as session:
        f.through_models(session, model="duplicate,duplicate")
        session.answer(b"Correct this field: ", "cancel")
        session.finish(False)
    assert not invalid_model.exists()
    passed("invalid_model_after_hidden_key_refuses_before_publication")

    oversize = f.home()
    with Terminal(f, oversize) as session:
        at_hidden(session)
        session.send(b"x" * (16 * 1024 + 1) + b"\n")
        session.answer(b"Correct this field: ", "cancel")
        session.finish(False)
    assert not oversize.exists()
    passed("oversized_hidden_input_is_bounded_and_restores_terminal")

    for args in [("setup", "--no-provider"), ("init", "--no-provider"), ("setup", "--json")]:
        offline = f.home()
        with Terminal(f, offline, args) as session:
            output = session.finish()
        assert PROMPTS["auth"] not in output and (offline / "pib.json").exists()
    dry = f.home()
    f.run(dry, "setup", "--dry-run", "--json")
    assert not dry.exists()
    repair = f.run(existing, "setup", "repair", "--dry-run", "--json")
    assert json.loads(repair.stdout)["status"] == "dry_run" and snapshot(existing) == concurrent
    guided = f.home()
    with Terminal(f, guided, ("setup", "--guided")) as session:
        session.answer(b"Provider name: ", "")
        output = session.finish()
    assert b"Offline setup" in output and PROMPTS["auth"] not in output
    passed("explicit_offline_guided_dry_run_repair_and_json_modes_remain_deterministic")


def only_get(calls, count=1, auth=None):
    assert len(calls) == count and all(call["method"] == "GET" for call in calls), "unexpected catalog request count"
    assert all(call["auth"] == auth for call in calls), "catalog used the wrong bound credential"


def configured_model(f, home, model=MODEL):
    return next(entry for entry in f.config(home)["provider"][0]["models"] if entry["id"] == model)


def refresh(f, home, schema="openrouter", extra_env=None):
    before = len(f.calls)
    result = f.run(home, "provider", "refresh", "fixture", "--schema", schema, "--json", extra_env=extra_env)
    report = json.loads(result.stdout)
    assert report.get("schema") == "orbit.cli/v1" and report.get("command") == "provider refresh"
    assert report.get("status") == "ok" and report.get("offline") is False, "refresh did not report a successful online action"
    return f.calls[before:]


def assert_unknown_effort(model, body):
    assert model.get("supported_efforts") is None and model.get("default_effort") is None
    assert all(field not in body for field in ("reasoning_effort", "reasoning", "thinking")), "unknown effort acquired a wire control"


def discovery_tracer_cases(f, passed):
    f.server.reset()
    home = f.home()
    output, calls = f.discovery_wizard(home)
    only_get(calls, auth="Bearer " + SECRET)
    assert calls[0]["path"] == "/v1/models"
    model = configured_model(f, home)
    assert model["context_window"] == 32000 and model["max_output_tokens"] == 4000
    assert f.config(home)["roles"]["main"] == "fixture/" + MODEL
    assert f.request(home)["auth"] == "Bearer " + SECRET
    assert b"Catalog: complete" in output and b"Completion connectivity: not tested" in output
    passed("catalog_selects_raw_id_and_advertised_limits_after_restart")

    candidate = f.home()
    reference = "FIXTURE_CANDIDATE_ONBOARDING_KEY"
    output, calls = f.discovery_wizard(candidate, auth="key-env", env_name=reference,
                                     extra_env={reference: OVERRIDE})
    only_get(calls, auth="Bearer " + OVERRIDE)
    assert f.config(candidate)["provider"][0]["env"] == reference
    assert f.request(candidate, {reference: OVERRIDE})["auth"] == "Bearer " + OVERRIDE
    assert f.request(candidate)["auth"] == "Bearer " + SECRET
    assert b"environment override" in output
    f.assert_public_private(candidate)
    passed("candidate_env_overrides_draft")

    replacement = f.home()
    f.wizard(replacement, auth="env", extra_env={"FIXTURE_PROVIDER_KEY": OLD_ENV})
    previous = identity(replacement)
    _, calls = f.discovery_wizard(replacement, replacement=True, default=False,
                                  extra_env={"FIXTURE_PROVIDER_KEY": OLD_ENV})
    only_get(calls, auth="Bearer " + SECRET)
    assert identity(replacement) == previous
    assert f.config(replacement)["provider"][0]["env"].startswith("ORBIT_AUTH_")
    assert f.request(replacement, {"FIXTURE_PROVIDER_KEY": OLD_ENV})["auth"] == "Bearer " + SECRET
    passed("private_candidate_ignores_old_env")

    add_home = f.home()
    _, calls = f.discovery_wizard(add_home, auth="none", args=("provider", "add"),
                                  extra_env={"ORBIT_GATE_TOKEN": OLD_ENV, "OPENAI_API_KEY": OVERRIDE})
    only_get(calls)
    assert f.request(add_home, {"ORBIT_GATE_TOKEN": OLD_ENV, "OPENAI_API_KEY": OVERRIDE})["auth"] is None
    assert not (add_home / "auth").exists()
    passed("provider_add_discovery_and_restart_honor_explicit_no_auth")

    large = f.home()
    entries = [advertised(f"family/item{index:03}") for index in range(200)]
    entries[139] = advertised()
    f.server.route("/v1/models", {"data": entries})
    output, calls = f.discovery_wizard(large, auth="none", choices=("next", "prev", "filter " + MODEL, "1"))
    only_get(calls)
    assert [model["id"] for model in f.config(large)["provider"][0]["models"]] == [MODEL]
    assert b"Catalog page 2/10" in output and b"1 matching models" in output
    assert f.request(large)["auth"] is None
    passed("large_catalog_pages_and_filters_without_truncating_raw_selection")

    f.server.reset()
    manual = f.home()
    before = len(f.calls)
    f.wizard(manual, auth="none")
    assert len(f.calls) == before
    assert f.request(manual)["auth"] is None
    assert not any(call["method"] == "GET" for call in f.calls[before:])
    passed("manual_source_sends_zero_discovery_requests")

    scoped = f.home()
    endpoint = f.server.origin + "/tenant/v1?scope=synthetic"
    _, calls = f.discovery_wizard(scoped, auth="none", endpoint=endpoint)
    only_get(calls)
    assert calls[0]["path"] == "/tenant/v1/models?scope=synthetic"
    post = f.request(scoped)
    assert post["path"] == "/tenant/v1/chat/completions?scope=synthetic", "completion dropped the configured endpoint query after discovery"
    passed("discovery_preserves_exact_base_path_and_query_and_restart_model")


def discovery_boundary_cases(f, passed):
    f.server.reset()
    unknown = f.home()
    _, calls = f.discovery_wizard(unknown, auth="none", schema="generic")
    only_get(calls)
    assert_unknown_effort(configured_model(f, unknown), f.request(unknown)["body"])
    only_get(refresh(f, unknown, "generic"))
    assert_unknown_effort(configured_model(f, unknown), f.request(unknown)["body"])
    assert configured_model(f, unknown).get("context_window") is None
    passed("missing_effort_stays_unknown")

    explicit = f.home()
    f.wizard(explicit, auth="none", model=MODEL + ",no-effort/raw")
    path = explicit / "providers.toml"
    text = path.read_text()
    text = text.replace('id = "' + MODEL + '"', 'id = "' + MODEL + '"\nsupported_efforts = ["low", "high"]\ndefault_effort = "high"', 1)
    text = text.replace('id = "no-effort/raw"', 'id = "no-effort/raw"\nsupported_efforts = []', 1)
    private_write(path, text)
    expected = [(model["id"], model.get("supported_efforts"), model.get("default_effort"))
                for model in f.config(explicit)["provider"][0]["models"]]
    only_get(refresh(f, explicit))
    actual = [(model["id"], model.get("supported_efforts"), model.get("default_effort"))
              for model in f.config(explicit)["provider"][0]["models"]]
    assert actual == expected and expected == [(MODEL, ["low", "high"], "high"), ("no-effort/raw", [], None)]
    post = f.request(explicit)
    assert post["body"].get("reasoning_effort") == "high"
    assert "thinking" not in post["body"] and "reasoning" not in post["body"]
    unsupported = f.request(explicit, model="no-effort/raw", select_model=True)
    assert all(key not in unsupported["body"] for key in ("reasoning_effort", "reasoning", "thinking"))
    passed("explicit_effort_survives_refresh")

    anthropic = f.home()
    endpoint = f.server.origin + "/anthropic"
    ids = ("family/one", "family/two")
    f.server.route("/anthropic/models", {"data": [{"id": model} for model in ids], "has_more": False})
    for index, model in enumerate(ids):
        f.server.route("/anthropic/models/" + model.replace("/", "%2F"),
                       {"id": model, "max_input_tokens": 50000 + index * 10000,
                        "max_tokens": 5000 + index * 1000})
    _, calls = f.discovery_wizard(anthropic, auth="none", endpoint=endpoint, kind="anthropic",
                                  choices=("1,2",), default=False)
    only_get(calls, count=3)
    assert {call["path"] for call in calls} == {"/anthropic/models", "/anthropic/models/family%2Fone", "/anthropic/models/family%2Ftwo"}
    models = f.config(anthropic)["provider"][0]["models"]
    assert [(model["id"], model["context_window"], model["max_output_tokens"]) for model in models] == [
        (ids[0], 50000, 5000), (ids[1], 60000, 6000)]
    passed("all_selected_unknown_anthropic_models_receive_exact_detail_requests")

    f.server.reset()
    f.server.route("/v1/models", {"data": [advertised()], "has_more": True})
    for consent in (True, False):
        partial = f.home()
        output, calls = f.discovery_wizard(partial, auth="none", partial=consent,
            manual_fallback=None if consent else MODEL)
        only_get(calls)
        assert b"incomplete" in output
        model = configured_model(f, partial)
        if consent:
            assert model.get("context_window") == 32000
        else:
            assert model.get("context_window") is None
    passed("incomplete_catalog_requires_explicit_partial_consent_or_manual_fallback")

    f.server.reset()
    failure = f.home()
    f.server.route("/v1/models", {"error": {"message": SECRET}}, status=503)
    output, calls = f.discovery_wizard(failure, manual_fallback=MODEL)
    only_get(calls, auth="Bearer " + SECRET)
    assert b"manual" in output.lower()
    assert configured_model(f, failure).get("context_window") is None
    assert f.request(failure)["auth"] == "Bearer " + SECRET
    passed("provider_failure_offers_manual_fallback_without_echoing_response_body")

    f.server.reset()
    redirected = f.home()
    trap_calls = []
    with ProviderServer(trap_calls) as trap:
        f.server.route("/v1/models", status=307, headers={"Location": trap.origin + "/trap"})
        _, calls = f.discovery_wizard(redirected, manual_fallback=MODEL)
        only_get(calls, auth="Bearer " + SECRET)
        assert not trap_calls, "discovery forwarded a bound credential to a redirect origin"
        assert f.request(redirected)["auth"] == "Bearer " + SECRET
    passed("discovery_redirect_never_forwards_bound_credentials")

    f.server.reset()
    canceled = f.home()
    f.server.route("/v1/models", {"data": [advertised()]}, delay=2)
    before = len(f.calls)
    with Terminal(f, canceled) as session:
        f.discovery_start(session)
        call = f.server.wait_call(before)
        assert not call["response_started"], "cancel fixture response finished before the signal"
        os.kill(session.process.pid, signal.SIGINT)
        session.finish(False)
    f.server.wait_idle()
    only_get(f.calls[before:], auth="Bearer " + SECRET)
    assert not canceled.exists()
    passed("cancel_during_catalog_fetch_restores_terminal_without_publication")

    f.server.reset()
    stale = f.home()
    f.wizard(stale, auth="none", model="old/raw")
    f.server.route("/v1/models", {"data": [advertised()]}, delay=1)
    before = len(f.calls)
    with Terminal(f, stale) as session:
        f.discovery_start(session, replacement=True)
        call = f.server.wait_call(before)
        assert not call["response_started"], "stale fixture response finished before the edit"
        path = stale / "providers.toml"
        private_write(path, path.read_bytes() + b'\n[concurrent]\nkeep = true\n')
        assert not call["response_started"], "config edit was not made during the actual pending request"
        concurrent = snapshot(stale)
        session.answer("select", "1")
        session.answer("default", "no")
        session.finish(False)
    f.server.wait_idle()
    assert snapshot(stale) == concurrent
    only_get(f.calls[before:], auth="Bearer " + SECRET)
    passed("stale_config_edit_during_fetch_refuses_before_private_record_save")

    f.server.reset()
    preserved = f.home()
    f.discovery_wizard(preserved, auth="none")
    f.wizard(preserved, name="second", auth="none", default=False, model="second/raw")
    path = preserved / "providers.toml"
    text = path.read_text().replace("max_output_tokens = 4000", "max_output_tokens = 7777", 1)
    text = text.replace('main = "fixture/' + MODEL + '"', 'main = "fixture/' + MODEL + '"\nsubagent = "fixture/' + MODEL + '"', 1)
    private_write(path, text + '\n[unrelated]\nkeep="preserved"\n')
    previous_identity = identity(preserved)
    f.server.route("/v1/models", {"data": [advertised(context=64000, output=8000)]})
    only_get(refresh(f, preserved))
    cfg = f.config(preserved)
    model = configured_model(f, preserved)
    assert model["context_window"] == 64000 and model["max_output_tokens"] == 7777
    assert cfg["roles"]["main"] == "fixture/" + MODEL and cfg["roles"]["subagent"] == "fixture/" + MODEL
    assert cfg["unrelated"]["keep"] == "preserved" and cfg["provider"][1]["models"][0]["id"] == "second/raw"
    assert identity(preserved) == previous_identity
    assert f.request(preserved)["auth"] is None
    passed("refresh_preserves_manual_override_unrelated_roles_provider_and_identity")

    f.server.reset()
    manual = f.home()
    f.wizard(manual, auth="none")
    path = manual / "providers.toml"
    text = path.read_text().replace('id = "' + MODEL + '"', 'id = "' + MODEL + '"\ncontext_window = 77777\nmax_output_tokens = 7777', 1)
    private_write(path, text)
    assert not (manual / "metadata").exists()
    only_get(refresh(f, manual))
    model = configured_model(f, manual)
    assert model["context_window"] == 77777 and model["max_output_tokens"] == 7777
    assert f.request(manual)["auth"] is None
    passed("missing_provenance_preserves_existing_explicit_numeric_limits")

    f.server.reset()
    invalid = f.home()
    f.server.route("/v1/models", {"data": [advertised(context=0, output="invalid")]})
    output, calls = f.discovery_wizard(invalid, auth="none", partial=True)
    only_get(calls)
    model = configured_model(f, invalid)
    assert model.get("context_window") is None and model.get("max_output_tokens") is None
    assert b"context unknown; output unknown" in output
    assert_unknown_effort(model, f.request(invalid)["body"])
    passed("invalid_advertised_limits_remain_unknown_without_invented_controls")

    f.server.reset()
    offline = f.home()
    f.wizard(offline, auth="none")
    baseline = snapshot(offline)
    before = len(f.calls)
    f.run(offline, "provider", "list", "--json")
    f.run(offline, "models", "--json")
    f.run(offline, "doctor", "--json", success=None)
    invalid_refresh = [("missing",), ("fixture", "--schema"), ("fixture", "--schema", "unsupported"),
                       ("fixture", "--schema", "generic", "--schema", "openrouter"),
                       ("fixture", "extra"), ("fixture", "--unknown")]
    for arguments in invalid_refresh:
        f.run(offline, "provider", "refresh", *arguments, success=False)
    assert len(f.calls) == before and snapshot(offline) == baseline
    passed("refresh_is_explicit_and_strict_while_provider_models_and_doctor_stay_offline")


def login_boundary_cases(f, passed):
    home = f.home()
    f.wizard(home, auth="env", extra_env={"FIXTURE_PROVIDER_KEY": OLD_ENV})
    initial = f.config(home)
    before = snapshot(home)
    request_count = len(f.calls)
    with Terminal(f, home, ("provider", "login", "fixture", "--method", "key"),
                  {"FIXTURE_PROVIDER_KEY": OLD_ENV}) as session:
        session.answer("key", SECRET)
        session.expect(b"Save provider login?")
        assert snapshot(home) == before, "login published before confirmation"
        session.send("yes")
        output = session.finish()
    changed = f.config(home)
    assert changed["provider"][0]["env"].startswith("ORBIT_AUTH_")
    assert changed["provider"][0]["models"] == initial["provider"][0]["models"]
    assert changed["roles"] == initial["roles"]
    assert b"previous ENV reference no longer serves" in output
    assert len(f.calls) == request_count, "key login performed provider I/O"
    f.assert_public_private(home)
    assert f.request(home, {"FIXTURE_PROVIDER_KEY": OLD_ENV})["auth"] == "Bearer " + SECRET
    passed("existing_key_login_is_confirmed_privately_and_restarted_default_uses_fresh_binding")

    env_home = f.home()
    f.wizard(env_home, auth="none")
    initial = f.config(env_home)
    before = snapshot(env_home)
    request_count = len(f.calls)
    with Terminal(f, env_home, ("provider", "login", "fixture", "--method", "env"),
                  {"FIXTURE_LOGIN_ENV": OVERRIDE}) as session:
        session.answer("env", "FIXTURE_LOGIN_ENV")
        session.expect(b"Save provider login?")
        assert snapshot(env_home) == before
        session.send("yes")
        output = session.finish()
    assert b"environment override" in output and b"API key (hidden)" not in output
    assert not (env_home / "auth").exists() and len(f.calls) == request_count
    assert f.config(env_home)["provider"][0]["models"] == initial["provider"][0]["models"]
    assert f.config(env_home)["roles"] == initial["roles"]
    assert f.request(env_home, {"FIXTURE_LOGIN_ENV": OVERRIDE})["auth"] == "Bearer " + OVERRIDE
    passed("existing_env_login_uses_explicit_reference_without_saving_an_environment_value")

    logout = f.home()
    f.wizard(logout)
    before = snapshot(logout)
    request_count = len(f.calls)
    with Terminal(f, logout, ("provider", "logout", "fixture")) as session:
        session.answer(b"Log out locally?", "no")
        session.finish(False)
    assert snapshot(logout) == before and len(f.calls) == request_count
    reference = f.config(logout)["provider"][0]["env"]
    config_before = (logout / "providers.toml").read_bytes()
    result = f.run(logout, "provider", "logout", "fixture", "--yes", "--json",
                   extra_env={reference: OVERRIDE})
    receipt = json.loads(result.stdout)
    assert receipt["removed"] is True and receipt["env_override_active"] is True
    assert receipt["scope"] == "current_local_binding" and receipt["offline"] is True
    assert receipt["command"] == "provider logout"
    assert (logout / "providers.toml").read_bytes() == config_before
    assert len(f.calls) == request_count, "local logout contacted a provider"
    assert f.request(logout, {reference: OVERRIDE})["auth"] == "Bearer " + OVERRIDE
    request_count = len(f.calls)
    f.run(logout, "-p", "removed private binding must not dispatch", "--max-turns", "1", success=False)
    assert len(f.calls) == request_count
    passed("logout_decline_preserves_bytes_and_confirmed_exact_removal_leaves_env_override_active")

    custom = f.home()
    f.wizard(custom, name="openrouter", auth="none")
    before = snapshot(custom)
    request_count = len(f.calls)
    with Terminal(f, custom, ("provider", "login", "openrouter", "--method", "browser", "--headless", "--no-browser")) as session:
        output = session.finish(False)
    assert b"Authorize with the provider:" not in output and b"Authorization code (hidden)" not in output
    assert snapshot(custom) == before and len(f.calls) == request_count
    passed("custom_endpoint_named_openrouter_cannot_acquire_official_browser_flow")

    def official_home():
        result = f.home()
        f.run(result, "setup", "--provider", "browserfixture", "--gate", "https://openrouter.ai/api/v1",
              "--model", MODEL, "--credential-env", "FIXTURE_BROWSER_ENV")
        return result

    callback_home = official_home()
    before = snapshot(callback_home)
    request_count = len(f.calls)
    with Terminal(f, callback_home, ("provider", "login", "browserfixture", "--no-browser")) as session:
        session.expect(b"Waiting for the local authorization callback.")
        authorization = bytes(session.output).decode().split("Authorize with the provider: ", 1)[1].splitlines()[0].strip()
        parsed = urlsplit(authorization)
        query = parse_qs(parsed.query)
        assert parsed.scheme == "https" and parsed.netloc == "openrouter.ai" and parsed.path == "/auth"
        assert query["code_challenge_method"] == ["S256"] and len(query["state"][0]) >= 32
        assert "code_verifier" not in query
        callback = urlsplit(query["callback_url"][0])
        assert callback.scheme == "http" and callback.hostname == "localhost" and callback.port
        os.killpg(session.process.pid, signal.SIGINT)
        session.finish(False)
    assert snapshot(callback_home) == before and len(f.calls) == request_count
    connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        connection.settimeout(0.2)
        assert connection.connect_ex(("127.0.0.1", callback.port)) != 0, "callback listener survived cancellation"
    finally:
        connection.close()
    passed("official_callback_wait_cancels_without_browser_launch_exchange_or_listener_leak")

    headless = official_home()
    before = snapshot(headless)
    request_count = len(f.calls)
    for ending in (b"\x03", b"\x04"):
        with Terminal(f, headless, ("provider", "login", "browserfixture", "--headless")) as session:
            session.expect(b"Authorization code (hidden): ")
            authorization = bytes(session.output).decode().split("Authorize with the provider: ", 1)[1].splitlines()[0].strip()
            query = parse_qs(urlsplit(authorization).query)
            assert "callback_url" not in query and "state" not in query and "code_verifier" not in query
            assert query["code_challenge_method"] == ["S256"]
            session.send(SECRET[:768].encode() + ending)
            output = session.finish(False)
            assert SECRET[:64].encode() not in output, "partial authorization code was echoed"
        assert snapshot(headless) == before and len(f.calls) == request_count
    passed("headless_hidden_partial_code_ctrl_c_and_eof_restore_terminal_without_exchange")

    invalid = f.home()
    request_count = len(f.calls)
    for arguments in [
        ("login", "fixture", "--method"), ("login", "fixture", "--method", "unknown"),
        ("login", "fixture", "--method", "key", "--headless"),
        ("login", "fixture", "--method", "env", "--no-browser"),
        ("login", "fixture", "--method", "key", "--method", "key"),
        ("login", "fixture", "--headless", "--headless"),
        ("login", "fixture", "--json"), ("login", "fixture", "--api-key", "not-a-key"),
        ("login", "fixture", "extra"), ("logout", "fixture", "--json"),
        ("logout", "fixture", "--yes", "--yes"), ("logout", "fixture", "--method", "key"),
    ]:
        f.run(invalid, "provider", *arguments, success=False)
        assert not invalid.exists()
    f.run(invalid, "provider", "login", "fixture", "--method", "key", success=False)
    assert not invalid.exists() and len(f.calls) == request_count
    result = f.run(invalid, "help")
    assert "provider refresh NAME" in result.stdout and "provider login NAME" in result.stdout
    assert "provider logout NAME" in result.stdout and "--headless" in result.stdout
    assert not invalid.exists() and len(f.calls) == request_count
    passed("strict_login_logout_flags_and_redirected_input_refuse_before_home_creation_or_provider_io")



def interactive_cases(f, passed):
    home = f.home()
    output = f.wizard(home, args=("init",))
    assert f.config(home)["roles"]["main"] == "fixture/" + MODEL
    assert b'"schema":"orbit.cli/v1"' not in output, "terminal init dumped a JSON receipt"
    assert f.request(home)["auth"] == "Bearer " + SECRET
    passed("bare_terminal_init_saves_private_provider_and_fresh_default_dispatch_uses_it")

    request_count = len(f.calls)
    offline = f.home()
    with Terminal(f, offline, ("init", "--no-provider")) as session:
        output = session.finish()
    assert b"Provider (name or number)" not in output and (offline / "pib.json").exists()
    for args in [("init",), ("init", "--json")]:
        redirected = f.home()
        result = f.run(redirected, *args)
        assert json.loads(result.stdout)["command"] == "init"
        assert "Authentication (" not in result.stdout and (redirected / "pib.json").exists()
    assert len(f.calls) == request_count
    passed("explicit_offline_terminal_and_redirected_init_preserve_prompt_free_identity_setup")

    untouched = f.home()
    request_count = len(f.calls)
    for args in [("config",), ("config", "show"), ("config", "--json"),
                 ("config", "show", "--json")]:
        result = f.run(untouched, *args)
        if "--json" in args:
            assert isinstance(json.loads(result.stdout), dict)
        assert not untouched.exists(), "read-only configuration created storage"
    for args in [("config", "show", "--json", "--json"), ("config", "--json", "show"),
                 ("config", "set"), ("config", "show", "extra")]:
        f.run(untouched, *args, success=False)
        assert not untouched.exists()
    assert len(f.calls) == request_count
    passed("configuration_show_and_strict_grammar_are_read_only_without_provider_effects")

    absent = f.home()
    with Terminal(f, absent, ("init",)) as session:
        session.expect("provider")
        session.send(b"\x03")
        session.finish(False)
    assert not absent.exists()
    existing = f.home()
    f.wizard(existing, auth="none")
    before = snapshot(existing)
    with Terminal(f, existing, ("init",)) as session:
        session.expect("provider")
        session.send(b"\x04")
        session.finish(False)
    assert snapshot(existing) == before
    passed("terminal_init_cancel_and_eof_preserve_absence_and_existing_identity")

    rich = f.home()
    with Terminal(f, rich, ("init",), {"NO_COLOR": None}, size=(100, 32)) as session:
        session.expect("provider")
        session.resize(40, 10)
        session.read(0.2)
        session.resize(160, 32)
        session.read(0.2)
        session.send(b"\x1b[F\r")
        session.answer("name", "fixture")
        session.answer("kind", "openai-compatible")
        session.answer("url", f.endpoint)
        session.answer("auth", "key")
        session.answer("key", SECRET)
        session.expect("source")
        session.send(b"\r")
        session.answer("models", MODEL)
        session.answer("default", "yes")
        session.answer("main", MODEL)
        session.answer("confirm", "yes")
        output = session.finish()
    assert b"\x1b[" in output and b"ORBIT" in output, "rich selector was not exercised"
    assert f.config(rich)["roles"]["main"] == "fixture/" + MODEL
    assert f.request(rich)["auth"] == "Bearer " + SECRET
    passed("rich_selector_end_key_and_wide_narrow_resize_keep_exact_provider_and_private_key")

    f.server.reset()
    catalog_home = f.home()
    second_model = "family/second/raw"
    f.server.route("/v1/models", {"data": [advertised(MODEL), advertised(second_model)]})
    before = len(f.calls)
    with Terminal(f, catalog_home, ("init",), {"NO_COLOR": None}, size=(100, 32)) as session:
        f.discovery_start(session, auth="none")
        session.expect("Discovered models")
        session.send("1")
        session.expect("1 selected; Enter toggles")
        session.send(b"\x1b[B\r")
        session.expect("2 selected; Enter toggles")
        session.send(b"\x1b[F\r")
        session.answer("default", "yes")
        session.answer("main", MODEL)
        session.answer("confirm", "yes")
        output = session.finish()
    f.server.wait_idle()
    calls = f.calls[before:]
    only_get(calls)
    models = f.config(catalog_home)["provider"][0]["models"]
    assert [model["id"] for model in models] == [MODEL, second_model]
    assert f.config(catalog_home)["roles"]["main"] == "fixture/" + MODEL
    assert b"[x]" in output and b"Select model numbers" not in output
    passed("rich_catalog_multi_select_toggles_models_and_preserves_exact_ids")

    paged_home = f.home()
    paged_models = [MODEL] + [f"family/extra/model-{index:02}" for index in range(1, 22)]
    f.server.route("/v1/models", {"data": [advertised(model) for model in paged_models]})
    with Terminal(f, paged_home, ("init",), {"NO_COLOR": None}, size=(100, 32)) as session:
        f.discovery_start(session, auth="none")
        session.expect("Discovered models")
        session.send(b"\x1b[B" * 21 + b"\r")
        session.expect("page 2/2")
        session.send(b"\x1b[B\r")
        session.expect("1 selected")
        session.send(b"\x1b[B\x1b[B\r")
        session.expect("page 1/2")
        session.send(b"\r")
        session.expect("2 selected")
        session.send(b"\x1b[B" * 20 + b"\r")
        session.expect("Filter models (blank shows all)")
        session.send("family/extra/model-21")
        session.expect("2 selected")
        session.send(b"\x1b[F\r")
        session.answer("default", "yes")
        session.answer("main", MODEL)
        session.answer("confirm", "yes")
        session.finish()
    models = f.config(paged_home)["provider"][0]["models"]
    assert {model["id"] for model in models} == {MODEL, paged_models[-1]}
    assert f.config(paged_home)["roles"]["main"] == "fixture/" + MODEL
    passed("rich_catalog_paging_and_filter_keep_prior_selection_and_raw_ids")

    for size in [(1, 1), (0, 0)]:
        tiny = f.home()
        request_count = len(f.calls)
        with Terminal(f, tiny, ("init",), {"NO_COLOR": None}) as session:
            session.expect(b"\x1b[?1049h")
            session.expect("provider")
            session.cursor = len(session.output)
            session.resize(*size)
            session.expect(b"\x1b[?1049l")
            # The fresh plain prompt follows installation of its input guards.
            session.expect("provider")
            session.resize(80, 24)
            session.send(b"\x03")
            session.finish(False)
        assert not tiny.exists() and len(f.calls) == request_count
    passed("rich_zero_and_tiny_resize_cancel_restores_terminal_without_publication")


    # These are actual CLI terminal journeys, followed by separate fresh consumers.
    def edit(session, category, key, value):
        session.answer(b"Configuration: ", category)
        prompt = {"defaults": b"Models and roles: ", "routing": b"Phase routing: ",
                  "appearance": b"Appearance and layout: "}[category]
        session.answer(prompt, key)
        session.answer(b"Choose appearance: " if category == "appearance" else b"Choose a model: ", value)
        session.answer(b"Save this change? Type yes to confirm: ", "yes")

    configured = f.home()
    f.wizard(configured, model=MODEL + ",second/raw")
    old_identity = immutable_identity(configured)
    before = len(f.calls)
    with Terminal(f, configured, ("config",)) as session:
        edit(session, "defaults", "main", "fixture/second/raw")
        edit(session, "defaults", "compaction", "fixture/" + MODEL)
        session.answer(b"Configuration: ", "done")
        session.finish()
    assert len(f.calls) == before and immutable_identity(configured) == old_identity
    assert f.config(configured)["roles"]["compaction"] == "fixture/" + MODEL
    assert f.request(configured, model="second/raw")["auth"] == "Bearer " + SECRET
    view = json.loads(f.run(configured, "config", "show", "--json").stdout)
    assert view["roles"]["main"] == "fixture/second/raw"
    assert view["roles"]["compaction"] == "fixture/" + MODEL
    passed("terminal_configuration_saves_roles_and_fresh_unpinned_default_dispatch_uses_them")

    routed = f.home()
    f.wizard(routed, auth="none", model=MODEL + ",easy/raw,hard/raw,override/raw")
    path = routed / "providers.toml"
    private_write(path, path.read_bytes() + b"\n[routing.keywords]\nclear=true\neasy=['light']\nhard=['deep']\n[routing.phases.coding]\nhard='fixture/override/raw'\n[retained]\nvalue='preserve-me'\n")
    before = len(f.calls)
    with Terminal(f, routed, ("config",)) as session:
        edit(session, "routing", "easy", "fixture/easy/raw")
        edit(session, "routing", "hard", "fixture/hard/raw")
        session.answer(b"Configuration: ", "done")
        session.finish()
    cfg = f.config(routed)
    assert cfg["routing"]["phases"]["coding"]["hard"] == "fixture/override/raw"
    assert cfg["retained"]["value"] == "preserve-me"
    for text, model in [("light", "fixture/easy/raw"), ("deep", "fixture/hard/raw")]:
        preview = json.loads(f.run(routed, "route", "test", text, "--json").stdout)
        assert preview["model"] == model
    pinned = json.loads(f.run(routed, "route", "test", "deep", "--model", "fixture/" + MODEL, "--json").stdout)
    assert pinned["model"] == "fixture/" + MODEL
    assert len(f.calls) == before, "configuration and preview contacted a provider"
    passed("terminal_configuration_updates_both_fallbacks_preserves_phase_override_and_explicit_pin")

    styled = f.home()
    before = len(f.calls)
    settings = [("theme", "midnight"), ("layout.preset", "columns"), ("density", "compact"),
                ("glyphs", "ascii"), ("color_mode", "mono"), ("reduced_motion", "true")]
    with Terminal(f, styled, ("config",)) as session:
        for key, value in settings:
            edit(session, "appearance", key, value)
        session.answer(b"Configuration: ", "done")
        session.finish()
    fresh = json.loads(f.run(styled, "customize", "show", "--json").stdout)["profile"]["profile"]
    assert (fresh["theme"], fresh["layout"]["preset"], fresh["density"], fresh["glyphs"],
            fresh["color_mode"], fresh["reduced_motion"]) == ("midnight", "columns", "compact", "ascii", "mono", True)
    assert not (styled / "providers.toml").exists() and len(f.calls) == before
    unchanged = snapshot(styled)
    with Terminal(f, styled, ("config",)) as session:
        session.answer(b"Configuration: ", "appearance")
        session.answer(b"Appearance and layout: ", "theme")
        session.answer(b"Choose appearance: ", "paper")
        session.answer(b"Save this change? Type yes to confirm: ", "no")
        session.answer(b"Configuration: ", "done")
        session.finish()
    assert snapshot(styled) == unchanged
    passed("terminal_appearance_edits_reopen_through_shared_profile_and_decline_preserves_exact_bytes")

    stale = f.home()
    f.wizard(stale, auth="none", model=MODEL + ",second/raw")
    before = len(f.calls)
    with Terminal(f, stale, ("config",)) as session:
        session.answer(b"Configuration: ", "defaults")
        session.answer(b"Models and roles: ", "main")
        session.answer(b"Choose a model: ", "fixture/second/raw")
        session.expect(b"Save this change? Type yes to confirm: ")
        path = stale / "providers.toml"
        private_write(path, path.read_bytes() + b"\n[concurrent]\nkeep=true\n")
        concurrent = snapshot(stale)
        session.send("yes")
        session.expect(b"This edit was not retried")
        session.answer(b"Configuration: ", "done")
        session.finish()
    assert snapshot(stale) == concurrent and len(f.calls) == before
    passed("terminal_configuration_stale_confirmation_never_overwrites_or_retries")

    long_home = f.home()
    last = "vendor/模型/e\u0301-final"
    models = ["raw/" + str(n) for n in range(32)] + [last]
    f.wizard(long_home, auth="none", model=",".join(models))
    before = len(f.calls)
    with Terminal(f, long_home, ("config",), {"NO_COLOR": None}, size=(100, 32)) as session:
        session.answer(b"Configuration: ", "defaults")
        session.answer(b"Models and roles: ", "main")
        session.expect(b"Choose a model: ")
        def fresh_model_frame(checkpoint, columns, rows):
            deadline = time.monotonic() + 5
            marker = b"\x1b[H\x1b[2J"
            footer = "Arrows select  Enter choose  Left/Esc back  Ctrl-C cancel"[:columns - 1]
            newline_processing = termios.OPOST | termios.ONLCR
            line_delimiter = "\r\r\n" if (session.initial[1] & newline_processing) == newline_processing else "\r\n"
            while time.monotonic() < deadline:
                fresh = bytes(session.output[checkpoint:])
                if marker in fresh:
                    frame = fresh.rsplit(marker, 1)[-1]
                    if frame.endswith(b"\x1b[0m"):
                        clean = re.sub(rb"\x1b\[[0-9;?]*[ -/]*[@-~]", b"", frame).decode("utf-8")
                        lines = clean.split(line_delimiter)
                        assert all("\r" not in line and "\n" not in line for line in lines), "choice frame contains an unexpected line delimiter"
                        if lines[-1] == footer:
                            assert lines[:2] == ["ORBIT  /  SETUP", "Choose a model"]
                            assert len(lines) == rows, "long choice frame has wrong fresh viewport geometry"
                            assert any(line.startswith("> ") and last in line for line in lines), "selected late Unicode identity was not visible"
                            for line in lines:
                                cells = sum(0 if unicodedata.combining(c) else 2 if unicodedata.east_asian_width(c) in ("W", "F") else 1 for c in line)
                                assert cells < columns, "choice frame exceeds terminal width"
                            return
                session.read(0.05)
            raise AssertionError("no fresh complete choice frame after navigation or resize")
        checkpoint = len(session.output)
        session.send(b"\x1b[F")
        fresh_model_frame(checkpoint, 100, 32)
        for columns, rows in [(40, 10), (160, 32)]:
            checkpoint = len(session.output)
            session.resize(columns, rows)
            fresh_model_frame(checkpoint, columns, rows)
        session.send(b"\r")
        session.answer(b"Save this change? Type yes to confirm: ", "yes")
        session.answer(b"Configuration: ", "done")
        session.finish()
    assert len(f.calls) == before and f.config(long_home)["roles"]["main"] == "fixture/" + last
    assert f.request(long_home, model=last)["auth"] is None
    passed("rich_long_unicode_model_menu_keeps_selected_exact_identity_visible_through_resize")

    added = f.home()
    f.wizard(added)
    before = len(f.calls)
    old_identity = immutable_identity(added)
    with Terminal(f, added, ("config",)) as session:
        session.answer(b"Configuration: ", "provider")
        f.through_models(session, name="second", auth="none")
        session.answer("default", "no")
        session.answer("confirm", "yes")
        session.answer(b"Configuration: ", "done")
        session.finish()
    assert immutable_identity(added) == old_identity and len(f.calls) == before
    assert [provider["name"] for provider in f.config(added)["provider"]] == ["fixture", "second"]
    assert f.request(added)["auth"] == "Bearer " + SECRET
    f.assert_public_private(added)
    passed("configuration_provider_action_uses_shared_wizard_preserves_identity_and_old_private_default")

    cached = f.home()
    f.server.route("/v1/models", {"data": [advertised()]})
    before = len(f.calls)
    with Terminal(f, cached, ("init",)) as session:
        f.discovery_start(session, auth="none")
        session.answer("select", "1")
        session.answer("default", "back")
        session.answer(b"Model selection draft: ", "keep")
        session.answer("default", "yes")
        session.answer("main", MODEL)
        session.answer("confirm", "back")
        session.answer(b"Default model draft: ", "keep")
        session.answer("confirm", "yes")
        session.finish()
    only_get(f.calls[before:])
    assert f.config(cached)["roles"]["main"] == "fixture/" + MODEL
    passed("terminal_back_and_keep_reuse_discovery_and_default_without_effect_replay")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/orbit"))
    parser.add_argument("--group", choices=("manual", "private-key", "preservation", "discovery-tracer", "discovery-boundaries", "login-boundaries", "interactive", "all"), default="all")
    options = parser.parse_args()
    repo = Path(__file__).resolve().parents[1]
    binary = options.binary.resolve(strict=True)
    assert binary.is_file() and os.access(binary, os.X_OK), "current orbit binary is required"
    # Cargo's dependency file identifies the source actually compiled into this
    # executable; unregistered modules and independent tests are not its inputs.
    depfile = binary.with_name(binary.name + ".d")
    dependency_line = depfile.read_text().splitlines()[0]
    target, dependencies = dependency_line.split(": ", 1)
    assert Path(shlex.split(target)[0]).resolve() == binary, "dependency file does not match the selected binary"
    sources = [Path(path) for path in shlex.split(dependencies)]
    assert (repo / "crates/cli/src/onboarding.rs") in sources, "binary lacks the registered onboarding source"
    if options.group in ("discovery-tracer", "discovery-boundaries", "all"):
        assert (repo / "crates/cli/src/provider_discovery.rs") in sources, "binary lacks registered discovery source"
    if options.group in ("login-boundaries", "all"):
        assert (repo / "crates/cli/src/provider_login.rs") in sources, "binary lacks registered login source"
    sources += list((repo / "crates").rglob("Cargo.toml")) + [repo / "Cargo.lock"]
    assert binary.stat().st_mtime_ns >= max(path.stat().st_mtime_ns for path in sources), "binary is stale; build the current source before acceptance"
    os.umask(0o077)
    calls, checks = [], {}

    with ProviderServer(calls) as server:
        with tempfile.TemporaryDirectory(prefix="orbit-onboarding-acceptance-") as temporary:
            fixture = Fixture(binary, Path(temporary), calls, server.origin + "/v1", server)

            def passed(name):
                assert name not in checks
                assert not server.errors, "fixture request worker failed"
                checks[name] = {"passed": True, "assertions": 1}
                print("passed: " + name, flush=True)

            groups = (("manual", manual_cases), ("private-key", private_cases),
                      ("preservation", preservation_cases), ("discovery-tracer", discovery_tracer_cases),
                      ("discovery-boundaries", discovery_boundary_cases), ("login-boundaries", login_boundary_cases),
                      ("interactive", interactive_cases))
            for name, cases in groups:
                if options.group in (name, "all"):
                    server.reset()
                    request_count = len(calls)
                    cases(fixture, passed)
                    server.wait_idle()
                    if name in ("manual", "preservation"):
                        assert len(calls) == request_count, "offline onboarding contacted a provider"
            required = {"manual": 5, "private-key": 8, "preservation": 12,
                        "discovery-tracer": 7, "discovery-boundaries": 12, "login-boundaries": 7,
                        "interactive": 15, "all": 66}[options.group]
            assert len(checks) == required, "missing named onboarding workflow"
            print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": checks}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
