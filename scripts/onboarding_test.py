#!/usr/bin/env python3
"""Current-binary provider onboarding acceptance; run inside scripts/in-jail.sh.

Each receipt names an executed workflow, with fresh private homes and a local
HTTP fixture. This script never builds or invokes an installed orbit binary.
"""
import argparse
import errno
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import pty
import select
import shlex
import signal
import stat
import subprocess
import tempfile
import termios
import threading
import time
import tomllib


# Longer than the terminal reader's former 256-byte allocation: both success
# and cancellation exercise the full-bound hidden buffer, without echo.
SECRET = "synthetic-private-onboarding-" + "k" * 1024 + "-736490152"
OVERRIDE = "synthetic-explicit-env-override-825194"
OLD_ENV = "synthetic-old-reference-must-not-serve-972846"
MODEL = "family/vendor/raw-model"
PROMPTS = {
    "provider": b"Provider (name or number): ",
    "name": b"Provider name", "replace": b"Replace this existing provider?",
    "kind": b"Adapter kind (openai-compatible/anthropic/ollama)",
    "url": b"Base URL", "auth": b"Authentication (env/key/none): ",
    "env": b"Credential ENV name", "key": b"API key (hidden): ",
    "source": b"Model source (manual)", "models": b"Raw model IDs (comma-separated): ",
    "default": b"Set main default? (yes/no): ", "main": b"Main model ID: ",
    "replace_main": b"Replace main default?", "confirm": b"Save provider configuration?",
}


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
    def __init__(self, fixture, home, args=("setup",), extra_env=None):
        self.fixture = fixture
        self.master, self.slave = pty.openpty()
        self.initial = termios.tcgetattr(self.slave)
        self.output = bytearray()
        self.cursor = 0
        self.process = subprocess.Popen(
            [str(fixture.binary), "--home", str(home), *args],
            cwd=fixture.work, env=fixture.env(home, extra_env),
            stdin=self.slave, stdout=self.slave, stderr=self.slave,
            start_new_session=True, close_fds=True,
        )

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
    def __init__(self, binary, root, calls, endpoint):
        self.binary, self.root, self.calls, self.endpoint = binary, root, calls, endpoint
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
            result.update(extra)
        return result

    @staticmethod
    def assert_no_secrets(value):
        data = value.encode() if isinstance(value, str) else bytes(value)
        assert all(secret.encode() not in data for secret in (SECRET, OVERRIDE, OLD_ENV)), "synthetic credential leaked"

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

    def through_models(self, session, name="fixture", auth="key", replacement=False,
                       model=MODEL, endpoint=None, env_name="FIXTURE_PROVIDER_KEY"):
        session.answer("provider", "custom")
        session.answer("name", name)
        if replacement:
            session.answer("replace", "yes")
        session.answer("kind", "openai-compatible")
        session.answer("url", endpoint or self.endpoint)
        session.answer("auth", auth)
        if auth == "key":
            session.answer("key", SECRET)
        elif auth == "env":
            session.answer("env", env_name)
        session.answer("source", "manual")
        session.answer("models", model)

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

    def request(self, home, extra_env=None):
        before = len(self.calls)
        self.run(home, "-p", "onboarding restart fixture", "--max-turns", "1", extra_env=extra_env)
        new = self.calls[before:]
        assert len(new) == 1 and new[0]["method"] == "POST", "expected one actual provider request"
        assert new[0]["body"].get("model") == MODEL, "raw default model changed on dispatch"
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
        assert "Authentication (env/key/none)" not in result.stdout + result.stderr
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
            output = session.finish(False)
        assert not invalid.exists() and PROMPTS["key"] not in output
    passed("invalid_endpoint_refuses_before_hidden_input_and_home_creation")

    invalid_model = f.home()
    with Terminal(f, invalid_model) as session:
        f.through_models(session, model="duplicate,duplicate")
        session.finish(False)
    assert not invalid_model.exists()
    passed("invalid_model_after_hidden_key_refuses_before_publication")

    oversize = f.home()
    with Terminal(f, oversize) as session:
        at_hidden(session)
        session.send(b"x" * (16 * 1024 + 1) + b"\n")
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/orbit"))
    parser.add_argument("--group", choices=("manual", "private-key", "preservation", "all"), default="all")
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
    sources += list((repo / "crates").rglob("Cargo.toml")) + [repo / "Cargo.lock"]
    assert binary.stat().st_mtime_ns >= max(path.stat().st_mtime_ns for path in sources), "binary is stale; build the current source before acceptance"
    os.umask(0o077)
    calls, checks = [], {}

    class Provider(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append({"method": "GET", "path": self.path})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":[]}')

        def do_POST(self):
            size = int(self.headers.get("Content-Length", "0"))
            assert 0 < size <= 128 * 1024, "fixture request body bound"
            body = json.loads(self.rfile.read(size))
            calls.append({"method": "POST", "path": self.path, "auth": self.headers.get("Authorization"), "body": body})
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.end_headers()
            events = [
                {"choices": [{"index": 0, "delta": {"content": "onboarding fixture reply"}, "finish_reason": None}]},
                {"choices": [{"index": 0, "delta": {}, "finish_reason": "stop"}], "usage": {"prompt_tokens": 2, "completion_tokens": 3}},
            ]
            for event in events:
                self.wfile.write(("data: " + json.dumps(event) + "\n\n").encode())
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-onboarding-acceptance-") as temporary:
            fixture = Fixture(binary, Path(temporary), calls, f"http://127.0.0.1:{server.server_port}/v1")

            def passed(name):
                assert name not in checks
                checks[name] = {"passed": True, "assertions": 1}
                print("passed: " + name, flush=True)

            for name, cases in (("manual", manual_cases), ("private-key", private_cases), ("preservation", preservation_cases)):
                if options.group in (name, "all"):
                    request_count = len(calls)
                    cases(fixture, passed)
                    if name in ("manual", "preservation"):
                        assert len(calls) == request_count, "offline onboarding contacted a provider"
            required = {"manual": 5, "private-key": 8, "preservation": 12, "all": 25}[options.group]
            assert len(checks) == required, "missing named onboarding workflow"
            print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": checks}, sort_keys=True))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive(), "local fixture server did not stop"
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
