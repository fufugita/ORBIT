#!/usr/bin/env python3
"""Captured local startup and routing workflows. Run inside in-jail.sh."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import tomllib


def wait_for(probe, label, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("timed out: " + label)


def ready_json(path):
    try:
        return json.loads(path.read_text())
    except (FileNotFoundError, json.JSONDecodeError):
        return None


def digest_tree(path):
    return {str(item.relative_to(path)): hashlib.sha256(item.read_bytes()).hexdigest()
            for item in path.rglob("*") if item.is_file() and not item.is_symlink()}


def stop_process(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=4)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=4)


@contextmanager
def fixture_directory(processes):
    with tempfile.TemporaryDirectory(prefix="orbit-routing-release-") as tmp:
        try:
            yield tmp
        finally:
            # Reap providers/owners before removing any capture or session files.
            for process in reversed(processes):
                stop_process(process)


DECISION_KEYS = ("phase", "difficulty", "matched", "provider_id", "raw_model",
                 "source", "suppressed_reason")


def decision_fields(value):
    return {key: value[key] for key in DECISION_KEYS}


def live_workflows(binary, web, scripts, root, home, work, env, cli, calls,
                   fixtures, processes, module, checked):
    """Actual frontend requests; predictions always come from the public CLI."""
    prompt = "implement comprehensive parser"
    config_path = home / "providers.toml"
    original = config_path.read_text()
    config_path.write_text(original + '\n[fixture_metadata]\nkeep="routing-release"\n')
    provider_facts = tomllib.loads(config_path.read_text())["provider"]

    def command(*words, **options):
        return json.loads(cli("route", *words, "--json", **options).stdout)

    def prediction(*options):
        return command("test", prompt, *options)

    def counts():
        return tuple(len(calls(name)) for name in ("left", "right"))

    def exact_call(before, provider, model, effort="low"):
        expected = tuple(count + (name == provider)
                         for name, count in zip(("left", "right"), before))
        assert counts() == expected, ("unexpected provider call count", before, counts(), expected)
        call = calls(provider)[-1]
        assert call["model"] == model, call
        assert call.get("reasoning_effort") == effort, call
        assert "phase" not in call and "difficulty" not in call, call
        return call

    def saved(session_id):
        return json.loads((home / "sessions" / (session_id + ".json")).read_text())

    def session_ids():
        return {path.stem for path in (home / "sessions").glob("*.json")}

    def fresh_cli(*words, **options):
        before = session_ids()
        result = cli(*words, **options)
        created = session_ids() - before
        assert len(created) == 1, ("one new session required", created, result.stdout, result.stderr)
        return result, created.pop()

    def base_preserved(session_id, origin):
        value = saved(session_id)
        assert (value["provider"], value["model"], value["gate"], value["selection_origin"]) == (
            "left", "base", fixtures["left"][1], origin), value
        return value

    def reply_saved(session_id, turns):
        value = ready_json(home / "sessions" / (session_id + ".json"))
        return value and value["turns"] >= turns and any(
            message["role"] == "assistant" and "owned fixture reply" in message["content"]
            for message in value["transcript"])

    # Both configuration success and complete-candidate refusal remain offline.
    before = counts()
    command("setup", "--easy", "left/base", "--hard", "right/advanced")
    status = command("status")
    preview = prediction()
    parsed = tomllib.loads(config_path.read_text())
    checked("offline_setup_status_preview_preserve_providers_roles_and_unknown_tables",
            counts() == before, status["enabled"], preview["phase"] == "coding",
            preview["difficulty"] == "hard", preview["provider_id"] == "right",
            preview["raw_model"] == "advanced", preview["source"] == "phase_difficulty",
            parsed["provider"] == provider_facts, parsed["roles"]["main"] == "left/base",
            parsed["fixture_metadata"]["keep"] == "routing-release",
            "local_fixture_authorization" not in json.dumps([status, preview]))

    command("set", "coding", "default", "right/shared")
    set_preview = command("test", "implement parser")
    command("reset", "coding")
    reset_preview = command("test", "implement parser")
    command("keywords", "add", "hard", "fixtureweight")
    keyword_preview = command("test", "implement fixtureweight parser")
    command("keywords", "remove", "hard", "fixtureweight")
    removed_preview = command("test", "implement fixtureweight parser")
    checked("offline_set_reset_and_keyword_edits_change_only_the_candidate_routing",
            set_preview["raw_model"] == "shared", set_preview["source"] == "phase_default",
            reset_preview["provider_id"] == "left", reset_preview["source"] == "base",
            keyword_preview["difficulty"] == "hard", removed_preview["difficulty"] == "normal",
            counts() == before, tomllib.loads(config_path.read_text())["provider"] == provider_facts)

    config_before = config_path.read_bytes()
    for words in [("set", "coding", "hard", "right/missing"),
                  ("set", "coding", "hard", "shared"),
                  ("setup", "--easy", "left/base", "--hard", "right/missing")]:
        cli("route", *words, "--json", success=False)
        assert config_path.read_bytes() == config_before, words
    checked("offline_invalid_full_candidates_preserve_exact_config_bytes_and_send_zero_requests",
            counts() == before, config_path.read_bytes() == config_before)

    # Preview uses the same explicit constraints as live selection; configuration
    # maintenance is independent of ambient session choices.
    before = counts()
    raw_before = config_path.read_bytes()
    result = cli("route", "test", prompt, "--model", "left/base", "--gate", fixtures["right"][1], "--json", success=False)
    checked("preview_conflicting_endpoint_refuses_without_mutation_or_provider_calls",
            bool(result.stderr), counts() == before, config_path.read_bytes() == raw_before)
    result = cli("route", "test", prompt, "--provider", "right", "--json", success=False)
    checked("preview_provider_constraint_requires_an_actual_model_selection",
            bool(result.stderr), counts() == before, config_path.read_bytes() == raw_before)
    for words in [("reset", "--model", "left/base"), ("off", "--provider", "left"),
                  ("set", "coding", "hard", "right/advanced", "--gate", fixtures["left"][1])]:
        result = cli("route", *words, "--json", success=False)
        assert result.stderr and counts() == before and config_path.read_bytes() == raw_before
    checked("configuration_mutations_reject_ignored_model_provider_and_gate_flags",
            counts() == before, config_path.read_bytes() == raw_before)
    cli("route", "setup", "--easy", "left/base", "--hard", "right/advanced", "--json",
        extra_env={"ORBIT_MODEL": "unrelated/missing-model", "ORBIT_GATE_URL": "https://unrelated.invalid"})
    configured = tomllib.loads(config_path.read_text())
    checked("offline_route_setup_ignores_unrelated_ambient_model_and_gate",
            configured["provider"] == provider_facts, configured["fixture_metadata"]["keep"] == "routing-release", counts() == before)
    result = cli("route", "status", "--json", extra_env={"ORBIT_MODEL": "unrelated/missing-model"})
    checked("offline_status_does_not_resolve_an_ambient_session_pin",
            json.loads(result.stdout)["status"] == "ok", counts() == before)
    raw_before = config_path.read_bytes()
    result = cli("route", "test", prompt, "--json", success=False,
                 extra_env={"ORBIT_MODEL": "unrelated/missing-model"})
    checked("preview_invalid_ambient_pin_refuses_as_live_startup_does",
            bool(result.stderr), counts() == before, config_path.read_bytes() == raw_before)

    # Restore one phase target, leaving normal turns on their stable base.
    command("reset")
    command("set", "coding", "hard", "right/advanced")
    auto_preview = prediction()
    pin_preview = prediction("--model", "left/base")
    assert auto_preview["provider_id"] == "right" and auto_preview["raw_model"] == "advanced"
    assert pin_preview["source"] == "explicit" and pin_preview["suppressed_reason"]

    before = counts()
    result, automatic_id = fresh_cli("-p", prompt, "--bare", "--output-format", "stream-json")
    exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
    auto_saved = base_preserved(automatic_id, "role")
    events = [json.loads(line) for line in result.stdout.splitlines() if line.strip()]
    route_lines = [item["text"] for item in events
                   if item.get("type") == "status" and item.get("text", "").startswith("route ")]
    checked("headless_automatic_request_matches_preview_once_and_keeps_role_base",
            auto_saved["turns"] == 1, reply_saved(automatic_id, 1), len(route_lines) == 1,
            "coding/hard" in route_lines[0], "right/advanced" in route_lines[0])

    before = counts()
    _, pinned_id = fresh_cli("-p", prompt, "--model", "left/base", "--bare")
    exact_call(before, pin_preview["provider_id"], pin_preview["raw_model"])
    base_preserved(pinned_id, "flag")
    before = counts()
    cli("-p", prompt, "--resume", pinned_id, "--bare")
    exact_call(before, "left", "base")
    checked("headless_same_default_flag_pin_survives_saved_session_restart",
            base_preserved(pinned_id, "flag")["turns"] == 2, reply_saved(pinned_id, 2))

    before = counts()
    _, environment_id = fresh_cli("-p", prompt, "--bare", extra_env={"ORBIT_MODEL": "left/base"})
    exact_call(before, "left", "base")
    checked("headless_environment_choice_equal_to_default_is_an_explicit_pin",
            base_preserved(environment_id, "environment")["turns"] == 1)

    before = counts()
    cleared = command("auto", "--session", pinned_id)
    assert counts() == before and saved(pinned_id)["selection_origin"] == "default"
    cli("-p", prompt, "--resume", pinned_id, "--bare")
    exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
    checked("offline_saved_route_auto_clears_pin_without_request_then_resumed_headless_routes",
            cleared["selection_origin"] == "default", base_preserved(pinned_id, "default")["turns"] == 3)

    before = counts()
    result, plain_id = fresh_cli("--no-tui", "--bare", stdin=prompt + "\nhello there\nexit\n")
    expected = (before[0] + 1, before[1] + 1)
    assert counts() == expected, (counts(), expected, result.stdout, result.stderr)
    checked("plain_repl_routes_hard_then_normal_once_each_and_keeps_base",
            calls("right")[-1]["model"] == auto_preview["raw_model"],
            calls("left")[-1]["model"] == "base", base_preserved(plain_id, "role")["turns"] == 2,
            "route coding/hard → right/advanced" in result.stdout,
            "route general/normal → left/base" in result.stdout)

    before = counts()
    cli("--no-tui", "--resume", plain_id, "--bare", stdin="/model left/base\n" + prompt + "\nexit\n")
    exact_call(before, "left", "base")
    before = counts()
    cli("--no-tui", "--resume", plain_id, "--bare", stdin=prompt + "\nexit\n")
    exact_call(before, "left", "base")
    checked("plain_manual_same_default_pin_is_durable_across_repl_restart",
            base_preserved(plain_id, "interactive")["turns"] == 4)

    before = counts()
    query = cli("--no-tui", "--resume", plain_id, "--bare", stdin="/route\n/route auto\nexit\n")
    assert counts() == before and saved(plain_id)["selection_origin"] == "default"
    result = cli("--no-tui", "--resume", plain_id, "--bare", stdin=prompt + "\nexit\n")
    exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
    checked("plain_route_query_and_auto_are_offline_then_next_turn_matches_preview",
            "Automatic routing enabled" in query.stdout,
            "route coding/hard → right/advanced" in result.stdout,
            base_preserved(plain_id, "default")["turns"] == 5)

    owner_socket = home / "run/live-routing.sock"

    def owner_start(resume=False):
        words = ["--resume", "live-routing-owner"] if resume else ["--session", "live-routing-owner"]
        process = subprocess.Popen([binary, "serve", "--home", str(home), "--socket", str(owner_socket),
                                    *words, "--bare"], cwd=work, env=env,
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)
        wait_for(lambda: owner_socket.exists() or process.poll() is not None, "live owner socket")
        assert process.poll() is None, "live owner startup failed"
        return process

    def owner_status():
        return json.loads(cli("attach", "--socket", str(owner_socket), "--status").stdout)

    def owner_input(text):
        return cli("attach", "--socket", str(owner_socket), stdin=text + "\n/detach\n")

    def owner_turn():
        before = counts()
        turns = owner_status()["turns"]
        owner_input(prompt)
        snapshot = wait_for(lambda: (value if (value := owner_status())["turns"] == turns + 1
                                    and value["state"] == "idle" else None), "attached turn completion")
        return before, snapshot

    def owner_stop(process):
        cli("attach", "--socket", str(owner_socket), "--stop")
        assert process.wait(timeout=8) == 0
        wait_for(lambda: not owner_socket.exists(), "owner socket cleanup")

    owner = owner_start()
    before = counts()
    owner_input("/route\n/effort\n/models\n/sessions")
    assert counts() == before and owner_status()["turns"] == 0
    before, snapshot = owner_turn()
    exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
    checked("owner_attach_queries_are_offline_and_one_shared_decision_matches_preview",
            decision_fields(snapshot["last_route"]) == decision_fields(auto_preview),
            snapshot["provider"] == "left", snapshot["model"] == "base",
            snapshot["selection_origin"] == "role", reply_saved("live-routing-owner", 1))

    before = counts()
    owner_input("/model left/base")
    assert counts() == before and owner_status()["selection_origin"] == "interactive"
    owner_stop(owner)
    owner = owner_start(resume=True)
    assert counts() == before and owner_status()["selection_origin"] == "interactive"
    before, snapshot = owner_turn()
    exact_call(before, "left", "base")
    checked("attached_manual_same_default_pin_survives_owner_restart_without_replay",
            snapshot["last_route"]["source"] == "explicit", snapshot["turns"] == 2,
            base_preserved("live-routing-owner", "interactive")["turns"] == 2)

    before = counts()
    owner_input("/route auto")
    assert counts() == before and owner_status()["selection_origin"] == "default"
    before, snapshot = owner_turn()
    exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
    checked("attached_route_auto_is_offline_and_next_owner_turn_routes_once",
            decision_fields(snapshot["last_route"]) == decision_fields(auto_preview),
            base_preserved("live-routing-owner", "default")["turns"] == 3)
    owner_stop(owner)

    def browser_start(session_id=None):
        with socket.socket() as chosen:
            chosen.bind(("127.0.0.1", 0))
            port = chosen.getsockname()[1]
        words = ["--resume", session_id] if session_id else []
        process = subprocess.Popen([web, "--home", str(home), "--port", str(port), "--no-browser", "--bare", *words],
                                   cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        processes.append(process)

        def listening():
            assert process.poll() is None, "live browser startup failed"
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return True
            except OSError:
                return False

        wait_for(listening, "live browser listener")
        stream = module.SSEClient(port)
        recovery = stream.wait_for("recovery", timeout=8)
        assert recovery, "browser recovery event required"
        controller = module.WSClient(port)
        ready = json.loads(controller.recv_text(timeout=8))
        assert ready.get("type") == "controller_ready", ready
        return process, stream, controller, recovery["snapshot"]

    def action(controller, value):
        controller.send(value)
        reply = json.loads(controller.recv_text(timeout=8))
        assert reply.get("type") == "action_ack", reply
        return reply["snapshot"]

    def browser_turn(stream, controller, request_id):
        before = counts()
        action(controller, {"type": "prompt", "request_id": request_id, "text": prompt})
        finished = stream.wait_for("request_finished", timeout=10, pred=lambda value: value["request_id"] == request_id)
        assert finished, ("browser request not finished", request_id)
        # Read-only owner action obtains authoritative completion state; the
        # browser's own projection is independently covered by its DOM suite.
        snapshot = action(controller, {"type": "routing"})
        return before, snapshot

    def browser_stop(process, stream, controller):
        try:
            controller.send({"type": "stop"})
            assert process.wait(timeout=8) == 0
        finally:
            controller.sock.close()
            stream.sock.close()
            stream.thread.join(timeout=2)

    browser, stream, controller, snapshot = browser_start()
    try:
        browser_id = snapshot["session_id"]
        before = counts()
        for kind in ("routing", "effort", "list_models", "list_sessions"):
            action(controller, {"type": kind})
        assert counts() == before
        before, snapshot = browser_turn(stream, controller, "browser-routing-1")
        exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
        route_event = stream.wait_for("routing", timeout=8, pred=lambda value: "source" in value)
        checked("browser_queries_are_offline_and_shared_owner_request_matches_exact_preview",
                decision_fields(snapshot["last_route"]) == decision_fields(auto_preview),
                decision_fields(route_event) == decision_fields(auto_preview), snapshot["turns"] == 1,
                base_preserved(browser_id, "role")["turns"] == 1)
        before = counts()
        snapshot = action(controller, {"type": "set_model", "model": "left/base", "provider": None})
        assert counts() == before and snapshot["selection_origin"] == "interactive"
    finally:
        browser_stop(browser, stream, controller)

    browser, stream, controller, snapshot = browser_start(browser_id)
    try:
        assert counts() == before and snapshot["selection_origin"] == "interactive"
        before, snapshot = browser_turn(stream, controller, "browser-routing-2")
        exact_call(before, "left", "base")
        checked("browser_manual_same_default_pin_survives_restart_without_replay",
                snapshot["last_route"]["source"] == "explicit", snapshot["turns"] == 2,
                base_preserved(browser_id, "interactive")["turns"] == 2)
        before = counts()
        snapshot = action(controller, {"type": "route_auto"})
        assert counts() == before and snapshot["selection_origin"] == "default"
        before, snapshot = browser_turn(stream, controller, "browser-routing-3")
        exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
        checked("browser_route_auto_is_offline_and_next_shared_owner_turn_routes_once",
                decision_fields(snapshot["last_route"]) == decision_fields(auto_preview),
                base_preserved(browser_id, "default")["turns"] == 3)
    finally:
        browser_stop(browser, stream, controller)

    from pty_tui_test import PtySession, pyte
    assert pyte is not None, "pyte required for real terminal routing assertions"
    # PtySession merges the parent environment. Explicitly remove inherited
    # routing knobs absent from our isolated environment without mutating it.
    clean_env = [part for key in os.environ if key.startswith("ORBIT_") and key not in env
                 for part in ("-u", key)]

    def terminal_start(session_id=None):
        before = session_ids()
        words = ["--resume", session_id] if session_id else []
        terminal = PtySession(["/usr/bin/env", *clean_env, binary, "--home", str(home), "--bare", *words],
                              env=env, cwd=work, rows=44, cols=160)
        processes.append(terminal.proc)
        try:
            terminal_wait(terminal, lambda: "ORBIT" in terminal.screen_text(), "terminal routing boot")
            if session_id is None:
                created = session_ids() - before
                assert len(created) == 1, created
                session_id = created.pop()
            return terminal, session_id
        except BaseException:
            terminal.terminate()
            raise

    def terminal_wait(terminal, predicate, label):
        def probe():
            terminal.read(0.1)
            assert terminal.proc.poll() is None, terminal.screen_text()
            return predicate()
        return wait_for(probe, label, seconds=12)

    def terminal_input(terminal, text):
        terminal.type(text)
        terminal.key("enter")

    def terminal_turn(terminal, session_id, turns):
        before = counts()
        terminal_input(terminal, prompt)
        terminal_wait(terminal, lambda: reply_saved(session_id, turns), "terminal routed reply saved")
        return before

    terminal, terminal_id = terminal_start()
    try:
        before = terminal_turn(terminal, terminal_id, 1)
        exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
        terminal_wait(terminal, lambda: "right/advanced" in terminal.screen_text(), "terminal routing visible")
        checked("terminal_automatic_live_request_matches_preview_and_displays_route",
                base_preserved(terminal_id, "role")["turns"] == 1,
                "coding/hard" in terminal.screen_text())
        before = counts()
        terminal_input(terminal, "/model left/base")
        terminal_wait(terminal, lambda: saved(terminal_id)["selection_origin"] == "interactive", "terminal pin saved")
        assert counts() == before
    finally:
        terminal.terminate()

    terminal, _ = terminal_start(terminal_id)
    try:
        assert counts() == before
        before = terminal_turn(terminal, terminal_id, 2)
        exact_call(before, "left", "base")
        checked("terminal_manual_same_default_pin_survives_restart_without_request_replay",
                base_preserved(terminal_id, "interactive")["turns"] == 2)
        before = counts()
        terminal_input(terminal, "/route status")
        terminal_wait(terminal, lambda: '"selection_origin": "interactive"' in terminal.screen_text()
                      or '"pinned": true' in terminal.screen_text(), "terminal offline route status")
        terminal_input(terminal, "/route auto")
        terminal_wait(terminal, lambda: saved(terminal_id)["selection_origin"] == "default", "terminal auto saved")
        assert counts() == before
        before = terminal_turn(terminal, terminal_id, 3)
        exact_call(before, auto_preview["provider_id"], auto_preview["raw_model"])
        checked("terminal_route_status_and_auto_are_offline_then_next_request_routes_once",
                base_preserved(terminal_id, "default")["turns"] == 3,
                "Automatic routing enabled" in terminal.screen_text())
    finally:
        terminal.terminate()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/orbit")
    parser.add_argument("--web", default="target/debug/orbit-web")
    parser.add_argument("--group", choices=["identity", "all"], default="all")
    args = parser.parse_args()
    binary, web = str(Path(args.binary).resolve()), str(Path(args.web).resolve())
    scripts = Path(__file__).resolve().parent
    scenarios, processes = {}, []

    def checked(label, *conditions):
        assert label not in scenarios, ("duplicate scenario", label)
        assert conditions and all(conditions), label
        scenarios[label] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + label, flush=True)

    try:
        with fixture_directory(processes) as tmp:
            root = Path(tmp)
            home, work = root / "home", root / "workspace"
            work.mkdir(mode=0o700)
            env = os.environ.copy()
            for key in list(env):
                if key.startswith("ORBIT_"):
                    env.pop(key)
            env.update(ORBIT_HOME=str(home), ORBIT_FIXTURE_TOKEN="local_fixture_authorization")

            def cli(*words, stdin=None, success=True, extra_env=None):
                result = subprocess.run([binary, *words, "--home", str(home)], cwd=work,
                                        env={**env, **(extra_env or {})}, input=stdin,
                                        text=True, capture_output=True, timeout=15)
                if success:
                    assert result.returncode == 0, (words, result.returncode, result.stdout, result.stderr)
                else:
                    assert result.returncode != 0, (words, result.stdout)
                return result

            cli("init", "--no-provider")
            fixtures = {}
            for name in ("left", "right"):
                path = root / name
                path.mkdir(mode=0o700)
                process = subprocess.Popen(["python3", str(scripts / "fixtures/p35_provider.py"), str(path)],
                                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                processes.append(process)
                fixtures[name] = (path, wait_for(lambda p=path: ready_json(p / "ready.json"), name + " provider")["gate"])

            raw = ""
            for name, (_, gate) in fixtures.items():
                raw += f'[[provider]]\nname="{name}"\nurl="{gate}"\nenv="ORBIT_FIXTURE_TOKEN"\n'
                for model in (["base", "left/base", "shared"] if name == "left" else ["shared", "advanced"]):
                    raw += f'[[provider.models]]\nid="{model}"\nsupported_efforts=["low","high"]\ndefault_effort="low"\n'
            raw += '[roles]\nmain="left/base"\n'
            (home / "providers.toml").write_text(raw)
            (home / "providers.toml").chmod(0o600)

            def calls(name=None):
                selected = [fixtures[name]] if name else fixtures.values()
                result = []
                for path, _ in selected:
                    file = path / "calls.jsonl"
                    if file.exists():
                        data = file.read_text()
                        for line in data.splitlines(keepends=True):
                            # The fixture flushes one JSONL record before replying;
                            # readiness polling may catch its final partial write.
                            if line.endswith("\n"):
                                result.append(json.loads(line))
                return result

            cli("-p", "qualified identity", "--model", "left/base", "--bare")
            checked("qualified_headless_uses_exact_provider_and_raw_model", len(calls("left")) == 1,
                    calls("left")[-1]["model"] == "base", not calls("right"))
            cli("-p", "raw slash identity", "--model", "left/left/base", "--bare")
            checked("slash_bearing_raw_identity_is_not_stripped_twice", len(calls("left")) == 2,
                    calls("left")[-1]["model"] == "left/base", not calls("right"))
            for label, options in [
                ("ambiguous_bare_model_refuses_before_dispatch_or_mutation", ["--model", "shared"]),
                ("unknown_qualified_model_refuses_before_dispatch_or_mutation", ["--model", "left/missing"]),
                ("conflicting_provider_and_qualified_model_refuses", ["--model", "left/base", "--provider", "right"]),
            ]:
                before, count = digest_tree(home), len(calls())
                result = cli("-p", "must refuse", *options, "--bare", success=False)
                checked(label, bool(result.stderr), len(calls()) == count, digest_tree(home) == before)
            cli("-p", "hinted duplicate", "--provider", "right", "--model", "shared", "--bare")
            checked("explicit_provider_disambiguates_duplicate_raw_model", len(calls("right")) == 1,
                    calls("right")[-1]["model"] == "shared")

            owner_socket = home / "run/routing.sock"
            owner = subprocess.Popen([binary, "serve", "--home", str(home), "--socket", str(owner_socket),
                                      "--session", "identity-owner", "--model", "left/left/base", "--bare"],
                                     cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(owner)
            wait_for(lambda: owner_socket.exists() or owner.poll() is not None, "owner socket")
            assert owner.poll() is None, "owner startup failed"
            snapshot = json.loads(cli("attach", "--socket", str(owner_socket), "--status").stdout)
            checked("owner_startup_keeps_exact_raw_slash_identity_without_request",
                    snapshot["model"] == "left/base", snapshot["provider"] == "left", len(calls()) == 3)
            cli("attach", "--socket", str(owner_socket), "--stop")
            assert owner.wait(timeout=8) == 0

            with socket.socket() as chosen:
                chosen.bind(("127.0.0.1", 0))
                port = chosen.getsockname()[1]
            browser = subprocess.Popen([web, "--home", str(home), "--model", "left/left/base", "--port", str(port), "--no-browser", "--bare"],
                                       cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            processes.append(browser)

            def listening():
                if browser.poll() is not None:
                    raise AssertionError("browser startup failed")
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                        return True
                except OSError:
                    return False

            wait_for(listening, "browser listener")
            spec = importlib.util.spec_from_file_location("orbit_browser_fixture", scripts / "web_harness_test.py")
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            stream = module.SSEClient(port)
            recovery = stream.wait_for("recovery", timeout=8)
            snapshot = recovery["snapshot"]
            checked("browser_startup_uses_shared_exact_identity_without_request",
                    snapshot["model"] == "left/base", snapshot["provider"] == "left", len(calls()) == 3)
            controller = module.WSClient(port)
            controller.send({"type": "stop"})
            assert browser.wait(timeout=8) == 0
            controller.sock.close()
            stream.sock.close()
            stream.thread.join(timeout=2)

            if args.group == "all":
                live_workflows(binary, web, scripts, root, home, work, env, cli, calls,
                               fixtures, processes, module, checked)
                for prompt in ("setup", "web", "--help"):
                    count = len(calls("left"))
                    right_count = len(calls("right"))
                    cli("-p", prompt, "--model", "left/base", "--bare")
                    captured = calls("left")[-1]
                    checked("headless_literal_" + prompt.lstrip('-') + "_is_sent_as_one_prompt",
                            len(calls("left")) == count + 1,
                            len(calls("right")) == right_count,
                            captured["model"] == "base",
                            any(message.get("role") == "user" and message.get("content") == prompt
                                for message in captured["messages"]))
            print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}), flush=True)
    finally:
        for process in reversed(processes):
            stop_process(process)


if __name__ == "__main__":
    main()
