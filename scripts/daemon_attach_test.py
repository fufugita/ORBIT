#!/usr/bin/env python3
"""Exercise the foreground owner and attach CLI against a captured local provider.

Run in scripts/in-jail.sh. Each receipt describes observed behavior, not source text.
"""
import argparse
import json
import os
import signal
from pathlib import Path
import stat
import subprocess
import tempfile
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default="target/debug/orbit")
    args = parser.parse_args()
    binary = str(Path(args.binary).resolve())
    provider_script = Path(__file__).resolve().parent / "fixtures/p35_provider.py"
    scenarios = {}
    processes = []

    def checked(label, *conditions):
        assert conditions and all(conditions), label
        scenarios[label] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + label, flush=True)

    def wait_for(predicate, label, seconds=10):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            value = predicate()
            if value:
                return value
            time.sleep(0.025)
        raise AssertionError("timed out: " + label)

    try:
        with tempfile.TemporaryDirectory(prefix="orbit-daemon-cli-") as tmp:
            root = Path(tmp)
            home, work = root / "home", root / "workspace"
            work.mkdir()
            fixture = root / "provider"
            fixture.mkdir(mode=0o700)
            provider = subprocess.Popen(
                ["python3", str(provider_script), str(fixture)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            processes.append(provider)
            wait_for(lambda: (fixture / "ready.json").exists(), "provider readiness")
            gate = json.loads((fixture / "ready.json").read_text())["gate"]
            env = os.environ.copy()
            for key in ["ORBIT_MODEL", "ORBIT_ACTIVE_MODEL", "ORBIT_EFFORT", "ORBIT_GATE_URL"]:
                env.pop(key, None)
            env.update(ORBIT_HOME=str(home), ORBIT_GATE_TOKEN="local_fixture_authorization", ORBIT_GATE_URL=gate)

            def cli(*words, stdin=None, expect=0):
                result = subprocess.run(
                    [binary, *words, "--home", str(home)], cwd=work, env=env,
                    input=stdin, text=True, capture_output=True, timeout=15,
                )
                assert result.returncode == expect, (words, result.returncode, result.stdout, result.stderr)
                return result

            cli("init", "--no-provider")
            (home / "providers.toml").write_text(
                f'[[provider]]\nname="fixture"\nurl="{gate}"\nenv="ORBIT_GATE_TOKEN"\n'
                '[[provider.models]]\nid="fixture/model-a"\nsupported_efforts=["low","high"]\ndefault_effort="low"\n'
                '[[provider.models]]\nid="model-a"\nsupported_efforts=["low"]\ndefault_effort="low"\n'
            )
            socket = home / "run/owner.sock"
            owner_log = (root / "owner.log").open("w+")

            def start_owner(resume=False):
                identity = ["--resume", "owned-cli"] if resume else ["--session", "owned-cli"]
                model_args = [] if resume else ["--model", "fixture/fixture/model-a"]
                process = subprocess.Popen(
                    [binary, "--permission-mode", "dontAsk", "serve", "--home", str(home),
                     "--socket", str(socket), *model_args, *identity],
                    cwd=work, env=env, stdout=owner_log, stderr=owner_log,
                )
                processes.append(process)
                wait_for(lambda: socket.exists() or process.poll() is not None, "owner socket")
                assert process.poll() is None, owner_log.read()
                return process

            def calls():
                path = fixture / "calls.jsonl"
                return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

            def status():
                return json.loads(cli("attach", "--socket", str(socket), "--status").stdout)

            owner = start_owner()
            refused = cli("serve", "--socket", str(socket), "--resume", "owned-cli", "--continue", expect=2)
            checked("conflicting_session_selectors_refuse_before_dispatch", "choose --resume or --continue" in refused.stderr, len(calls()) == 0)
            checked("private_socket_and_directory", stat.S_ISSOCK(socket.stat().st_mode),
                    stat.S_IMODE(socket.stat().st_mode) == 0o600,
                    stat.S_IMODE(socket.parent.stat().st_mode) == 0o700)
            snapshot = status()
            checked("read_only_status_without_provider_request", snapshot["session_id"] == "owned-cli",
                    snapshot["state"] == "idle", len(calls()) == 0)
            duplicate = cli("serve", "--socket", str(socket), "--resume", "owned-cli", expect=2)
            checked("second_owner_refuses", "already owned" in duplicate.stderr.lower(), len(calls()) == 0)
            before = (home / "sessions/owned-cli.json").read_bytes()
            denied = cli("-p", "must not reach provider", "--resume", "owned-cli",
                         "--model", "fixture/model-a", "--provider", "fixture", "--gate", gate, expect=1)
            checked("headless_respects_owned_session", "already owned" in denied.stderr.lower(),
                    (home / "sessions/owned-cli.json").read_bytes() == before, len(calls()) == 0)
            cli("attach", "--socket", str(socket), stdin="one owned prompt\n/detach\n")
            wait_for(lambda: len(calls()) == 1, "single prompt request")
            wait_for(lambda: status()["state"] == "idle", "completed turn")
            saved = json.loads((home / "sessions/owned-cli.json").read_text())
            checked("one_prompt_one_request_and_saved_reply", len(calls()) == 1, saved["turns"] == 1,
                    any(m["role"] == "assistant" for m in saved["transcript"]))
            snapshot = status()
            checked("reconnect_reads_completed_state", len(calls()) == 1,
                    any("owned fixture reply" in m.get("text", "") for m in snapshot["messages"]),
                    snapshot["cursor"]["sequence"] > 0)
            cli("attach", "--socket", str(socket), stdin="/effort high\n/detach\n")
            snapshot = wait_for(lambda: (s if (s := status())["effort"] == {"mode": "value", "value": "high"} else None), "effort save")
            checked("settings_save_without_provider_request", len(calls()) == 1,
                    snapshot["resolved_effort"] == "high",
                    json.loads((home / "sessions/owned-cli.json").read_text())["effort"] == snapshot["effort"])
            logs = json.loads(cli("attach", "--socket", str(socket), "--logs").stdout)
            checked("read_only_logs_recover_cursor", logs["snapshot"]["session_id"] == "owned-cli",
                    logs["cursor"]["instance"] == snapshot["cursor"]["instance"], len(calls()) == 1)
            (fixture / "mode.json").write_text(json.dumps({"blocked": True}))
            cli("attach", "--socket", str(socket), stdin="cancel this request\n/detach\n")
            wait_for(lambda: len(calls()) == 2, "blocked request")
            cli("attach", "--socket", str(socket), "--cancel")
            cancelled = wait_for(lambda: (s if (s := status())["state"] in ["idle", "interrupted"] else None), "cancel completion", seconds=3)
            # A cancelled in-flight request settles conservative: billing is
            # uncertain (no receipt ever arrived), so the record is unknown
            # with a terminal snapshot state — never silently replayed. This
            # matches owned-session p35_daemon cancel expectations.
            unknown_ids = [key for key, record in cancelled["requests"].items() if record["state"] == "unknown"]
            checked("cancel_is_bounded_and_never_replays", len(calls()) == 2,
                    calls()[-1].get("reasoning_effort") == "high", len(unknown_ids) == 1,
                    cancelled["state"] in ["idle", "interrupted"])
            cli("attach", "--socket", str(socket), "--stop")
            assert owner.wait(timeout=8) == 0
            wait_for(lambda: not socket.exists(), "socket cleanup")
            (fixture / "release").touch()
            (fixture / "mode.json").write_text("{}")
            # The cancelled request settled conservatively: its accounting is
            # uncertain, so admission of a new owner is refused until the
            # uncertainty is inspected read-only (orbit recovery status).
            # This matches owned-session p35_daemon restart-refusal tests.
            resumed = subprocess.Popen(
                [binary, "--permission-mode", "dontAsk", "serve", "--home", str(home),
                 "--socket", str(socket), "--resume", "owned-cli"],
                cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            processes.append(resumed)
            wait_for(lambda: resumed.poll() is not None, "resume refusal exit")
            checked("restart_admission_refused_after_uncertainty", resumed.returncode != 0,
                    len(calls()) == 2)
            inspect = cli("recovery", "status", "--session", "owned-cli", "--json")
            inspected = json.loads(inspect.stdout)
            checked("restart_refused_and_inspection_reads_uncertainty",
                    len(calls()) == 2,
                    inspected["status"] == "available",
                    inspected["owner_session_id"] == "owned-cli",
                    inspected["totals"]["knownness"] == "uncertain",
                    inspected["pending"]["uncertain"] is True,
                    unknown_ids[0] in inspected["pending"]["receipt"]["request_id"])
            # Signal cleanup needs a live owner: run one on a fresh session.
            signal_socket = home / "run/signal.sock"
            signal_owner = subprocess.Popen(
                [binary, "--permission-mode", "dontAsk", "serve", "--home", str(home),
                 "--socket", str(signal_socket), "--session", "owned-signal",
                 "--model", "fixture/fixture/model-a"],
                cwd=work, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            )
            processes.append(signal_owner)
            wait_for(lambda: signal_socket.exists() or signal_owner.poll() is not None, "signal socket")
            assert signal_owner.poll() is None
            signal_owner.send_signal(signal.SIGTERM)
            checked("foreground_signal_cleans_up_with_signal_exit", signal_owner.wait(timeout=8) == 128 + signal.SIGTERM,
                    not signal_socket.exists(), len(calls()) == 2)
            owner_log.close()
            print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}), flush=True)
    finally:
        for process in reversed(processes):
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)


if __name__ == "__main__":
    main()
