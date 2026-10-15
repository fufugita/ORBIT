#!/usr/bin/env python3
"""Actual disposable offline setup and doctor workflows. Run inside in-jail.sh."""
import argparse
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import threading


def tree(path):
    return {str(p.relative_to(path)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in path.rglob("*") if p.is_file() and not p.is_symlink()}


def identity(path):
    names = ["trust/operator.key", "trust/manifest.json", "pib.json"]
    names.extend(str(p.relative_to(path)) for p in sorted((path / "ledger").rglob("*"))
                 if p.is_file())
    return {name: (path / name).read_bytes() for name in names}


def private(path, data):
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_bytes(data if isinstance(data, bytes) else data.encode())
    path.chmod(0o600)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=Path("target/debug/orbit"))
    parser.add_argument("--group", choices=["setup", "all"], default="all")
    options = parser.parse_args()
    binary = options.binary.resolve(strict=True)
    os.umask(0o077)
    checks = {}
    calls = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            calls.append(("GET", self.path))
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"data":[{"id":"fixture/raw"}]}')

        def do_POST(self):
            calls.append(("POST", self.path))
            self.send_response(500)
            self.end_headers()

        def log_message(self, *unused):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        with tempfile.TemporaryDirectory(prefix="orbit-release-setup-") as tmp:
            root = Path(tmp)
            work = root / "work"
            work.mkdir(mode=0o700)
            env = os.environ.copy()
            for key in ("ORBIT_MODEL", "ORBIT_GATE", "ORBIT_SESSION_ID", "ORBIT_SEARCH_API", "ORBIT_SEARCH_KEY"):
                env.pop(key, None)
            secret = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"
            env.update(HOME=str(root), XDG_CONFIG_HOME=str(root / "xdg"),
                       FIXTURE_SETUP_KEY=secret, NO_COLOR="1")

            def run(home, *words, expected=0, raw=False, extra_env=None):
                process_env = dict(env, ORBIT_HOME=str(home))
                if extra_env:
                    process_env.update(extra_env)
                result = subprocess.run([str(binary), "--home", str(home), *map(str, words)],
                                        cwd=work, env=process_env, input="", text=True,
                                        capture_output=True, timeout=30)
                assert result.returncode in ([0, 1] if expected is None else [expected]), (words, result.returncode, result.stdout, result.stderr)
                assert secret not in result.stdout + result.stderr, "credential value leaked"
                assert len(result.stdout.encode()) <= 128 * 1024, "unbounded report"
                return result if raw else json.loads(result.stdout)

            def passed(name):
                assert not calls, (name, "unexpected provider traffic", calls)
                checks[name] = {"passed": True, "assertions": 1}

            home = root / "home"
            first = run(home, "init", "--no-provider")
            assert first["schema"] == "orbit.cli/v1" and first["status"] == "ok"
            assert first["trust_root_verified"] and first["pib_id"].startswith("pib-")
            assert all(stat.S_IMODE((home / name).stat().st_mode) == 0o600
                       for name in ("trust/operator.key", "trust/manifest.json", "pib.json"))
            before = identity(home)
            passed("fresh_private_identity_offline")

            repeat = run(home, "setup", "--no-provider", "--json")
            assert repeat["reused"] and repeat["pib_id"] == first["pib_id"] and identity(home) == before
            passed("repeat_setup_preserves_exact_identity")

            gate = f"http://127.0.0.1:{server.server_port}/v1"
            flags = ("--provider", "fixture", "--gate", gate, "--model", "family/raw,family/second", "--credential-env", "FIXTURE_SETUP_KEY")
            added = run(home, "setup", *flags, "--json")
            assert added["providers_configured"] == ["fixture"] and identity(home) == before
            config = (home / "providers.toml").read_bytes()
            assert b"family/raw" in config and secret.encode() not in config
            passed("manual_provider_configuration_preserves_identity")

            unchanged = tree(home)
            again = run(home, "init", *flags, "--json")
            assert not again["config_changed"] and tree(home) == unchanged
            passed("repeat_provider_setup_is_byte_identical")

            dry_home = root / "dry"
            plan = run(dry_home, "setup", *flags, "--dry-run", "--json")
            assert plan["status"] == "dry_run" and plan["plan"]["initialize"] and not dry_home.exists()
            passed("setup_dry_run_plans_without_mutation")

            bad_home = root / "bad-url"
            run(bad_home, "init", "--provider", "bad", "--gate", "relative/path", "--model", "raw", expected=2, raw=True)
            assert not bad_home.exists()
            passed("invalid_provider_input_refuses_before_home")

            unknown_home = root / "unknown"
            run(unknown_home, "setup", "--unknown-option", expected=2, raw=True)
            assert not unknown_home.exists()
            passed("unknown_flag_refuses_before_home")

            partial_home = root / "partial"
            run(partial_home, "init", "--no-provider")
            (partial_home / "pib.json").unlink()
            partial_before = tree(partial_home)
            run(partial_home, "setup", "--no-provider", expected=2, raw=True)
            assert tree(partial_home) == partial_before
            passed("partial_identity_never_rotates_remaining_material")

            if options.group == "setup":
                print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": checks}, sort_keys=True))
                return 0

            dispatch_before = tree(home)
            prefix = run(home, "--json", "setup")
            assert prefix["reused"] and not prefix["initialized"] and tree(home) == dispatch_before
            passed("leading_json_setup_uses_strict_command_dispatch_without_session_creation")
            rejected = run(home, "--unknown", "customize", "show", expected=2, raw=True)
            assert rejected.stderr and tree(home) == dispatch_before
            passed("unknown_prefix_cannot_enter_chat_or_create_a_session")

            rejected = run(home, "customize", "set", "name", "-p", "hello", expected=2, raw=True)
            assert rejected.stderr and tree(home) == dispatch_before
            passed("local_command_operand_cannot_select_headless_or_send_provider_request")

            for arguments in [("-p", "hello", "--unknown"), ("-p", "hello", "unexpected")]:
                rejected = run(home, *arguments, expected=1, raw=True)
                assert rejected.stderr and tree(home) == dispatch_before
            passed("headless_unknown_arguments_refuse_before_identity_or_session_mutation")

            for flag, value in [("--max-cost", "typo"), ("--max-cost", "-1"),
                                ("--max-cost", "18446744073709551616"),
                                ("--max-turns", "typo"), ("--max-turns", "4294967296")]:
                rejected = run(home, "-p", "must not send", flag, value, expected=1, raw=True)
                assert rejected.stderr and tree(home) == dispatch_before
                untouched = root / "invalid-headless-budget"
                run(untouched, "-p", "must not initialize", flag, value, expected=1, raw=True)
                assert not untouched.exists()
            passed("invalid_headless_budgets_never_disable_guard_or_initialize_home")

            rejected = run(home, "-p", "must not send", "--output-format", "unknown", expected=1, raw=True)
            assert rejected.stderr and tree(home) == dispatch_before
            passed("invalid_headless_output_format_refuses_without_provider_or_session")

            schema_path = work / "invalid-schema.json"
            for content in [b"{broken", b"[]", b" " * (128 * 1024 + 1)]:
                schema_path.write_bytes(content)
                rejected = run(home, "-p", "must not send", "--json-schema", schema_path, expected=1, raw=True)
                assert rejected.stderr and tree(home) == dispatch_before
            schema_path.unlink()
            os.mkfifo(schema_path, 0o600)
            rejected = run(home, "-p", "must not send", "--json-schema", schema_path, expected=1, raw=True)
            assert rejected.stderr and tree(home) == dispatch_before
            schema_path.unlink()
            passed("invalid_oversized_or_fifo_schema_refuses_without_falling_back_to_plain_request")

            for key in ("api_key", "%61pi%5fkey", "Access-Token"):
                unsafe_gate = gate + "?" + key + "=PRIVATE_QUERY_CREDENTIAL"
                private(home / "providers.toml", config.decode().replace(gate, unsafe_gate))
                unsafe_before = tree(home)
                for arguments in [("provider", "list"), ("models",)]:
                    rejected = run(home, *arguments, expected=2, raw=True)
                    assert "PRIVATE_QUERY_CREDENTIAL" not in rejected.stdout + rejected.stderr
                    assert tree(home) == unsafe_before
                query_home = root / "query-credential-home"
                rejected = run(query_home, "setup", "--provider", "bad", "--gate", unsafe_gate,
                               "--model", "raw", expected=2, raw=True)
                assert not query_home.exists() and "PRIVATE_QUERY_CREDENTIAL" not in rejected.stdout + rejected.stderr
            private(home / "providers.toml", config.decode().replace(gate, gate + "?api-version=2026-01-01"))
            assert "api-version=2026-01-01" in run(home, "provider", "list")["providers"][0]["url"]
            private(home / "providers.toml", config)
            assert tree(home) == dispatch_before
            passed("credential_queries_are_refused_before_setup_or_provider_metadata_display")

            legacy_home = root / "legacy-explicit-gateway"
            run(legacy_home, "init", "--no-provider")
            legacy_before = tree(legacy_home)
            for key in ("api_key", "%61pi%5fkey", "Access-Token"):
                unsafe_gate = gate + "?" + key + "=PRIVATE_QUERY_CREDENTIAL"
                rejected = run(legacy_home, "-p", "must not send", "--model", "raw",
                               "--gate", unsafe_gate, expected=1, raw=True)
                assert "PRIVATE_QUERY_CREDENTIAL" not in rejected.stdout + rejected.stderr
                assert tree(legacy_home) == legacy_before
                assert not list((legacy_home / "sessions").glob("*.json"))
            passed("legacy_gateway_credential_query_refuses_without_request_or_session_mutation")

            report = run(home, "doctor", "--json", expected=None)["report"]
            assert any(c["id"] == "provider.0" and c["status"] == "configured" for c in report["checks"])
            assert all("connectivity" not in c["id"] or c["status"] == "not_tested" for c in report["checks"])
            passed("doctor_distinguishes_configured_from_live_validation")

            private(home / "providers.toml", config.decode().replace("FIXTURE_SETUP_KEY", "FIXTURE_ABSENT_SETUP_KEY"))
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert not report["ready"] and any(c["id"] == "credential.0" and c["status"] == "missing" for c in report["checks"])
            private(home / "providers.toml", config)
            passed("doctor_missing_env_is_presence_only")

            private(home / "providers.toml", "provider = [ malformed\n")
            malformed = tree(home)
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert any(c["id"] == "providers" and c["status"] == "invalid" for c in report["checks"]) and tree(home) == malformed
            private(home / "providers.toml", config)
            passed("doctor_malformed_config_is_reported_without_rewrite")

            segment = next((home / "ledger/segments").glob("*.log"))
            ledger = segment.read_bytes()
            private(segment, ledger + b"\x00\x00")
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert any(c["id"] == "ledger" and c["status"] == "invalid" for c in report["checks"]) and segment.read_bytes() == ledger + b"\x00\x00"
            private(segment, ledger)
            passed("doctor_torn_ledger_is_read_only")

            marker = root / "marker"
            executable = root / "configured-server"
            private(executable, f"#!/bin/sh\nprintf launched >> '{marker}'\n")
            executable.chmod(0o700)
            private(home / "mcp.json", json.dumps({"servers": {"fixture": {"command": str(executable), "args": []}}}))
            private(home / "lsp.toml", f'enabled = true\n[[servers]]\nname="fixture"\ncommand="{executable}"\nlanguage_id="text"\nextensions=["txt"]\nworkspace_root="{work}"\n')
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert not marker.exists() and any(c["id"].startswith("mcp.") and c["status"] == "not_tested" for c in report["checks"])
            assert any(c["id"].startswith("lsp.") and c["status"] == "not_tested" for c in report["checks"])
            passed("doctor_checks_configured_executables_without_launch")

            mod = home / "mods/fixture"
            private(mod / "mod.toml", 'description = "unterminated\n')
            private(mod / "instructions.md", "Local inert guidance\n")
            malformed_mod = tree(home / "mods")
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert any(c["id"] == "mods" and c["status"] == "invalid" for c in report["checks"]) and tree(home / "mods") == malformed_mod
            private(mod / "mod.toml", 'description="Fixture bundle"\ndefault=false\n')
            passed("doctor_reports_malformed_instruction_metadata")

            private(home / "mods/enabled.json", b'{"enabled": [')
            enabled_before = (home / "mods/enabled.json").read_bytes()
            report = run(home, "doctor", "--json", expected=None)["report"]
            assert any(c["id"] == "mods" and c["status"] == "invalid" for c in report["checks"]) and (home / "mods/enabled.json").read_bytes() == enabled_before
            passed("doctor_reports_malformed_enabled_set_without_repair")

            link = root / "linked-home"
            link.symlink_to(home, target_is_directory=True)
            before_link = tree(home)
            run(link, "setup", "--no-provider", expected=2, raw=True)
            assert link.is_symlink() and tree(home) == before_link
            passed("symlink_home_is_refused_without_target_mutation")

            human = run(home, "doctor", expected=None, raw=True).stdout
            assert "doctor" in human and ("No provider or configured server was contacted" in human or "Provider connectivity remains untested" in human)
            assert secret not in human
            passed("human_diagnostics_are_useful_and_secret_free")

            repair_before = tree(partial_home)
            repair = run(partial_home, "setup", "repair", "--dry-run", "--json")
            assert "pib.json" in repair["report"]["missing"] and repair["report"]["refuses_identity_regeneration"]
            assert tree(partial_home) == repair_before
            passed("repair_dry_run_lists_missing_identity_without_mutation")

            print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": checks}, sort_keys=True))
            return 0
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)


if __name__ == "__main__":
    raise SystemExit(main())
