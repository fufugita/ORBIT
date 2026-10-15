#!/usr/bin/env python3
"""Actual checked customization commands and files; run through in-jail.sh."""
import argparse
from contextlib import AbstractContextManager
import copy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
from pathlib import Path
import subprocess
import tempfile
import threading


class Fixture(AbstractContextManager):
    def __init__(self, binary):
        self.binary = str(Path(binary).resolve())
        self.tmp = tempfile.TemporaryDirectory(prefix="orbit-customization-release-")
        self.root = Path(self.tmp.name)
        self.home = self.root / "home"
        self.work = self.root / "workspace"
        self.work.mkdir(mode=0o700)
        self.calls = []
        self.sessions = []
        calls = self.calls

        class Provider(BaseHTTPRequestHandler):
            def do_POST(self):
                calls.append(self.rfile.read(int(self.headers.get("Content-Length", "0"))))
                self.send_response(500)
                self.end_headers()

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Provider)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.env = {key: value for key, value in os.environ.items() if not key.startswith("ORBIT_")}
        self.env.update(ORBIT_HOME=str(self.home), ORBIT_GATE_TOKEN="customization-fixture-only",
                        ORBIT_GATE_URL=f"http://127.0.0.1:{self.server.server_port}")
        self.run("init", "--no-provider")
        self.home.chmod(0o700)
        (self.home / "providers.toml").write_text(
            f'[[provider]]\nname="fixture"\nurl="{self.env["ORBIT_GATE_URL"]}"\nenv="ORBIT_GATE_TOKEN"\n'
            '[[provider.models]]\nid="local"\n[roles]\nmain="fixture/local"\n')
        (self.home / "providers.toml").chmod(0o600)
        self.protected = self.protected_tree()

    def __exit__(self, *_):
        for session in reversed(self.sessions):
            if session.master is not None:
                session.terminate()
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=3)
        self.tmp.cleanup()

    def run(self, *words, success=True, home=None, stdin=None):
        selected = home or self.home
        result = subprocess.run([self.binary, *words, "--home", str(selected)],
                                env={**self.env, "ORBIT_HOME": str(selected)}, cwd=self.work,
                                input=stdin, text=True, capture_output=True, timeout=20)
        if success:
            assert result.returncode == 0, (words, result.returncode, result.stdout, result.stderr)
        else:
            assert result.returncode != 0, (words, result.stdout, result.stderr)
        return result

    def command(self, *words, success=True, home=None):
        result = self.run("customize", *words, "--json", success=success, home=home)
        if success:
            value = json.loads(result.stdout)
            assert (value["schema"], value["command"], value["status"]) == ("orbit.cli/v1", "customize", "ok"), value
            return value
        return result

    def profile(self, home=None):
        return self.command("show", home=home)["profile"]["profile"]

    def protected_tree(self):
        return {str(p.relative_to(self.home)): hashlib.sha256(p.read_bytes()).hexdigest()
                for p in self.home.rglob("*") if p.is_file() and not p.is_symlink()
                and str(p.relative_to(self.home)) not in {"customization.json", "tui.toml", ".customization.lock"}}

    def unchanged(self, allow_new_sessions=False):
        current = self.protected_tree()
        self.preservation_error = None
        def refused(reason):
            self.preservation_error = reason
            return False
        if self.calls or any(p.is_symlink() for p in self.home.rglob("*")):
            return refused("unexpected provider call or symlink")
        if not allow_new_sessions:
            return current == self.protected
        # Every baseline identity/configuration/ledger byte must remain exact.
        changed = [path for path, digest in self.protected.items() if current.get(path) != digest]
        if changed:
            return refused(("changed baseline files", changed))
        for name in current.keys() - self.protected.keys():
            path = self.home / name
            if path.stat().st_mode & 0o777 != 0o600:
                return refused(("unexpected new file mode", name, oct(path.stat().st_mode & 0o777)))
            if re.fullmatch(r"sessions/\.leases/[a-zA-Z0-9_-]+\.lock", name):
                continue
            transcript = re.fullmatch(r"projects/([a-zA-Z0-9_-]+)\.jsonl", name)
            if transcript:
                # TUI startup opens an empty append-only transcript for the
                # exact new zero-turn session; it must contain no turn events.
                if path.read_bytes() != b"" or "sessions/" + transcript[1] + ".json" not in current:
                    return refused(("unexpected transcript contents or session", name))
                continue
            if not re.fullmatch(r"sessions/[a-zA-Z0-9_-]+\.json", name):
                return refused(("unexpected new file", name))
            value = json.loads(path.read_text())
            if (value.get("turns"), value.get("transcript"), value.get("provider"), value.get("model"), value.get("gate")) != (0, [], "fixture", "local", self.env["ORBIT_GATE_URL"]):
                return refused(("unexpected session identity or transcript", name,
                                {key: value.get(key) for key in ("turns", "provider", "model", "gate")},
                                bool(value.get("transcript"))))
        return True

    def stored(self):
        path = self.home / "customization.json"
        return path.read_bytes() if path.exists() else None


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", default=str(Path(__file__).resolve().parents[1] / "target/debug/orbit"))
    args = parser.parse_args()
    scenarios = {}

    def checked(name, *conditions):
        assert conditions and all(conditions), name
        scenarios[name] = {"passed": True, "assertions": len(conditions)}
        print("PASS " + name, flush=True)

    with Fixture(args.binary) as f:
        original = f.profile()
        checked("show_and_capabilities_are_offline_readonly_and_explain_terminal_font",
                f.stored() is None, f.unchanged(),
                "terminal" in f.command("capabilities")["profile"]["capabilities"]["terminal_font"].lower())
        for key, value in [("theme", "paper"), ("density", "compact"), ("glyphs", "ascii"),
                           ("reduced_motion", "true"), ("browser.font_family", "monospace"),
                           ("browser.font_size_px", "18")]:
            f.command("set", key, value)
        changed = f.profile()
        checked("full_settings_persist_across_fresh_cli_processes_without_provider_work",
                changed["theme"] == "paper", changed["density"] == "compact", changed["glyphs"] == "ascii",
                changed["reduced_motion"] is True, changed["browser"] == {"font_family": "monospace", "font_size_px": 18.0},
                f.unchanged(), (f.home / "customization.json").stat().st_mode & 0o777 == 0o600)
        f.command("set", "colors.accent", "#123456")
        f.command("set", "token_overrides.magenta", "#654321")
        colors = f.profile()["token_overrides"]
        checked("legacy_color_alias_and_canonical_role_have_one_effective_value",
                colors.get("magenta") == "#654321", "accent" not in colors, f.unchanged())
        before = f.stored()
        for key, value in [("unknown", "bad"), ("theme", "missing"), ("browser.font_size_px", "99"),
                           ("reduced_motion", "yes"), ("colors.ink", "#wrong")]:
            f.command("set", key, value, success=False)
            assert f.stored() == before
        checked("invalid_keys_values_and_complete_candidates_preserve_exact_bytes", f.stored() == before, f.unchanged())
        exported = f.work / "portable.json"
        f.command("export", "portable.json")
        export_bytes = exported.read_bytes()
        parsed = json.loads(export_bytes)
        f.command("validate", "portable.json")
        f.command("export", "portable.json", success=False)
        checked("portable_export_is_private_valid_and_never_overwrites_existing_file",
                parsed == f.profile(), exported.read_bytes() == export_bytes,
                exported.stat().st_mode & 0o777 == 0o600,
                str(f.home) not in export_bytes.decode(), str(f.work) not in export_bytes.decode(), f.unchanged())
        before = f.stored()
        malformed = f.work / "invalid.json"
        malformed.write_text('{"schema_version":1,broken')
        f.command("validate", "invalid.json", success=False)
        f.command("import", "invalid.json", success=False)
        extra = copy.deepcopy(parsed)
        extra["panes"] = [{"id": "proof", "title": "Proof", "surfaces": ["terminal"],
                           "source": {"kind": "text", "text": "inert"},
                           "actions": [{"kind": "refresh", "unexpected": "must refuse"}]}]
        malformed.write_text(json.dumps(extra))
        f.command("import", "invalid.json", success=False)
        checked("malformed_import_and_unknown_unit_action_fields_are_strictly_rejected",
                f.stored() == before, f.unchanged())
        f.command("reset", "theme")
        reset_one = f.profile()
        checked("key_reset_preserves_other_customization_and_unrelated_configuration",
                reset_one["theme"] == original["theme"], reset_one["density"] == "compact",
                reset_one["token_overrides"] == colors, f.unchanged())
        second = f.root / "other-home"
        f.run("init", "--no-provider", home=second)
        second.chmod(0o700)
        f.command("import", "portable.json", home=second)
        checked("portable_export_import_into_fresh_home_has_exact_profile_parity",
                f.profile(home=second) == parsed, not f.calls, f.unchanged())
        f.command("set", "layout.preset", "review")
        layout = f.profile()["layout"]
        checked("named_layout_is_persisted_as_valid_split_tree", layout["preset"] == "review",
                layout["tree"]["kind"] == "split", f.unchanged())
        before = f.stored()
        link = f.work / "link.json"
        link.symlink_to(exported)
        f.command("import", "link.json", success=False)
        hard = f.work / "hard.json"
        os.link(exported, hard)
        f.command("import", "hard.json", success=False)
        hard.unlink()
        checked("symlink_and_hardlinked_imports_preserve_configuration", f.stored() == before,
                exported.read_bytes() == export_bytes, f.unchanged())
        legacy = b'[color]\nmode="mono"\n[unrelated]\nkeep="exact legacy bytes"\n'
        (f.home / "tui.toml").write_bytes(legacy)
        (f.home / "tui.toml").chmod(0o644)
        f.command("reset")
        checked("full_reset_returns_to_owned_0644_legacy_and_preserves_unrelated_bytes",
                f.stored() is None, f.profile()["color_mode"] == "mono",
                (f.home / "tui.toml").read_bytes() == legacy, f.unchanged())
        broken = b"[invalid legacy\n"
        (f.home / "tui.toml").write_bytes(broken)
        f.command("set", "theme", "paper", success=False)
        f.command("reset", success=False)
        checked("malformed_legacy_is_visible_and_never_silently_rewritten",
                (f.home / "tui.toml").read_bytes() == broken, f.stored() is None, f.unchanged())
        (f.home / "tui.toml").write_bytes(legacy)
        bad_profile = b'{"malformed":'
        (f.home / "customization.json").write_bytes(bad_profile)
        (f.home / "customization.json").chmod(0o600)
        f.command("show", success=False)
        f.command("theme", "paper", success=False)
        checked("malformed_profile_refuses_show_and_change_without_implicit_fallback",
                f.stored() == bad_profile, (f.home / "tui.toml").read_bytes() == legacy, f.unchanged())
        protected_before = f.protected_tree()
        safe = f.run("--no-tui", "--safe-customization", "--bare",
                     stdin="/theme paper\n/customize reset\nexit\n")
        protected_after = f.protected_tree()
        new_paths = set(protected_after) - set(protected_before)
        saved_sessions = list((f.home / "sessions").glob("*.json"))
        checked("plain_safe_defaults_refuse_theme_and_reset_preserving_all_existing_state",
                f.stored() == bad_profile, (f.home / "tui.toml").read_bytes() == legacy,
                all(protected_after.get(path) == digest for path, digest in protected_before.items()),
                bool(new_paths) and all(path.startswith("sessions/") for path in new_paths),
                bool(saved_sessions) and all(json.loads(path.read_text())["turns"] == 0 for path in saved_sessions),
                "Session-only defaults cannot write customization" in safe.stderr,
                not f.calls)
    print("ORBIT_CHECK_RECEIPT " + json.dumps({"scenarios": scenarios}, sort_keys=True), flush=True)


if __name__ == "__main__":
    main()
