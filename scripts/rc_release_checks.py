#!/usr/bin/env python3
"""Run actual managed binaries in a disposable installation, inside in-jail.sh.

Pass --binary-dir explicitly (or ORBIT_RC_BINARY_DIR). This never builds, installs
into the operator's home, or contacts an external release/provider endpoint.
"""
import argparse
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib.util
import json
import os
from pathlib import Path
import platform
import shlex
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
SCENARIOS = {}


def checked(name, *conditions):
    assert name not in SCENARIOS, ("duplicate scenario", name)
    assert conditions and all(conditions), name
    SCENARIOS[name] = {"passed": True, "assertions": len(conditions)}
    print("PASS " + name, flush=True)


def wait_for(probe, label, seconds=12):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        value = probe()
        if value:
            return value
        time.sleep(0.025)
    raise AssertionError("timed out: " + label)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def digest_tree(path):
    if not path.exists():
        return {}
    return {str(item.relative_to(path)): sha256(item)
            for item in path.rglob("*") if item.is_file() and not item.is_symlink()}


def module_from(path, name):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def process_identity(pid):
    try:
        # Fields after the final ')' start at stat field3. The executable name
        # itself may contain spaces or parentheses; starttime is field22.
        fields = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return fields[19]
    except (FileNotFoundError, ProcessLookupError):
        return None


def descendants(pid):
    result, pending = [], [pid]
    while pending:
        parent = pending.pop()
        try:
            children = Path(f"/proc/{parent}/task/{parent}/children").read_text().split()
        except FileNotFoundError:
            continue
        for item in children:
            child = int(item)
            assert child > 0 and len(result) < 64, "invalid or excessive fixture child tree"
            identity = process_identity(child)
            if identity is not None:
                result.append((child, identity))
                pending.append(child)
    return result


def stop_process_tree(process):
    # Only positive descendants of this still-owned Popen handle are signalled.
    if process.poll() is not None:
        return
    children = descendants(process.pid)
    for pid, identity in reversed(children):
        if process_identity(pid) == identity:
            try:
                os.kill(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
    process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=4)
    for pid, identity in reversed(children):
        if process_identity(pid) == identity:
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass


class InstalledFixture:
    def __init__(self, root, binary_dir):
        self.root = root
        self.work = root / "away from checkout"
        self.work.mkdir(mode=0o700)
        self.home = root / "private-orbit-home"
        self.home.mkdir(mode=0o700)
        self.operator_home = root / "private-shell-home"
        self.operator_home.mkdir(mode=0o700)
        self.destination = root / "installed bin"
        self.tools = root / "allowed-tools"
        self.tools.mkdir(mode=0o700)
        self.assets = root / "assets"
        self.assets.mkdir(mode=0o700)
        self.inputs = root / "actual-binary-inputs"
        self.inputs.mkdir(mode=0o700)
        self.children = []
        self.network = []
        self.network_lock = threading.Lock()
        self.server = None
        self.thread = None
        self.sentinel = self.home / "keep-existing-settings"
        self.sentinel.write_bytes(b"preserve this unrelated local setting\n")
        self.sentinel.chmod(0o600)
        self.installer = root / "install.sh"
        shutil.copyfile(ROOT / "install.sh", self.installer)
        self.installer.chmod(0o700)
        self.target = {"x86_64": "x86_64-unknown-linux-gnu",
                       "aarch64": "aarch64-unknown-linux-gnu"}.get(platform.machine())
        assert sys.platform == "linux" and self.target, "this receipt supports native Linux only"
        self.version = tomllib.loads((ROOT / "Cargo.toml").read_text())["workspace"]["package"]["version"]
        self.hashes = {}
        for name in ("orbit", "orbit-web"):
            source = binary_dir / name
            assert source.is_file() and os.access(source, os.X_OK), ("missing actual built executable", source)
            with source.open("rb") as stream:
                assert stream.read(4) == b"\x7fELF", ("actual native binary required", source)
            target = self.inputs / name
            shutil.copyfile(source, target)
            target.chmod(0o700)
            self.hashes[name] = sha256(source)
            assert sha256(target) == self.hashes[name], "binary changed while preparing the release fixture"
        # Reuse the accepted04 bundler, without invoking Cargo or a source build.
        bundler = module_from(ROOT / "scripts/package_install_bundle.py", "orbit_release_bundle")
        self.archive = bundler.package(self.inputs / "orbit", self.inputs / "orbit-web",
                                       self.version, self.target, self.assets)
        self.asset_paths = {
            f"/v{self.version}/{name}": self.assets / name
            for name in (self.archive.name, self.archive.name + ".sha256")
        }
        for name in ("bash", "curl", "dirname", "sha256sum", "shasum"):
            tool = shutil.which(name)
            if tool:
                (self.tools / name).symlink_to(Path(tool).resolve())
        assert (self.tools / "bash").exists() and (self.tools / "curl").exists()
        assert (self.tools / "sha256sum").exists() or (self.tools / "shasum").exists()
        (self.tools / "python3").symlink_to(Path(sys.executable).resolve())
        self.env = {
            "HOME": str(self.operator_home), "PATH": str(self.destination) + os.pathsep + str(self.tools),
            "LANG": "C.UTF-8", "TERM": "dumb", "NO_COLOR": "1",
            "ORBIT_HOME": str(self.home), "ORBIT_RC_FIXTURE_TOKEN": "fabricated-local-fixture-value",
            "NO_PROXY": "127.0.0.1,localhost,::1", "no_proxy": "127.0.0.1,localhost,::1",
            "XDG_CONFIG_HOME": str(root / "xdg-config"), "XDG_CACHE_HOME": str(root / "xdg-cache"),
            "XDG_DATA_HOME": str(root / "xdg-data"),
        }
        assert shutil.which("cargo", path=self.env["PATH"]) is None
        assert shutil.which("rustc", path=self.env["PATH"]) is None
        assert str(ROOT) not in self.env["PATH"] and "ORBIT_WEB" not in self.env
        assert not self.work.is_relative_to(ROOT)

    def start_assets(self):
        fixture = self

        class Assets(BaseHTTPRequestHandler):
            def do_GET(self):
                with fixture.network_lock:
                    fixture.network.append(("GET", self.path))
                path = fixture.asset_paths.get(self.path)
                if path is None:
                    self.send_error(404)
                    return
                data = path.read_bytes()
                self.send_response(200)
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                try:
                    self.wfile.write(data)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def do_POST(self):
                with fixture.network_lock:
                    fixture.network.append(("POST", self.path))
                self.send_error(500, "provider requests are forbidden in offline release smoke")

            def log_message(self, *_):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Assets)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.asset_url = f"http://127.0.0.1:{self.server.server_port}"

    def provider_requests(self):
        with self.network_lock:
            return [item for item in self.network if item[0] == "POST" or item[1].startswith("/provider-")]

    def install(self, okay=True, version=None):
        result = subprocess.run([
            str(self.tools / "bash"), str(self.installer), "--method", "release", "--version", version or self.version,
            "--dir", str(self.destination), "--base-url", self.asset_url,
        ], cwd=self.work, env=self.env, capture_output=True, text=True, timeout=60)
        assert (result.returncode == 0) == okay, (result.returncode, result.stdout, result.stderr)
        return result

    def run(self, *words, json_output=False, okay=True, cwd=None):
        args = [str(self.destination / "orbit"), *words, "--home", str(self.home)]
        if json_output:
            args.append("--json")
        result = subprocess.run(args, cwd=cwd or self.work, env=self.env, input="", text=True,
                                capture_output=True, timeout=20)
        assert (result.returncode == 0) == okay, (words, result.returncode, result.stdout, result.stderr)
        if json_output and okay:
            value = json.loads(result.stdout)
            assert value["schema"] == "orbit.cli/v1", value
            return value
        return result

    def identity(self):
        return {name: sha256(self.home / name) for name in (
            "trust/operator.key", "trust/manifest.json", "pib.json")}, digest_tree(self.home / "ledger")

    def bundle(self):
        current = self.destination / ".orbit/current"
        directory = current.resolve(strict=True)
        assert directory.is_relative_to(self.destination / ".orbit/versions"), directory
        manifest = json.loads((directory / "manifest.json").read_text())
        return os.readlink(current), directory, manifest

    def installation_snapshot(self):
        pointer, directory, manifest = self.bundle()
        return pointer, manifest, {name: sha256(directory / name) for name in ("orbit", "orbit-web")}, digest_tree(self.home)

    def close(self):
        for process in reversed(self.children):
            stop_process_tree(process)
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if self.thread:
            self.thread.join(timeout=2)


@contextmanager
def installed_fixture(binary_dir):
    with tempfile.TemporaryDirectory(prefix="orbit-release-installed-") as tmp:
        fixture = None
        try:
            fixture = InstalledFixture(Path(tmp), binary_dir)
            fixture.start_assets()
            yield fixture
        finally:
            if fixture:
                fixture.close()


def installed_browser(f):
    module = module_from(ROOT / "scripts/web_harness_test.py", "orbit_release_browser_fixture")
    import socket
    with socket.socket() as chosen:
        chosen.bind(("127.0.0.1", 0))
        port = chosen.getsockname()[1]
    process = subprocess.Popen([
        str(f.destination / "orbit"), "web", "--home", str(f.home), "--port", str(port), "--no-browser", "--bare",
    ], cwd=f.work, env=f.env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    f.children.append(process)
    stream = controller = None
    try:
        expected = f.bundle()[1] / "orbit-web"

        def launched_sibling():
            assert process.poll() is None, "installed browser launcher exited before readiness"
            for pid, identity in descendants(process.pid):
                try:
                    executable = Path(f"/proc/{pid}/exe").resolve(strict=True)
                except FileNotFoundError:
                    continue
                if executable == expected and process_identity(pid) == identity:
                    return pid
            return None

        sibling_pid = wait_for(launched_sibling, "installed sibling executable")
        assert Path(f"/proc/{process.pid}/exe").resolve() == f.bundle()[1] / "orbit", "launcher did not execute managed CLI"

        def listening():
            assert process.poll() is None
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.1):
                    return True
            except OSError:
                return False

        wait_for(listening, "installed browser listener")
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/", timeout=5) as response:
            html = response.read(2 * 1024 * 1024).decode()
            assert response.status == 200 and "ORBIT" in html
        stream = module.SSEClient(port)
        recovery = stream.wait_for("recovery", timeout=8)
        assert recovery and recovery["snapshot"], "installed browser must recover its actual shared owner"
        controller = module.WSClient(port)
        snapshot = recovery["snapshot"]
        checked("installed_cli_launches_exact_managed_sibling_browser_away_from_checkout",
                sibling_pid > 0, Path(f"/proc/{sibling_pid}/exe").resolve() == expected,
                snapshot["provider"] == "first", snapshot["model"] == "small", snapshot["turns"] == 0,
                "ORBIT_WEB" not in f.env, not f.provider_requests())
        controller.send({"type": "stop"})
        assert process.wait(timeout=8) == 0
    finally:
        if controller:
            controller.sock.close()
        if stream:
            stream.sock.close()
            stream.thread.join(timeout=2)
        stop_process_tree(process)


def smoke(f):
    before = digest_tree(f.home)
    f.install()
    pointer, directory, manifest = f.bundle()
    checked("actual_two_binary_bundle_installs_over_local_assets_without_cargo_or_config_changes",
            digest_tree(f.home) == before, manifest["schema_version"] == 1,
            manifest["version"] == f.version, manifest["target"] == f.target, manifest["signature"] == "absent",
            all(manifest["components"][name]["sha256"] == sha256(directory / name) == f.hashes[name]
                and manifest["components"][name]["size"] == (directory / name).stat().st_size
                for name in ("orbit", "orbit-web")), len(f.network) == 2,
            shutil.which("cargo", path=f.env["PATH"]) is None)

    version = f.run("--version").stdout.strip()
    help_text = f.run("--help").stdout
    checked("installed_version_and_help_run_with_private_path_outside_checkout",
            version == "orbit " + f.version, "ORBIT" in help_text.upper(),
            stat.S_ISREG((f.destination / "orbit").lstat().st_mode),
            stat.S_ISREG((f.destination / "orbit-web").lstat().st_mode),
            str(ROOT) not in f.env["PATH"], not f.work.is_relative_to(ROOT))

    git = f.tools / "git"
    marker = f.root / "version-must-not-run-git"
    try:
        records = []
        for invented in ("checkout-before", "checkout-after"):
            git.write_text("#!/bin/bash\nprintf called >> " + shlex.quote(str(marker)) +
                           "\nprintf '%s\\n' " + shlex.quote(invented) + "\n")
            git.chmod(0o700)
            records.append(json.loads(f.run("version").stdout)["data"])
    finally:
        git.unlink(missing_ok=True)
    evidence = records[0]["evidence"]
    checked("installed_version_evidence_never_borrows_checkout_or_invents_signing",
            records[0] == records[1], not marker.exists(),
            records[0]["version"] == f.version,
            records[0]["commit_sha"] not in ("checkout-before", "checkout-after"),
            evidence["bundle_ready"] is False, evidence["status"] == "unavailable",
            all(evidence[key] == "" for key in ("sbom_sha256", "provenance_sha256",
                                                "reproducibility_sha256", "signature_key")),
            digest_tree(f.home) == before)

    first = f.run("setup", json_output=True)
    checked("fresh_installed_offline_setup_creates_private_verified_identity_once",
            first["initialized"], not first["reused"], first["trust_root_verified"], first["offline"],
            stat.S_IMODE(f.home.stat().st_mode) == 0o700,
            all(stat.S_IMODE((f.home / name).stat().st_mode) == 0o600
                for name in ("trust/operator.key", "trust/manifest.json", "pib.json")), not f.provider_requests())

    identity, home_before = f.identity(), digest_tree(f.home)
    repeated = f.run("setup", json_output=True)
    initialized = f.run("init", "--no-provider", json_output=True)
    repair = f.run("setup", "repair", "--dry-run", json_output=True)
    checked("repeated_installed_setup_init_and_repair_preserve_identity_ledger_and_settings",
            repeated["reused"], initialized["reused"], not repeated["initialized"], not initialized["initialized"],
            first["pib_id"] == repeated["pib_id"] == initialized["pib_id"], f.identity() == identity,
            digest_tree(f.home) == home_before, repair["report"]["missing"] == [], not f.provider_requests())

    for name in ("first", "second"):
        configured = f.run("setup", "--provider", name, "--kind", "openai-compatible", "--gate",
                           f.asset_url + "/provider-" + name + "/v1", "--model", "small,strong",
                           "--credential-env", "ORBIT_RC_FIXTURE_TOKEN", json_output=True)
        assert configured["providers_configured"] == [name] and configured["reused"]
    providers = tomllib.loads((f.home / "providers.toml").read_text())["provider"]
    listed = f.run("provider", "list")
    checked("installed_manual_two_provider_setup_keeps_exact_metadata_and_never_discovers",
            len(providers) == 2,
            all(provider["url"] == f.asset_url + "/provider-" + provider["name"] + "/v1"
                and provider["env"] == "ORBIT_RC_FIXTURE_TOKEN"
                and [model["id"] for model in provider["models"]] == ["small", "strong"]
                for provider in providers), f.identity() == identity,
            f.env["ORBIT_RC_FIXTURE_TOKEN"] not in (f.home / "providers.toml").read_text(),
            "first" in listed.stdout and "second" in listed.stdout, not f.provider_requests())

    before = digest_tree(f.home)
    doctor = f.run("doctor", json_output=True)["report"]
    checks = {item["id"]: item for item in doctor["checks"]}
    checked("installed_doctor_verifies_actual_managed_browser_bundle_without_launching_or_network",
            doctor["schema_version"] == 1, doctor["ready"], checks["browser"]["status"] == "ready",
            checks["identity"]["status"] == "ready", checks["routing"]["status"] == "configured",
            len(doctor["checks"]) <= 128, digest_tree(f.home) == before,
            f.env["ORBIT_RC_FIXTURE_TOKEN"] not in json.dumps(doctor), not f.provider_requests())

    f.run("route", "setup", "--easy", "first/small", "--hard", "second/strong", json_output=True)
    preview = f.run("route", "test", "Implement a comprehensive parser", json_output=True)
    config_before = (f.home / "providers.toml").read_bytes()
    f.run("route", "set", "coding", "hard", "second/missing", okay=False)
    checked("installed_offline_routing_preview_matches_declared_target_and_invalid_edit_is_atomic",
            preview["phase"] == "coding", preview["difficulty"] == "hard",
            preview["provider_id"] == "second", preview["raw_model"] == "strong",
            preview["source"] == "phase_difficulty", (f.home / "providers.toml").read_bytes() == config_before,
            f.identity() == identity, not f.provider_requests())

    legacy = f.home / "tui.toml"
    legacy.write_text('[unrelated]\nkeep="existing setting"\n')
    legacy.chmod(0o600)
    legacy_before = legacy.read_bytes()
    for key, value in (("theme", "midnight"), ("density", "compact"), ("browser.font_size_px", "17")):
        f.run("customize", "set", key, value, json_output=True)
    customized = f.run("customize", "show", json_output=True)["profile"]["profile"]
    exported = f.work / "release-profile.json"
    f.run("customize", "export", exported.name, json_output=True)
    f.run("customize", "validate", exported.name, json_output=True)
    f.run("customize", "reset", json_output=True)
    restored = f.run("customize", "import", exported.name, json_output=True)["profile"]["profile"]
    checked("installed_customization_set_export_validate_reset_and_import_round_trip",
            customized["theme"] == "midnight", customized["density"] == "compact",
            customized["browser"]["font_size_px"] == 17, restored == customized,
            legacy.read_bytes() == legacy_before, str(f.home) not in exported.read_text(),
            f.env["ORBIT_RC_FIXTURE_TOKEN"] not in exported.read_text(), not f.provider_requests())

    profile_before = (f.home / "customization.json").read_bytes()
    invalid = f.work / "invalid-profile.json"
    invalid.write_text(json.dumps({**customized, "schema_version": 999}))
    invalid.chmod(0o600)
    f.run("customize", "import", invalid.name, okay=False)
    checked("installed_invalid_customization_import_preserves_complete_stored_profile",
            (f.home / "customization.json").read_bytes() == profile_before,
            legacy.read_bytes() == legacy_before, f.identity() == identity, not f.provider_requests())

    engagement = f.work / "engagement"
    before = digest_tree(f.home)
    dry = f.run("pentest", "init", "engagement", "--dry-run", json_output=True)["report"]
    checked("installed_engagement_dry_run_creates_no_workspace_or_home_changes",
            dry["dry_run"], bool(dry["created"]), not engagement.exists(),
            digest_tree(f.home) == before, not f.provider_requests())

    created = f.run("pentest", "init", "engagement", json_output=True)["report"]
    scope = tomllib.loads((engagement / "scope.toml").read_text())
    checked("installed_engagement_scaffold_is_private_empty_scope_and_does_not_apply_profile_or_trust",
            created["trust_unchanged"], not created["dry_run"], len(created["created"]) >= 20,
            scope["schema_version"] == 1, scope["in_scope"] == [] and scope["out_of_scope"] == [],
            all(stat.S_IMODE((engagement / name).stat().st_mode) == 0o600
                for name in ("scope.toml", "notes.md", "reports/report.md", "pentest-profile.json")),
            all(stat.S_IMODE((engagement / name).stat().st_mode) == 0o700
                for name in ("evidence", "findings", "reports", ".orbit")),
            digest_tree(f.home) == before, not f.provider_requests())

    evidence = engagement / "evidence/original.bin"
    evidence.write_bytes(b"local original fixture evidence\n")
    evidence.chmod(0o600)
    report = engagement / "reports/report.md"
    report.write_text("Keep the operator's edited report.\n")
    existing = digest_tree(engagement)
    repeated = f.run("pentest", "init", "engagement", json_output=True)["report"]
    status = f.run("pentest", "status", "engagement", json_output=True)["report"]
    templates = f.run("pentest", "templates", json_output=True)["templates"]
    readiness = f.run("pentest", "readiness", "engagement", json_output=True)["report"]
    checked("installed_engagement_repeat_status_templates_and_readiness_preserve_real_evidence",
            not repeated["created"], "reports/report.md" in repeated["conflicts"],
            digest_tree(engagement) == existing, digest_tree(f.home) == before,
            status["scope_valid"], status["profile_valid"], status["evidence"]["files"] == 1,
            len(templates) == 6, readiness["schema_version"] == 1,
            readiness["ready"], not f.provider_requests())

    imported = f.run("customize", "import", "engagement/pentest-profile.json", json_output=True)["profile"]
    capabilities = f.run("customize", "capabilities", json_output=True)
    checked("installed_engagement_panels_require_explicit_import_and_validate_shared_capabilities",
            len(imported["profile"]["panes"]) == 5,
            {pane["id"] for pane in imported["profile"]["panes"]} == {"scope", "notes", "evidence", "findings", "agents"},
            capabilities["profile"]["profile"] == imported["profile"],
            (f.home / "customization.json").read_bytes() != profile_before,
            f.identity() == identity, not f.provider_requests())

    installed_browser(f)

    previous = f.installation_snapshot()
    f.install()
    checked("repeated_actual_bundle_install_keeps_both_components_manifest_identity_and_config",
            f.installation_snapshot() == previous, f.run("--version").stdout.strip() == "orbit " + f.version,
            f.bundle()[0] == pointer, not f.provider_requests())

    major, minor, patch = f.version.split("-", 1)[0].split("+", 1)[0].split(".")
    next_version = f"{major}.{minor}.{int(patch) + 1}"
    next_name = f"orbit-{next_version}-{f.target}.tar.gz"
    candidate = f.assets / next_name
    shutil.copyfile(f.archive, candidate)
    checksum = f.assets / (next_name + ".sha256")
    checksum.write_text("0" * 64 + "  " + next_name + "\n")
    # A deliberately invalid future download is refused before parsing its
    # archive. This fixture never represents it as a successfully built version.
    f.asset_paths.update({f"/v{next_version}/{next_name}": candidate,
                          f"/v{next_version}/{next_name}.sha256": checksum})
    result = f.install(okay=False, version=next_version)
    checked("failed_managed_upgrade_retains_prior_both_binaries_manifest_and_configuration",
            bool(result.stderr), f.installation_snapshot() == previous,
            f.run("--version").stdout.strip() == "orbit " + f.version,
            sha256(f.bundle()[1] / "orbit-web") == f.hashes["orbit-web"],
            not list((f.destination / ".orbit").glob(".stage-*")), not f.provider_requests())


DOC_COMMANDS = (
    "orbit --version",
    "orbit --help",
    "orbit setup",
    "orbit setup repair --dry-run",
    "orbit doctor",
    "orbit provider list",
    "orbit route status",
    'orbit route test "Implement a comprehensive parser"',
    "orbit route set coding hard first/strong",
    "orbit route reset coding",
    "orbit customize show --json",
    "orbit customize capabilities --json",
    "orbit customize set theme midnight",
    "orbit customize export portable-profile.json",
    "orbit customize validate portable-profile.json",
    "orbit customize import portable-profile.json",
    "orbit customize reset",
    "orbit pentest templates --json",
    "orbit pentest init ./engagement --profile standard",
    "orbit pentest status ./engagement --json",
    "orbit pentest readiness ./engagement --json",
)


def documentation_commands(f):
    documents = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
    corpus = " ".join(" ".join(path.read_text().replace("\\\n", " ").split()) for path in documents)
    executed = 0
    for text in DOC_COMMANDS:
        assert text in corpus, ("documented command example is missing", text)
        before_calls = f.provider_requests()
        before_identity = f.identity()
        # Execute the documented syntax verbatim, including its human/JSON
        # output choice. Only --home is added to isolate managed state.
        result = f.run(*shlex.split(text)[1:])
        assert result.stdout.strip(), (text, result.stderr)
        if "--json" in shlex.split(text):
            value = json.loads(result.stdout)
            assert value["schema"] == "orbit.cli/v1" and value["command"], (text, value)
        checked("documented_command_" + text,
                f.provider_requests() == before_calls, f.identity() == before_identity)
        executed += 1
    assert executed >= 12, "at least twelve actual documented commands are required"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary-dir", default=os.environ.get("ORBIT_RC_BINARY_DIR"),
                        help="explicit directory containing freshly built orbit and orbit-web")
    parser.add_argument("--check-doc-commands", action="store_true")
    args = parser.parse_args()
    if not args.binary_dir:
        parser.error("pass --binary-dir or ORBIT_RC_BINARY_DIR; this script does not build or guess binaries")
    binary_dir = Path(args.binary_dir).resolve(strict=True)
    with installed_fixture(binary_dir) as fixture:
        smoke(fixture)
        assert len(SCENARIOS) >= 12, "installed workflows must contain at least twelve real scenarios"
        if args.check_doc_commands:
            documentation_commands(fixture)
        assert not fixture.provider_requests(), "offline workflow contacted a provider endpoint"
        print("ORBIT_CHECK_RECEIPT " + json.dumps({
            "scenarios": SCENARIOS, "binary_sha256": fixture.hashes,
            "version": fixture.version, "target": fixture.target,
        }), flush=True)


if __name__ == "__main__":
    main()
