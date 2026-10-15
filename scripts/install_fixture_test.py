#!/usr/bin/env python3
"""Disposable, offline installer acceptance. Never touches the operator install."""
import argparse
from contextlib import contextmanager
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("bundle", ROOT / "scripts/package_install_bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)
TARGET = {"x86_64": "x86_64-unknown-linux-gnu", "aarch64": "aarch64-unknown-linux-gnu"}.get(platform.machine())
SCENARIOS = {}
ASSERTIONS = 0


def check(condition, message):
    global ASSERTIONS
    ASSERTIONS += 1
    if not condition:
        raise AssertionError(message)


@contextmanager
def scenario(name):
    global ASSERTIONS
    ASSERTIONS = 0
    yield
    check(ASSERTIONS > 0, "scenario must assert real outcomes")
    SCENARIOS[name] = {"passed": True, "assertions": ASSERTIONS}
    print(f"PASS {name}", flush=True)


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="orbit-install-fixture-")
        self.root = Path(self.temp.name)
        self.transport = self.root / "transport"
        self.transport.mkdir()
        self.shims = self.root / "tools"
        self.shims.mkdir()
        self.dest = self.root / "destination with spaces"
        self.home = self.root / "operator-home"
        self.home.mkdir()
        (self.home / "sentinel").write_bytes(b"keep existing configuration\n")
        self.log = self.root / "commands.jsonl"
        self.python = Path(sys.executable).resolve()
        for tool in ("bash", "dirname", "sha256sum", "shasum"):
            if path := shutil.which(tool):
                (self.shims / tool).symlink_to(Path(path).resolve())
        (self.shims / "python3").symlink_to(self.python)
        self.env = {**os.environ, "HOME": str(self.home), "PATH": str(self.shims),
                    "FIXTURE_TRANSPORT": str(self.transport), "FIXTURE_LOG": str(self.log),
                    "FIXTURE_ROOT": str(self.root), "FIXTURE_PYTHON": str(self.python)}
        self.shim("curl", '''import json,os,shutil,sys,time
from pathlib import Path
with open(os.environ['FIXTURE_LOG'],'a') as log:log.write(json.dumps(sys.argv)+'\\n')
args=sys.argv[1:]; output=Path(args[args.index('--output')+1]); url=args[-1]
if os.environ.get('FIXTURE_PAUSE') and not url.endswith('.sha256'):
 Path(os.environ['FIXTURE_PAUSE']).write_text('paused')
 while not Path(os.environ['FIXTURE_PAUSE']+'.release').exists():time.sleep(.02)
if os.environ.get('FIXTURE_CURL_FAIL'):sys.exit(22)
source=Path(os.environ['FIXTURE_TRANSPORT'])/url.rsplit('/',1)[-1]
if not source.is_file():sys.exit(22)
shutil.copyfile(source,output)
''')
        self.package("0.2.0", "first")

    def shim(self, name, code):
        path = self.shims / name
        path.write_text(f"#!{self.python}\n" + code)
        path.chmod(0o700)

    def package(self, version, label, target=None):
        binaries = self.root / ("inputs-" + version)
        binaries.mkdir(exist_ok=True)
        for name in ("orbit", "orbit-web"):
            path = binaries / name
            path.write_text(f"#!/bin/sh\nprintf '%s\\n' '{name}:{label}'\n")
            path.chmod(0o700)
        return bundle.package(binaries / "orbit", binaries / "orbit-web", version, target or TARGET, self.transport)

    def start(self, *args, env=None):
        return subprocess.Popen([str(self.shims / "bash"), str(ROOT / "install.sh"), "--version", "0.2.0", "--dir", str(self.dest), "--base-url", "https://fixtures.invalid/releases", *args], env=env or self.env, cwd=self.root, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    def install(self, *args, okay=True, env=None):
        process = self.start(*args, env=env)
        out, err = process.communicate(timeout=20)
        check((process.returncode == 0) == okay, f"unexpected installer exit {process.returncode}: {out} {err}")
        return out + err

    def run(self, name):
        return subprocess.run([str(self.dest / name), "--version"], cwd=self.root, env=self.env, capture_output=True, text=True, check=True, timeout=5).stdout.strip()

    def snapshot(self):
        pointer = self.dest / ".orbit/current"
        return (os.readlink(pointer), self.run("orbit"), self.run("orbit-web"), (self.home / "sentinel").read_bytes())

    def unchanged(self, previous):
        check(self.snapshot() == previous, "prior bundle or configuration changed")
        check(not list((self.dest / ".orbit").glob(".stage-*")), "temporary installation stage leaked")

    def rewrite_archive(self, mutate, version="0.2.0"):
        archive = self.transport / f"orbit-{version}-{TARGET}.tar.gz"
        with tarfile.open(archive) as tar:
            members = [(item, tar.extractfile(item).read()) for item in tar]
        members = mutate(members)
        with tarfile.open(archive, "w:gz", format=tarfile.USTAR_FORMAT) as tar:
            for item, data in members:
                item.size = len(data)
                tar.addfile(item, io.BytesIO(data) if item.isfile() else None)
        self.checksum(archive)

    def checksum(self, archive):
        archive.with_name(archive.name + ".sha256").write_text(f"{hashlib.sha256(archive.read_bytes()).hexdigest()}  {archive.name}\n")

    def source(self, fail=False, missing=False, wrong_version=False):
        checkout = self.root / "checkout"
        checkout.mkdir()
        (checkout / "Cargo.toml").write_text('[workspace.package]\nversion="0.2.0"\nrust-version="1.99"\n')
        (checkout / "Cargo.lock").write_text('version=4\n')
        self.shim("rustc", "print('rustc 1.99.0 (fixture)')\n")
        self.shim("cargo", '''import json,os,sys
from pathlib import Path
with open(os.environ['FIXTURE_LOG'],'a') as log:log.write(json.dumps(sys.argv)+'\\n')
args=sys.argv[1:]
if os.environ.get('FIXTURE_BUILD_FAIL'):sys.exit(2)
root=Path(args[args.index('--target-dir')+1])/args[args.index('--target')+1]/'release';root.mkdir(parents=True)
for name in ('orbit','orbit-web'):
 if name=='orbit-web' and os.environ.get('FIXTURE_MISSING_WEB'):continue
 path=root/name;path.write_text('#!/bin/sh\\nprintf "%s\\\\n" "'+name+':source"\\n');path.chmod(0o700)
''')
        if fail: self.env["FIXTURE_BUILD_FAIL"] = "1"
        if missing: self.env["FIXTURE_MISSING_WEB"] = "1"
        if wrong_version: (checkout / "Cargo.toml").write_text('[workspace.package]\nversion="9.9.9"\nrust-version="1.99"\n')
        return checkout

    def commands(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()] if self.log.exists() else []

    def close(self):
        self.temp.cleanup()


@contextmanager
def fixture():
    instance = Fixture()
    try:
        yield instance
    finally:
        instance.close()


def release_tests():
    with scenario("release_without_cargo_launches_both_away_from_checkout"), fixture() as f:
        check(not (f.shims / "cargo").exists(), "Cargo unexpectedly available")
        f.install()
        check(f.run("orbit") == "orbit:first", "CLI not runnable")
        check(f.run("orbit-web") == "orbit-web:first", "browser not runnable")
        check((f.home / "sentinel").read_bytes() == b"keep existing configuration\n", "configuration changed")
        check(len([c for c in f.commands() if Path(c[0]).name == "curl"]) == 2, "unexpected release transport calls")
    with scenario("missing_mandatory_checksum_retains_both"), fixture() as f:
        f.install(); prior = f.snapshot()
        next(f.transport.glob("*.sha256")).unlink()
        f.install(okay=False); f.unchanged(prior)
    with scenario("bad_archive_checksum_retains_both"), fixture() as f:
        f.install(); prior = f.snapshot()
        path = next(f.transport.glob("*.sha256")); path.write_text("0" * 64 + "  " + path.name.removesuffix(".sha256") + "\n")
        f.install(okay=False); f.unchanged(prior)
    with scenario("archive_traversal_never_extracts"), fixture() as f:
        f.install(); prior = f.snapshot()
        def mutate(items):
            item = tarfile.TarInfo("../escaped"); return items[:2] + [(item, b"untrusted")]
        f.rewrite_archive(mutate); f.install(okay=False); f.unchanged(prior)
        check(not (f.root / "escaped").exists(), "archive escaped installation")
    with scenario("archive_symlink_member_is_refused"), fixture() as f:
        f.install(); prior = f.snapshot()
        def mutate(items):
            item = tarfile.TarInfo("orbit-web"); item.type = tarfile.SYMTYPE; item.linkname = "/tmp/foreign"; return [items[0], items[1], (item, b"")]
        f.rewrite_archive(mutate); f.install(okay=False); f.unchanged(prior)
    with scenario("manifest_target_mismatch_is_refused"), fixture() as f:
        def mutate(items):
            return [(i, json.dumps({**json.loads(data), "target": "wrong-target"}).encode() if i.name == "manifest.json" else data) for i, data in items]
        f.rewrite_archive(mutate); f.install(okay=False)
        check(not (f.dest / ".orbit/current").exists(), "mismatched target published")
    with scenario("manifest_version_mismatch_is_refused"), fixture() as f:
        def mutate(items):
            return [(i, json.dumps({**json.loads(data), "version": "9.9.9"}).encode() if i.name == "manifest.json" else data) for i, data in items]
        f.rewrite_archive(mutate); f.install(okay=False)
        check(not (f.dest / ".orbit/current").exists(), "mismatched version published")
    with scenario("missing_browser_component_is_refused"), fixture() as f:
        f.install(); prior = f.snapshot(); f.rewrite_archive(lambda items: [(i,d) for i,d in items if i.name != "orbit-web"])
        f.install(okay=False); f.unchanged(prior)
    with scenario("component_hash_mismatch_is_refused"), fixture() as f:
        f.install(); prior = f.snapshot(); f.rewrite_archive(lambda items: [(i,d+b"changed" if i.name=="orbit" else d) for i,d in items])
        f.install(okay=False); f.unchanged(prior)
    with scenario("archive_duplicate_member_is_refused"), fixture() as f:
        f.rewrite_archive(lambda items: items+[items[0]]); f.install(okay=False)
        check(not (f.dest / ".orbit/current").exists(), "duplicate member published")
    with scenario("unmanaged_executable_is_never_overwritten"), fixture() as f:
        f.dest.mkdir(); path = f.dest / "orbit"; path.write_bytes(b"keep executable"); path.chmod(0o700)
        f.install(okay=False); check(path.read_bytes()==b"keep executable", "unmanaged binary overwritten")
        check(not (f.dest / ".orbit").exists(), "unmanaged refusal created managed state")
    with scenario("destination_symlink_is_refused"), fixture() as f:
        actual = f.root / "actual"; actual.mkdir(); f.dest.symlink_to(actual, target_is_directory=True)
        f.install(okay=False); check(not list(actual.iterdir()), "symlink destination mutated")
        f.dest.unlink();unsafe=f.root/"unsafe-parent";unsafe.mkdir();unsafe.chmod(0o777);f.dest=unsafe/"bin"
        f.install(okay=False);check(not list(unsafe.iterdir()),"unsafe ancestor mutated")

    with scenario("pax_metadata_is_refused_before_metadata_allocation"), fixture() as f:
        f.install(); prior=f.snapshot()
        def mutate(items):
            item=tarfile.TarInfo("metadata");item.type=tarfile.XGLTYPE
            return [(item,b"18 path=orbit-web\n")]+items
        f.rewrite_archive(mutate);f.install(okay=False);f.unchanged(prior)
    with scenario("setuid_archive_component_is_refused"), fixture() as f:
        def mutate(items):
            for item,_ in items:
                if item.name=="orbit":item.mode=0o4755
            return items
        f.rewrite_archive(mutate);f.install(okay=False)
        check(not (f.dest/".orbit/current").exists(),"setuid component published")
    with scenario("fifo_destination_component_is_refused_without_blocking"), fixture() as f:
        f.dest.mkdir();os.mkfifo(f.dest/"orbit",0o600);started=time.monotonic()
        f.install(okay=False);check(time.monotonic()-started<3,"FIFO blocked installer")
        check((f.dest/"orbit").is_fifo(),"FIFO mutated")


def all_tests():
    with scenario("managed_upgrade_switches_matching_pair_and_retains_old_version"), fixture() as f:
        f.install(); prior=f.snapshot(); f.package("0.2.1","second"); f.install("--version","0.2.1")
        check((f.run("orbit"),f.run("orbit-web"))==("orbit:second","orbit-web:second"),"upgrade pair not switched")
        check((f.dest/".orbit"/prior[0]).is_dir(),"old version removed")
        check((f.home/"sentinel").read_bytes()==prior[3],"configuration changed")
    with scenario("idempotent_same_bundle_keeps_current_identity"), fixture() as f:
        f.install(); prior=f.snapshot(); f.install(); f.unchanged(prior)
        check(len(list((f.dest/".orbit/versions").iterdir()))==1,"duplicate immutable version")
    with scenario("concurrent_install_is_refused_without_touching_current"), fixture() as f:
        f.install(); prior=f.snapshot(); pause=f.root/"paused"; env={**f.env,"FIXTURE_PAUSE":str(pause)}; process=f.start(env=env)
        try:
            deadline=time.monotonic()+5
            while not pause.exists() and time.monotonic()<deadline:time.sleep(.02)
            check(pause.exists(),"first installer never reached barrier")
            text=f.install(okay=False); check("in progress" in text,"concurrent refusal not explained")
            check(f.snapshot()==prior,"concurrent refusal changed current")
            Path(str(pause)+".release").write_text("release"); out,err=process.communicate(timeout=10); check(process.returncode==0,f"first installer failed: {out} {err}")
        finally:
            if process.poll() is None:process.kill();process.communicate()
    with scenario("interrupted_upgrade_retains_old_pair_and_cleans_stage"), fixture() as f:
        f.install(); prior=f.snapshot(); pause=f.root/"paused"; process=f.start(env={**f.env,"FIXTURE_PAUSE":str(pause)})
        try:
            deadline=time.monotonic()+5
            while not pause.exists() and time.monotonic()<deadline:time.sleep(.02)
            check(pause.exists(),"installer never reached interrupt barrier")
            process.send_signal(signal.SIGTERM); process.communicate(timeout=10)
            check(process.returncode!=0,"interrupted install falsely succeeded"); f.unchanged(prior)
        finally:
            if process.poll() is None:process.kill();process.communicate()
    with scenario("stale_unheld_lock_does_not_block_recovery"), fixture() as f:
        f.install(); prior=f.snapshot(); (f.dest/".orbit/install.lock").write_text("stale process metadata")
        f.install(); f.unchanged(prior)
    with scenario("unsafe_current_pointer_cannot_redirect_publication"), fixture() as f:
        f.install(); current=f.dest/".orbit/current"; current.unlink(); current.symlink_to("../../foreign")
        f.install(okay=False); check(os.readlink(current)=="../../foreign","unsafe current changed")
        check(not (f.root/"foreign").exists(),"unsafe pointer followed")
    with scenario("locked_source_build_captures_exact_paths_and_both_components"), fixture() as f:
        checkout=f.source(); f.install("--method","source","--source",str(checkout))
        check((f.run("orbit"),f.run("orbit-web"))==("orbit:source","orbit-web:source"),"source components not installed")
        calls=[c for c in f.commands() if Path(c[0]).name=="cargo"]; check(len(calls)==1,"source retried")
        call=calls[0]; check("--locked" in call and "--release" in call,"build omitted locked release")
        check(call[call.index("--manifest-path")+1]==str(checkout/"Cargo.toml"),"wrong checkout")
        check("--root" not in call and "orbit-cli" in call and "orbit-web" in call,"wrong package/output path")
        check(not [c for c in f.commands() if Path(c[0]).name=="curl"],"source contacted release transport")
    with scenario("source_build_failure_never_retries_unlocked_or_changes_current"), fixture() as f:
        f.install(); prior=f.snapshot(); checkout=f.source(fail=True); f.install("--method","source","--source",str(checkout),okay=False)
        calls=[c for c in f.commands() if Path(c[0]).name=="cargo"]; check(len(calls)==1 and "--locked" in calls[0],"failed build retried unlocked");f.unchanged(prior)
    with scenario("source_version_mismatch_fails_before_build"), fixture() as f:
        checkout=f.source(wrong_version=True);f.install("--method","source","--source",str(checkout),okay=False)
        check(not [c for c in f.commands() if Path(c[0]).name=="cargo"],"wrong-version checkout built")
    with scenario("source_requires_lockfile"), fixture() as f:
        checkout=f.source();(checkout/"Cargo.lock").unlink();f.install("--method","source","--source",str(checkout),okay=False)
        check(not [c for c in f.commands() if Path(c[0]).name=="cargo"],"unlocked source built")
    with scenario("missing_built_browser_cannot_replace_current"), fixture() as f:
        f.install(); prior=f.snapshot(); checkout=f.source(missing=True);f.install("--method","source","--source",str(checkout),okay=False);f.unchanged(prior)
    with scenario("corrupt_existing_immutable_version_is_refused"), fixture() as f:
        f.install(); pointer=os.readlink(f.dest/".orbit/current"); component=f.dest/".orbit"/pointer/"orbit";component.chmod(0o700);component.write_text("corrupt")
        f.install(okay=False);check(component.read_text()=="corrupt","corrupt current silently overwritten")
    with scenario("invalid_release_arguments_make_zero_transport_calls"), fixture() as f:
        f.install("--version","../../escape",okay=False);check(not f.commands(),"invalid version downloaded")
        check(not f.dest.exists(),"invalid version created destination")
        f.install("--base-url","https://user:secret@example.invalid",okay=False);check(not f.commands(),"credential URL used")
    with scenario("bundle_manifest_has_actual_hashes_and_no_fabricated_signing"), fixture() as f:
        archive=next(f.transport.glob("*.tar.gz"))
        with tarfile.open(archive) as tar:
            doc=json.load(tar.extractfile("manifest.json"))
            check(doc["signature"]=="absent","fabricated signature")
            for name,fact in doc["components"].items():
                data=tar.extractfile(name).read();check(fact=={"sha256":hashlib.sha256(data).hexdigest(),"size":len(data)},"fabricated component facts")
            check(set(tar.getnames())=={"orbit","orbit-web","manifest.json"},"unexpected bundle artifacts")

    with scenario("symlink_lock_is_refused_without_touching_target"), fixture() as f:
        f.install();lock=f.dest/".orbit/install.lock";lock.unlink();sentinel=f.root/"lock-target";sentinel.write_bytes(b"preserve")
        lock.symlink_to(sentinel);f.install(okay=False);check(sentinel.read_bytes()==b"preserve","lock symlink target changed")
    with scenario("wrong_rust_version_cannot_start_source_build"), fixture() as f:
        checkout=f.source();f.shim("rustc","print('rustc 1.93.0 (fixture)')\n")
        f.install("--method","source","--source",str(checkout),okay=False)
        check(not [c for c in f.commands() if Path(c[0]).name=="cargo"],"wrong toolchain built source")
    with scenario("failed_release_download_never_falls_back_to_source"), fixture() as f:
        f.install();prior=f.snapshot();f.source();f.env["FIXTURE_CURL_FAIL"]="1";f.install(okay=False)
        check(not [c for c in f.commands() if Path(c[0]).name=="cargo"],"release failure invoked Cargo");f.unchanged(prior)

    with scenario("explicit_old_version_rolls_back_the_complete_pair"), fixture() as f:
        f.install();prior=f.snapshot();f.package("0.2.1","second");f.install("--version","0.2.1")
        check(f.run("orbit")=="orbit:second","upgrade failed before rollback")
        f.install("--version","0.2.0");f.unchanged(prior)
    with scenario("post_publication_sync_failure_reports_uncertainty_with_valid_pair"), fixture() as f:
        f.install();f.package("0.2.1","second");patch=f.root/"fault-module";patch.mkdir()
        (patch/"sitecustomize.py").write_text('import os\noriginal=os.fsync\ndef sync(fd):\n path=os.readlink("/proc/self/fd/"+str(fd))\n if path.endswith("/.orbit") and os.path.islink(path+"/current"):raise OSError("fixture directory sync failure")\n return original(fd)\nos.fsync=sync\n')
        message=f.install("--version","0.2.1",okay=False,env={**f.env,"PYTHONPATH":str(patch)})
        check("durability is uncertain" in message,"post-publication error falsely claimed rollback")
        check((f.run("orbit"),f.run("orbit-web"))==("orbit:second","orbit-web:second"),"uncertain publication left mixed pair")
        check((f.home/"sentinel").read_bytes()==b"keep existing configuration\n","sync failure changed config")

    with scenario("existing_empty_version_is_not_clobbered"), fixture() as f:
        f.install();prior=f.snapshot();archive=f.package("0.2.1","second")
        with tarfile.open(archive) as tar:manifest=tar.extractfile("manifest.json").read()
        name="0.2.1-"+TARGET+"-"+hashlib.sha256(manifest).hexdigest()[:24]
        existing=f.dest/".orbit/versions"/name;existing.mkdir(mode=0o700)
        before=existing.stat().st_ino
        f.install("--version","0.2.1",okay=False);f.unchanged(prior)
        check(existing.stat().st_ino==before and not list(existing.iterdir()),"existing version was clobbered")


def main():
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument("--group",choices=("release","all"),default="all");args=parser.parse_args()
    if platform.system()!="Linux" or TARGET is None:parser.error("fixture acceptance requires a native Linux target")
    release_tests()
    if args.group=="all":all_tests()
    print("ORBIT_CHECK_RECEIPT "+json.dumps({"scenarios":SCENARIOS},sort_keys=True))


if __name__=="__main__":main()
